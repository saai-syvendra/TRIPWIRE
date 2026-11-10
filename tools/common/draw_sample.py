#!/usr/bin/env python3
"""
Draw the stratified sample for a batch (paper/sampling.md) from the dataset repos pinned at one commit each, and
optionally fetch it. The draw is reproducible: the same commits and seed give the same manifest on any machine.

Frame: npm from the Datadog malicious-software-packages dataset, stratified by label (malicious_intent,
compromised_lib) and the year in the archive name; PyPI from Datadog (by label) and pypi_malregistry (by archive
kind: sdist, wheel, zip), one version per name across both. Unit: one version per package name. Allocation: --npm names split into --compromised from
compromised_lib and the rest from malicious_intent, each shared across years in proportion to their names with at
least --min-per-year per non-empty year; --pypi names shared across archive kinds in proportion. Within a stratum,
archives are taken in sha256(seed|path) order, keeping the first version met per name, until the quota is filled.

The manifest (reports/_draws/<sample-id>.json, committed) records the seed, each repo's commit, every stratum
with its name count N and draw n (the design weight is N/n), and every drawn archive with its git blob sha. --fetch
downloads the drawn archives from the pinned commits into samples/ (where prepare.py expects them) and checks each
against its blob sha; archives are never committed.

--pilot pins the pilot the same way: every record whose archive is in no draw manifest, located at the commits the
draws pinned and checked against its blob sha, in reports/_draws/pilot.json (stratum `pilot`, no weight), so
`--sample-id pilot --fetch` fetches the pilot archives on any machine.

Usage: draw_sample.py --seed N --sample-id ID [--npm 250 --pypi 250 --compromised 100 --min-per-year 10]
                      [--pin datadog=SHA --pin pypi_malregistry=SHA] [--fetch]
       draw_sample.py --pilot
       draw_sample.py --sample-id ID --fetch          (an existing manifest)
The frame is listed with git from a treeless clone in samples/.catalog/ (no package files are fetched until
--fetch); downloads use raw files at the pinned commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import fetch_samples, paths  # noqa: E402
from tools.common.contract import normalise_name  # noqa: E402

API = fetch_samples.API
REPOS = {"datadog": fetch_samples.DATADOG_REPO, "pypi_malregistry": fetch_samples.MALREG_REPO}
YEAR = re.compile(r"/(\d{4})-\d\d-\d\d-[^/]*$")
KINDS = ((".tar.gz", "sdist"), (".tgz", "sdist"), (".whl", "wheel"), (".zip", "zip"), (".egg", "egg"))


def h(seed: int, path: str) -> str:
    return hashlib.sha256(f"{seed}|{path}".encode()).hexdigest()


def _git(*args, cwd=None) -> str:
    import subprocess
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"git {' '.join(args[:3])} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def pinned_tree(dataset: str, commit: str | None) -> tuple[str, list[dict]]:
    """(commit sha, blobs) of the dataset repo at `commit`, or at the head of main. Listed with git from a treeless
    clone (no file contents are fetched), because the API's recursive listing truncates large repos and the frame
    must be complete."""
    repo = REPOS[dataset]
    cache = paths.SAMPLES / ".catalog"
    gitdir = cache / f"{dataset}.git"
    if not gitdir.is_dir():
        cache.mkdir(parents=True, exist_ok=True)
        _git("init", "--bare", "-q", str(gitdir))
        _git("--git-dir", str(gitdir), "remote", "add", "origin", f"https://github.com/{repo}.git")
    sha = commit or _git("--git-dir", str(gitdir), "ls-remote", "origin", "refs/heads/main").split()[0]
    listing = cache / f"{dataset}@{sha}.json"
    if listing.is_file():
        return sha, json.loads(listing.read_text())
    _git("--git-dir", str(gitdir), "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", sha)
    blobs = []
    # no -l: in a partial clone a blob's size is only known by downloading it, which would fetch the whole dataset
    for line in _git("--git-dir", str(gitdir), "-c", "fetch.negotiationAlgorithm=noop", "ls-tree", "-r",
                     "--full-tree", sha).splitlines():
        meta, path = line.split("\t", 1)
        mode, kind, obj = meta.split()
        if kind == "blob":
            blobs.append({"path": path, "type": "blob", "sha": obj, "size": None})
    listing.write_text(json.dumps(blobs))
    return sha, blobs


def frame(dataset: str, blobs: list[dict]) -> list[dict]:
    """Every archive of the frame with its ecosystem, label, stratum and package name."""
    out = []
    if dataset == "datadog":
        for t in blobs:
            p = t["path"]
            if not p.endswith(".zip"):
                continue
            for prefix, (eco, label) in fetch_samples.DATADOG_PREFIXES.items():
                if p.startswith(prefix + "/"):
                    m = YEAR.search(p)
                    parts = p.split("/")
                    name = parts[3] if len(parts) > 4 else parts[-1]
                    # npm by label and year; Datadog's PyPI by label, next to pypi_malregistry's strata
                    stratum = f"{label}/{m.group(1) if m else 'undated'}" if eco == "npm" else f"datadog-{label}"
                    out.append({"dataset": dataset, "ecosystem": eco, "label": label, "path": p, "blob": t["sha"],
                                "size": t.get("size", 0), "name": normalise_name(eco, name), "stratum": stratum})
                    break
    else:
        for t in blobs:
            p = t["path"]
            kind = next((k for ext, k in KINDS if p.lower().endswith(ext)), None)
            if kind is None:
                continue
            out.append({"dataset": dataset, "ecosystem": "pypi", "label": "malicious_intent", "path": p,
                        "blob": t["sha"], "size": t.get("size", 0), "name": normalise_name("pypi", p.split("/")[0]),
                        "stratum": f"malregistry-{kind}"})
    return out


def names_per_stratum(entries: list[dict]) -> dict[str, int]:
    out: dict[str, set] = {}
    for e in entries:
        out.setdefault(e["stratum"], set()).add(e["name"])
    return {s: len(v) for s, v in out.items()}


def allocate(total: int, sizes: dict[str, int], minimum: int = 0) -> dict[str, int]:
    """Quotas summing to min(total, available): each stratum gets min(minimum, its size) first, the rest in
    proportion to size by largest remainder, never more than a stratum holds (ties broken by stratum name)."""
    total = min(total, sum(sizes.values()))
    quota = {s: min(minimum, n) for s, n in sizes.items()}
    if sum(quota.values()) > total:  # the floors alone do not fit: proportional from zero
        quota = {s: 0 for s in sizes}
    while sum(quota.values()) < total:
        left = total - sum(quota.values())
        room = {s: sizes[s] - quota[s] for s in sizes if sizes[s] > quota[s]}
        weight = sum(sizes[s] for s in room)
        share = {s: left * sizes[s] / weight for s in room}
        add = {s: min(int(share[s]), room[s]) for s in room}
        if not any(add.values()):  # hand out the remainder one by one, largest fraction first
            for s in sorted(room, key=lambda s: (-(share[s] - int(share[s])), s))[:left]:
                add[s] = 1
        for s, n in add.items():
            quota[s] += n
    return quota


def draw(entries: list[dict], quotas: dict[str, int], seed: int, taken: set | None = None) -> list[dict]:
    """The first quota[s] names of each stratum in hash order (one version per name; a name already taken in
    another stratum of the same ecosystem is skipped)."""
    taken = taken if taken is not None else set()
    out = []
    by_stratum: dict[str, list[dict]] = {}
    for e in entries:
        by_stratum.setdefault(e["stratum"], []).append(e)
    for s in sorted(quotas):
        n = 0
        for e in sorted(by_stratum.get(s, []), key=lambda e: h(seed, e["path"])):
            if n >= quotas[s]:
                break
            if (e["ecosystem"], e["name"]) in taken:
                continue
            taken.add((e["ecosystem"], e["name"]))
            out.append(e)
            n += 1
    return out


def plan(frames: dict[str, list[dict]], seed: int, npm: int, pypi: int, compromised: int,
         min_per_year: int, pypi_compromised: int = 10 ** 6) -> tuple[list[dict], list[dict]]:
    """(drawn entries, strata rows) for the whole sample. PyPI combines Datadog's PyPI and pypi_malregistry, one
    version per name across both; up to pypi_compromised names come from Datadog's PyPI compromised_lib (all of them
    by default), the rest in proportion to the other PyPI strata."""
    npm_e = [e for e in frames.get("datadog", []) if e["ecosystem"] == "npm"]
    py_e = [e for e in frames.get("datadog", []) if e["ecosystem"] == "pypi"] + frames.get("pypi_malregistry", [])
    sizes_npm = names_per_stratum(npm_e)
    comp = {s: n for s, n in sizes_npm.items() if s.startswith("compromised_lib/")}
    mal = {s: n for s, n in sizes_npm.items() if s.startswith("malicious_intent/")}
    quotas = {**allocate(min(compromised, npm), comp, min_per_year),
              **allocate(npm - min(compromised, npm, sum(comp.values())), mal, min_per_year)}
    sizes_py = names_per_stratum(py_e)
    pcomp = {s: n for s, n in sizes_py.items() if s == "datadog-compromised_lib"}
    quotas_py = allocate(min(pypi_compromised, pypi), pcomp)
    quotas_py.update(allocate(pypi - sum(quotas_py.values()), {s: n for s, n in sizes_py.items() if s not in pcomp}))
    drawn = draw(npm_e, quotas, seed) + draw(py_e, quotas_py, seed)  # compromised strata sort first, so drawn first
    got: dict[tuple, int] = {}
    for e in drawn:
        got[(e["ecosystem"], e["stratum"])] = got.get((e["ecosystem"], e["stratum"]), 0) + 1
    strata = [{"ecosystem": eco, "stratum": s, "names": n, "drawn": got.get((eco, s), 0),
               "weight": (n / got[(eco, s)]) if got.get((eco, s)) else None}
              for eco, sizes in (("npm", sizes_npm), ("pypi", sizes_py)) for s, n in sorted(sizes.items())]
    for e in drawn:
        e["weight"] = next(r["weight"] for r in strata if (r["ecosystem"], r["stratum"]) == (e["ecosystem"],
                                                                                              e["stratum"]))
    return drawn, strata


def dest(e: dict) -> Path:
    if e["dataset"] == "datadog":
        return fetch_samples._datadog_dest(e)
    return fetch_samples._malreg_dest(e)


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch(manifest: dict) -> tuple[int, list[str]]:
    """(fetched or present, failures). Each archive comes from its repo's pinned commit and must match its blob
    sha, so the bytes are exactly the ones drawn."""
    import urllib.request
    ok, failed = 0, []
    for e in manifest["items"]:
        d = dest(e)
        if d.is_file() and blob_sha(d.read_bytes()) == e["blob"]:
            ok += 1
            continue
        repo, sha = manifest["datasets"][e["dataset"]]["repo"], manifest["datasets"][e["dataset"]]["commit"]
        url = f"https://raw.githubusercontent.com/{repo}/{sha}/{urllib.request.quote(e['path'])}"
        try:
            with urllib.request.urlopen(urllib.request.Request(url), timeout=60) as resp:
                data = resp.read()
        except Exception as exc:  # noqa: BLE001 - a failed download is reported, the rest go on
            failed.append(f"{e['path']}: {exc}")
            continue
        if blob_sha(data) != e["blob"]:
            failed.append(f"{e['path']}: downloaded bytes do not match the pinned blob")
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(data)
        ok += 1
    return ok, failed


def local(e: dict) -> str:
    """Where --fetch puts an archive, relative to samples/."""
    return dest(e).resolve().relative_to(paths.SAMPLES.resolve()).as_posix()


def pin_pilot(archives: dict[str, str], frames: dict[str, list[dict]], drawn: set[str]) -> list[dict]:
    """The pilot items: each archive (path under samples/ -> git blob sha) that no draw holds, as the one frame
    entry with the same fetch destination and blob. Refuses an archive the pinned frames do not hold byte for
    byte, since --fetch could not reproduce it."""
    by_dest = {}
    for ds, entries in frames.items():
        for e in entries:
            by_dest.setdefault(local(e), []).append(e)
    items, missing = [], []
    for rel in sorted(set(archives) - drawn):
        hits = [e for e in by_dest.get(rel, []) if e["blob"] == archives[rel]]
        if len(hits) != 1:
            missing.append(rel)
            continue
        e = hits[0]
        items.append({**{k: e[k] for k in ("dataset", "ecosystem", "label", "name", "path", "blob", "size")},
                      "stratum": "pilot", "weight": None})
    if missing:
        raise SystemExit(f"{len(missing)} pilot archives are not in the pinned commits byte for byte: "
                         + ", ".join(missing[:5]))
    return items


def pilot_manifest() -> dict:
    """reports/_draws/pilot.json from the records and the local samples/, at the commits the draws pinned."""
    from tools.common.aggregate import read_records
    from tools.verify.source import sample_index
    draws = [json.loads(p.read_text()) for p in sorted((paths.REPORTS / "_draws").glob("*.json"))
             if p.stem != "pilot"]
    datasets = {}
    for m in draws:
        for ds, meta in m["datasets"].items():
            if datasets.setdefault(ds, meta)["commit"] != meta["commit"]:
                raise SystemExit(f"the draws pin {ds} at two commits; pin the pilot by hand")
    drawn = {local(e) for m in draws for e in m["items"]}
    index = sample_index()
    archives, absent = {}, []
    for path, rec, _ in read_records():
        f = index.get((rec or {}).get("package", {}).get("archive_sha256"))
        if f is None:
            absent.append(path.name)
            continue
        archives[f.resolve().relative_to(paths.SAMPLES.resolve()).as_posix()] = blob_sha(f.read_bytes())
    if absent:
        raise SystemExit(f"{len(absent)} records have no archive under samples/: {', '.join(absent[:5])}")
    frames = {ds: frame(ds, pinned_tree(ds, meta["commit"])[1]) for ds, meta in datasets.items()}
    items = pin_pilot(archives, frames, drawn)
    strata = [{"ecosystem": eco, "stratum": "pilot", "names": n, "drawn": n, "weight": None}
              for eco in ("npm", "pypi") if (n := sum(1 for e in items if e["ecosystem"] == eco))]
    return {"sample_id": "pilot", "seed": None,
            "rule": "paper/sampling.md (the pilot: taken alphabetically, not drawn)", "allocation": None,
            "datasets": {ds: {**meta, "archives": sum(1 for e in items if e["dataset"] == ds)}
                         for ds, meta in datasets.items()},
            "strata": strata, "items": items}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seed", type=int, help="fixed before the draw and recorded in the manifest")
    ap.add_argument("--sample-id", help="the manifest name, e.g. strat")
    ap.add_argument("--pilot", action="store_true", help="pin the pilot archives in reports/_draws/pilot.json")
    ap.add_argument("--npm", type=int, default=250)
    ap.add_argument("--pypi", type=int, default=250)
    ap.add_argument("--compromised", type=int, default=100, help="npm names from compromised_lib (oversampled)")
    ap.add_argument("--min-per-year", type=int, default=10)
    ap.add_argument("--pypi-compromised", type=int, default=10 ** 6,
                    help="PyPI names from Datadog's compromised_lib (default: all of them)")
    ap.add_argument("--pin", action="append", default=[], metavar="DATASET=SHA", help="reuse a recorded commit")
    ap.add_argument("--fetch", action="store_true", help="download the drawn archives into samples/")
    ap.add_argument("--dry-run", action="store_true", help="print the strata and quotas, write nothing")
    args = ap.parse_args()
    if args.pilot:
        args.sample_id = "pilot"
    if not args.sample_id:
        ap.error("--sample-id or --pilot is needed")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", args.sample_id):
        ap.error("--sample-id: lowercase letters, digits, dot, dash, underscore")
    pins = dict(p.split("=", 1) for p in args.pin)
    out = paths.REPORTS / "_draws" / f"{args.sample_id}.json"
    if out.is_file():
        manifest = json.loads(out.read_text())
        print(f"{out.relative_to(paths.ROOT)} exists; reusing it (a draw is never redone under the same id)")
    elif args.pilot:
        manifest = pilot_manifest()
        out.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
        print(f"pinned {len(manifest['items'])} pilot archives in {out.relative_to(paths.ROOT)}")
    elif args.seed is None or args.sample_id == "pilot":
        ap.error("a new draw needs --seed (and the id `pilot` is kept for --pilot)")
    else:
        frames, datasets = {}, {}
        for ds in REPOS:
            sha, blobs = pinned_tree(ds, pins.get(ds))
            frames[ds] = frame(ds, blobs)
            datasets[ds] = {"repo": REPOS[ds], "commit": sha, "archives": len(frames[ds])}
        items, strata = plan(frames, args.seed, args.npm, args.pypi, args.compromised, args.min_per_year,
                             args.pypi_compromised)
        manifest = {"sample_id": args.sample_id, "seed": args.seed,
                    "rule": "paper/sampling.md",
                    "allocation": {"npm": args.npm, "pypi": args.pypi, "compromised": args.compromised,
                                   "min_per_year": args.min_per_year, "pypi_compromised": args.pypi_compromised},
                    "datasets": datasets, "strata": strata,
                    "items": [{k: e[k] for k in ("dataset", "ecosystem", "label", "stratum", "name", "path", "blob",
                                                 "size", "weight")} for e in items]}
        if args.dry_run:
            print(f"would draw {len(items)} names (nothing written)")
        else:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n")
            print(f"drew {len(items)} names into {out.relative_to(paths.ROOT)}")
    for r in manifest["strata"]:
        w = f"{r['weight']:.1f}" if r["weight"] else "-"
        print(f"  {r['ecosystem']:5} {r['stratum']:24} names {r['names']:>6}  drawn {r['drawn']:>4}  weight {w}")
    if args.fetch and not args.dry_run:
        ok, failed = fetch(manifest)
        print(f"fetched {ok} of {len(manifest['items'])}" + (f"; {len(failed)} failed:" if failed else ""))
        for f in failed[:20]:
            print(f"  {f}")
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
