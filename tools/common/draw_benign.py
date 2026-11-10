#!/usr/bin/env python3
"""
Draw the benign control set: the most-downloaded npm and PyPI packages that run code at install time, so the same
pipeline can be read on packages nobody suspects (paper/sampling.md, Benign control set).

npm pool: every name of npm-high-impact's download list (pinned by version and tarball integrity); a package
qualifies when its latest version declares a preinstall, install or postinstall script or ships a binding.gyp
(`gypfile`), and the qualifying packages are ranked by last-month downloads from the npm downloads API. PyPI pool: the
top-pypi-packages 30-day list (pinned by its last_update stamp and sha256), in rank order; a package qualifies when
its latest release has an sdist with a setup.py at its root. Packages are taken in rank order until --npm and
--pypi qualify.

The manifest (reports/_draws/<sample-id>.json, committed) records each pool as retrieved and each package's rank,
downloads, version, archive name and SHA-256; a draw is never redone under the same id. --fetch downloads the
archives into samples/benign_sample/<ecosystem>/benign/ (where prepare.py labels them benign) and checks each
against its SHA-256. Package code is never run: an sdist is only listed to look for setup.py.

Usage: draw_benign.py --sample-id benign [--npm 25 --pypi 25 --npm-candidates N] [--fetch]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402

USER_AGENT = "tripwire-benign-draw/1 (academic supply-chain research; registry metadata and archives only)"
NPM_LIST = ("npm-high-impact", "1.13.0", "package/lib/top-download.js")
PYPI_LIST = "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json"
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
BULK = 128  # names per npm downloads API bulk query (unscoped only)
MAX_SDIST = 100 * 2 ** 20  # larger sdists are passed over and listed in the manifest


BACKOFF = (2, 5, 15, 30)  # seconds before each retry of a rate limit or server error; fixed counts


def get(url: str) -> bytes:
    import time
    import urllib.error
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(len(BACKOFF) + 1):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if attempt == len(BACKOFF) or not (e.code == 429 or e.code >= 500):
                raise
        except (urllib.error.URLError, TimeoutError):
            if attempt == len(BACKOFF):
                raise
        time.sleep(BACKOFF[attempt])
    raise RuntimeError("unreachable")


def q(name: str) -> str:
    return urllib.parse.quote(name, safe="@")


def npm_pool(fetch, candidates: int | None) -> tuple[list[str], dict]:
    """The candidate names in list order, and the pool's provenance."""
    pkg, version, member = NPM_LIST
    meta = json.loads(fetch(f"https://registry.npmjs.org/{pkg}/{version}"))
    tgz = fetch(meta["dist"]["tarball"])
    with tarfile.open(fileobj=io.BytesIO(tgz)) as t:
        text = t.extractfile(member).read().decode("utf-8")
    names = re.findall(r"^\s*'([^']+)',?$", text, re.M)[:candidates]
    return names, {"list": f"{pkg}@{version} {member.removeprefix('package/')}", "integrity": meta["dist"]["integrity"],
                   "candidates": len(names)}


def npm_downloads(fetch, names: list[str]) -> tuple[dict[str, int], str]:
    """Last-month downloads per name, and the period the API reports."""
    out, period = {}, ""
    plain = [n for n in names if not n.startswith("@")]
    for i in range(0, len(plain), BULK):
        doc = json.loads(fetch("https://api.npmjs.org/downloads/point/last-month/" + ",".join(plain[i:i + BULK])))
        for n, v in doc.items():
            if v:
                out[n], period = v["downloads"], f"{v['start']}..{v['end']}"
    for n in (n for n in names if n.startswith("@")):
        v = json.loads(fetch(f"https://api.npmjs.org/downloads/point/last-month/{q(n)}"))
        if v and "downloads" in v:
            out[n], period = v["downloads"], f"{v['start']}..{v['end']}"
    return out, period


def npm_install_code(manifest: dict) -> list[str]:
    scripts = manifest.get("scripts")
    scripts = scripts if isinstance(scripts, dict) else {}  # a few published manifests carry a list
    found = [s for s in INSTALL_SCRIPTS if scripts.get(s)]
    return found + (["binding.gyp"] if manifest.get("gypfile") else [])


def integrity_ok(data: bytes, integrity: str | None) -> bool:
    import base64
    if not integrity or not integrity.startswith("sha512-"):
        return False
    return base64.b64encode(hashlib.sha512(data).digest()).decode() == integrity.removeprefix("sha512-")


def latest_manifests(fetch, names: list[str], workers: int = 8) -> dict[str, dict]:
    """name -> its latest version's manifest, fetched in parallel; names the registry no longer serves are left
    out."""
    from concurrent.futures import ThreadPoolExecutor

    def one(n):
        try:
            return n, json.loads(fetch(f"https://registry.npmjs.org/{q(n)}/latest"))
        except Exception:  # noqa: BLE001 - a package gone from the registry does not qualify
            return n, None
    with ThreadPoolExecutor(workers) as pool:
        got = dict(pool.map(one, names))
    return {n: m for n, m in got.items() if isinstance(m, dict) and "version" in m}


def draw_npm(fetch, want: int, candidates: int | None) -> tuple[list[dict], dict, dict[str, bytes]]:
    names, pool = npm_pool(fetch, candidates)
    latest = latest_manifests(fetch, names)
    qualifying = [n for n in names if n in latest and npm_install_code(latest[n])]
    downloads, period = npm_downloads(fetch, qualifying)
    ranked = sorted((n for n in qualifying if n in downloads), key=lambda n: (-downloads[n], n))
    items, kept = [], {}
    for rank, n in enumerate(ranked, 1):
        if len(items) == want:
            break
        why = npm_install_code(latest[n])
        print(f"  npm #{rank} {n} {','.join(why)}", file=sys.stderr, flush=True)
        url, integrity = latest[n]["dist"]["tarball"], latest[n]["dist"].get("integrity")
        data = fetch(url)
        if not integrity_ok(data, integrity):
            continue
        items.append({"ecosystem": "npm", "name": n, "version": latest[n]["version"], "rank": rank,
                      "downloads": downloads[n], "install_code": why, "url": url, "integrity": integrity,
                      "sha256": hashlib.sha256(data).hexdigest()})
        kept[url] = data
    pool.update(downloads=f"api.npmjs.org last-month {period}", served=len(latest), qualifying=len(qualifying),
                ranked=len(ranked), inspected=items[-1]["rank"] if items else 0)
    return items, pool, kept


def sdist_has_setup_py(data: bytes) -> bool:
    """A setup.py directly under the sdist's top folder (listed, never extracted)."""
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as t:
            names = t.getnames()
    except tarfile.TarError:
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
        except zipfile.BadZipFile:
            return False
    return any(re.fullmatch(r"[^/]+/setup\.py", n) for n in names)


def draw_pypi(fetch, want: int) -> tuple[list[dict], dict, dict[str, bytes]]:
    raw = fetch(PYPI_LIST)
    doc = json.loads(raw)
    pool = {"list": PYPI_LIST, "last_update": doc.get("last_update"), "sha256": hashlib.sha256(raw).hexdigest()}
    items, kept, large = [], {}, []
    for rank, row in enumerate(doc["rows"], 1):
        if len(items) == want:
            break
        meta = json.loads(fetch(f"https://pypi.org/pypi/{q(row['project'])}/json"))
        sdist = next((u for u in meta.get("urls", []) if u["packagetype"] == "sdist"), None)
        if sdist is None:
            continue
        if (sdist.get("size") or 0) > MAX_SDIST:
            large.append(f"{row['project']} (#{rank}, {sdist['size'] // 2 ** 20} MB)")
            continue
        print(f"  pypi #{rank} {row['project']}", file=sys.stderr, flush=True)
        data = fetch(sdist["url"])
        if hashlib.sha256(data).hexdigest() != sdist["digests"]["sha256"] or not sdist_has_setup_py(data):
            continue
        items.append({"ecosystem": "pypi", "name": meta["info"]["name"], "version": meta["info"]["version"],
                      "rank": rank, "downloads": row["download_count"], "install_code": ["setup.py"],
                      "url": sdist["url"], "sha256": sdist["digests"]["sha256"]})
        kept[sdist["url"]] = data
    pool["inspected"] = items[-1]["rank"] if items else 0
    pool["passed_over_large_sdist"] = large
    return items, pool, kept


def archive_name(item: dict) -> str:
    return Path(urllib.parse.urlparse(item["url"]).path).name


def manifest_items(items: list[dict]) -> list[dict]:
    """Manifest rows in the shape the dataset join reads (tools/common/prevalence.py)."""
    out = []
    for e in items:
        file = archive_name(e)
        out.append({"dataset": "benign_sample", "ecosystem": e["ecosystem"], "label": "benign",
                    "stratum": f"benign-top-{e['ecosystem']}", "name": e["name"],
                    "path": f"{e['name']}/{e['version']}/{file}", "version": e["version"], "rank": e["rank"],
                    "downloads": e["downloads"], "install_code": e["install_code"], "url": e["url"],
                    "sha256": e.get("sha256"), "integrity": e.get("integrity"), "weight": None})
    return out


def dest(item: dict) -> Path:
    return paths.SAMPLES / "benign_sample" / item["ecosystem"] / "benign" / Path(item["path"]).name


def fetch_archives(manifest: dict, fetch=get, cache: dict | None = None) -> tuple[int, list[str]]:
    ok, failed = 0, []
    for e in manifest["items"]:
        d = dest(e)
        data = d.read_bytes() if d.is_file() else (cache or {}).get(e["url"]) or fetch(e["url"])
        if hashlib.sha256(data).hexdigest() != e["sha256"]:
            failed.append(f"{e['name']}: bytes do not match the pinned sha256")
            continue
        d.parent.mkdir(parents=True, exist_ok=True)
        d.write_bytes(data)
        ok += 1
    return ok, failed


def cached(fetch, cache_dir: Path):
    """fetch, with each response kept under cache_dir so an interrupted draw resumes."""
    def get_cached(url: str) -> bytes:
        f = cache_dir / hashlib.sha256(url.encode()).hexdigest()
        if f.is_file():
            return f.read_bytes()
        data = fetch(url)
        cache_dir.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
        return data
    return get_cached


def draw(fetch, npm: int, pypi: int, candidates: int, sample_id: str) -> tuple[dict, dict]:
    npm_items, npm_pool_meta, kept = draw_npm(fetch, npm, candidates)
    pypi_items, pypi_pool_meta, kept_py = draw_pypi(fetch, pypi)
    kept.update(kept_py)
    items = manifest_items(npm_items + pypi_items)
    strata = [{"ecosystem": eco, "stratum": f"benign-top-{eco}", "names": n, "drawn": n, "weight": None}
              for eco, n in (("npm", len(npm_items)), ("pypi", len(pypi_items)))]
    manifest = {"sample_id": sample_id, "seed": None,
                "rule": "tools/common/draw_benign.py (most-downloaded packages with install-time code)",
                "pools": {"npm": npm_pool_meta, "pypi": pypi_pool_meta}, "strata": strata, "items": items}
    return manifest, kept


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sample-id", required=True)
    ap.add_argument("--npm", type=int, default=25)
    ap.add_argument("--pypi", type=int, default=25)
    ap.add_argument("--npm-candidates", type=int, help="only the first N names of the download list (tests)")
    ap.add_argument("--fetch", action="store_true", help="download the archives into samples/benign_sample/")
    args = ap.parse_args()
    out = paths.REPORTS / "_draws" / f"{args.sample_id}.json"
    kept = {}
    if out.is_file():
        manifest = json.loads(out.read_text(encoding="utf-8"))
        print(f"{out.relative_to(paths.ROOT)} exists; reusing it (a draw is never redone under the same id)")
    else:
        manifest, kept = draw(cached(get, paths.SAMPLES / ".catalog" / "benign"), args.npm, args.pypi,
                              args.npm_candidates, args.sample_id)
        print(f"drew {len(manifest['items'])} packages")
    for e in manifest["items"]:
        print(f"  {e['ecosystem']:5} #{e['rank']:<5} {e['name']}@{e['version']}  {','.join(e['install_code'])}")
    if args.fetch:
        ok, failed = fetch_archives(manifest, cache=kept)
        print(f"fetched {ok} of {len(manifest['items'])}" + (f"; {len(failed)} failed:" if failed else ""))
        for f in failed:
            print(f"  {f}")
        if failed:
            return 1
    if not out.is_file():
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
