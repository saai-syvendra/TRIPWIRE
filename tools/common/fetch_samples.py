#!/usr/bin/env python3
"""
Download sample archives from supported malicious-package datasets.

Writes archives into samples/<dataset>/<ecosystem>/<label>/ so that prepare.py
can infer source_dataset, ecosystem and source_label from the path.

Usage:
    python tools/common/fetch_samples.py datadog --ecosystem npm --count 20
    python tools/common/fetch_samples.py pypi_malregistry --count 50 --offset 10
    python tools/common/fetch_samples.py datadog --list --ecosystem npm
    python tools/common/fetch_samples.py --datasets                  # list available datasets

Requires GITHUB_TOKEN or GH_TOKEN for large listings (unauthenticated requests
are rate-limited to 60/hour).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402

API = "https://api.github.com"
CACHE_TTL = 3600


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _token() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")


def _get_json(url: str):
    req = urllib.request.Request(url)
    tok = _token()
    if tok:
        req.add_header("Authorization", f"token {tok}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url)
    tok = _token()
    if tok:
        req.add_header("Authorization", f"token {tok}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(req) as resp:
        dest.write_bytes(resp.read())


def _get_tree(repo: str, cache_name: str) -> dict:
    cache = paths.SCRATCH / f".{cache_name}_tree.json"
    if cache.exists() and (time.time() - cache.stat().st_mtime) < CACHE_TTL:
        print("Using cached repository tree.", file=sys.stderr)
        return json.loads(cache.read_text())
    print("Fetching repository tree...", file=sys.stderr)
    tree = _get_json(f"{API}/repos/{repo}/git/trees/main?recursive=1")
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(tree))
    return tree


# ---------------------------------------------------------------------------
# Dataset: datadog
# ---------------------------------------------------------------------------

DATADOG_REPO = "DataDog/malicious-software-packages-dataset"
DATADOG_RAW = f"https://raw.githubusercontent.com/{DATADOG_REPO}/main"
DATADOG_PREFIXES = {
    "samples/npm/malicious_intent":  ("npm", "malicious_intent"),
    "samples/npm/compromised_lib":   ("npm", "compromised_lib"),
    "samples/pypi/malicious_intent": ("pypi", "malicious_intent"),
    "samples/pypi/compromised_lib":  ("pypi", "compromised_lib"),
}


def _datadog_list(ecosystem: str | None) -> list[dict]:
    tree = _get_tree(DATADOG_REPO, "datadog")
    zips = []
    for item in tree.get("tree", []):
        if item["type"] != "blob" or not item["path"].endswith(".zip"):
            continue
        matched = None
        for prefix, (eco, label) in DATADOG_PREFIXES.items():
            if item["path"].startswith(prefix + "/"):
                matched = (eco, label)
                break
        if matched is None:
            continue
        eco, label = matched
        if ecosystem and eco != ecosystem:
            continue
        zips.append({"path": item["path"], "size": item.get("size", 0),
                     "ecosystem": eco, "label": label})
    return zips


def _datadog_dest(z: dict) -> Path:
    return paths.SAMPLES / "datadog" / z["ecosystem"] / z["label"] / Path(z["path"]).name


def _datadog_url(z: dict) -> str:
    return f"{DATADOG_RAW}/{urllib.request.quote(z['path'])}"


# ---------------------------------------------------------------------------
# Dataset: pypi_malregistry
# ---------------------------------------------------------------------------

MALREG_REPO = "lxyeternal/pypi_malregistry"
MALREG_RAW = f"https://raw.githubusercontent.com/{MALREG_REPO}/main"
MALREG_EXTENSIONS = (".tar.gz", ".tgz", ".zip", ".whl", ".egg")


def _malreg_list(ecosystem: str | None) -> list[dict]:
    if ecosystem and ecosystem != "pypi":
        return []
    tree = _get_tree(MALREG_REPO, "pypi_malregistry")
    archives = []
    for item in tree.get("tree", []):
        if item["type"] != "blob":
            continue
        path_lower = item["path"].lower()
        if not any(path_lower.endswith(ext) for ext in MALREG_EXTENSIONS):
            continue
        archives.append({"path": item["path"], "size": item.get("size", 0),
                         "ecosystem": "pypi", "label": "malicious_intent"})
    return archives


def _malreg_dest(z: dict) -> Path:
    return paths.SAMPLES / "pypi_malregistry" / "pypi" / z["label"] / Path(z["path"]).name


def _malreg_url(z: dict) -> str:
    return f"{MALREG_RAW}/{urllib.request.quote(z['path'])}"


# ---------------------------------------------------------------------------
# Dataset registry
# ---------------------------------------------------------------------------

DATASETS: dict[str, dict] = {
    "datadog": {
        "description": "Datadog malicious-software-packages-dataset (npm)",
        "ecosystems": ["npm"],
        "list": _datadog_list,
        "dest": _datadog_dest,
        "url": _datadog_url,
    },
    "pypi_malregistry": {
        "description": "lxyeternal/pypi_malregistry (pypi, 10k+ packages)",
        "ecosystems": ["pypi"],
        "list": _malreg_list,
        "dest": _malreg_dest,
        "url": _malreg_url,
    },
}


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def fetch(dataset_name: str, entries: list[dict]) -> list[dict]:
    ds = DATASETS[dataset_name]
    fetched = []
    for i, z in enumerate(entries, 1):
        dest = ds["dest"](z)
        if dest.exists():
            print(f"  [{i}/{len(entries)}] exists   {dest.relative_to(paths.ROOT)}", file=sys.stderr)
            fetched.append(z)
            continue
        try:
            _download(ds["url"](z), dest)
            print(f"  [{i}/{len(entries)}] fetched  {dest.relative_to(paths.ROOT)}", file=sys.stderr)
            fetched.append(z)
        except urllib.error.HTTPError as e:
            print(f"  [{i}/{len(entries)}] FAILED   {z['path']} (HTTP {e.code})", file=sys.stderr)
        except Exception as e:
            print(f"  [{i}/{len(entries)}] FAILED   {z['path']} ({e})", file=sys.stderr)
    return fetched


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dataset", nargs="?", choices=list(DATASETS), default=None,
                    help="which dataset to fetch from")
    ap.add_argument("--ecosystem", choices=["npm", "pypi"], default=None,
                    help="filter by ecosystem (when a dataset has multiple)")
    ap.add_argument("--count", type=int, default=10,
                    help="number of archives to fetch (default: 10)")
    ap.add_argument("--offset", type=int, default=0,
                    help="skip the first N archives in the listing")
    ap.add_argument("--list", action="store_true",
                    help="list available archives and exit (no download)")
    ap.add_argument("--datasets", action="store_true",
                    help="list available datasets and exit")
    args = ap.parse_args()

    if args.datasets or args.dataset is None:
        print("Available datasets:\n", file=sys.stderr)
        for name, ds in DATASETS.items():
            ecos = ", ".join(ds["ecosystems"])
            print(f"  {name:20s}  ecosystems: {ecos:10s}  {ds['description']}", file=sys.stderr)
        if args.dataset is None and not args.datasets:
            ap.error("specify a dataset name, or --datasets to list them")
        return

    ds = DATASETS[args.dataset]
    entries = ds["list"](args.ecosystem)
    eco_note = f" ({args.ecosystem})" if args.ecosystem else ""
    print(f"Found {len(entries)} archives in {args.dataset}{eco_note}.", file=sys.stderr)

    if args.list:
        for z in entries:
            print(f"{z['ecosystem']:5s}  {z['label']:20s}  {z['size']:>8d}  {z['path']}")
        return

    selected = entries[args.offset:args.offset + args.count]
    if not selected:
        print("Nothing to fetch (offset beyond listing).", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching {len(selected)} archives...\n", file=sys.stderr)
    fetched = fetch(args.dataset, selected)

    by_eco = {}
    for z in fetched:
        by_eco[z["ecosystem"]] = by_eco.get(z["ecosystem"], 0) + 1
    counts = ", ".join(f"{e}: {n}" for e, n in sorted(by_eco.items()))
    print(f"\nDone: {len(fetched)} archives ({counts})"
          f" in samples/{args.dataset}/", file=sys.stderr)
    eco = args.ecosystem or ds["ecosystems"][0]
    print(f"Next: .venv/bin/python tools/analysis/prepare.py samples/{args.dataset}/{eco}"
          f" --batch", file=sys.stderr)


if __name__ == "__main__":
    main()
