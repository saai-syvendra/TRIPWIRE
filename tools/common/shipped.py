#!/usr/bin/env python3
"""
Writes the shipped-paths sidecars: for each analysed record whose env recipes name a path relative to the install
directory (`file_present: ["tahg"]`), whether the package's archive ships that path, so the profile evaluator can
score it (a fresh install directory holds exactly what the package ships).

reports/_shipped/<key>.json holds only the paths the recipes name, never a file listing, and is bound to the
record by archive_sha256 and package_root. Built from samples/ (unpacked as data by tools/verify/source.py,
nothing executed); aggregate.py reads the sidecars and never needs samples/. A path counts as shipped when the
archive holds it as a file, directory or link.

Usage: python tools/common/shipped.py [--check]
  --check  rebuild every sidecar from samples/ and fail where one is missing or differs, write nothing
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402
from tools.common.contract import key_for  # noqa: E402
from tools.common.profiles import path_kind, relative  # noqa: E402

TOOL = "shipped@1"


def relative_paths(rec: dict) -> list[str]:
    """Sorted normal-form relative paths the record's env recipes name."""
    out = set()
    for g in rec.get("gates", []):
        for br in (g.get("then"), g.get("else")):
            recipe = (br or {}).get("env_recipe") or {}
            for key in ("file_present", "file_absent"):
                for path in recipe.get(key, []):
                    if path_kind(str(path)) == "relative" and (p := relative(str(path))) is not None:
                        out.add(p)
    return sorted(out)


def record_key(rec: dict) -> str:
    pk = rec["package"]
    return key_for(pk["ecosystem"], pk["name"], pk["version"])


def sidecar_path(key: str):
    return paths.REPORTS / "_shipped" / f"{key}.json"


def build(rec: dict, index: dict) -> dict:
    """The sidecar for one record, from its archive. Raises Unanchored (sample_missing) without one."""
    from tools.verify.source import Package
    root = Package(rec, index).root
    pk = rec["package"]
    return {"key": record_key(rec), "archive_sha256": pk["archive_sha256"], "package_root": pk.get("package_root"),
            "tool": TOOL, "paths": {p: os.path.lexists(root / p) for p in relative_paths(rec)}}


def load() -> dict[str, dict]:
    """key -> sidecar for every committed sidecar."""
    return {p.stem: json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((paths.REPORTS / "_shipped").glob("*.json"))}


def join(packages: list[dict], sidecars: dict[str, dict]) -> tuple[dict[str, dict], list[str]]:
    """({record key: {path: shipped?}}, warnings). A sidecar bound to another archive or package root, or one
    with no record, is ignored; a record whose relative paths no sidecar covers keeps them unknown."""
    out, warnings, keys = {}, [], set()
    for rec in packages:
        key, pk = record_key(rec), rec["package"]
        keys.add(key)
        wanted = relative_paths(rec)
        s = sidecars.get(key)
        if s is not None and (s.get("archive_sha256"), s.get("package_root")) != (pk["archive_sha256"],
                                                                               pk.get("package_root")):
            warnings.append(f"reports/_shipped/{key}.json is bound to another archive or package root; ignored")
            s = None
        if s is not None:
            out[key] = {p: bool(v) for p, v in s.get("paths", {}).items()}
        missing = [p for p in wanted if p not in out.get(key, {})]
        if missing:
            warnings.append(f"{key}: no shipped-paths sidecar covers {', '.join(missing)}; run "
                            f"tools/common/shipped.py")
    warnings += [f"reports/_shipped/{k}.json has no analysed record" for k in sorted(set(sidecars) - keys)]
    return out, warnings


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="fail where a sidecar is missing or differs")
    args = ap.parse_args()
    from tools.common.aggregate import read_records
    from tools.verify.source import Unanchored, sample_index
    index, committed = sample_index(), load()
    written = same = bad = 0
    for _, rec, _ in read_records():
        if not rec or rec.get("record_type") != "analysed" or not relative_paths(rec):
            continue
        key = record_key(rec)
        try:
            side = build(rec, index)
        except Unanchored as e:
            bad += 1
            print(f"FAIL {key}: {e.detail}", file=sys.stderr)
            continue
        if committed.get(key) == side:
            same += 1
        elif args.check:
            bad += 1
            print(f"FAIL {key}: sidecar {'differs' if key in committed else 'missing'}", file=sys.stderr)
        else:
            sidecar_path(key).parent.mkdir(parents=True, exist_ok=True)
            sidecar_path(key).write_text(json.dumps(side, indent=1) + "\n", encoding="utf-8")
            written += 1
            print(f"wrote {key}: " + ", ".join(f"{p} {'shipped' if v else 'not shipped'}"
                                               for p, v in side["paths"].items()))
    print(f"{written} written, {same} unchanged, {bad} failed", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
