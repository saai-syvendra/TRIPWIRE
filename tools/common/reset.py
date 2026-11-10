#!/usr/bin/env python3
"""
Clears the working state before a new analysis session, so nothing from an earlier session (decoded payloads
in scratch/<key>/unpacked/, other packages' prepared facts, the old batch queue, aggregated verdicts) can
leak into the next one.

Deletes everything under scratch/ and dataset/ (dataset/ is rebuilt from reports/ by aggregate.py). Never
touches reports/, samples/ or schema/.

Refuses, and deletes nothing, while work is unfinished: a prepared package with analyst edits (record.json,
summary.md or skip.json) but no finished record in reports/, a scratch/queue.jsonl that still lists
packages without a record, or a scratch/verify/queue.jsonl with review packets that have no recorded
verdicts. Finish it (write_report.py, record_verdict.py), or pass --force to discard it.

Usage: python tools/common/reset.py [--dry-run] [--force]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import contract, paths  # noqa: E402

TODO = "TODO"
# What prepare.py writes before the analyst edits anything.
SUMMARY_TEMPLATE = "## Summary\n\nTODO\n\n## Notes\n\nTODO\n"


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def in_progress(work: Path) -> str | None:
    """Why scratch/<key>/ holds unfinished analyst work, or None if it is safe to delete."""
    prepared = load(work / "prepared.json")
    if not isinstance(prepared, dict) or not isinstance(prepared.get("package"), dict):
        return None  # unpack leftovers or an interrupted prepare: nothing the analyst wrote
    pk = prepared["package"]
    if contract.existing_record(paths.REPORTS, pk.get("ecosystem", ""), pk.get("name", ""), pk.get("version")):
        return None
    edited = []
    if (work / "record.json").exists() and load(work / "record.json") != prepared.get("record"):
        edited.append("record.json")
    summary = work / "summary.md"
    if summary.exists() and summary.read_text(encoding="utf-8", errors="replace") != SUMMARY_TEMPLATE:
        edited.append("summary.md")
    if (work / "skip.json").exists():
        choice = load(work / "skip.json")
        if not isinstance(choice, dict) or any(choice.get(k) != TODO for k in ("reason", "note")):
            edited.append("skip.json")
    return f"{', '.join(edited)} edited, no record in reports/" if edited else None


def pending_queue() -> list[str]:
    """Keys in scratch/queue.jsonl whose package has no finished record yet."""
    queue = paths.SCRATCH / "queue.jsonl"
    if not queue.is_file():
        return []
    pending = []
    for line in queue.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        # An entry whose prepared package is gone cannot be resumed, so it is not pending work.
        prepared = load(paths.ROOT / entry["prepared"]) if isinstance(entry, dict) and entry.get("prepared") else None
        pk = prepared.get("package") if isinstance(prepared, dict) else None
        if isinstance(pk, dict) and not contract.existing_record(paths.REPORTS, pk.get("ecosystem", ""),
                                                                  pk.get("name", ""), pk.get("version")):
            pending.append(entry.get("key", "?"))
    return pending


def pending_packets() -> list[str]:
    """Review packets in scratch/verify/queue.jsonl that no reviewer CLI has recorded yet."""
    queue = paths.SCRATCH / "verify" / "queue.jsonl"
    if not queue.is_file():
        return []
    rows = []
    for line in queue.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return [r.get("packet_id", "?") for r in rows if isinstance(r, dict) and r.get("status") != "done"
            and not r.get("done") and not r.get("superseded")]


def remove(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink()
        return
    # Unpacked archives can carry read-only directories; open them up first (never following links).
    os.chmod(path, stat.S_IRWXU)
    for dirpath, dirnames, _ in os.walk(path):
        for d in dirnames:
            p = os.path.join(dirpath, d)
            if not os.path.islink(p):
                os.chmod(p, stat.S_IRWXU)
    shutil.rmtree(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="list what would be deleted, delete nothing")
    ap.add_argument("--force", action="store_true", help="also discard interrupted analyses")
    args = ap.parse_args()

    busy = [(w.name, why) for w in sorted(paths.SCRATCH.iterdir()) if w.is_dir() and (why := in_progress(w))] \
        if paths.SCRATCH.is_dir() else []
    packets = pending_packets()
    if packets:
        shown = ", ".join(packets[:5]) + (", ..." if len(packets) > 5 else "")
        busy.append(("verify/queue.jsonl", f"{len(packets)} review packets have no recorded verdicts: {shown}"))
    queued = pending_queue()
    if queued:
        shown = ", ".join(queued[:5]) + (", ..." if len(queued) > 5 else "")
        busy.append(("queue.jsonl", f"{len(queued)} queued packages have no record yet: {shown}"))
    if busy and not args.force:
        print("not cleared, analysis in progress (finish it with write_report.py, or rerun with --force to "
              "discard it):", file=sys.stderr)
        for key, why in busy:
            print(f"  scratch/{key}: {why}", file=sys.stderr)
        return 1

    counts = {}
    for d in (paths.SCRATCH, paths.DATASET):
        entries = sorted(d.iterdir()) if d.is_dir() else []
        counts[d.name] = len(entries)
        for p in entries:
            if args.dry_run:
                print(f"would delete {p.relative_to(paths.ROOT)}")
            else:
                remove(p)
    verb = "would clear" if args.dry_run else "cleared"
    discarded = f", discarding unfinished work: {', '.join(k for k, _ in busy)}" if busy else ""
    print(f"{verb} {counts['scratch']} entries in scratch/ and {counts['dataset']} in dataset/{discarded}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
