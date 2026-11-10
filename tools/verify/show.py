#!/usr/bin/env python3
"""
A reviewer's only window onto package code beyond a packet's slices. Output is capped, defanged and redacted,
and every request is logged to scratch/verify/<packet_id>/access.log.

  show.py <packet_id> --slice sN [--context K]     the slice with K more lines either side (default 10)
  show.py <packet_id> --slice sN --bytes K          K bytes either side of the slice's anchor (for one-line
                                                    minified or decoded files, where lines are useless)
  show.py <packet_id> --file fN --lines A-B        lines A to B of a packet file (at most 40)
  show.py <packet_id> --file fN --grep WORD        lines of that file mentioning WORD (at most 20 hits)

Package code is read as text from the rebuilt sample; nothing is executed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import contract, paths, verification  # noqa: E402
from tools.common.sanitize import defang  # noqa: E402
from tools.verify.source import Package, Unanchored  # noqa: E402

MAX_LINES, MAX_HITS, LINE_CAP, MAX_BYTES = 40, 20, 240, 800


def open_packet(pid: str):
    root = paths.SCRATCH / "verify"
    packet = json.loads((root / pid / "packet.json").read_text(encoding="utf-8"))
    entry = json.loads((root / "_index.json").read_text())[pid]
    return packet, contract.read_record(paths.ROOT / entry["report"])


def file_bytes(packet: dict, rec: dict, fid: str) -> bytes:
    f = next((f for f in packet["files"] if f["id"] == fid), None)
    if f is None:
        raise SystemExit(f"no file {fid} in this packet")
    derived = None
    if f["derived"]:  # the derivation id is not in the packet; find it from the record's anchors on that file
        derived = next((a["derived_from"] for _, a in contract.iter_anchors(rec)
                        if a["file"] == f["path"] and a["derived_from"]), None)
    return Package(rec).bytes(f["path"], derived)


def render(lines: list[str], numbers: list[int]) -> str:
    return defang("\n".join(f"{n:6} {lines[n - 1][:LINE_CAP]}" for n in numbers))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("packet_id")
    ap.add_argument("--slice")
    ap.add_argument("--context", type=int, default=10)
    ap.add_argument("--bytes", dest="byte_window", type=int)
    ap.add_argument("--file")
    ap.add_argument("--lines")
    ap.add_argument("--grep")
    args = ap.parse_args()
    packet, rec = open_packet(args.packet_id)
    log = paths.SCRATCH / "verify" / args.packet_id / "access.log"
    with open(log, "a", encoding="utf-8") as f:
        f.write(json.dumps({"argv": sys.argv[2:]}) + "\n")
    try:
        if args.slice:
            s = next((s for s in packet["slices"] if s["id"] == args.slice), None)
            if s is None:
                raise SystemExit(f"no slice {args.slice}")
            raw = file_bytes(packet, rec, s["file"])
            if args.byte_window is not None:
                k = min(args.byte_window, MAX_BYTES)
                start, end = s.get("start", 0), s.get("end", 0)
                lo, hi = max(0, start - k), min(len(raw), end + k)
                window = raw[lo:start] + b" >>> " + raw[start:end] + b" <<< " + raw[end:hi]
                print(defang(f"bytes {lo}-{hi} of {s['file']} (anchor {start}-{end}):\n"
                             + window.decode("utf-8", "replace")))
            else:
                lines = raw.decode("utf-8", "replace").split("\n")
                line = s["line"] or 1
                k = min(args.context, MAX_LINES // 2)
                print(render(lines, list(range(max(1, line - k), min(len(lines), line + k) + 1))))
        elif args.file and args.lines:
            m = re.fullmatch(r"(\d+)-(\d+)", args.lines)
            if not m:
                raise SystemExit("--lines A-B")
            lines = file_bytes(packet, rec, args.file).decode("utf-8", "replace").split("\n")
            a, b = int(m.group(1)), min(int(m.group(2)), int(m.group(1)) + MAX_LINES - 1, len(lines))
            print(render(lines, list(range(max(1, a), b + 1))))
        elif args.file and args.grep:
            lines = file_bytes(packet, rec, args.file).decode("utf-8", "replace").split("\n")
            hits = [i + 1 for i, line in enumerate(lines) if args.grep in line][:MAX_HITS]
            for n in hits:  # long lines: a window around each hit
                line = lines[n - 1]
                at = line.find(args.grep)
                print(defang(f"{n:6} {line[max(0, at - 100):at + 140]}"))
            if not hits:
                print("no hits")
        else:
            ap.error("give --slice, or --file with --lines or --grep")
    except Unanchored as e:
        raise SystemExit(f"code unavailable: {e.reason}")


if __name__ == "__main__":
    main()
