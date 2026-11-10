#!/usr/bin/env python3
"""
Reads package code in windows, so a large or single-line file (a bundle, a recovered string-table file) can be
examined a piece at a time instead of loaded whole. Output is capped and defanged; nothing is executed.

  view.py scratch/<key> <file> [--derived dN] --grep REGEX [--context N] [--max M]   lines/regions matching REGEX
  view.py scratch/<key> <file> [--derived dN] --bytes A-B                            the byte range A..B
  view.py scratch/<key> <file> [--derived dN] --line N [--context K]                 around line N

Files resolve under scratch/<key>/unpacked/<package_root>/ or, with --derived, scratch/<key>/derived/<id>.
Pair with cite.py once you have found the code to cite.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402
from tools.common.sanitize import defang  # noqa: E402

MAX_BYTES = 4000      # per window, before defanging
MAX_HITS = 40         # grep matches shown
WINDOW = 200          # bytes of context around a grep hit on a long line


def resolve(work: Path, file: str, derived: str | None) -> bytes:
    if not work.is_dir():
        raise SystemExit(f"no prepared package at {work}")
    if derived:
        path = work / "derived" / derived
    else:
        root = json.loads((work / "prepared.json").read_text())["package"]["package_root"]
        path = (work / "unpacked" / root / file).resolve()
        if not path.is_relative_to((work / "unpacked").resolve()):
            raise SystemExit("file escapes the package")
    if not path.is_file():
        raise SystemExit(f"no such file: {path}")
    return path.read_bytes()


def line_col(src: bytes, pos: int) -> tuple[int, int]:
    nl = src.rfind(b"\n", 0, pos)
    return src.count(b"\n", 0, pos) + 1, pos - nl


def emit(src: bytes, start: int, end: int, label: str) -> None:
    start, end = max(0, start), min(len(src), end)
    line, col = line_col(src, start)
    body = src[start:end].decode("utf-8", "replace")
    print(f"--- {label} (line {line}, col {col}, bytes {start}-{end})")
    print(defang(body))


def grep(src: bytes, pattern: str, context: int, limit: int) -> None:
    rx = re.compile(pattern.encode(), re.I)
    one_line = src.count(b"\n") <= 1
    shown = 0
    for m in rx.finditer(src):
        if shown >= limit:
            print(f"... more than {limit} matches; narrow the pattern")
            break
        if one_line:
            emit(src, m.start() - WINDOW, m.end() + WINDOW, f"match {shown + 1}")
        else:
            lo = src.rfind(b"\n", 0, m.start()) + 1
            for _ in range(context):
                lo = src.rfind(b"\n", 0, lo - 1) + 1 if lo > 0 else 0
            hi = m.end()
            for _ in range(context + 1):
                nxt = src.find(b"\n", hi)
                hi = len(src) if nxt == -1 else nxt + 1
            emit(src, lo, hi, f"match {shown + 1}")
        shown += 1
    if shown == 0:
        print("no matches")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("work", type=Path)
    ap.add_argument("file")
    ap.add_argument("--derived")
    ap.add_argument("--grep")
    ap.add_argument("--bytes", dest="byte_range")
    ap.add_argument("--line", type=int)
    ap.add_argument("--context", type=int, default=2)
    ap.add_argument("--max", type=int, default=MAX_HITS, dest="limit")
    args = ap.parse_args()
    src = resolve(paths.confine(args.work), args.file, args.derived)
    if args.grep:
        grep(src, args.grep, args.context, args.limit)
    elif args.byte_range:
        m = re.fullmatch(r"(\d+)-(\d+)", args.byte_range)
        if not m:
            ap.error("--bytes A-B")
        a, b = int(m.group(1)), int(m.group(2))
        emit(src, a, min(b, a + MAX_BYTES), "bytes")
    elif args.line:
        lines = src.split(b"\n")
        if not 1 <= args.line <= len(lines):
            ap.error(f"line {args.line} outside 1-{len(lines)}")
        lo = sum(len(x) + 1 for x in lines[:max(0, args.line - 1 - args.context)])
        hi = sum(len(x) + 1 for x in lines[:args.line + args.context])
        emit(src, lo, min(hi, lo + MAX_BYTES), f"lines {args.line}±{args.context}")
    else:
        ap.error("give --grep, --bytes or --line")


if __name__ == "__main__":
    main()
