#!/usr/bin/env python3
"""
List the registered decoders under tools/common/decoders/ with the Family, Reverses and Per sample lines of each
docstring, so an analyst reuses a decoder that fits before writing a new one:

  list_decoders.py              every decoder, one block each
  list_decoders.py WORD ...     only decoders whose header mentions every WORD (case-insensitive), e.g. fernet

Reuse one with `register_decode.py scratch/<key> --decoder NAME ...` and this package's own params. Reads the
modules as text (ast); imports none of them.
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402

FIELDS = ("Family", "Reverses", "Per sample")
SKIP = ("__init__", "example_xor")
_FIELD = re.compile(r"^(Family|Reverses|Per sample):\s*(.*)$")


def header(src: str) -> dict[str, str]:
    """The Family / Reverses / Per sample fields of a decoder's docstring, continuation lines joined."""
    doc = ast.get_docstring(ast.parse(src)) or ""
    out: dict[str, str] = {}
    field = None
    for line in doc.splitlines():
        m = _FIELD.match(line.strip())
        if m:
            field = m.group(1)
            out[field] = m.group(2).strip()
        elif field and line.startswith(" ") and line.strip():
            out[field] += " " + line.strip()
        else:
            field = None
    return out


def decoders(directory: Path | None = None) -> list[tuple[str, dict[str, str]]]:
    directory = directory or paths.CODE_ROOT / "tools" / "common" / "decoders"
    found = []
    for path in sorted(directory.glob("*.py")):
        if path.stem in SKIP or path.stem.startswith("test_"):
            continue
        try:
            found.append((path.stem, header(path.read_text(encoding="utf-8"))))
        except (SyntaxError, UnicodeDecodeError):
            found.append((path.stem, {}))
    return found


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("words", nargs="*", help="only decoders whose header mentions every word")
    args = ap.parse_args()
    shown = 0
    for name, head in decoders():
        blob = " ".join(head.values()).lower()
        if not all(w.lower() in blob for w in args.words):
            continue
        shown += 1
        print(name)
        for f in FIELDS:
            print(f"  {f + ':':12} {head.get(f, '(missing)')}")
    if not shown:
        print("no decoder matches" if args.words else "no decoders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
