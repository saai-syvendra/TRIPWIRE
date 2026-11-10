#!/usr/bin/env python3
"""
Prints the anchor for a piece of package code, so a record can cite it: a condition site, a guard, a branch
region, a call, a function definition or a sink. Anchors are checked byte for byte by write_report.py, so cite
code with this tool instead of typing offsets.

  cite.py scratch/<key> FILE --line N --text SNIPPET [--type NODE_TYPE] [--nth K]
      the smallest syntax node on line N whose text contains SNIPPET (exact text wins)
  cite.py scratch/<key> FILE --line N --to-line M
      the statements from the one starting on line N to the one ending on line M (a branch region)
  add --derived dN to cite inside a derived file (scratch/<key>/derived/dN) instead of the package file.

Package files are parsed with tree-sitter as data; nothing is executed. The preview is defanged.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import anchors, paths  # noqa: E402
from tools.common.sanitize import defang  # noqa: E402
from tools.common.tsparse import EXTENSIONS, PARSERS, descendants  # noqa: E402

BLOCKS = {"statement_block", "program", "block", "module", "switch_body", "class_body"}


def derivation(work: Path, prepared: dict, did: str) -> dict:
    """A derivation by id: the analyst's record.json (where a decode_spec from register_decode.py is registered) first,
    then the prepared skeleton (string tables and inline hooks found by prepare.py)."""
    records = [prepared.get("record") or {}]
    if (work / "record.json").is_file():
        records.insert(0, json.loads((work / "record.json").read_text(encoding="utf-8")))
    for rec in records:
        for d in rec.get("normalisation", {}).get("derivations", []):
            if d["id"] == did:
                return d
    return {}


def load(work: Path, file: str, derived: str | None) -> tuple[bytes, str | None]:
    prepared = json.loads((work / "prepared.json").read_text(encoding="utf-8"))
    if derived:
        path = work / "derived" / derived
        d = derivation(work, prepared, derived)
        params = d.get("params", {})
        if d.get("recipe") == "decode_spec" and params.get("lang"):
            lang = params["lang"]
        else:
            lang = "py" if str(params.get("flag", "")).startswith("-c") else EXTENSIONS.get(Path(file).suffix.lower(), "js")
    else:
        path = (work / "unpacked" / prepared["package"]["package_root"] / file).resolve()
        if not path.is_relative_to((work / "unpacked").resolve()):
            raise SystemExit("file escapes the package")
        lang = EXTENSIONS.get(Path(file).suffix.lower())
    if not path.is_file():
        raise SystemExit(f"no such file: {path}")
    return path.read_bytes(), lang


def line_bounds(src: bytes, line: int) -> tuple[int, int]:
    lines = src.split(b"\n")
    if not 1 <= line <= len(lines):
        raise SystemExit(f"line {line} is outside the file (1-{len(lines)})")
    start = sum(len(x) + 1 for x in lines[:line - 1])
    return start, start + len(lines[line - 1])


def pick(hits: list, nth: int | None, snippet: str, line: int):
    if not hits:
        raise SystemExit(f"{snippet!r} not found on line {line}")
    if len(hits) > 1 and nth is None:
        raise SystemExit(f"{snippet!r} matches {len(hits)} places on line {line}; pass --nth 1..{len(hits)}")
    if not 1 <= (nth or 1) <= len(hits):
        raise SystemExit(f"--nth must be 1..{len(hits)}")
    return hits[(nth or 1) - 1]


def cite_text(src: bytes, line: int, snippet: str, nth: int | None) -> int:
    lo, hi = line_bounds(src, line)
    needle, hits, i = snippet.encode(), [], lo
    while (i := src.find(needle, i, hi)) != -1:
        hits.append(i)
        i += 1
    return pick(hits, nth, snippet, line)


def cite_node(src: bytes, lang: str, line: int, snippet: str, node_type: str | None, nth: int | None):
    lo, hi = line_bounds(src, line)
    tree = PARSERS[lang].parse(src)
    best = []
    for n in descendants(tree.root_node):
        if not n.is_named or n.end_byte <= lo or n.start_byte >= hi:
            continue
        if not lo <= n.start_byte < hi or (node_type and n.type != node_type):
            continue
        body = src[n.start_byte:n.end_byte].decode("utf-8", "replace")
        if snippet in body:
            best.append(n)
    if not best:
        raise SystemExit(f"no {node_type or 'syntax'} node starting on line {line} contains {snippet!r}")
    exact = [n for n in best if src[n.start_byte:n.end_byte].decode("utf-8", "replace").strip() == snippet.strip()]
    pool = exact or best
    size = min(n.end_byte - n.start_byte for n in pool)
    pool = sorted({(n.start_byte, n.end_byte): n for n in pool if n.end_byte - n.start_byte == size}.values(),
                  key=lambda n: n.start_byte)
    return pick(pool, nth, snippet, line)


def depth_of(node) -> int:
    d, n = 0, node.parent
    while n is not None:
        d, n = d + 1, n.parent
    return d


def cite_range(src: bytes, lang: str, line: int, to_line: int):
    """The run of sibling statements that starts on `line` and ends on `to_line`. When blocks at several depths
    qualify (minified code, where an outer and an inner block share the lines) the range is ambiguous and is
    refused rather than guessed, as is a run that is the whole of a one-line file."""
    tree = PARSERS[lang].parse(src)
    lo, _ = line_bounds(src, line)
    _, hi = line_bounds(src, to_line)
    found = []
    for n in descendants(tree.root_node):
        if n.type not in BLOCKS:
            continue
        stmts = [c for c in n.named_children if c.type != "comment"]
        first = next((c for c in stmts if lo <= c.start_byte), None)
        inside = [c for c in stmts if first is not None and c.start_byte >= first.start_byte and c.end_byte <= hi]
        if first is not None and inside and inside[0] is first and first.start_byte < hi and \
                src.count(b"\n", 0, first.start_byte) + 1 == line and \
                src.count(b"\n", 0, inside[-1].end_byte) + 1 == to_line:
            found.append((depth_of(n), n, first, inside[-1]))
    if not found:
        raise SystemExit(f"no run of sibling statements from line {line} to line {to_line}")
    if len(found) > 1:
        raise SystemExit(f"lines {line}-{to_line} hold {len(found)} nested statement runs; cite the statement with "
                         "--text instead")
    _, block, first, last = found[0]
    if block.type in ("program", "module") and not src[:first.start_byte].strip() and \
            not src[last.end_byte:].strip() and line == to_line:
        raise SystemExit(f"lines {line}-{to_line} are the whole file; cite the statement with --text instead")
    return first, last


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("work", type=Path)
    ap.add_argument("file")
    ap.add_argument("--line", type=int, required=True)
    ap.add_argument("--text")
    ap.add_argument("--to-line", type=int)
    ap.add_argument("--type", dest="node_type")
    ap.add_argument("--nth", type=int)
    ap.add_argument("--derived")
    args = ap.parse_args()
    if (args.text is None) == (args.to_line is None):
        ap.error("give exactly one of --text or --to-line")
    if args.to_line is not None and (args.node_type or args.nth):
        ap.error("--type and --nth apply to --text only; --to-line cites a run of whole statements")

    src, lang = load(paths.confine(args.work), args.file, args.derived)
    if args.to_line is not None:
        if lang is None:
            ap.error("--to-line needs a parsed (.js/.py) file")
        first, last = cite_range(src, lang, args.line, args.to_line)
        anchor = anchors.span_anchor(args.file, src, first, last, args.derived)
    elif lang is None:
        start = cite_text(src, args.line, args.text, args.nth)
        anchor = anchors.range_anchor(args.file, src, start, start + len(args.text.encode()), anchors.TEXT,
                                      args.derived)
    else:
        node = cite_node(src, lang, args.line, args.text, args.node_type, args.nth)
        anchor = anchors.node_anchor(args.file, src, node, args.derived)
    preview = src[anchor["start_byte"]:anchor["end_byte"]].decode("utf-8", "replace")
    preview = defang(preview if len(preview) <= 160 else preview[:120] + " … " + preview[-30:])
    print(json.dumps(anchor))
    print(f"# {anchor['node_type']}, {anchor['end_byte'] - anchor['start_byte']} bytes from line {anchor.get('line')}: "
          f"{preview}", file=sys.stderr)


if __name__ == "__main__":
    main()
