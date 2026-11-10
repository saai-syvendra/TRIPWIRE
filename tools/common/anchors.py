"""
Anchors: machine-checkable pointers into package code. An anchor names a file (or a derived file, by
derivation id), a byte range, the tree-sitter node type found there and a short SHA-256 of exactly those bytes.
Anyone holding the sample can rebuild the bytes and confirm that a claim points at real code.

Candidate ids are content ids over the anchor, so they stay stable when unrelated code changes.
"""
from __future__ import annotations

import hashlib

from tree_sitter import Node

HASH_LEN = 16
RANGE = "stmt_range"  # consecutive sibling statements, e.g. the code after an early exit
TEXT = "text"         # a byte range in a file that is not parsed (a hook command in a manifest)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:HASH_LEN]


def line_of(src: bytes, offset: int) -> int:
    return src.count(b"\n", 0, offset) + 1


def range_anchor(file: str, src: bytes, start: int, end: int, node_type: str, derived_from: str | None = None) -> dict:
    return {"file": file, "derived_from": derived_from, "start_byte": start, "end_byte": end, "node_type": node_type,
            "sha256": digest(src[start:end]), "line": line_of(src, start)}


def node_anchor(file: str, src: bytes, node: Node, derived_from: str | None = None) -> dict:
    return range_anchor(file, src, node.start_byte, node.end_byte, node.type, derived_from)


def span_anchor(file: str, src: bytes, first: Node, last: Node | None = None, derived_from: str | None = None) -> dict:
    """One node, or the statements from first to last as a stmt_range."""
    if last is None or (last.start_byte == first.start_byte and last.end_byte == first.end_byte):
        return node_anchor(file, src, first, derived_from)
    return range_anchor(file, src, first.start_byte, last.end_byte, RANGE, derived_from)


def candidate_id(prefix: str, anchor: dict, kind: str = "") -> str:
    key = f"{anchor['file']}|{anchor['derived_from']}|{anchor['start_byte']}|{anchor['end_byte']}|{kind}"
    return f"{prefix}_{hashlib.sha256(key.encode()).hexdigest()[:10]}"


def mismatch(anchor: dict, src: bytes | None) -> str | None:
    """Why the anchor does not hold against src, or None when the bytes match."""
    if src is None:
        return "file_missing"
    start, end = anchor["start_byte"], anchor["end_byte"]
    if not 0 <= start <= end <= len(src):
        return "out_of_range"
    if digest(src[start:end]) != anchor["sha256"]:
        return "hash_mismatch"
    return None


def contains(outer: dict, inner: dict) -> bool:
    """inner lies within outer in the same (possibly derived) file."""
    return (outer["file"], outer["derived_from"]) == (inner["file"], inner["derived_from"]) and \
        outer["start_byte"] <= inner["start_byte"] and inner["end_byte"] <= outer["end_byte"]


def short(anchor: dict) -> str:
    """Human-readable location, e.g. lib/x.js:12 or bundle.js[d1]:1."""
    where = f"{anchor['file']}[{anchor['derived_from']}]" if anchor.get("derived_from") else anchor["file"]
    return f"{where}:{anchor.get('line', '?')}"
