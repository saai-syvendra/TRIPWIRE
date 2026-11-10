"""
Family:     PyPI setup.py droppers that run a stage with `exec(b64decode('<literal>'))`, often per OS branch
Reverses:   a base64 string or bytes literal handed to b64decode (base64.b64decode, __import__('base64').b64decode)
            and executed, optionally through .decode(...); nested layers of the same shape
Per sample: none (params.max_layers optionally caps the nesting, default 4)

decode() returns the input source with every `exec(<b64decode of a literal>)` call replaced in place by the decoded
source, so the guards around it (`if name == 'nt': exec(...)`) stay in the same file and the result still parses.
A call that is a statement of its own is replaced by the decoded statements, indented to the call's column (lines
that continue a multi-line string are left as they are, read with the tokenizer). A call used as an expression is
left untouched. The output is decoded again until no such call is left or max_layers is reached. A literal that is
not valid base64, or decodes to something that is not UTF-8 Python that tokenizes, is left untouched.

Only the literals are read (as data, by hand); nothing is imported, compiled, run or evaluated. Pure and
deterministic: stdlib base64/io/tokenize plus tree-sitter.
"""
from __future__ import annotations

import base64
import binascii
import io
import re
import tokenize

from tools.common.tsparse import PARSERS, descendants, text

_STR = re.compile(r"""^(?:[bBuU]|[bB][rR]|[rR][bB])?(['"]{1,3})(.*)\1$""", re.S)
MAX_LAYERS = 4


def _literal(node) -> bytes | None:
    """The bytes of a plain (or implicitly concatenated) string literal, no interpolation, no escapes needed for
    base64."""
    if node is None:
        return None
    if node.type == "concatenated_string":
        parts = [_literal(c) for c in node.named_children]
        return b"".join(parts) if all(p is not None for p in parts) else None
    if node.type != "string" or any(c.type == "interpolation" for c in node.named_children):
        return None
    m = _STR.match(text(node))
    return m.group(2).encode("ascii", "ignore") if m else None


def _is_b64decode(fn) -> bool:
    """b64decode, base64.b64decode, or __import__('base64').b64decode."""
    if fn is None:
        return False
    if fn.type == "identifier":
        return text(fn) == "b64decode"
    if fn.type != "attribute" or text(fn.child_by_field_name("attribute")) != "b64decode":
        return False
    obj = fn.child_by_field_name("object")
    if obj is not None and obj.type == "identifier":
        return text(obj) == "base64"
    if obj is not None and obj.type == "call" and text(obj.child_by_field_name("function")) == "__import__":
        args = [a for a in obj.child_by_field_name("arguments").named_children if a.type != "comment"]
        return len(args) == 1 and _literal(args[0]) == b"base64"
    return False


def _payload(arg) -> bytes | None:
    """The decoded bytes when `arg` is b64decode(<literal>) or b64decode(<literal>).decode(...)."""
    node = arg
    if node.type == "call":
        f = node.child_by_field_name("function")
        if f is not None and f.type == "attribute" and text(f.child_by_field_name("attribute")) == "decode":
            node = f.child_by_field_name("object")
    if node is None or node.type != "call" or not _is_b64decode(node.child_by_field_name("function")):
        return None
    args = [a for a in node.child_by_field_name("arguments").named_children if a.type != "comment"]
    if len(args) != 1:
        return None
    lit = _literal(args[0])
    if lit is None:
        return None
    try:
        return base64.b64decode(re.sub(rb"\s+", b"", lit), validate=True)
    except (binascii.Error, ValueError):
        return None


def _continuation_lines(src: str) -> set[int]:
    """1-based line numbers that start inside a multi-line string token (their text must not be re-indented)."""
    out = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type == tokenize.STRING and tok.end[0] > tok.start[0]:
                out.update(range(tok.start[0] + 1, tok.end[0] + 1))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        raise ValueError("decoded stage does not tokenize as Python")
    return out


def _indented(src: str, col: int) -> str:
    """The stage's statements at column `col`: every line but the first (which takes the call's place) gets `col`
    spaces, except lines inside a multi-line string."""
    keep = _continuation_lines(src)
    lines = src.splitlines(keepends=True)
    pad = " " * col
    return "".join(line if i == 0 or (i + 1) in keep or not line.strip() else pad + line
                   for i, line in enumerate(lines)).rstrip("\n")


def _one_layer(src: bytes) -> tuple[bytes, int]:
    root = PARSERS["py"].parse(src).root_node
    edits = []
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != "exec":
            continue
        args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 1:
            continue
        stmt = call.parent
        if stmt is None or stmt.type != "expression_statement" or len(stmt.named_children) != 1:
            continue  # exec used as an expression: splicing statements there would not parse
        plain = _payload(args[0])
        if plain is None:
            continue
        try:
            stage = plain.decode("utf-8")
            body = _indented(stage, call.start_point[1])
        except (UnicodeDecodeError, ValueError):
            continue
        edits.append((call.start_byte, call.end_byte, body.encode("utf-8")))
    out = bytearray(src)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out), len(edits)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    out = input_bytes
    for _ in range(int(params.get("max_layers", MAX_LAYERS))):
        out, n = _one_layer(out)
        if not n:
            break
    return out
