"""
Family:     Python stages that alias exec (`X=exec`) and run `X(zlib.decompress(xorfn(base64.b85decode("..."+"..."), KEY)))`
            with KEY = bytes([..ints..]) and xorfn the repeating-key XOR `bytes(d[i]^k[i%len(k)] for i in range(len(d)))`,
            or the fallback `X(zlib.decompress(base64.b64decode("...")))`
Reverses:   base85 / base64 decode, repeating-key XOR with a key literal in the same source, zlib
Per sample: none (params.max_layers optionally caps the nesting, default 20)

decode() returns the input source with every such exec statement replaced in place by the decoded source (indented
to the call's column). Module objects may be bound to names (`m=__import__('zlib')`) or imported plainly. Calls are
recognised by attribute name only (decompress, b85decode, b64decode); the XOR helper is recognised by its body shape.
A stage that does not decode, or is not UTF-8, is left untouched.

Only literals are read (as data); nothing is imported, compiled, run or evaluated. Pure and deterministic.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib

from tools.common.tsparse import PARSERS, descendants, text

MAX_LAYERS = 20
_LIT = re.compile(r"""^[bB]?(['"])(.*)\1$""", re.S)
_XOR_BODY = re.compile(r"^returnbytes\((\w+)\[(\w+)\]\^(\w+)\[\2%len\(\3\)\]for\2inrange\(len\(\1\)\)\)$")


class _Fail(Exception):
    pass


def _scan(root):
    aliases, xorfns, assigns = {"exec"}, set(), {}
    for node in descendants(root):
        if node.type == "assignment":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if left is not None and right is not None and left.type == "identifier":
                assigns[text(left)] = right
                if right.type == "identifier" and text(right) == "exec":
                    aliases.add(text(left))
        elif node.type == "function_definition":
            body = node.child_by_field_name("body")
            params = node.child_by_field_name("parameters")
            if body is None or params is None or len(params.named_children) != 2:
                continue
            m = _XOR_BODY.match(re.sub(r"\s+", "", text(body)))
            if m and [text(p) for p in params.named_children] == [m.group(1), m.group(3)]:
                xorfns.add(text(node.child_by_field_name("name")))
    return aliases, xorfns, assigns


def _value(node, xorfns, assigns, depth=0):
    if depth > 20:
        raise _Fail
    while node.type == "parenthesized_expression" and len(node.named_children) == 1:
        node = node.named_children[0]
    if node.type == "string":
        if any(c.type == "interpolation" for c in node.named_children):
            raise _Fail
        m = _LIT.match(text(node))
        if not m:
            raise _Fail
        return m.group(2).encode("latin-1")
    if node.type == "concatenated_string":
        return b"".join(_value(c, xorfns, assigns, depth + 1) for c in node.named_children)
    if node.type == "binary_operator" and text(node.child_by_field_name("operator")) == "+":
        parts = []
        while node.type == "binary_operator" and text(node.child_by_field_name("operator")) == "+":
            parts.append(node.child_by_field_name("right"))
            node = node.child_by_field_name("left")
        parts.append(node)
        return b"".join(_value(p, xorfns, assigns, depth + 1) for p in reversed(parts))
    if node.type == "identifier" and text(node) in assigns:
        return _value(assigns[text(node)], xorfns, assigns, depth + 1)
    if node.type != "call":
        raise _Fail
    fn = node.child_by_field_name("function")
    args = [a for a in node.child_by_field_name("arguments").named_children if a.type != "comment"]
    if fn.type == "identifier" and text(fn) == "bytes" and len(args) == 1 and args[0].type == "list":
        try:
            return bytes(int(text(x), 0) for x in args[0].named_children)
        except ValueError:
            raise _Fail
    if fn.type == "identifier" and text(fn) in xorfns and len(args) == 2:
        d = _value(args[0], xorfns, assigns, depth + 1)
        k = _value(args[1], xorfns, assigns, depth + 1)
        if not k:
            raise _Fail
        return bytes(d[i] ^ k[i % len(k)] for i in range(len(d)))
    if fn.type == "attribute" and len(args) == 1:
        attr = text(fn.child_by_field_name("attribute"))
        inner = _value(args[0], xorfns, assigns, depth + 1)
        try:
            if attr == "decompress":
                return zlib.decompress(inner)
            if attr == "b85decode":
                return base64.b85decode(inner)
            if attr == "b64decode":
                return base64.b64decode(re.sub(rb"\s+", b"", inner), validate=True)
        except (binascii.Error, ValueError, zlib.error):
            raise _Fail
    raise _Fail


def _one_layer(src: bytes) -> tuple[bytes, int]:
    root = PARSERS["py"].parse(src).root_node
    aliases, xorfns, assigns = _scan(root)
    edits = []
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) not in aliases:
            continue
        args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
        stmt = call.parent
        if len(args) != 1 or stmt is None or stmt.type != "expression_statement" or len(stmt.named_children) != 1:
            continue
        if args[0].type != "call":
            continue
        try:
            stage = _value(args[0], xorfns, assigns).decode("utf-8")
        except (_Fail, UnicodeDecodeError):
            continue
        pad = " " * call.start_point[1]
        lines = stage.splitlines(keepends=True)
        body = "".join(line if i == 0 or not line.strip() else pad + line for i, line in enumerate(lines))
        edits.append((call.start_byte, call.end_byte, body.rstrip("\n").encode("utf-8")))
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
