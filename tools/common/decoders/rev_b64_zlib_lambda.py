"""
Family:     Python droppers wrapped by the "_ = lambda __: zlib.decompress(b64decode(__[::-1])); exec((_)(b'...'))"
            obfuscator, usually nested many layers deep
Reverses:   reversed base64 of zlib data, handed to a one-argument lambda bound to a name and executed
Per sample: none (params.max_layers optionally caps the nesting, default 200)

decode() returns the input source with every `exec((<name>)(<bytes literal>))` statement replaced in place by the
decoded source (indented to the call's column), where <name> is assigned in the same source a lambda whose body is
zlib.decompress(base64.b64decode(<param>[::-1])) (the modules may be reached through __import__('...')). The output
is decoded again until no such call is left or max_layers is reached. A literal that does not decode, or decodes to
something that is not UTF-8, is left untouched.

Only the literals are read (as data); nothing is imported, compiled, run or evaluated. Pure and deterministic:
stdlib base64/zlib/re plus tree-sitter.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib

from tools.common.tsparse import PARSERS, descendants, text

MAX_LAYERS = 200
_LIT = re.compile(r"""^[bB]?(['"])(.*)\1$""", re.S)
_BODY = re.compile(r"""^__import__\(['"]zlib['"]\)\.decompress\(__import__\(['"]base64['"]\)\.b64decode\((\w+)\[::-1\]\)\)$"""
                   r"""|^zlib\.decompress\(base64\.b64decode\((\w+)\[::-1\]\)\)$""")


def _decoder_names(root) -> set[str]:
    names = set()
    for node in descendants(root):
        if node.type != "assignment":
            continue
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left is None or right is None or left.type != "identifier" or right.type != "lambda":
            continue
        params = right.child_by_field_name("parameters")
        body = right.child_by_field_name("body")
        if params is None or body is None or len(params.named_children) != 1:
            continue
        m = _BODY.match(re.sub(r"\s+", "", text(body)))
        if m and (m.group(1) or m.group(2)) == text(params.named_children[0]):
            names.add(text(left))
    return names


def _callee_name(fn) -> str | None:
    while fn is not None and fn.type == "parenthesized_expression" and len(fn.named_children) == 1:
        fn = fn.named_children[0]
    return text(fn) if fn is not None and fn.type == "identifier" else None


def _payload(arg, names: set[str]) -> bytes | None:
    if arg.type != "call" or _callee_name(arg.child_by_field_name("function")) not in names:
        return None
    args = [a for a in arg.child_by_field_name("arguments").named_children if a.type != "comment"]
    if len(args) != 1 or args[0].type != "string":
        return None
    m = _LIT.match(text(args[0]))
    if not m:
        return None
    try:
        raw = base64.b64decode(re.sub(r"\s+", "", m.group(2))[::-1], validate=True)
        return zlib.decompress(raw)
    except (binascii.Error, ValueError, zlib.error):
        return None


def _one_layer(src: bytes) -> tuple[bytes, int]:
    root = PARSERS["py"].parse(src).root_node
    names = _decoder_names(root)
    if not names:
        return src, 0
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
            continue
        plain = _payload(args[0], names)
        if plain is None:
            continue
        try:
            stage = plain.decode("utf-8")
        except UnicodeDecodeError:
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
