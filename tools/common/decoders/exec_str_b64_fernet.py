"""
Family:     PyPI setup.py droppers that nest stages as exec("<escaped source>") -> exec(b64decode('<lit>')) ->
            exec(Fernet(bytes(b64decode(KEYVAR))).decrypt(b'<token>')), with module aliases (b_, _b)
Reverses:   escaped string literals handed to exec, base64 literals handed to <any>.b64decode and executed, and
            Fernet tokens whose key is a literal or b64decode/bytes of a name assigned a literal in the same stage
Per sample: none (params.max_depth optionally caps the nesting, default 8)

decode() returns the input source with every such exec(...) statement replaced in place by the plaintext of its
stage, recursively, indented to the call's column. Stages that do not decode or verify (Fernet HMAC, padding,
UTF-8) are left untouched. Literals are read as data only; nothing is compiled, imported or run.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import re

from tools.common.decoders.fernet_exec import fernet_decrypt
from tools.common.tsparse import PARSERS, descendants, text

_STR = re.compile(r"""^([bBuUrR]{0,2})('''|\"\"\"|'|")(.*)\2$""", re.S)
_LINE_ASSIGN = re.compile(r"""^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*(['"])([A-Za-z0-9+/_=\-]+)\2[ \t]*$""", re.M)


def _str_value(node) -> str | None:
    if node is None or node.type != "string" or any(c.type == "interpolation" for c in node.named_children):
        return None
    m = _STR.match(text(node))
    if not m:
        return None
    prefix, body = m.group(1).lower(), m.group(3)
    if "r" in prefix:
        return body
    try:
        return codecs.decode(body.encode("latin-1"), "unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
        return None


def _args(call):
    a = call.child_by_field_name("arguments")
    return [] if a is None else [c for c in a.named_children if c.type != "comment"]


def _attr_name(fn) -> str | None:
    if fn is None:
        return None
    if fn.type == "identifier":
        return text(fn)
    if fn.type == "attribute":
        return text(fn.child_by_field_name("attribute"))
    return None


def _assigned_literals(root) -> dict:
    out = {}
    for n in descendants(root):
        if n.type == "assignment":
            left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
            if left is not None and left.type == "identifier":
                v = _str_value(right)
                if v is not None:
                    out[text(left)] = v
    for m in _LINE_ASSIGN.finditer(text(root)):  # assignments tree-sitter left inside an ERROR node
        out.setdefault(m.group(1), m.group(3))
    return out


def _b64_arg(node, names) -> bytes | None:
    """bytes of b64decode(<literal or name>) [wrapped in bytes(...) or .decode(...)]."""
    if node is None or node.type != "call":
        return None
    fn = node.child_by_field_name("function")
    if fn is not None and fn.type == "identifier" and text(fn) == "bytes" and len(_args(node)) == 1:
        return _b64_arg(_args(node)[0], names)
    if fn is not None and fn.type == "attribute" and _attr_name(fn) == "decode":
        return _b64_arg(fn.child_by_field_name("object"), names)
    if _attr_name(fn) != "b64decode" or len(_args(node)) != 1:
        return None
    a = _args(node)[0]
    lit = names.get(text(a)) if a.type == "identifier" else _str_value(a)
    if lit is None:
        return None
    try:
        return base64.b64decode(re.sub(r"\s+", "", lit), validate=True)
    except (binascii.Error, ValueError):
        return None


def _fernet(node, names) -> bytes | None:
    if node is None or node.type != "call":
        return None
    fn = node.child_by_field_name("function")
    if fn is None or fn.type != "attribute" or _attr_name(fn) != "decrypt" or len(_args(node)) != 1:
        return None
    ctor = fn.child_by_field_name("object")
    if ctor is None or ctor.type != "call" or len(_args(ctor)) != 1:
        return None
    karg = _args(ctor)[0]
    key = _b64_arg(karg, names)
    if key is None:
        v = _str_value(karg)
        key = v.encode("latin-1") if v is not None else None
    tok = _str_value(_args(node)[0])
    if key is None or tok is None:
        return None
    try:
        return fernet_decrypt(key, tok.encode("latin-1"))
    except ValueError:
        return None


def _stage(arg, names) -> str | None:
    s = _str_value(arg)
    if s is not None:
        return s
    raw = _b64_arg(arg, names)
    if raw is None:
        raw = _fernet(arg, names)
    if raw is None:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _flatten(src: str, depth: int) -> str:
    if depth <= 0:
        return src
    data = src.encode("utf-8")
    root = PARSERS["py"].parse(data).root_node
    names = _assigned_literals(root)
    edits = []
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != "exec" or len(_args(call)) != 1:
            continue
        stmt = call.parent
        if stmt is None or stmt.type not in ("expression_statement", "ERROR", "module", "block"):
            continue
        if stmt.type == "expression_statement" and len(stmt.named_children) != 1:
            continue
        stage = _stage(_args(call)[0], names)
        if stage is None:
            continue
        body = _flatten(stage.strip("\n"), depth - 1)
        pad = " " * call.start_point[1]
        lines = body.split("\n")
        body = "\n".join([lines[0]] + [pad + ln if ln.strip() else ln for ln in lines[1:]])
        edits.append((call.start_byte, call.end_byte, body.encode("utf-8")))
    out = bytearray(data)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return _fernet_text(out.decode("utf-8"), names, depth)


# `exec (F (bytes (B .b64decode (NAME ))).decrypt (b'<token>')[.decode ()])`, which tree-sitter does not always give as a call
# (a spaced `exec (` can parse as a Python 2 exec statement), matched on the text instead.
_FERNET_EXEC = re.compile(r"""exec\s*\(\s*\w+\s*\(\s*(?:bytes\s*\(\s*)?\w+\s*\.\s*b64decode\s*\(\s*(\w+)\s*\)\s*\)?\s*\)"""
                          r"""\s*\.\s*decrypt\s*\(\s*b(['"])([A-Za-z0-9_=#\-]+)\2\s*\)(?:\s*\.\s*decode\s*\(\s*\))?\s*\)""")


def _fernet_text(src: str, names: dict, depth: int) -> str:
    def repl(m):
        lit = names.get(m.group(1))
        if lit is None:
            return m.group(0)
        try:
            key = base64.b64decode(lit, validate=True)
            plain = fernet_decrypt(key, m.group(3).encode("ascii")).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return m.group(0)
        col = m.start() - (src.rfind("\n", 0, m.start()) + 1)
        lines = _flatten(plain.strip("\n"), depth - 1).split("\n")
        return "\n".join([lines[0]] + [" " * col + ln if ln.strip() else ln for ln in lines[1:]])
    return _FERNET_EXEC.sub(repl, src)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    return _flatten(input_bytes.decode("utf-8"), int(params.get("max_depth", 8))).encode("utf-8")
