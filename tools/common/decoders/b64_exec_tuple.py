"""
Family:     PyPI setup.py droppers that hide `exec(b64decode('<literal>'))` as the last item of a tuple expression
            statement padded with whitespace (`type("By HW")   ...   ,exec(base64.b64decode("..."))`)
Reverses:   a base64 string literal handed to base64.b64decode / b64decode and executed, when the exec call is a
            statement of its own or an element of an expression_list that is a statement of its own
Per sample: none

decode() returns the input source with each such statement replaced in place: every element of the tuple is
written as its own statement in order, and the exec call is replaced by the decoded source, indented to the
statement's column. Literals that are not valid base64 or do not decode to UTF-8 are left untouched.

Only the literals are read (as data); nothing is imported, compiled, run or evaluated.
"""
import base64
import binascii
import re

from tools.common.tsparse import PARSERS, descendants, text

_STR = re.compile(r"""^(?:[bBuU]|[bB][rR]|[rR][bB])?(['"]{1,3})(.*)\1$""", re.S)


def _literal(node):
    if node is None or node.type != "string":
        return None
    if any(c.type == "interpolation" for c in node.named_children):
        return None
    m = _STR.match(text(node))
    return m.group(2).encode("ascii", "ignore") if m else None


def _is_b64decode(fn):
    if fn is None:
        return False
    if fn.type == "identifier":
        return text(fn) == "b64decode"
    if fn.type != "attribute" or text(fn.child_by_field_name("attribute")) != "b64decode":
        return False
    obj = fn.child_by_field_name("object")
    return obj is not None and obj.type == "identifier" and text(obj) == "base64"


def _exec_payload(call):
    """Decoded stage text when `call` is exec(b64decode(<literal>)), else None."""
    if call.type != "call":
        return None
    f = call.child_by_field_name("function")
    if f is None or f.type != "identifier" or text(f) != "exec":
        return None
    args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
    if len(args) != 1 or args[0].type != "call" or not _is_b64decode(args[0].child_by_field_name("function")):
        return None
    inner = [a for a in args[0].child_by_field_name("arguments").named_children if a.type != "comment"]
    if len(inner) != 1:
        return None
    lit = _literal(inner[0])
    if lit is None:
        return None
    try:
        return base64.b64decode(re.sub(rb"\s+", b"", lit), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def _indent(src, col):
    pad = " " * col
    lines = src.splitlines()
    return "\n".join(line if i == 0 or not line.strip() else pad + line for i, line in enumerate(lines))


def decode(input_bytes, params, read):
    root = PARSERS["py"].parse(input_bytes).root_node
    edits = []
    for stmt in (n for n in descendants(root) if n.type == "expression_statement"):
        kids = [c for c in stmt.named_children if c.type != "comment"]
        if len(kids) == 1 and kids[0].type == "expression_list":
            kids = [c for c in kids[0].named_children if c.type != "comment"]
        elems = kids
        stages = [_exec_payload(e) for e in elems]
        if not any(s is not None for s in stages):
            continue
        col = stmt.start_point[1]
        parts = [s if s is not None else text(e) for e, s in zip(elems, stages)]
        body = ("\n" + " " * col).join(_indent(p, col) for p in parts)
        edits.append((stmt.start_byte, stmt.end_byte, body.encode("utf-8")))
    out = bytearray(input_bytes)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out)
