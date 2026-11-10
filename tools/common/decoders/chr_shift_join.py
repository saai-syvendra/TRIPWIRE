"""
Family:     PyPI setup.py droppers obfuscated with chr-from-builtins string building and opaque integer states
            (`''.join(map(<getter of chr>, [(3 << 5) - 1, ...]))`, `while state: if 108363 == state: ...`)
Reverses:   constant integer expressions (+ - * // % << >> & | ^ ~ and parentheses over int literals) are folded to
            their value; `''.join(map(<getter>, [<constant ints>]))` becomes the string literal of those code points
Per sample: params.chr_getter (the exact source text of the map's first argument, which resolves to chr)

decode() returns the input source with every maximal constant integer expression replaced by its decimal value and
every matching join call replaced by a string literal, so the result still parses. Only literals are read, as data;
the arithmetic is done by this module over parsed integer literals, nothing from the package is evaluated.
"""
from __future__ import annotations

from tools.common.tsparse import PARSERS, descendants, text

MAX_SHIFT = 100000
MAX_BITS = 1000000

_BIN = {
    "+": lambda a, b: a + b,
    "-": lambda a, b: a - b,
    "*": lambda a, b: a * b,
    "//": lambda a, b: a // b,
    "%": lambda a, b: a % b,
    "&": lambda a, b: a & b,
    "|": lambda a, b: a | b,
    "^": lambda a, b: a ^ b,
}


def _int(node):
    """The value of a constant integer expression, or None."""
    t = node.type
    if t == "integer":
        s = text(node).replace("_", "").lower()
        if s.startswith("0x"):
            return int(s[2:], 16)
        if s.startswith("0o"):
            return int(s[2:], 8)
        if s.startswith("0b"):
            return int(s[2:], 2)
        if s.isdigit():
            return int(s)
        return None
    if t == "parenthesized_expression":
        inner = [c for c in node.named_children if c.type != "comment"]
        return _int(inner[0]) if len(inner) == 1 else None
    if t == "unary_operator":
        arg = _int(node.child_by_field_name("argument"))
        if arg is None:
            return None
        op = text(node.child_by_field_name("operator"))
        return {"-": -arg, "+": arg, "~": ~arg}.get(op)
    if t == "binary_operator":
        a = _int(node.child_by_field_name("left"))
        b = _int(node.child_by_field_name("right"))
        if a is None or b is None:
            return None
        op = text(node.child_by_field_name("operator"))
        if op in ("<<", ">>"):
            if b < 0 or b > MAX_SHIFT:
                return None
            r = a << b if op == "<<" else a >> b
        elif op in _BIN:
            if op in ("//", "%") and b == 0:
                return None
            r = _BIN[op](a, b)
        else:
            return None
        return r if r.bit_length() <= MAX_BITS else None
    return None


def _args(call):
    a = call.child_by_field_name("arguments")
    return [] if a is None else [x for x in a.named_children if x.type != "comment"]


def _join_string(call, getter: str):
    """The string built by ''.join(map(<getter>, [<ints>])), or None."""
    f = call.child_by_field_name("function")
    if f is None or f.type != "attribute" or text(f.child_by_field_name("attribute")) != "join":
        return None
    obj = f.child_by_field_name("object")
    if obj is None or obj.type != "string" or text(obj) not in ("''", '""'):
        return None
    args = _args(call)
    if len(args) != 1 or args[0].type != "call" or text(args[0].child_by_field_name("function")) != "map":
        return None
    margs = _args(args[0])
    if len(margs) != 2 or text(margs[0]) != getter or margs[1].type != "list":
        return None
    codes = [_int(e) for e in margs[1].named_children if e.type != "comment"]
    if any(c is None or c < 0 or c > 0x10FFFF for c in codes):
        return None
    return "".join(chr(c) for c in codes)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    getter = params["chr_getter"]
    root = PARSERS["py"].parse(input_bytes).root_node
    edits = []
    taken = []

    def inside(n):
        return any(s <= n.start_byte and n.end_byte <= e for s, e in taken)

    for n in descendants(root):
        if inside(n):
            continue
        rep = None
        if n.type == "call":
            s = _join_string(n, getter)
            if s is not None:
                rep = repr(s)
        elif n.type in ("binary_operator", "unary_operator", "parenthesized_expression") \
                and n.parent is not None and n.parent.type not in ("binary_operator", "unary_operator"):
            v = _int(n)
            if v is not None:
                rep = "(%d)" % v if v < 0 else "%d" % v
        if rep is not None:
            edits.append((n.start_byte, n.end_byte, rep.encode("utf-8")))
            taken.append((n.start_byte, n.end_byte))
    out = bytearray(input_bytes)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out)
