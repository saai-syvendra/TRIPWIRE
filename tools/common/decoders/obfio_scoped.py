"""
Family:     generic (obfuscator.io output whose local alias names are reused across scopes)
Reverses:   the base64 string array (lowercase-first alphabet, UTF-8), with its checksum-gated rotation
Per sample: nothing (provider, decoder, offset, rotation target and checksum are read from the file)

Same recipe as tools/common/deobf.py, but every decoder alias (`const x = D`) and every `OBJ.prop` index is
resolved by lexical scope: a name is looked up in the nearest enclosing function that declares it (parameters
shadow), then outwards to the program. deobf.py keeps one global name map, so a reused local name (common in
large obfuscator.io files) hides the alias and no rotation matches.

decode() returns the input with every resolved decoder call replaced by a JSON string literal, byte for byte
elsewhere. Raises when the layout is missing or no rotation makes the checksum equal the target, so a wrong
decode is never written. Pure: tree-sitter parse plus base64/json/re; nothing is evaluated.
params: none.
"""
from __future__ import annotations

import base64
import json
import re

from tools.common.tsparse import PARSERS, descendants, static_string, text

FUNCS = ("function_declaration", "function_expression", "function", "arrow_function", "method_definition",
         "generator_function_declaration", "generator_function")
ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TR = str.maketrans(ALPHA, STD)


class _Fail(Exception):
    pass


def _b64(s: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9+/]", "", s).translate(_TR)
    return base64.b64decode(clean + "=" * (-len(clean) % 4)).decode("utf-8")


def _key(n):
    return None if n is None else (n.start_byte, n.end_byte)


def _scope(node):
    n = node.parent
    while n is not None:
        if n.type in FUNCS:
            return n
        n = n.parent
    return None


def _param_names(node):
    """Names bound by a parameter list or pattern (default values are skipped)."""
    t = node.type
    if t in ("identifier", "shorthand_property_identifier_pattern"):
        return [text(node)]
    if t == "assignment_pattern":
        left = node.child_by_field_name("left")
        return _param_names(left) if left is not None else []
    if t == "pair_pattern":
        value = node.child_by_field_name("value")
        return _param_names(value) if value is not None else []
    out = []
    for c in node.named_children:
        out += _param_names(c)
    return out


class _Scopes:
    def __init__(self, root):
        self.decls = {}
        for n in descendants(root):
            if n.type == "variable_declarator":
                name = n.child_by_field_name("name")
                if name is not None and name.type == "identifier":
                    self.decls.setdefault(_key(_scope(n)), {})[text(name)] = n.child_by_field_name("value")
            elif n.type in FUNCS:
                name = n.child_by_field_name("name")
                if n.type in ("function_declaration", "generator_function_declaration") and name is not None:
                    self.decls.setdefault(_key(_scope(n)), {})[text(name)] = n
                own = self.decls.setdefault(_key(n), {})
                params = n.child_by_field_name("parameters") or n.child_by_field_name("parameter")
                if params is not None:
                    for p in _param_names(params):
                        own.setdefault(p, None)
                if n.type in ("function_expression", "generator_function") and name is not None:
                    own.setdefault(text(name), n)

    def lookup(self, name: str, at):
        s = _scope(at)
        while True:
            d = self.decls.get(_key(s))
            if d is not None and name in d:
                return d[name]
            if s is None:
                return None
            s = _scope(s)


def _num(node, sc: _Scopes) -> float:
    t = node.type
    if t == "number":
        s = text(node).replace("_", "")
        return float(int(s, 0)) if re.match(r"^0[xXoObB]", s) else float(s)
    if t == "parenthesized_expression" and node.named_children:
        return _num(node.named_children[0], sc)
    if t == "unary_expression":
        op = text(node.child_by_field_name("operator"))
        v = _num(node.child_by_field_name("argument"), sc)
        if op == "-":
            return -v
        if op == "+":
            return v
        raise _Fail("unary " + op)
    if t == "binary_expression":
        op = text(node.child_by_field_name("operator"))
        a = _num(node.child_by_field_name("left"), sc)
        b = _num(node.child_by_field_name("right"), sc)
        if op == "+":
            return a + b
        if op == "-":
            return a - b
        raise _Fail("binary " + op)
    if t == "member_expression":
        obj, prop = node.child_by_field_name("object"), node.child_by_field_name("property")
        if obj is None or obj.type != "identifier" or prop is None:
            raise _Fail("member")
        value = sc.lookup(text(obj), node)
        if value is None or value.type != "object":
            raise _Fail("member object")
        for pair in value.named_children:
            if pair.type == "pair":
                k = pair.child_by_field_name("key")
                if k is not None and text(k).strip("'\"") == text(prop):
                    return _num(pair.child_by_field_name("value"), sc)
        raise _Fail("member key")
    raise _Fail(t)


def _parse_int(s: str) -> float:
    m = re.match(r"^\s*([+-]?\d+)", s)
    return float(int(m.group(1))) if m else float("nan")


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    root = PARSERS["js"].parse(input_bytes).root_node
    provider = table = pfn = None
    for fn in descendants(root):
        if fn.type != "function_declaration" or fn.child_by_field_name("name") is None:
            continue
        name = text(fn.child_by_field_name("name"))
        if not re.search(re.escape(name) + r"\s*=\s*function", text(fn)):
            continue
        for arr in descendants(fn):
            if arr.type == "array" and len(arr.named_children) >= 5:
                items = [static_string(c) for c in arr.named_children]
                if all(i is not None for i in items):
                    provider, table, pfn = name, items, fn
                    break
        if provider:
            break
    if provider is None:
        raise ValueError("string array provider not found")
    decoder = dfn = None
    offset = 0
    for fn in descendants(root):
        if fn.type != "function_declaration" or fn == pfn or fn.child_by_field_name("name") is None:
            continue
        body = text(fn)
        if not re.search(r"\b" + re.escape(provider) + r"\b", body) or ALPHA not in body:
            continue
        m = re.search(r"(\w+)\s*=\s*\1\s*-\s*(0x[0-9a-fA-F]+|\d+)", body)
        if m:
            decoder, dfn, offset = text(fn.child_by_field_name("name")), fn, int(m.group(2), 0)
            break
    if decoder is None:
        raise ValueError("decoder not found")
    sc = _Scopes(root)
    memo = {}

    def is_decoder(name, at, depth=0):
        if depth > 20:
            return False
        value = sc.lookup(name, at)
        if value is None:
            return False
        k = _key(value)
        if k in memo:
            return memo[k]
        if value == dfn:
            res = True
        elif value.type == "identifier":
            res = is_decoder(text(value), value, depth + 1)
        else:
            res = False
        memo[k] = res
        return res

    rot = target = None
    for call in descendants(root):
        if call.type != "call_expression":
            continue
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        if len(argv) != 2 or text(argv[0]) != provider:
            continue
        fn = call.child_by_field_name("function")
        while fn is not None and fn.type == "parenthesized_expression" and fn.named_children:
            fn = fn.named_children[0]
        if fn is not None and fn.type in FUNCS and "push" in text(fn) and "shift" in text(fn):
            rot, target = fn, _num(argv[1], sc)
            break
    if rot is None:
        raise ValueError("rotation not found")
    expr = None
    for d in descendants(rot):
        if d.type == "variable_declarator" and d.child_by_field_name("value") is not None \
                and "parseInt" in text(d.child_by_field_name("value")):
            expr = d.child_by_field_name("value")
            break
    if expr is None:
        raise ValueError("checksum not found")

    def entry(work, index):
        i = int(index) - offset
        if index != int(index) or not 0 <= i < len(work):
            raise _Fail("index")
        return _b64(work[i])

    def calc(node, work):
        t = node.type
        if t == "parenthesized_expression":
            return calc(node.named_children[0], work)
        if t == "unary_expression":
            op = text(node.child_by_field_name("operator"))
            v = calc(node.child_by_field_name("argument"), work)
            if op == "-":
                return -v
            if op == "+":
                return v
            raise _Fail(op)
        if t == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            a, b = calc(node.child_by_field_name("left"), work), calc(node.child_by_field_name("right"), work)
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                return float("nan") if b == 0 else a / b
            raise _Fail(op)
        if t == "call_expression":
            f = node.child_by_field_name("function")
            argv = [a for a in node.child_by_field_name("arguments").named_children if a.type != "comment"]
            if text(f) == "parseInt" and argv:
                inner = argv[0]
                if inner.type != "call_expression":
                    raise _Fail("parseInt arg")
                g = inner.child_by_field_name("function")
                iargs = [a for a in inner.child_by_field_name("arguments").named_children if a.type != "comment"]
                if g.type != "identifier" or not is_decoder(text(g), inner) or not iargs:
                    raise _Fail("not a decoder call")
                return _parse_int(entry(work, _num(iargs[0], sc)))
            raise _Fail("call")
        return _num(node, sc)

    work = list(table)
    for _ in range(len(table)):
        try:
            if calc(expr, work) == target:
                break
        except (_Fail, ValueError, UnicodeDecodeError):
            pass
        work.append(work.pop(0))
    else:
        raise ValueError("rotation checksum never matched")

    machinery = [pfn, dfn, rot]
    edits = []
    for c in descendants(root):
        if c.type != "call_expression":
            continue
        f = c.child_by_field_name("function")
        if f is None or f.type != "identifier" or not is_decoder(text(f), c):
            continue
        if any(m.start_byte <= c.start_byte and c.end_byte <= m.end_byte for m in machinery):
            continue
        argv = [a for a in c.child_by_field_name("arguments").named_children if a.type != "comment"]
        if not argv:
            continue
        try:
            value = entry(work, _num(argv[0], sc))
        except (_Fail, ValueError, UnicodeDecodeError):
            continue
        edits.append((c.start_byte, c.end_byte, json.dumps(value).encode()))
    out = bytearray(input_bytes)
    last = len(input_bytes) + 1
    for start, end, rep in sorted(edits, reverse=True):
        if end <= last:
            out[start:end] = rep
            last = start
    return bytes(out)
