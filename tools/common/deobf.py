"""
Reproducible recovery of obfuscator.io string arrays, in pure Python. Nothing from the package is executed or
evaluated: the string table, the decoder's offset and encoding, the rotation and its checksum are read from the
syntax tree, and the checksum is computed by a small interpreter that only knows numbers, arithmetic, parseInt
and calls of the decoder with literal arguments.

Layout handled (obfuscator.io 2.x and later, and the older 0.x form):
  function P() { const a = ['..', ...]; P = function () { return a; }; return P(); }      the provider
  function D(i, k) { const a = P(); return D = function (i, k) { i = i - OFFSET; ... }, D(i, k); }  the decoder
  (function (p, TARGET) { const d = D, a = p(); while (!![]) { try { const s = parseInt(d(0x1b5)) / 1 + ...;
      if (s === TARGET) break; else a.push(a.shift()); } catch (e) { a.push(a.shift()); } } }(P, 0x3f2a1));
plus local aliases (const x = D) and wrapper functions (function w(a, b) { return D(b - 0x12, a); }).
Old form: var A = ['..']; (function (a, n) { var f = function (k) { while (--k) a.push(a.shift()); }; f(++n); }(A, 0x1a3));

derive(src) returns (derived bytes, params, stats) or None. The derived file is the input with every resolved
decoder call replaced by a JSON string literal, byte for byte elsewhere, so anchors into it stay readable.
"""
from __future__ import annotations

import base64
import json
import math
import re
import urllib.parse

from tools.common.sanitize import unescape
from tools.common.tsparse import PARSERS, descendants, text

RECIPE_VERSION = 1
B64_CUSTOM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
MIN_STRINGS = 5
FUNCS = ("function_declaration", "function_expression", "function", "arrow_function")


class NotRecovered(Exception):
    pass


# --- string decoders -----------------------------------------------------------------------------------------

def b64_custom(s: str) -> str:
    """obfuscator.io's base64: lowercase-first alphabet, bytes then read as percent-encoded UTF-8."""
    table = str.maketrans(B64_CUSTOM[:64], B64_STD[:64])
    clean = re.sub(r"[^A-Za-z0-9+/]", "", s).translate(table)
    raw = base64.b64decode(clean + "=" * (-len(clean) % 4))
    return urllib.parse.unquote("".join(f"%{b:02x}" for b in raw), errors="strict")


def rc4(data: str, key: str) -> str:
    sbox, j, out = list(range(256)), 0, []
    for i in range(256):
        j = (j + sbox[i] + ord(key[i % len(key)])) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
    i = j = 0
    for ch in data:
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out.append(chr(ord(ch) ^ sbox[(sbox[i] + sbox[j]) % 256]))
    return "".join(out)


def b64_bytes_as_chars(s: str) -> str:
    """The rc4 variant's base64 step: decoded bytes kept as Latin-1 characters (RC4 works on char codes)."""
    table = str.maketrans(B64_CUSTOM[:64], B64_STD[:64])
    clean = re.sub(r"[^A-Za-z0-9+/]", "", s).translate(table)
    return base64.b64decode(clean + "=" * (-len(clean) % 4)).decode("latin-1")


def decode_entry(table: list[str], offset: int, variant: str, index, key=None) -> str:
    if isinstance(index, str):  # old form: decoder('0x1a') relies on JS turning the string into a number
        try:
            index = float(int(index, 0))
        except ValueError:
            raise NotRecovered("index is not a number") from None
    if not isinstance(index, (int, float)) or index != int(index):
        raise NotRecovered("index is not an integer")
    i = int(index) - offset
    if not 0 <= i < len(table):
        raise NotRecovered("index outside the table")
    value = table[i]
    if variant == "base64":
        return b64_custom(value)
    if variant == "rc4":
        if not isinstance(key, str) or not key:
            raise NotRecovered("rc4 needs a key")
        return urllib.parse.unquote("".join(f"%{ord(c):02x}" for c in rc4(b64_bytes_as_chars(value), key)))
    return value


# --- reading the layout ----------------------------------------------------------------------------------------

def string_items(arr) -> list[str] | None:
    items = []
    for c in arr.named_children:
        if c.type != "string":
            return None
        raw = "".join(text(x) for x in c.named_children if x.type in ("string_fragment", "escape_sequence"))
        items.append(unescape(raw)[0])
    return items


def number(node) -> float | None:
    if node is None:
        return None
    if node.type == "number":
        t = text(node).replace("_", "")
        try:
            return float(int(t, 0)) if re.match(r"^0[xXoObB]", t) else float(t)
        except ValueError:
            return None
    if node.type == "unary_expression" and text(node.child_by_field_name("operator")) == "-":
        v = number(node.child_by_field_name("argument"))
        return -v if v is not None else None
    if node.type == "parenthesized_expression" and node.named_children:
        return number(node.named_children[0])
    return None


def fn_name(fn) -> str | None:
    name = fn.child_by_field_name("name")
    return text(name) if name is not None else None


def find_provider(root):
    """(name, table) of a provider function, or of an old-style top-level string array variable."""
    for fn in (n for n in descendants(root) if n.type == "function_declaration"):
        name = fn_name(fn)
        body = text(fn)
        if not name or not re.search(re.escape(name) + r"\s*=\s*function", body):
            continue
        for arr in (n for n in descendants(fn) if n.type == "array"):
            items = string_items(arr)
            if items is not None and len(items) >= MIN_STRINGS:
                return name, items, "v2"
    for decl in (n for n in descendants(root) if n.type == "variable_declarator"):
        value = decl.child_by_field_name("value")
        if value is not None and value.type == "array":
            items = string_items(value)
            if items is not None and len(items) >= MIN_STRINGS and decl.parent.parent is not None and \
                    decl.parent.parent.type == "program":
                return text(decl.child_by_field_name("name")), items, "v1"
    return None


def named_functions(root):
    """(name, function node) for function declarations and functions bound to a variable."""
    for n in descendants(root):
        if n.type == "function_declaration":
            yield fn_name(n), n
        elif n.type == "variable_declarator":
            value = n.child_by_field_name("value")
            if value is not None and value.type in ("function_expression", "function"):
                yield text(n.child_by_field_name("name")), value


def find_decoder(root, provider: str):
    """(name, offset, variant) of the decoder that indexes the provider's table."""
    for name, fn in named_functions(root):
        body = text(fn)
        if not name or name == provider or not re.search(r"\b" + re.escape(provider) + r"\b", body):
            continue
        m = re.search(r"(\w+)\s*=\s*\1\s*-\s*(0x[0-9a-fA-F]+|\d+)|(\w+)\s*-=\s*(0x[0-9a-fA-F]+|\d+)", body)
        if not m:
            continue
        offset = int(m.group(2) or m.group(4), 0)
        variant = "none"
        if B64_CUSTOM in body.replace("\\x", ""):
            variant = "rc4" if re.search(r"0x100|%\s*256|\^", body) and "fromCharCode" in body else "base64"
        return name, offset, variant
    return None


def find_rotation(root, provider: str, kind: str):
    """(iife call node, target or count) of the rotation that cycles the provider's table."""
    for call in (n for n in descendants(root) if n.type == "call_expression"):
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        if len(argv) != 2 or text(argv[0]) != provider:
            continue
        target = number(argv[1])
        fn = call.child_by_field_name("function")
        while fn is not None and fn.type == "parenthesized_expression" and fn.named_children:
            fn = fn.named_children[0]
        if target is None or fn is None or fn.type not in FUNCS:
            continue
        if "push" in text(fn) and "shift" in text(fn):
            return fn, target
    return None


# --- the checksum interpreter -----------------------------------------------------------------------------------

def js_parse_int(s) -> float:
    m = re.match(r"^\s*([+-]?\d+)", str(s))
    return float(int(m.group(1))) if m else math.nan


class Checksum:
    """Evaluates the rotation's checksum expression. Only numbers, + - * / %, unary minus, parentheses,
    parseInt(...) and calls of known decoders with literal arguments are allowed; anything else stops the
    decode, so no package code is ever interpreted beyond arithmetic."""

    def __init__(self, decode):
        self.decode = decode  # (callee name, [args]) -> str, raising NotRecovered

    def eval(self, node) -> float:
        t = node.type
        if t == "number":
            return number(node)
        if t == "parenthesized_expression":
            return self.eval(node.named_children[0])
        if t == "unary_expression":
            op = text(node.child_by_field_name("operator"))
            v = self.eval(node.child_by_field_name("argument"))
            if op == "-":
                return -v
            if op == "+":
                return v
            raise NotRecovered(f"operator {op}")
        if t == "binary_expression":
            op = text(node.child_by_field_name("operator"))
            a, b = self.eval(node.child_by_field_name("left")), self.eval(node.child_by_field_name("right"))
            if op == "+":
                return a + b
            if op == "-":
                return a - b
            if op == "*":
                return a * b
            if op == "/":
                return math.nan if b == 0 else a / b
            if op == "%":
                return math.nan if b == 0 else math.fmod(a, b)
            raise NotRecovered(f"operator {op}")
        if t == "call_expression":
            fn = node.child_by_field_name("function")
            args = [a for a in node.child_by_field_name("arguments").named_children if a.type != "comment"]
            if text(fn) == "parseInt" and len(args) >= 1:
                return js_parse_int(self.value(args[0]))
            raise NotRecovered(f"call {text(fn)[:30]} in the checksum")
        raise NotRecovered(f"{t} in the checksum")

    def value(self, node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = [a for a in node.child_by_field_name("arguments").named_children if a.type != "comment"]
            vals = [literal(a) for a in args]
            return self.decode(text(fn), vals)
        if node.type == "string":
            return literal(node)
        return self.eval(node)


def literal(node):
    v = number(node)
    if v is not None:
        return v
    if node.type == "string":
        raw = "".join(text(x) for x in node.named_children if x.type in ("string_fragment", "escape_sequence"))
        return unescape(raw)[0]
    return None


# --- aliases and wrappers ------------------------------------------------------------------------------------

def callables(root, decoder: str) -> dict[str, list]:
    """name -> argument map onto the decoder. A map is a list of (param index or None, addend, literal) per
    decoder argument; the decoder itself maps identically. Aliases (const x = D) and wrapper functions whose
    body only returns a call of a known callable with params +/- constants are composed until nothing changes."""
    known = {decoder: None}  # None: identity
    aliases_of = {}
    fns = {}
    for n in descendants(root):
        if n.type == "variable_declarator":
            name, value = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and value is not None and name.type == "identifier" and value.type == "identifier":
                aliases_of[text(name)] = text(value)
        elif n.type in ("function_declaration", "function_expression"):
            name = fn_name(n)
            if name is None and n.parent is not None and n.parent.type == "variable_declarator":
                name = text(n.parent.child_by_field_name("name"))
            if name:
                fns.setdefault(name, n)
    changed = True
    while changed:
        changed = False
        for a, b in aliases_of.items():
            if a not in known and b in known:
                known[a] = known[b]
                changed = True
        for name, fn in fns.items():
            if name in known:
                continue
            m = wrapper_map(fn, known)
            if m is not None:
                known[name] = m
                changed = True
    return known


def wrapper_map(fn, known: dict):
    params = fn.child_by_field_name("parameters")
    names = [text(p) for p in params.named_children if p.type == "identifier"] if params is not None else []
    body = fn.child_by_field_name("body")
    stmts = [c for c in body.named_children if c.type != "comment"] if body is not None else []
    if len(stmts) != 1 or stmts[0].type != "return_statement" or not stmts[0].named_children:
        return None
    call = stmts[0].named_children[0]
    if call.type != "call_expression" or text(call.child_by_field_name("function")) not in known:
        return None
    inner = known[text(call.child_by_field_name("function"))]
    args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
    mapped = []
    for a in args:
        term = affine(a, names)
        if term is None:
            return None
        mapped.append(term)
    return compose(mapped, inner)


def affine(node, params: list[str]):
    """(param index, addend, literal): `p`, `p - 0x12`, `p + -3`, or a literal."""
    if node.type == "identifier" and text(node) in params:
        return (params.index(text(node)), 0, None)
    if node.type == "binary_expression" and text(node.child_by_field_name("operator")) in ("+", "-"):
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        k = number(right)
        if left.type == "identifier" and text(left) in params and k is not None:
            return (params.index(text(left)), k if text(node.child_by_field_name("operator")) == "+" else -k, None)
    lit = literal(node)
    if lit is not None:
        return (None, 0, lit)
    if node.type == "parenthesized_expression" and node.named_children:
        return affine(node.named_children[0], params)
    return None


def compose(outer: list, inner):
    if inner is None:
        return outer
    out = []
    for p, k, lit in inner:
        if p is None:
            out.append((None, 0, lit))
        elif p < len(outer):
            q, k2, lit2 = outer[p]
            out.append((q, k + k2, lit2) if q is not None else (None, 0, lit2 + k if isinstance(lit2, float) else lit2))
        else:
            out.append((None, 0, None))
    return out


def apply_map(m, args: list):
    if m is None:
        return args
    out = []
    for p, k, lit in m:
        if p is None:
            out.append(lit)
        else:
            v = args[p] if p < len(args) else None
            out.append(v + k if isinstance(v, float) else v)
    return out


# --- the whole recipe ------------------------------------------------------------------------------------------

def derive(src: bytes) -> tuple[bytes, dict, dict] | None:
    """Recovers the string table of an obfuscator.io file. None when the layout is not found or the rotation
    checksum never matches (a wrong decode is never written)."""
    tree = PARSERS["js"].parse(src)
    root = tree.root_node
    found = find_provider(root)
    if found is None:
        return None
    provider, table, form = found
    if form == "v2":
        dec = find_decoder(root, provider)
        if dec is None:
            return None
        decoder, offset, variant = dec
    else:  # v1: the table itself is indexed, usually by a decoder taking a hex string
        dec = find_decoder(root, provider)
        decoder, offset, variant = dec if dec else (None, 0, "none")
        if decoder is None:
            return None
    known = callables(root, decoder)
    rot = find_rotation(root, provider, form)
    params = {"provider": provider, "decoder": decoder, "offset": offset, "variant": variant, "form": form,
              "table_size": len(table)}
    if rot is not None:
        fn, target = rot
        if form == "v1":
            k = int(target) % len(table)  # f(++n) then while (--k) shifts: exactly n rotations
            table = table[k:] + table[:k]
            params.update(rotations=k, checksum_target=None)
        else:
            expr = checksum_expression(fn)
            if expr is None:
                return None
            work = list(table)

            def call(name, vals):
                m = known.get(name, "missing")
                if m == "missing":
                    raise NotRecovered(f"{name} is not a decoder")
                a = apply_map(m, vals)
                return decode_entry(work, offset, variant, a[0] if a else None, a[1] if len(a) > 1 else None)
            for k in range(len(table)):
                try:
                    if Checksum(call).eval(expr) == target:
                        table = work
                        params.update(rotations=k, checksum_target=int(target))
                        break
                except (NotRecovered, ValueError, UnicodeDecodeError, IndexError):
                    pass
                work.append(work.pop(0))
            else:
                return None
    else:
        params.update(rotations=0, checksum_target=None)
    # Calls inside the obfuscator's own machinery (decoder, wrappers, rotation) pass parameters, not indexes.
    machinery = [fn for name, fn in named_functions(root) if name in known or name == provider]
    if rot is not None:
        machinery.append(rot[0])
    edits, total, unresolved = [], 0, 0
    for c in (n for n in descendants(root) if n.type == "call_expression"):
        fn = c.child_by_field_name("function")
        if fn is None or fn.type != "identifier" or text(fn) not in known:
            continue
        if any(m.start_byte <= c.start_byte and c.end_byte <= m.end_byte for m in machinery):
            continue
        args = [a for a in c.child_by_field_name("arguments").named_children if a.type != "comment"]
        if not args:
            continue
        total += 1
        vals = [literal(a) for a in args]
        a = apply_map(known[text(fn)], vals)
        try:
            value = decode_entry(table, offset, variant, a[0] if a else None, a[1] if len(a) > 1 else None)
        except (NotRecovered, ValueError, UnicodeDecodeError):
            unresolved += 1
            continue
        edits.append((c.start_byte, c.end_byte, json.dumps(value).encode()))
    out = bytearray(src)
    last = len(src) + 1
    for start, end, rep in sorted(edits, reverse=True):
        if end <= last:  # nested calls: the outer replacement wins
            out[start:end] = rep
            last = start
    params["callables"] = len(known)
    return bytes(out), params, {"calls_total": total, "substituted": len(edits), "unresolved": unresolved}


def checksum_expression(fn):
    """The value compared with the target inside the rotation loop's try block."""
    for decl in (n for n in descendants(fn) if n.type == "variable_declarator"):
        value = decl.child_by_field_name("value")
        if value is not None and "parseInt" in text(value):
            return value
    return None
