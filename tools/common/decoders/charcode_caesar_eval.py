"""
Family:     npm droppers that run `eval(caesar(String.fromCharCode(...codes), n))`
Reverses:   a char-code array joined into a string, then a Caesar shift by n over ASCII letters
            (`s.replace(/[a-zA-Z]/g, c => fromCharCode((code - base + n) % 26 + base))`), handed to eval
Per sample: none (the shift n is read from the call itself)

decode() returns the input source with every such `eval(...)` call replaced in place by the decoded source.
The wrapper text must match the shift function exactly, so a different transform is left untouched.
Only the literals are read as data; nothing is evaluated. Pure: stdlib re only.
"""
from __future__ import annotations

import re

_CALL = re.compile(
    rb'eval\(function\(s,n\)\{return s\.replace\(/\[a-zA-Z\]/g,function\(c\)\{var b=c<="Z"\?65:97;'
    rb'return String\.fromCharCode\(\(c\.charCodeAt\(0\)-b\+n\)%26\+b\)\}\)\}'
    rb'\(\[([0-9,\s]+)\]\.map\(function\(c\)\{return String\.fromCharCode\(c\)\}\)\.join\(""\),(\d+)\)\)'
)


def _shift(s: str, n: int) -> str:
    out = []
    for ch in s:
        if "A" <= ch <= "Z" or "a" <= ch <= "z":
            b = 65 if ch <= "Z" else 97
            out.append(chr((ord(ch) - b + n) % 26 + b))
        else:
            out.append(ch)
    return "".join(out)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    def repl(m):
        codes = [int(x) for x in m.group(1).split(b",") if x.strip()]
        plain = "".join(chr(c) for c in codes)
        return _shift(plain, int(m.group(2))).encode("utf-8")

    return _CALL.sub(repl, input_bytes)
