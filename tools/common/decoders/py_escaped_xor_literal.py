"""
Family:     setup.py install override that XORs an escaped string literal with a repeating
            digit-string key literal and passes the result to eval(compile(..., 'exec'))
Reverses:   reads the encoded literal and the key literal as data, strips the quotes, decodes
            Python escapes (\\x, \\\\, \\n, ...) and XORs each character code with the key
Per sample: data_site, key_site (anchors on the two string literals, quotes included)

Nothing from the package is imported, compiled or run. Pure stdlib plus tools.common.sanitize.
"""
from __future__ import annotations

from tools.common.sanitize import unescape


def _literal(raw: bytes) -> str:
    text = raw.decode("utf-8")
    if len(text) < 2 or text[0] != text[-1] or text[0] not in "\"'":
        raise ValueError("not a simple quoted string literal")
    return unescape(text[1:-1])[0]


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    data = _literal(read(params["data_site"]))
    key = _literal(read(params["key_site"]))
    if not key:
        raise ValueError("empty XOR key")
    out = "".join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
    return out.encode("utf-8")
