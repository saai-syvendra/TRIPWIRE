"""
Family:     PyPI setup.py droppers that hide a stage behind `exec(Fernet(b'<key>').decrypt(b'<token>'))`
Reverses:   Fernet tokens (AES-128-CBC + HMAC-SHA256) given as two bytes literals at the call site
Per sample: none

Fernet key = urlsafe-base64 of signing key (16 bytes) | encryption key (16 bytes). Token = version 0x80 | timestamp[8]
| iv[16] | ciphertext | hmac[32]; the HMAC covers everything before it and is checked before decrypting. Key and token
are literals at the call site, so the decode replays from the package alone.

decode() returns the input source with every `exec(Fernet(<key literal>).decrypt(<token literal>))` call replaced by the
plaintext source (an expression statement in the same place, so the result still parses). A call whose HMAC, padding or
UTF-8 does not verify is left untouched. Only the literal bytes expressions are parsed (as data, by hand), never run.

Pure and deterministic: stdlib only (own AES block function from the sibling decoder, hmac, hashlib) plus tree-sitter; no
eval, no package execution, no network.
params: none.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re

from tools.common.decoders.aesgcm_gunzip import _SBOX, _expand_key, _xtime
from tools.common.tsparse import PARSERS, descendants, text

_INV = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV[_v] = _i

_BYTES_LIT = re.compile(r"""^b(['"])([A-Za-z0-9_=\-]*)\1$""")


def _mul(a: int, b: int) -> int:
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a) & 0xFF
        b >>= 1
    return r


def _decrypt_block(round_keys: list[list[int]], block: bytes) -> bytes:
    s = [b ^ k for b, k in zip(block, round_keys[-1])]
    for r in range(len(round_keys) - 2, -1, -1):
        t = [0] * 16
        for i in range(16):  # inverse ShiftRows
            t[(i + 4 * (i % 4)) % 16] = s[i]
        s = [_INV[b] for b in t]
        s = [b ^ k for b, k in zip(s, round_keys[r])]
        if r:
            out = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                out += [_mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9),
                        _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13),
                        _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11),
                        _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)]
            s = out
    return bytes(s)


def fernet_decrypt(key_b64: bytes, token_b64: bytes) -> bytes:
    """Fernet decrypt; ValueError when the key, HMAC, length or padding is wrong."""
    try:
        key = base64.urlsafe_b64decode(key_b64)
        tok = base64.urlsafe_b64decode(token_b64)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"bad base64: {e}")
    if len(key) != 32 or len(tok) < 9 + 16 + 16 + 32 or tok[0] != 0x80:
        raise ValueError("not a fernet key/token")
    signing, enc = key[:16], key[16:]
    if not hmac.compare_digest(hmac.new(signing, tok[:-32], hashlib.sha256).digest(), tok[-32:]):
        raise ValueError("HMAC mismatch")
    iv, ct = tok[9:25], tok[25:-32]
    if len(ct) % 16:
        raise ValueError("ciphertext is not block aligned")
    rk = _expand_key(enc)
    out, prev = bytearray(), iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += bytes(x ^ y for x, y in zip(_decrypt_block(rk, blk), prev))
        prev = blk
    pad = out[-1] if out else 0
    if not 1 <= pad <= 16 or bytes(out[-pad:]) != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return bytes(out[:-pad])


def _bytes_literal(node) -> bytes | None:
    m = _BYTES_LIT.match(text(node))
    return m.group(2).encode() if m else None


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    root = PARSERS["py"].parse(input_bytes).root_node
    edits = []
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != "exec":
            continue
        args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 1 or args[0].type != "call":
            continue
        dec = args[0]
        attr = dec.child_by_field_name("function")
        if attr is None or attr.type != "attribute" or text(attr.child_by_field_name("attribute")) != "decrypt":
            continue
        ctor = attr.child_by_field_name("object")
        if ctor is None or ctor.type != "call" or text(ctor.child_by_field_name("function")) != "Fernet":
            continue
        kargs = [a for a in ctor.child_by_field_name("arguments").named_children if a.type != "comment"]
        targs = [a for a in dec.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(kargs) != 1 or len(targs) != 1:
            continue
        key, tok = _bytes_literal(kargs[0]), _bytes_literal(targs[0])
        if key is None or tok is None:
            continue
        try:
            plain = fernet_decrypt(key, tok)
            plain.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        edits.append((call.start_byte, call.end_byte, plain))
    out = bytearray(input_bytes)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out)
