"""
Family:     shai-hulud (npm worm, "Second Coming" wave)
Reverses:   per-string substitution-permutation cipher behind one global decode function
Per sample: fn (the decode function's minified name, e.g. f2959c600 or fc2edea72), key, salt; iterations,
            keylen and rounds have so far always been the defaults

Bespoke per-byte substitution-permutation cipher used by the "Shai-Hulud / Second Coming" npm worm to
hide endpoint and environment-variable strings behind a global decode function.

The key schedule is fully static in the package, so the decode replays from the package alone:
  masterKey = pbkdf2_hmac('sha256', key, salt, iterations, keylen)        (key/salt are passed as strings)
  per blob:  buf = base64(blob); nonce = buf[:16]; ct = buf[16:]
             roundKey = sha256(masterKey || nonce)
             for r in rounds-1 .. 0:  ct = dec_round(ct, roundKey, r)
             plaintext = ct (utf-8)
  dec_round(data, rk, r):  for each byte i, perm = sbox(rk, r, i) (Fisher-Yates over a sha256-seeded CSPRNG);
             out[i] = inverse(perm)[data[i]] ^ prev_ciphertext_byte   (CBC-style chaining over ciphertext)

decode() returns the input source with every `<fn>("<base64>")` call replaced by the JSON string literal of
its plaintext, so the result still parses and anchors into it stay readable.

Pure and deterministic: hashlib + base64 + tree-sitter only; no eval, no package execution, no network.
params: key (str), salt (str), iterations (int, default 200000), keylen (int, default 32),
        rounds (int, default 3), fn (str, the global decode function name).
"""
from __future__ import annotations

import base64
import hashlib
import json

from tools.common.tsparse import PARSERS, descendants, text


class _Csprng:
    def __init__(self, seed: bytes):
        self.key, self.counter, self.buf, self.off = seed, 0, b"", 0

    def _refill(self):
        h = hashlib.sha256(self.key)
        h.update(self.counter.to_bytes(8, "big"))
        self.counter += 1
        self.buf, self.off = h.digest(), 0

    def next_byte(self) -> int:
        if self.off >= len(self.buf):
            self._refill()
        b = self.buf[self.off]
        self.off += 1
        return b

    def next_u32(self) -> int:
        return ((self.next_byte() << 24) | (self.next_byte() << 16)
                | (self.next_byte() << 8) | self.next_byte()) & 0xFFFFFFFF


def _sbox(round_key: bytes, rnd: int, i: int) -> list[int]:
    seed = hashlib.sha256(round_key + bytes([rnd]) + str(i).encode()).digest()
    rng = _Csprng(seed)
    a = list(range(256))
    for k in range(255, 0, -1):
        lim = 0xFFFFFFFF - (0xFFFFFFFF % (k + 1))
        v = rng.next_u32()
        while v > lim:
            v = rng.next_u32()
        j = v % (k + 1)
        a[k], a[j] = a[j], a[k]
    return a


def _dec_round(data: bytes, round_key: bytes, rnd: int) -> bytes:
    out = bytearray(len(data))
    prev = 0
    for i in range(len(data)):
        perm = _sbox(round_key, rnd, i)
        inv = [0] * 256
        for j in range(256):
            inv[perm[j]] = j
        out[i] = inv[data[i]] ^ prev
        prev = data[i]
    return bytes(out)


def decrypt(blob_b64: str, master: bytes, rounds: int) -> bytes:
    buf = base64.b64decode(blob_b64)
    nonce, ct = buf[:16], buf[16:]
    round_key = hashlib.sha256(master + nonce).digest()
    for rnd in range(rounds - 1, -1, -1):
        ct = _dec_round(ct, round_key, rnd)
    return ct


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    key = params["key"]
    salt = params["salt"]
    iterations = int(params.get("iterations", 200000))
    keylen = int(params.get("keylen", 32))
    rounds = int(params.get("rounds", 3))
    fn = params["fn"]
    master = hashlib.pbkdf2_hmac("sha256", key.encode(), salt.encode(), iterations, keylen)

    root = PARSERS["js"].parse(input_bytes).root_node
    edits = []
    for c in (n for n in descendants(root) if n.type == "call_expression"):
        f = c.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != fn:
            continue
        args = [a for a in c.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 1 or args[0].type != "string":
            continue
        raw = text(args[0])[1:-1]  # strip quotes; these literals contain no escapes
        try:
            plain = decrypt(raw, master, rounds).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        edits.append((c.start_byte, c.end_byte, json.dumps(plain).encode()))
    out = bytearray(input_bytes)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out)
