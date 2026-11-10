"""
Family:     pyobfuscate[.]com style setup.py: `random.seed(<int from b64/zlib/rot13/b64 of literal b>)`, then
            `exec(_(__))` where `_` maps each number n in the space-separated literal `__` to
            chr(n // random.randint(1, 100000))
Reverses:   the seed literal `b='...'` (base64 -> zlib -> rot13 -> base64 -> decimal int) and the number literal
            `__='...'`, by re-implementing CPython's MT19937 seeding (init_by_array) and randint/_randbelow as data
Per sample: params.c_int optional (the randint upper bound, default 100000)

decode() returns the input source followed by a comment marker line and the recovered stage, so the original code
still parses and the stage can be cited. Self-check: every number must be an exact multiple of its random divisor
and give a character in 9..126 or the decode is refused (ValueError).

Nothing is imported from the package, compiled, run or evaluated. Pure stdlib: base64, zlib, codecs, re.
"""
from __future__ import annotations

import base64
import codecs
import re
import zlib

_B = re.compile(rb"""(?m)(?:^|;)\s*b\s*=\s*'([A-Za-z0-9+/=]+)'""")
_NUMS = re.compile(rb"""(?:^|;)\s*__\s*=\s*'([0-9 ]+)'""", re.M)
M = 0xFFFFFFFF


class _MT:
    def __init__(self, seed: int):
        n = abs(seed)
        key = []
        while n:
            key.append(n & M)
            n >>= 32
        if not key:
            key = [0]
        mt = [0] * 624
        mt[0] = 19650218
        for i in range(1, 624):
            mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & M
        i, j = 1, 0
        for _k in range(max(624, len(key))):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1664525)) + key[j] + j) & M
            i += 1
            j += 1
            if i >= 624:
                mt[0] = mt[623]
                i = 1
            if j >= len(key):
                j = 0
        for _k in range(623):
            mt[i] = ((mt[i] ^ ((mt[i - 1] ^ (mt[i - 1] >> 30)) * 1566083941)) - i) & M
            i += 1
            if i >= 624:
                mt[0] = mt[623]
                i = 1
        mt[0] = 0x80000000
        self.mt, self.idx = mt, 624

    def u32(self) -> int:
        mt = self.mt
        if self.idx >= 624:
            for kk in range(624):
                y = (mt[kk] & 0x80000000) | (mt[(kk + 1) % 624] & 0x7FFFFFFF)
                mt[kk] = mt[(kk + 397) % 624] ^ (y >> 1) ^ (0x9908B0DF if y & 1 else 0)
            self.idx = 0
        y = mt[self.idx]
        self.idx += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y

    def randint(self, a: int, b: int) -> int:
        n = b - a + 1
        k = n.bit_length()
        r = self.u32() >> (32 - k)
        while r >= n:
            r = self.u32() >> (32 - k)
        return a + r


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    mb, mn = _B.search(input_bytes), _NUMS.search(input_bytes)
    if not mb or not mn:
        raise ValueError("seed literal b or number literal __ not found")
    stage = zlib.decompress(base64.b64decode(mb.group(1))).decode()
    seed_text = base64.b64decode(codecs.decode(stage, "rot13")).decode().strip()
    if not seed_text.isdigit():
        raise ValueError("seed is not a decimal integer")
    rng = _MT(int(seed_text))
    hi = int(params.get("c_int", 100000))
    out = []
    for tok in mn.group(1).split():
        n, r = int(tok), rng.randint(1, hi)
        if n % r:
            raise ValueError("number not a multiple of its divisor: wrong seed or PRNG")
        c = n // r
        if not 9 <= c <= 126:
            raise ValueError("decoded character out of range")
        out.append(chr(c))
    return input_bytes.rstrip(b"\n") + b"\n# --- decoded stage: exec(_(__)) with seed " + seed_text.encode() + \
        b" ---\n" + "".join(out).encode() + b"\n"
