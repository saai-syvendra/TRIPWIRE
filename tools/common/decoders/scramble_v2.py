"""
Family:     "ctf-scramble-v2" string cipher (seen in a compromised @cap-js npm release, Bun-run payload)
Reverses:   per-byte substitution cipher behind a global decode function (one round, no chaining)
Per sample: key (the hex string passed to the cipher class), salt, fn (the global decode function's name);
            iterations and keylen default to the values seen (200000, 32)

Key schedule, as read from the package's own cipher class (static, replays from the package alone):
  masterKey = pbkdf2_hmac('sha256', key, salt, iterations, keylen)        (key/salt used as utf-8 strings)
  per blob:  buf = base64(blob); nonce = buf[:12]; ct = buf[12:]
             h = sha256(masterKey || nonce)
             for byte i: perm = Fisher-Yates over a CSPRNG seeded with sha256(h || str(i)),
                         CSPRNG = sha256(seed || u64be(counter)) stream, u32 big-endian, rejection sampling
             plaintext[i] = inverse(perm)[ct[i]]

Only direct calls `fn("<base64>")` are decoded: each call whose single string argument is well-formed
base64 and decrypts to printable UTF-8 is replaced, call and all, by the JSON literal of its plaintext.
Literals elsewhere are left alone, since a short random base64 string decrypts to printable bytes often
enough to plant junk plaintext. Blobs reached only through wrapper objects stay encoded.

Pure and deterministic: hashlib + base64 + re + json + tree-sitter only; no eval, no package execution.
params: key (str), salt (str), fn (str), iterations (int, default 200000), keylen (int, default 32).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from tools.common.tsparse import PARSERS, descendants, text

_B64 = re.compile(rb"^[A-Za-z0-9+/]{16,}={0,2}$")


def _u32_stream(seed: bytes):
    counter = 0
    while True:
        block = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
        counter += 1
        for k in range(0, 32, 4):
            yield int.from_bytes(block[k:k + 4], "big")


def _perm(h: bytes, i: int) -> list[int]:
    seed = hashlib.sha256(h + str(i).encode()).digest()
    rng = _u32_stream(seed)
    a = list(range(256))
    for k in range(255, 0, -1):
        lim = 0xFFFFFFFF - (0xFFFFFFFF % (k + 1))
        v = next(rng)
        while v > lim:
            v = next(rng)
        j = v % (k + 1)
        a[k], a[j] = a[j], a[k]
    return a


def _ok(b: int) -> bool:
    return 0x20 <= b or b in (0x09, 0x0A, 0x0D)


def decrypt(buf: bytes, master: bytes):
    nonce, ct = buf[:12], buf[12:]
    if not ct:
        return None
    h = hashlib.sha256(master + nonce).digest()
    out = bytearray()
    for i, c in enumerate(ct):
        perm = _perm(h, i)
        p = perm.index(c)
        if not _ok(p) or p == 0x7F:
            return None
        out.append(p)
    return bytes(out)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    key = params["key"]
    salt = params["salt"]
    iterations = int(params.get("iterations", 200000))
    keylen = int(params.get("keylen", 32))
    master = hashlib.pbkdf2_hmac("sha256", key.encode(), salt.encode(), iterations, keylen)

    fn = params["fn"]
    root = PARSERS["js"].parse(input_bytes).root_node
    edits = []
    # only literals handed to the decode function: a random base64 literal elsewhere decrypts to printable bytes
    # often enough (short ones especially) to plant junk "plaintext" in the derived file
    for c in (n for n in descendants(root) if n.type == "call_expression"):
        f = c.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != fn:
            continue
        args = [a for a in c.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 1 or args[0].type != "string":
            continue
        raw = text(args[0])
        if isinstance(raw, str):
            raw = raw.encode()
        body = raw[1:-1]
        if len(body) % 4 or not _B64.match(body):
            continue
        try:
            buf = base64.b64decode(body, validate=True)
        except ValueError:
            continue
        if len(buf) < 13:
            continue
        plain = decrypt(buf, master)
        if plain is None:
            continue
        try:
            rep = json.dumps(plain.decode("utf-8")).encode()
        except UnicodeDecodeError:
            continue
        edits.append((c.start_byte, c.end_byte, rep))
    out = bytearray(input_bytes)
    for st, en, rep in sorted(edits, reverse=True):
        out[st:en] = rep
    return bytes(out)
