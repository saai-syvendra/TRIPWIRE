#!/usr/bin/env python3
"""
Pure data transforms for obfuscated strings from package code. Nothing is evaluated.

Usage: python tools/common/decode.py OP [OP ...] [--in FILE]      (reads stdin without --in)
Ops, applied left to right: base64, hex, unescape, charcodes, reverse, xor:KEY (xor:0xHEX for a hex key),
zlib, gzip. The result is printed defanged and capped, so URLs in it are not live.
Example: echo 'aHR0cHM6Ly9ldmlsLmV4YW1wbGU=' | python tools/common/decode.py base64
"""
from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import re
import sys
import zlib
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402
from tools.common.sanitize import defang, unescape  # noqa: E402

MAX_OUTPUT = 20000


def as_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def from_text(s: str) -> bytes:
    return s.encode("latin-1") if all(ord(ch) < 256 for ch in s) else s.encode("utf-8")


def op_base64(data: bytes) -> bytes:
    s = re.sub(rb"\s", b"", data)
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s) if re.search(rb"[-_]", s) else base64.b64decode(s)


def op_hex(data: bytes) -> bytes:
    return bytes.fromhex(re.sub(r"0x|\\x|[\s,]", "", as_text(data)))


def op_unescape(data: bytes) -> bytes:
    return from_text(unescape(as_text(data))[0])


def op_charcodes(data: bytes) -> bytes:
    codes = [int(n, 0) for n in re.findall(r"0x[0-9a-fA-F]+|\d+", as_text(data))]
    return from_text("".join(chr(c) for c in codes))


def op_xor(data: bytes, key: str) -> bytes:
    k = bytes.fromhex(key[2:]) if key.startswith("0x") else key.encode()
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(data))


def op_zlib(data: bytes) -> bytes:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, zlib.MAX_WBITS | 32):
        try:
            return zlib.decompress(data, wbits)
        except zlib.error:
            continue
    raise ValueError("not zlib or raw deflate data")


OPS = {"base64": op_base64, "hex": op_hex, "unescape": op_unescape, "charcodes": op_charcodes,
       "reverse": lambda d: d[::-1], "zlib": op_zlib, "gzip": gzip.decompress}


def run(data: bytes, ops: list[str]) -> bytes:
    for op in ops:
        name, _, arg = op.partition(":")
        if name == "xor":
            if not arg:
                raise ValueError("xor needs a key: xor:KEY")
            data = op_xor(data, arg)
        elif name in OPS:
            data = OPS[name](data)
        else:
            raise ValueError(f"unknown op {op!r}")
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("ops", nargs="+")
    ap.add_argument("--in", dest="infile", type=Path)
    args = ap.parse_args()
    data = paths.confine(args.infile).read_bytes() if args.infile else sys.stdin.buffer.read()
    try:
        out = run(data.strip(), args.ops)
    except (ValueError, binascii.Error, zlib.error, gzip.BadGzipFile, OSError) as e:
        sys.exit(f"decode failed: {e}")
    text = defang(as_text(out))
    print(text[:MAX_OUTPUT] + (f"\n... [{len(text) - MAX_OUTPUT} more characters]" if len(text) > MAX_OUTPUT else ""))


if __name__ == "__main__":
    main()
