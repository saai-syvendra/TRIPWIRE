"""
Family:     none (worked example for the tests)
Reverses:   repeating-key XOR
Per sample: key_hex or key_site

A tiny, reversible repeating-key XOR decoder.

This is a worked example of the `decode_spec` extension point, not a real-world cipher: it exists to
exercise and document the mechanism (and to back the regression fixtures). A real hand-cracked cipher
(pbkdf2 + S-box CBC, SHA256-CTR Feistel, ...) is added as its own module alongside this one.

params:
  key_hex:  the repeating XOR key as hex, OR
  key_site: an anchor {file, derived_from, start_byte, end_byte} whose bytes ARE the key (read as
            data from the package).
"""
from __future__ import annotations


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    if "key_site" in params:
        key = read(params["key_site"])
    else:
        key = bytes.fromhex(params["key_hex"])
    if not key:
        raise ValueError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(input_bytes))
