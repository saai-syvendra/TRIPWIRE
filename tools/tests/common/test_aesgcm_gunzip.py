"""aesgcm_gunzip: pure-Python AES-256-GCM + gzip blob decoder. Vectors are public (FIPS-197 C.3, GCM spec test case 14);
the source round trip uses a blob built here with the module's own primitives, not taken from any sample."""
import base64
import zlib

import pytest

from tools.common.decoders import aesgcm_gunzip as ag, load_decoder


def test_aes256_block_vector():
    rk = ag._expand_key(bytes(range(32)))
    assert ag.encrypt_block(rk, bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == \
        "8ea2b7ca516745bfeafc49904b496089"


def test_gcm_vector_and_tag_check():
    ct = bytes.fromhex("cea7403d4d606b6e074ec5d3baf39d18")
    tag = bytes.fromhex("d0d1c8a799996bf0265b98b5d48ab919")
    assert ag.gcm_decrypt(bytes(32), bytes(12), tag, ct) == bytes(16)
    with pytest.raises(ValueError):
        ag.gcm_decrypt(bytes(32), bytes(12), bytes(16), ct)


def _seal(key: bytes, iv: bytes, plain: bytes) -> tuple[bytes, bytes]:
    rk = ag._expand_key(key)
    ct = bytearray()
    for n, i in enumerate(range(0, len(plain), 16), start=2):
        ks = ag.encrypt_block(rk, iv + n.to_bytes(4, "big"))
        ct += bytes(a ^ b for a, b in zip(plain[i:i + 16], ks))
    ct = bytes(ct)
    h = int.from_bytes(ag.encrypt_block(rk, bytes(16)), "big")
    pad = ct + bytes((-len(ct)) % 16)
    s = ag._ghash(h, pad + (0).to_bytes(8, "big") + (len(ct) * 8).to_bytes(8, "big"))
    tag = (s ^ int.from_bytes(ag.encrypt_block(rk, iv + b"\0\0\0\1"), "big")).to_bytes(16, "big")
    return tag, ct


def test_decode_substitutes_calls_in_source():
    key = bytes(range(32))
    iv = bytes(range(12))
    gz = zlib.compressobj(wbits=31)
    plain = b"echo hello\nexit 0\n"
    tag, ct = _seal(key, iv, gz.compress(plain) + gz.flush())
    blob = base64.b64encode(iv + tag + ct).decode()
    src = ('var s=dec_fn("%s","%s");other("x","y");' % (key.hex(), blob)).encode()
    out = ag.decode(src, {"fn": "dec_fn"}, None).decode()
    assert out == 'var s="echo hello\\nexit 0\\n";other("x","y");'


def test_registered():
    assert callable(load_decoder("aesgcm_gunzip"))
