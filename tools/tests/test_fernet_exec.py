"""Round-trip test for the fernet_exec decoder (synthetic input, no package content)."""
import base64
import hashlib
import hmac

from tools.common.decoders.aesgcm_gunzip import _expand_key, encrypt_block
from tools.common.decoders.fernet_exec import decode, fernet_decrypt


def fernet_encrypt(key_b64: bytes, plain: bytes, iv: bytes = bytes(range(16))) -> bytes:
    key = base64.urlsafe_b64decode(key_b64)
    rk = _expand_key(key[16:])
    pad = 16 - len(plain) % 16
    data = plain + bytes([pad]) * pad
    ct, prev = b"", iv
    for i in range(0, len(data), 16):
        prev = encrypt_block(rk, bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        ct += prev
    body = b"\x80" + bytes(8) + iv + ct
    return base64.urlsafe_b64encode(body + hmac.new(key[:16], body, hashlib.sha256).digest())


KEY = base64.urlsafe_b64encode(bytes(range(32)))


def test_roundtrip():
    plain = b"print('synthetic stage')"
    assert fernet_decrypt(KEY, fernet_encrypt(KEY, plain)) == plain


def test_decode_replaces_the_exec_call():
    tok = fernet_encrypt(KEY, b"print('x')")
    src = b"if a:\n    exec(Fernet(b'%s').decrypt(b'%s'))\n    b()\n" % (KEY, tok)
    assert decode(src, {}, None) == b"if a:\n    print('x')\n    b()\n"


def test_bad_hmac_is_left_untouched():
    tok = bytearray(fernet_encrypt(KEY, b"print('x')"))
    tok[-3] = ord("A") if tok[-3] != ord("A") else ord("B")
    src = b"exec(Fernet(b'%s').decrypt(b'%s'))\n" % (KEY, bytes(tok))
    assert decode(src, {}, None) == src
