"""scramble_v2: the one-round per-byte substitution string cipher behind a named decode function. Synthetic blobs
sealed here with the module's own permutation; the key, salt and nonces are made up."""
import base64
import hashlib

from tools.common.decoders import load_decoder, scramble_v2 as sv

PARAMS = {"key": "00ff" * 8, "salt": "5a1t", "iterations": 1000, "fn": "__dec"}


def seal(plain: str, nonce: bytes, params=PARAMS) -> str:
    master = hashlib.pbkdf2_hmac("sha256", params["key"].encode(), params["salt"].encode(), params["iterations"], 32)
    h = hashlib.sha256(master + nonce).digest()
    return base64.b64encode(nonce + bytes(sv._perm(h, i)[b] for i, b in enumerate(plain.encode()))).decode()


def test_calls_to_the_decode_function_are_replaced():
    a, b = seal("child_process", bytes(12)), seal("os", bytes(range(12)))
    src = f'const x=require(__dec("{a}"));const y=__dec("{b}");'
    assert sv.decode(src.encode(), PARAMS, None).decode() == 'const x=require("child_process");const y="os";'


def test_literals_outside_decode_calls_stay_untouched():
    lone = seal("env", bytes(12))  # decrypts, but is not handed to __dec
    src = f'const t=["{lone}"];other("{lone}");__dec("{lone}");'
    assert sv.decode(src.encode(), PARAMS, None).decode() == f'const t=["{lone}"];other("{lone}");"env";'


def test_a_wrong_key_leaves_the_file_as_is():
    src = f'__dec("{seal("whoami", bytes(12))}");'.encode()
    out = sv.decode(src, dict(PARAMS, key="11ee" * 8), None)
    assert b"whoami" not in out


def test_registered():
    assert callable(load_decoder("scramble_v2"))
