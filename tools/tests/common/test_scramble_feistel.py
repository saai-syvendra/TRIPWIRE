"""scramble_feistel: round-trip the bespoke SP-network cipher used to hide strings behind a global decode function.
Key, salt and function name are synthetic, not taken from any sample."""
import base64
import hashlib

from tools.common.decoders import load_decoder, scramble_feistel as sf

KEY = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
SALT = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
FN = "dec_fn"


def _master():
    return hashlib.pbkdf2_hmac("sha256", KEY.encode(), SALT.encode(), 200000, 32)


def _enc_round(data: bytes, round_key: bytes, rnd: int) -> bytes:
    out = bytearray(len(data))
    prev = 0
    for i in range(len(data)):
        perm = sf._sbox(round_key, rnd, i)
        out[i] = perm[data[i] ^ prev]
        prev = out[i]
    return bytes(out)


def _encrypt(value: str, nonce: bytes, rounds: int = 3) -> str:
    master = _master()
    round_key = hashlib.sha256(master + nonce).digest()
    ct = value.encode("utf-8")
    for rnd in range(rounds):
        ct = _enc_round(ct, round_key, rnd)
    return base64.b64encode(nonce + ct).decode()


def test_decrypt_round_trips():
    nonce = bytes(range(16))
    for value in ["JENKINS_HOME", "https://api.github.com", "GITHUB_REPOSITORY", ""]:
        blob = _encrypt(value, nonce)
        assert sf.decrypt(blob, _master(), 3).decode("utf-8") == value


def test_decode_substitutes_calls_in_source():
    blob = _encrypt("JENKINS_HOME", bytes(range(16)))
    src = ('if(process.env[%s("%s")]!==void 0x0)return!0x1;' % (FN, blob)).encode()
    params = {"key": KEY, "salt": SALT, "fn": FN}
    out = sf.decode(src, params, None).decode()
    assert 'process.env["JENKINS_HOME"]' in out


def test_registered():
    assert callable(load_decoder("scramble_feistel"))
