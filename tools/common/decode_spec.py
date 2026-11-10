"""
Replay a `decode_spec` derivation: run a registered hand-cracked decoder over package bytes to
rebuild decoded source.

This is the single source of truth for the recipe. The analyst tool (``tools/analysis/register_decode.py``)
calls it to produce ``scratch/<key>/derived/dN`` and stamp ``output_sha256``; the verifier
(``tools/verify/source.py``) calls it to rebuild those bytes and gate them against the same
``output_sha256``. Because the decoder is pure and reads only package bytes handed to it as data, the
same input yields the same output on any machine — which is what lets the verification run anywhere.

A derivation is::

    {"id": "d1", "recipe": "decode_spec", "recipe_version": 1,
     "input": {"file": "<path>", "derived_from": <id or null>},
     "params": {"decoder": "<registry name>", ...cipher args, key-material anchors...},
     "output_sha256": "<16 hex>"}
"""
from __future__ import annotations

from typing import Callable

from tools.common.decoders import load_decoder

RECIPE = "decode_spec"
RECIPE_VERSION = 1


def replay(read_bytes: Callable[[str, str | None], bytes], derivation: dict, decode=None) -> bytes:
    """Decoded source bytes for `derivation`. `read_bytes(file, derived_from)` returns a file's bytes
    (the caller decides whether that is the unpacked package or another derivation). Raises
    ValueError/KeyError on a bad spec and lets the decoder's own errors propagate."""
    params = derivation["params"]
    decode = decode or load_decoder(params["decoder"])  # a candidate decoder is handed in by register_decode
    inp = derivation["input"]
    input_bytes = read_bytes(inp["file"], inp.get("derived_from"))

    def read(anchor: dict) -> bytes:
        data = read_bytes(anchor["file"], anchor.get("derived_from"))
        return data[anchor["start_byte"]:anchor["end_byte"]]

    out = decode(input_bytes, params, read)
    if not isinstance(out, (bytes, bytearray)):
        raise ValueError(f"decoder {params['decoder']!r} returned {type(out).__name__}, not bytes")
    return bytes(out)
