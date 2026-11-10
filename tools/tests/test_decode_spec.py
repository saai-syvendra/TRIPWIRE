"""Unit tests for the decode_spec replay framework and the decoder registry."""
import pytest

from tools.common import decode_spec
from tools.common.decoders import load_decoder


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def reader(files: dict):
    return lambda file, derived_from: files[(file, derived_from)]


def test_replay_roundtrips_an_xor_blob():
    decoded = b"if (process.env.GITHUB_TOKEN) {}"
    key = bytes.fromhex("5a172c")
    deriv = {"input": {"file": "p.enc", "derived_from": None},
             "params": {"decoder": "example_xor", "key_hex": key.hex()}}
    assert decode_spec.replay(reader({("p.enc", None): xor(decoded, key)}), deriv) == decoded


def test_key_material_is_read_from_the_package_as_data():
    decoded = b"payload"
    key = b"KEYKEY"
    files = {("p.enc", None): xor(decoded, key), ("k.bin", None): b"....KEYKEY...."}
    deriv = {"input": {"file": "p.enc", "derived_from": None},
             "params": {"decoder": "example_xor",
                        "key_site": {"file": "k.bin", "derived_from": None, "start_byte": 4, "end_byte": 10}}}
    assert decode_spec.replay(reader(files), deriv) == decoded


def test_unknown_decoder_is_rejected():
    deriv = {"input": {"file": "p.enc", "derived_from": None}, "params": {"decoder": "no_such_cipher"}}
    with pytest.raises(ValueError, match="unknown decoder"):
        decode_spec.replay(reader({("p.enc", None): b""}), deriv)


@pytest.mark.parametrize("name", ["../etc/passwd", "Bad", "x.y", "", "a b"])
def test_only_bare_registry_names_load(name):
    with pytest.raises(ValueError):
        load_decoder(name)


def test_example_xor_is_registered():
    assert callable(load_decoder("example_xor"))
