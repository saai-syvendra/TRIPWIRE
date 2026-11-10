"""list_decoders.py: reads decoder headers as text and filters them by word. Synthetic modules only."""
from tools.analysis import list_decoders

SRC = '''"""
Family:     npm droppers that run `eval(caesar(...))`
Reverses:   a char-code array, then a Caesar shift
            over ASCII letters
Per sample: none

Longer notes.
"""
def decode(input_bytes, params, read):
    return input_bytes
'''


def test_header_joins_continuation_lines():
    head = list_decoders.header(SRC)
    assert head == {"Family": "npm droppers that run `eval(caesar(...))`",
                    "Reverses": "a char-code array, then a Caesar shift over ASCII letters", "Per sample": "none"}


def test_decoders_skips_the_registry_and_examples(tmp_path):
    for name in ("__init__", "example_xor", "test_x", "caesar_eval"):
        (tmp_path / f"{name}.py").write_text(SRC)
    (tmp_path / "broken.py").write_text("def (:\n")
    assert [n for n, _ in list_decoders.decoders(tmp_path)] == ["broken", "caesar_eval"]


def test_the_real_registry_lists_fernet_exec():
    names = dict(list_decoders.decoders())
    assert "fernet_exec" in names and names["fernet_exec"]["Family"]
