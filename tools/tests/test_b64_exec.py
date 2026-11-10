"""The b64_exec decoder on synthetic input (no package content): splicing, nesting, indentation, refusals."""
import base64

from tools.common.decoders import load_decoder
from tools.common.tsparse import PARSERS

decode = load_decoder("b64_exec")


def b64(src: str) -> str:
    return base64.b64encode(src.encode()).decode()


def parses(src: bytes) -> bool:
    return not PARSERS["py"].parse(src).root_node.has_error


def test_a_guarded_stage_is_spliced_in_place_with_its_indentation():
    stage = "import os\nif os.path.exists('x'):\n    print('a')\nprint('b')\n"
    src = f"from base64 import b64decode\nif name == 'nt':\n    exec(b64decode('{b64(stage)}').decode())\nelse:\n    pass\n"
    out = decode(src.encode(), {}, None)
    assert out == ("from base64 import b64decode\nif name == 'nt':\n    import os\n    if os.path.exists('x'):\n"
                   "        print('a')\n    print('b')\nelse:\n    pass\n").encode()
    assert parses(out)


def test_every_spelling_of_b64decode_is_read():
    for call in ("base64.b64decode", "__import__('base64').b64decode", "b64decode"):
        out = decode(f"exec({call}(b'{b64('x = 1')}'))\n".encode(), {}, None)
        assert out == b"x = 1\n", call


def test_nested_layers_are_decoded_up_to_the_cap():
    inner = f"exec(b64decode('{b64('y = 2')}'))"
    src = f"exec(b64decode('{b64(inner)}'))\n".encode()
    assert decode(src, {}, None) == b"y = 2\n"
    assert decode(src, {"max_layers": 1}, None) == f"exec(b64decode('{b64('y = 2')}'))\n".encode()


def test_multiline_strings_in_a_stage_keep_their_text():
    stage = 's = """line1\nline2"""\nprint(s)\n'
    out = decode(f"if a:\n    exec(b64decode('{b64(stage)}'))\n".encode(), {}, None)
    assert out == b'if a:\n    s = """line1\nline2"""\n    print(s)\n' and parses(out)


def test_what_cannot_be_read_is_left_untouched():
    for src in ("exec(b64decode(var))\n",                       # not a literal
                "exec(b64decode('@@not base64@@'))\n",           # not base64
                f"exec(b64decode('{base64.b64encode(bytes([255, 254])).decode()}'))\n",  # not UTF-8
                f"x = exec(b64decode('{b64('z = 3')}'))\n"):     # exec as an expression
        assert decode(src.encode(), {}, None) == src.encode(), src
