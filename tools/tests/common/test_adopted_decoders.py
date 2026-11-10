"""Round trips for the decoders the strat batch adopted. Every input is built here (synthetic stages, public
GCM vectors, stdlib random as the PRNG reference), never taken from a sample."""
import base64
import codecs
import random
import zlib

import pytest

from tools.common.decoders import load_decoder
from tools.tests.test_fernet_exec import fernet_encrypt

NAMES = ["aesgcm_hex_stage", "b64_exec_tuple", "b64_wrapper_drop", "charcode_caesar_eval", "chr_shift_join",
         "py_chr_shift_fold", "py_escaped_xor_literal", "pyobfuscate_seeded_div", "stickytape_module",
         "exec_alias_b85xor_zlib", "rev_b64_zlib_lambda", "exec_str_b64_fernet", "py_shift_charcode_join"]


def dec(name, src, params=None, read=None):
    return load_decoder(name)(src if isinstance(src, bytes) else src.encode(), params or {}, read)


@pytest.mark.parametrize("name", NAMES)
def test_registered(name):
    assert callable(load_decoder(name))


# GCM spec test case 14 (AES-256, zero key and iv, one zero block)
TC14 = (bytes(32).hex(), bytes(12).hex(), "d0d1c8a799996bf0265b98b5d48ab919", "cea7403d4d606b6e074ec5d3baf39d18")


def test_aesgcm_hex_stage_vector_and_tamper():
    key, iv, tag, ct = TC14
    src = f'const a=dk("x","y");\nconst stage=dk("{key}","{iv}","{tag}","{ct}");'
    assert dec("aesgcm_hex_stage", src, {"fn": "dk", "var": "stage"}) == bytes(16)
    bad = src.replace(tag, "0" * 32)
    with pytest.raises(ValueError, match="tag"):
        dec("aesgcm_hex_stage", bad, {"fn": "dk", "var": "stage"})
    with pytest.raises(ValueError, match="not found"):
        dec("aesgcm_hex_stage", src, {"fn": "dk", "var": "other"})


def test_b64_exec_tuple_splits_the_tuple_and_inlines_the_stage():
    stage = base64.b64encode(b"print(1)\nx = 2").decode()
    src = f'import base64\ntype("tag")   ,   exec(base64.b64decode("{stage}"))\nkeep = 1\n'
    assert dec("b64_exec_tuple", src).decode() == 'import base64\ntype("tag")\nprint(1)\nx = 2\nkeep = 1\n'


def test_b64_exec_tuple_leaves_non_base64_alone():
    src = 'exec(base64.b64decode("not base64!"))\n'
    assert dec("b64_exec_tuple", src).decode() == src


def test_b64_wrapper_drop_returns_the_nth_literal():
    src = ("def b64(s):\n    return base64.b64decode(s).decode('utf8')\n"
           f"f.write(b64('{base64.b64encode(b'one').decode()}'))\n"
           f"g.write(b64('{base64.b64encode(b'two').decode()}'))\n")
    assert dec("b64_wrapper_drop", src) == b"one"
    assert dec("b64_wrapper_drop", src, {"nth": 1}) == b"two"
    with pytest.raises(ValueError):
        dec("b64_wrapper_drop", src, {"nth": 2})


def _caesar(s, n):
    return "".join(chr((ord(c) - b + n) % 26 + b) if c.isascii() and c.isalpha() else c
                   for c in s for b in [65 if c <= "Z" else 97])


def test_charcode_caesar_eval_round_trip():
    plain, n = 'console.log("Hi, Zed");', 7
    codes = ",".join(str(ord(c)) for c in _caesar(plain, 26 - n))
    call = ('eval(function(s,n){return s.replace(/[a-zA-Z]/g,function(c){var b=c<="Z"?65:97;'
            'return String.fromCharCode((c.charCodeAt(0)-b+n)%26+b)})}'
            f'([{codes}].map(function(c){{return String.fromCharCode(c)}}).join(""),{n}))')
    assert dec("charcode_caesar_eval", f"a();{call};b();").decode() == f"a();{plain};b();"
    other = call.replace("%26", "%25")  # a different transform is left untouched
    assert dec("charcode_caesar_eval", other).decode() == other


def test_chr_shift_join_folds_strings_and_states():
    src = "x = ''.join(map(getchr, [(3 << 5) + 8, 0x69]))\nstate = 1000 + 7 * 2\ny = f(1) + 2\n"
    out = dec("chr_shift_join", src, {"chr_getter": "getchr"}).decode()
    assert out == "x = 'hi'\nstate = 1014\ny = f(1) + 2\n"


def test_py_chr_shift_fold_round_trip():
    getter = ("getattr(__builtins__, oct.__str__()[-3 << 0] + hex.__str__()[-1 << 2] + "
              "copyright.__str__()[4 << 0])")
    src = f"s = ''.join(map({getter}, [13 << 3, 52 + 53]))\nstate = 834*(395 & 643) | 104 << 3\n"
    assert dec("py_chr_shift_fold", src).decode() == f"s = 'hi'\nstate = {834 * (395 & 643) | 104 << 3}\n"
    with pytest.raises(ValueError):
        dec("py_chr_shift_fold", "s = 1 + 2\n")


def test_py_escaped_xor_literal_round_trip():
    plain, key = "print('x')\n", "4912"
    data = "".join("\\x%02x" % (ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plain))
    sites = {"d": f'"{data}"'.encode(), "k": f"'{key}'".encode()}
    assert dec("py_escaped_xor_literal", b"", {"data_site": "d", "key_site": "k"}, sites.__getitem__) == plain.encode()


def test_pyobfuscate_seeded_div_matches_cpython_random():
    seed, plain = 987654321987654321, "import os\nprint('stage')\n"
    rot = codecs.encode(base64.b64encode(str(seed).encode()).decode(), "rot13")
    b = base64.b64encode(zlib.compress(rot.encode())).decode()
    rng = random.Random(seed)
    nums = " ".join(str(ord(c) * rng.randint(1, 100000)) for c in plain)
    src = f"import random\nb='{b}'\n__='{nums}'\n"
    out = dec("pyobfuscate_seeded_div", src).decode()
    assert out == src + f"# --- decoded stage: exec(_(__)) with seed {seed} ---\n" + plain + "\n"
    with pytest.raises(ValueError):  # a wrong seed fails the multiple-of-divisor self-check
        dec("pyobfuscate_seeded_div", src.replace(nums, " ".join(str(int(t) + 1) for t in nums.split())))


def test_stickytape_module_returns_the_named_module():
    src = ("__stickytape_write_module('pkg/__init__.py', b'')\n"
           "__stickytape_write_module('pkg/mod.py', b'print(\\'x\\')\\nv = \"\\\\x41\"\\n')\n")
    assert dec("stickytape_module", src, {"module": "pkg/mod.py"}) == b"print('x')\nv = \"\\x41\"\n"
    with pytest.raises(ValueError):
        dec("stickytape_module", src, {"module": "pkg/missing.py"})


def test_exec_alias_b85xor_zlib_unwraps_two_layers():
    key = bytes([1, 2, 3])
    xor = bytes(c ^ key[i % 3] for i, c in enumerate(zlib.compress(
        ('y = 1\nE(zlib.decompress(base64.b64decode("%s")))' %
         base64.b64encode(zlib.compress(b"print(2)")).decode()).encode())))
    enc = base64.b85encode(xor).decode()
    head = ("import base64, zlib\ndef x(d, k):\n    return bytes(d[i] ^ k[i % len(k)] for i in range(len(d)))\n"
            "K = bytes([1, 2, 3])\nE = exec\n")
    src = head + f'E(zlib.decompress(x(base64.b85decode("{enc[:10]}" + "{enc[10:]}"), K)))\n'
    assert dec("exec_alias_b85xor_zlib", src).decode() == head + "y = 1\nprint(2)\n"


def test_rev_b64_zlib_lambda_unwraps_nested_layers():
    lam = "_ = lambda __: __import__('zlib').decompress(__import__('base64').b64decode(__[::-1]))\n"

    def wrap(s):
        return "exec((_)(b'%s'))" % base64.b64encode(zlib.compress(s.encode())).decode()[::-1]
    out = dec("rev_b64_zlib_lambda", lam + wrap(lam + wrap("print(3)")) + "\n").decode()
    assert out == lam + lam + "print(3)\n"


def test_exec_str_b64_fernet_unwraps_escaped_b64_and_fernet_stages():
    key = base64.urlsafe_b64encode(bytes(range(32)))
    kv = base64.b64encode(key).decode()
    token = fernet_encrypt(key, b"print('fernet')").decode()
    s3 = f"KV = '{kv}'\nexec(F(bytes(B.b64decode(KV))).decrypt(b'{token}'))"
    s2 = f"exec(B.b64decode('{base64.b64encode(s3.encode()).decode()}'))"
    top = 'import base64 as B\nexec("' + s2.replace("\\", "\\\\").replace('"', '\\"') + '")\n'
    assert dec("exec_str_b64_fernet", top).decode() == f"import base64 as B\nKV = '{kv}'\nprint('fernet')\n"
    tampered = top.replace(base64.b64encode(s3.encode()).decode(),
                           base64.b64encode(s3.replace(token, token[:-8] + "AAAAAAA=").encode()).decode())
    assert "print('fernet')" not in dec("exec_str_b64_fernet", tampered).decode()  # a bad HMAC is left untouched


def test_py_shift_charcode_join_folds_joins_and_integer_assignments():
    resolver = "getattr(__builtins__, 'chr')"
    word = "setup"
    items = ", ".join(f"(({ord(c)} << 2) >> 2) + 0" for c in word)
    src = (f"x = ''.join(map(getattr(__builtins__,  'chr'), [{items}]))\n"
           "state = (3 << 4) - 1 ^ 2\n"
           "keep = ''.join(map(getattr(__builtins__, 'chr'), [a, 104]))\n")
    out = dec("py_shift_charcode_join", src, {"resolver": resolver}).decode()
    assert out.splitlines()[0] == f"x = {word!r}"
    assert out.splitlines()[1] == f"state = {((3 << 4) - 1) ^ 2}"
    assert out.splitlines()[2] == src.splitlines()[2]  # a non-constant item leaves the join as it was
