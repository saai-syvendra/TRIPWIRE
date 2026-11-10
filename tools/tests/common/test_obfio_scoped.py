"""obfio_scoped: the obfuscator.io base64 string array with decoder aliases resolved by lexical scope. Synthetic
fixture from tools.tests.obfio; the real need (a reused local name that defeats obfio_objprop) is from the batch."""
import pytest

from tools.common.decoders import load_decoder, obfio_scoped
from tools.tests.common.test_obfio_objprop import TEMPLATE, USES
from tools.tests.obfio import obfuscate

LOCAL = ("function _0xy(){const _0xc=_0xd;return _0xc(435,'kQ9z');}\n"
         "function _0xz(){const _0xc=function(_0xu){return _0xu;};return _0xc(1);}\n")


def test_direct_and_scoped_alias_calls_are_resolved():
    src = obfuscate(USES, TEMPLATE, variant="base64", rotation=7)
    src = src.replace("const os=require(_0xd(435,'kQ9z'));", LOCAL + "const os=require(_0xy());", 1)
    out = obfio_scoped.decode(src.encode(), {}, None).decode()
    assert 'return "os";' in out  # the alias inside _0xy
    assert "return _0xc(1);" in out  # the unrelated local _0xc is left alone
    assert '.exec("whoami")' in out and '==="win32"' in out


def test_a_wrong_checksum_target_is_refused():
    src = obfuscate(USES, TEMPLATE, variant="base64", rotation=7).replace("(_0xp,0x1af9b)", "(_0xp,0x1af9c)", 1)
    with pytest.raises(ValueError):
        obfio_scoped.decode(src.encode(), {}, None)


def test_registered():
    assert callable(load_decoder("obfio_scoped"))
