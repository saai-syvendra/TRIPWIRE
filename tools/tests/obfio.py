"""A forward obfuscator in the style of obfuscator.io's string arrays, for tests only: it hides a small inert
script's strings behind a rotated table, a decoder with an offset (plain, base64 or rc4) and a wrapper, so the
deobfuscator can be checked without real malware."""
import base64
import json

from tools.common.deobf import B64_CUSTOM, B64_STD, js_parse_int, rc4

FILLER = ["1234abc", "56789xy", "4321zz", "toString", "length", "prototype", "call", "apply"]


def b64_custom_encode(data: bytes) -> str:
    return base64.b64encode(data).decode().rstrip("=").translate(str.maketrans(B64_STD[:64], B64_CUSTOM[:64]))


def encode(value: str, variant: str, key: str) -> str:
    if variant == "base64":
        return b64_custom_encode(value.encode())
    if variant == "rc4":
        return b64_custom_encode(rc4(value.encode().decode("latin-1"), key).encode("latin-1"))
    return value


DECODERS = {
    "none": "",
    "base64": "const _0xal='" + B64_CUSTOM + "';_0xv=_0xb64(_0xv,_0xal);",
    "rc4": "const _0xal='" + B64_CUSTOM + "';_0xv=_0xrc4(_0xb64(_0xv,_0xal),_0xk,0x100,String.fromCharCode,'^');",
}


def obfuscate(uses: dict[str, str], template: str, variant: str = "none", offset: int = 0x1b3, rotation: int = 5,
              key: str = "kQ9z") -> str:
    """template refers to strings as {name}; each becomes a decoder call. Returns the obfuscated script."""
    plain = list(dict.fromkeys(list(uses.values()) + FILLER))
    index = {v: i for i, v in enumerate(plain)}
    k = rotation % len(plain)
    stored = plain[-k:] + plain[:-k] if k else list(plain)  # rotated back; the loop shifts it forward k times
    stored_enc = [encode(v, variant, key) for v in stored]
    nums = [index[v] + offset for v in FILLER[:3]]
    target = js_parse_int(FILLER[0]) + js_parse_int(FILLER[1]) * 2 - js_parse_int(FILLER[2])

    def call(v, wrapped=False):
        i = index[v] + offset
        return f"_0xw('{key}',{i + 5})" if wrapped else f"_0xd({i},'{key}')"
    body = template.format(**{n: call(v, wrapped=(j % 2 == 1)) for j, (n, v) in enumerate(uses.items())})
    return (
        f"function _0xp(){{const _0xa={json.dumps(stored_enc)};_0xp=function(){{return _0xa;}};return _0xp();}}\n"
        f"function _0xd(_0xi,_0xk){{const _0xa=_0xp();return _0xd=function(_0xi,_0xk){{_0xi=_0xi-{hex(offset)};"
        f"let _0xv=_0xa[_0xi];{DECODERS[variant]}return _0xv;}},_0xd(_0xi,_0xk);}}\n"
        f"(function(_0xq,_0xt){{const _0xc=_0xd,_0xr=_0xq();while(!![]){{try{{const _0xs=parseInt(_0xc({nums[0]},'{key}'))"
        f"+parseInt(_0xc({nums[1]},'{key}'))*0x2-parseInt(_0xc({nums[2]},'{key}'));if(_0xs===_0xt)break;"
        f"else _0xr['push'](_0xr['shift']());}}catch(_0xe){{_0xr['push'](_0xr['shift']());}}}}}}(_0xp,{hex(int(target))}));\n"
        f"function _0xw(_0xm,_0xn){{return _0xd(_0xn-0x5,_0xm);}}\n" + body)
