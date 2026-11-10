"""
Family:     PyPI setup.py droppers that write a stage to disk with `f.write(<wrapper>('<base64 literal>'))`, where the
            wrapper is a local one-line helper around base64.b64decode(...).decode('utf8')
Reverses:   the base64 string literal passed to the named wrapper (params.func, default "b64"); the nth such call
            (params.nth, default 0)
Per sample: params.func (wrapper name), params.nth

decode() returns the decoded stage text, i.e. the file the dropper writes. Only the literal is read as data;
nothing is imported, compiled, run or evaluated. Pure and deterministic: stdlib base64 plus tree-sitter.
"""
from __future__ import annotations

import base64
import re

from tools.common.tsparse import PARSERS, descendants, text

_STR = re.compile(r"""^(?:[bBuU]|[bB][rR]|[rR][bB])?(['"]{1,3})(.*)\1$""", re.S)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    func = params.get("func", "b64")
    nth = int(params.get("nth", 0))
    root = PARSERS["py"].parse(input_bytes).root_node
    found = []
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != func:
            continue
        args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 1 or args[0].type != "string":
            continue
        m = _STR.match(text(args[0]))
        if m:
            found.append(m.group(2).encode("ascii", "ignore"))
    if nth >= len(found):
        raise ValueError(f"no call {func}(<literal>) number {nth}")
    return base64.b64decode(re.sub(rb"\s+", b"", found[nth]), validate=True)
