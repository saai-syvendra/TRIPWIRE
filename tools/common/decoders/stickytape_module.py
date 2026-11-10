"""
Family:     stickytape bundles (one Python file that recreates modules with
            `__stickytape_write_module('<path>', b'<source>')` before running its main code)
Reverses:   the bytes literal holding one bundled module's source (params.module, the path given as first argument)
Per sample: params.module

decode() returns the module's source text: the literal body with its backslash escapes undone
(codecs.escape_decode). Only the literal is read as data; nothing is imported, compiled, run or evaluated.
Pure and deterministic: stdlib codecs/re plus tree-sitter.
"""
from __future__ import annotations

import codecs
import re

from tools.common.tsparse import PARSERS, descendants, text

_STR = re.compile(r"""^(?:[bB])?(['"]{1,3})(.*)\1$""", re.S)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    want = params["module"]
    root = PARSERS["py"].parse(input_bytes).root_node
    for call in (n for n in descendants(root) if n.type == "call"):
        f = call.child_by_field_name("function")
        if f is None or f.type != "identifier" or text(f) != "__stickytape_write_module":
            continue
        args = [a for a in call.child_by_field_name("arguments").named_children if a.type != "comment"]
        if len(args) != 2 or args[0].type != "string" or args[1].type != "string":
            continue
        name = _STR.match(text(args[0]))
        if not name or name.group(2) != want:
            continue
        body = _STR.match(text(args[1]))
        if not body:
            raise ValueError("module literal not recognised")
        return codecs.escape_decode(body.group(2).encode("latin-1", "backslashreplace"))[0]
    raise ValueError(f"module {want!r} not found")
