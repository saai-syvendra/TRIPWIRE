"""
Family:     generic (obfuscator.io output; seen in shai-hulud bundles)
Reverses:   the base64 string array when its rotation checksum and call sites index it through const-object
            properties
Per sample: nothing (no params; the table, offset and rotation are found in the file)

obfuscator.io base64 string-array recovery for files where the rotation checksum (and the body's
decoder calls) index the decoder through local const-object properties, e.g.

    const _0x46b694 = { _0x4a8b2d: 0x5bf, ... };
    ... parseInt(_0x4ef8a(_0x46b694._0x4a8b2d)) ...

The stock recovery in tools/common/deobf.py reads only numeric-literal arguments, so these member
expressions make the checksum unresolvable and no rotation matches. This module resolves each
`OBJ.prop` member expression to its numeric literal, scope-aware (nearest enclosing function wins,
program scope otherwise), rewrites them in place, and then defers to deobf.derive() for the table
decode, rotation (checksum-gated) and call-site substitution.

Pure and deterministic: tree-sitter parse only, no eval, no package execution, no key material.
params: none required.
"""
from __future__ import annotations

from tools.common import deobf
from tools.common.tsparse import PARSERS, descendants, text


def _enclosing_fn_range(node):
    FUNCS = ("function_declaration", "function_expression", "function", "arrow_function",
             "method_definition")
    n = node.parent
    while n is not None:
        if n.type in FUNCS:
            return (n.start_byte, n.end_byte)
        n = n.parent
    return (0, 1 << 62)  # program scope


def _object_maps(root):
    """List of (name, (scope_start, scope_end), {prop: literal_text})."""
    maps = []
    for d in descendants(root):
        if d.type != "variable_declarator":
            continue
        name = d.child_by_field_name("name")
        val = d.child_by_field_name("value")
        if not name or not val or name.type != "identifier" or val.type != "object":
            continue
        m = {}
        for pair in val.named_children:
            if pair.type != "pair":
                continue
            k = pair.child_by_field_name("key")
            v = pair.child_by_field_name("value")
            if not k or not v or v.type != "number":
                continue
            m[text(k)] = text(v)
        if m:
            maps.append((text(name), _enclosing_fn_range(d), m))
    return maps


def _resolve_member(name, byte, maps):
    """Resolve OBJ.prop at a use site to its literal text, innermost enclosing scope first."""
    best = None
    for obj, (s, e), m in maps:
        if obj == name[0] and name[1] in m and s <= byte <= e:
            span = e - s
            if best is None or span < best[0]:
                best = (span, m[name[1]])
    return None if best is None else best[1]


def _substitute_objprops(src: bytes) -> bytes:
    tree = PARSERS["js"].parse(src)
    root = tree.root_node
    maps = _object_maps(root)
    edits = []  # (start, end, replacement bytes)
    for n in descendants(root):
        if n.type != "member_expression":
            continue
        obj = n.child_by_field_name("object")
        prop = n.child_by_field_name("property")
        if not obj or not prop or obj.type != "identifier" or prop.type != "property_identifier":
            continue
        lit = _resolve_member((text(obj), text(prop)), n.start_byte, maps)
        if lit is not None:
            edits.append((n.start_byte, n.end_byte, lit.encode()))
    out = bytearray(src)
    for s, e, rep in sorted(edits, reverse=True):
        out[s:e] = rep
    return bytes(out)


def decode(input_bytes: bytes, params: dict, read) -> bytes:
    pre = _substitute_objprops(input_bytes)
    result = deobf.derive(pre)
    if result is None:
        raise ValueError("obfio_objprop: deobf.derive failed after object-property resolution")
    return result[0]
