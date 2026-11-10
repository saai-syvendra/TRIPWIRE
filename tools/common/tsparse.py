"""
tree-sitter parsers and node helpers for package code. Files are parsed as data; nothing is executed.
"""
from __future__ import annotations

import sys

import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language, Node, Parser

from tools.common.sanitize import unescape

# Minified bundles nest far deeper than Python's default limit.
sys.setrecursionlimit(20000)

PARSERS = {"js": Parser(Language(tree_sitter_javascript.language())),
           "py": Parser(Language(tree_sitter_python.language()))}
EXTENSIONS = {".js": "js", ".cjs": "js", ".mjs": "js", ".jsx": "js", ".py": "py"}


def text(node: Node) -> str:
    return node.text.decode("utf-8", "replace")


def field(node: Node, *names: str) -> Node | None:
    for name in names:
        child = node.child_by_field_name(name)
        if child is not None:
            return child
    return None


def descendants(node: Node):
    stack = [node]
    while stack:
        n = stack.pop()
        yield n
        stack.extend(reversed(n.children))


def static_string(node: Node | None) -> str | None:
    """The value of a string literal written out in full (`'b'`, `"b"`, `` `b` ``), or None for anything else,
    including a template or f-string with a substitution."""
    if node is None or node.type not in ("string", "template_string"):
        return None
    if any(c.type in ("template_substitution", "interpolation") for c in node.named_children):
        return None
    raw = "".join(text(c) for c in node.named_children
                  if c.type in ("string_fragment", "string_content", "escape_sequence"))
    return unescape(raw)[0]


def static_member_name(node: Node | None) -> str | None:
    """The property a member access names when the code fixes it: `a.b`, `a['b']`, `a["b"]`, a[`b`] (and Python
    `a.b`, `a['b']`). None for a computed one (`a[k]`, `a[f(x)]`, a[`b${x}`]) and for anything that is not a
    member access. Obfuscator.io decoding leaves every property in bracket form, so both spellings must read alike."""
    if node is None:
        return None
    if node.type in ("member_expression", "attribute"):
        prop = field(node, "property", "attribute")
        return text(prop) if prop is not None and prop.type in (
            "property_identifier", "private_property_identifier", "identifier") else None
    if node.type in ("subscript_expression", "subscript"):
        return static_string(field(node, "index", "subscript"))
    return None


def static_key(node: Node | None) -> str | None:
    """The name an object, class or method key gives when the code fixes it: `b`, `'b'`, `["b"]`, [`b`]."""
    if node is None:
        return None
    if node.type in ("identifier", "property_identifier", "private_property_identifier",
                     "shorthand_property_identifier"):
        return text(node)
    if node.type == "computed_property_name":
        return static_string(node.named_children[0]) if node.named_children else None
    return static_string(node)


def member_object(node: Node | None) -> Node | None:
    """The object of a member access (`a` in `a.b` or `a['b']`), or None."""
    if node is None or node.type not in ("member_expression", "attribute", "subscript_expression", "subscript"):
        return None
    return field(node, "object", "value")


def pure_alias(stmt: Node) -> bool:
    """A declaration that only copies names (`const _0x51ad63 = _0x192368;`), which obfuscator.io leaves at the top
    of every function it rewrote. It has no effect, so it does not stop a helper reading as one-line."""
    if stmt.type not in ("lexical_declaration", "variable_declaration"):
        return False
    decls = [d for d in stmt.named_children if d.type == "variable_declarator"]
    return bool(decls) and all((v := d.child_by_field_name("value")) is not None and v.type == "identifier"
                               for d in decls)
