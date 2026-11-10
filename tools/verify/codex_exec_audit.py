"""Read a narrow subset of Codex's JavaScript tool wrappers without executing JavaScript.

Only literal arguments, constant bindings, direct allowed tool calls, and text() output are accepted.
Dynamic commands, arbitrary JavaScript, and unknown tools fail closed.
"""
from __future__ import annotations

import json
import re

from tools.common.sanitize import unescape
from tools.common.tsparse import PARSERS, field, text


class WrapperError(ValueError):
    pass


_RESULT = object()


def tool_calls(script: str, allowed: set[str]) -> list[tuple[str, object]]:
    tree = PARSERS["js"].parse(script.encode())
    if tree.root_node.has_error:
        raise WrapperError("unparseable JavaScript tool wrapper")
    bindings, calls = {}, []

    def literal(node):
        if node is None:
            raise WrapperError("missing tool argument")
        if node.type in ("string", "template_string"):
            if any(c.type == "template_substitution" for c in node.named_children):
                raise WrapperError("computed string in tool wrapper")
            escapes = [text(c) for c in node.named_children if c.type == "escape_sequence"]
            if any(not re.fullmatch(r"\\(?:[ntr0\\'\"`]|x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|u\{[0-9a-fA-F]+\})", e)
                   for e in escapes):
                raise WrapperError("unsupported string escape in tool wrapper")
            raw = "".join(text(c) for c in node.named_children
                          if c.type in ("string_fragment", "escape_sequence"))
            return unescape(raw)[0]
        if node.type in ("number", "true", "false", "null"):
            try:
                return json.loads(text(node))
            except ValueError as e:
                raise WrapperError("unsupported literal in tool wrapper") from e
        if node.type == "identifier" and text(node) in bindings:
            value = bindings[text(node)]
            if value is not _RESULT:
                return value
        if node.type == "array":
            return [literal(c) for c in node.named_children]
        if node.type == "object":
            result = {}
            for pair in node.named_children:
                if pair.type != "pair":
                    raise WrapperError("computed object in tool wrapper")
                key = field(pair, "key")
                if key.type in ("property_identifier", "identifier"):
                    name = text(key)
                elif key.type == "string":
                    name = literal(key)
                else:
                    raise WrapperError("computed object key in tool wrapper")
                if name in result:
                    raise WrapperError("duplicate object key in tool wrapper")
                result[name] = literal(field(pair, "value"))
            return result
        raise WrapperError(f"nonliteral tool argument: {node.type}")

    def expression(node, output=False):
        if node.type == "await_expression":
            return expression(node.named_children[0], output)
        if node.type == "call_expression":
            fn = field(node, "function")
            args = field(node, "arguments").named_children
            if fn.type == "identifier" and text(fn) == "text":
                if not output or len(args) != 1:
                    raise WrapperError("unsupported text() call in tool wrapper")
                expression(args[0], True)
                return _RESULT
            if fn.type != "member_expression" or text(field(fn, "object")) != "tools":
                raise WrapperError("unsupported call in tool wrapper")
            name = text(field(fn, "property"))
            if name not in allowed:
                raise WrapperError(f"disallowed nested tool: {name}")
            if len(args) != 1:
                raise WrapperError("nested tool must have one literal argument")
            value = literal(args[0])
            if name == "apply_patch":
                if not isinstance(value, str):
                    raise WrapperError("apply_patch input must be a literal string")
            elif not isinstance(value, dict):
                raise WrapperError("nested tool arguments must be a literal object")
            calls.append((name, value))
            return _RESULT
        if output and node.type == "identifier" and bindings.get(text(node)) is _RESULT:
            return _RESULT
        if output and node.type == "member_expression":
            obj, prop = field(node, "object"), field(node, "property")
            if obj.type == "identifier" and bindings.get(text(obj)) is _RESULT and text(prop) == "output":
                return _RESULT
            raise WrapperError("unsupported output access in tool wrapper")
        return literal(node)

    for stmt in tree.root_node.named_children:
        if stmt.type in ("comment", "empty_statement"):
            continue
        if stmt.type == "lexical_declaration" and stmt.children[0].type == "const":
            for decl in stmt.named_children:
                name = field(decl, "name")
                if decl.type != "variable_declarator" or name.type != "identifier" or \
                        text(name) in bindings or text(name) in {"tools", "text"}:
                    raise WrapperError("unsupported binding in tool wrapper")
                bindings[text(name)] = expression(field(decl, "value"))
        elif stmt.type == "expression_statement":
            expression(stmt.named_children[0], True)
        else:
            raise WrapperError(f"unsupported JavaScript in tool wrapper: {stmt.type}")
    if not calls:
        raise WrapperError("tool wrapper has no auditable tool calls")
    return calls
