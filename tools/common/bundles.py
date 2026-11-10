"""
Module units inside bundled JavaScript (webpack 4/5 and ncc, esbuild, browserify): each unit is the factory
function of one original module, with its module id (a path or number), the module ids it requires, and a role:
`library` for code from node_modules, licensed third-party code and bundler shims, `package` for the package's
own sources, `unknown` otherwise.

Minified webpack and ncc bundles number their modules, so ids say nothing. There the bundle's entry (the module
the bootstrap loads, `__webpack_require__(__webpack_require__.s = N)`, ncc's `module.exports = r(N)`,
browserify's entry list, esbuild's top-level `require_x()`) is package code, and every unit gets its require
distance from the entry (`depth`, null when unreached or when no entry is found). The generator ranks unknown
units by that distance.

Units are byte ranges in the original (or derived) file, so anchors into them stay valid. Parsed with
tree-sitter as data; nothing is executed.
"""
from __future__ import annotations

import re

from tools.common.tsparse import descendants, text

FACTORIES = {"function_expression", "arrow_function", "function"}
MIN_UNITS = 3  # an object literal with fewer factory functions is ordinary code, not a module table


def key_text(key) -> str:
    raw = text(key)
    return raw[1:-1] if raw[:1] in "'\"`" and raw[-1:] == raw[:1] else raw


# A module whose whole body just re-exports another module is a bundler-generated shim for an external
# dependency or a Node builtin, so it is library code whatever its id.
REEXPORT = re.compile(r"(module\.)?exports\s*=\s*[\w$.]+(?:\([^()]*\))?\(\s*[\"'][^\"']+[\"']\s*\)\s*;?\s*$")
# A preserved license banner marks third-party code (bundlers keep `/*! ... */` and `@license` comments).
BANNER = re.compile(r"/\*!|@license\b|@preserve\b")


def role_of(module_id: str, body: str = "") -> str:
    if "node_modules/" in module_id or module_id.startswith(("webpack/", "(webpack)")):
        return "library"
    if body and len(body) < 400 and REEXPORT.search(body.strip().rstrip("}").strip()):
        return "library"
    if module_id.startswith(("./", "src/", "lib/")) or module_id.endswith((".js", ".ts", ".mjs", ".cjs")):
        return "package"
    if body and BANNER.search(body[:2000]):
        return "library"
    return "unknown"


def factory_of(value):
    """The module factory a module-table entry holds: a function, or browserify's [function, deps]."""
    if value is None:
        return None, None
    if value.type == "parenthesized_expression" and value.named_children:
        value = value.named_children[0]
    if value.type in FACTORIES:
        return value, "webpack"
    if value.type == "array" and value.named_children and value.named_children[0].type in FACTORIES:
        return value.named_children[0], "browserify"
    return None, None


def require_param(fn, kind: str) -> str | None:
    """The name a factory receives the bundle's require function under: webpack/ncc's third parameter,
    browserify's first."""
    params = fn.child_by_field_name("parameters") if fn is not None else None
    names = [text(p) for p in params.named_children if p.type == "identifier"] if params is not None else []
    if fn is not None and fn.child_by_field_name("parameter") is not None:  # `e => ...`
        names = [text(fn.child_by_field_name("parameter"))]
    if kind == "webpack":
        return names[2] if len(names) > 2 else None
    if kind == "browserify":
        return names[0] if names else None
    return None


def reexport_of(fn, kind: str) -> str | None:
    """The module a webpack/ncc unit only re-exports: its whole body is `<module>.exports = require("x")`, with
    <module> the factory's first parameter (or `module`) and `require` not one of its parameters, so it is the
    runtime's own require. Read from the syntax tree, never from text. None for anything else."""
    if fn is None or kind != "webpack":
        return None
    params = fn.child_by_field_name("parameters")
    names = [text(p) for p in params.named_children if p.type == "identifier"] if params is not None else []
    if fn.child_by_field_name("parameter") is not None:
        names = [text(fn.child_by_field_name("parameter"))]
    body = fn.child_by_field_name("body")
    if body is None:
        return None
    expr = body
    if body.type == "statement_block":
        stmts = [c for c in body.named_children if c.type != "comment" and not (
            c.type == "expression_statement" and c.named_children and c.named_children[0].type == "string")]
        if len(stmts) != 1 or stmts[0].type != "expression_statement" or not stmts[0].named_children:
            return None
        expr = stmts[0].named_children[0]
    while expr.type == "parenthesized_expression" and expr.named_children:
        expr = expr.named_children[0]
    if expr.type != "assignment_expression":
        return None
    left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
    if left is None or right is None or left.type != "member_expression":
        return None
    prop, obj = left.child_by_field_name("property"), left.child_by_field_name("object")
    if prop is None or text(prop) != "exports" or obj is None or obj.type != "identifier" or \
            text(obj) not in ({names[0]} if names else set()) | {"module"}:
        return None
    if right.type != "call_expression":
        return None
    callee, args = right.child_by_field_name("function"), right.child_by_field_name("arguments")
    argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
    if callee is None or callee.type != "identifier" or text(callee) != "require" or "require" in names or \
            len(argv) != 1 or argv[0].type != "string":
        return None
    return key_text(argv[0])


def literal_id(arg) -> str | None:
    """A module id given literally, also as webpack's `__webpack_require__.s = 12`."""
    if arg is None:
        return None
    if arg.type in ("assignment_expression", "augmented_assignment_expression"):
        arg = arg.child_by_field_name("right")
    if arg is not None and arg.type in ("number", "string"):
        return key_text(arg)
    return None


def require_calls(scope, names: set[str]) -> list[tuple[object, str]]:
    """(call, module id) for every call of a require binding with one literal id inside `scope`."""
    out = []
    for call in (n for n in descendants(scope) if n.type == "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or fn.type != "identifier" or text(fn) not in names:
            continue
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        mid = literal_id(argv[0]) if len(argv) == 1 else None
        if mid is not None:
            out.append((call, mid))
    return out


MODULE_KEY = re.compile(r"^\d+$|[/\\]|\.(c|m)?[jt]sx?$|\.json$")


def module_key(key) -> bool:
    """A module-table key is a number or a module path; a plain property name (`start`, `onMessage`) belongs
    to an ordinary object of functions, not a bundle."""
    if key is None:
        return False
    if key.type == "number":
        return True
    return key.type == "string" and bool(MODULE_KEY.search(key_text(key)))


def tables(tree) -> list[tuple]:
    """(key node, factory node, kind) for every entry of every module table, before nesting is resolved."""
    out = []
    for obj in (n for n in descendants(tree.root_node) if n.type == "object"):
        entries = []
        for member in obj.named_children:
            if member.type == "pair":
                fn, kind = factory_of(member.child_by_field_name("value"))
                if fn is not None and module_key(member.child_by_field_name("key")):
                    entries.append((member.child_by_field_name("key"), fn, kind))
            elif member.type == "method_definition":  # esbuild: __commonJS({ "path"(exports, module) {...} })
                name = member.child_by_field_name("name")
                if name is not None and name.type in ("string", "number") and module_key(name):
                    entries.append((name, member, "esbuild"))
        if len(entries) >= MIN_UNITS:
            out += entries
    # esbuild wraps each module in its own __commonJS call, so single-entry objects count there
    for call in (n for n in descendants(tree.root_node) if n.type == "call_expression"):
        fn = call.child_by_field_name("function")
        if fn is None or text(fn) not in ("__commonJS", "__esm"):
            continue
        args = call.child_by_field_name("arguments")
        obj = args.named_children[0] if args is not None and args.named_children else None
        for member in (obj.named_children if obj is not None and obj.type == "object" else []):
            name = member.child_by_field_name("name") or member.child_by_field_name("key")
            if name is not None and not any(m is member for _, m, _ in out):
                out.append((name, member, "esbuild"))
    return out


def esbuild_wrappers(tree, by_node: dict) -> dict[str, str]:
    """`var require_x = __commonJS({...})` -> {"require_x": module id}."""
    out = {}
    for decl in (n for n in descendants(tree.root_node) if n.type == "variable_declarator"):
        value = decl.child_by_field_name("value")
        name = decl.child_by_field_name("name")
        if value is None or name is None or value.type != "call_expression":
            continue
        for (s, e), mid in by_node.items():
            if value.start_byte <= s and e <= value.end_byte:
                out[text(name)] = mid
                break
    return out


def analyse(tree, file: str, derived_from: str | None = None) -> dict:
    """{"units": [...], "entries": [module ids], "require_names": [names the bootstrap requires through]}.
    Each unit: file, derived_from, start_byte, end_byte, kind, module_id, role, requires, depth."""
    raw = []
    for key, fn, kind in tables(tree):
        raw.append({"file": file, "derived_from": derived_from, "start_byte": fn.start_byte, "end_byte": fn.end_byte,
                    "kind": kind, "module_id": key_text(key)[:200], "_node": fn})
    raw.sort(key=lambda u: (u["start_byte"], -u["end_byte"]))
    kept, end = [], -1  # outermost units only: a module table inside a unit belongs to that unit
    for u in raw:
        if u["start_byte"] >= end:
            kept.append(u)
            end = u["end_byte"]
    if not kept:
        return {"units": [], "entries": [], "require_names": []}
    ids = {u["module_id"] for u in kept}
    wrappers = esbuild_wrappers(tree, {(u["start_byte"], u["end_byte"]): u["module_id"] for u in kept
                                       if u["kind"] == "esbuild"})
    for u in kept:
        fn = u["_node"]
        if u["kind"] == "esbuild":
            calls = [(c, wrappers[text(c.child_by_field_name("function"))])
                     for c in descendants(fn) if c.type == "call_expression"
                     and text(c.child_by_field_name("function") or c) in wrappers]
        else:
            name = require_param(fn, u["kind"])
            calls = require_calls(fn, {name}) if name else []
        u["requires"] = sorted({mid for _, mid in calls if mid in ids and mid != u["module_id"]})

    def outside(node) -> bool:
        return not any(u["start_byte"] <= node.start_byte < u["end_byte"] for u in kept)

    entries, loaders = [], {}
    # The bootstrap's require is a function the bundle declares itself (never a global such as parseInt).
    declared = {text(n.child_by_field_name("name")) for n in descendants(tree.root_node)
                if n.type in ("function_declaration", "variable_declarator") and outside(n)
                and n.child_by_field_name("name") is not None}
    # webpack/ncc: the bootstrap's own require called with a literal id outside every unit
    for call in (n for n in descendants(tree.root_node) if n.type == "call_expression" and outside(n)):
        fn = call.child_by_field_name("function")
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        if fn is None or fn.type != "identifier" or len(argv) != 1 or text(fn) not in declared:
            continue
        mid = literal_id(argv[0])
        if mid in ids:
            rank = 0 if argv[0].type == "assignment_expression" else 1
            entries.append((rank, call.start_byte, mid))
            loaders.setdefault(text(fn), rank)
    # esbuild: require_x() at top level
    for call in (n for n in descendants(tree.root_node) if n.type == "call_expression" and outside(n)):
        fn = call.child_by_field_name("function")
        if fn is not None and text(fn) in wrappers:
            entries.append((1, call.start_byte, wrappers[text(fn)]))
    # browserify: prelude(modules, cache, [entry ids])
    for call in (n for n in descendants(tree.root_node) if n.type == "call_expression"):
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        if len(argv) == 3 and argv[0].type == "object" and argv[2].type == "array" and \
                any(u["start_byte"] >= argv[0].start_byte and u["end_byte"] <= argv[0].end_byte for u in kept):
            entries += [(0, call.start_byte, key_text(x)) for x in argv[2].named_children
                        if x.type in ("number", "string") and key_text(x) in ids]
    # an explicit `.s = N` entry wins over other top-level loads
    best = min((e[0] for e in entries), default=None)
    require_names = {name for name, rank in loaders.items() if rank == best}
    entry_ids = list(dict.fromkeys(mid for rank, _, mid in sorted(entries, key=lambda e: (e[0], e[1]))
                                   if rank == best))

    by_id = {u["module_id"]: u for u in kept}
    depth = {mid: 0 for mid in entry_ids}
    frontier = list(entry_ids)
    while frontier:
        nxt = []
        for mid in frontier:
            for r in by_id[mid]["requires"]:
                if r not in depth:
                    depth[r] = depth[mid] + 1
                    nxt.append(r)
        frontier = nxt
    out = []
    for u in kept:
        fn = u.pop("_node")
        role = role_of(u["module_id"], text(fn))
        if role == "unknown" and depth.get(u["module_id"]) == 0:
            role = "package"  # the module the bundle starts from
        out.append({**u, "role": role, "depth": depth.get(u["module_id"])})
    return {"units": out, "entries": entry_ids, "require_names": sorted(require_names)}


def units(tree, file: str, derived_from: str | None = None) -> list[dict]:
    """Every module unit in a parsed JavaScript file, outermost tables only, in source order."""
    return analyse(tree, file, derived_from)["units"]


def unit_at(all_units: list[dict], file: str, offset: int, derived_from: str | None = None) -> dict | None:
    return next((u for u in all_units if u["file"] == file and u.get("derived_from") == derived_from
                 and u["start_byte"] <= offset < u["end_byte"]), None)


def summary(all_units: list[dict], entries: dict | None = None) -> list[dict]:
    """Per-file unit counts by role, for the record (the full list stays in prepared.json)."""
    out = {}
    for u in all_units:
        key = (u["file"], u.get("derived_from"))
        s = out.setdefault(key, {"file": u["file"], "derived_from": u.get("derived_from"), "bundler": u["kind"],
                                 "count": 0, "entry": (entries or {}).get(key), "by_role": {}})
        s["count"] += 1
        s["by_role"][u["role"]] = s["by_role"].get(u["role"], 0) + 1
    return list(out.values())
