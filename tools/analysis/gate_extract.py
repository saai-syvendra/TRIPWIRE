#!/usr/bin/env python3
"""
The candidate generator: static code facts for the install path of one unpacked package. It proposes the
closed set an analyst chooses from: environment conditions in positive form (one candidate site per test node,
k_ ids), the decisions that test them (guards with kind and arm, q_ ids), candidate gates with their nesting
expression, regions and env recipe, and hints (sinks with anchors, delays, swallowed errors, defanged endpoints,
obfuscation signals, bundle units). Every location is an anchor (tools/common/anchors.py).

Beyond if/ternary/switch/short-circuit/early exits it treats a try body that starts with a probe (opening a path,
loading a module, running a probe command) as a decision, and tested commands such as `sudo -n` or `ps` as
conditions. Value bindings are per function scope, so names reused across a minified bundle are not joined.
obfuscator.io string arrays are recovered first (deobf.py) and analysed in the recovered copy, and calls into
bundle module tables are followed into the unit they load.

Package files are parsed with tree-sitter as data. Nothing is executed, imported or evaluated.

Library use: Extractor(root).run(entries), see prepare.py.
CLI (debugging): python tools/analysis/gate_extract.py <unpacked dir> <hook> <entry file> [more entry files]
"""
from __future__ import annotations

import bisect
import functools
import json
import re
import sys
from pathlib import Path

from tree_sitter import Node

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import anchors, bundles, deobf  # noqa: E402
from tools.common.anchors import candidate_id, node_anchor, span_anchor  # noqa: E402
from tools.common.contract import COND_ID, IN_SCOPE, dnf_terms, min_false_set  # noqa: E402
from tools.common.sanitize import IPV4, URL, defang, redact, unescape  # noqa: E402,F401
from tools.common.tsparse import (EXTENSIONS, PARSERS, descendants, field, member_object, pure_alias,  # noqa: E402
                                  static_member_name, text)
from tools.common.tables import (
    ARG_WRAPPERS,
    ENV_GETTERS,
    EXEC_PROBES,
    FILE_TESTS,
    HOME_VARS,
    JS_CMP,
    MIRROR,
    NEGATE,
    PATH_JOINS,
    PATH_LIKE,
    PY_CMP,
    QUERIES,
    READ_CALLS,
    SINKS,
    STRIP_METHODS,
    TOOL_TESTS,
    TRY_PROBES,
    env_category,
    path_category,
)
from tools.common.recipe import build_recipe, negate_condition  # noqa: E402

# Members that pick part of a command's result: its output, its error output or its exit status.
ACCESSORS = {"toString": "stdout", "stdout": "stdout", "trim": "stdout", "output": "stdout", "stderr": "stderr",
             "status": "returncode", "returncode": "returncode", "exitCode": "returncode", "code": "returncode"}

MAX_WALKS = 50000
# Distinct guard stacks a function is walked under. A popular library helper would otherwise be re-walked under
# every caller's stack and use up MAX_WALKS before the package's own modules are reached.
MAX_CONTEXTS = 2


def worst_role(roles: set) -> str:
    """The least-trusted role among a claim's sites: a library site makes it library, else an unknown site makes
    it unknown, else package. Only confidently-package claims are prefilled into the record."""
    if "library" in roles:
        return "library"
    if "unknown" in roles:
        return "unknown"
    return "package"


def template_command(tpl: Node) -> str:
    """The command text of a template string, with ${...} interpolations shown as a wildcard."""
    out = []
    for c in tpl.children:
        if c.type in ("template_substitution", "template_chars"):
            out.append("*" if c.type == "template_substitution" else text(c))
        elif c.type == "string_fragment" or (not c.is_named and c.type not in ("`",)):
            out.append(text(c))
    return "".join(out).strip()


def span(fi: "FileInfo", first: Node, last: Node | None = None) -> dict:
    return span_anchor(fi.rel, fi.src, first, last, fi.derived)


@functools.lru_cache(maxsize=64)
def package_file_names(root: Path) -> frozenset[str]:
    """Base names of every file in the package, so named-path lookups skip strings that cannot match."""
    return frozenset(p.name for p in Path(root).rglob("*") if p.is_file())


FUNC_SCOPES = {"function_declaration", "function_expression", "arrow_function", "method_definition",
               "generator_function_declaration", "generator_function", "function", "function_definition", "lambda",
               "class_definition"}


def scope_chain(node: Node) -> list[int]:
    """Enclosing function (or Python class) scopes of a node, innermost first, by start byte; -1 is the file."""
    keys, n = [], node.parent
    while n is not None:
        if n.type in FUNC_SCOPES:
            keys.append(n.start_byte)
        n = n.parent
    return keys + [-1]


class Bindings:
    """Name -> value per function scope. A lookup by node sees only bindings in scopes that enclose it, so the
    same one-letter name in two functions of a minified bundle never shares a value. A lookup by plain string
    sees only file-level bindings."""

    def __init__(self):
        self.by_name: dict[str, dict[int, object]] = {}

    @staticmethod
    def _chain(key) -> tuple[str, list[int]]:
        return (key, [-1]) if isinstance(key, str) else (text(key), scope_chain(key))

    def bind(self, node: Node, value, first: bool = False) -> None:
        name, chain = self._chain(node)
        scopes = self.by_name.setdefault(name, {})
        if not (first and chain[0] in scopes):
            scopes[chain[0]] = value

    def get(self, key, default=None):
        name, chain = self._chain(key)
        scopes = self.by_name.get(name)
        if scopes:
            for k in chain:
                if k in scopes:
                    return scopes[k]
        return default

    def __contains__(self, key) -> bool:
        return self.get(key, _MISSING) is not _MISSING

    def setdefault(self, key: str, value):
        scopes = self.by_name.setdefault(key, {})
        return scopes.setdefault(-1, value)


_MISSING = object()


def member_name(fi: "FileInfo", node: Node | None) -> str | None:
    """The property a member access names, dot or bracket form (`a.b`, `a['b']`, a string-table key the file
    decodes); None when it is computed or `node` is not a member access."""
    name = static_member_name(node)
    if name is None and node is not None and node.type in ("subscript_expression", "subscript"):
        name = fi.string_value(field(node, "index", "subscript"))
    return name


def dotted(fn: Node) -> str:
    """A callee as `obj.name` whether written `obj.name` or `obj["name"]` (so `process["exit"]` reads as
    process.exit); other callees as written."""
    obj, name = member_object(fn), static_member_name(fn)
    return f"{text(obj)}.{name}" if obj is not None and obj.type == "identifier" and name else text(fn)


LITERALS = {"string", "template_string", "number", "integer", "float", "null", "none", "true", "false", "True",
            "False", "array", "list", "object", "dictionary"}


def without_default(node: Node | None) -> Node | None:
    """`(x || '')`, `x ?? ''`, `x or ''`: the value tested is x, read with a literal default for when it is missing.
    A chain of fallbacks (`a || b || ''`) is left alone: it tests more than one value."""
    while node is not None and node.type == "parenthesized_expression" and node.named_children:
        node = node.named_children[0]
    if node is None or node.type not in ("binary_expression", "boolean_operator"):
        return node
    op = next((text(c) for c in node.children if not c.is_named), "")
    left, right = field(node, "left"), field(node, "right")
    if op in ("||", "??", "or") and left is not None and right is not None and right.type in LITERALS:
        return left
    return node


class FileInfo:
    """One parsed file plus the bindings the walker needs: aliases, local modules, functions, constants."""

    def __init__(self, root: Path, rel: str, lang: str, src: bytes, derived: str | None = None):
        self.root, self.rel, self.lang, self.src = root, rel, lang, src
        self.derived = derived  # derivation id when src is a recovered (deobfuscated) copy of the file
        self.tree = PARSERS[lang].parse(src)
        # Value bindings are per function scope (see Bindings); functions and modules stay per file.
        self.aliases = Bindings()
        self.exprs = Bindings()
        self.consts = Bindings()
        self.assigned = Bindings()
        self.functions: dict[str, Node] = {}
        self.all_funcs: list[Node] = []
        self.modules: dict[str, str] = {}
        self.imported: dict[str, tuple[str, str]] = {}
        self.imports: list[str] = []
        self._launches: bool | None = None
        self.units: dict[str, Node] | None = None  # bundle module factories by module id, computed on demand
        self._bundle: dict | None = None
        self._endpoints: list[tuple[str, int]] | None = None
        self._reexports: dict[str, str] | None = None
        (self._prepass_js if lang == "js" else self._prepass_py)()
        self.error_ratio = self._error_ratio()
        self.signals = self._signals()

    def resolve(self, spec: str) -> str | None:
        if self.lang == "js":
            if not spec.startswith("."):
                return None
            base = (self.root / self.rel).parent / spec
            candidates = [base] + [base.with_name(base.name + e) for e in (".js", ".cjs", ".mjs")] + \
                         [base / "index.js"]
            pkg = base / "package.json"
            if pkg.is_file():
                try:
                    main = json.loads(pkg.read_text(errors="replace")).get("main")
                    if isinstance(main, str):
                        candidates.insert(1, base / main)
                except json.JSONDecodeError:
                    pass
        else:
            level = len(spec) - len(spec.lstrip("."))
            parts = [p for p in spec.lstrip(".").split(".") if p]
            if level:
                base = (self.root / self.rel).parent
                for _ in range(level - 1):
                    base = base.parent
                bases = [base]
            else:
                here = (self.root / self.rel).parent
                bases = [here, self.root, self.root / "src"]
            candidates = []
            for b in bases:
                p = b.joinpath(*parts) if parts else b
                candidates += [p.with_name(p.name + ".py"), p / "__init__.py"] if parts else [p / "__init__.py"]
        root = self.root.resolve()
        for c in candidates:
            try:
                r = c.resolve()
                if r.is_file() and r.is_relative_to(root) and not r.name.endswith(".json"):
                    return r.relative_to(root).as_posix()
            except OSError:
                continue
        return None

    def _add_import(self, rel: str | None):
        if rel and rel != self.rel and rel not in self.imports:
            self.imports.append(rel)

    def _prepass_js(self):
        for n in descendants(self.tree.root_node):
            t = n.type
            if t in ("function_declaration", "generator_function_declaration", "method_definition"):
                name = n.child_by_field_name("name")
                if name is not None:
                    self.functions.setdefault(text(name), n)
                self.all_funcs.append(n)
            elif t in ("arrow_function", "function_expression", "function", "generator_function"):
                self.all_funcs.append(n)
            elif t == "variable_declarator":
                self._bind_js(n.child_by_field_name("name"), n.child_by_field_name("value"))
            elif t == "assignment_expression":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and left.type == "identifier":
                    self._bind_js(left, right)
                elif left is not None and left.type == "member_expression":
                    self._bind_export(text(left), right)
            elif t == "import_statement":
                self._bind_esm(n)
            elif t == "call_expression":
                fn = n.child_by_field_name("function")
                spec = self.first_string(n)
                if fn is not None and spec and (text(fn) in ("require", "import") or fn.type == "import"):
                    self._add_import(self.resolve(spec))
                else:
                    target = self.node_target(n)
                    if target:
                        self._add_import(self.resolve(target if target.startswith(".") else "./" + target))

    def node_target(self, call: Node) -> str | None:
        """Local script a child_process call starts with node: fork(x), spawn('node', [x]), exec('node x')."""
        name = self.canon(call.child_by_field_name("function")) or ""
        m = re.match(r"child_process\.(fork|spawn\w*|exec\w*)$", name)
        args = call.child_by_field_name("arguments")
        argv = [a for a in args.named_children if a.type != "comment"] if args is not None else []
        if not m or not argv:
            return None
        first = self.literal(argv[0])
        if m.group(1) == "fork":
            return first[0] if first and isinstance(first[0], str) else None
        if (first and first[0] == "node") or self.canon(argv[0]) == "process.execPath":
            rest = self.literal(argv[1]) if len(argv) > 1 else None
            return rest[0][0] if rest and isinstance(rest[0], list) and rest[0] and \
                isinstance(rest[0][0], str) else None
        if first and isinstance(first[0], str):
            cmd = re.match(r"^\s*node\s+(?:-\S+\s+)*([^\s;&|]+)", first[0])
            return cmd.group(1) if cmd else None
        return None

    def _bind_js(self, name: Node | None, value: Node | None):
        if name is None or value is None:
            return
        if name.type == "identifier":
            ident = text(name)
            if value.type in ("arrow_function", "function_expression", "function"):
                self.functions.setdefault(ident, value)
                return
            spec = self.require_spec(value)
            if spec is not None:
                local = self.resolve(spec)
                if local:
                    self.modules[ident] = local
                else:
                    self.aliases.bind(name, spec.removeprefix("node:"))
                return
            self.assigned.bind(name, value)
            if value.type in ("binary_expression", "unary_expression", "parenthesized_expression"):
                self.exprs.bind(name, value)
            elif self.literal(value) is not None:
                self.consts.bind(name, value)
            else:
                c = self.canon(value)
                if c is not None:
                    self.aliases.bind(name, c)
        elif name.type == "object_pattern":
            spec = self.require_spec(value)
            local = self.resolve(spec) if spec else None
            base = spec.removeprefix("node:") if spec and not local else (None if spec else self.canon(value))
            for p in name.named_children:
                if p.type == "shorthand_property_identifier_pattern":
                    key, alias_node = text(p), p
                elif p.type == "pair_pattern":
                    k, v = p.child_by_field_name("key"), p.child_by_field_name("value")
                    if k is None or v is None or v.type != "identifier":
                        continue
                    key, alias_node = text(k).strip("'\""), v
                else:
                    continue
                if local:
                    self.imported[text(alias_node)] = (local, key)
                elif base:
                    self.aliases.bind(alias_node, f"{base}.{key}")

    def _bind_export(self, left: str, value: Node | None):
        if value is None:
            return
        m = re.fullmatch(r"(?:module\.)?exports\.(\w+)", left)
        if m:
            self._export(m.group(1), value)
        elif left == "module.exports":
            if value.type == "object":
                for p in value.named_children:
                    if p.type == "shorthand_property_identifier":
                        self._export(text(p), p)
                    elif p.type == "pair" and p.child_by_field_name("key") is not None:
                        self._export(text(p.child_by_field_name("key")).strip("'\""), p.child_by_field_name("value"))
            else:
                self._export("default", value)

    def _export(self, name: str, value: Node):
        if value.type in ("arrow_function", "function_expression", "function"):
            self.functions.setdefault(name, value)
        elif value.type in ("identifier", "shorthand_property_identifier") and text(value) != name:
            self.aliases.setdefault(f"@export:{name}", text(value))

    def _bind_esm(self, n: Node):
        source = n.child_by_field_name("source")
        if source is None:
            return
        spec = self.string_value(source)
        if spec is None:
            return
        local = self.resolve(spec)
        self._add_import(local)
        mod = spec.removeprefix("node:")
        for clause in (c for c in n.named_children if c.type == "import_clause"):
            for c in clause.named_children:
                if c.type == "identifier":
                    self._bind_module(c, local, mod)
                elif c.type == "namespace_import":
                    ident = next((x for x in c.named_children if x.type == "identifier"), None)
                    if ident is not None:
                        self._bind_module(ident, local, mod)
                elif c.type == "named_imports":
                    for s in c.named_children:
                        if s.type != "import_specifier":
                            continue
                        key = text(s.child_by_field_name("name"))
                        alias = s.child_by_field_name("alias") or s.child_by_field_name("name")
                        if local:
                            self.imported[text(alias)] = (local, key)
                        else:
                            self.aliases.bind(alias, f"{mod}.{key}")

    def _bind_module(self, ident: Node, local: str | None, mod: str):
        if local:
            self.modules[text(ident)] = local
        else:
            self.aliases.bind(ident, mod)

    def _prepass_py(self):
        for n in descendants(self.tree.root_node):
            t = n.type
            if t == "function_definition":
                name = text(n.child_by_field_name("name"))
                cls = self._enclosing_class(n)
                if cls:
                    self.functions[f"{cls}.{name}"] = n
                self.functions.setdefault(name, n)
                self.all_funcs.append(n)
            elif t == "import_statement":
                for c in n.named_children:
                    if c.type == "dotted_name":
                        mod = text(c)
                        local = self.resolve(mod)
                        self._add_import(local)
                        head = mod.split(".")[0]
                        if local and "." not in mod:
                            self.modules[head] = local
                        else:
                            self.aliases.bind(c.named_children[0] if c.named_children else c, head)
                    elif c.type == "aliased_import":
                        mod, alias_node = text(c.child_by_field_name("name")), c.child_by_field_name("alias")
                        local = self.resolve(mod)
                        self._add_import(local)
                        if local:
                            self.modules[text(alias_node)] = local
                        else:
                            self.aliases.bind(alias_node, mod)
            elif t == "import_from_statement":
                mod_node = n.child_by_field_name("module_name")
                if mod_node is None:
                    continue
                mod = text(mod_node).replace(" ", "")
                local = self.resolve(mod)
                self._add_import(local)
                for c in n.children_by_field_name("name"):
                    if c.type == "aliased_import":
                        key, alias_node = text(c.child_by_field_name("name")), c.child_by_field_name("alias")
                    else:
                        key, alias_node = text(c), (c.named_children[-1] if c.named_children else c)
                    alias = text(alias_node)
                    sub = self.resolve(mod.rstrip(".") + "." + key if not mod.endswith(".") else mod + key)
                    if sub:
                        self._add_import(sub)
                        self.modules[alias] = sub
                    elif local:
                        self.imported[alias] = (local, key)
                    else:
                        self.aliases.bind(alias_node, f"{mod}.{key}")
            elif t == "assignment":
                left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                if left is not None and right is not None and left.type == "identifier":
                    ident = text(left)
                    self.assigned.bind(left, right)
                    if right.type == "lambda":
                        self.functions.setdefault(ident, right)
                    elif right.type in ("comparison_operator", "boolean_operator", "not_operator"):
                        self.exprs.bind(left, right)
                    elif self.literal(right) is not None:
                        self.consts.bind(left, right)
                    else:
                        c = self.canon(right)
                        if c is not None:
                            self.aliases.bind(left, c)
            elif t == "call":
                target = self.exec_target(n)
                if target:
                    self._add_import(self.resolve_path(target))

    def _enclosing_class(self, n: Node) -> str | None:
        p = n.parent
        while p is not None and p.type in ("decorated_definition", "block"):
            p = p.parent
        if p is not None and p.type == "class_definition":
            return text(p.child_by_field_name("name"))
        return None

    def resolve_path(self, path: str, base: Path | None = None) -> str | None:
        """A literal file path relative to this file's directory (or `base`), kept inside the package root."""
        root = self.root.resolve()
        try:
            r = ((base if base is not None else (self.root / self.rel).parent) / path).resolve()
            if r.is_file() and r.is_relative_to(root):
                return r.relative_to(root).as_posix()
        except OSError:
            pass
        return None

    def exec_target(self, call: Node) -> str | None:
        """Local file a Python call runs: exec(open('x').read()), runpy.run_path('x'), subprocess 'python x'."""
        fn = call.child_by_field_name("function")
        if fn is None:
            return None
        name = self.canon(fn)
        args = call.child_by_field_name("arguments")
        first = args.named_children[0] if args is not None and args.named_children else None
        if first is None:
            return None
        if name == "exec" and first.type == "call":
            inner = first.child_by_field_name("function")
            if inner is not None and inner.type == "attribute" and text(inner).endswith(".read"):
                opener = inner.child_by_field_name("object")
                if opener is not None and opener.type == "call":
                    oa = opener.child_by_field_name("arguments")
                    if oa is not None and oa.named_children:
                        lit = self.literal(oa.named_children[0])
                        return lit[0] if lit and isinstance(lit[0], str) else None
        if name in ("runpy.run_path", "execfile"):
            lit = self.literal(first)
            return lit[0] if lit and isinstance(lit[0], str) else None
        if name and re.match(r"(subprocess\.\w+|os\.system)$", name):
            lit = self.literal(first)
            if lit:
                v = lit[0]
                parts = v if isinstance(v, list) else str(v).split()
                if len(parts) >= 2 and re.match(r"(python[\d.]*|sys\.executable)$", str(parts[0])):
                    return str(parts[1])
        return None

    def first_string(self, call: Node) -> str | None:
        args = call.child_by_field_name("arguments")
        if args is None or not args.named_children:
            return None
        return self.string_value(args.named_children[0])

    def require_spec(self, node: Node | None) -> str | None:
        if node is not None and node.type == "await_expression" and node.named_children:
            node = node.named_children[0]
        if node is None or node.type != "call_expression":
            return None
        fn = node.child_by_field_name("function")
        if fn is not None and (text(fn) == "require" or fn.type == "import"):
            return self.first_string(node)
        args = node.child_by_field_name("arguments")
        argv = [a for a in args.named_children if a.type != "comment"] if args is not None else []
        if len(argv) == 1 and argv[0].type in ("number", "string") and self.reexports():
            return self.reexports().get(text(argv[0]).strip("'\""))  # webpack n(32081) -> "child_process"
        return None

    def bundle(self) -> dict:
        """Bundle units of this file (bundles.analyse), computed once."""
        if self._bundle is None:
            self._bundle = bundles.analyse(self.tree, self.rel, self.derived) if self.lang == "js" else \
                {"units": [], "entries": [], "require_names": []}
        return self._bundle

    def reexports(self) -> dict[str, str]:
        """Bundle units whose whole body re-exports a module (`t.exports = require("child_process")`), by module
        id, so a bundled require of that id reads as a require of the module."""
        if self._reexports is None:
            self._reexports = {}
            if self.lang == "js":
                for u in self.bundle()["units"]:
                    if u["end_byte"] - u["start_byte"] > 300:
                        continue
                    # require("x"), or a bundler's loader for externals such as
                    # __WEBPACK_EXTERNAL_createRequire(import.meta.url)("x")
                    m = re.search(r"exports\s*=\s*[\w$.]+(?:\([^()]*\))?\(\s*[\"']([^\"']+)[\"']\s*\)",
                                  self.src[u["start_byte"]:u["end_byte"]].decode("utf-8", "replace"))
                    if m:
                        self._reexports[u["module_id"]] = m.group(1)
        return self._reexports

    def string_value(self, node: Node) -> str | None:
        lit = self.literal(node)
        return lit[0] if lit and isinstance(lit[0], str) and lit[1] in ("plain", "decoded") else None

    def canon(self, node: Node | None, depth: int = 0) -> str | None:
        """Dotted canonical name of an expression after alias resolution, e.g. `os.platform()`."""
        if node is None or depth > 40:
            return None
        t = node.type
        if t in ("parenthesized_expression", "await_expression", "await", "non_null_expression"):
            inner = node.named_children[0] if node.named_children else None
            return self.canon(inner, depth + 1)
        if t in ("identifier", "shorthand_property_identifier", "this"):
            return self.aliases.get(node, text(node))
        if t in ("member_expression", "attribute"):
            obj = self.canon(node.child_by_field_name("object"), depth + 1)
            prop = node.child_by_field_name("property" if t == "member_expression" else "attribute")
            return f"{obj}.{text(prop)}" if obj is not None and prop is not None else None
        if t in ("subscript_expression", "subscript"):
            obj = self.canon(node.child_by_field_name("object" if t == "subscript_expression" else "value"),
                             depth + 1)
            idx = node.child_by_field_name("index" if t == "subscript_expression" else "subscript")
            if obj is None or idx is None:
                return None
            key = self.string_value(idx)
            if key is not None:
                return f"{obj}.{key}"
            return f"{obj}[{text(idx)}]" if idx.type in ("number", "integer") else f"{obj}[]"
        if t in ("call_expression", "call"):
            fn = node.child_by_field_name("function")
            if fn is None:
                return None
            if self.lang == "js" and text(fn) == "require":
                spec = self.first_string(node)
                return spec.removeprefix("node:") if spec and not spec.startswith(".") else None
            if member_name(self, fn) in STRIP_METHODS:
                return self.canon(member_object(fn), depth + 1)
            c = self.canon(fn, depth + 1)
            return f"{c}()" if c is not None else None
        if t == "new_expression":
            c = self.canon(node.child_by_field_name("constructor"), depth + 1)
            return f"new {c}()" if c is not None else None
        return None

    def literal(self, node: Node | None, depth: int = 0):
        """(value, value_recovered) for a constant expression, or None. Paths keep ~ and %VAR% placeholders."""
        if node is None or depth > 20:
            return None
        t = node.type
        if t == "parenthesized_expression" and node.named_children:
            return self.literal(node.named_children[0], depth + 1)
        if t == "string" and self.lang == "js":
            value, decoded = unescape(text(node)[1:-1])
            return value, "decoded" if decoded else "plain"
        if t == "string":
            return self._py_string(node, depth)
        if t == "concatenated_string":
            parts = [self.literal(c, depth + 1) for c in node.named_children]
            return self._join(parts, "")
        if t == "template_string":
            parts = []
            for c in node.named_children:
                if c.type == "template_substitution":
                    inner = c.named_children[0] if c.named_children else None
                    parts.append(self.path_part(inner, depth + 1))
                else:
                    parts.append((text(c), "plain"))
            return self._join(parts, "")
        if t in ("number", "integer", "float"):
            try:
                return int(text(node), 0), "plain"
            except ValueError:
                try:
                    return float(text(node)), "plain"
                except ValueError:
                    return None
        if t in ("true", "True"):
            return True, "plain"
        if t in ("false", "False"):
            return False, "plain"
        if t in ("null", "undefined", "none", "None"):
            return None, "plain"
        if t == "unary_expression" and text(node).startswith("-") and node.named_children:
            inner = self.literal(node.named_children[-1], depth + 1)
            return (-inner[0], inner[1]) if inner and isinstance(inner[0], (int, float)) else None
        if t in ("array", "list", "tuple", "set"):
            items = [self.literal(c, depth + 1) for c in node.named_children if c.type != "comment"]
            if items and all(i is not None for i in items):
                rec = "plain" if all(i[1] == "plain" for i in items) else "partial"
                return [i[0] for i in items], rec
            return None
        if t in ("binary_expression", "binary_operator"):
            op = node.child_by_field_name("operator")
            if op is not None and text(op) in ("+", "/"):
                left = self.literal(node.child_by_field_name("left"), depth + 1) or \
                       self.path_part(node.child_by_field_name("left"), depth + 1)
                right = self.literal(node.child_by_field_name("right"), depth + 1) or \
                        self.path_part(node.child_by_field_name("right"), depth + 1)
                if text(op) == "+" and all(isinstance(x[0], (int, float)) for x in (left, right)):
                    return None
                return self._join([left, right], "/" if text(op) == "/" else "")
            return None
        if t == "identifier" and node in self.consts:
            return self.literal(self.consts.get(node), depth + 1)
        if t in ("call_expression", "call"):
            fn = self.canon(node.child_by_field_name("function"))
            args = node.child_by_field_name("arguments")
            argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
            if fn in PATH_JOINS:
                return self._join([self.path_part(a, depth + 1) for a in argv], "/")
            if fn in ("os.path.expanduser", "pathlib.Path", "os.path.abspath", "os.path.normpath",
                      "path.normalize") and argv:
                return self.literal(argv[0], depth + 1) or self.path_part(argv[0], depth + 1)
            if fn in ("pathlib.Path.home", "os.homedir"):
                return "~", "plain"
        return None

    def _py_string(self, node: Node, depth: int):
        start = node.child(0)
        prefix = text(start).lower() if start is not None else ""
        parts, partial = [], False
        for c in node.children:
            if c.type in ("string_content", "escape_sequence"):
                parts.append(text(c))
            elif c.type == "interpolation":
                parts.append("<?>")
                partial = True
        raw = "".join(parts)
        if "r" in prefix:
            return raw, "partial" if partial else "plain"
        value, decoded = unescape(raw)
        return value, "partial" if partial else ("decoded" if decoded else "plain")

    def _join(self, parts, sep):
        if not parts or any(p is None for p in parts):
            return None
        values = ["" if v is None else str(v) for v, _ in parts]
        joined = sep.join(v for v in values if v != "" or sep == "")
        if sep == "/":
            joined = re.sub(r"(?<!:)/{2,}", "/", joined)
        recs = {r for _, r in parts}
        return joined, "partial" if "partial" in recs else ("decoded" if "decoded" in recs else "plain")

    def path_part(self, node: Node | None, depth: int = 0):
        if node is None:
            return "<?>", "partial"
        lit = self.literal(node, depth + 1)
        if lit is not None:
            return lit
        c = self.canon(node)
        env = self.env_name(node, c)
        if env:
            return ("~" if env in HOME_VARS else f"%{env}%"), "plain"
        if c in ("os.homedir()", "os.userInfo().homedir", "pathlib.Path.home()", "os.path.expanduser()"):
            return "~", "plain"
        if c in ("__dirname", "process.cwd()", "os.getcwd()", "os.path.dirname()"):
            return ".", "plain"
        if c in ("os.tmpdir()", "tempfile.gettempdir()"):
            return "%TMP%", "plain"
        return "<?>", "partial"

    def env_name(self, node: Node | None, c: str | None) -> str | None:
        if c is None:
            return None
        m = re.match(r"(?:process\.env|os\.environ)\.(\w+)$", c)
        if m:
            return m.group(1)
        if node is not None and node.type == "call" and re.sub(r"\(\)$", "", c) in ENV_GETTERS:
            args = node.child_by_field_name("arguments")
            if args is not None and args.named_children:
                return self.string_value(args.named_children[0])
        return None

    def _error_ratio(self) -> float:
        bad = 0
        stack = [self.tree.root_node]
        while stack:
            n = stack.pop()
            if n.is_error:
                bad += n.end_byte - n.start_byte
                continue
            if n.is_missing:
                bad += 1
            if n.has_error:
                stack.extend(n.children)
        return round(bad / max(len(self.src), 1), 3)

    def _signals(self) -> list[str]:
        s = self.src.decode("utf-8", "replace")
        signals = []
        if len(re.findall(r"\b_0x[0-9a-f]{4,}\b", s)) >= 10:
            signals.append("hex_identifiers")
        if re.search(r"[A-Za-z0-9+/]{200,}={0,2}", s):
            signals.append("long_base64_literal")
        if re.search(r"\b(?:0x)?[0-9a-fA-F]{200,}\b", s):
            signals.append("long_hex_literal")
        if len(re.findall(r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}", s)) >= 50:
            signals.append("escaped_strings")
        if max((len(line) for line in s.splitlines()), default=0) >= 2000:
            signals.append("very_long_lines")
        if self.error_ratio >= 0.02:
            signals.append("parse_errors")
        if "pyarmor" in s.lower():
            signals.append("pyarmor")
        if "marshal.loads" in s:
            signals.append("marshal")
        for n in descendants(self.tree.root_node):
            if n.type in ("array", "list") and sum(c.type == "string" for c in n.named_children) >= 50:
                signals.append("string_array")
                break
        for n in descendants(self.tree.root_node):
            if n.type in ("call_expression", "call", "new_expression"):
                fn = field(n, "function", "constructor")
                if fn is not None and text(fn) in ("eval", "Function", "exec", "compile"):
                    args = n.child_by_field_name("arguments")
                    first = args.named_children[0] if args is not None and args.named_children else None
                    if first is not None and self.literal(first) is None:
                        signals.append("dynamic_eval")
                        break
        return signals

    def unrecovered_reason(self) -> str | None:
        if self.error_ratio >= 0.1:
            return f"{round(self.error_ratio * 100)}% of the file did not parse"
        heavy = {"long_base64_literal", "long_hex_literal", "string_array", "hex_identifiers", "escaped_strings",
                 "marshal", "pyarmor"}
        if "pyarmor" in self.signals:
            return "pyarmor-protected code"
        if "dynamic_eval" in self.signals and heavy & set(self.signals):
            return "code built at runtime and evaluated: " + ", ".join(sorted(heavy & set(self.signals)))
        return None

    def launches_processes(self) -> bool:
        """True when the file contains a call the sink table classes as starting a process."""
        if self._launches is None:
            rxs = [rx for rx, kind in SINKS[self.lang] if kind == "exec"]
            self._launches = False
            for n in descendants(self.tree.root_node):
                if n.type in ("call_expression", "call", "new_expression"):
                    name = self.canon(n)
                    if name and any(rx.match(name) for rx in rxs):
                        self._launches = True
                        break
        return self._launches

    def _feeds_read(self, node: Node) -> bool:
        """The literal's nearest consuming call (past path joins and argument wrappers) only reads a file."""
        p = node.parent
        while p is not None:
            if p.type in ("call_expression", "call"):
                if self.canon(p.child_by_field_name("function")) in PATH_JOINS:
                    p = p.parent
                    continue
                return bool(READ_CALLS.match(self.canon(p) or ""))
            if p.type not in ARG_WRAPPERS:
                return False
            p = p.parent
        return False

    def named_paths(self) -> list[tuple[str, int]]:
        """Path-like constants the file names, with their line: string literals, joined paths, and the words of
        short command strings. Literals whose only use is a plain file read are skipped."""
        out = []
        for n in descendants(self.tree.root_node):
            t = n.type
            if t == "string" or (t == "template_string" and
                                 not any(c.type == "template_substitution" for c in n.named_children)):
                value = self.string_value(n)
            elif t in ("call_expression", "call") and self.canon(n.child_by_field_name("function")) in PATH_JOINS:
                value = self.string_value(n)
            else:
                continue
            if not value or self._feeds_read(n):
                continue
            words = re.split(r"[\s;&|'\"`]+", value) if len(value) <= 300 and re.search(r"\s", value) else [value]
            for w in words:
                if PATH_LIKE.match(w) and ("." in w or "/" in w):
                    out.append((w.replace("\\", "/"), n.start_point[0] + 1))
        return out

    def launch_targets(self) -> list[tuple[str, int]]:
        """Package files named by path in a file that starts processes, with the first naming line: possible
        launch targets the import walk cannot see (a path handed to a runtime held in a variable, a command
        string). Empty when the file starts no process."""
        if not self.launches_processes():
            return []
        names = package_file_names(self.root)
        found: dict[str, int] = {}
        for value, line in self.named_paths():
            if value.rstrip("/").rsplit("/", 1)[-1] not in names:
                continue
            rel = self.resolve_path(value) or self.resolve_path(value, self.root)
            if rel and rel != self.rel:
                found.setdefault(rel, line)
        return list(found.items())

    def endpoints(self) -> list[tuple[str, int]]:
        """Defanged URLs and IPs with their line, computed once (bundles are scanned once, not per test)."""
        if self._endpoints is None:
            s = self.src.decode("utf-8", "replace")
            newlines = [m.start() for m in re.finditer("\n", s)]
            self._endpoints = [(defang(m.group(0)), bisect.bisect_left(newlines, m.start()) + 1)
                               for rx in (URL, IPV4) for m in rx.finditer(s)]
        return self._endpoints


class Extractor:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.files: dict[str, FileInfo | None] = {}
        self.conds: dict[tuple, dict] = {}
        self.gates: dict[tuple, dict] = {}
        self.guards: dict[str, dict] = {}
        self.derivations: list[dict] = []
        self.derived_bytes: dict[str, bytes] = {}
        self.guard_nodes: dict[tuple, tuple] = {}
        self.sinks: dict[tuple, dict] = {}
        self.delays: list[dict] = []
        self.silent: dict[str, list[str]] = {}
        self.unrecovered: dict[str, str] = {}
        self.not_parsed: set[str] = set()
        self.visited: set = set()
        self.walked_funcs: set = set()
        self.walks = 0
        self.contexts: dict[tuple, int] = {}
        self.truncated: set[str] = set()
        self.walk_limit_hit = False
        self.reached = "direct"

    def file(self, rel: str, lang: str | None = None) -> FileInfo | None:
        if rel in self.files:
            return self.files[rel]
        path = self.root / rel
        lang = EXTENSIONS.get(Path(rel).suffix.lower(), lang if not Path(rel).suffix else None)
        fi = None
        if lang and path.is_file():
            raw = path.read_bytes()
            did, src = self.recover(rel, raw) if lang == "js" else (None, raw)
            fi = FileInfo(self.root, rel, lang, src, did)
            if did:
                fi.signals = sorted(set(fi.signals) | {"string_array (recovered)"})
        elif path.is_file():
            self.not_parsed.add(rel)
        self.files[rel] = fi
        return fi

    def recover(self, rel: str, raw: bytes) -> tuple[str | None, bytes]:
        """Deobfuscates an obfuscator.io string array (tools/common/deobf.py) so candidates and anchors point
        into the recovered code; the recipe is recorded as a derivation a verifier can rebuild."""
        if not (b"shift" in raw and b"push" in raw and b"parseInt" in raw):
            return None, raw
        got = deobf.derive(raw)
        if got is None:
            return None, raw
        data, params, stats = got
        did = f"d{len(self.derivations) + 1}"
        self.derivations.append({"id": did, "recipe": "obfuscatorio_strings", "recipe_version": deobf.RECIPE_VERSION,
                                 "input": {"file": rel, "derived_from": None}, "params": params,
                                 "output_sha256": anchors.digest(data), "stats": stats})
        self.derived_bytes[did] = data
        return did, data

    def add_inline(self, name: str, code: str, lang: str) -> None:
        self.files[name] = FileInfo(self.root, name, lang, code.encode())

    def chain(self, entry: str, lang: str) -> list[str]:
        """Entry file plus every local module it reaches through static imports, in discovery order."""
        order, queue = [], [entry]
        while queue:
            rel = queue.pop(0)
            if rel in order:
                continue
            order.append(rel)
            fi = self.file(rel, lang)
            if fi is not None:
                queue += [r for r in fi.imports if r not in order]
        return order

    def cond(self, fi: FileInfo, node: Node, q: dict, op: str, value=None, rec="plain", neg=False) -> tuple:
        if neg:
            op = NEGATE.get(op, "other")
        return ("cond", {"category": q["category"], "api": q["api"], "env": q.get("env"), "operator": op,
                         "value": value, "value_recovered": rec, "probe": q.get("probe"),
                         "anchor": node_anchor(fi.rel, fi.src, node, fi.derived)})

    def register(self, hook: str, c: dict) -> str:
        value = defang(c["value"]) if isinstance(c["value"], str) else c["value"]
        if isinstance(value, list):
            value = [defang(v) if isinstance(v, str) else v for v in value]
        # The reached bucket is part of the key, so an install-reached check and a semantically identical check
        # in code only named (a not_chained payload, an unwalked helper) never merge into one condition: a
        # reached plumbing site and an unreached worm site must stay apart.
        reached = self.reached == "direct"
        # A probe's command is part of what is tested: `id -u` and `sudo -n true` are different conditions even
        # when both are privilege checks compared the same way.
        key = (hook, reached, c["category"], c["env"], c["operator"], json.dumps(value, sort_keys=True, default=str),
               json.dumps(c.get("probe"), sort_keys=True))
        rec = self.conds.get(key)
        if rec is None:
            rec = self.conds[key] = {
                "id": f"c{len(self.conds) + 1}", "category": c["category"], "apis": [], "operator": c["operator"],
                "value": value, "value_recovered": c["value_recovered"], "in_scope": c["category"] in IN_SCOPE,
                "sites": [], "env": c["env"], "hook": hook, "reached": reached}
            if c.get("probe"):
                rec["probe"] = c["probe"]
        if c["api"] not in rec["apis"]:
            rec["apis"].append(c["api"])
        site = {"candidate": candidate_id("k", c["anchor"], c["category"]), "anchor": c["anchor"]}
        if site not in rec["sites"]:
            rec["sites"].append(site)
        return rec["id"]

    def guarded(self, tree, fi: FileInfo, node: Node, kind: str, arm: str):
        """A condition tree tagged with the decision that tests it: the guard node, its kind and which outcome
        of its test leads into the code being walked. Kept as a hashable key so walk memos stay stable."""
        if tree is None:
            return None
        key = (fi.rel, node.start_byte, node.end_byte, node.type, kind, arm)
        self.guard_nodes[key] = (fi, node)
        return ("guard", key, tree)

    def render(self, hook: str, tree: tuple, parent: str | None = None) -> str:
        kind = tree[0]
        if kind == "guard":
            return self.render(hook, tree[2], parent)
        if kind == "cond":
            return self.register(hook, tree[1])
        parts = []
        for child in tree[1]:
            s = self.render(hook, child, kind)
            parts.append(f"({s})" if child[0] not in ("cond", kind) else s)
        joined = (" && " if kind == "and" else " || ").join(dict.fromkeys(parts))
        return joined

    def enter(self, hook: str, stack: tuple, fi: FileInfo, first: Node, last: Node | None = None) -> str:
        levels, guards = [], []
        for tree in stack:
            s = self.render(hook, tree)
            inner = tree[2] if tree[0] == "guard" else tree
            levels.append(f"({s})" if inner[0] == "or" and len(stack) > 1 else s)
            if tree[0] == "guard":
                guards.append(self.guard(tree[1], s))
        expr = " && ".join(dict.fromkeys(levels))
        key = (hook, expr)
        g = self.gates.get(key)
        if g is None:
            g = self.gates[key] = {"gate_id": f"g{len(self.gates) + 1}", "hook": hook, "expression": expr,
                                   "regions": [], "else_regions": [], "guards": [], "reached": False}
        g["reached"] = g["reached"] or self.reached == "direct"
        for q in guards:
            if q not in g["guards"]:
                g["guards"].append(q)
        region = span(fi, first, last)
        if region not in g["regions"]:
            g["regions"].append(region)
        return g["gate_id"]

    def guard(self, key: tuple, rendered: str) -> str:
        """Registers a guard candidate (q_ id) for a decision node and returns its id."""
        fi, node = self.guard_nodes[key]
        kind, arm = key[4], key[5]
        site = node_anchor(fi.rel, fi.src, node, fi.derived)
        qid = candidate_id("q", site, f"{kind}|{arm}")
        entry = self.guards.setdefault(qid, {"candidate": qid, "site": site, "kind": kind, "arm": arm,
                                             "conditions": []})
        for cid in COND_ID.findall(rendered):
            if cid not in entry["conditions"]:
                entry["conditions"].append(cid)
        return qid

    def add_else(self, gate_id: str, region: dict):
        for g in self.gates.values():
            if g["gate_id"] == gate_id and region not in g["else_regions"]:
                g["else_regions"].append(region)

    def query(self, fi: FileInfo, node: Node | None) -> dict | None:
        node = without_default(node)
        if node is None:
            return None
        c = fi.canon(node)
        if c is None:
            return None
        env = fi.env_name(node, c)
        if env:
            api = f"process.env.{env}" if fi.lang == "js" else f"os.environ['{env}']"
            return {"category": env_category(env), "api": api, "env": env}
        for rx, cat in QUERIES[fi.lang]:
            if rx.match(c):
                return {"category": cat, "api": c, "env": None}
        return self.exec_probe(fi, node)

    def exec_call(self, fi: FileInfo, call: Node) -> tuple[str, str] | None:
        """(api, command) for a call that runs a command given as a literal string or argv list."""
        name = fi.canon(call.child_by_field_name("function"))
        if not name or not any(kind == "exec" and rx.match(name + "()") for rx, kind in SINKS[fi.lang]):
            return None
        tpl = next((c for c in call.named_children if c.type in ("template_string", "template_literal")), None)
        if tpl is not None:  # a shell command run as a tagged template, e.g. Bun.$`sudo -n true`
            cmd = template_command(tpl)
            return (name, cmd) if cmd else None
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        lit = fi.literal(argv[0]) if argv else None
        if not lit or lit[0] in (None, "<?>"):
            return None
        cmd = " ".join(map(str, lit[0])) if isinstance(lit[0], list) else str(lit[0])
        if isinstance(lit[0], str) and len(argv) > 1:  # spawn('ps', ['aux'])
            rest = fi.literal(argv[1])
            if rest and isinstance(rest[0], list):
                cmd += " " + " ".join(map(str, rest[0]))
        return name, cmd

    def exec_probe(self, fi: FileInfo, node: Node, depth: int = 0) -> dict | None:
        """A tested command that probes the environment (sudo -n, ps, which, systemd-detect-virt, ...), through
        output accessors such as .toString(), .stdout, .returncode or a variable holding the result; or a
        tested read of a file outside the package (`readFileSync(home + '/.npmrc').includes('_authToken')`).
        The command or path goes into `probe`, so the compared literal stays the condition's value."""
        n, accessor = node, None
        while n is not None and depth < 8:
            depth += 1
            if n.type in ("call_expression", "call"):
                hit = self.exec_call(fi, n)
                if hit:
                    name, cmd = hit
                    cat = next((c for rx, c in EXEC_PROBES if rx.search(cmd)), None)
                    return {"category": cat, "api": name, "env": None,
                            "probe": {"kind": "exec", "callee": name, "target": defang(cmd)[:300],
                                      "accessor": accessor or "stdout"}} if cat else None
                read = self.read_probe(fi, n)
                if read:
                    return read
                fn = n.child_by_field_name("function")
                if member_object(fn) is not None:
                    accessor = accessor or ACCESSORS.get(member_name(fi, fn) or "")
                    n = member_object(fn)
                else:
                    n = None
            elif member_object(n) is not None:
                accessor = accessor or ACCESSORS.get(member_name(fi, n) or "")
                n = member_object(n)
            elif n.type in ("parenthesized_expression", "await_expression", "await") and n.named_children:
                n = n.named_children[0]
            elif n.type == "identifier":
                n = fi.assigned.get(n)
            else:
                return None
        return None

    def read_probe(self, fi: FileInfo, call: Node) -> dict | None:
        """A read of a file outside the package whose content is tested (a credential store, a marker file)."""
        name = fi.canon(call.child_by_field_name("function"))
        if not name or not READ_CALLS.match(name if name.endswith("()") else name + "()"):
            return None
        args = call.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        lit = (fi.literal(argv[0]) or fi.path_part(argv[0])) if argv else None
        path = lit[0] if lit and isinstance(lit[0], str) and lit[0] != "<?>" else None
        if path is None or path.startswith(".") or Path(path).name in package_file_names(self.root):
            return None  # a package file, not the machine
        api = name.removesuffix("()")
        return {"category": path_category(path), "api": api, "env": None,
                "probe": {"kind": "file", "callee": api, "target": defang(path)[:300], "accessor": "content"}}

    def try_probe(self, fi: FileInfo, body: Node | None) -> tuple | None:
        """The condition a try body tests by attempting something first: opening or listing a path, loading a
        module, or running a probe command. None when the body does not start with such a probe."""
        stmts = [c for c in body.named_children if c.type != "comment"] if body is not None else []
        if not stmts:
            return None
        for call in (d for d in descendants(stmts[0]) if d.type in ("call_expression", "call")):
            name = (fi.canon(call.child_by_field_name("function")) or "").removesuffix("()")
            args = call.child_by_field_name("arguments")
            argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
            if name in TRY_PROBES[fi.lang] and argv:
                if name in ("open", "io.open", "fs.openSync") and len(argv) > 1:
                    mode = fi.literal(argv[1])
                    if mode and isinstance(mode[0], str) and re.search(r"[wax+]", mode[0]):
                        continue  # opening to write/append is not a probe of whether the file exists
                lit = fi.literal(argv[0]) or fi.path_part(argv[0])
                value, rec = lit if lit and lit[0] != "<?>" else (None, "not_recovered")
                module = name in ("require", "__import__", "importlib.import_module")
                if module and isinstance(value, str) and value.startswith("."):
                    return None  # a package file, not a probe of the machine
                cat = "dependency_tree" if module else path_category(value or "")
                return self.cond(fi, call, {"category": cat, "api": name, "env": None}, "exists", value, rec)
            hit = self.exec_call(fi, call)
            if hit:
                cat = next((c for rx, c in EXEC_PROBES if rx.search(hit[1])), None)
                if cat:
                    probe = {"kind": "exec", "callee": hit[0], "target": defang(hit[1])[:300], "accessor": "throws"}
                    return self.cond(fi, call, {"category": cat, "api": hit[0], "env": None, "probe": probe},
                                     "exists", None, "plain")
        return None

    def test(self, fi: FileInfo, node: Node | None, neg: bool = False, depth: int = 0):
        """A conditional's test as a tree of ("cond", c) / ("and"|"or", [...]) in positive form, or None when it
        checks nothing environmental. `neg` asks for the test's negation."""
        if node is None or depth > 8:
            return None
        t = node.type
        kids = [c for c in node.named_children if c.type != "comment"]
        if t == "parenthesized_expression" and kids:
            return self.test(fi, kids[0], neg, depth + 1)
        if t == "unary_expression" and text(node).lstrip().startswith("!") and kids:
            return self.test(fi, kids[-1], not neg, depth + 1)
        if t == "not_operator":
            return self.test(fi, node.child_by_field_name("argument"), not neg, depth + 1)
        if t in ("binary_expression", "boolean_operator"):
            op = text(node.child_by_field_name("operator"))
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if op in ("&&", "||", "and", "or"):
                kind = "and" if op in ("&&", "and") else "or"
                if neg:
                    kind = "or" if kind == "and" else "and"
                return self.combine(kind, self.test(fi, left, neg, depth + 1), self.test(fi, right, neg, depth + 1))
            if op in JS_CMP:
                return self.compare(fi, node, left, JS_CMP[op], right, neg)
            if op == "in":
                return self.membership(fi, node, left, right, False, neg)
            return None
        if t == "comparison_operator":
            operands = [c for c in node.children if c.type not in PY_CMP and c.is_named]
            ops = [c.type for c in node.children if c.type in PY_CMP]
            if len(operands) < 2 or not ops:
                return None
            if ops[0] in ("in", "not in"):
                return self.membership(fi, node, operands[0], operands[1], ops[0] == "not in", neg)
            return self.compare(fi, node, operands[0], PY_CMP[ops[0]], operands[1], neg)
        if t in ("call_expression", "call"):
            return self.call_test(fi, node, neg)
        if t == "identifier" and node in fi.exprs:
            return self.test(fi, fi.exprs.get(node), neg, depth + 1)
        q = self.query(fi, node)
        if q is not None:
            return self.cond(fi, node, q, "truthy", None, "plain", neg)
        return None

    @staticmethod
    def combine(kind: str, *parts):
        parts = [p for p in parts if p is not None]
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        flat = []
        for p in parts:
            flat += p[1] if p[0] == kind else [p]
        return (kind, flat)

    def compare(self, fi, node, left, op, right, neg):
        if fi.lang == "js" and left.type == "unary_expression" and text(left).startswith("typeof"):
            q = self.query(fi, left.named_children[-1]) if left.named_children else None
            lit = fi.literal(right)
            if q and lit and lit[0] == "undefined":
                return self.cond(fi, node, q, "falsy" if op == "==" else "truthy", None, "plain", neg)
            return None
        index = self.index_of(fi, node, left, op, right, neg)
        if index is not None:
            return index
        q = self.query(fi, left)
        other = right
        if q is None:
            q, other, op = self.query(fi, right), left, MIRROR.get(op, op)
        if q is None:
            return None
        lit = fi.literal(other)
        # A probe compared to a sentinel asks whether it produced anything: output unequal to '' (or null), an
        # exit status equal to 0. Compared to anything else (`id -u` output === '0'), it is an ordinary test.
        if q.get("probe") and lit is not None and op in ("==", "!=") and lit[0] in ("", None, 0, False):
            success_on_equal = lit[0] == 0 and q["probe"]["accessor"] == "returncode"
            return self.cond(fi, node, q, "exists" if (op == "==") == success_on_equal else "not_exists", None,
                             "plain", neg)
        if lit is not None and lit[0] is None and op in ("==", "!="):
            return self.cond(fi, node, q, "falsy" if op == "==" else "truthy", None, "plain", neg)
        if lit is None:
            return self.cond(fi, node, q, op, None, "not_recovered", neg)
        return self.cond(fi, node, q, op, lit[0], lit[1], neg)

    def index_of(self, fi, node, left, op, right, neg):
        """`[..].indexOf(q) !== -1` means q in [..]; `q.indexOf('x') !== -1` means q includes 'x'."""
        if fi.lang != "js" or left.type != "call_expression":
            return None
        fn = left.child_by_field_name("function")
        if fn is None or member_name(fi, fn) != "indexOf":
            return None
        bound = fi.literal(right)
        if bound is None or not isinstance(bound[0], (int, float)):
            return None
        found = (op in ("!=", ">") and bound[0] == -1) or (op == ">=" and bound[0] == 0)
        missing = (op == "==" and bound[0] == -1) or (op == "<" and bound[0] == 0)
        if not (found or missing):
            return None
        args = left.child_by_field_name("arguments")
        arg = args.named_children[0] if args is not None and args.named_children else None
        obj = member_object(fn)
        q, lit = self.query(fi, arg), fi.literal(obj)
        if q is not None and lit is not None and isinstance(lit[0], list):
            return self.cond(fi, node, q, "in" if found else "not_in", lit[0], lit[1], neg)
        q, lit = self.query(fi, obj), fi.literal(arg) if arg is not None else None
        if q is not None and lit is not None:
            return self.cond(fi, node, q, "includes" if found else "not_includes", lit[0], lit[1], neg)
        return None

    def membership(self, fi, node, item, container, negated, neg):
        neg = neg ^ negated
        c = fi.canon(container)
        lit = fi.literal(item)
        if c in ("process.env", "os.environ") and lit is not None and isinstance(lit[0], str):
            name = lit[0]
            q = {"category": env_category(name), "env": name,
                 "api": f"process.env.{name}" if fi.lang == "js" else f"os.environ['{name}']"}
            return self.cond(fi, node, q, "truthy", None, "plain", neg)
        q = self.query(fi, container)
        if q is not None and lit is not None:
            return self.cond(fi, node, q, "includes", lit[0], lit[1], neg)
        q, lit = self.query(fi, item), fi.literal(container)
        if q is not None:
            if lit is None:
                return self.cond(fi, node, q, "in", None, "not_recovered", neg)
            return self.cond(fi, node, q, "in", lit[0] if isinstance(lit[0], list) else [lit[0]], lit[1], neg)
        return None

    def call_test(self, fi, node, neg):
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type not in ("comment",)]
        name = fi.canon(fn) if fn is not None else None
        if name in FILE_TESTS[fi.lang] and argv:
            lit = fi.literal(argv[0]) or fi.path_part(argv[0])
            value, rec = lit if lit else (None, "not_recovered")
            if value == "<?>":
                value, rec = None, "not_recovered"
            q = {"category": path_category(value or ""), "api": name, "env": None}
            return self.cond(fi, node, q, "exists", value, rec, neg)
        if name in TOOL_TESTS[fi.lang] and argv:
            lit = fi.literal(argv[0])
            q = {"category": "installed_tool", "api": name, "env": None}
            return self.cond(fi, node, q, "exists", lit[0] if lit else None, lit[1] if lit else "not_recovered", neg)
        if member_object(fn) is not None and member_name(fi, fn) is not None:
            method = member_name(fi, fn)
            obj = member_object(fn)
            if method in ("exists", "is_file", "is_dir") and obj is not None and fi.canon(obj) == "pathlib.Path()":
                oargs = obj.child_by_field_name("arguments")
                inner = oargs.named_children[0] if oargs is not None and oargs.named_children else None
                lit = fi.literal(inner) or fi.path_part(inner)
                q = {"category": path_category(lit[0]), "api": f"pathlib.Path().{method}()", "env": None}
                return self.cond(fi, node, q, "exists", lit[0], lit[1], neg)
            if method in ("includes", "startsWith", "startswith", "endsWith", "endswith", "match", "test",
                          "hasOwnProperty") and argv:
                q, lit = self.query(fi, obj), fi.literal(argv[0])
                if method == "hasOwnProperty" and fi.canon(obj) == "process.env" and lit:
                    q = {"category": env_category(lit[0]), "api": f"process.env.{lit[0]}", "env": lit[0]}
                    return self.cond(fi, node, q, "truthy", None, "plain", neg)
                if method == "test":
                    q, lit = self.query(fi, argv[0]), (text(obj), "plain")
                if method == "includes" and q is None and lit is None:
                    q, lit = self.query(fi, argv[0]), fi.literal(obj)
                    if q is not None and lit is not None and isinstance(lit[0], list):
                        return self.cond(fi, node, q, "in", lit[0], lit[1], neg)
                    return None
                if q is None:
                    return None
                op = {"includes": "includes", "startsWith": "startswith", "startswith": "startswith",
                      "match": "regex", "test": "regex"}.get(method, "other")
                return self.cond(fi, node, q, op, lit[0] if lit else None,
                                 lit[1] if lit else "not_recovered", neg)
        if name in ("re.match", "re.search", "re.fullmatch") and len(argv) >= 2:
            q, lit = self.query(fi, argv[1]), fi.literal(argv[0])
            if q is not None:
                return self.cond(fi, node, q, "regex", lit[0] if lit else None,
                                 lit[1] if lit else "not_recovered", neg)
            return None
        q = self.query(fi, node)
        if q is not None:
            return self.cond(fi, node, q, "truthy", None, "plain", neg)
        return self.predicate_call(fi, node, neg)

    def predicate_call(self, fi, node, neg, depth: int = 0):
        """A call of a helper whose body only returns a test (`const isLinux = () => os.platform() === 'linux'`):
        the test inside the helper is the condition, anchored where the helper tests it."""
        if depth > 3:
            return None
        for target_fi, fnode in self.callees(fi, node.child_by_field_name("function")):
            if target_fi is None or fnode is None:
                continue
            body = fnode.child_by_field_name("body")
            if body is None:
                continue
            if body.type in ("statement_block", "block"):
                stmts = [c for c in body.named_children if c.type != "comment" and not pure_alias(c)]
                if len(stmts) != 1 or stmts[0].type != "return_statement" or not stmts[0].named_children:
                    continue
                body = stmts[0].named_children[0]
            tree = self.test(target_fi, body, neg, depth + 1)
            if tree is not None:
                return tree
        return None

    def walk_file(self, rel: str, hook: str, stack: tuple, gate) -> None:
        fi = self.file(rel)
        if fi is None:
            return
        sig = ("file", rel, hook, repr(stack), gate)
        if sig in self.visited:
            return
        self.visited.add(sig)
        reason = fi.unrecovered_reason()
        if reason:
            self.unrecovered.setdefault(rel, reason)
        try:
            self.walk(fi.tree.root_node, fi, hook, stack, gate)
        except RecursionError:
            self.unrecovered.setdefault(rel, "nesting too deep for the extractor")

    def walk_function(self, fnode: Node, fi: FileInfo, hook: str, stack: tuple, gate) -> None:
        sig = ("func", fi.rel, fnode.start_byte, hook, repr(stack), gate)
        if sig in self.visited:
            return
        if self.walks >= MAX_WALKS:
            self.walk_limit_hit = True
            return
        seen = self.contexts.get((fi.rel, fnode.start_byte, hook), 0)
        if seen >= MAX_CONTEXTS:
            self.truncated.add(fi.rel)
            return
        self.contexts[(fi.rel, fnode.start_byte, hook)] = seen + 1
        self.visited.add(sig)
        self.walked_funcs.add((fi.rel, fnode.start_byte))
        self.walks += 1
        body = field(fnode, "body")
        if body is None:
            body = fnode
        try:
            self.walk(body, fi, hook, stack, gate)
        except RecursionError:
            self.unrecovered.setdefault(fi.rel, "nesting too deep for the extractor")

    def walk(self, node: Node, fi: FileInfo, hook: str, stack: tuple, gate) -> None:
        """Conditionals push their test onto `stack`; regions and sinks belong to the gate the whole stack forms.
        `gate` is (gate id, "then" or "else") for the innermost region, or None outside every gate."""
        t = node.type
        if t in ("program", "statement_block", "module", "block", "class_body"):
            return self.walk_block([c for c in node.named_children if c.type != "comment"], fi, hook, stack, gate)
        if t in ("function_declaration", "generator_function_declaration", "method_definition",
                 "function_definition"):
            return
        if t in ("arrow_function", "function_expression", "function", "generator_function", "lambda") \
                and not self.runs_inline(node):
            return
        if t == "if_statement":
            return self.walk_if(node, fi, hook, stack, gate)
        if t in ("ternary_expression", "conditional_expression"):
            return self.walk_ternary(node, fi, hook, stack, gate)
        if t == "switch_statement":
            return self.walk_switch(node, fi, hook, stack, gate)
        if t == "expression_statement" and node.named_children and \
                node.named_children[0].type in ("binary_expression", "boolean_operator"):
            if self.walk_short_circuit(node.named_children[0], fi, hook, stack, gate):
                return
        if t in ("call_expression", "call", "new_expression"):
            self.on_call(node, fi, hook, stack, gate)
        elif t in ("import_statement", "import_from_statement"):
            self.on_import(node, fi, hook, stack, gate)
        elif t == "try_statement":
            return self.walk_try(node, fi, hook, stack, gate)
        for c in node.children:
            self.walk(c, fi, hook, stack, gate)

    @staticmethod
    def runs_inline(fn: Node) -> bool:
        """Anonymous functions passed as arguments or invoked on the spot run where they appear."""
        p = fn.parent
        while p is not None and p.type == "parenthesized_expression":
            fn, p = p, p.parent
        if p is None:
            return False
        if p.type in ("arguments", "argument_list"):
            return True
        return p.type == "call_expression" and p.child_by_field_name("function") == fn

    def walk_block(self, stmts: list[Node], fi, hook, stack, gate) -> None:
        for i, st in enumerate(stmts):
            exit_test = self.early_exit_test(st)
            if exit_test is not None:
                neg = self.test(fi, exit_test, True)
                rest = stmts[i + 1:]
                if neg is not None and rest:
                    self.walk(exit_test, fi, hook, stack, gate)
                    new_stack = stack + (self.guarded(neg, fi, st, "early_exit", "else"),)
                    g = self.enter(hook, new_stack, fi, rest[0], rest[-1])
                    cons = st.child_by_field_name("consequence")
                    self.add_else(g, span(fi, cons))
                    self.walk(cons, fi, hook, stack + (self.guarded(self.test(fi, exit_test), fi, st, "if", "then"),),
                              (g, "else"))
                    return self.walk_block(rest, fi, hook, new_stack, (g, "then"))
            self.walk(st, fi, hook, stack, gate)

    def early_exit_test(self, st: Node) -> Node | None:
        if st.type != "if_statement" or st.child_by_field_name("alternative") is not None:
            return None
        cons = st.child_by_field_name("consequence")
        if cons is None:
            return None
        body = [c for c in cons.named_children if c.type != "comment"] if cons.type in ("statement_block", "block") \
            else [cons]
        if not body:
            return None
        last = body[-1]
        if last.type in ("return_statement", "throw_statement", "raise_statement"):
            return st.child_by_field_name("condition")
        if last.type == "expression_statement" and last.named_children:
            call = last.named_children[0]
            if call.type in ("call_expression", "call"):
                fn = call.child_by_field_name("function")
                if fn is not None and dotted(fn) in ("process.exit", "process.abort", "sys.exit", "exit", "quit",
                                                     "os._exit", "os.abort"):
                    return st.child_by_field_name("condition")
        return None

    def walk_if(self, node, fi, hook, stack, gate) -> None:
        branches, else_body = [], None
        if fi.lang == "js":
            cur = node
            while cur is not None:
                branches.append((cur.child_by_field_name("condition"), cur.child_by_field_name("consequence"),
                                 cur, "if"))
                alt = cur.child_by_field_name("alternative")
                body = next((c for c in alt.named_children if c.type != "comment"), None) if alt is not None else None
                if body is not None and body.type == "if_statement":
                    cur = body
                else:
                    cur, else_body = None, body
        else:
            branches.append((node.child_by_field_name("condition"), node.child_by_field_name("consequence"), node, "if"))
            for alt in node.children_by_field_name("alternative"):
                if alt.type == "elif_clause":
                    branches.append((alt.child_by_field_name("condition"), alt.child_by_field_name("consequence"),
                                     alt, "elif"))
                elif alt.type == "else_clause":
                    else_body = alt.child_by_field_name("body")
        negs, last_gate = [], None
        for cond, body, gnode, gkind in branches:
            if cond is not None:
                self.walk(cond, fi, hook, stack, gate)
            tree = self.guarded(self.test(fi, cond), fi, gnode, gkind, "then")
            if tree is None or body is None:
                if body is not None:
                    self.walk(body, fi, hook, stack, gate)
                continue
            # elif branches use their own test only: the earlier tests are usually mutually exclusive values.
            g = self.enter(hook, stack + (tree,), fi, body)
            self.walk(body, fi, hook, stack + (tree,), (g, "then"))
            negs.append(self.test(fi, cond, True))
            last_gate = g
        if else_body is None:
            return
        if last_gate is None:
            return self.walk(else_body, fi, hook, stack, gate)
        self.add_else(last_gate, span(fi, else_body))
        neg = self.guarded(self.combine("and", *negs), fi, node, "if", "else")
        self.walk(else_body, fi, hook, stack + ((neg,) if neg else ()), (last_gate, "else"))

    def walk_ternary(self, node, fi, hook, stack, gate) -> None:
        if fi.lang == "js":
            cond, cons, alt = (node.child_by_field_name(f) for f in ("condition", "consequence", "alternative"))
        else:
            kids = [c for c in node.named_children if c.type != "comment"]
            if len(kids) != 3:
                return
            cons, cond, alt = kids
        self.walk(cond, fi, hook, stack, gate)
        tree = self.test(fi, cond)
        if tree is None:
            for part in (cons, alt):
                if part is not None:
                    self.walk(part, fi, hook, stack, gate)
            return
        tree = self.guarded(tree, fi, node, "ternary", "then")
        g = self.enter(hook, stack + (tree,), fi, cons)
        self.walk(cons, fi, hook, stack + (tree,), (g, "then"))
        if alt is not None:
            self.add_else(g, span(fi, alt))
            self.walk(alt, fi, hook, stack + (self.guarded(self.test(fi, cond, True), fi, node, "ternary", "else"),),
                      (g, "else"))

    def walk_switch(self, node, fi, hook, stack, gate) -> None:
        value = node.child_by_field_name("value")
        q = self.query(fi, value.named_children[0] if value is not None and value.named_children else value)
        body = node.child_by_field_name("body")
        if q is None or body is None:
            for c in node.children:
                self.walk(c, fi, hook, stack, gate)
            return
        seen, pending = [], []
        for case in body.named_children:
            stmts = [c for c in case.children_by_field_name("body") if c.type != "comment"]
            if case.type == "switch_case":
                lit = fi.literal(case.child_by_field_name("value"))
                pending.append(self.cond(fi, case, q, "==", lit[0] if lit else None, lit[1] if lit else
                                         "not_recovered"))
                seen.append(lit[0] if lit else None)
                if not stmts:
                    continue
                tree = self.combine("or", *pending)
                pending = []
            elif case.type == "switch_default":
                if not stmts:
                    continue
                tree = self.cond(fi, case, q, "not_in", [v for v in seen if v is not None])
            else:
                continue
            tree = self.guarded(tree, fi, case, "switch_case" if case.type == "switch_case" else "switch_default",
                                "then")
            g = self.enter(hook, stack + (tree,), fi, stmts[0], stmts[-1])
            for st in stmts:
                self.walk(st, fi, hook, stack + (tree,), (g, "then"))

    @staticmethod
    def changes_course(handler: Node) -> bool:
        """True when an except/catch handler alters control flow (exits, re-raises, breaks) rather than just
        swallowing the error or collecting data, so the try is a real decision."""
        for n in descendants(handler):
            if n.type in ("return_statement", "raise_statement", "throw_statement", "break_statement",
                          "continue_statement"):
                return True
            if n.type in ("call_expression", "call"):
                name = dotted(n.child_by_field_name("function")) if n.child_by_field_name("function") else ""
                if re.search(r"(process\.exit|sys\.exit|os\._exit|\bexit|\bquit)\b", name):
                    return True
        return False

    def walk_try(self, node, fi, hook, stack, gate) -> None:
        """A try whose body starts with a probe is a decision: the body runs when the probe succeeds, the
        handlers when it fails."""
        self.on_try(node, fi, hook)
        body = node.child_by_field_name("body")
        handlers = [c for c in node.named_children if c.type in ("catch_clause", "except_clause")]
        tree = self.try_probe(fi, body) if handlers else None
        if tree is not None and tree[1]["category"] == "file_or_dir_exists" \
                and not any(self.changes_course(h) for h in handlers):
            tree = None  # a generic file probe whose handler only collects data is not a gate, just a read
        if tree is None:
            for c in node.children:
                self.walk(c, fi, hook, stack, gate)
            return
        call_q = tree[1]
        then = self.guarded(tree, fi, node, "try_except", "then")
        g = self.enter(hook, stack + (then,), fi, body)
        self.walk(body, fi, hook, stack + (then,), (g, "then"))
        failed = ("cond", {**call_q, "operator": NEGATE.get(call_q["operator"], "other")})
        otherwise = self.guarded(failed, fi, node, "try_except", "else")
        for h in handlers:
            self.add_else(g, span(fi, h))
            self.walk(h, fi, hook, stack + (otherwise,), (g, "else"))
        for c in node.named_children:
            if c.type not in ("catch_clause", "except_clause") and not (body is not None and
                                                                         c.start_byte == body.start_byte):
                self.walk(c, fi, hook, stack, gate)

    def walk_short_circuit(self, expr, fi, hook, stack, gate) -> bool:
        op = text(expr.child_by_field_name("operator"))
        if op not in ("&&", "||", "and", "or"):
            return False
        left, right = expr.child_by_field_name("left"), expr.child_by_field_name("right")
        tree = self.guarded(self.test(fi, left, op in ("||", "or")), fi, expr, "short_circuit",
                            "else" if op in ("||", "or") else "then")
        if tree is None or right is None:
            return False
        self.walk(left, fi, hook, stack, gate)
        g = self.enter(hook, stack + (tree,), fi, right)
        self.walk(right, fi, hook, stack + (tree,), (g, "then"))
        return True

    def on_call(self, node, fi, hook, stack, gate) -> None:
        fn = field(node, "function", "constructor")
        if fn is None:
            return
        name = fi.canon(node)
        args = node.child_by_field_name("arguments")
        argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
        site = f"{fi.rel}:{node.start_point[0] + 1}"
        gid, branch = gate if gate else (None, None)

        if fi.lang == "js" and (text(fn) == "require" or fn.type == "import"):
            spec = fi.first_string(node)
            target = fi.resolve(spec) if spec else None
            if target:
                self.walk_file(target, hook, stack, gate)
        target = fi.exec_target(node) if fi.lang == "py" else None
        if target:
            local = fi.resolve_path(target)
            if local:
                self.walk_file(local, hook, stack, gate)

        if name:
            for rx, kind in SINKS[fi.lang]:
                if rx.match(name):
                    detail = None
                    if kind in ("fs_read", "fs_write", "fs_delete") and argv:
                        lit = fi.literal(argv[0]) or fi.path_part(argv[0])
                        detail = defang(str(lit[0])) if lit and lit[0] not in (None, "<?>") else None
                    self.sinks.setdefault((site, kind, gid, branch), {
                        "site": site, "kind": kind, "api": name, "path": detail, "gate": gid, "branch": branch,
                        "reached": self.reached, "anchor": node_anchor(fi.rel, fi.src, node, fi.derived)})
                    break
            if fi.lang == "py" and name == "open()" and len(argv) >= 2:
                mode = fi.literal(argv[1])
                if mode and isinstance(mode[0], str) and re.search(r"[wax]", mode[0]):
                    lit = fi.literal(argv[0]) or fi.path_part(argv[0])
                    self.sinks.setdefault((site, "fs_write", gid, branch), {
                        "site": site, "kind": "fs_write", "api": "open()", "gate": gid, "branch": branch,
                        "path": defang(str(lit[0])) if lit else None, "reached": self.reached,
                        "anchor": node_anchor(fi.rel, fi.src, node, fi.derived)})
            if name in ("setTimeout()", "time.sleep()", "asyncio.sleep()") and argv:
                lit = fi.literal(argv[-1] if name == "setTimeout()" else argv[0])
                if lit and isinstance(lit[0], (int, float)):
                    self.delays.append({"site": site, "seconds": lit[0] / 1000 if name == "setTimeout()" else lit[0]})

        unit = self.unit_target(fi, node, argv)
        if unit is not None:
            self.walk_function(unit, fi, hook, stack, gate)
        for callee in self.callees(fi, fn) + [(fi, fi.functions.get(text(a))) for a in argv if a.type == "identifier"]:
            target_fi, fnode = callee
            if fnode is not None:
                self.walk_function(fnode, target_fi, hook, stack, gate)

    def unit_target(self, fi: FileInfo, call: Node, argv: list[Node]) -> Node | None:
        """The bundle module factory a call loads: a call of the bundle's require binding with a literal id
        (inside a unit, the factory's require parameter; outside, the bootstrap's require), including webpack's
        `n(n.s = 12)`, or esbuild's require_x() bound to a __commonJS wrapper. Any other one-argument call with
        a literal (parseInt("2")) is not a module load."""
        if fi.lang != "js":
            return None
        if fi.units is None:
            fi.units = {}
            for u in fi.bundle()["units"]:
                node = fi.tree.root_node.descendant_for_byte_range(u["start_byte"], u["end_byte"])
                while node is not None and (node.start_byte, node.end_byte) != (u["start_byte"], u["end_byte"]):
                    node = node.parent
                if node is not None:
                    fi.units[u["module_id"]] = node
        if not fi.units:
            return None
        fn = call.child_by_field_name("function")
        if len(argv) == 1 and fn is not None and fn.type == "identifier":
            mid = bundles.literal_id(argv[0])
            if mid is None:
                lit = fi.literal(argv[0])
                mid = str(lit[0]) if lit and isinstance(lit[0], (str, int, float)) else None
            if mid in fi.units and text(fn) in self.require_names(fi, call):
                return fi.units[mid]
        if fn is not None and fn.type == "identifier" and not argv:
            bound = fi.assigned.get(fn)
            if bound is not None and bound.type == "call_expression":
                for mid, node in fi.units.items():
                    if bound.start_byte <= node.start_byte and node.end_byte <= bound.end_byte:
                        return node
        return None

    @staticmethod
    def require_names(fi: FileInfo, call: Node) -> set[str]:
        """Names a call may load a bundle module through at this point: the enclosing factory's require
        parameter, else the bootstrap's require (and the conventional names)."""
        for u in fi.bundle()["units"]:
            if u["start_byte"] <= call.start_byte < u["end_byte"] and u["kind"] in ("webpack", "browserify"):
                node = fi.units.get(u["module_id"]) if fi.units else None
                name = bundles.require_param(node, u["kind"]) if node is not None else None
                return {name} if name else set()
        return set(fi.bundle()["require_names"]) | {"__webpack_require__", "__nccwpck_require__", "require"}

    def callees(self, fi: FileInfo, fn: Node) -> list[tuple[FileInfo, Node | None]]:
        """Functions a call can reach: same-file names, `self.x`, and exports of local modules."""
        if fn.type == "identifier":
            name = text(fn)
            if name in fi.imported:
                rel, key = fi.imported[name]
                other = self.file(rel)
                return [(other, self.export(other, key))] if other else []
            if name in fi.modules:
                other = self.file(fi.modules[name])
                return [(other, self.export(other, "default"))] if other else []
            return [(fi, fi.functions.get(name))]
        obj, prop = member_object(fn), member_name(fi, fn)
        if obj is None or prop is None:
            return []
        if text(obj) in ("self", "this", "cls"):
            return [(fi, fi.functions.get(prop))]
        if text(obj) in fi.modules:
            other = self.file(fi.modules[text(obj)])
            return [(other, self.export(other, prop))] if other else []
        return []

    @staticmethod
    def export(fi: FileInfo, name: str) -> Node | None:
        target = fi.aliases.get(f"@export:{name}", name)
        return fi.functions.get(target)

    def on_import(self, node, fi, hook, stack, gate) -> None:
        if fi.lang != "py":
            source = node.child_by_field_name("source")
            spec = fi.string_value(source) if source is not None else None
            target = fi.resolve(spec) if spec else None
            if target:
                self.walk_file(target, hook, stack, gate)
            return
        targets = []
        if node.type == "import_statement":
            for c in node.named_children:
                name = c.child_by_field_name("name") if c.type == "aliased_import" else c
                targets.append(fi.resolve(text(name)))
        else:
            mod_node = node.child_by_field_name("module_name")
            mod = text(mod_node).replace(" ", "") if mod_node is not None else ""
            targets.append(fi.resolve(mod))
            for c in node.children_by_field_name("name"):
                key = text(c.child_by_field_name("name")) if c.type == "aliased_import" else text(c)
                targets.append(fi.resolve(mod + key if mod.endswith(".") else f"{mod}.{key}"))
        for target in targets:
            if target:
                self.walk_file(target, hook, stack, gate)

    def on_try(self, node, fi, hook) -> None:
        for h in node.named_children:
            if h.type not in ("catch_clause", "except_clause"):
                continue
            body = field(h, "body")
            if body is None:
                body = next((c for c in h.named_children if c.type == "block"), None)
            stmts = [c for c in body.named_children if c.type != "comment"] if body is not None else []
            if all(s.type in ("pass_statement", "continue_statement") or
                   re.match(r"(console\.\w+|print|logging\.\w+|logger\.\w+)\(", text(s)) or text(s) in ("...",)
                   for s in stmts):
                sites = self.silent.setdefault(hook, [])
                site = f"{fi.rel}:{h.start_point[0] + 1}"
                if site not in sites:
                    sites.append(site)

    def run(self, entries: list[dict]) -> dict:
        """entries: [{"hook", "lang", "entry_files": [...], "chain": [...], "entry_functions": [(rel, qualname)],
        "launched": [...]}]"""
        for e in entries:
            hook = e["hook"]
            for rel in e.get("entry_files", []):
                if self.file(rel, e["lang"]) is not None:
                    self.walk_file(rel, hook, (), None)
            for rel, qual in e.get("entry_functions", []):
                fi = self.file(rel, e["lang"])
                fnode = fi.functions.get(qual) if fi else None
                if fnode is not None:
                    self.walk_function(fnode, fi, hook, (), None)
            for rel in e.get("chain", []):
                if self.file(rel, e["lang"]) is not None:
                    self.walk_file(rel, hook, (), None)
            # Files the install names while starting a process but never imports (a runtime held in a variable,
            # `bun x.js`): loaded so obfuscation is recovered and walked so their checks are candidates, but
            # marked unreached, since only the analyst can confirm the install runs them.
            self.reached = "not_chained"
            for rel in e.get("launched", []):
                if self.file(rel, e["lang"]) is not None:
                    self.walk_file(rel, hook, (), None)
            self.reached = "unresolved_function"
            for rel in list(e.get("chain", [])) + list(e.get("entry_files", [])):
                fi = self.files.get(rel)
                for fnode in fi.all_funcs if fi else []:
                    if (rel, fnode.start_byte) not in self.walked_funcs:
                        self.walk_function(fnode, fi, hook, (), None)
            self.reached = "direct"
        return self.result()

    def units(self) -> tuple[list[dict], dict]:
        """Every bundle unit of the parsed files, and each bundled file's entry module id."""
        out, entries = [], {}
        for rel, fi in self.files.items():
            if fi is not None and fi.lang == "js" and not rel.startswith("<"):
                b = fi.bundle()
                out += b["units"]
                if b["units"]:
                    entries[(rel, fi.derived)] = b["entries"][0] if b["entries"] else None
        return out, entries

    def result(self) -> dict:
        units, entries = self.units()

        def unit(anchor: dict) -> dict | None:
            return bundles.unit_at(units, anchor["file"], anchor["start_byte"], anchor.get("derived_from"))

        def role(anchor: dict) -> str:
            u = unit(anchor)
            return u["role"] if u else "package"

        def depth(anchor: dict) -> int | None:
            u = unit(anchor)
            return 0 if u is None else u["depth"]
        conds = sorted(self.conds.values(), key=lambda c: int(c["id"][1:]))
        by_id = {c["id"]: c for c in conds}
        gates = []
        for g in sorted(self.gates.values(), key=lambda g: int(g["gate_id"][1:])):
            terms = sorted(dnf_terms(g["expression"]), key=lambda t: (len(t), sorted(t)))
            recipe, guessed, missing = build_recipe([by_id[c] for c in sorted(terms[0])])
            sinks = [s for s in self.sinks.values() if s["gate"] == g["gate_id"]]
            then = {"min_conditions": len(terms[0]), "env_recipe": recipe, "recipe_guessed_fields": guessed,
                    "recipe_missing": missing, "sinks": sorted({s["kind"] for s in sinks if s["branch"] == "then"}),
                    "regions": g["regions"]}
            else_sinks = sorted({s["kind"] for s in sinks if s["branch"] == "else"})
            # Only a two-outcome gate: a bare early-exit (else does nothing) stays one-branch.
            else_branch = None
            if else_sinks:
                falsify = sorted(min_false_set(g["expression"]))
                erecipe, eguessed, emissing = build_recipe([negate_condition(by_id[c]) for c in falsify])
                else_branch = {"min_conditions": len(falsify), "env_recipe": erecipe,
                               "recipe_guessed_fields": eguessed, "recipe_missing": emissing, "sinks": else_sinks,
                               "regions": g["else_regions"]}
            roles = {role(r) for r in g["regions"]}
            depths = [depth(r) for r in g["regions"]]
            gates.append({"gate_id": g["gate_id"], "hook": g["hook"], "expression": g["expression"],
                          "guards": [self.guards[q] for q in g["guards"]], "reached": g["reached"],
                          "role": worst_role(roles),
                          # require distance of its units from the bundle entry (0 outside bundles; None when
                          # a unit is not reached from the entry), used to rank unknown-role gates
                          "unit_depth": None if None in depths else max(depths, default=0),
                          "then": then, "else": else_branch})
        endpoints: dict[str, list[str]] = {}
        obfuscation = {}
        files = {}
        for rel, fi in self.files.items():
            if fi is None:
                continue
            files[rel] = {"lang": fi.lang, "error_ratio": fi.error_ratio}
            if fi.signals:
                obfuscation[rel] = fi.signals
            for indicator, line in fi.endpoints():
                sites = endpoints.setdefault(indicator, [])
                if f"{rel}:{line}" not in sites:
                    sites.append(f"{rel}:{line}")
        return {
            "conditions": [{"id": c["id"], "category": c["category"], "api": " / ".join(c["apis"]),
                            "operator": c["operator"], "value": c["value"], "value_recovered": c["value_recovered"],
                            "in_scope": c["in_scope"], "sites": c["sites"], "provenance": "in_set", "hook": c["hook"],
                            "reached": c.get("reached", True),
                            "role": worst_role({role(s["anchor"]) for s in c["sites"]}),
                            **({"probe": c["probe"]} if c.get("probe") else {})}
                           for c in conds],
            "gates": gates,
            "guards": sorted(self.guards.values(), key=lambda q: (q["site"]["file"], q["site"]["start_byte"])),
            "units": units,
            "units_summary": bundles.summary(units, entries),
            "hints": {
                "sinks": list(self.sinks.values()),
                "delays": self.delays,
                "silent_failure": self.silent,
                "endpoints": [{"indicator": k, "sites": v} for k, v in endpoints.items()],
                "obfuscation_signals": obfuscation,
                "not_parsed": sorted(self.not_parsed),
            },
            "unrecovered": [{"file": f, "reason": r} for f, r in self.unrecovered.items()],
            "files": files,
            # Where the walk stopped short, so recall figures can disclose it: the global walk budget, and files
            # with a function walked under only MAX_CONTEXTS of its guard stacks.
            "truncation": {"walk_limit": self.walk_limit_hit, "max_walks": MAX_WALKS,
                           "context_limited_files": sorted(self.truncated), "max_contexts": MAX_CONTEXTS},
        }


def main():
    if len(sys.argv) < 4 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if sys.argv[1:2] in (["-h"], ["--help"]) else 2)
    root, hook, entries = Path(sys.argv[1]), sys.argv[2], sys.argv[3:]
    lang = "py" if hook in ("setup_py", "cmdclass", "build_backend") else "js"
    ex = Extractor(root)
    chain = []
    for e in entries:
        chain += [r for r in ex.chain(e, lang) if r not in chain]
    print(json.dumps(ex.run([{"hook": hook, "lang": lang, "entry_files": entries, "chain": chain}]), indent=2,
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
