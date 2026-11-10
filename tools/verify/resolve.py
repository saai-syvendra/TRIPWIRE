"""
The verifier's name resolution: what an identifier is bound to, and what an expression names, with an explicit
answer to "is this complete?".

The old lookup gave the same empty answer for "no binding", "a parameter", "a global" and "something the walk
did not see", and its callers read all of them as absence. Here every answer carries `complete` and a `gap`
reason, and callers may only use absence as evidence when the answer is complete (layers.md, principles 1 and 4).

Scopes (one index per file, built once and cached on the package; deterministic, not charged to a claim's budget):
- JavaScript: program, functions (parameters, `var`, hoisted function declarations), blocks (`let`, `const`,
  `class`, block function declarations), `for` heads and `catch` clauses. Declarations are hoisted within their
  scope, so a helper defined below its caller resolves.
- Python: module, functions and lambdas, classes (visible only in their own body) and comprehensions, with LEGB
  lookup and `global`/`nonlocal`.
A binding's value set is its initialiser plus every assignment to it anywhere in the file, closures included
(flow-insensitive, so it over-approximates what the variable may hold). Parameters, loop variables, caught errors
and augmented assignments are opaque values; `eval`, `with`, `exec` and `globals()` make every binding of the
scopes around them incomplete.

Canonical names (`canon`): dotted paths such as `os.platform()`, `process.env.CI`, `child_process.execSync()`,
through `require`/`import` aliases, destructuring and renames, `(0, x.m)`, static bracket keys, promisify and
interop wrappers, Python `import x as y`, `from m import n as k`, `__import__` and literal `getattr`, and webpack
module ids (`n(101)`) when `n` is provably the bundle's require and module 101 only re-exports a module. Local
definitions canonicalise to `fn:<offset>`, `class:<Name>`, instances to `inst:<Name>`.

Nothing in a package is executed: files are parsed with tree-sitter and read as data.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.common import bundles
from tools.common.tsparse import field as child, static_member_name, static_string, text

JS_FUNCTIONS = {"function_declaration", "function_expression", "arrow_function", "method_definition",
                "generator_function_declaration", "generator_function", "function"}
PY_FUNCTIONS = {"function_definition", "lambda"}
FUNCTIONS = JS_FUNCTIONS | PY_FUNCTIONS
PY_COMPREHENSIONS = {"list_comprehension", "set_comprehension", "dictionary_comprehension", "generator_expression"}
JS_CLASSES = {"class_declaration", "class"}
CLASSES = JS_CLASSES | {"class_definition"}

# Free names a program may read without declaring them. Anything else that is free is unresolved: another file,
# a browser global or a typo, and the checker cannot say what it holds.
KNOWN_GLOBALS = {
    "js": {"process", "require", "module", "exports", "globalThis", "global", "window", "self", "console", "Buffer",
           "Intl", "Date", "JSON", "Math", "Bun", "Deno", "navigator", "fetch", "String", "Array", "Object", "Number",
           "Boolean", "RegExp", "Promise", "URL", "URLSearchParams", "Symbol", "Reflect", "Error", "TypeError",
           "Function", "eval", "parseInt", "parseFloat", "isNaN", "encodeURIComponent", "decodeURIComponent",
           "escape", "unescape", "atob", "btoa", "setTimeout", "setInterval", "setImmediate", "clearTimeout",
           "clearInterval", "queueMicrotask", "structuredClone", "TextEncoder", "TextDecoder", "AbortController",
           "WebSocket", "XMLHttpRequest", "crypto", "performance", "__dirname", "__filename", "undefined", "NaN",
           "Infinity", "Map", "Set", "WeakMap", "Uint8Array", "ArrayBuffer", "DataView", "BigInt", "arguments",
           "importScripts", "document", "location"},
    "py": {"open", "__import__", "getattr", "setattr", "hasattr", "exec", "eval", "compile", "print", "len", "str",
           "int", "float", "bool", "bytes", "list", "dict", "set", "tuple", "range", "enumerate", "zip", "map",
           "filter", "any", "all", "isinstance", "type", "object", "Exception", "OSError", "IOError",
           "FileNotFoundError", "ImportError", "KeyError", "ValueError", "SystemExit", "KeyboardInterrupt",
           "__file__", "__name__", "__builtins__", "globals", "locals", "vars", "exit", "quit", "input", "repr",
           "sorted", "reversed", "min", "max", "sum", "abs", "chr", "ord", "hex", "format", "iter", "next",
           "super", "property", "staticmethod", "classmethod", "True", "False", "None", "NotImplemented",
           "BaseException", "RuntimeError", "PermissionError", "TimeoutError", "callable", "id", "hash", "round"},
}
# Free names that stand for the global object: `globalThis.process` is `process`.
GLOBAL_OBJECTS = {"globalThis", "global", "window", "self"}
# Calls that return their first argument's module or function unchanged, for our purposes.
TRANSPARENT = {"__toESM", "__toCommonJS", "__importDefault", "__importStar", "_interopRequireDefault",
               "_interopRequireWildcard", "__importWildcard", "_interop_require_default", "_interop_require_wildcard",
               "util.promisify", "promisify"}
DYNAMIC_SCOPE_CALLS = {"js": {"eval"}, "py": {"exec", "eval", "globals", "locals", "vars"}}
MAX_DEPTH = 8  # binding steps one canon may follow; deeper is reported incomplete, never guessed


@dataclass(eq=False)
class Scope:
    node: object
    kind: str  # module, function, block, catch, class, comprehension
    parent: "Scope | None"
    names: dict = field(default_factory=dict)
    py_global: set = field(default_factory=set)
    py_nonlocal: set = field(default_factory=set)
    dynamic: bool = False  # eval, with, exec or globals() inside: bindings here may change unseen


@dataclass(eq=False)
class Binding:
    name: str
    kind: str  # var, let, const, function, class, param, import, catch, loop, assign
    scope: Scope
    decl: object = None
    values: list = field(default_factory=list)  # value entries, see module docstring of Index
    refs: list = field(default_factory=list)    # identifier nodes that read or write this binding

    @property
    def complete(self) -> bool:
        return not self.scope.dynamic and not any(v[0] == "opaque" for v in self.values)

    @property
    def gap(self) -> str | None:
        if self.scope.dynamic:
            return "unresolved_binding"
        op = next((v for v in self.values if v[0] == "opaque"), None)
        return op[1] if op else None


@dataclass(frozen=True)
class Resolved:
    """What a name may hold. `complete` means the value set is exhaustive."""
    values: tuple
    complete: bool
    gap: str | None = None
    binding: Binding | None = None


def key(node) -> tuple:
    return (node.start_byte, node.end_byte, node.type)


def ancestors(node):
    n = node.parent
    while n is not None:
        yield n
        n = n.parent


def unwrap(node):
    """Strips parentheses and awaits (`(await x)` reads as x)."""
    while node is not None and node.type in ("parenthesized_expression", "await_expression", "await") and \
            node.named_children:
        node = node.named_children[-1]
    return node


# --- the scope index -------------------------------------------------------------------------------------

class Index:
    """Scopes and bindings of one parsed file.

    Value entries of a binding:
      ("node", n)            the binding takes the value of expression n
      ("destr", n, path)     a destructured part of n: path is a tuple of keys (str), indexes (int) or None
      ("import", mod, name)  an import: name None is the module object
      ("fn", n) / ("class", n)  a function or class definition
      ("undefined",)         declared without a value
      ("opaque", gap)        an unknown value (a parameter, a loop variable, an augmented assignment, ...)
    """

    def __init__(self, tree, lang: str):
        self.lang = lang
        self.scopes: dict[tuple, Scope] = {}
        self.ref: dict[tuple, Binding | None] = {}  # identifier node -> binding (None: free name)
        self.free_refs: dict[str, list] = {}
        self.root = tree.root_node
        if lang == "js":
            self._declare_js()
        else:
            self._declare_py()
        self._resolve_refs()

    # scope helpers
    def _new_scope(self, node, kind, parent) -> Scope:
        s = Scope(node, kind, parent)
        self.scopes[key(node)] = s
        return s

    def _declare(self, scope: Scope, name_node, kind: str, value) -> Binding:
        name = text(name_node)
        b = scope.names.get(name)
        if b is None:
            b = scope.names[name] = Binding(name, kind, scope, name_node)
        b.values.append(value)
        if name_node is not None:
            self.ref[key(name_node)] = b
            b.refs.append(name_node)
        return b

    def scope_kind_js(self, node) -> str | None:
        t = node.type
        if t == "program":
            return "module"
        if t in JS_FUNCTIONS:
            return "function"
        if t == "statement_block" and node.parent is not None and node.parent.type in JS_FUNCTIONS:
            return None  # a function body shares the function's scope
        if t in ("statement_block", "for_statement", "for_in_statement", "switch_body", "class_body"):
            return "block"
        if t == "catch_clause":
            return "catch"
        return None

    def scope_kind_py(self, node) -> str | None:
        t = node.type
        if t == "module":
            return "module"
        if t in PY_FUNCTIONS:
            return "function"
        if t == "class_definition":
            return "class"
        if t in PY_COMPREHENSIONS:
            return "comprehension"
        return None

    @staticmethod
    def _function_scope(scope: Scope) -> Scope:
        while scope.kind not in ("function", "module"):
            scope = scope.parent
        return scope

    # JavaScript declarations
    def _pattern_names(self, pat, path=()):
        """(identifier node, path, default value or None) for every name a binding pattern declares."""
        if pat is None:
            return
        t = pat.type
        if t in ("identifier", "shorthand_property_identifier_pattern"):
            yield pat, path, None
        elif t == "object_pattern":
            for p in pat.named_children:
                if p.type == "shorthand_property_identifier_pattern":
                    yield p, path + (text(p),), None
                elif p.type == "object_assignment_pattern":
                    left, right = p.child_by_field_name("left"), p.child_by_field_name("right")
                    k = text(left) if left is not None and left.type == "shorthand_property_identifier_pattern" \
                        else None
                    for n, sub, _ in self._pattern_names(left, path + (k,)):
                        yield n, sub, right
                elif p.type == "pair_pattern":
                    kn = p.child_by_field_name("key")
                    k = static_key_text(kn)
                    yield from self._pattern_names(p.child_by_field_name("value"), path + (k,))
                elif p.type == "rest_pattern":
                    for n, _, _ in self._pattern_names(p.named_children[0] if p.named_children else None):
                        yield n, path + (None,), None
        elif t == "array_pattern":
            for i, p in enumerate(c for c in pat.named_children if c.type != "comment"):
                if p.type == "rest_pattern":
                    for n, _, _ in self._pattern_names(p.named_children[0] if p.named_children else None):
                        yield n, path + (None,), None
                else:
                    yield from self._pattern_names(p, path + (i,))
        elif t in ("assignment_pattern", "object_assignment_pattern"):
            for n, sub, _ in self._pattern_names(pat.child_by_field_name("left"), path):
                yield n, sub, pat.child_by_field_name("right")
        elif t == "rest_pattern" and pat.named_children:
            yield from self._pattern_names(pat.named_children[0], path + (None,))

    def _declare_pattern(self, scope, pat, kind, init):
        for name, path, default in self._pattern_names(pat):
            if init is None:
                # a gap is a verdict reason_code: a parameter's value comes from its callers, an unresolved binding
                value = ("undefined",) if kind != "param" else ("opaque", "unresolved_binding")
            elif init == "opaque":
                value = ("opaque", "unresolved_binding")
            else:
                value = ("node", init) if not path else ("destr", init, path)
            b = self._declare(scope, name, kind, value)
            if default is not None:
                b.values.append(("node", default))

    def _declare_js(self):
        stack = [(self.root, None)]
        while stack:
            node, scope = stack.pop()
            kind = self.scope_kind_js(node)
            if kind:
                outer = scope
                scope = self._new_scope(node, kind, scope)
                t = node.type
                if t in ("function_declaration", "generator_function_declaration") and outer is not None:
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self._declare(outer, name, "function", ("fn", node))
                if t in ("function_expression", "generator_function", "function"):
                    name = node.child_by_field_name("name")
                    if name is not None:
                        self._declare(scope, name, "function", ("fn", node))
                if t in JS_FUNCTIONS:
                    params = node.child_by_field_name("parameters")
                    single = node.child_by_field_name("parameter")
                    for p in ([single] if single is not None else
                              [c for c in (params.named_children if params is not None else []) if c.type != "comment"]):
                        self._declare_pattern(scope, p, "param", "opaque")
                if t == "catch_clause":
                    self._declare_pattern(scope, node.child_by_field_name("parameter"), "catch", "opaque")
                if t == "for_in_statement":
                    words = {c.type for c in node.children if not c.is_named}
                    left = node.child_by_field_name("left")
                    if words & {"let", "const"}:
                        self._declare_pattern(scope, left, "loop", "opaque")
                    elif "var" in words:
                        self._declare_pattern(self._function_scope(scope), left, "loop", "opaque")
            t = node.type
            if t == "class_declaration" and scope is not None:
                name = node.child_by_field_name("name")
                if name is not None:
                    self._declare(scope, name, "class", ("class", node))
            elif t == "class" and node.child_by_field_name("name") is not None:
                pass  # a named class expression binds its name inside itself only; reads of it stay unresolved
            elif t == "variable_declarator":
                decl = node.parent
                words = {c.type for c in decl.children if not c.is_named} if decl is not None else set()
                target = self._function_scope(scope) if decl is not None and decl.type == "variable_declaration" \
                    else scope
                vkind = "var" if decl is not None and decl.type == "variable_declaration" else \
                    ("const" if "const" in words else "let")
                self._declare_pattern(target, node.child_by_field_name("name"), vkind, node.child_by_field_name("value"))
            elif t == "import_statement":
                self._declare_import_js(scope, node)
                continue
            for c in reversed(node.children):
                stack.append((c, scope))

    def _declare_import_js(self, scope, node):
        src = static_string(node.child_by_field_name("source"))
        mod = module_name(src) if src is not None else None
        clause = next((c for c in node.named_children if c.type == "import_clause"), None)
        if clause is None:
            return
        for c in clause.named_children:
            if c.type == "identifier":  # default import
                self._declare(scope, c, "import", ("import", mod, None) if mod else ("opaque", "unresolved_binding"))
            elif c.type == "namespace_import" and c.named_children:
                self._declare(scope, c.named_children[0], "import",
                              ("import", mod, None) if mod else ("opaque", "unresolved_binding"))
            elif c.type == "named_imports":
                for spec in c.named_children:
                    if spec.type != "import_specifier":
                        continue
                    name, alias = spec.child_by_field_name("name"), spec.child_by_field_name("alias")
                    local = alias if alias is not None else name
                    self._declare(scope, local, "import", ("import", mod, text(name)) if mod else
                                  ("opaque", "unresolved_binding"))

    # Python declarations
    def _py_targets(self, target, path=()):
        """(identifier, path) for every name an assignment target binds; attribute and subscript targets bind none."""
        if target is None:
            return
        t = target.type
        if t == "identifier":
            yield target, path
        elif t in ("pattern_list", "tuple_pattern", "list_pattern", "expression_list", "tuple", "list"):
            for i, c in enumerate(x for x in target.named_children if x.type != "comment"):
                if c.type in ("list_splat_pattern", "list_splat"):
                    for n, _ in self._py_targets(c.named_children[0] if c.named_children else None):
                        yield n, path + (None,)
                else:
                    yield from self._py_targets(c, path + (i,))
        elif t in ("parenthesized_expression",) and target.named_children:
            yield from self._py_targets(target.named_children[0], path)

    def _py_bind_scope(self, scope: Scope, name: str) -> Scope:
        """Where an assignment in `scope` binds `name`: the module for `global`, an enclosing function for
        `nonlocal`, else the scope itself."""
        if name in scope.py_global:
            s = scope
            while s.parent is not None:
                s = s.parent
            return s
        if name in scope.py_nonlocal:
            s = scope.parent
            while s is not None and not (s.kind == "function" and name in s.names):
                s = s.parent
            return s or scope
        return scope

    def _py_assign(self, scope, target, value_entry_for):
        for name, path in self._py_targets(target):
            s = self._py_bind_scope(scope, text(name))
            self._declare(s, name, "assign", value_entry_for(path))

    def _declare_py(self):
        # globals/nonlocals first, so assignments know where they bind
        stack = [(self.root, None)]
        order = []
        while stack:
            node, scope = stack.pop()
            kind = self.scope_kind_py(node)
            if kind:
                outer = scope
                scope = self._new_scope(node, kind, scope)
                if node.type in ("function_definition", "class_definition") and outer is not None:
                    name = node.child_by_field_name("name")
                    if name is not None:
                        order.append(("def", outer, node, name))
                if node.type in PY_FUNCTIONS:
                    params = node.child_by_field_name("parameters")
                    for p in (params.named_children if params is not None else []):
                        order.append(("param", scope, p, None))
            if node.type in ("global_statement", "nonlocal_statement"):
                names = {text(c) for c in node.named_children if c.type == "identifier"}
                (scope.py_global if node.type == "global_statement" else scope.py_nonlocal).update(names)
                for c in node.named_children:
                    self.ref[key(c)] = None  # resolved after declarations
                continue
            order.append(("node", scope, node, None))
            for c in reversed(node.children):
                stack.append((c, scope))
        for what, scope, node, name in order:
            if what == "def":
                s = self._py_bind_scope(scope, text(name))
                self._declare(s, name, "function" if node.type == "function_definition" else "class",
                              ("fn", node) if node.type == "function_definition" else ("class", node))
            elif what == "param":
                p = node
                if p.type in ("default_parameter", "typed_default_parameter"):
                    nm = p.child_by_field_name("name")
                    if nm is not None:
                        self._declare(scope, nm, "param", ("opaque", "unresolved_binding"))
                elif p.type in ("typed_parameter",):
                    nm = next((c for c in p.named_children if c.type == "identifier"), None)
                    if nm is not None:
                        self._declare(scope, nm, "param", ("opaque", "unresolved_binding"))
                elif p.type in ("list_splat_pattern", "dictionary_splat_pattern") and p.named_children:
                    self._declare(scope, p.named_children[0], "param", ("opaque", "unresolved_binding"))
                elif p.type == "identifier":
                    self._declare(scope, p, "param", ("opaque", "unresolved_binding"))
            else:
                self._declare_py_node(scope, node)

    def _declare_py_node(self, scope, node):
        t = node.type
        if t == "assignment":
            left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
            if right is None:  # an annotation only: `x: int`
                return
            # chained `a = b = v` parses as nested assignments on the right
            while right is not None and right.type == "assignment":
                self._py_assign(scope, right.child_by_field_name("left"),
                                lambda path, r=right: ("node", r.child_by_field_name("right")))
                right = right.child_by_field_name("right")
            self._py_assign(scope, left, lambda path, r=right: ("node", r) if not path else ("destr", r, path))
        elif t == "augmented_assignment":
            self._py_assign(scope, node.child_by_field_name("left"), lambda path: ("opaque", "unresolved_binding"))
        elif t in ("for_statement", "for_in_clause"):
            self._py_assign(scope, node.child_by_field_name("left"), lambda path: ("opaque", "unresolved_binding"))
        elif t == "as_pattern":
            alias = node.child_by_field_name("alias")
            for c in (alias.named_children if alias is not None else []):
                self._py_assign(scope, c, lambda path: ("opaque", "unresolved_binding"))
        elif t == "named_expression":
            s = scope
            while s.kind == "comprehension":
                s = s.parent
            name = node.child_by_field_name("name")
            if name is not None:
                self._declare(self._py_bind_scope(s, text(name)), name, "assign",
                              ("node", node.child_by_field_name("value")))
        elif t == "import_statement":
            for nm in node.children_by_field_name("name"):
                if nm.type == "aliased_import":
                    dotted, alias = nm.child_by_field_name("name"), nm.child_by_field_name("alias")
                    self._declare(scope, alias, "import", ("import", text(dotted), None))
                elif nm.type == "dotted_name" and nm.named_children:
                    first = nm.named_children[0]
                    self._declare(scope, first, "import", ("import", text(first), None))
        elif t == "import_from_statement":
            modn = node.child_by_field_name("module_name")
            mod = text(modn) if modn is not None and modn.type == "dotted_name" else None
            if any(c.type == "wildcard_import" for c in node.named_children):
                scope.dynamic = True  # names arrive unseen
                return
            for nm in node.children_by_field_name("name"):
                if nm.type == "aliased_import":
                    orig, alias = nm.child_by_field_name("name"), nm.child_by_field_name("alias")
                    self._declare(scope, alias, "import", ("import", mod, text(orig)) if mod else
                                  ("opaque", "unresolved_binding"))
                elif nm.type == "dotted_name" and nm.named_children:
                    last = nm.named_children[-1]
                    self._declare(scope, last, "import", ("import", mod, text(nm)) if mod else
                                  ("opaque", "unresolved_binding"))

    # references
    def _is_reference(self, ident) -> bool:
        p = ident.parent
        if p is None:
            return False
        if key(ident) in self.ref:
            return False  # a declaration name, already bound
        if self.lang == "js":
            if p.type in ("import_specifier", "export_specifier", "namespace_import", "labeled_statement",
                          "break_statement", "continue_statement"):
                return False
            return True
        if p.type == "attribute" and p.child_by_field_name("attribute") is not None and \
                key(p.child_by_field_name("attribute")) == key(ident):
            return False
        if p.type == "keyword_argument" and p.child_by_field_name("name") is not None and \
                key(p.child_by_field_name("name")) == key(ident):
            return False
        if p.type in ("dotted_name", "aliased_import", "import_from_statement", "import_statement"):
            return False
        return True

    def lookup_name(self, scope: Scope, name: str) -> Binding | None:
        if self.lang == "py":
            s = scope
            if name in s.names:
                return s.names[name]
            s = s.parent
            while s is not None:
                if s.kind != "class" and name in s.names:
                    return s.names[name]
                s = s.parent
            return None
        s = scope
        while s is not None:
            if name in s.names:
                return s.names[name]
            s = s.parent
        return None

    @staticmethod
    def _in_function(scope: Scope) -> bool:
        s = scope
        while s is not None:
            if s.kind == "function":
                return True
            if s.kind == "module":
                return False
            s = s.parent
        return False

    @staticmethod
    def _module_scope(scope: Scope) -> Scope:
        s = scope
        while s.parent is not None:
            s = s.parent
        return s

    def _mark_dynamic(self, scope: Scope):
        s = scope
        while s is not None:
            s.dynamic = True
            if s.kind in ("function", "module"):
                break
            s = s.parent

    def _resolve_refs(self):
        stack = [(self.root, None)]
        while stack:
            node, scope = stack.pop()
            s = self.scopes.get(key(node))
            if s is not None:
                scope = s
            t = node.type
            if t == "with_statement" and self.lang == "js":
                self._mark_dynamic(scope)
            if t == "exec_statement" and self.lang == "py":  # Python 2 `exec code`: anything may change
                self._mark_dynamic(scope)
                self._mark_dynamic(self._module_scope(scope))
            if t in ("identifier", "shorthand_property_identifier") and self._is_reference(node):
                name = text(node)
                if self.lang == "py" and node.parent is not None and node.parent.type in (
                        "global_statement", "nonlocal_statement"):
                    b = self.lookup_name(scope, name)
                else:
                    b = self.lookup_name(scope, name)
                self.ref[key(node)] = b
                if b is None:
                    self.free_refs.setdefault(name, []).append(node)
                else:
                    b.refs.append(node)
                    if self.lang == "js":
                        self._js_write(node, b)
                if b is None and name in DYNAMIC_SCOPE_CALLS[self.lang] and node.parent is not None and \
                        node.parent.type in ("call_expression", "call"):
                    if self.lang == "py" and self._in_function(scope):
                        # Python 3: exec/eval/locals() inside a function cannot rebind its own (fast) locals, but
                        # exec/eval code may declare `global x` and globals() writes module names, so the module's
                        # bindings are what may change unseen
                        if name in ("exec", "eval", "globals", "vars"):  # vars(module) is the module's dict
                            self._mark_dynamic(self._module_scope(scope))
                    else:
                        self._mark_dynamic(scope)
            for c in reversed(node.children):
                stack.append((c, scope))

    def _js_write(self, ident, b: Binding):
        """Adds the value an assignment to this reference stores."""
        p, child_ = ident.parent, ident
        path = ()
        # climb out of a destructuring assignment pattern: ({a: x} = v), [x, y] = v
        while p is not None and p.type in ("pair_pattern", "object_pattern", "array_pattern", "pair", "object",
                                           "array", "object_assignment_pattern", "shorthand_property_identifier"):
            if p.type in ("pair_pattern", "pair"):
                path = (static_key_text(p.child_by_field_name("key")),) + path
            elif p.type in ("array_pattern", "array"):
                path = ([c for c in p.named_children if c.type != "comment"].index(child_),) + path \
                    if child_ in p.named_children else (None,) + path
            child_, p = p, p.parent
        if p is None:
            return
        if p.type == "assignment_expression" and p.child_by_field_name("left") is not None and \
                key(p.child_by_field_name("left")) == key(child_):
            right = p.child_by_field_name("right")
            b.values.append(("node", right) if not path else ("destr", right, path))
        elif p.type == "augmented_assignment_expression" and key(p.child_by_field_name("left")) == key(child_):
            b.values.append(("opaque", "unresolved_binding"))
        elif p.type == "update_expression":
            b.values.append(("opaque", "unresolved_binding"))

    # queries
    def binding_of(self, ident) -> Binding | None:
        return self.ref.get(key(ident))

    def scope_of(self, node) -> Scope | None:
        for n in [node, *ancestors(node)]:
            s = self.scopes.get(key(n))
            if s is not None:
                return s
        return None

    def lookup(self, ident) -> Resolved:
        """What an identifier reference may hold."""
        if key(ident) not in self.ref:
            return Resolved((), False, "unresolved_binding")
        b = self.ref[key(ident)]
        if b is None:
            name = text(ident)
            known = name in KNOWN_GLOBALS[self.lang]
            return Resolved((("global", name),), known, None if known else "unresolved_binding")
        return Resolved(tuple(b.values), b.complete, b.gap, b)


def static_key_text(k) -> str | None:
    if k is None:
        return None
    if k.type in ("property_identifier", "identifier", "shorthand_property_identifier_pattern"):
        return text(k)
    if k.type in ("string", "template_string"):
        return static_string(k)
    if k.type == "number":
        return text(k)
    if k.type == "computed_property_name" and k.named_children:
        return static_string(k.named_children[0])
    return None


def module_name(spec: str) -> str:
    """`node:os` -> os; relative paths stay as written (a package file, not a builtin)."""
    return spec[5:] if spec.startswith("node:") else spec


# --- per-file context -------------------------------------------------------------------------------------

class FileCtx:
    """A parsed file with its scope index and bundle layout, cached on the package."""

    def __init__(self, pkg, file: str, derived_from: str | None):
        self.pkg, self.file, self.derived = pkg, file, derived_from
        self.src, self.tree, self.lang = pkg.tree(file, derived_from)
        cache_key = ("resolve.index", file, derived_from)
        if cache_key not in pkg.cache:
            pkg.cache[cache_key] = Index(self.tree, self.lang) if self.tree is not None else None
        self.index: Index | None = pkg.cache[cache_key]
        bkey = ("resolve.bundle", file, derived_from)
        if bkey not in pkg.cache:
            pkg.cache[bkey] = bundle_layout(self.tree, file, derived_from) if self.lang == "js" else None
        self.bundle = pkg.cache[bkey]


def ctx_for(pkg, anchor: dict) -> FileCtx:
    k = ("resolve.ctx", anchor["file"], anchor["derived_from"])
    if k not in pkg.cache:
        pkg.cache[k] = FileCtx(pkg, anchor["file"], anchor["derived_from"])
    return pkg.cache[k]


def bundle_layout(tree, file, derived) -> dict | None:
    """Module units of a bundle by id, with the factory node, its kind and what a re-export shim exports."""
    if tree is None:
        return None
    info = bundles.analyse(tree, file, derived)
    if not info["units"]:
        return None
    units = {}
    for u in info["units"]:
        node = tree.root_node.descendant_for_byte_range(u["start_byte"], u["end_byte"])
        while node is not None and (node.start_byte, node.end_byte) != (u["start_byte"], u["end_byte"]):
            node = node.parent
        if node is not None:
            units[u["module_id"]] = {"node": node, "kind": u["kind"], "reexports": bundles.reexport_of(node, u["kind"])}
    return {"units": units, "require_names": set(info["require_names"]),
            "factories": {key(v["node"]): (mid, v["kind"]) for mid, v in units.items()}}


# --- canonical names --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Canon:
    """What an expression names: a set of canonical names, whether that set is exhaustive, and the literal static
    member chain as written (`this.octokit.rest.users.getAuthenticated()`), for claims that name package-local
    objects."""
    names: frozenset
    complete: bool
    gap: str | None = None
    chain: tuple | None = None

    @staticmethod
    def unknown(gap: str, chain=None) -> "Canon":
        return Canon(frozenset(), False, gap, chain)

    def extend(self, suffix: str, chain_part: str | None) -> "Canon":
        chain = self.chain + (chain_part,) if self.chain is not None and chain_part is not None else None
        return Canon(frozenset(n + suffix for n in self.names), self.complete, self.gap, chain)


def merge(canons: list[Canon], chain=None) -> Canon:
    names = frozenset().union(*(c.names for c in canons)) if canons else frozenset()
    complete = bool(canons) and all(c.complete for c in canons)
    gap = next((c.gap for c in canons if c.gap), None) if not complete else None
    return Canon(names, complete, gap or (None if complete else "unresolved_binding"), chain)


def literal_chain(node) -> tuple | None:
    """`a.b["c"].d()` -> ('a', 'b', 'c', 'd()'); None when any part is computed or not a name."""
    node = unwrap(node)
    if node is None:
        return None
    t = node.type
    if t in ("identifier", "this", "property_identifier", "shorthand_property_identifier"):
        return (text(node),)
    if t in ("member_expression", "subscript_expression", "attribute", "subscript"):
        prop = static_member_name(node)
        obj = literal_chain(child(node, "object", "value"))
        return obj + (prop,) if obj is not None and prop is not None else None
    if t in ("call_expression", "call"):
        fn = literal_chain(node.child_by_field_name("function"))
        return fn[:-1] + (fn[-1] + "()",) if fn else None
    if t == "new_expression":
        c = literal_chain(node.child_by_field_name("constructor"))
        return ("new " + ".".join(c),) if c else None
    return None


def canon(ctx: FileCtx, node, depth: int = 0, seen: frozenset = frozenset()) -> Canon:
    """Canonical names of an expression."""
    from tools.verify import checks
    checks.spend()
    node = unwrap(node)
    if node is None or ctx.index is None:
        return Canon.unknown("lang_unsupported")
    chain = literal_chain(node)
    if depth > MAX_DEPTH:
        return Canon.unknown("budget_exceeded", chain)
    t = node.type
    if t in ("identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern"):
        return _canon_ident(ctx, node, depth, seen, chain)
    if t == "this":
        return Canon.unknown("unresolved_binding", chain)
    if t in ("member_expression", "subscript_expression", "attribute", "subscript"):
        prop = static_member_name(node)
        if prop is None:
            idx = child(node, "index", "subscript")
            vals = const_values(ctx, idx, depth + 1) if idx is not None else None
            if vals is None or not vals.complete or not all(isinstance(v, str) for v in vals.values):
                return Canon.unknown("dynamic_dispatch", chain)
            obj = canon(ctx, child(node, "object", "value"), depth + 1, seen)
            return merge([obj.extend("." + v, v) for v in vals.values], chain)
        obj_node = unwrap(child(node, "object", "value"))
        if obj_node is not None and obj_node.type == "identifier" and text(obj_node) in GLOBAL_OBJECTS and \
                ctx.index.binding_of(obj_node) is None:
            return Canon(frozenset({prop}), True, None, chain)  # globalThis.process -> process
        obj = canon(ctx, obj_node, depth + 1, seen)
        if prop == "default" and any(not n.startswith(("fn:", "class:", "inst:", "lit:")) for n in obj.names):
            return Canon(obj.names, obj.complete, obj.gap, chain)  # interop: require('os').default is os
        return obj.extend("." + prop, prop) if obj.names or obj.complete else Canon(frozenset(), False, obj.gap, chain)
    if t in ("call_expression", "call"):
        return _canon_call(ctx, node, depth, seen, chain)
    if t == "new_expression":
        c = canon(ctx, node.child_by_field_name("constructor"), depth + 1, seen)
        names = frozenset(("inst:" + n[6:]) if n.startswith("class:") else ("new:" + n) for n in c.names)
        return Canon(names, c.complete, c.gap, chain)
    if t == "sequence_expression" and node.named_children:
        return canon(ctx, node.named_children[-1], depth + 1, seen)
    if t in FUNCTIONS:
        return Canon(frozenset({f"fn:{node.start_byte}"}), True, None, chain)
    if t in CLASSES:
        name = node.child_by_field_name("name")
        return Canon(frozenset({f"class:{text(name) if name is not None else node.start_byte}"}), True, None, chain)
    if t in ("string", "template_string", "number", "integer", "float", "true", "false", "null", "none",
             "undefined", "object", "array", "regex", "dictionary", "list"):
        return Canon(frozenset({f"lit:{t}"}), True, None, chain)
    if t in ("binary_expression", "boolean_operator") and text(node.child_by_field_name("operator") or node) in (
            "||", "??", "or"):
        parts = [canon(ctx, node.child_by_field_name("left"), depth + 1, seen),
                 canon(ctx, node.child_by_field_name("right"), depth + 1, seen)]
        return merge(parts, chain)
    if t in ("ternary_expression",):
        parts = [canon(ctx, node.child_by_field_name("consequence"), depth + 1, seen),
                 canon(ctx, node.child_by_field_name("alternative"), depth + 1, seen)]
        return merge(parts, chain)
    return Canon.unknown("unresolved_binding", chain)


def _canon_ident(ctx: FileCtx, node, depth, seen, chain) -> Canon:
    r = ctx.index.lookup(node)
    if r.binding is None:
        if not r.values:
            return Canon.unknown(r.gap or "unresolved_binding", chain)
        name = r.values[0][1]
        return Canon(frozenset({name}), r.complete, r.gap, chain)
    bkey = id(r.binding)
    if bkey in seen:
        return Canon.unknown("unresolved_binding", chain)
    seen = seen | {bkey}
    parts = []
    for v in r.values:
        parts.append(value_canon(ctx, v, depth, seen))
    out = merge(parts, chain)
    if not r.complete:
        return Canon(out.names, False, r.gap or out.gap or "unresolved_binding", chain)
    return out


def value_canon(ctx: FileCtx, v: tuple, depth: int, seen: frozenset) -> Canon:
    kind = v[0]
    if kind == "node":
        return canon(ctx, v[1], depth + 1, seen)
    if kind == "destr":
        base = canon(ctx, v[1], depth + 1, seen)
        for k in v[2]:
            if k is None or isinstance(k, int):
                return Canon.unknown("unresolved_binding")
            base = base.extend("." + k, k)
        return base
    if kind == "import":
        mod, name = v[1], v[2]
        if mod is None:
            return Canon.unknown("unresolved_binding")
        return Canon(frozenset({f"{mod}.{name}" if name and name != "default" else mod}), True)
    if kind == "fn":
        return Canon(frozenset({f"fn:{v[1].start_byte}"}), True)
    if kind == "class":
        name = v[1].child_by_field_name("name")
        return Canon(frozenset({f"class:{text(name) if name is not None else v[1].start_byte}"}), True)
    if kind == "undefined":
        return Canon(frozenset({"lit:undefined"}), True)
    return Canon.unknown(v[1] if len(v) > 1 else "unresolved_binding")


def call_args(node) -> list:
    args = node.child_by_field_name("arguments")
    if args is None or args.type in ("template_string",):
        return []
    return [a for a in args.named_children if a.type != "comment"]


def _canon_call(ctx: FileCtx, node, depth, seen, chain) -> Canon:
    fn = unwrap(node.child_by_field_name("function"))
    argv = call_args(node)
    if fn is None:
        return Canon.unknown("unresolved_binding", chain)
    first = static_string(argv[0]) if argv else None
    if fn.type in ("identifier",) and ctx.index.binding_of(fn) is None:
        name = text(fn)
        if name == "require" and first is not None:
            return Canon(frozenset({module_name(first)}), True, None, chain)
        if name == "__import__" and first is not None:
            return Canon(frozenset({first}), True, None, chain)
        if name == "getattr" and len(argv) >= 2 and static_string(argv[1]) is not None:
            return canon(ctx, argv[0], depth + 1, seen).extend("." + static_string(argv[1]), static_string(argv[1]))
        if name == "require":
            return Canon.unknown("dynamic_dispatch", chain)
    if fn.type == "identifier" and ctx.bundle is not None:
        loaded = bundle_load(ctx, node, fn, argv)
        if loaded is not None:
            return Canon(loaded.names, loaded.complete, loaded.gap, chain)
    callee = canon(ctx, fn, depth + 1, seen)
    if callee.names & TRANSPARENT and argv:
        inner = canon(ctx, argv[0], depth + 1, seen)
        return merge([inner, Canon(callee.names - TRANSPARENT, callee.complete, callee.gap)], chain) \
            if callee.names - TRANSPARENT else Canon(inner.names, inner.complete and callee.complete, inner.gap, chain)
    if fn.type in ("member_expression", "attribute") and static_member_name(fn) in ("call", "apply", "bind"):
        target = canon(ctx, child(fn, "object", "value"), depth + 1, seen)
        return target.extend("()", None) if static_member_name(fn) != "bind" else target
    if callee.names == frozenset({"importlib.import_module"}) and first is not None:
        return Canon(frozenset({first}), True, None, chain)
    out = callee.extend("()", None)
    return Canon(out.names, out.complete, out.gap, chain)


def bundle_load(ctx: FileCtx, call, fn, argv) -> Canon | None:
    """A call of the bundle's require with a literal module id: the module a re-export shim exports, `unit:<id>`
    for the package's own modules, or an unresolved answer for an id the bundle does not hold. None when the call
    is not a bundle require at all."""
    if len(argv) != 1:
        return None
    mid = bundles.literal_id(argv[0])
    if mid is None:
        return None
    b = ctx.index.binding_of(fn)
    is_require = False
    if b is not None and b.kind == "param":
        hit = ctx.bundle["factories"].get(key(b.scope.node))
        if hit is not None and bundles.require_param(b.scope.node, hit[1]) == b.name and ctx.bundle["require_names"]:
            is_require = True
    elif b is not None and b.kind in ("function", "var", "let", "const") and b.name in ctx.bundle["require_names"]:
        is_require = True
    if not is_require:
        return None
    unit = ctx.bundle["units"].get(mid)
    if unit is None:
        return Canon.unknown("bundle_unresolved")
    if unit["reexports"]:
        return Canon(frozenset({module_name(unit["reexports"])}), True)
    return Canon(frozenset({f"unit:{mid}"}), False, "bundle_unresolved")


# --- constant values --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Values:
    """The constant values an expression may evaluate to; `complete` means no other value is possible."""
    values: tuple
    complete: bool


@dataclass(frozen=True)
class Regex:
    pattern: str
    flags: str = ""


MAX_VALUES = 16


def const_values(ctx: FileCtx, node, depth: int = 0, seen: frozenset = frozenset()) -> Values | None:
    """Constant values of an expression (strings, numbers, booleans, None, regexes), following bindings."""
    from tools.verify import checks
    checks.spend()
    node = unwrap(node)
    if node is None or depth > MAX_DEPTH:
        return Values((), False)
    t = node.type
    s = static_string(node)
    if s is not None:
        return Values((s,), True)
    if t in ("number", "integer", "float"):
        raw = text(node).replace("_", "")
        try:
            return Values((int(raw, 0) if raw.lower().startswith(("0x", "0o", "0b")) else
                           (float(raw) if any(c in raw for c in ".eE") and not raw.lower().startswith("0x")
                            else int(raw)),), True)
        except ValueError:
            return Values((), False)
    if t in ("true", "false"):
        return Values((t == "true",), True)
    if t in ("null", "none", "undefined"):
        return Values((None,), True)
    if t == "regex":
        pat, flags = node.child_by_field_name("pattern"), node.child_by_field_name("flags")
        return Values((Regex(text(pat) if pat is not None else "", text(flags) if flags is not None else ""),), True)
    if t == "identifier":
        if text(node) == "undefined" and ctx.index.binding_of(node) is None:
            return Values((None,), True)
        r = ctx.index.lookup(node)
        if r.binding is None or id(r.binding) in seen:
            return Values((), False)
        out, complete = [], r.complete
        for v in r.values:
            if v[0] == "node":
                sub = const_values(ctx, v[1], depth + 1, seen | {id(r.binding)})
            elif v[0] == "undefined":
                sub = Values((None,), True)
            else:
                sub = Values((), False)
            out += [x for x in sub.values if x not in out]
            complete = complete and sub.complete
        return Values(tuple(out[:MAX_VALUES]), complete and len(out) <= MAX_VALUES)
    if t == "template_string":
        parts = [[]]
        complete = True
        for c in node.children:
            if c.type == "template_substitution":
                sub = const_values(ctx, c.named_children[0] if c.named_children else None, depth + 1, seen)
                if not sub.complete or not sub.values:
                    return Values((), False)
                parts = [p + [str(v)] for p in parts for v in sub.values][:MAX_VALUES]
            elif c.type in ("string_fragment", "escape_sequence"):
                frag = static_string_fragment(c)
                parts = [p + [frag] for p in parts]
        return Values(tuple("".join(p) for p in parts), complete)
    if t == "binary_expression" and text(node.child_by_field_name("operator")) == "+":
        a = const_values(ctx, node.child_by_field_name("left"), depth + 1, seen)
        b = const_values(ctx, node.child_by_field_name("right"), depth + 1, seen)
        if not (a.complete and b.complete and a.values and b.values):
            return Values((), False)
        vals = []
        for x in a.values:
            for y in b.values:
                if isinstance(x, str) or isinstance(y, str):
                    vals.append(f"{_js_str(x)}{_js_str(y)}")
                elif isinstance(x, (int, float)) and isinstance(y, (int, float)):
                    vals.append(x + y)
                else:
                    return Values((), False)
        return Values(tuple(dict.fromkeys(vals))[:MAX_VALUES], len(vals) <= MAX_VALUES)
    if t == "unary_expression" and text(node.child_by_field_name("operator")) == "-":
        a = const_values(ctx, node.child_by_field_name("argument"), depth + 1, seen)
        if a.complete and a.values and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in a.values):
            return Values(tuple(-x for x in a.values), True)
        return Values((), False)
    if t in ("unary_expression",) and text(node.child_by_field_name("operator")) == "void":
        return Values((None,), True)
    if t in ("binary_expression", "boolean_operator") and text(node.child_by_field_name("operator") or node) in (
            "||", "??", "or"):
        a = const_values(ctx, node.child_by_field_name("left"), depth + 1, seen)
        b = const_values(ctx, node.child_by_field_name("right"), depth + 1, seen)
        return Values(tuple(dict.fromkeys(a.values + b.values))[:MAX_VALUES], a.complete and b.complete)
    if t == "ternary_expression":
        a = const_values(ctx, node.child_by_field_name("consequence"), depth + 1, seen)
        b = const_values(ctx, node.child_by_field_name("alternative"), depth + 1, seen)
        return Values(tuple(dict.fromkeys(a.values + b.values))[:MAX_VALUES], a.complete and b.complete)
    if t in ("tuple", "list", "array", "set"):
        items = [const_values(ctx, c, depth + 1, seen) for c in node.named_children if c.type != "comment"]
        if all(i.complete and len(i.values) == 1 for i in items):
            return Values((tuple(i.values[0] for i in items),), True)
        return Values((), False)
    return Values((), False)


def _js_str(x) -> str:
    if x is None:
        return "null"
    if isinstance(x, bool):
        return "true" if x else "false"
    return str(x)


def static_string_fragment(c) -> str:
    from tools.common.sanitize import unescape
    return unescape(text(c))[0]
