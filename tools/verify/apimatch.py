"""
L1 and L2 for the deterministic checker, rebuilt on resolve.py (names) and cfg.py (control). The contract:
verify only on positive proof, refute only on positive contradiction, cannot_tell (with a reason) otherwise.

L1: at every cited site, the code tests the named API. "Tests" means the API expression sits in a decision
(comparison, negation, existence/lookup call, a branch/loop/ternary/switch condition, the left of a short
circuit, or a try-body probe), or is a value a decision reads through a binding or a one-line helper. The API is
matched structurally through resolve.canon: module and global APIs by their canonical dotted name; built-in
prototype methods (String.startsWith, Array.includes, RegExp.test) by method name on any receiver; package-local
names only when the call resolves to a single local definition.

L2: the compared value is a constant the code compares against (resolve.const_values of the operand actually
compared with the API), and the operator, read exactly and put in positive form through the control edge the
guard takes, equals the claim (through a small table of idioms: indexOf !== -1 == includes, typeof !== undefined
== exists, /^p/ == startswith, ...).
"""
from __future__ import annotations

import re

from tools.common import anchors
from tools.common.sanitize import defang
from tools.common.tables import ARCH_VALUES, ENV_GETTERS, OS_VALUES, STRIP_METHODS
from tools.common.tsparse import field as child, member_object, static_member_name, static_string, text
from tools.verify import cfg, resolve
from tools.verify.resolve import Regex, Values, ancestors, unwrap
from tools.verify.source import Unanchored

BUILTIN_TYPES = {"String", "Array", "Object", "Number", "Boolean", "RegExp", "JSON", "Math", "Date", "Promise",
                 "Symbol", "Reflect", "Buffer", "Map", "Set"}
POSITIVE = {"==", "in", "includes", "startswith", "regex", "truthy", "exists"}
NEGATIVE = {"!=", "not_in", "falsy", "not_exists", "not_startswith", "not_includes", "not_regex"}
ORDERED = {">", "<", ">=", "<="}
NEGATE = {"==": "!=", "!=": "==", "in": "not_in", "not_in": "in", "truthy": "falsy", "falsy": "truthy",
          ">": "<=", "<": ">=", ">=": "<", "<=": ">", "exists": "not_exists", "not_exists": "exists",
          "startswith": "not_startswith", "not_startswith": "startswith", "includes": "not_includes",
          "not_includes": "includes", "regex": "not_regex", "not_regex": "regex"}
MIRROR = {">": "<", "<": ">", ">=": "<=", "<=": ">=", "==": "==", "!=": "!="}
JS_CMP = {"===": "==", "==": "==", "!==": "!=", "!=": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">="}
PY_CMP = {"==": "==", "!=": "!=", "<>": "!=", "<": "<", ">": ">", "<=": "<=", ">=": ">=", "in": "in",
          "not in": "not_in", "is": "==", "is not": "!="}
NULLISH = {"''", '""', "``", "null", "undefined", "None", "0", "false", "False"}


def result(verdict, reason=None, evidence="", refs=(), grade=None) -> dict:
    return {"verdict": verdict, "grade": grade, "reason_code": reason, "evidence": evidence,
            "evidence_refs": list(refs)}


def combine(verdicts: list[dict]) -> dict:
    """All sites must hold. A refuted site refutes; else the weakest (cannot_tell/unanchored) decides; else
    verified."""
    refs = [r for v in verdicts for r in v["evidence_refs"]][:10]
    for order in ("refuted", "unanchored", "cannot_tell"):
        hit = next((v for v in verdicts if v["verdict"] == order), None)
        if hit:
            return {**hit, "evidence_refs": refs}
    if not verdicts:
        return result("unanchored", "no_anchor")
    return {**verdicts[0], "evidence": f"{len(verdicts)} site(s) test the API", "evidence_refs": refs}


# --- API identity ----------------------------------------------------------------------------------------

def norm_api(api: str) -> tuple:
    """A claim's API as a tuple of segments without call parentheses: os.platform() -> ('os','platform')."""
    api = re.sub(r"\(\)", "", api.strip())
    return tuple(p for p in api.split(".") if p)


_CLEAN_API = re.compile(r"^[\w$]+(?:\.[\w$]+)*$")


def is_prose_api(api: str) -> bool:
    """The api is not a single parseable code name: it is a description, or combines several calls (spaces,
    operators, parentheses with prose). The verifier cannot match such an api, so it holds rather than refutes.
    A merged `a / b` alternatives api is fine when each side is clean."""
    for alt in api.split(" / "):
        if not _CLEAN_API.match(re.sub(r"\(\)", "", alt.strip())):
            return True
    return False


def canon_segments(name: str) -> tuple:
    return tuple(p for p in re.sub(r"\(\)", "", name).split(".") if p)


def api_bearing(node) -> list:
    from tools.verify import checks
    checks.spend()
    """Sub-expressions of a decision that may carry the tested API: the node, the operands of a comparison, the
    operands of a short circuit, the operand of a negation/typeof, the receiver and the call for a method call,
    through parentheses and awaits and value-preserving string methods (.toLowerCase())."""
    node = unwrap(node)
    if node is None:
        return []
    out = [node]
    t = node.type
    if t in ("binary_expression", "comparison_operator"):
        for f in ("left", "right"):
            c = node.child_by_field_name(f)
            if c is not None:
                out += api_bearing(c)
        if t == "comparison_operator":
            for c in node.named_children:
                out += api_bearing(c)
    elif t in ("boolean_operator",):
        for f in ("left", "right"):
            c = node.child_by_field_name(f)
            if c is not None:
                out += api_bearing(c)
    elif t in ("unary_expression", "not_operator"):
        arg = node.child_by_field_name("argument") or (node.named_children[-1] if node.named_children else None)
        if arg is not None:
            out += api_bearing(arg)
    elif t in ("call_expression", "call"):
        fn = node.child_by_field_name("function")
        recv = member_object(fn) if fn is not None else None
        if recv is not None and static_member_name(fn) in STRIP_METHODS:
            out += api_bearing(recv)  # x.trim().startsWith -> x
        elif recv is not None:
            out.append(recv)
    elif t in ("member_expression", "attribute", "subscript_expression", "subscript"):
        obj = member_object(node)
        if obj is not None and static_member_name(obj) in STRIP_METHODS:
            out += api_bearing(member_object(obj))
    return out


def method_calls(node) -> list:
    """Every call in the api-bearing sub-expressions, for built-in method-name matching."""
    return [n for n in api_bearing(node) if n.type in ("call_expression", "call")]


# Modules whose functions are the platform's own: a call into one of them cannot hide a read of another API in
# package code. Anything else (package files, third-party libraries, unresolved names) may.
NODE_CORE = {"os", "fs", "path", "child_process", "process", "util", "crypto", "net", "http", "https", "dns", "tls",
             "url", "zlib", "stream", "events", "buffer", "readline", "assert", "vm", "worker_threads", "cluster",
             "dgram", "querystring", "string_decoder", "timers", "tty", "v8", "perf_hooks", "module", "constants",
             "fs/promises", "node:fs", "node:os", "node:child_process", "node:path"}
PY_STDLIB = {"os", "sys", "platform", "subprocess", "socket", "shutil", "getpass", "pathlib", "re", "json", "base64",
             "time", "datetime", "locale", "ctypes", "winreg", "_winreg", "pwd", "grp", "glob", "tempfile", "uuid",
             "hashlib", "urllib", "http", "ssl", "zlib", "io", "codecs", "string", "random", "struct", "binascii",
             "importlib", "pkgutil", "site", "sysconfig", "distutils", "setuptools", "typing", "collections",
             "itertools", "functools", "operator", "math", "stat", "signal", "threading", "multiprocessing", "zipfile",
             "tarfile", "gzip", "logging", "textwrap", "inspect", "types", "copy", "errno", "fnmatch", "posixpath",
             "ntpath", "getopt", "argparse", "shlex", "configparser", "email", "smtplib", "ftplib", "telnetlib",
             "builtins", "warnings", "traceback", "atexit", "contextlib", "enum", "abc", "dataclasses", "secrets",
             "hmac", "mimetypes", "webbrowser", "uu", "marshal", "pickle", "sqlite3", "csv", "xml", "html"}


def _platform_name(ctx, name: str) -> bool:
    """A canonical name that belongs to the platform (a core module or a language global), not to package code."""
    if name.startswith(("lit:",)):
        return True
    if name.startswith(("fn:", "unit:", ".", "/")):
        return False
    bare = name.split(":", 1)[1] if name.startswith(("inst:", "new:")) else name
    head = bare.split(".")[0].split("(")[0]
    core = NODE_CORE if ctx.lang == "js" else PY_STDLIB
    return head in core or head in resolve.KNOWN_GLOBALS.get(ctx.lang, set()) or head in BUILTIN_TYPES


def _runs_package_code(ctx, node) -> bool:
    """The expression is, or holds the result of, a call whose callee may be package or library code (or does not
    resolve): that code may read any API, so its absence at the site proves nothing."""
    c = resolve.canon(ctx, node)
    if node.type in ("call_expression", "call", "new_expression"):
        return not c.complete or not c.names or not all(_platform_name(ctx, n) for n in c.names)
    return any("(" in n and not _platform_name(ctx, n) for n in c.names)


def api_matches(ctx, node, api: str) -> tuple[bool, bool, str | None]:
    """(matched, complete, gap): does the decision at `node` test the claimed API? The whole test expression is
    searched, so an API passed into a call inside the test (`list.includes(os.platform())`) is found. complete says
    whether absence would be a contradiction: it is false when any name in the test is unresolved, or the test runs
    (directly or through a variable holding a call's result) code that is not the platform's own."""
    want = norm_api(api)
    if not want:
        return False, True, None
    sub = _descend(node)
    calls = [n for n in sub if n.type in ("call_expression", "call", "new_expression")]
    leaves = ("identifier", "member_expression", "subscript_expression", "attribute", "subscript",
              "call_expression", "call", "new_expression")
    # built-in prototype method: match the method name on any call in the test
    if want[0] in BUILTIN_TYPES and len(want) >= 2:
        meth = want[-1].lower()
        for cexpr in calls:
            fn = cexpr.child_by_field_name("function") or cexpr.child_by_field_name("constructor")
            if fn is not None and (static_member_name(fn) or "").lower() == meth:
                return True, True, None
        for cexpr in calls:
            fn = cexpr.child_by_field_name("function") or cexpr.child_by_field_name("constructor")
            if fn is None or (static_member_name(fn) is None and fn.type != "identifier"):
                return False, False, "dynamic_dispatch"  # a computed method name could be this one
            recv = member_object(fn)
            if fn.type == "identifier" or (recv is not None and _runs_package_code(ctx, recv)) or \
                    (recv is not None and recv.type == "identifier" and
                     not all(_platform_name(ctx, n) for n in resolve.canon(ctx, recv).names)):
                return False, False, "witness_gap"  # a helper or library method: its body may call the method
        if any(d.type in leaves[:5] and _runs_package_code(ctx, d) for d in sub):
            return False, False, "witness_gap"
        return False, True, None
    complete = True
    gap = None
    local_method = False  # the method name was seen, but its class/receiver did not resolve (interpretive)
    pkg_local = want[0] not in resolve.KNOWN_GLOBALS.get(ctx.lang, set())
    seen = set()
    bearers = [b for b in api_bearing(node) + [d for d in sub if d.type in leaves]
               if not ((b.start_byte, b.end_byte, b.type) in seen or seen.add((b.start_byte, b.end_byte, b.type)))]
    for b in bearers:
        c = resolve.canon(ctx, b)
        for name in c.names:
            if name.startswith(("lit:", "fn:", "unit:")):
                continue
            segs = canon_segments(name.split(":", 1)[1] if name.startswith(("inst:", "new:")) else name)
            if segs == want:
                return True, True, None
            if pkg_local and len(want) >= 2 and segs[-len(want):] == want and not name.startswith("unit:"):
                return True, True, None
            if pkg_local and len(want) >= 2 and segs and segs[-1] == want[-1]:
                local_method = True  # the method matches; the class is the analyst's interpretation
        if b.type in leaves and not c.complete:
            complete = False
            gap = gap or c.gap
        if b.type in leaves and _runs_package_code(ctx, b):
            complete, gap = False, gap or "witness_gap"  # package or library code runs in (or feeds) the test
    if pkg_local and len(want) >= 2:
        meth = want[-1]
        for cexpr in calls:
            fn = cexpr.child_by_field_name("function")
            if fn is not None and static_member_name(fn) == meth:
                local_method = True
    if local_method:
        return False, False, "unresolved_binding"
    return False, complete, gap


# --- decision position -----------------------------------------------------------------------------------

def logical(node) -> bool:
    if node.type == "boolean_operator":
        return True
    op = node.child_by_field_name("operator") if node.type == "binary_expression" else None
    return op is not None and op.type in ("&&", "||", "??")


def in_test_position(node) -> tuple[bool, object | None]:
    """(is the node in a decision position, the decision node). Walks up through parentheses, negations, short
    circuits to a branch/loop/ternary/switch condition, a short-circuit statement, or a try-body probe."""
    from tools.verify import checks
    child_node, through_logical = node, False
    for anc in ancestors(node):
        checks.spend()
        t = anc.type
        if t in ("parenthesized_expression", "not_operator") or (
                t == "unary_expression" and (anc.child_by_field_name("operator") is not None and
                                             anc.child_by_field_name("operator").type == "!")):
            child_node = anc
            continue
        if logical(anc):
            through_logical, child_node = True, anc
            continue
        if t in ("if_statement", "while_statement", "do_statement", "elif_clause", "for_statement"):
            cond = anc.child_by_field_name("condition")
            return (_same(cond, child_node), anc)
        if t in ("ternary_expression",):
            return (_same(anc.child_by_field_name("condition"), child_node), anc)
        if t == "conditional_expression":  # python a if cond else b
            return (len(anc.named_children) > 1 and _same(anc.named_children[1], child_node), anc)
        if t in ("switch_statement",):
            return (_same(anc.child_by_field_name("value"), child_node), anc)
        if t in ("switch_case", "case_clause", "match_statement", "assert_statement"):
            return True, anc
        if t == "expression_statement" and through_logical:
            return True, child_node if child_node.type in ("binary_expression", "boolean_operator") else anc
        if t.endswith("_statement") or t in ("variable_declarator", "assignment", "pair"):
            # a statement that is the body of a try block is a probe: whether it throws decides the branch
            body = anc.parent
            if body is not None and body.type in ("statement_block", "block") and body.parent is not None and \
                    body.parent.type == "try_statement" and _same(body.parent.child_by_field_name("body"), body):
                return True, body.parent
            return False, None
        child_node = anc
    return False, None


def _same(a, b) -> bool:
    return a is not None and b is not None and (a.start_byte, a.end_byte) == (b.start_byte, b.end_byte)


def reaches_decision(ctx, site_node) -> tuple[bool, bool, str | None]:
    """A value at `site_node` is read by a decision through its binding or a one-line helper. (reached, complete,
    gap). Not reaching a decision is complete (a contradiction) only when the value is provably dropped: the
    site is a whole expression statement. A value stored, returned, passed on or exported may be tested where the
    checker does not look."""
    if ctx.index is None:
        return False, False, "lang_unsupported"
    # the name this site binds, if it is an initialiser or assignment value
    binding = _binding_for_value(ctx, site_node)
    if binding is not None:
        for ref in binding.refs:
            ok, _ = in_test_position(ref)
            if ok:
                return True, True, None
        return False, False, binding.gap or "unresolved_binding"
    # the value is the return of a one-line helper whose result a decision reads
    fn = _returning_function(site_node)
    if fn is not None and ctx.index is not None:
        nbind = _function_binding(ctx, fn)
        if nbind is not None:
            for ref in nbind.refs:
                ok, _ = in_test_position(_call_of(ref))
                if ok:
                    return True, True, None
        return False, False, "unresolved_binding"
    par = site_node.parent
    if par is not None and (
            (par.type in ("assignment_expression", "assignment", "augmented_assignment_expression",
                          "augmented_assignment") and _same(par.child_by_field_name("left"), site_node)) or
            (par.type == "variable_declarator" and _same(par.child_by_field_name("name"), site_node))):
        return False, True, None  # the site is written to, not read
    stmt = site_node.parent
    while stmt is not None and stmt.type == "parenthesized_expression":
        stmt = stmt.parent
    if stmt is not None and stmt.type == "expression_statement" and not any(
            a.type in resolve.FUNCTIONS for a in ancestors(site_node)):
        return False, True, None  # the value is computed and dropped
    return False, False, "witness_gap"


def _function_binding(ctx, fn):
    """The binding a function is reachable by: its own name, or the variable it is assigned to (an arrow or a
    function expression bound to `const isLinux = () => ...`)."""
    name = fn.child_by_field_name("name")
    if name is not None and ctx.index is not None:
        b = ctx.index.binding_of(name)
        if b is not None:
            return b
    p = fn.parent
    while p is not None and p.type in ("parenthesized_expression",):
        p = p.parent
    if p is not None and p.type == "variable_declarator":
        vn = p.child_by_field_name("name")
        if vn is not None and vn.type == "identifier":
            return ctx.index.binding_of(vn)
    if p is not None and p.type in ("assignment_expression", "assignment"):
        left = p.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            return ctx.index.binding_of(left)
    return None


def _binding_for_value(ctx, node):
    """The binding whose declared/assigned value expression contains `node` (the value may negate or wrap the
    site; for L1 that does not matter, the value still flows into whatever reads the variable)."""
    for anc in ancestors(node):
        if anc.type == "variable_declarator":
            val = anc.child_by_field_name("value")
            name = anc.child_by_field_name("name")
            if val is not None and anchors_contains(val, node) and name is not None and name.type == "identifier":
                return ctx.index.binding_of(name)
            return None
        if anc.type in ("assignment_expression", "assignment"):
            val = anc.child_by_field_name("right")
            left = anc.child_by_field_name("left")
            if val is not None and anchors_contains(val, node) and left is not None and left.type == "identifier":
                return ctx.index.binding_of(left)
            return None
        if anc.type in resolve.FUNCTIONS or anc.type.endswith("_statement") and anc.type != "expression_statement":
            return None
    return None


def anchors_contains(outer, inner) -> bool:
    return outer.start_byte <= inner.start_byte and inner.end_byte <= outer.end_byte


def _call_of(ref):
    """The call expression whose callee is `ref` (an identifier), or `ref` itself."""
    p = ref.parent
    if p is not None and p.type in ("call_expression", "call") and _same(p.child_by_field_name("function"), ref):
        return p
    return ref


def _returning_function(ref):
    from tools.common.tsparse import pure_alias
    for anc in ancestors(ref):
        if anc.type in resolve.FUNCTIONS:
            body = anc.child_by_field_name("body")
            if body is not None and body.type in ("statement_block", "block"):
                # obfuscators prepend alias-only declarations (`const _a = _b;`); they do not stop a helper
                # reading as one-line
                stmts = [c for c in body.named_children if c.type not in ("comment",) and not pure_alias(c)]
                if len(stmts) == 1 and stmts[0].type == "return_statement":
                    return anc
            elif body is not None:  # arrow with expression body
                return anc
            return None
    return None


# --- L1 --------------------------------------------------------------------------------------------------

def check_l1(pkg, cond: dict) -> dict:
    api = cond["api"]
    verdicts = []
    for site in cond["sites"]:
        a = site["anchor"]
        verdicts.append(_l1_site(pkg, cond, a, api))
    return combine(verdicts)


def _l1_site(pkg, cond, a, api) -> dict:
    ref = [anchors.short(a)]
    try:
        node, src, lang = pkg.node(a)
    except Unanchored as e:
        return result("unanchored", e.reason, e.detail, ref)
    if node is None and lang is None and a["node_type"] not in (anchors.TEXT, anchors.RANGE):
        return result("cannot_tell", "lang_unsupported", "the cited file's language is not parsed", ref)
    if node is None:
        if a["node_type"] == anchors.TEXT:
            return _l1_text(cond, a, src, api, ref)
        return result("cannot_tell", "witness_gap", "the cited site is a statement range, not a test node", ref)
    ctx = resolve.ctx_for(pkg, a)
    if cond.get("probe"):
        return _l1_probe(ctx, node, cond["probe"], a, ref)
    if is_prose_api(api):
        return result("cannot_tell", "other", "the API is a description or combines several calls, not a single "
                      "code name, so it cannot be matched here", ref)
    is_test, decision = in_test_position(node)
    reached, reach_complete, reach_gap = (False, True, None)
    if not is_test:
        reached, reach_complete, reach_gap = reaches_decision(ctx, node)
    if not is_test and not reached:
        if not reach_complete:
            return result("cannot_tell", reach_gap or "unresolved_binding",
                          "cannot tell whether a decision reads this value", ref)
        return result("refuted", "not_a_test", f"{node.type} is neither a test nor read by one", ref)
    matched, complete, gap = api_matches(ctx, node, api)
    if matched:
        return result("verified", None, f"the test uses {api}", ref)
    if _encoded_hold(cond, a, node):
        return result("cannot_tell", "encoded_unchecked", "the condition was recovered by decoding or a name here "
                      "is computed by a call, so the API cannot be read at this site", ref)
    if not complete:
        return result("cannot_tell", gap or "unresolved_binding",
                      f"the API at this site could not be fully resolved, so {api} is neither shown nor ruled out",
                      ref)
    return result("refuted", "api_mismatch", f"the test does not use {api}", ref)


def _encoded_hold(cond, a, node) -> bool:
    """The site cannot be read because the condition was decoded by hand but this site still sits on the encoded
    bytes (no derivation), or a name at the site is computed by a call (a string-table or cipher lookup). Absence
    of the API text at such a site is not a contradiction."""
    if cond.get("value_recovered") in ("decoded", "partial") and not a.get("derived_from"):
        return True
    return _opaque(node)


def _opaque(node) -> bool:
    for d in _descend(node):
        if d.type in ("subscript_expression", "subscript"):
            idx = d.child_by_field_name("index") or d.child_by_field_name("subscript")
            if idx is not None and idx.type in ("call_expression", "call"):
                return True
    return False


def _l1_text(cond, a, src, api, ref) -> dict:
    body = src[a["start_byte"]:a["end_byte"]].decode("utf-8", "replace")
    if api.startswith("package.json#"):
        key = api.split("#", 1)[1]
        ok = f'"{key}"' in body
    else:
        want = norm_api(api)
        if not want:
            return result("cannot_tell", "other", "API is described in prose", ref)
        # a shell reads an environment variable as $NAME / ${NAME} / %NAME%; a dotted API appears whole
        names = {".".join(want), want[-1]} if want[:2] in (("process", "env"), ("os", "environ")) or \
            len(want) == 1 else {".".join(want)}
        tokens = {t.strip("${}%") for t in re.findall(r"[$%]?\{?[A-Za-z_][\w.]*\}?%?", body)}
        ok = bool(names & tokens)
        if not ok:
            if want[-1].lower() in body.lower() or _shell_encoded(body):
                return result("cannot_tell", "witness_gap", "the hook command may name the API in another form",
                              ref)
            return result("refuted", "api_mismatch", "the API is not in the hook command", ref)
    return result("verified", None, "the hook command names the API", ref) if ok else \
        result("refuted", "api_mismatch", "the manifest field is not at the cited site", ref)


def _shell_encoded(body: str) -> bool:
    """The command decodes or evaluates text, so what it tests is not visible in it."""
    return bool(re.search(r"base64|\beval\b|\\x[0-9a-fA-F]{2}|\$\(|`|\bnode\s+-e\b|python[0-9.]*\s+-c\b", body))


def _l1_probe(ctx, node, probe, a, ref) -> dict:
    calls, named, computed = _probe_calls(ctx, node, probe["callee"])
    if not calls:
        if named or computed:
            return result("cannot_tell", "dynamic_dispatch", f"a call that may be {probe['callee']} is reached from "
                          "the test, but its callee does not resolve", ref)
        return result("cannot_tell", "witness_gap", f"no resolved call of {probe['callee']} reached from the test",
                      ref)
    if probe.get("target") is None:
        return result("verified", None, f"the test reaches {probe['callee']}", ref)
    if _redacted(probe["target"]):
        return result("cannot_tell", "value_redacted", f"the test reaches {probe['callee']}, but the record redacted "
                      "part of the probe's target, so it cannot be compared with the code", ref)
    want = _norm_command(probe["target"])
    targets = [_probe_target(ctx, c) for c in calls]
    if any(t is not None and (_norm_command(t) == want or (probe.get("kind") == "file" and _path_hit(probe["target"],
                                                                                                      t)))
           for t in targets):
        return result("verified", None, f"the test runs {probe['callee']} on the claimed target", ref)
    if any(t is None for t in targets) or named or computed:
        return result("cannot_tell", "value_unchecked", "a probe's command is not given literally, or another call "
                      "may be the probe", ref)
    return result("refuted", "api_mismatch", f"{probe['callee']} runs {defang(str(targets[0]))[:60]}", ref)


def _probe_roots(ctx, node) -> list:
    """The test node, the values its identifiers are bound to, and the calls its callback parameters come from, so
    a probe reached through a variable (`const out = exec(...); if (out)`) or a callback (`exec(c,(err)=>...)`) is
    found."""
    roots = api_bearing(node) + _helper_bodies(ctx, node)
    if ctx.index is None:
        return roots
    for ident in [d for d in _descend(node) if d.type == "identifier"]:
        r = ctx.index.lookup(ident)
        for v in r.values:
            if v and v[0] == "node":
                roots.append(v[1])
        b = r.binding
        if b is not None and b.kind in ("param", "catch"):
            cs = _callback_source(b)
            if cs is not None:
                roots.append(cs)
    return roots


def _callback_source(binding):
    """The call a callback parameter receives its value from: in `exec(cmd,(err,out)=>{})` err and out come from
    the exec call."""
    decl = binding.decl
    for anc in ancestors(decl) if decl is not None else []:
        if anc.type in resolve.FUNCTIONS:
            args = anc.parent
            call = args.parent if args is not None and args.type in ("arguments", "argument_list") else None
            return call if call is not None and call.type in ("call_expression", "call") else None
    return None


def _probe_calls(ctx, node, callee: str):
    """(calls, named, computed) reached from the test: calls whose resolved callee is the probe's callee; calls
    that only share its last name (`/re/.exec(s)` is not child_process.exec) but do not resolve, so they may be it;
    and whether some callee is computed."""
    want = norm_api(callee)
    tail = want[-1] if want else ""
    out, named, computed = [], 0, False
    seen = set()
    for r in _probe_roots(ctx, node):
        for d in _descend(r):
            if d.type not in ("call_expression", "call") or (d.start_byte, d.end_byte) in seen:
                continue
            seen.add((d.start_byte, d.end_byte))
            fn = d.child_by_field_name("function")
            if fn is None:
                continue
            name = static_member_name(fn) or (text(fn) if fn.type == "identifier" else None)
            if name is None and fn.type not in ("identifier",):
                computed = True
                continue
            if name != tail and fn.type != "template_string":
                continue
            c = resolve.canon(ctx, fn)
            segs = [canon_segments(n.split(":", 1)[1] if n.startswith(("inst:", "new:")) else n) for n in c.names
                    if not n.startswith(("lit:", "fn:", "unit:"))]
            low = tuple(x.lower() for x in want)
            if any(tuple(x.lower() for x in sg[-len(want):]) == low for sg in segs if len(sg) >= len(want)):
                out.append(d)
            elif not c.complete:
                named += 1
    return out, named, computed


def _helper_bodies(ctx, node):
    """Bodies of one-line/arrow helpers whose result the test reads, so a probe inside them is reachable."""
    out = []
    for cexpr in [n for n in _descend(node) if n.type in ("call_expression", "call")]:
        fn = cexpr.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and ctx.index is not None:
            r = ctx.index.lookup(fn)
            for v in r.values:
                if v[0] == "fn":
                    out.append(v[1])
    return out


def _descend(node):
    from tools.verify.checks import _descendants
    return list(_descendants(node))


def _probe_target(ctx, call):
    args = call.child_by_field_name("arguments")
    if args is not None and args.type in ("template_string", "template_literal"):
        return _command_values(ctx, args)
    argv = [a for a in (args.named_children if args is not None else []) if a.type != "comment"]
    if not argv:
        return None
    first = _command_values(ctx, argv[0])
    if first is not None and len(argv) > 1 and argv[1].type in ("array", "list"):
        rest = _command_values(ctx, argv[1])
        return f"{first} {rest}" if rest is not None else None
    return first


def _command_values(ctx, node):
    vals = resolve.const_values(ctx, node)
    if vals.values and all(isinstance(v, str) for v in vals.values):
        return vals.values[0]
    if vals.values and isinstance(vals.values[0], tuple):  # argv array
        return " ".join(str(x) for x in vals.values[0])
    # template with a substitution: render substitutions as *
    if node.type in ("template_string", "template_literal"):
        out = []
        for c in node.children:
            if c.type in ("template_substitution",):
                out.append("*")
            elif c.type in ("string_fragment", "escape_sequence"):
                out.append(text(c))
        return "".join(out)
    return None


def _norm_command(cmd: str) -> str:
    return defang(re.sub(r"\s+", " ", cmd).strip())


def _path_hit(claimed: str, got: str) -> bool:
    parts = [p for p in re.split(r"[\\/~]+", claimed) if p and p not in (".", "$HOME", "%USERPROFILE%")]
    return bool(parts) and all(p in got for p in parts)


# --- L2 --------------------------------------------------------------------------------------------------

def check_l2(pkg, rec: dict, cond: dict) -> dict:
    if cond["value_recovered"] == "partial":
        return result("cannot_tell", "value_unchecked", "value only partly recovered")
    if cond["value_recovered"] == "decoded" and not all(s["anchor"]["derived_from"] for s in cond["sites"]):
        return result("cannot_tell", "encoded_unchecked", "value recovered by decoding, but a site is still on the "
                      "encoded bytes (no decode_spec derivation), so it cannot be read")
    if _redacted(cond["value"]):
        return result("cannot_tell", "value_redacted", "the value was redacted in the record (personal data or a "
                      "secret), so it cannot be compared with the code; the API and operator are left to review")
    verdicts, seen = [], set()
    for site in cond["sites"]:
        v = _l2_site(pkg, rec, cond, site["anchor"])
        seen |= v.pop("_seen", set())
        verdicts.append(v)
    out = combine(verdicts)
    claimed = _claimed_set(cond)
    if out["verdict"] == "verified" and claimed is not None and seen != claimed:
        # every site compares against claimed values, but some claimed value is compared at no cited site
        return {**out, "verdict": "cannot_tell", "reason_code": "value_unchecked",
                "evidence": "each site compares against a claimed value, but not every claimed value is compared"}
    return out


REDACTED = re.compile(r"<[^<>]*redacted[^<>]*>|\u2026|…")


def _redacted(value) -> bool:
    vals = value if isinstance(value, list) else [value]
    return any(isinstance(v, str) and REDACTED.search(v) for v in vals)


def _claimed_set(cond):
    """The claimed values as a set of normalised alternatives, or None when the claim has no value or is an ordered
    comparison against one (tuple) value."""
    claimed = cond["value"]
    if claimed is None or cond["operator"] in ORDERED:
        return None
    items = claimed if isinstance(claimed, list) else [claimed]
    return {_hashable(_norm_value(x, cond["category"])) for x in items}


_NUMERIC = re.compile(r"^-?\d+(\.\d+)?$")


def _hashable(v):
    """A set-safe form of a value: lists become tuples, booleans are tagged so True never equals 1, and a number
    written as a string ("4") equals the number (4): how a record writes a value is not a contradiction."""
    if isinstance(v, bool):
        return ("bool", v)
    if isinstance(v, str) and _NUMERIC.match(v.strip()):
        n = float(v)
        return int(n) if n.is_integer() else n
    if isinstance(v, float) and v.is_integer():
        return int(v)
    return tuple(_hashable(x) for x in v) if isinstance(v, (list, tuple)) else v


def _l2_site(pkg, rec, cond, a) -> dict:
    ref = [anchors.short(a)]
    try:
        node, src, lang = pkg.node(a)
    except Unanchored as e:
        return result("unanchored", e.reason, e.detail, ref)
    if node is None and lang is None and a["node_type"] not in (anchors.TEXT, anchors.RANGE):
        return result("cannot_tell", "lang_unsupported", "the cited file's language is not parsed", ref)
    if node is None:
        return _l2_text(cond, a, src, ref)
    ctx = resolve.ctx_for(pkg, a)
    if is_prose_api(cond["api"]):
        return result("cannot_tell", "operator_unchecked", "the API is a description, not a single code name, so "
                      "the compared operand cannot be located here", ref)
    if _opaque(node):
        return result("cannot_tell", "encoded_unchecked", "a name at the test is computed by a call, so the "
                      "operator cannot be read without decoding", ref)
    # value: the constant(s) the API is compared against at this site
    vnode, sure = _value_operand(ctx, node, cond, rec)
    if cond.get("value_site"):
        try:
            vn2, _, _ = pkg.node(cond["value_site"])
            vnode, sure = (vn2, True) if vn2 is not None else (vnode, sure)
        except Unanchored as e:
            return result("unanchored", e.reason, e.detail, [anchors.short(cond["value_site"])])
    status, seen = _value_status(ctx, cond, vnode) if sure or cond["value"] is None else ("unclear", set())
    if status == "mismatch":
        return result("refuted", "value_mismatch",
                      f"{defang(str(cond['value']))[:80]} is not the compared value", ref)
    if status == "unclear":
        return result("cannot_tell", "value_unchecked", "the compared value could not be fully resolved, or it only "
                      "partly overlaps the claimed values", ref)
    # operator, in the gate's positive sense
    op, op_complete, op_gap = _effective_operator(pkg, rec, ctx, cond, node, a)
    if (op is None or not op_complete) and _opaque(node):
        return result("cannot_tell", "encoded_unchecked", "value found; a name at the test is computed by a call, "
                      "so its operator cannot be read without decoding", ref)
    if op is None:
        return result("cannot_tell", op_gap or "operator_unchecked",
                      "value found; the operator could not be read", ref)
    if not op_complete:
        return result("cannot_tell", op_gap or "operator_unchecked",
                      f"value found; cannot confirm the operator is {cond['operator']}", ref)
    if cond["operator"] in ("regex", "not_regex") and status == "match" and _argument_of(vnode) in _AS_REGEX:
        # the claim is exactly the regex this string method's literal stands for (`\.lnk$` for endswith('.lnk'))
        op = {"includes": "regex", "startswith": "regex", "not_includes": "not_regex",
              "not_startswith": "not_regex"}.get(op, op)
    rel = _op_relation(op, cond["operator"])
    if rel == "equal":
        return {**result("verified", None, f"value found; code tests {op} in the gate's sense", ref), "_seen": seen}
    if rel == "contradiction":
        return result("refuted", "operator_mismatch", f"code tests {op} in the gate's sense, claim says "
                      f"{cond['operator']}", ref)
    return result("cannot_tell", "operator_unchecked", f"value found; code tests {op}, claim says "
                  f"{cond['operator']} (same polarity, different operator)", ref)


_POS = POSITIVE
_NEG = NEGATIVE


def _op_relation(code_op: str, claim_op: str) -> str:
    """'equal', 'contradiction' (opposite polarity, so the code cannot satisfy the claim) or 'unclear' (same
    polarity, a different operator: not proof either way). Refute only on a contradiction."""
    if code_op == claim_op:
        return "equal"
    if code_op in ORDERED or claim_op in ORDERED:
        if code_op in ORDERED and claim_op in ORDERED and (code_op[0] != claim_op[0]):
            return "contradiction"  # opposite directions (> vs <); strictness alone is not proof either way
        return "unclear"
    code_pos, claim_pos = code_op in _POS, claim_op in _POS
    code_neg, claim_neg = code_op in _NEG, claim_op in _NEG
    if (code_pos and claim_neg) or (code_neg and claim_pos):
        return "contradiction"
    return "unclear"


def _value_operand(ctx, node, cond, rec=None):
    """(operand, sure): the operand the API is compared with (the non-API side of a comparison, the argument of
    startsWith/includes/indexOf, the regex pattern of .test(), else None for truthy/exists), and whether it was
    located from the code's structure rather than guessed."""
    v = _value_operand_node(ctx, node, dict(cond, _rec=rec))
    if v is _UNSURE:
        return None, False
    return v, True


_UNSURE = object()


def _value_operand_node(ctx, node, cond):
    node = unwrap(node)
    if node is None:
        return None
    t = node.type
    if t in ("binary_expression", "comparison_operator"):
        left = node.child_by_field_name("left") or (node.named_children[0] if node.named_children else None)
        right = node.child_by_field_name("right") or (node.named_children[-1] if node.named_children else None)
        on_left, on_right = _carries_api(ctx, left, cond["api"]), _carries_api(ctx, right, cond["api"])
        if on_left == on_right:
            # the API is on neither side (or both): the value is the one side written as a literal, if exactly
            # one is (`"Access is denied." in out`); anything else would be a guess
            lit = [x for x in (left, right) if _is_literal(x)]
            if len(lit) != 1:
                return _UNSURE
            return lit[0]
        api_side = left if on_left else right
        if unwrap(right if on_left else left) is not None and unwrap(right if on_left else left).type in BOOLEANS:
            # `os.path.exists(p) == False`: the boolean is the test's sense, the value is what the API is given
            return _value_operand_node(ctx, api_side, cond)
        # `x.indexOf('ru') !== -1` / `x.includes('ru')`: the value is the method argument, not the sentinel
        meth = unwrap(api_side)
        if meth is not None and meth.type in ("call_expression", "call"):
            fn = meth.child_by_field_name("function")
            if fn is not None and static_member_name(fn) in ("indexOf", "includes", "startsWith", "search"):
                argv = [c for c in (meth.child_by_field_name("arguments").named_children
                                    if meth.child_by_field_name("arguments") is not None else []) if c.type != "comment"]
                return argv[0] if argv else None
        return right if on_left else left
    if t in ("call_expression", "call"):
        fn = node.child_by_field_name("function")
        name = static_member_name(fn) if fn is not None else None
        args = node.child_by_field_name("arguments")
        argv = [c for c in (args.named_children if args is not None else []) if c.type != "comment"]
        if name in ("startsWith", "endsWith", "includes", "indexOf", "startswith", "endswith", "search", "find"):
            return argv[0] if argv else None
        if name in ("test", "match", "fullmatch"):
            recv = member_object(fn)
            return recv if recv is not None and recv.type == "regex" else (argv[0] if argv and name != "test"
                                                                           else recv)
        # a file/tool existence test or env getter: the value is the path or name argument
        if _carries_api(ctx, node, cond["api"]) and argv:
            return argv[0]
        return None if cond["value"] is None else _UNSURE
    if t in ("unary_expression", "not_operator") and node.named_children:
        return _value_operand_node(ctx, node.named_children[-1], cond)
    if t in ("member_expression", "attribute", "subscript_expression", "subscript", "identifier"):
        # a switch discriminant: the value is the label of the case the gate's guard cites
        sw = _enclosing_switch_discriminant(node)
        if sw is not None:
            return _cited_case_value(sw, cond)  # None when no guard cites a case of this switch
    return None if cond["value"] is None else _UNSURE


def _enclosing_switch_discriminant(node):
    node = unwrap(node)
    for anc in ancestors(node):
        if anc.type == "switch_statement" and _same(unwrap(anc.child_by_field_name("value")), node):
            return anc
        if anc.type.endswith("_statement") or anc.type in ("switch_body",):
            return None
    return None


BOOLEANS = {"true", "false"}
LITERALS = {"string", "template_string", "number", "integer", "float", "true", "false", "none", "null",
            "concatenated_string", "regex"}


def _is_literal(node) -> bool:
    """A constant written in place: a string, number or regex, or a list/tuple/array of them."""
    node = unwrap(node)
    if node is None:
        return False
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.children)
    if node.type == "string":
        return not any(c.type == "interpolation" for c in node.named_children)
    if node.type in LITERALS:
        return True
    if node.type in ("tuple", "list", "array", "parenthesized_expression"):
        kids = [c for c in node.named_children if c.type != "comment"]
        return bool(kids) and all(_is_literal(c) for c in kids)
    return False


def _cited_case_value(sw, cond):
    """The label of the case (of switch `sw`) that a gate guard testing this condition cites; _UNSURE when no guard
    does, or a guard cites the default arm (which compares against every label at once)."""
    rec = cond.get("_rec") or {}
    labels = []
    for g in rec.get("gates", []):
        for guard in g.get("guards") or []:
            if cond["id"] not in guard.get("conditions", []):
                continue
            gs = guard["site"]
            if not (sw.start_byte <= gs["start_byte"] and gs["end_byte"] <= sw.end_byte):
                continue
            if guard.get("kind") != "switch_case":
                return _UNSURE
            case = sw.descendant_for_byte_range(gs["start_byte"], gs["end_byte"])
            while case is not None and case.type not in ("switch_case", "case_clause"):
                case = case.parent
            v = case.child_by_field_name("value") if case is not None else None
            if v is None:
                return _UNSURE
            labels.append(v)
    if len(labels) != 1:
        return _UNSURE
    return labels[0]


def _carries_api(ctx, node, api: str) -> bool:
    if node is None:
        return False
    want = norm_api(api)
    for b in api_bearing(node):
        for name in resolve.canon(ctx, b).names:
            if canon_segments(name) == want or (len(want) >= 2 and canon_segments(name)[-len(want):] == want):
                return True
        if want and want[0] in BUILTIN_TYPES and b.type in ("call_expression", "call"):
            fn = b.child_by_field_name("function")
            if fn is not None and (static_member_name(fn) or "").lower() == want[-1].lower():
                return True
    return False


def _norm_value(v, category: str):
    if isinstance(v, Regex):
        return v
    if isinstance(v, str):
        low = v.lower()
        if category == "os":
            return OS_VALUES.get(low, low)
        if category == "arch":
            return ARCH_VALUES.get(low, low)
        return defang(v)
    return v


def _value_status(ctx, cond, vnode) -> tuple[str, set]:
    """('match' | 'mismatch' | 'unclear', the claimed values this site compares against).

    match: every value the site compares against is a claimed value (for an ordered comparison, the one tuple
    equals the claim). mismatch: the site's values are fully known and none of them is claimed (or the ordered
    tuple differs). Anything else (unresolved values, a regex, values that only partly overlap) is unclear."""
    claimed, cat = cond["value"], cond["category"]
    if claimed is None:
        return "match", set()
    if vnode is None:
        return "unclear", set()
    vals = resolve.const_values(ctx, vnode)
    if not vals.values:
        return "unclear", set()
    if any(isinstance(v, Regex) for v in vals.values):
        return _regex_status(vals, claimed, cat)
    if cond["operator"] in ("regex", "not_regex"):
        return _literal_as_regex(vals, claimed, cat, _argument_of(vnode))
    if cond["operator"] in ORDERED:
        want = _hashable(claimed if isinstance(claimed, list) else [claimed])
        got = {_hashable(v if isinstance(v, (list, tuple)) else (v,)) for v in vals.values}
        if want in got and len(got) == 1 and vals.complete:
            return "match", set()
        return ("mismatch" if vals.complete and want not in got else "unclear"), set()
    want = _claimed_set(cond) or set()
    site = set()
    for v in vals.values:
        items = v if isinstance(v, (list, tuple)) else (v,)
        site |= {_hashable(_norm_value(x, cat)) for x in items}
    site_l = {x.lower() if isinstance(x, str) else x for x in site}
    want_l = {x.lower() if isinstance(x, str) else x for x in want}
    if site_l <= want_l:
        if not vals.complete:
            return "unclear", set()  # the site may also compare against a value not seen here
        return "match", {w for w in want if (w.lower() if isinstance(w, str) else w) in site_l}
    if site_l & want_l:
        return "unclear", set()
    if cat in PATH_CATEGORIES and _path_overlap(want, site):
        return "unclear", set()  # a claimed path assembled from pieces the code joins: not a contradiction
    return ("mismatch" if vals.complete else "unclear"), set()


PATH_CATEGORIES = {"file_or_dir_exists", "target_artifact", "home_or_path", "vm_sandbox_artifact", "file_content"}


def _path_overlap(want, site) -> bool:
    """Some claimed path shares a non-trivial component with some code string."""
    def parts(x):
        return {p for p in re.split(r"[\\/~]+", str(x)) if p and p not in (".", "$HOME", "%USERPROFILE%")}
    return any(parts(w) & parts(s) for w in want for s in site)


def _regex_status(vals, claimed, cat) -> tuple[str, set]:
    """A regex literal: the claim matches when it is the pattern itself (anchors aside) or exactly its top-level
    alternatives, as a value set would have to be. A regex never contradicts a claim: what it accepts is not
    read here."""
    items = claimed if isinstance(claimed, list) else [claimed]
    pats = [v.pattern for v in vals.values if isinstance(v, Regex)]
    if not vals.complete or len(pats) != 1 or not all(isinstance(c, str) for c in items):
        return "unclear", set()
    pat = pats[0]
    core = pat.strip("^$")
    if core.startswith("(") and core.endswith(")") and core.count("(") == 1:
        core = core[1:-1]
    whole = {pat, pat.strip("^$")}
    if set(items) <= whole and len(items) == 1 or set(items) == set(core.split("|")):
        return "match", {_hashable(_norm_value(c, cat)) for c in items}
    return "unclear", set()


def _argument_of(vnode) -> str | None:
    """The method a literal is the first argument of (`f.endswith('.lnk')` -> 'endswith'), else None."""
    v = unwrap(vnode)
    if v is None or v.parent is None or v.parent.type not in ("arguments", "argument_list"):
        return None
    call = v.parent.parent
    fn = call.child_by_field_name("function") if call is not None else None
    return static_member_name(fn) if fn is not None else None


# the regex a literal argument of each string method stands for, as the record writes it (the operator list has
# no endswith, so `s.endswith('.lnk')` is recorded as regex `\.lnk$`)
_AS_REGEX = {"endswith": "{}$", "endsWith": "{}$", "startswith": "^{}", "startsWith": "^{}", "includes": "{}",
             "indexOf": "{}", "search": "{}", "find": "{}"}


def _literal_as_regex(vals, claimed, cat, method) -> tuple[str, set]:
    """A regex claim against a literal: it matches when the claim is exactly that method's pattern for the literal.
    Any other pattern is unclear, never a mismatch: what a regex accepts is not compared here."""
    if not isinstance(claimed, str) or method not in _AS_REGEX or not vals.complete or len(vals.values) != 1:
        return "unclear", set()
    (lit,) = vals.values
    if not isinstance(lit, str) or claimed != _AS_REGEX[method].format(re.escape(lit)):
        return "unclear", set()
    return "match", {_hashable(_norm_value(claimed, cat))}


# --- operator & polarity ----------------------------------------------------------------------------------

def _code_operator(ctx, node, cond) -> tuple[str | None, bool]:
    """The operator the node tests in its own sense (before polarity), and whether it was fully read."""
    node = unwrap(node)
    if node is None:
        return None, True
    t = node.type
    if t in ("binary_expression", "comparison_operator"):
        if cond["operator"] in ("exists", "not_exists"):
            sent = _sentinel_operator(node, (cond.get("probe") or {}).get("accessor"))
            if sent is not None:
                return sent, True
        return _compare_operator(ctx, node, cond)
    if t in ("call_expression", "call"):
        fn = node.child_by_field_name("function")
        if fn is not None and static_member_name(fn) is None and fn.type not in ("identifier",):
            return None, False  # computed method name
        name = static_member_name(fn) if fn is not None else None
        if name in ("includes", "has"):
            return "includes", True
        if name == "indexOf":
            return "indexof", True  # only meaningful with a sentinel comparison; bare call is truthy-ish
        if name in ("startsWith", "startswith"):
            return "startswith", True
        if name in ("endsWith", "endswith", "search"):
            return "includes", True
        if name in ("test", "match", "fullmatch"):
            return "regex", True
        return _call_operator(ctx, node, fn, name, cond)
    if t in ("unary_expression", "not_operator") and node.named_children:
        base, complete = _code_operator(ctx, node.named_children[-1], cond)
        if base is None:
            return None, complete
        return NEGATE.get(base, "other"), complete
    if t in ("member_expression", "attribute", "subscript_expression", "subscript", "identifier"):
        return "truthy", True
    return None, False  # any other shape (an await, a template, an assignment) is not read as a test here


EXISTENCE_CALLS = {"existsSync", "exists", "lexists", "isfile", "isdir", "islink", "access", "accessSync",
                   "statSync", "lstatSync", "which", "find_executable", "commandExistsSync", "has", "hasOwnProperty",
                   "__contains__", "find_spec"}


def _call_operator(ctx, node, fn, name, cond) -> tuple[str | None, bool]:
    """A bare call used as a test: an existence check reads as exists, an environment getter or the claimed API
    itself as truthy. Any other call is a predicate whose meaning is not read here."""
    if name in EXISTENCE_CALLS:
        return "exists", True
    canon = resolve.canon(ctx, node)
    names = {re.sub(r"\(\)$", "", n) for n in canon.names}
    if names & {g for g in ENV_GETTERS} or name == "getenv":
        return "truthy", True
    if canon_segments(cond["api"]) and any(canon_segments(n) == norm_api(cond["api"]) for n in names):
        return "truthy", True
    return None, False


def _compare_operator(ctx, node, cond) -> tuple[str | None, bool]:
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator").type
        if op == "in":
            return "exists", True
        if op not in JS_CMP:
            return None, True
        cmp = JS_CMP[op]
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
    else:  # comparison_operator (python)
        ops = [c.type for c in node.children if not c.is_named]
        if len(ops) != 1 or ("".join(ops) if False else ops[0]) not in PY_CMP:
            # python "not in" / "is not" are two tokens
            joined = " ".join(ops)
            if joined not in PY_CMP:
                return None, True
            cmp = PY_CMP[joined]
        else:
            cmp = PY_CMP[ops[0]]
        sides = node.named_children
        left, right = (sides[0], sides[-1]) if len(sides) >= 2 else (None, None)
        if cmp in ("in", "not_in"):
            # x in y: membership; if the API is the right (container) it's "includes", if left it's "in"
            on_left, on_right = _carries_api(ctx, left, cond["api"]), _carries_api(ctx, right, cond["api"])
            if on_left == on_right:
                return None, False  # which side holds the API is a guess
            return ("includes" if cmp == "in" else "not_includes") if on_right else cmp, True
    # indexOf(x) !== -1 style: handled by sentinel below, here plain compares
    if _is_index_of(left) or _is_index_of(right):
        return _indexof_operator(cmp, left, right), True
    if cmp in ("==", "!="):
        return cmp, True
    # ordered comparison: mirror so the operator reads from the API's side, which must be known
    on_left, on_right = _carries_api(ctx, left, cond["api"]), _carries_api(ctx, right, cond["api"])
    if on_left == on_right:
        return None, False
    return (cmp if on_left else MIRROR.get(cmp, cmp)), True


def _is_index_of(node) -> bool:
    node = unwrap(node)
    if node is None or node.type not in ("call_expression", "call"):
        return False
    fn = node.child_by_field_name("function")
    return fn is not None and static_member_name(fn) in ("indexOf", "search", "find")


def _indexof_operator(cmp, left, right) -> str | None:
    lit = None
    for side in (left, right):
        s = unwrap(side)
        if s is not None and s.type in ("number", "unary_expression"):
            lit = text(s).replace(" ", "")
    if lit == "-1":
        return "not_includes" if cmp == "==" else ("includes" if cmp == "!=" else None)
    if lit in ("0",):
        return "includes" if cmp in (">=",) else ("not_includes" if cmp == "<" else None)
    return None


def _sentinel_operator(node, accessor):
    if node.type == "binary_expression":
        op = node.child_by_field_name("operator").type
        sides = [node.child_by_field_name("left"), node.child_by_field_name("right")]
        cmp = JS_CMP.get(op)
    elif node.type == "comparison_operator":
        ops = [c.type for c in node.children if not c.is_named]
        sides = node.named_children[:2]
        cmp = PY_CMP.get(" ".join(ops)) if ops else None
    else:
        return None
    if cmp not in ("==", "!=") or len(sides) != 2 or None in sides:
        return None
    lit = None
    other = None
    for side in sides:
        raw = text(side).strip()
        sval = static_string(side)
        if raw in NULLISH or sval in ("undefined", "null", "None"):
            lit = sval if sval in ("undefined", "null", "None") else raw.strip("'\"`")
        else:
            other = side
    if lit is None:
        return None
    if _is_index_of(other):
        return _indexof_operator(cmp, sides[0], sides[1])
    success_on_equal = lit == "0" and accessor in ("returncode", None)
    equal = cmp == "=="
    return "exists" if equal == success_on_equal else "not_exists"


def _effective_operator(pkg, rec, ctx, cond, node, a) -> tuple[str | None, bool, str | None]:
    """The operator in the gate's positive sense: the code's own operator, flipped by negations between the site
    and the guard decision (through the binding chain) and by the else arm the guard takes, read from the CFG."""
    sw = _enclosing_switch_discriminant(node)
    if sw is not None:
        kinds = {guard.get("kind") for g in rec.get("gates", []) for guard in g.get("guards") or []
                 if cond["id"] in guard.get("conditions", []) and anchors.contains(
                     {"file": a["file"], "derived_from": a["derived_from"], "start_byte": sw.start_byte,
                      "end_byte": sw.end_byte}, guard["site"])}
        if kinds == {"switch_case"}:
            return "==", True, None  # the discriminant equals the cited case's label on that branch
        return None, False, "operator_unchecked"  # a default arm (or mixed arms) is not read here
    base, complete = _code_operator(ctx, node, cond)
    guards, gap = _governing_guards(pkg, rec, ctx, cond, node, a)
    if not guards:
        return None, False, gap or "operator_unchecked"
    if node.type in ("call_expression", "call") and all(g.get("kind") == "try_except" for g in guards):
        base, complete = "exists", True  # a call in a try body: the then arm is the call returning normally
    if base is None:
        return None, complete, "operator_unchecked"
    if (cond.get("probe") or {}).get("accessor") in ("error", "stderr") and base in ("truthy", "falsy"):
        base = "not_exists" if base == "truthy" else "exists"
    ops = set()
    for guard in guards:
        if guard.get("kind") == "other":
            return None, False, "operator_unchecked"  # no definite arm to read the polarity from
        flips = _negation_count(ctx, node, a, guard)
        if flips is None:
            return base, False, "operator_unchecked"
        if guard.get("arm", "then") == "else":
            flips += 1
        op = base
        for _ in range(flips % 2):
            op = NEGATE.get(op, "other")
        ops.add(op)
    if len(ops) != 1:
        return None, False, "operator_unchecked"  # guards that test this site read it with opposite polarity
    return ops.pop(), True, None


def _governing_guards(pkg, rec, ctx, cond, node, a):
    """(guards, gap): every gate guard that tests this condition and contains or reads this site. All of them
    must agree on the operator; one that disagrees makes the operator unreadable rather than wrong."""
    out = []
    for g in rec.get("gates", []):
        for guard in g.get("guards") or []:
            if cond["id"] not in guard.get("conditions", []):
                continue
            gs = guard["site"]
            if (gs["file"], gs["derived_from"]) != (a["file"], a["derived_from"]):
                continue
            if anchors.contains(gs, a) or _reaches_site(pkg, ctx, guard, node, a):
                if guard not in out:
                    out.append(guard)
    return out, (None if out else "operator_unchecked")


def _reaches_site(pkg, ctx, guard, node, a) -> bool:
    """The guard's test reads the site, directly (contained) or through a variable/one-line helper the guard
    calls: `if (isWin)` or `if (isLinux())` with the site in isLinux's return."""
    try:
        gnode = _ctx_node(ctx, guard["site"])
    except Unanchored:
        return False
    if gnode is None or ctx.index is None:
        return False
    test = _guard_test(gnode)
    if test is None:
        return False
    for ident in [d for d in _descend(test) if d.type == "identifier"]:
        r = ctx.index.lookup(ident)
        for v in r.values:
            vn = v[1] if v and v[0] == "node" else (_one_line_return_expr(v[1]) if v and v[0] == "fn" else None)
            if vn is not None and vn.start_byte <= a["start_byte"] and a["end_byte"] <= vn.end_byte:
                return True
            if v and v[0] == "fn":  # helper: site in its one-line return
                ret = _returning_function(node)
                if ret is not None and (ret.start_byte, ret.end_byte) == (v[1].start_byte, v[1].end_byte):
                    return True
    return False


def _guard_test(gnode):
    t = gnode.type
    if t in ("if_statement", "elif_clause", "while_statement", "do_statement", "for_statement", "ternary_expression"):
        return gnode.child_by_field_name("condition")
    if t == "conditional_expression":
        kids = gnode.named_children
        return kids[1] if len(kids) > 1 else None
    return gnode


def _negation_count(ctx, node, a, guard) -> int | None:
    """Negations between the test node and the guard decision, counting `!` and `not` along the binding chain
    from the guard's test down to the site (so `!notMac` with `notMac = !(...)` is two flips). typeof, unary
    minus and void are not negations."""
    gnode = _ctx_node(ctx, guard["site"])
    if gnode is None:
        return _plain_negations(node, None)
    test = _guard_test(gnode) or gnode
    if gnode.start_byte <= a["start_byte"] and a["end_byte"] <= gnode.end_byte:
        return _plain_negations(node, gnode)
    return _chain_flips(ctx, test, a, node, 0)  # None when the path from the guard to the site is not found


def _chain_flips(ctx, test, a, node, depth) -> int | None:
    """`!` operators from `test` down to the site through variable bindings, or None when the path is not found
    within a few hops."""
    if test.start_byte <= a["start_byte"] and a["end_byte"] <= test.end_byte:
        return _plain_negations(node, test)
    if depth > 3 or ctx.index is None:
        return None
    for ident in [d for d in _descend(test) if d.type == "identifier"]:
        b = ctx.index.binding_of(ident)
        if b is None:
            continue
        for v in b.values:
            vn = v[1] if v and v[0] in ("node", "fn") else None
            if v and v[0] == "fn":
                # through a helper only its one-line return is read: elsewhere in its body control flow (`if (t)
                # return false;`) can flip the result without a `!`
                vn = _one_line_return_expr(vn)
            if vn is None or not (vn.start_byte <= a["start_byte"] and a["end_byte"] <= vn.end_byte):
                continue
            outer = _plain_negations(ident, test)
            # count `!` from the site up to the value's parent, so the value's own leading `!` (notMac = !(...))
            # is included
            inner = _plain_negations(node, vn.parent)
            return outer + inner
    return None


def _one_line_return_expr(fn):
    """The returned expression of a helper whose body is a single return (or an arrow's expression body)."""
    from tools.common.tsparse import pure_alias
    body = fn.child_by_field_name("body") if fn is not None else None
    if body is None:
        return None
    if body.type not in ("statement_block", "block"):
        return body
    stmts = [c for c in body.named_children if c.type != "comment" and not pure_alias(c)]
    if len(stmts) == 1 and stmts[0].type == "return_statement" and stmts[0].named_children:
        return stmts[0].named_children[0]
    return None


def _plain_negations(node, stop) -> int:
    flips = 0
    for anc in ancestors(node):  # the node's own operator is already read by _code_operator
        if stop is not None and _same(anc, stop):
            break
        if anc.type == "not_operator":
            flips += 1
        elif anc.type == "unary_expression":
            op = anc.child_by_field_name("operator")
            if op is not None and op.type == "!":
                flips += 1
    return flips


def _ctx_node(ctx, anchor):
    src, tree, lang = ctx.pkg.tree(anchor["file"], anchor["derived_from"])
    if tree is None:
        return None
    n = tree.root_node.descendant_for_byte_range(anchor["start_byte"], anchor["end_byte"])
    while n is not None and (n.start_byte, n.end_byte) == (anchor["start_byte"], anchor["end_byte"]):
        if n.type == anchor["node_type"]:
            return n
        n = n.parent
    return None


def _l2_text(cond, a, src, ref) -> dict:
    import json as _json
    body = src[a["start_byte"]:a["end_byte"]].decode("utf-8", "replace")
    if cond["api"].startswith("package.json#"):
        m = re.search(r":\s*(\[.*\]|\".*\")", body, re.S)
        try:
            vals = _json.loads(m.group(1)) if m else None
        except ValueError:
            vals = None
        vals = [vals] if isinstance(vals, str) else vals
        if not isinstance(vals, list):
            return result("cannot_tell", "parse_failed", "manifest field not readable", ref)
        allow = [v for v in vals if isinstance(v, str) and not v.startswith("!")]
        deny = [v[1:] for v in vals if isinstance(v, str) and v.startswith("!")]
        if allow and deny:
            return result("cannot_tell", "operator_unchecked", "manifest mixes allowed and negated values", ref)
        op, values = ("in", allow) if allow else ("not_in", deny)
        claimed = cond["value"] if isinstance(cond["value"], list) else [cond["value"]]
        claim_op = {"==": "in", "!=": "not_in"}.get(cond["operator"], cond["operator"]) if len(claimed) == 1 \
            else cond["operator"]
        if claim_op not in ("in", "not_in"):
            return result("cannot_tell", "operator_unchecked", f"manifest says {op} {values}", ref)
        same_values = sorted(map(str, claimed)) == sorted(values)
        if claim_op == op and same_values:
            return result("verified", None, f"manifest says {op} {values}", ref)
        if claim_op != op and same_values:
            return result("refuted", "operator_mismatch", f"manifest says {op} {values}", ref)
        if set(map(str, claimed)) & set(values):
            return result("cannot_tell", "value_unchecked", f"manifest says {op} {values}; the claim only partly "
                          "overlaps it", ref)
        return result("refuted", "value_mismatch", f"manifest says {op} {values}", ref)
    if _redacted(cond["value"]):
        return result("cannot_tell", "value_redacted", "the value was redacted in the record", ref)
    claimed = cond["value"] if isinstance(cond["value"], list) else [cond["value"]]
    low = defang(body).lower()
    found = cond["value"] is None or all(defang(str(v)).lower() in low for v in claimed)
    if found or _shell_encoded(body) or cond["value_recovered"] != "plain":
        return result("cannot_tell", "operator_unchecked", "value in the hook command; shell operator not checked"
                      if found else "the hook command may hold the value in another form", ref)
    return result("refuted", "value_mismatch", "value not in the command", ref)
