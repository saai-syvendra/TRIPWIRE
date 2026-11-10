"""
Deterministic checks for gates: L3 (payload reached from guarded code), L3.excl (reached only there), L4 (how
the guards combine) and L5 (the branch's behaviours rest on sinks of a matching kind).

Rebuilt on cfg.py (structured control dependence) and resolve.py (names, bindings, canonical callees). The
contract is the project's: verify only on positive proof, refute only on positive contradiction, cannot_tell
(with a reason) otherwise. Concretely:

- A branch region is "on a guard's claimed side" when the CFG says the guard's edge controls it; a region is
  refuted (outside_region) only when the CFG is complete and some guard provably controls the opposite edge or
  the region runs regardless of every guard; anything unresolved is cannot_tell.
- A witness is validated hop by hop. A call reaches a definition only through a resolved scoped binding, a bind
  hop, or a resolved receiver class; a bare name match is not proof and yields cannot_tell (name_only_link). A
  hop that provably contradicts the code refutes (broken_hop / outside_region); a gap is cannot_tell.
- Exclusivity is a grade: exclusive (verified) only when every payload definition is non-escaping and every
  reference to it is a resolved call inside the guarded regions; non_exclusive (refuted) only with a concrete
  resolved call outside; otherwise unknown (cannot_tell).
- L4 derives each guard's formula from the CFG decision structure and compares by truth table.
- L5 reads each sink's kind from its resolved binding and follows package wrappers only while every call in them
  resolves; it refutes only on a complete kind set that lacks the claimed kind.

Nothing is executed; the syntax tree comes from tree-sitter.
"""
from __future__ import annotations

import re
from itertools import product
from pathlib import PurePosixPath

from tools.common import anchors
from tools.common.contract import dnf_terms, min_conditions_of
from tools.common.tables import SINKS
from tools.common.tsparse import field as child, member_object, static_key, static_member_name, text
from tools.verify import apimatch, cfg, resolve
from tools.verify.resolve import FUNCTIONS, ancestors, unwrap
from tools.verify.source import Package, Unanchored

CALLS = {"call_expression", "call", "new_expression"}
CLASSES = {"class_declaration", "class", "class_definition"}
CONSTRUCTORS = {"constructor", "__init__"}
ARGUMENT_LISTS = {"arguments", "argument_list"}
MAX_NAMESAKES = 3
BEHAVIOUR_SINKS = {
    "exfil": {"network"}, "download": {"network"}, "exec_downloaded": {"exec", "eval"}, "spawn_process": {"exec"},
    "write_file": {"fs_write"}, "delete_file": {"fs_delete"}, "destructive": {"fs_delete", "exec"},
    "persistence": {"fs_write", "exec"}, "cred_read": {"fs_read", "exec", "network"},
    "reverse_shell": {"network", "exec"}, "self_propagation": {"network", "exec", "fs_write"},
    "crypto_mining": {"exec", "network"}, "modify_other_packages": {"fs_write", "exec", "network"},
}


# Sink kinds that may still carry out a behaviour they are not listed for: shutil.copy/move are fs_write sinks
# that read their source, which is how stealers take a credential file.
AMBIGUOUS = {"cred_read": {"fs_write"}, "exfil": {"fs_write"}}


def result(verdict, reason=None, evidence="", refs=(), grade=None) -> dict:
    return {"verdict": verdict, "grade": grade, "reason_code": reason, "evidence": evidence,
            "evidence_refs": list(refs)}


def same(a, b) -> bool:
    return a is not None and b is not None and (a.start_byte, a.end_byte) == (b.start_byte, b.end_byte)


def contains(outer: dict, inner: dict) -> bool:
    return anchors.contains(outer, inner)


def within(inner: dict, regions: list[dict]) -> bool:
    return any(anchors.contains(r, inner) for r in regions)


# --- resolving a guard to its controlling decision -------------------------------------------------------

GUARD_TYPES = {
    "if": {"if_statement"}, "elif": {"elif_clause", "if_statement"}, "early_exit": {"if_statement"},
    "ternary": {"ternary_expression", "conditional_expression"},
    "switch_case": {"switch_case", "case_clause"}, "switch_default": {"switch_default", "case_clause"},
    "short_circuit": {"binary_expression", "boolean_operator"}, "try_except": {"try_statement"},
    "loop": {"while_statement", "for_statement", "for_in_statement", "do_statement"},
}


def guard_test(gnode):
    t = gnode.type
    if t in ("if_statement", "elif_clause", "while_statement", "do_statement", "for_statement", "ternary_expression"):
        return gnode.child_by_field_name("condition")
    if t == "conditional_expression":
        kids = gnode.named_children
        return kids[1] if len(kids) > 1 else None
    if t in ("switch_case", "case_clause"):
        return gnode.child_by_field_name("value") or gnode
    op = gnode.child_by_field_name("operator") if t == "binary_expression" else None
    if t == "boolean_operator" or (op is not None and op.type in ("&&", "||", "??")):
        return gnode.child_by_field_name("left") or (gnode.named_children[0] if gnode.named_children else None)
    if t == "try_statement":
        return gnode.child_by_field_name("body")
    return gnode


def decision_node(gnode, kind: str):
    """The decision a guard governs. A guard cited on its test expression is read as the enclosing decision of
    its kind."""
    types = GUARD_TYPES.get(kind)
    if kind == "other" or types is None or gnode.type in types:
        return gnode
    n = gnode.parent
    while n is not None:
        if n.type in types:
            t = guard_test(n)
            if t is not None and t.start_byte <= gnode.start_byte and gnode.end_byte <= t.end_byte:
                return n
        n = n.parent
    return None


def node_at(pkg, anchor):
    """The node at an anchor (or None for a text/range anchor); raises Unanchored on a mismatch."""
    node, _, _ = pkg.node(anchor)
    return node


def region_entry(pkg, region: dict):
    """A node inside a region whose control dependence stands for the region's: the region's own node, or the
    first statement in it for a stmt_range."""
    try:
        node = node_at(pkg, region)
    except Unanchored:
        return None
    if node is not None:
        # a handler carries its guards on the statements in its body
        if node.type in ("catch_clause", "except_clause"):
            body = node.child_by_field_name("body") or next((c for c in node.named_children
                                                             if c.type in ("statement_block", "block")), None)
            node = body if body is not None else node
        # a block or case carries its guards on its inner statements; descend to the first real statement
        while node.type in ("statement_block", "block", "switch_case", "switch_default", "case_clause"):
            stmts = [c for c in node.named_children if c.type != "comment"
                     and not (node.type in ("switch_case", "case_clause") and
                              same(c, node.child_by_field_name("value")))]
            inner = [c for c in stmts if c.type.endswith("_statement") or c.type in ("statement_block", "block")]
            if not inner:
                break
            node = inner[0]
        return node
    src, tree, _ = pkg.tree(region["file"], region["derived_from"])
    if tree is None:
        return None
    n = tree.root_node.descendant_for_byte_range(region["start_byte"], region["start_byte"])
    while n is not None and not (region["start_byte"] <= n.start_byte and n.end_byte <= region["end_byte"]):
        n = n.parent
    # the first statement that begins at or after the region start
    if n is not None:
        for c in [n, *resolve_descendants(n)]:
            if c.start_byte >= region["start_byte"] and c.type.endswith("_statement"):
                return c
    return n


# --- L3: guards control the regions --------------------------------------------------------------------------

def check_guards(pkg: Package, rec: dict, gate: dict, branch: str):
    """(decisions, verdict). decisions is a list of (decision node, side, guard, ctx) for the guards that could
    be resolved; verdict is a refusal/hold when a guard cannot be read as a decision at all."""
    decisions = []
    for i, g in enumerate(gate["guards"]):
        try:
            gnode = node_at(pkg, g["site"])
        except Unanchored as e:
            return None, result("unanchored", e.reason, f"guard {i}: {e.detail}", [anchors.short(g["site"])])
        if gnode is None:
            if g["site"]["node_type"] == anchors.TEXT:
                return None, result("cannot_tell", "witness_gap", "guard in a hook command; shell flow not checked",
                                    [anchors.short(g["site"])])
            return None, result("cannot_tell", "incomplete_cfg", f"guard {i} is not a syntax node",
                                [anchors.short(g["site"])])
        dnode = decision_node(gnode, g["kind"])
        if dnode is None:
            return None, result("cannot_tell", "incomplete_cfg", f"guard {i} is not a {g['kind']} decision",
                                [anchors.short(g["site"])])
        # on the else branch a guard flips to its other side, unless the branch `requires` its conditions: an
        # enclosing guard the else side still sits inside keeps the side it has for the then branch
        held = set((gate.get("else") or {}).get("requires") or [])
        keep = branch == "then" or (held and set(g["conditions"]) <= held)
        side = g["arm"] if keep else ("else" if g["arm"] == "then" else "then")
        ctx = resolve.ctx_for(pkg, g["site"])
        decisions.append((dnode, side, g, ctx))
    return decisions, None


def check_l3(pkg: Package, rec: dict, gate: dict, branch: str) -> dict:
    br = gate[branch]
    decisions, bad = check_guards(pkg, rec, gate, branch)
    if bad:
        return bad
    # a guard with `via` calls (an early exit inside a helper) extends its controlled side into the helper's
    # callers: the code after each cited call runs only when the exit did not fire
    via_regions, via_of = [], {}
    for i, (dnode, side, g, ctx) in enumerate(decisions):
        if g.get("via") and side == "else":
            extra, bad = _via_regions(pkg, dnode, g, ctx)
            if bad:
                return bad
            via_regions += extra
            via_of[i] = extra
    # every region must be controlled by some guard's claimed side; refute only when the CFG is complete and a
    # region provably runs on the wrong side of every guard (or regardless of them)
    for region in br["regions"]:
        if within(region, via_regions):
            continue
        entry = region_entry(pkg, region)
        if entry is None:
            return result("cannot_tell", "incomplete_cfg", "a branch region could not be located", [anchors.short(region)])
        status = _region_status(decisions, region, entry)
        if status == "covered":
            continue
        if status == "wrong_side":
            return result("refuted", "outside_region", "a branch region runs outside every guard's side",
                          [anchors.short(region)])
        return result("cannot_tell", "incomplete_cfg", "cannot confirm a guard controls a branch region",
                      [anchors.short(region)])
    # every guard must control at least one region on its claimed side (layers.md): a guard whose side holds
    # none of the branch's code is refuted only when the CFG proves it puts every region on its other edge
    for i, d in enumerate(decisions):
        per = []
        for region in br["regions"]:
            if within(region, via_of.get(i, [])):  # only this guard's own via extends its side
                per.append("yes")
                continue
            entry = region_entry(pkg, region)
            per.append(guard_controls(d, region, entry) if entry is not None else "unknown")
        if "yes" in per:
            continue
        ref = [anchors.short(d[2]["site"])]
        if per and all(x == "no" for x in per):
            return result("refuted", "outside_region", f"guard {i} puts every region of the branch on its other "
                          "side", ref)
        return result("cannot_tell", "incomplete_cfg", f"cannot confirm guard {i} controls a region of the branch",
                      ref)
    # witness: the payload sink is reached from a region
    verdicts = [check_payload(pkg, br["regions"], p) for p in br["payload"]]
    for order in ("refuted", "unanchored", "cannot_tell"):
        hit = next((v for v in verdicts if v["verdict"] == order), None)
        if hit:
            return hit
    return result("verified", None, f"{len(gate['guards'])} guard(s) control the region(s); "
                  f"{len(verdicts)} payload path(s) reach the sink",
                  [r for v in verdicts for r in v["evidence_refs"]][:10])


def _via_regions(pkg, dnode, g, ctx):
    """(extra controlled regions, verdict-or-None) for a guard's `via` calls. An early exit that ends the
    process inside a helper also guards the code after each cited call that runs the helper, up the chain."""
    cons = dnode.child_by_field_name("consequence")
    ref = [anchors.short(g["site"])]
    if g["kind"] != "early_exit" or cons is None:
        return None, result("refuted", "broken_hop", "guard cites via calls but does not end the process", ref)
    if _last_exit_opaque(cons):
        return None, result("cannot_tell", "encoded_unchecked", "the guard's exit is called through a computed "
                            "name, so it cannot be read without decoding", ref)
    if not _ends_process(cons):
        if _plainly_returns(cons):
            return None, result("refuted", "broken_hop", "guard cites via calls but only returns, which does not "
                                "end the process", ref)
        return None, result("cannot_tell", "witness_gap", "cannot confirm the guard's exit ends the process", ref)
    inner, out = cfg.enclosing_function(dnode), []
    for j, a in enumerate(g["via"]):
        try:
            call = node_at(pkg, a)
        except Unanchored as e:
            return None, result("unanchored", e.reason, f"via {j}: {e.detail}", [anchors.short(a)])
        call = unwrap(call)
        if call is None or call.type not in CALLS:
            return None, result("refuted", "broken_hop", f"via {j} is not a call", [anchors.short(a)])
        if inner is None or inner.type not in FUNCTIONS:
            return None, result("refuted", "broken_hop", f"via {j}: the step before it is not inside a function",
                                [anchors.short(a)])
        cctx = resolve.ctx_for(pkg, a)
        bad = tie_call(call, cctx.lang, inner, [], [anchors.short(a)], cctx.index)
        if bad:
            return None, {**bad, "evidence": f"via {j}: {bad['evidence']}"}
        region = _rest_after(call, a["file"], a["derived_from"])
        if region is None:
            return None, result("cannot_tell", "witness_gap", f"via {j} is not in a statement list, so the code "
                                "after it cannot be located", [anchors.short(a)])
        out.append(region)
        inner = cfg.enclosing_function(call)
    return out, None


def _last_exit_opaque(block) -> bool:
    """The block's last statement is a call whose callee name is computed by a call (a string-table lookup such
    as `process[_0x4a(0x7)](0)`), so whether it is a process exit cannot be read."""
    stmts = [c for c in (block.named_children if block.type in ("statement_block", "block") else [block])
             if c.type != "comment"]
    if not stmts:
        return False
    last = stmts[-1]
    call = last.named_children[0] if last.type == "expression_statement" and last.named_children else last
    if call is None or call.type not in ("call_expression", "call"):
        return False
    fn = call.child_by_field_name("function")
    if fn is None or fn.type not in ("subscript_expression", "subscript"):
        return False
    idx = fn.child_by_field_name("index") or fn.child_by_field_name("subscript")
    return idx is not None and idx.type in ("call_expression", "call")


def _plainly_returns(block) -> bool:
    """The block ends in a return/break/continue and calls nothing, so it provably does not end the process."""
    stmts = [c for c in (block.named_children if block.type in ("statement_block", "block") else [block])
             if c.type != "comment"]
    if not stmts or stmts[-1].type not in ("return_statement", "break_statement", "continue_statement"):
        return False
    return not any(d.type in CALLS for st in stmts for d in resolve_descendants(st))


def _ends_process(block) -> bool:
    stmts = [c for c in (block.named_children if block.type in ("statement_block", "block") else [block])
             if c.type != "comment"]
    return bool(stmts) and cfg.is_process_exit(stmts[-1].named_children[0] if stmts[-1].type == "expression_statement"
                                               and stmts[-1].named_children else stmts[-1])


def _rest_after(node, file, derived):
    stmt = node
    while stmt.parent is not None and stmt.parent.type not in ("statement_block", "block", "program", "module"):
        stmt = stmt.parent
    if stmt.parent is None:
        return None
    return {"file": file, "derived_from": derived, "start_byte": stmt.end_byte, "end_byte": stmt.parent.end_byte}


def guard_controls(decision, region: dict, entry) -> str:
    """Whether one guard puts a region on its claimed side: 'yes', 'no' (the region sits on the guard's opposite
    edge), 'absent' (the function's CFG is complete and the guard is not on the region's path at all), or
    'unknown'. A guard in another function or file is unknown: the CFG does not follow the call that reaches the
    region."""
    dnode, side, g, ctx = decision
    gfn, rfn = cfg.enclosing_function(dnode), cfg.enclosing_function(entry)
    if (g["site"]["file"], g["site"]["derived_from"]) != (region["file"], region["derived_from"]) \
            or not same(gfn, rfn):
        return "unknown"
    return cfg.controlled(ctx, dnode, side, entry)  # yes / no / absent (complete CFG, not on its path) / unknown


def _region_status(decisions, region: dict, entry) -> str:
    """'covered' (a guard controls it on the claimed side), 'wrong_side' (every guard provably puts it on the
    opposite edge), or 'unknown'."""
    status = [guard_controls(d, region, entry) for d in decisions]
    if "yes" in status:
        return "covered"
    if status and all(x == "no" for x in status):
        return "wrong_side"
    return "unknown"


# --- witness hops ------------------------------------------------------------------------------------------

def check_payload(pkg: Package, regions: list[dict], payload: dict) -> dict:
    scope, prev = regions, None
    entered = False  # scope is a function/file a hop stepped into, where a sink in it is genuinely reached
    hops = payload["witness"]
    state = {"aliases": [], "pending": []}
    try:
        for i, hop in enumerate(hops):
            nxt = next((h["anchor"] for h in hops[i + 1:] if h["hop"] != "bind"), payload["sink"])
            new_scope, bad = check_hop(pkg, prev, scope, hop, nxt, state)
            if bad:
                return bad
            if hop["hop"] in ("def", "import", "run_file", "unit"):
                entered = True
            if hop["hop"] != "bind":
                node = node_at(pkg, hop["anchor"])
                prev = (hop["hop"], node, _lang(pkg, hop["anchor"]), hop["anchor"])
            scope = new_scope
        sink = node_at(pkg, payload["sink"])
    except Unanchored as e:
        return result("unanchored", e.reason, e.detail)
    if sink is None:
        return result("cannot_tell", "witness_gap", "the sink is cited on text, not a syntax node",
                      [anchors.short(payload["sink"])])
    if unwrap(sink) is None or unwrap(sink).type not in CALLS:
        return result("refuted", "no_sink", "the sink is not a call", [anchors.short(payload["sink"])])
    if payload.get("unresolved"):
        return result("cannot_tell", "dynamic_dispatch", f"{len(hops)} hop(s) hold; the path stops at "
                      f"{payload['unresolved']}", [anchors.short(payload["sink"])])
    status = _reach_status(pkg, payload["sink"], scope, entered)
    if status == "outside" and _other_version(payload["sink"], scope):
        return result("cannot_tell", "witness_gap", "the sink is cited in another version of the region's file (a "
                      "decoded derivation or its source), which the checker does not map onto the other",
                      [anchors.short(payload["sink"])])
    if status == "outside":
        return result("refuted", "outside_region", "the sink is not inside the last step",
                      [anchors.short(payload["sink"])])
    if status == "nested":
        return result("cannot_tell", "witness_gap", "the sink sits in a nested function in the region; the witness "
                      "does not show it runs", [anchors.short(payload["sink"])])
    return result("verified", None, f"{len(hops)} hop(s) from the region to the sink",
                  [anchors.short(payload["sink"])])


def _other_version(anchor: dict, scope: list[dict]) -> bool:
    """The anchor names the same file as some scope region, but a different version of it (the raw file vs a
    decoded derivation, or two derivations), so byte containment cannot be compared."""
    return any(r["file"] == anchor["file"] and r.get("derived_from") != anchor.get("derived_from") for r in scope)


def _lang(pkg, anchor):
    _, _, lang = pkg.tree(anchor["file"], anchor["derived_from"])
    return lang


def _reach_status(pkg, anchor: dict, scope: list[dict], entered: bool = False) -> str:
    """'reached' (the sink runs when the scope runs), 'nested' (byte-inside a region but in a function nested in
    it, which the witness has not shown runs) or 'outside' (not inside any scope region)."""
    if not within(anchor, scope):
        return "outside"
    node = node_at(pkg, anchor)  # Unanchored propagates: a missing anchor is not evidence of being outside
    if node is None:
        return "nested"  # a text anchor: inside the scope by bytes, but whether it runs is not read
    if entered:
        return "reached"
    region = next((r for r in scope if anchors.contains(r, anchor)), None)
    if region is None:
        return "outside"
    fn = cfg.enclosing_function(node)
    if fn is not None and fn.type in FUNCTIONS and region["start_byte"] <= fn.start_byte and \
            fn.end_byte <= region["end_byte"]:
        return "nested"
    return "reached"


def _reached(pkg, anchor: dict, scope: list[dict], entered: bool = False) -> bool:
    return _reach_status(pkg, anchor, scope, entered) == "reached"


def check_hop(pkg, prev, scope, hop, nxt, state):
    a = hop["anchor"]
    node = node_at(pkg, a)
    lang = _lang(pkg, a)
    ref = [anchors.short(a)]
    kind = hop["hop"]
    if kind == "def":
        if node is None or node.type not in FUNCTIONS:
            return None, result("cannot_tell", "witness_gap", "def hop is not a function definition", ref)
        if prev is not None and prev[0] == "call":
            cctx = resolve.ctx_for(pkg, prev[3]) if prev[3] is not None else None
            if _module_member_tie(pkg, cctx, prev[1], prev[3], node, a):
                bind_parameters(node, lang, state)
                return [a], None
            bad = tie_call(prev[1], prev[2], node, state["aliases"], ref, cctx.index if cctx else None)
            if bad:
                return None, bad
            bind_parameters(node, lang, state)
        else:
            # a definition only runs when something calls it; a def hop with no call before it cannot prove the
            # sink runs (a function may sit in the region yet never be invoked)
            return None, result("cannot_tell", "witness_gap", "a definition is only reached through a call; the "
                                "witness has no call before it", ref)
        return [a], None
    if kind == "unit":
        return check_unit(pkg, node, a, prev, ref)
    if not within(a, scope):
        if _other_version(a, scope):
            return None, result("cannot_tell", "witness_gap", f"{kind} hop is cited in another version of the "
                                "previous step's file, which the checker does not map onto it", ref)
        return None, result("refuted", "outside_region", f"{kind} hop is not inside the previous step", ref)
    if kind == "bind":
        return check_bind(node, a, lang, prev, state, scope, ref)
    if kind == "call":
        if node is None or node.type not in CALLS:
            return None, result("cannot_tell", "witness_gap", "call hop is not a call", ref)
        return scope, None
    if kind in ("import", "run_file"):
        return check_file_hop(pkg, node, a, nxt, kind, ref)
    return None, result("cannot_tell", "witness_gap", f"{kind} hops are not checked", ref)


def tie_call(call, lang: str, fn, aliases: list[dict], ref, index=None):
    """None when the call provably reaches this definition, a refuted verdict when it provably reaches a
    different one, and a cannot_tell verdict when the tie rests only on a shared name (name_only_link) or cannot
    be made (dynamic_dispatch). `index` is the resolve Index of the call's file, when available."""
    callee = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    name = _callee_name(call)
    cls = _enclosing_class(fn)
    # a resolved scoped binding is proof
    if callee is not None and callee.type == "identifier" and index is not None:
        r = index.lookup(callee)
        fns = [v[1] for v in r.values if v and v[0] == "fn"]
        if fns:
            if any(same(t, fn) for t in fns):
                return None
            if r.complete and all(v[0] == "fn" for v in r.values):
                return result("refuted", "broken_hop", "the call resolves to a different function", ref)
    # a method called directly on a fresh instance: new Sender().send() / new Sender()["send"]()
    receiver = member_object(callee)
    rfresh = unwrap(receiver) if receiver is not None else None
    if rfresh is not None and rfresh.type == "new_expression" and cls is not None and name in _def_names(fn):
        ctor = rfresh.child_by_field_name("constructor")
        cname = text(ctor) if ctor is not None and ctor.type == "identifier" else static_member_name(ctor)
        if cname is not None:
            return None if cname in _class_names(cls) else _other_class(call, cname, name, ref)
    # a method on a receiver that resolves to an instance of the definition's class
    if receiver is not None and index is not None and cls is not None and name in _def_names(fn):
        rc = resolve.canon(_mkctx(index), receiver) if False else None  # canon needs a FileCtx; use binding instead
        inst = _resolved_instance_class(index, receiver)
        if inst is not None:
            return None if inst in _class_names(cls) else _other_class(call, inst, name, ref)
    # a constructor of the named class
    if name is not None and cls is not None and static_key(fn.child_by_field_name("name")) in CONSTRUCTORS and \
            name in _class_names(cls) and (call.type == "new_expression" or lang == "py"):
        return None
    # an alias a bind hop registered
    recv = text(receiver) if receiver is not None and receiver.type == "identifier" else static_member_name(receiver)
    for al in reversed(aliases):
        if al["kind"] == "fn" and al["key"] == name and (
                (al.get("node") is not None and same(al["node"], fn)) or (al.get("name") and al["name"] in _def_names(fn))):
            return None
        if al["kind"] == "instance" and recv is not None and al["key"] == recv:
            if cls is not None and al["class"] in _class_names(cls) and name in _def_names(fn):
                return None
            return _other_class(call, al["class"], name, ref)
    # a bare name match is not proof
    if name is not None and name in _def_names(fn):
        return result("cannot_tell", "name_only_link", f"the call to {name} is tied to this definition only by "
                      "name; add a bind hop or a resolved binding to prove it", ref)
    return result("cannot_tell", "dynamic_dispatch", f"call to {name or 'a computed callee'} not tied to this "
                  "definition", ref)


def _member_defs(ctx, call, name):
    """The definitions a method call `recv.name()` provably runs, when its receiver is bound (once, completely) to
    an object literal holding that method or to `new C()` for a class C declared once in the file that defines
    the method itself. None when the receiver does not resolve that far."""
    fn = call.child_by_field_name("function")
    recv = member_object(fn) if fn is not None else None
    if name is None or recv is None or recv.type != "identifier" or ctx.index is None:
        return None
    r = ctx.index.lookup(recv)
    if not r.complete or len(r.values) != 1 or r.values[0][0] != "node":
        return None
    val = unwrap(r.values[0][1])
    if val is None:
        return None
    if val.type in ("object", "dictionary"):
        hits = [m for m in val.named_children if m.type == "method_definition" and
                static_key(m.child_by_field_name("name")) == name]
        hits += [unwrap(m.child_by_field_name("value")) for m in val.named_children if m.type == "pair" and
                 static_key(m.child_by_field_name("key")) == name and
                 unwrap(m.child_by_field_name("value")) is not None and
                 unwrap(m.child_by_field_name("value")).type in FUNCTIONS]
        return hits if len(hits) == 1 else None
    if val.type == "new_expression":
        ctor = val.child_by_field_name("constructor")
        cname = text(ctor) if ctor is not None and ctor.type == "identifier" else None
        root = call
        while root.parent is not None:
            root = root.parent
        decls = [c for c in resolve_descendants(root) if c.type in CLASSES and cname in _class_names(c)]
        if len(decls) != 1:
            return None
        body = decls[0].child_by_field_name("body")
        hits = [m for m in (body.named_children if body is not None else [])
                if m.type == "method_definition" and static_key(m.child_by_field_name("name")) == name]
        return hits if len(hits) == 1 else None
    return None


def _resolved_instance_class(index, receiver):
    """The class name an identifier receiver resolves to via `new C()` / `C()`, or None."""
    if receiver is None or receiver.type != "identifier":
        return None
    r = index.lookup(receiver)
    for v in r.values:
        if v and v[0] == "node":
            val = unwrap(v[1])
            if val is not None and val.type in CALLS:
                ctor = val.child_by_field_name("constructor") or val.child_by_field_name("function")
                name = text(ctor) if ctor is not None and ctor.type == "identifier" else static_member_name(ctor)
                if name is not None and (val.type == "new_expression"):
                    return name
    return None


def _mkctx(index):
    return None


def _module_member_tie(pkg, cctx, call, call_anchor, fn, def_anchor) -> bool:
    """`mod.member()` where `mod = require('./x')` in the call's file, `x` resolves to the definition's file, and
    the definition is exported under `member`: a resolved cross-module tie, not a name match."""
    if cctx is None or cctx.index is None or call_anchor is None:
        return False
    callee = call.child_by_field_name("function")
    recv = member_object(callee) if callee is not None else None
    name = static_member_name(callee) if callee is not None else None
    if recv is None or recv.type != "identifier" or name is None or name not in _def_names(fn):
        return False
    if not _exports_name(fn, name):
        return False
    c = resolve.canon(cctx, recv)
    for mod in c.names:
        if mod.startswith(("fn:", "class:", "inst:", "unit:", "lit:")):
            continue
        if def_anchor["file"] in _resolve_module(mod, call_anchor["file"]):
            return True
    return False


def _exports_name(fn, name) -> bool:
    """The definition is exported under `name` (exports.name = fn, module.exports.name = fn) or is a top-level
    declaration of that name in its module."""
    p = fn.parent
    if p is not None and p.type in ("assignment_expression", "assignment"):
        left = p.child_by_field_name("left")
        chain = static_member_name(left) if left is not None else None
        if chain == name and left is not None and (member_object(left) is not None):
            obj = member_object(left)
            base = member_object(obj) if obj is not None and obj.type in ("member_expression",) else obj
            if obj is not None and (text(obj).startswith("exports") or text(obj).startswith("module.exports")):
                return True
    return name in _def_names(fn)  # a named top-level declaration is reachable as a module member


def _callee_name(call):
    fn = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    if fn is None:
        return None
    if fn.type == "identifier":
        return text(fn)
    return static_member_name(fn)


def _def_names(fn) -> set[str]:
    names = set()
    name = static_key(fn.child_by_field_name("name"))
    if name is not None:
        names.add(name)
    p = fn.parent
    if p is not None and p.type == "variable_declarator":
        names.add(text(p.child_by_field_name("name")))
    elif p is not None and p.type in ("assignment_expression", "assignment"):
        left = p.child_by_field_name("left")
        if left is not None:
            names.add(static_member_name(left) or text(left))
    elif p is not None and p.type == "pair":
        key = static_key(p.child_by_field_name("key"))
        if key is not None:
            names.add(key)
    elif p is not None and p.type in ("field_definition", "public_field_definition"):
        key = static_key(p.child_by_field_name("property"))
        if key is not None:
            names.add(key)
    return names


def _other_class(call, cname: str, method: str | None, ref) -> dict:
    """The call's receiver is an instance of class `cname`, not of the definition's class. That refutes the tie
    only when `cname` is declared once in the call's file and either defines `method` itself (an override) or
    extends nothing (so it cannot inherit the definition); otherwise the method may be inherited."""
    root = call
    while root.parent is not None:
        root = root.parent
    decls = [c for c in resolve_descendants(root) if c.type in CLASSES and cname in _class_names(c)]
    if len(decls) == 1:
        c = decls[0]
        body = c.child_by_field_name("body")
        members = body.named_children if body is not None else []
        own = {text(m.child_by_field_name("name")) for m in members
               if m.type in ("method_definition", "function_definition") and m.child_by_field_name("name") is not None}
        heritage = any(k.type in ("class_heritage", "argument_list") for k in c.children) or \
            c.child_by_field_name("superclasses") is not None
        # a method can also arrive as a field (`run = other.run`), through the prototype, Object.assign, setattr or
        # a decorator; any sign of that in the file leaves the tie open
        src = text(root)
        attached = any(m.type in ("field_definition", "public_field_definition", "expression_statement",
                                  "decorated_definition") for m in members) or \
            re.search(rf"\b{re.escape(cname)}\s*(\.\s*prototype\b|\.\s*{re.escape(method or '')}\s*=)", src) or \
            re.search(rf"(Object\.assign|Object\.defineProperty|setattr|Reflect\.set)\s*\(\s*{re.escape(cname)}\b",
                      src) or c.parent is not None and c.parent.type == "decorated_definition"
        if not attached and (method in own or not heritage):
            return result("refuted", "broken_hop", f"the receiver is a {cname}, whose {method} is not this "
                          "definition", ref)
    return result("cannot_tell", "dynamic_dispatch", f"the receiver is a {cname}; this method may be inherited", ref)


def _class_names(cls) -> set[str]:
    names = set()
    own = cls.child_by_field_name("name")
    if own is not None:
        names.add(text(own))
    p = cls.parent
    while p is not None and p.type == "parenthesized_expression":
        p = p.parent
    if p is not None and p.type == "variable_declarator":
        names.add(text(p.child_by_field_name("name")))
    elif p is not None and p.type in ("assignment_expression", "assignment"):
        left = p.child_by_field_name("left")
        if left is not None:
            names.add(static_member_name(left) or text(left))
    return names


def _enclosing_class(fn):
    for anc in ancestors(fn):
        if anc.type in CLASSES:
            return anc
        if anc.type in FUNCTIONS:
            return None
    return None


def alias_for(key: str, value, lang: str) -> dict:
    v = unwrap(value)
    if v is not None and v.type in CALLS:
        ctor = v.child_by_field_name("constructor") or v.child_by_field_name("function")
        cls = text(ctor) if ctor is not None and ctor.type == "identifier" else static_member_name(ctor)
        if cls is not None and (v.type == "new_expression" or lang == "py"):
            return {"key": key, "kind": "instance", "class": cls}
    if v is not None and v.type in FUNCTIONS:
        return {"key": key, "kind": "fn", "node": v, "name": None}
    name = text(v) if v is not None and v.type == "identifier" else static_member_name(v)
    return {"key": key, "kind": "fn", "node": None, "name": name}




def check_bind(node, a, lang, prev, state, scope, ref):
    if node is None:
        return None, result("cannot_tell", "witness_gap", "bind hop is not a syntax node", ref)
    if node.parent is not None and node.parent.type in ARGUMENT_LISTS:
        call = node.parent.parent
        if prev is None or prev[0] != "call":
            # handed to a call that is not on the witness (a library constructor or scheduler such as
            # threading.Thread or setTimeout): what that call does with it cannot be followed
            return None, result("cannot_tell", "witness_gap", "bind argument goes to a call the witness does not "
                                "follow", ref)
        if not same(prev[1], call):
            return None, result("refuted", "broken_hop", "bind argument is not an argument of the previous call", ref)
        index = [c for c in node.parent.named_children if c.type != "comment"].index(node)
        state["pending"].append((index, node))
        return scope, None
    if node.type == "pair":
        key, value = static_key(node.child_by_field_name("key")), node.child_by_field_name("value")
    elif node.type in ("assignment_expression", "assignment"):
        left, value = node.child_by_field_name("left"), node.child_by_field_name("right")
        key = text(left) if left is not None and left.type == "identifier" else static_member_name(left)
    elif node.type == "variable_declarator":
        name, value = node.child_by_field_name("name"), node.child_by_field_name("value")
        key = text(name) if name is not None and name.type == "identifier" else None
    else:
        return None, result("cannot_tell", "witness_gap",
                            f"bind hop is a {node.type}, not an object key, assignment or argument", ref)
    if key is None or value is None:
        return None, result("cannot_tell", "dynamic_dispatch", "the bind's key is computed", ref)
    al = alias_for(key, value, lang)
    state["aliases"].append(al)
    return scope, None


def bind_parameters(fn, lang, state):
    params = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    names = [c for c in (params.named_children if params is not None else []) if c.type != "comment"]
    if params is not None and params.type == "identifier":
        names = [params]
    for index, value in state["pending"]:
        p = names[index] if index < len(names) else None
        if p is not None and p.type in ("assignment_pattern", "default_parameter", "typed_parameter",
                                        "typed_default_parameter"):
            p = p.child_by_field_name("left") or p.child_by_field_name("name") or \
                (p.named_children[0] if p.named_children else None)
        if p is not None and p.type == "identifier":
            state["aliases"].append(alias_for(text(p), value, lang))
    state["pending"].clear()


def check_file_hop(pkg, node, a, nxt, kind, ref):
    if nxt is None:
        return None, result("cannot_tell", "witness_gap", f"{kind} hop leads nowhere", ref)
    strings = _string_args(node) if node is not None and node.type in CALLS else \
        [text(d) for d in resolve_descendants(node) if d.type in ("string_fragment", "string_content", "dotted_name")] \
        if node is not None else []
    target = nxt["file"]
    if kind == "run_file" and node is not None and node.type in CALLS:
        canon = resolve.canon(resolve.ctx_for(pkg, a), node)
        from tools.common.tables import READ_CALLS
        if any(READ_CALLS.match(n + "()") for n in canon.names):
            return None, result("cannot_tell", "witness_gap", "run_file hop launches through a read call", ref)
    ok = any(target in _resolve_module(s, a["file"]) for s in strings) if kind == "import" else \
        any(PurePosixPath(target).name in s or s.endswith(PurePosixPath(target).stem) for s in strings)
    if kind == "import" and not ok:
        ok = any(target.replace("/", ".").removesuffix(".py").endswith(s) for s in strings)
    if not ok:
        return None, result("cannot_tell", "witness_gap", f"{kind} does not name {target}", ref)
    tgt_src = pkg.bytes(target, nxt["derived_from"])
    return [{"file": target, "derived_from": nxt["derived_from"], "start_byte": 0, "end_byte": len(tgt_src)}], None


def _string_args(call):
    args = call.child_by_field_name("arguments")
    return [text(d) for d in (resolve_descendants(args) if args is not None else [])
            if d.type in ("string_fragment", "string_content")]


def _resolve_module(spec, from_file):
    if not spec.startswith("."):
        return []
    base = PurePosixPath(from_file).parent / spec
    parts = []
    for p in base.parts:
        if p == "..":
            parts = parts[:-1]
        elif p != ".":
            parts.append(p)
    stem = "/".join(parts)
    return [stem, f"{stem}.js", f"{stem}.cjs", f"{stem}.mjs", f"{stem}/index.js", f"{stem}.py", f"{stem}/__init__.py"]


def resolve_descendants(node):
    from tools.verify.checks import _descendants
    return list(_descendants(node))


def check_unit(pkg, node, a, prev, ref):
    if node is None or node.type not in FUNCTIONS | {"method_definition"}:
        return None, result("cannot_tell", "witness_gap", "unit hop is not a module factory", ref)
    key = _unit_key(node)
    if key is None:
        return None, result("cannot_tell", "witness_gap", "unit hop is not an entry of a module table", ref)
    if prev is None or prev[0] != "call" or prev[1] is None:
        return None, result("cannot_tell", "witness_gap", "a unit hop must follow the call that loads it", ref)
    call, lang = prev[1], prev[2]
    from tools.common import bundles
    args = call.child_by_field_name("arguments")
    argv = [c for c in (args.named_children if args is not None else []) if c.type != "comment"]
    mid = bundles.literal_id(argv[0]) if len(argv) == 1 else None
    if mid == key:
        return [a], None
    callee = call.child_by_field_name("function")
    if callee is not None and callee.type == "identifier":
        ctx = resolve.ctx_for(pkg, a)
        r = ctx.index.lookup(callee) if ctx.index is not None else None
        for v in (r.values if r else []):
            if v and v[0] == "node" and v[1].start_byte <= node.start_byte and node.end_byte <= v[1].end_byte:
                return [a], None
    return None, result("cannot_tell", "dynamic_dispatch", f"cannot tie the call to module {str(key)[:60]}", ref)


def _unit_key(node):
    entry = node.parent
    if entry is not None and entry.type == "array":
        entry = entry.parent
    while entry is not None and entry.type == "parenthesized_expression":
        entry = entry.parent
    key = None
    if node.type == "method_definition":
        key = node.child_by_field_name("name")
    elif entry is not None and entry.type == "pair":
        key = entry.child_by_field_name("key")
    if key is None:
        return None
    raw = text(key)
    return raw[1:-1] if raw[:1] in "'\"`" and raw[-1:] == raw[:1] else raw


# --- L3.excl: reached only through the gate ------------------------------------------------------------------

def check_exclusive(pkg: Package, rec: dict, gate: dict, branch: str) -> dict:
    br = gate[branch]
    # exclusivity ("reached only through this branch") presupposes L3 ("reached through this branch"): when the
    # base L3 is not verified, the payload is not confirmed reached here, so exclusivity cannot be established
    base = check_l3(pkg, rec, gate, branch)
    if base["verdict"] != "verified":
        return result("cannot_tell", "witness_gap", "the branch's payload is not confirmed reached (L3 is "
                      f"{base['verdict']}), so exclusivity cannot be established", grade="unknown")
    if any(p.get("unresolved") for p in br["payload"]):
        return result("cannot_tell", "dynamic_dispatch", "a payload path is not fully traced, so other ways to its "
                      "sink cannot be ruled out", grade="unknown")
    refs = []
    for p in br["payload"]:
        if not p["witness"] and not _reached(pkg, p["sink"], br["regions"]):
            refs.append(anchors.short(p["sink"]))
    if refs:
        return result("cannot_tell", "witness_gap", "a sink lies outside the branch region and no witness links "
                      "them", refs[:10], "unknown")
    if all(not p["witness"] for p in br["payload"]):
        return result("verified", None, "every sink sits in the region itself", grade="exclusive")
    grade, refs = "exclusive", []
    files = _record_files(rec)
    for p in br["payload"]:
        defs = [h["anchor"] for h in p["witness"] if h["hop"] == "def"]
        chain = br["regions"] + defs
        for d in defs:
            try:
                fn = node_at(pkg, d)
                trees = {f: pkg.tree(*f) for f in files | {(d["file"], d["derived_from"])}}
            except Unanchored as e:
                return result("unanchored", e.reason, e.detail, grade="unknown")
            if fn is None:
                continue
            names = _def_names(fn)
            if _escapes(pkg, d, fn, names) or _named_elsewhere(pkg, files | {(d["file"], d["derived_from"])}, names):
                grade = _weaker(grade, "unknown")
                refs.append(anchors.short(d))
            for (file, derived), (src, tree, flang) in trees.items():
                if tree is None:
                    continue
                home = (file, derived) == (d["file"], d["derived_from"])
                ctx = resolve.ctx_for(pkg, {"file": file, "derived_from": derived, "start_byte": 0,
                                            "end_byte": 0, "node_type": "x", "sha256": ""})
                for ident in (x for x in resolve_descendants(tree.root_node)
                              if x.type in ("identifier", "property_identifier") and text(x) in names):
                    at = {"file": file, "derived_from": derived, "start_byte": ident.start_byte,
                          "end_byte": ident.end_byte}
                    if within(at, chain) or (home and (_is_own_name(ident, fn) or
                                                       any(same(aa, fn) for aa in ancestors(ident)))):
                        continue
                    callee = ident.parent if ident.parent is not None and ident.parent.type in (
                        "member_expression", "attribute") else ident
                    is_call = callee.parent is not None and callee.parent.type in CALLS and \
                        same(callee.parent.child_by_field_name("function"), callee)
                    bound = ctx.index.binding_of(ident) if home and ident.type == "identifier" and ctx.index else None
                    resolved_here = bound is not None and any(
                        v[0] == "fn" and same(v[1], fn) for v in bound.values)
                    where = anchors.short({**at, "line": src.count(b"\n", 0, ident.start_byte) + 1})
                    if is_call and resolved_here and _runs_unguarded(ctx, ident):
                        # a call that provably resolves to this payload function and runs unconditionally when
                        # the file loads, outside the gate
                        grade = "non_exclusive"
                        refs.append(where)
                    elif is_call and resolved_here:
                        # resolved, but itself inside a function or a branch: it may only run behind the gate
                        grade = _weaker(grade, "unknown")
                        refs.append(where)
                    elif is_call or (not is_call and grade == "exclusive"):
                        # a call or reference by the same name that does not resolve here (an unbound global, a
                        # cross-file or minified namesake): we cannot prove it reaches this function, so we cannot
                        # prove exclusivity either
                        grade = _weaker(grade, "unknown")
                        refs.append(where)
    verdict = {"exclusive": "verified", "non_exclusive": "refuted", "unknown": "cannot_tell"}[grade]
    reason = {"exclusive": None, "non_exclusive": "outside_region", "unknown": "witness_gap"}[grade]
    evidence = {"exclusive": "no other reference reaches the payload functions",
                "non_exclusive": "a payload function is also called outside the gate",
                "unknown": "a payload function is referenced elsewhere without a resolved call"}[grade]
    return result(verdict, reason, evidence, refs[:10], grade)


def _weaker(a, b):
    order = {"exclusive": 0, "unknown": 1, "non_exclusive": 2}
    return a if order[a] >= order[b] else b


def _runs_unguarded(ctx, ident) -> bool:
    """The reference is a call that is a whole statement of its own (`go();`, `await go();`) at the file's top
    level, under no decision, in a CFG that is complete. A call inside an expression (`x && go()`, a ternary, a
    declaration) may itself be conditional, so it is never taken as unguarded."""
    fn = cfg.enclosing_function(ident)
    if fn is None or fn.type not in ("program", "module"):
        return False
    call = ident.parent if ident.parent is not None and ident.parent.type in ("member_expression", "attribute") \
        else ident
    call = call.parent
    if call is None or call.type not in CALLS:
        return False
    stmt = call.parent
    while stmt is not None and stmt.type in ("await_expression", "await", "parenthesized_expression"):
        stmt = stmt.parent
    if stmt is None or stmt.type != "expression_statement":
        return False
    edges, complete = cfg.guards_of(ctx, stmt)
    return complete and not edges


def _named_elsewhere(pkg, scanned: set, names: set) -> bool:
    """A source file the exclusivity scan does not parse mentions a payload function's name, so a caller there
    cannot be ruled out (a text check over the package's files, charged to the claim's budget)."""
    if not names:
        return False
    from tools.verify import checks
    rx = re.compile(rb"(?<![\w$])(" + b"|".join(re.escape(n.encode()) for n in sorted(names)) + rb")(?![\w$])")
    lister = getattr(pkg, "source_files", None)
    for f in (lister() if lister else []):
        if (f, None) in scanned:
            continue
        try:
            body = pkg.bytes(f, None)
        except Unanchored:
            continue
        checks.spend(len(body) // 4096 + 1)
        if rx.search(body):
            return True
    return False


def _escapes(pkg, d, fn, names) -> bool:
    """The payload function is exported or stored where an outside caller could reach it (so its callers cannot
    be enumerated)."""
    p = fn.parent
    if p is not None and p.type in ("export_statement", "decorated_definition"):
        return True  # an ES module export, or a decorator that may register the function elsewhere
    if p is not None and p.type in ("assignment_expression", "assignment"):
        left = p.child_by_field_name("left")
        if left is not None and (static_member_name(left) or "").startswith(("exports", "module")):
            return True
        if left is not None and text(left).startswith(("exports.", "module.exports")):
            return True
    return False


def _is_own_name(ident, fn) -> bool:
    p = ident.parent
    if same(p, fn):
        return True
    if p is not None and p.type in ("member_expression", "attribute"):
        p = p.parent
    return p is not None and any(same(x, fn) for x in p.named_children)


def _record_files(rec):
    from tools.common.contract import iter_anchors
    return {(a["file"], a["derived_from"]) for _, a in iter_anchors({k: v for k, v in rec.items()
                                                                     if k in ("conditions", "gates")})}


# --- L4: combination ---------------------------------------------------------------------------------------

def check_l4(pkg: Package, rec: dict, gate: dict) -> dict:
    parts, complete, bad = guard_formulas(pkg, rec, gate)
    if bad:
        return bad
    expected = combination(pkg, rec, gate, parts)
    if expected is None or "?" in expected or not complete:
        return result("cannot_tell", "incomplete_cfg", "the guards read more than the claimed conditions or could "
                      "not be fully resolved", grade="cannot_tell")
    claim = gate["expression"]
    try:
        equiv = _truth_equal(expected, claim)
    except ValueError:
        return result("cannot_tell", "incomplete_cfg", f"could not read {expected}", grade="cannot_tell")
    if not equiv:
        return result("refuted", "expression_mismatch", f"guards combine as {expected}, claim says {claim}",
                      grade="inconsistent")
    if gate["then"]["min_conditions"] != min_conditions_of(expected):
        return result("refuted", "expression_mismatch", f"min_conditions should be {min_conditions_of(expected)}",
                      grade="inconsistent")
    return result("verified", None, f"guards combine as {expected}", grade="consistent")


def _truth_equal(expr_a: str, expr_b: str) -> bool:
    """Two gate expressions are equivalent iff they agree on every assignment of their condition ids."""
    ids = sorted(set(re.findall(r"c\d+", expr_a)) | set(re.findall(r"c\d+", expr_b)))
    if not ids:
        return dnf_terms(expr_a) == dnf_terms(expr_b)
    if len(ids) > 16:
        raise ValueError("too many conditions for a truth table")
    for bits in product((False, True), repeat=len(ids)):
        env = dict(zip(ids, bits))
        if _eval_expr(expr_a, env) != _eval_expr(expr_b, env):
            return False
    return True


def _eval_expr(expr: str, env: dict) -> bool:
    py = expr
    for cid, val in sorted(env.items(), key=lambda kv: -len(kv[0])):
        py = re.sub(rf"\b{cid}\b", "True" if val else "False", py)
    py = py.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
    try:
        return bool(eval(py, {"__builtins__": {}}, {}))  # noqa: S307 - expr is only cN, &&, ||, !, parens
    except Exception as e:  # noqa: BLE001
        raise ValueError(str(e))


def guard_formulas(pkg: Package, rec: dict, gate: dict):
    """(per-guard positive-form formula over condition ids, all-complete, verdict-or-None)."""
    conds = {c["id"]: c for c in rec["conditions"]}
    parts, complete = [], True
    for i, g in enumerate(gate["guards"]):
        try:
            gnode = node_at(pkg, g["site"])
        except Unanchored as e:
            return None, False, result("unanchored", e.reason, e.detail, grade="cannot_tell")
        if gnode is None:
            return None, False, result("cannot_tell", "incomplete_cfg", "guard is not a syntax node",
                                       grade="cannot_tell")
        dnode = decision_node(gnode, g["kind"])
        test = guard_test(dnode if dnode is not None else gnode)
        if test is None:
            return None, False, result("cannot_tell", "incomplete_cfg", f"guard {i} has no test", grade="cannot_tell")
        ctx = resolve.ctx_for(pkg, g["site"])
        sites = _sites_in_test(pkg, ctx, g, conds, test)
        f = _formula(ctx, test, sites)
        if "?" in _flatten(f):
            complete = False
        parts.append(_render(_positive(f, negate=g["arm"] == "else")))
    return parts, complete, None


def _sites_in_test(pkg, ctx, g, conds, test):
    """{(start,end): cid} for condition sites the guard's test reads, directly or through a binding/helper."""
    out = {}
    for cid in g["conditions"]:
        for s in conds[cid]["sites"]:
            a = s["anchor"]
            if (g["site"]["file"], g["site"]["derived_from"]) != (a["file"], a["derived_from"]):
                continue
            if anchors.contains(g["site"], a) or _test_reaches(ctx, test, a):
                out[(a["start_byte"], a["end_byte"])] = cid
    return out


def _test_reaches(ctx, test, a) -> bool:
    if ctx.index is None:
        return False
    for ident in [d for d in resolve_descendants(test) if d.type == "identifier"]:
        r = ctx.index.lookup(ident)
        for v in r.values:
            vn = v[1] if v and v[0] in ("node", "fn") else None
            if vn is not None and vn.start_byte <= a["start_byte"] and a["end_byte"] <= vn.end_byte:
                return True
    return False


def _formula(ctx, node, sites, depth=0):
    key = (node.start_byte, node.end_byte)
    if key in sites:
        return sites[key]
    node = unwrap(node)
    if node is None:
        return "?"
    if node.type in ("parenthesized_expression", "expression_statement") and len(node.named_children) == 1:
        return _formula(ctx, node.named_children[0], sites, depth)
    if node.type == "sequence_expression" and node.named_children:
        return _formula(ctx, node.named_children[-1], sites, depth)
    if apimatch.logical(node):
        op = text(node.child_by_field_name("operator")) if node.type == "binary_expression" else \
            next((text(c) for c in node.children if not c.is_named), "")
        kids = [node.child_by_field_name("left") or node.named_children[0],
                node.child_by_field_name("right") or node.named_children[-1]]
        parts = [_formula(ctx, k, sites, depth) for k in kids]
        if op in ("&&", "and") and parts[0] == "?" and isinstance(parts[1], str) and parts[1] != "?" and \
                _presence_guard(kids[0], kids[1]):
            return parts[1]
        return ("and" if op in ("&&", "and") else "or", parts)
    if node.type in ("not_operator", "unary_expression") and node.named_children:
        op = node.child_by_field_name("operator")
        if node.type == "unary_expression" and (op is None or op.type != "!"):
            return "?"
        return ("not", [_formula(ctx, node.named_children[-1], sites, depth)])
    inside = [cid for (s, e), cid in sites.items() if node.start_byte <= s and e <= node.end_byte]
    if len(set(inside)) == 1:
        return inside[0]
    if depth < 4 and not inside and ctx.index is not None:
        target = node.child_by_field_name("function") if node.type in ("call_expression", "call") else node
        if target is not None and target.type == "identifier":
            r = ctx.index.lookup(target)
            fns = [v[1] for v in r.values if v and v[0] == "fn"]
            if len(fns) == 1:
                ret = apimatch._returning_function(fns[0].child_by_field_name("body")) if False else _one_line_return(fns[0])
                if ret is not None:
                    return _formula(ctx, ret, sites, depth + 1)
            elif r.values and all(v[0] == "node" for v in r.values) and len(r.values) == 1:
                return _formula(ctx, r.values[0][1], sites, depth + 1)
    return "?"


def _one_line_return(fn):
    body = fn.child_by_field_name("body")
    if body is None:
        return None
    if body.type not in ("statement_block", "block"):
        return body
    from tools.common.tsparse import pure_alias
    stmts = [c for c in body.named_children if c.type != "comment" and not pure_alias(c)]
    if len(stmts) == 1 and stmts[0].type == "return_statement" and stmts[0].named_children:
        return stmts[0].named_children[0]
    return None


VALUE_REFS = {"identifier", "member_expression", "subscript_expression", "attribute", "subscript"}
NULLISH = {"undefined", "null", "None", "void 0", "void 0x0"}


def _presence_guard(test, other) -> bool:
    while test.type == "parenthesized_expression" and test.named_children:
        test = test.named_children[0]
    value = test if test.type in VALUE_REFS else None
    if test.type in ("binary_expression", "comparison_operator"):
        ops = [text(c) for c in test.children if not c.is_named]
        sides = [test.child_by_field_name("left"), test.child_by_field_name("right")] \
            if test.type == "binary_expression" else test.named_children[:2]
        if len(ops) == 1 and ops[0] in ("!==", "!=", "is not") and len(sides) == 2 and None not in sides:
            value = next((a for a, b in (sides, sides[::-1]) if a.type in VALUE_REFS and text(b) in NULLISH), None)
    if value is None:
        return False
    return any(d.type == value.type and text(d) == text(value) for d in resolve_descendants(other))


def _positive(f, negate=False):
    if isinstance(f, str):
        return f
    op, kids = f
    if op == "not":
        return _positive(kids[0], not negate)
    if negate:
        op = "or" if op == "and" else "and"
    return (op, [_positive(k, negate) for k in kids])


def _render(f) -> str:
    if isinstance(f, str):
        return f
    op, kids = f
    return "(" + (" && " if op == "and" else " || ").join(_render(k) for k in kids) + ")"


def _flatten(f) -> str:
    if isinstance(f, str):
        return f
    return f[0] + "".join(_flatten(k) for k in f[1])


def combination(pkg: Package, rec: dict, gate: dict, parts: list[str]):
    """How the guards combine for the then branch: per region, the guards controlling it joined with and; the
    regions as alternatives joined with or."""
    br = gate["then"]
    if not br.get("regions"):
        return None  # no cited code on the then side: how the guards combine there is not read
    decisions, bad = check_guards(pkg, rec, gate, "then")
    if bad or not decisions:
        return None
    via = {}
    for i, (dnode, side, g, ctx) in enumerate(decisions):
        if g.get("via") and side == "else":
            extra, vbad = _via_regions(pkg, dnode, g, ctx)
            if not vbad:
                via[i] = extra
    terms = []
    for region in br["regions"]:
        entry = region_entry(pkg, region)
        over = []
        for i, d in enumerate(decisions):
            if i in via and within(region, via[i]):
                over.append(parts[i])
                continue
            st = guard_controls(d, region, entry) if entry is not None else "unknown"
            if st == "yes":
                over.append(parts[i])
            elif st == "unknown":
                return "?"  # whether this guard joins the region's term is not known
        term = " && ".join(over) if over else "?"
        if term not in terms:
            terms.append(term)
    return terms[0] if len(terms) == 1 else " || ".join(f"({t})" for t in terms)


# --- L5: behaviour -------------------------------------------------------------------------------------------

CLIENTS = [(re.compile(p), k) for p, k in (
    (r"^(@octokit/.*|octokit|axios|got|node-fetch|undici|request|superagent|needle|ws|socket\.io-client|ftp"
     r"|nodemailer|requests|httpx|aiohttp|urllib3|paramiko|boto3|discord\.js|telegraf)$", "network"),
    (r"^(execa|shelljs|cross-spawn|simple-git)$", "exec"),
)]


def sink_kind(pkg, anchor, node, lang) -> tuple[str | None, bool]:
    """(sink kind, complete) from the call's resolved canonical callee. The kind is definite only when every name
    the callee may resolve to is a sink of that one kind and the resolution is complete; a callee that may be
    several things, or a package function, gives (kind-or-None, False)."""
    kinds, complete = sink_kinds(pkg, anchor, node, lang)
    if len(kinds) == 1:
        return next(iter(kinds)), complete
    return None, complete and not kinds


def sink_kinds(pkg, anchor, node, lang) -> tuple[set, bool]:
    """(every sink kind the callee may be, whether that set is exhaustive)."""
    if node is None or node.type not in CALLS or lang is None:
        return set(), True
    ctx = resolve.ctx_for(pkg, anchor)
    c = resolve.canon(ctx, node)
    kinds, unmatched = set(), False
    for name in c.names:
        canon = name if name.endswith("()") else name + "()"
        k = next((kind for rx, kind in SINKS[lang] if rx.match(canon)), None)
        if k is None:
            base = name.split(".")[0]
            k = next((kind for rx, kind in CLIENTS if rx.match(base)), None)
        if k is None:
            unmatched = True
        else:
            kinds.add(k)
    if any(n.startswith(("fn:", "unit:")) for n in c.names):
        return kinds, False  # package code runs here; what it reaches is followed by wrapper_kinds, not here
    return kinds, c.complete and not (kinds and unmatched)


def check_l5(pkg: Package, gate: dict, branch: str) -> dict:
    br = gate[branch]
    kinds = {}
    for p in br["payload"]:
        try:
            node = node_at(pkg, p["sink"])
            lang = _lang(pkg, p["sink"])
        except Unanchored as e:
            return result("unanchored", e.reason, e.detail, grade="cannot_tell")
        found, complete = sink_kind(pkg, p["sink"], node, lang)
        if found is None and node is not None and node.type in CALLS:
            via, via_complete = wrapper_kinds(pkg, p)
            if p["sink_kind"] in via and via_complete:
                found, complete = p["sink_kind"], True
            elif len(via) == 1 and via_complete:
                found, complete = next(iter(via)), True
            else:
                found, complete = None, False
        if found is not None and complete and p["sink_kind"] not in (found, "other") and \
                {found, p["sink_kind"]} != {"fs_read", "fs_write"}:  # a copy or move reads and writes
            return result("refuted", "sink_kind_mismatch", f"sink is {found}, claim says {p['sink_kind']}",
                          [anchors.short(p["sink"])], "inconsistent")
        if found is not None and not complete:
            found = None
        kinds.setdefault(p["behaviour"], set()).add(found if found is not None else ("?" if not complete else None))
    checked, open_ = [], []
    for b in br["behaviours"]:
        allowed = BEHAVIOUR_SINKS.get(b)
        if allowed is None:
            open_.append(b)
            continue
        got = {k for k in kinds.get(b, set()) if k and k != "?"}
        unknown = "?" in kinds.get(b, set()) or not got
        if got & allowed:
            checked.append(b)
        elif got <= {"exec", "eval"} | AMBIGUOUS.get(b, set()) | {"decode"}:
            # a process or evaluated code can do anything, a decode is a step of whatever it feeds, and a copy of
            # a credential file reads it: none of these contradicts the behaviour
            open_.append(b)
        elif got and not unknown:
            return result("refuted", "sink_kind_mismatch", f"{b} rests on {sorted(got)} sinks, needs {sorted(allowed)}",
                          grade="inconsistent")
        else:
            open_.append(b)
    if open_:
        return result("cannot_tell", "other", f"no sink class decides {', '.join(open_)}", grade="cannot_tell")
    return result("verified", None, f"{', '.join(checked)} rest on matching sinks", grade="consistent")


def defs_index(pkg, file, derived_from):
    key = ("defs", file, derived_from)
    if key not in pkg.cache:
        from tools.common.tsparse import descendants
        _, tree, _ = pkg.tree(file, derived_from)
        index = {}
        for d in (descendants(tree.root_node) if tree is not None else []):
            if d.type in FUNCTIONS:
                for name in _def_names(d):
                    index.setdefault(name, []).append(d)
        pkg.cache[key] = index
    return pkg.cache[key]


def wrapper_kinds(pkg, payload) -> tuple[set, bool]:
    """Sink kinds the package's own wrapper reaches, and whether that set is exhaustive: every call inside it
    resolved through a scoped binding, and every package function it calls was followed. A wrapper found only by
    its name, or a call into code not followed, leaves the set incomplete."""
    try:
        node = node_at(pkg, payload["sink"])
        lang = _lang(pkg, payload["sink"])
    except Unanchored:
        return set(), False
    if node is None or node.type not in CALLS or lang is None:
        return set(), True
    ctx = resolve.ctx_for(pkg, payload["sink"])
    index = defs_index(pkg, payload["sink"]["file"], payload["sink"]["derived_from"])
    kinds, complete, seen = set(), True, set()

    def defs_for(call):
        fn = call.child_by_field_name("function")
        if fn is not None and fn.type == "identifier" and ctx.index is not None:
            r = ctx.index.lookup(fn)
            fns = [v[1] for v in r.values if v and v[0] == "fn"]
            if fns:
                return fns, r.complete and len(fns) == len(r.values)
        name = _callee_name(call)
        member = _member_defs(ctx, call, name)
        if member is not None:
            return member, True
        ds = index.get(name, []) if name else []
        return (ds, False) if 0 < len(ds) <= MAX_NAMESAKES else ([], len(ds) == 0)

    def walk(fn, depth):
        nonlocal complete
        if (fn.start_byte, fn.end_byte) in seen:
            return
        if depth > 3:
            complete = False
            return
        seen.add((fn.start_byte, fn.end_byte))
        for call in (d for d in resolve_descendants(fn) if d.type in CALLS and not same(d, fn)):
            a = {"file": payload["sink"]["file"], "derived_from": payload["sink"]["derived_from"],
                 "start_byte": call.start_byte, "end_byte": call.end_byte, "node_type": call.type, "sha256": ""}
            ks, kc = sink_kinds(pkg, a, call, lang)
            kinds.update(ks)
            if ks and kc:
                continue
            ds, dc = defs_for(call)
            complete = complete and dc and (kc or bool(ds))
            for d in ds:
                walk(d, depth + 1)

    roots, rc = defs_for(node)
    complete = complete and rc
    for d in roots:
        walk(d, 0)
    return kinds, complete and bool(roots)
