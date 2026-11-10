"""
Structured control dependence for the verifier: which decisions, on which arm, control a piece of code, and
whether one statement always runs before another, within a single function (or a module/script top level).

The checker uses this to decide L3 (is a payload region on the side of the gate the guard claims), early-exit
polarity for L2, and witness reachability (a call that sits in a nested function nobody calls, or after an
unconditional exit, does not run). It is a *structured* model: it walks the statement tree of one function and,
for every node, records the branch edges that must be taken to reach it. It is sound for the constructs it
models; any construct it does not model (a labelled break/continue leaving the region, `with`, a `goto`-like
form, an unmodelled node where control branches) marks that function's model `complete = False`, and every
query over it then answers `unknown` so the checker falls back to `cannot_tell` rather than guessing.

An edge is `(decision_node, arm)` where arm is "then" or "else" (for a loop, "then" is the body; for try, "then"
is the body and "else" a handler; for switch, each case is its own decision). Control dependence here is the
structured form of the post-dominator definition (Ferrante et al. 1987): a node is control-dependent on an edge
when every path from the decision to the node takes that edge and the node does not post-dominate the decision.

Nothing is executed; the tree comes from tree-sitter.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from tools.common.tsparse import field as child, member_object, static_member_name, text
from tools.verify.resolve import FUNCTIONS, ancestors, unwrap

# Statements that end straight-line flow out of the enclosing block.
RETURNS = {"return_statement"}
THROWS = {"throw_statement", "raise_statement"}
LOOP_JUMPS = {"break_statement", "continue_statement"}
BLOCKS = {"statement_block", "block"}
# Nodes we know how to walk for control. Anything else inside a function (that is not a leaf expression) makes the
# model incomplete.
BRANCHERS = {"if_statement", "while_statement", "do_statement", "for_statement", "for_in_statement",
             "switch_statement", "try_statement", "ternary_expression", "conditional_expression",
             "match_statement", "with_statement"}
PROCESS_EXIT = {"process": {"exit", "abort"}, "sys": {"exit"}, "os": {"_exit", "abort"}}


@dataclass(eq=False)
class Flow:
    """How control leaves a straight-line sequence: fallthrough (next statement runs), or it stops."""
    kind: str  # fall, return, throw, process_exit, loop_jump, unknown
    complete: bool = True


@dataclass
class Edge:
    decision: object
    arm: str


@dataclass
class ControlModel:
    fn: object
    lang: str
    guards: dict = field(default_factory=dict)  # node key -> list[Edge] controlling that node
    flows: dict = field(default_factory=dict)   # node key -> Flow for that statement
    complete: bool = True


def nkey(node) -> tuple:
    return (node.start_byte, node.end_byte)


def enclosing_function(node, index=None):
    """The function or lambda a node sits in, or the module root if none."""
    for a in ancestors(node):
        if a.type in FUNCTIONS:
            return a
        if a.type in ("program", "module"):
            return a
    return None


def is_process_exit(node, resolve_ctx=None) -> bool:
    """A call that stops the whole process: process.exit/abort, sys.exit, os._exit, bare exit()/quit()."""
    node = unwrap(node)
    if node is None or node.type not in ("call_expression", "call"):
        return False
    fn = node.child_by_field_name("function")
    if fn is None:
        return False
    if fn.type == "identifier":
        return text(fn) in ("exit", "quit")
    obj, prop = member_object(fn), static_member_name(fn)
    base = text(obj) if obj is not None and obj.type == "identifier" else None
    return base in PROCESS_EXIT and prop in PROCESS_EXIT.get(base, ())


class Builder:
    def __init__(self, fn, lang: str):
        self.m = ControlModel(fn, lang)

    def build(self) -> ControlModel:
        body = self._body(self.m.fn)
        if body is None:
            self.m.complete = False
            return self.m
        self._seq(list(self._statements(body)), [])
        return self.m

    def _body(self, fn):
        if fn.type in ("program", "module"):
            return fn
        b = fn.child_by_field_name("body")
        return b

    def _statements(self, block):
        if block.type in BLOCKS or block.type in ("program", "module"):
            return [c for c in block.named_children if c.type not in ("comment",)]
        return [block]

    def _incomplete(self):
        self.m.complete = False

    def _seq(self, stmts, guards) -> Flow:
        """Walk a straight-line sequence under `guards`; return how it leaves (fall / stop). A conditional exit
        earlier in the sequence (an `if (c) return;` with no else, or `c || exit();`) guards every statement
        after it with the edge on which control falls through, which is how structured code expresses a gate."""
        flow = Flow("fall")
        extra = []  # edges every later statement in this sequence is control-dependent on
        for s in stmts:
            if flow.kind == "unknown":
                # an unmodelled statement may or may not fall through: the model is already incomplete, but the
                # statements after it are still walked so their nesting (which is sound on its own) is recorded
                flow = Flow("fall")
            if flow.kind != "fall":
                self._assign(s, guards + extra, reachable=False)
                continue
            self._pending = None
            flow = self._stmt(s, guards + extra)
            if self._pending is not None:
                extra = extra + [self._pending]
                self._pending = None
        return Flow("fall") if extra and flow.kind == "fall" else flow

    _pending = None

    def _assign(self, node, guards, reachable=True):
        self.m.guards[nkey(node)] = list(guards)
        if not reachable:
            self.m.flows[nkey(node)] = Flow("return")  # treated as not-falling-through

    def _stmt(self, s, guards) -> Flow:
        self.m.guards[nkey(s)] = list(guards)
        t = s.type
        if t in RETURNS:
            return Flow("return")
        if t in THROWS:
            return Flow("throw")
        if t in LOOP_JUMPS:
            return Flow("loop_jump")
        if t == "expression_statement" and s.named_children:
            expr = unwrap(s.named_children[0])
            if is_process_exit(expr, self.m.lang):
                return Flow("process_exit")
            if expr is not None and expr.type in ("binary_expression", "boolean_operator"):
                return self._short_circuit_stmt(expr, guards)
            return Flow("fall")
        if t == "if_statement":
            return self._if(s, guards)
        if t in ("statement_block", "block"):
            return self._seq(list(self._statements(s)), guards)
        if t == "try_statement":
            return self._try(s, guards)
        if t in ("while_statement", "do_statement", "for_statement", "for_in_statement"):
            return self._loop(s, guards)
        if t == "switch_statement":
            return self._switch(s, guards)
        if t in ("lexical_declaration", "variable_declaration", "import_statement", "import_from_statement",
                 "assignment", "augmented_assignment", "export_statement", "function_declaration",
                 "class_declaration", "class_definition", "empty_statement", "labeled_statement", "pass_statement",
                 "global_statement", "nonlocal_statement", "print_statement", "assert_statement",
                 "delete_statement", "comment", "hash_bang_line", "decorated_definition", "future_import_statement",
                 "generator_function_declaration", "debugger_statement"):
            # straight-line; function/class declarations do not run their body here (handled as their own function)
            if t == "labeled_statement":
                self._incomplete()  # a labelled break/continue may leave an outer region; be safe
            return Flow("fall")
        if t == "with_statement":
            return self._with(s, guards)
        if t in ("match_statement",):
            self._incomplete()
            return Flow("unknown", complete=False)
        # Unknown statement: record it, mark incomplete, assume it may or may not fall through.
        self._incomplete()
        return Flow("unknown", complete=False)

    def _with(self, s, guards) -> Flow:
        """Python `with`: the body runs once, under the same guards. Its context manager may swallow an exception,
        so a body that stops by raising (or by sys.exit, which raises) is not a definite stop. JS `with` changes
        name resolution, so its model is incomplete, but its body is still walked for nesting."""
        body = s.child_by_field_name("body") or next((c for c in s.named_children if c.type in BLOCKS), None)
        if self.m.lang != "py" or body is None:
            self._incomplete()
            if body is not None:
                self._seq(list(self._statements(body)), guards)
            return Flow("unknown", complete=False)
        flow = self._seq(list(self._statements(body)), guards)
        if flow.kind in ("throw", "process_exit"):
            self._incomplete()
            return Flow("unknown", complete=False)
        return flow

    def _walk_children_as_guarded(self, node, guards):
        for c in node.named_children:
            self.m.guards.setdefault(nkey(c), list(guards))

    def _if(self, s, guards) -> Flow:
        cons = s.child_by_field_name("consequence")
        then_flow = self._seq(list(self._statements(cons)), guards + [Edge(s, "then")]) if cons is not None \
            else Flow("fall")
        elifs = [c for c in s.named_children if c.type == "elif_clause"]
        else_clause = next((c for c in s.named_children if c.type == "else_clause"), None)
        alt = s.child_by_field_name("alternative")  # JS: else_clause or an if_statement (else-if)
        has_else = bool(elifs) or else_clause is not None or alt is not None
        eguards = guards + [Edge(s, "else")]
        if elifs:  # Python elif chain (then an optional else block)
            else_flow = self._elif_chain(s, elifs, else_clause, eguards)
        elif else_clause is not None:  # else_clause holds either an `else if` (an if_statement) or a block
            inner = next((c for c in else_clause.named_children if c.type != "comment"), None)
            if inner is not None and inner.type == "if_statement":
                else_flow = self._stmt_under(inner, eguards)
            elif inner is not None:
                else_flow = self._seq(list(self._statements(inner)), eguards)
            else:
                else_flow = Flow("fall")
        elif alt is not None:  # JS without an else_clause wrapper
            if alt.type == "if_statement":
                else_flow = self._stmt_under(alt, eguards)
            else:
                else_flow = self._seq(list(self._statements(alt)), eguards)
        else:
            else_flow = Flow("fall")
        # Early exit: when one arm always stops and the other falls through, the code after this `if` is
        # control-dependent on the falling-through arm's edge. Signal that to the enclosing sequence.
        stops = {"return", "throw", "process_exit", "loop_jump"}
        then_flow, else_flow = (then_flow, else_flow) if then_flow.complete and else_flow.complete else \
            (Flow("unknown", False), Flow("unknown", False))
        if then_flow.kind in stops and else_flow.kind == "fall":
            self._pending = Edge(s, "else")
            return Flow("fall")
        if else_flow.kind in stops and then_flow.kind == "fall" and alt is not None:
            self._pending = Edge(s, "then")
            return Flow("fall")
        return self._join(then_flow, else_flow, has_else=alt is not None)

    def _elif_chain(self, if_stmt, elifs, else_clause, guards) -> Flow:
        """Python's else side: each elif's body is on a deeper else edge; the else block is the final else."""
        flows = []
        acc = guards
        for e in elifs:
            cons = e.child_by_field_name("consequence")
            if cons is not None:
                flows.append(self._seq(list(self._statements(cons)), acc + [Edge(e, "then")]))
            acc = acc + [Edge(e, "else")]
        if else_clause is not None:
            body = next((c for c in else_clause.named_children if c.type in BLOCKS), None)
            if body is not None:
                flows.append(self._seq(list(self._statements(body)), acc))
        else:
            flows.append(Flow("fall"))  # no final else: that path falls through
        return self._join(*flows, has_else=True) if flows else Flow("fall")

    def _stmt_under(self, s, guards) -> Flow:
        """A single statement (an else-if's inner if) under the given guards. An early exit inside it guards only
        what follows within that arm, never the code after the enclosing if, so its pending edge is dropped."""
        self.m.guards[nkey(s)] = list(guards)
        flow = self._if(s, guards) if s.type == "if_statement" else self._stmt(s, guards)
        self._pending = None
        return flow

    def _join(self, *flows, has_else=True) -> Flow:
        if not has_else:
            return Flow("fall")  # the missing else falls through
        if any(not f.complete for f in flows):
            return Flow("unknown", complete=False)
        kinds = {f.kind for f in flows}
        if kinds == {"return"} or kinds <= {"return", "throw", "process_exit", "loop_jump"} and "fall" not in kinds:
            # both arms stop; the strongest guarantee for the process is process_exit only if all do
            if kinds <= {"process_exit"}:
                return Flow("process_exit")
            return Flow("return")
        return Flow("fall")

    def _short_circuit_stmt(self, expr, guards) -> Flow:
        """`cond && f()` or `cond || exit()` as a statement: the right side is guarded, and if it is an exit the
        statement stops the process when the guard allows it to run — but not unconditionally, so flow still
        falls through (the exit is conditional)."""
        op = text(expr.child_by_field_name("operator") or expr)
        right = expr.child_by_field_name("right") or (expr.named_children[-1] if expr.named_children else None)
        arm = "then" if op in ("&&", "and") else "else"
        if right is not None:
            self.m.guards[nkey(right)] = guards + [Edge(expr, arm)]
            if is_process_exit(right, self.m.lang):
                # `A || process.exit()`: reaching the next statement means A held (the opposite arm of the exit).
                self._pending = Edge(expr, "then" if arm == "else" else "else")
        return Flow("fall")

    def _try(self, s, guards) -> Flow:
        body = s.child_by_field_name("body")
        handlers = [c for c in s.named_children if c.type in ("catch_clause", "except_clause")]
        finalizer = next((c for c in s.named_children if c.type in ("finally_clause",)), None)
        if body is not None:
            self._seq(list(self._statements(body)), guards + [Edge(s, "then")])
        for h in handlers:
            hbody = h.child_by_field_name("body") or next((c for c in h.named_children if c.type in BLOCKS), None)
            if hbody is not None:
                self._seq(list(self._statements(hbody)), guards + [Edge(s, "else")])
        if finalizer is not None:
            fbody = next((c for c in finalizer.named_children if c.type in BLOCKS), None)
            if fbody is not None:
                self._seq(list(self._statements(fbody)), guards)  # finally always runs: not guarded by the try
        # After try/catch, control is hard to pin down soundly; treat as fall but do not over-claim exits.
        return Flow("fall")

    def _loop(self, s, guards) -> Flow:
        body = s.child_by_field_name("body")
        if body is not None:
            self._seq(list(self._statements(body)), guards + [Edge(s, "then")])
        return Flow("fall")

    def _switch(self, s, guards) -> Flow:
        body = s.child_by_field_name("body")
        if body is None:
            self._incomplete()
            return Flow("fall")
        cases = [c for c in body.named_children if c.type in ("switch_case", "switch_default")]
        # Fall-through: a case with no terminating statement flows into the next. We model each case body under
        # its own edge; fall-through makes a later case reachable from an earlier one, which we capture by marking
        # the model's case edges and letting region checks treat a case as reachable from a preceding empty case.
        for i, c in enumerate(cases):
            stmts = [x for x in c.named_children if x.type not in ("comment",) and not self._is_case_label(x)]
            self._seq(stmts, guards + [Edge(c, "then")])
        return Flow("fall")

    def _is_case_label(self, node) -> bool:
        return node.type in ("case", "default") or (node.parent is not None and
                                                     node.parent.type in ("switch_case", "switch_default") and
                                                     node.parent.child_by_field_name("value") is not None and
                                                     nkey(node) == nkey(node.parent.child_by_field_name("value")))


def model_for(ctx, node) -> ControlModel:
    """The control model of the function (or top level) containing `node`, built once and cached."""
    fn = enclosing_function(node)
    if fn is None:
        return ControlModel(None, ctx.lang, complete=False)
    k = ("cfg.model", ctx.file, ctx.derived, nkey(fn))
    if k not in ctx.pkg.cache:
        ctx.pkg.cache[k] = Builder(fn, ctx.lang).build()
    return ctx.pkg.cache[k]


def guards_of(ctx, node) -> tuple[list, bool]:
    """(edges controlling `node`, complete). The node must be (or sit directly in) a statement of the function;
    the nearest enclosing statement's guards are used."""
    from tools.verify import checks
    checks.spend()
    m = model_for(ctx, node)
    cur = node
    while cur is not None:
        if nkey(cur) in m.guards:
            return m.guards[nkey(cur)], m.complete
        cur = cur.parent
    return [], m.complete


def controlled(ctx, decision, arm: str, target) -> str:
    """Whether `target` runs only when `decision` takes `arm`: 'yes', 'no' (it runs on the opposite arm), or
    'unknown'. Structured dominance: yes when (decision, arm) is on target's guard path; no when (decision,
    other arm) is."""
    edges, complete = guards_of(ctx, target)
    on = any(nkey(e.decision) == nkey(decision) and e.arm == arm for e in edges)
    opp = any(nkey(e.decision) == nkey(decision) and e.arm != arm for e in edges)
    if on:
        return "yes"
    if opp:
        return "no"
    if not complete:
        return "unknown"
    # decision does not control target at all: the branch is irrelevant to this node.
    return "absent"


def runs_before(ctx, a, b) -> str:
    """Does statement `a` always run before `b` in the same function, unconditionally? 'yes' / 'unknown'.
    Used to catch a sink that executes before the guard that supposedly controls it."""
    ma = model_for(ctx, a)
    if not ma.complete or enclosing_function(a) is not enclosing_function(b):
        return "unknown"
    ga, _ = guards_of(ctx, a)
    gb, _ = guards_of(ctx, b)
    if ga:  # a itself is conditional; we only assert unconditional-before
        return "unknown"
    return "yes" if a.start_byte < b.start_byte and not gb else "unknown"
