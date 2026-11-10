"""
Shared plumbing for the deterministic checks: the verdict shape, the per-claim work budget, and the tree walk
every check charges to it. The checks themselves live in apimatch.py (L1, L2) and witness.py (L3-L5); check_l1
and check_l2 here are the stable entry points.

Each check returns a verdict dict: {verdict, grade, reason_code, evidence, evidence_refs}.
"""
from __future__ import annotations

from contextlib import contextmanager

from tools.verify.source import Package


def result(verdict, reason=None, evidence="", refs=(), grade=None) -> dict:
    return {"verdict": verdict, "grade": grade, "reason_code": reason, "evidence": evidence,
            "evidence_refs": list(refs)}


def ancestors(node):
    n = node.parent
    while n is not None:
        yield n
        n = n.parent


# Syntax nodes one claim may visit. A count, not a clock, so a claim is cut off at the same point on every machine.
# Indexes built once per file (parse, function names, scope declarations) are not counted, so a claim's verdict
# never depends on which other claims ran before it.
CLAIM_BUDGET = 2_000_000


class BudgetExceeded(BaseException):
    """A claim walked more than its budget. A BaseException so that no `except Exception` inside a check can turn
    the cut-off into an ordinary verdict."""


class Meter:
    def __init__(self, limit: int):
        self.limit, self.left = limit, limit

    @property
    def spent(self) -> int:
        return self.limit - self.left


_meter: Meter | None = None


@contextmanager
def budget(limit: int):
    """Meter every claim-specific tree walk (they all go through _descendants) while the block runs."""
    global _meter
    prev, _meter = _meter, Meter(limit)
    try:
        yield _meter
    finally:
        _meter = prev


def spend(n: int = 1):
    """Charge n units of work to the current claim's budget (a count of nodes, never a clock), raising
    BudgetExceeded past the limit. Used by resolve/cfg/apimatch so their walks are bounded deterministically."""
    meter = _meter
    if meter is not None:
        meter.left -= n
        if meter.left < 0:
            raise BudgetExceeded()


def _descendants(node):
    meter = _meter
    stack = [node]
    while stack:
        n = stack.pop()
        if meter is not None:
            meter.left -= 1
            if meter.left < 0:
                raise BudgetExceeded()
        yield n
        stack.extend(reversed(n.children))


def logical(node) -> bool:
    if node.type == "boolean_operator":
        return True
    op = node.child_by_field_name("operator") if node.type == "binary_expression" else None
    return op is not None and op.type in ("&&", "||", "??")


def guard_test(gnode):
    """The part of a decision that tests (a branch's condition, a short-circuit's left side, a try body)."""
    t = gnode.type
    if t in ("if_statement", "elif_clause", "while_statement", "do_statement", "for_statement", "ternary_expression"):
        return gnode.child_by_field_name("condition")
    if t == "conditional_expression":
        kids = gnode.named_children
        return kids[1] if len(kids) > 1 else None
    if t in ("switch_case", "case_clause"):
        return gnode.child_by_field_name("value") or gnode
    if logical(gnode):
        return gnode.child_by_field_name("left") or gnode.named_children[0]
    if t == "try_statement":
        return gnode.child_by_field_name("body")
    return gnode


def check_l1(pkg: Package, cond: dict, rec: dict | None = None) -> dict:
    from tools.verify import apimatch
    return apimatch.check_l1(pkg, cond)


def check_l2(pkg: Package, rec: dict, cond: dict) -> dict:
    from tools.verify import apimatch
    return apimatch.check_l2(pkg, rec, cond)
