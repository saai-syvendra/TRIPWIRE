"""
Soundness harness for the deterministic checker: small, inert synthetic packages held in memory, claims built
against them, and the checker's real dispatch (verify.package_verdicts) run over them.

The contract every case checks (layers.md): a true claim may come out verified or cannot_tell, never refuted; a
false claim (a hand-written false claim or a mutant of a true one) may come out refuted or cannot_tell, never
verified; and no claim may hit a checker fault. A case may also pin the verdict it expects, so the checker cannot
pass by leaving everything open.

Nothing here is real package code: every snippet is a few lines written for the test, with placeholder commands
and reserved hosts.
"""
from __future__ import annotations

import copy
import textwrap

from tools.common import anchors
from tools.common.tables import NEGATE
from tools.verify import verify
from tools.verify.source import Package, Unanchored


class MemPackage(Package):
    """A Package whose files live in memory (no sample archive, no unpacking)."""

    def __init__(self, files: dict[str, str]):
        self.key = "npm__mem@0.0.0"
        self.derivations, self._bytes, self._trees, self._failed, self.cache = {}, {}, {}, {}, {}
        self.files = {name: textwrap.dedent(src).lstrip("\n").encode() for name, src in files.items()}

    def source_files(self) -> list[str]:
        return sorted(self.files)

    def _read(self, file: str) -> bytes:
        if file not in self.files:
            raise Unanchored("no_anchor", f"{file} is not in the package")
        return self.files[file]


def default_file(pkg: MemPackage) -> str:
    return next(iter(pkg.files))


def _offset(src: bytes, snippet: str, nth: int) -> int:
    start = -1
    for _ in range(nth + 1):
        start = src.find(snippet.encode(), start + 1)
        if start < 0:
            raise AssertionError(f"snippet {snippet!r} (occurrence {nth}) not in the test file")
    return start


def at(pkg: MemPackage, snippet: str, node_type: str | None = None, file: str | None = None, nth: int = 0) -> dict:
    """Anchor on the syntax node spanning exactly SNIPPET (the innermost one, or the one of NODE_TYPE)."""
    file = file or default_file(pkg)
    src, tree, _ = pkg.tree(file, None)
    start = _offset(src, snippet, nth)
    end = start + len(snippet.encode())
    n = tree.root_node.descendant_for_byte_range(start, end)
    exact = []
    while n is not None and (n.start_byte, n.end_byte) == (start, end):
        exact.append(n)
        n = n.parent
    if not exact:
        raise AssertionError(f"no node spans {snippet!r} exactly")
    node = next((x for x in exact if x.type == node_type), None) if node_type else exact[0]
    if node is None:
        raise AssertionError(f"no {node_type} spans {snippet!r}; found {[x.type for x in exact]}")
    return anchors.node_anchor(file, src, node)


def enclosing(pkg: MemPackage, snippet: str, node_type: str, file: str | None = None, nth: int = 0) -> dict:
    """Anchor on the innermost NODE_TYPE node that contains SNIPPET."""
    file = file or default_file(pkg)
    src, tree, _ = pkg.tree(file, None)
    start = _offset(src, snippet, nth)
    n = tree.root_node.descendant_for_byte_range(start, start + len(snippet.encode()))
    while n is not None and n.type != node_type:
        n = n.parent
    if n is None:
        raise AssertionError(f"no {node_type} encloses {snippet!r}")
    return anchors.node_anchor(file, src, n)


def stmts(pkg: MemPackage, first: str, last: str | None = None, file: str | None = None) -> dict:
    """A stmt_range anchor from the statement holding FIRST to the statement holding LAST (default: FIRST's)."""
    file = file or default_file(pkg)
    src, tree, _ = pkg.tree(file, None)

    def statement(snippet):
        start = _offset(src, snippet, 0)
        n = tree.root_node.descendant_for_byte_range(start, start + len(snippet.encode()))
        while n.parent is not None and n.parent.type not in ("program", "module", "statement_block", "block"):
            n = n.parent
        return n
    a, b = statement(first), statement(last or first)
    return anchors.span_anchor(file, src, a, b) if (a.start_byte, a.end_byte) != (b.start_byte, b.end_byte) else \
        anchors.range_anchor(file, src, a.start_byte, a.end_byte, anchors.RANGE)


# --- claim builders --------------------------------------------------------------------------------------

def cond(cid: str, api: str, operator: str, value, sites: list[dict], category: str = "os",
         recovered: str = "plain", probe: dict | None = None, value_site: dict | None = None) -> dict:
    c = {"id": cid, "category": category, "api": api, "operator": operator, "value": value,
         "value_recovered": recovered, "in_scope": True, "provenance": "out_of_set",
         "sites": [{"candidate": None, "anchor": s} for s in sites]}
    if probe:
        c["probe"] = probe
    if value_site:
        c["value_site"] = value_site
    return c


def guard(site: dict, kind: str = "if", arm: str = "then", conds=("c1",), via: list[dict] | None = None) -> dict:
    g = {"candidate": None, "site": site, "kind": kind, "arm": arm, "conditions": list(conds)}
    if via:
        g["via"] = via
    return g


def hop(kind: str, anchor: dict) -> dict:
    return {"hop": kind, "anchor": anchor}


def payload(sink: dict, behaviour: str = "spawn_process", kind: str = "exec", witness=(),
            unresolved: str | None = None) -> dict:
    p = {"behaviour": behaviour, "sink_kind": kind, "sink": sink, "witness": list(witness)}
    if unresolved:
        p["unresolved"] = unresolved
    return p


def branch(regions: list[dict], payloads: list[dict], behaviours=None, min_conditions: int = 1) -> dict:
    return {"min_conditions": min_conditions,
            "behaviours": behaviours if behaviours is not None else sorted({p["behaviour"] for p in payloads}),
            "env_recipe": {}, "recipe_guessed_fields": [], "regions": regions, "payload": payloads}


def gate(guards: list[dict], expression: str, then: dict, else_: dict | None = None, gid: str = "g1") -> dict:
    return {"gate_id": gid, "hook": "postinstall", "expression": expression, "guards": guards,
            "provenance": "out_of_set", "polarity": "activate", "effect": "enables", "purpose": "targeting",
            "purpose_reason": "test", "then": then, "else": else_}


def record(conditions: list[dict], gates: list[dict]) -> dict:
    return {"record_type": "analysed", "package": {"ecosystem": "npm", "name": "mem", "version": "0.0.0"},
            "conditions": conditions, "gates": gates, "normalisation": {"derivations": []},
            "candidate_review": {"dropped": []}}


def run(pkg: MemPackage, rec: dict) -> dict[str, dict]:
    return {v["claim_id"]: v for v in verify.package_verdicts(pkg, rec)}


# --- the contract --------------------------------------------------------------------------------------

def faults(verdicts: dict[str, dict]) -> list[str]:
    return [f"{cid}: {v['evidence']}" for cid, v in verdicts.items() if v["reason_code"] == "checker_error"]


def show(v: dict) -> str:
    return f"{v['verdict']} ({v['reason_code']}): {v['evidence']}"


def mutants(rec: dict) -> list[tuple[str, dict, list[str]]]:
    """False variants of a true record: (description, mutated record, claim ids that must not verify)."""
    out = []
    for i, c in enumerate(rec["conditions"]):
        cid = c["id"]
        if c["value_recovered"] != "not_recovered" and c["operator"] in NEGATE:
            m = copy.deepcopy(rec)
            m["conditions"][i]["operator"] = NEGATE[c["operator"]]
            out.append((f"{cid} operator negated", m, [f"{cid}.L2"]))
        if c["value_recovered"] != "not_recovered" and isinstance(c["value"], str):
            m = copy.deepcopy(rec)
            m["conditions"][i]["value"] = "zz-absent-value"
            out.append((f"{cid} value swapped", m, [f"{cid}.L2"]))
        if not c.get("probe"):
            m = copy.deepcopy(rec)
            m["conditions"][i]["api"] = "os.uptime()" if "uptime" not in c["api"] else "os.hostname()"
            out.append((f"{cid} api swapped", m, [f"{cid}.L1"]))
    for gi, g in enumerate(rec["gates"]):
        gid = g["gate_id"]
        if len(g["guards"]) == 1 and g["then"].get("payload"):
            # flipping the only guard's arm moves the region off the single side that controls it; with several
            # guards another may still control the region, so the inconsistency shows at L4, not L3
            m = copy.deepcopy(rec)
            q = g["guards"][0]
            m["gates"][gi]["guards"][0]["arm"] = "else" if q["arm"] == "then" else "then"
            out.append((f"{gid} guard arm flipped", m, [f"{gid}.then.L3"]))
        for pi, p in enumerate(g["then"].get("payload") or []):
            m = copy.deepcopy(rec)
            other = "network" if p["sink_kind"] != "network" else "fs_delete"
            m["gates"][gi]["then"]["payload"][pi]["sink_kind"] = other
            out.append((f"{gid} payload {pi} sink kind swapped", m, [f"{gid}.then.L5"]))
        if "&&" in g["expression"]:
            m = copy.deepcopy(rec)
            m["gates"][gi]["expression"] = g["expression"].replace("&&", "||")
            m["gates"][gi]["then"]["min_conditions"] = 1
            out.append((f"{gid} and turned into or", m, [f"{gid}.L4"]))
    return out
