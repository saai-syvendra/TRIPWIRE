#!/usr/bin/env python3
"""
The record contract shared by the tools: schema validation, the checks the schema can't express, the gate
expression rules behind derived fields (min_conditions, the else branch's min_false), review triggers, and
where finished records live in reports/.

Imported by the analysis and verify tools and by aggregate.py and reset.py. Not a command.
"""
from __future__ import annotations

import itertools
import json
import re
import sys
from pathlib import Path

from tools.common.paths import SCHEMA

SCHEMA_VERSION = "3.2"
# Older versions that still validate. v3.2 added `inherited` on conditions, `else.requires` and analysis_type "tool".
ACCEPTED_VERSIONS = ("3.1", "3.2")
IN_SCOPE = set(json.loads(SCHEMA.read_text())["$defs"]["category_in_scope"]["enum"])
JSON_BLOCK = re.compile(r"```json\s*\n(.*?)\n```", re.S)
COND_ID = re.compile(r"\bc\d+\b")
EXPR_TOKEN = re.compile(r"c\d+|&&|\|\||[()]|\S+")
DISAGREEING = {("malicious", "benign"), ("benign", "malicious"), ("benign", "suspicious")}


def min_conditions_of(expr: str) -> int:
    """Size of the smallest set of conditions that satisfies `expr`."""
    return min(len(t) for t in dnf_terms(expr))


def min_conditions_excluding(expr: str, excluded) -> int:
    """min_conditions of `expr` when the conditions in `excluded` (e.g. the inherited ones) hold by themselves and
    so cost nothing: the smallest number of the other conditions some DNF term still needs. 0 when a term consists
    only of excluded conditions."""
    excluded = set(excluded)
    return min(len(t - excluded) for t in dnf_terms(expr))


def inherited_ids(rec: dict) -> set[str]:
    """Ids of the conditions flagged `inherited` (copied from the impersonated package)."""
    return {c["id"] for c in rec.get("conditions") or [] if c.get("inherited")}


def min_false_set(expr: str) -> frozenset[str]:
    """Smallest set of conditions whose falsity makes `expr` false: a minimum hitting set over its DNF terms.

    To falsify a DNF (OR of conjunctions) every term must be falsified, and a term is falsified by making one
    of its conditions false. So this is the smallest set of conditions touching every term. Expressions are
    tiny, so search by increasing size."""
    terms = list(dnf_terms(expr))
    variables = sorted(set().union(*terms))
    for size in range(1, len(variables) + 1):
        for combo in itertools.combinations(variables, size):
            picked = frozenset(combo)
            if all(picked & term for term in terms):
                return picked
    return frozenset(variables)


def min_false_of(expr: str) -> int:
    return len(min_false_set(expr))


def else_min_of(expr: str, requires=()) -> int:
    """min_conditions of an else branch: the conditions in `requires` hold (the enclosing guards the else side
    still sits inside), plus the fewest of the others whose falsity makes every DNF term false. Raises ValueError
    when `requires` alone satisfies a term (the expression could then never be false there)."""
    req = set(requires)
    terms = [t - req for t in dnf_terms(expr)]
    if any(not t for t in terms):
        raise ValueError(f"else.requires {sorted(req)} satisfies the expression, so it cannot be false")
    variables = sorted(set().union(*terms))
    for size in range(1, len(variables) + 1):
        for combo in itertools.combinations(variables, size):
            if all(set(combo) & t for t in terms):
                return len(req) + size
    return len(req) + len(variables)


def dnf_terms(expr: str) -> set[frozenset[str]]:
    """`expr` (grammar: cN, &&, ||, parentheses) as alternative sets of condition ids that must all hold."""
    tokens = EXPR_TOKEN.findall(expr)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def take(expected=None):
        nonlocal pos
        tok = peek()
        if tok is None or (expected and tok != expected):
            raise ValueError(f"expected {expected or 'a condition'} at token {pos + 1} of {expr!r}")
        pos += 1
        return tok

    def disjunction():
        terms = conjunction()
        while peek() == "||":
            take("||")
            terms = terms | conjunction()
        return terms

    def conjunction():
        terms = atom()
        while peek() == "&&":
            take("&&")
            right = atom()
            terms = {a | b for a in terms for b in right}
        return terms

    def atom():
        tok = take()
        if tok == "(":
            terms = disjunction()
            take(")")
            return terms
        if re.fullmatch(r"c\d+", tok):
            return {frozenset([tok])}
        raise ValueError(f"unexpected {tok!r} in {expr!r}")

    terms = disjunction()
    if peek() is not None:
        raise ValueError(f"unexpected {peek()!r} in {expr!r}")
    return terms


def gate_branches(gate: dict) -> list[dict]:
    """The gate's present branches: `then` always, `else` when it is not null."""
    return [gate["then"]] + ([gate["else"]] if gate.get("else") else [])


def review_triggers(rec: dict) -> list[str]:
    """Reasons that force needs_manual_review (SKILL.md, Assessment step)."""
    reasons = []
    if any(c["value_recovered"] in ("partial", "not_recovered") for c in rec["conditions"]):
        reasons.append("condition value not fully recovered")
    if rec["obfuscation"]["unrecovered"]:
        reasons.append("unrecovered code")
    if any(br["recipe_guessed_fields"] for g in rec["gates"] for br in gate_branches(g)):
        reasons.append("guessed recipe fields")
    if rec["confidence"] == "low":
        reasons.append("low confidence")
    if rec["label_disagreement"]:
        reasons.append("label disagreement")
    if out_of_set_ids(rec):
        reasons.append("out-of-set claim pending verification")
    if any(p.get("unresolved") for g in rec["gates"] for br in gate_branches(g) for p in br["payload"]):
        reasons.append("payload path not fully traced")
    return reasons


def condition_provenance(cond: dict) -> str:
    """in_set when every site is a generator candidate; an analyst-added site makes the condition out_of_set."""
    return "in_set" if all(site.get("candidate") for site in cond["sites"]) else "out_of_set"


def gate_provenance(gate: dict, conds: dict) -> str:
    """in_set when every guard is a generator candidate (a resolve gate: when all its conditions are)."""
    if gate["hook"] == "resolve":
        ids = COND_ID.findall(gate["expression"])
        return "in_set" if all(conds.get(i, {}).get("provenance") == "in_set" for i in ids) else "out_of_set"
    guards = gate.get("guards") or []
    return "in_set" if guards and all(g.get("candidate") for g in guards) else "out_of_set"


def out_of_set_ids(rec: dict) -> list[str]:
    return [c["id"] for c in rec["conditions"] if c.get("provenance") == "out_of_set"] + \
        [g["gate_id"] for g in rec["gates"] if g.get("provenance") == "out_of_set"]


def iter_anchors(value, path=""):
    """(json path, anchor) for every anchor in a record; an anchor is any object with start_byte and sha256."""
    if isinstance(value, dict):
        if "start_byte" in value and "sha256" in value:
            yield path, value
            return
        for k, v in value.items():
            yield from iter_anchors(v, f"{path}/{k}" if path else k)
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from iter_anchors(v, f"{path}/{i}")


def label_disagrees(rec: dict) -> bool:
    """Label and assessment pairs that always count as a disagreement; the analyst may flag others."""
    return (rec["package"]["source_label"], rec["claude_assessment"]) in DISAGREEING


def load_validator():
    try:
        import jsonschema
    except ImportError:
        print("error: jsonschema is not installed (pip install -r tools/requirements.txt)", file=sys.stderr)
        sys.exit(2)
    if not hasattr(jsonschema, "Draft202012Validator"):
        print("error: jsonschema is too old, need >= 4.18 (pip install -U -r tools/requirements.txt)",
              file=sys.stderr)
        sys.exit(2)
    schema = json.loads(SCHEMA.read_text())
    # Validate against the branch named by record_type, so errors point at the actual field.
    branches = {}
    for rt, ref in (("analysed", "#/$defs/analysed"), ("skip", "#/$defs/skipped"), ("member", "#/$defs/member")):
        s = {k: v for k, v in schema.items() if k != "oneOf"}
        s["$ref"] = ref
        branches[rt] = jsonschema.Draft202012Validator(s)

    class _V:
        def iter_errors(self, rec):
            v = branches.get(rec.get("record_type"))
            if v is None:
                return iter([jsonschema.ValidationError("record_type must be 'analysed', 'skip' or 'member'")])
            return v.iter_errors(rec)
    return _V()


def version_errors(rec: dict) -> list[str]:
    """Fields a record may only carry from the schema version that introduced them."""
    errs = []
    if rec.get("schema_version") == "3.1":
        if (rec.get("package") or {}).get("analysis_type") == "tool":
            errs.append("package/analysis_type: 'tool' needs schema_version 3.2")
        if any("inherited" in c for c in rec.get("conditions") or []):
            errs.append("conditions: 'inherited' needs schema_version 3.2")
        if any((g.get("else") or {}).get("requires") for g in rec.get("gates") or []):
            errs.append("gates: 'else.requires' needs schema_version 3.2")
    if rec.get("record_type") == "analysed" and (rec.get("package") or {}).get("analysis_type") == "tool":
        errs.append("package/analysis_type: 'tool' is only for skip and member records the tools write")
    return errs


def consistency_errors(rec: dict) -> list[str]:
    """Checks the schema can't express."""
    errs = version_errors(rec)
    if rec.get("record_type") != "analysed":
        return errs
    for kind, items, key in (("condition", rec["conditions"], "id"), ("gate", rec["gates"], "gate_id")):
        ids = [i[key] for i in items]
        for dup in sorted({i for i in ids if ids.count(i) > 1}):
            errs.append(f"duplicate {kind} id {dup}")
    conds = {c["id"]: c for c in rec["conditions"]}
    hooks = {e["hook"] for e in rec["execution"]["entry_points"]} | {"resolve"}
    used = set()
    for c in conds.values():
        if c["in_scope"] != (c["category"] in IN_SCOPE):
            errs.append(f"{c['id']}: in_scope={c['in_scope']} but category '{c['category']}'")
    seen = {}
    for g in rec["gates"]:
        ids = set(COND_ID.findall(g["expression"]))
        missing = ids - conds.keys()
        if missing:
            errs.append(f"{g['gate_id']}: expression uses unknown {sorted(missing)}")
        try:
            expected = min_conditions_of(g["expression"])
            if g["then"]["min_conditions"] != expected:
                errs.append(f"{g['gate_id']}: then.min_conditions {g['then']['min_conditions']} but expression "
                            f"gives {expected}")
            if g["then"].get("requires"):
                errs.append(f"{g['gate_id']}: requires belongs on the else branch only")
            if g["else"] is not None:
                req = g["else"].get("requires") or []
                if set(req) - ids:
                    errs.append(f"{g['gate_id']}: else.requires {sorted(set(req) - ids)} not in the expression")
                want = else_min_of(g["expression"], req)
                if g["else"]["min_conditions"] != want:
                    errs.append(f"{g['gate_id']}: else.min_conditions {g['else']['min_conditions']} but the else "
                                f"side needs {want}")
        except ValueError as e:
            errs.append(f"{g['gate_id']}: bad expression: {e}")
        if g["hook"] not in hooks:
            errs.append(f"{g['gate_id']}: hook '{g['hook']}' is not an entry point hook or 'resolve'")
        used |= ids
        key = (g["hook"], g["expression"].replace(" ", ""))
        if key in seen:
            errs.append(f"{g['gate_id']}: same hook+expression as {seen[key]} (merge them)")
        seen[key] = g["gate_id"]
    for cid in conds.keys() - used:
        errs.append(f"{cid}: condition not used by any gate")
    behind_gates = {b for g in rec["gates"] for br in gate_branches(g) for b in br["behaviours"]}
    if set(rec["behaviours"]["gated"]) != behind_gates:
        errs.append(f"behaviours.gated {sorted(set(rec['behaviours']['gated']))} != gates' then and else "
                    f"behaviours {sorted(behind_gates)}")
    errs += anchor_errors(rec, conds)
    if label_disagrees(rec) and not rec["label_disagreement"]:
        errs.append(f"label_disagreement must be true for source label "
                    f"'{rec['package']['source_label']}' and assessment '{rec['claude_assessment']}'")
    triggers = review_triggers(rec)
    if triggers and not rec["needs_manual_review"]:
        errs.append(f"needs_manual_review must be true: {'; '.join(triggers)}")
    return errs


def anchor_errors(rec: dict, conds: dict) -> list[str]:
    """v3 grounding rules: anchors name known derivations, gates name their guards, branches name their
    payload, and provenance matches the sites and guards."""
    errs = []
    derivations = {d["id"] for d in rec["normalisation"]["derivations"]}
    for d in rec["normalisation"]["derivations"]:
        if d["input"]["derived_from"] is not None and d["input"]["derived_from"] not in derivations:
            errs.append(f"derivation {d['id']}: input derived_from {d['input']['derived_from']} is not a derivation")
    for path, a in iter_anchors({k: v for k, v in rec.items() if k != "normalisation"}):
        if a["derived_from"] is not None and a["derived_from"] not in derivations:
            errs.append(f"{path}: derived_from {a['derived_from']} is not in normalisation.derivations")
        if a["start_byte"] > a["end_byte"]:
            errs.append(f"{path}: start_byte after end_byte")
    for c in rec["conditions"]:
        if c["provenance"] != condition_provenance(c):
            errs.append(f"{c['id']}: provenance {c['provenance']} but its sites say {condition_provenance(c)}")
    for g in rec["gates"]:
        gid, expr_ids = g["gate_id"], set(COND_ID.findall(g["expression"]))
        if g["provenance"] != gate_provenance(g, conds):
            errs.append(f"{gid}: provenance {g['provenance']} but its guards say {gate_provenance(g, conds)}")
        if g["hook"] == "resolve":
            continue
        if not g["guards"]:
            errs.append(f"{gid}: no guards; cite the if/early exit/try that holds the conditions")
        guarded = {c for guard in g["guards"] for c in guard["conditions"]}
        if guarded != expr_ids:
            errs.append(f"{gid}: guards hold {sorted(guarded)} but the expression uses {sorted(expr_ids)}")
        for name in ("then", "else"):
            br = g[name]
            if br is None or not br["behaviours"]:
                continue
            if not br["regions"]:
                errs.append(f"{gid}.{name}: behaviours but no regions")
            if not br["payload"]:
                errs.append(f"{gid}.{name}: behaviours but no payload sink")
            extra = {p["behaviour"] for p in br["payload"]} - set(br["behaviours"])
            if extra:
                errs.append(f"{gid}.{name}: payload behaviours {sorted(extra)} are not in the branch behaviours")
    return errs


def validation_errors(validator, rec: dict) -> list[str]:
    # Consistency checks index fields directly, so they only run on schema-valid records.
    errs = [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in validator.iter_errors(rec)]
    return errs or consistency_errors(rec)


def key_for(ecosystem: str, name: str, version: str | None) -> str:
    """scratch/<key>/ and the _skipped/_members file stem."""
    return f"{ecosystem}__{name.replace('/', '__')}@{version or 'unknown'}"


def normalise_name(ecosystem: str, name: str) -> str:
    """The name two records of one package share. PyPI names compare per PEP 503 (case-insensitive, runs of
    `-`, `_` and `.` equal); npm names compare exactly. Records keep the name as the package spells it."""
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "pypi" else name


def existing_record(reports: Path, ecosystem: str, name: str, version: str | None) -> Path | None:
    """The finished report, skip record or member record for this package version, if one exists. A PyPI name
    matches any spelling that normalises to the same name (PEP 503)."""
    stem = f"{name.replace('/', '__')}@{version or 'unknown'}"
    candidates = [(reports / ecosystem, f"{stem}.md"), (reports / "_skipped", f"{ecosystem}__{stem}.json"),
                  (reports / "_members", f"{ecosystem}__{stem}.json")]
    for folder, file in candidates:
        if (folder / file).exists():
            return folder / file
    if ecosystem != "pypi":
        return None
    want = (normalise_name(ecosystem, name), version or "unknown")
    for folder, file in candidates:
        prefix = "" if folder.name == ecosystem else f"{ecosystem}__"
        for p in sorted(folder.glob(f"{prefix}*@{glob_escape(version or 'unknown')}{Path(file).suffix}")):
            other, _, ver = p.name[len(prefix):-len(p.suffix)].rpartition("@")
            if (normalise_name(ecosystem, other), ver) == want:
                return p
    return None


def glob_escape(s: str) -> str:
    return re.sub(r"([*?\[])", r"[\1]", s)


def read_record(path: Path) -> dict:
    """The record in a report (last ```json block of a .md) or a JSON record file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".md":
        blocks = JSON_BLOCK.findall(text)
        if not blocks:
            raise ValueError(f"{path}: no ```json block")
        text = blocks[-1]
    return json.loads(text)


def report_path(reports: Path, ecosystem: str, name: str, version: str) -> Path:
    return reports / ecosystem / f"{name.replace('/', '__')}@{version}.md"
