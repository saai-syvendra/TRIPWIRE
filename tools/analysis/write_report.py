#!/usr/bin/env python3
"""
Turns Claude's completed scratch/<key>/record.json and summary.md into reports/<ecosystem>/<name>@<version>.md,
or scratch/<key>/skip.json into reports/_skipped/<key>.json.

Computes the derived fields (in_scope, min_conditions, behaviours.gated, label_disagreement, review triggers,
provenance, candidate_check), copies the generator's anchors into in-set sites, checks every anchor against the
package bytes (refusing hallucinated sites, and counting them), defangs every string outside `package`, renders
the report template and validates the record before writing anything.

With --model-used ID (or the TRIPWIRE_ANALYSIS_MODEL environment variable, which run_analyses.py sets for the
session it starts) it refuses a record or skip whose model_name is not ID or whose analysis_type is not ai, so a
batch session cannot write a record under another model's name.

Usage: python tools/analysis/write_report.py scratch/<key> [--model-used MODEL_ID]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import anchors, contract, paths  # noqa: E402
from tools.common.sanitize import IPV4, defang  # noqa: E402
from tools.common.tsparse import EXTENSIONS, PARSERS  # noqa: E402

# Node types a guard of each kind may anchor. Mirrors tools/verify/witness.GUARD_TYPES (the authority);
# kept here so write-time validation stays independent of the verifier. A guard may anchor either the
# whole decision statement or its test expression, so the site is accepted when it, or an ancestor, is
# one of these types. "other" and any unlisted kind are not structurally constrained.
GUARD_NODE_TYPES = {
    "if": {"if_statement"}, "elif": {"elif_clause", "if_statement"}, "early_exit": {"if_statement"},
    "ternary": {"ternary_expression", "conditional_expression"},
    "switch_case": {"switch_case", "case_clause"}, "switch_default": {"switch_default", "case_clause"},
    "short_circuit": {"binary_expression", "boolean_operator"}, "try_except": {"try_statement"},
    "loop": {"while_statement", "for_statement", "for_in_statement", "do_statement"},
}
CALL_NODE_TYPES = {"call_expression", "call", "new_expression"}  # what a payload sink must be (witness.CALLS)
# What a bind hop may anchor (mirrors tools/verify/witness.check_bind): an object key, an assignment, a variable
# declaration, or an argument of a call.
BIND_NODE_TYPES = {"pair", "assignment_expression", "assignment", "variable_declarator"}
MODEL_ENV = "TRIPWIRE_ANALYSIS_MODEL"


def todo_paths(value, path="") -> list[str]:
    if value == "TODO":
        return [path or "(root)"]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in todo_paths(v, f"{path}/{k}" if path else k)]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in todo_paths(v, f"{path}/{i}")]
    return []


def defang_all(value):
    if isinstance(value, str):
        return defang(value)
    if isinstance(value, dict):
        return {k: defang_all(v) for k, v in value.items()}
    if isinstance(value, list):
        return [defang_all(v) for v in value]
    return value


# A host name token, plain or partly defanged, with an optional port: `api.example.com:443`, `a.b[.]com`.
HOST_TOKEN = re.compile(r"^((?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,})(:\d+)?$", re.I)


def defang_host_token(token: str) -> str:
    m = HOST_TOKEN.match(token)
    if not m:
        return token
    return m.group(1).replace("[.]", ".").replace(".", "[.]") + (m.group(2) or "")


def defang_hosts(value):
    """Network requirement values are host:port strings; defang the hosts the URL defanger cannot see."""
    if isinstance(value, list):
        return [defang_hosts(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"[^\s,;()]+", lambda m: defang_host_token(m.group(0)), value)
    return value


def defang_host_key(host: str) -> str:
    """A recipe's network axis is keyed by host:port; defang the key like a requirement host (name or IPv4)."""
    return IPV4.sub(lambda m: m.group(0).replace(".", "[.]"), defang_host_token(host))


def defang_recipe_hosts(rec: dict) -> None:
    """Defangs the network keys of every branch recipe. defang_all only reaches values, never dict keys."""
    for g in rec.get("gates", []):
        for br in contract.gate_branches(g):
            net = (br.get("env_recipe") or {}).get("network")
            if net:
                br["env_recipe"]["network"] = {defang_host_key(h): state for h, state in net.items()}


class AnchorError(ValueError):
    pass


def candidate_anchors(skeleton: dict, prepared: dict) -> dict[str, dict]:
    """Every generator candidate id with its anchor: k_ condition sites and q_ guards, from the prefilled
    skeleton and from the full candidate set in prepared.json (so an analyst can cite an unreached candidate
    the generator found but did not prefill, e.g. a gate inside a not_chained payload)."""
    cand = prepared.get("candidates") or {}
    out = {site["candidate"]: site["anchor"] for c in skeleton["conditions"] for site in c["sites"]
           if site.get("candidate")}
    out.update({site["candidate"]: site["anchor"] for c in cand.get("conditions", []) for site in c["sites"]
                if site.get("candidate")})
    out.update({g["candidate"]: g["site"] for g in cand.get("guards", [])})
    return out


def ground(rec: dict, skeleton: dict, prepared: dict) -> None:
    """Fills in-set sites and guards from the candidate set, so an analyst can cite a candidate by id."""
    known = candidate_anchors(skeleton, prepared)
    problems = []
    for c in rec["conditions"]:
        for site in c["sites"]:
            cid = site.get("candidate")
            if cid:
                if cid not in known:
                    problems.append(f"{c['id']}: unknown candidate {cid}")
                else:
                    site["anchor"] = known[cid]
    for g in rec["gates"]:
        for guard in g.get("guards") or []:
            qid = guard.get("candidate")
            if qid:
                if qid not in known:
                    problems.append(f"{g['gate_id']}: unknown guard candidate {qid}")
                else:
                    guard["site"] = known[qid]
    for d in (rec.get("candidate_review") or {}).get("dropped", []):
        if d.get("candidate") not in known:
            problems.append(f"candidate_review: unknown candidate {d.get('candidate')}")
        else:
            d["anchor"] = known[d["candidate"]]
    if problems:
        raise AnchorError("\n  ".join(problems))


def prefilled_ids(skeleton: dict) -> list[str]:
    """The candidate ids prepare.py put into the record: condition sites (k_) and gate guards (q_)."""
    ks = [s["candidate"] for c in skeleton["conditions"] for s in c["sites"] if s.get("candidate")]
    qs = [q["candidate"] for g in skeleton["gates"] for q in (g["guards"] if isinstance(g["guards"], list) else [])
          if q.get("candidate")]
    return list(dict.fromkeys(ks + qs))


def cited_ids(rec: dict) -> set[str]:
    return {s["candidate"] for c in rec["conditions"] for s in c["sites"] if s.get("candidate")} | \
        {q["candidate"] for g in rec["gates"] for q in g.get("guards") or [] if q.get("candidate")}


def undisposed(rec: dict, skeleton: dict) -> list[str]:
    """Prefilled candidates the analyst neither kept (cited) nor dropped with a reason."""
    dropped = {d["candidate"] for d in rec["candidate_review"]["dropped"]}
    done = cited_ids(rec) | dropped
    return [i for i in prefilled_ids(skeleton) if i not in done]


def source_bytes(work: Path, prepared: dict, cache: dict, file: str, derived_from: str | None) -> bytes | None:
    key = (file, derived_from)
    if key not in cache:
        root = work / "unpacked" / prepared["package"]["package_root"]
        path = work / "derived" / derived_from if derived_from else root / file
        cache[key] = path.read_bytes() if path.is_file() else None
    return cache[key]


def anchor_problems(rec: dict, work: Path, prepared: dict) -> list[tuple[str, dict, str]]:
    """(json path, anchor, reason) for every anchor whose bytes are not in the package as claimed."""
    cache, out = {}, []
    for d in rec["normalisation"]["derivations"]:
        data = source_bytes(work, prepared, cache, d["input"]["file"], d["id"])
        if data is None or anchors.digest(data) != d["output_sha256"]:
            out.append((f"normalisation/derivations/{d['id']}", {}, "derived file missing or changed"))
    for path, a in contract.iter_anchors({k: v for k, v in rec.items() if k != "normalisation"}):
        why = anchors.mismatch(a, source_bytes(work, prepared, cache, a["file"], a["derived_from"]))
        if why:
            out.append((path, a, why))
    return out


def guard_lang(file: str, derived_from: str | None, rec: dict) -> str | None:
    if derived_from:
        d = next((d for d in rec["normalisation"]["derivations"] if d["id"] == derived_from), {})
        if d.get("recipe") == "inline_script":
            return "py" if str(d.get("params", {}).get("flag", "")).startswith("-c") else "js"
        if d.get("recipe") == "decode_spec" and d.get("params", {}).get("lang"):
            return d["params"]["lang"]
    return EXTENSIONS.get(Path(file).suffix.lower())


def node_at(src: bytes, lang: str, a: dict):
    tree = PARSERS[lang].parse(src)
    n = tree.root_node.descendant_for_byte_range(a["start_byte"], a["end_byte"])
    while n is not None and (n.start_byte, n.end_byte) == (a["start_byte"], a["end_byte"]):
        if n.type == a["node_type"]:
            return n
        n = n.parent
    return None


def decision_test(n):
    """The tested part of a decision node. Mirrors tools/verify/checks.guard_test (the authority)."""
    t = n.type
    if t in ("if_statement", "elif_clause", "while_statement", "do_statement", "for_statement", "ternary_expression"):
        return n.child_by_field_name("condition")
    if t == "conditional_expression":
        kids = n.named_children
        return kids[1] if len(kids) > 1 else None
    if t in ("switch_case", "case_clause"):
        return n.child_by_field_name("value") or n
    op = n.child_by_field_name("operator") if t == "binary_expression" else None
    if t == "boolean_operator" or (op is not None and op.type in ("&&", "||", "??")):
        return n.child_by_field_name("left") or n.named_children[0]
    if t == "try_statement":
        return n.child_by_field_name("body")
    return n


def governs(node, types: set) -> bool:
    """The node is a decision of one of `types`, or the test of one. Mirrors tools/verify/witness.decision_node:
    a guard may anchor its whole decision or its test expression, never a value tested through a variable."""
    if node.type in types:
        return True
    n = node.parent
    while n is not None:
        if n.type in types:
            t = decision_test(n)
            if t is not None and t.start_byte <= node.start_byte and node.end_byte <= t.end_byte:
                return True
        n = n.parent
    return False


def parsed_node(work: Path, prepared: dict, cache: dict, rec: dict, a: dict):
    """The syntax node at a code anchor, or None for text/range anchors, unparsed files and bad anchors (those
    are reported elsewhere)."""
    if a["node_type"] in (anchors.TEXT, anchors.RANGE):
        return None
    src = source_bytes(work, prepared, cache, a["file"], a["derived_from"])
    lang = guard_lang(a["file"], a["derived_from"], rec)
    return node_at(src, lang, a) if src is not None and lang is not None else None


def guard_problems(rec: dict, work: Path, prepared: dict) -> list[tuple[str, dict, str]]:
    """(json path, item, reason) for structure the verifier would refuse outright, pushed to write time: a guard
    whose site is neither a decision of its declared kind nor the test of one (a value source such as
    `const t = await f()` tested later through `t` is not a guard site), a guard `via` that is not a call (or sits
    on a guard that is not an early exit), a payload sink that is not a call, and a bind hop that is not an object
    key, assignment, declaration or call argument."""
    cache, out = {}, []
    for gi, gate in enumerate(rec["gates"]):
        for i, g in enumerate(gate.get("guards") or []):
            types = GUARD_NODE_TYPES.get(g["kind"])
            node = parsed_node(work, prepared, cache, rec, g["site"]) if types else None
            if node is not None and not governs(node, types):
                out.append((f"gates/{gi}/guards/{i}", g, f"kind {g['kind']!r} but the site is a {node.type} that is "
                            f"neither a {g['kind']} nor its test; anchor the decision or its condition"))
            for j, a in enumerate(g.get("via") or []):
                if g["kind"] != "early_exit":
                    out.append((f"gates/{gi}/guards/{i}/via", a, "via is only for an early exit that ends the process"))
                    break
                via = parsed_node(work, prepared, cache, rec, a)
                while via is not None and via.type in ("await_expression", "parenthesized_expression") and \
                        via.named_children:
                    via = via.named_children[-1]
                if via is not None and via.type not in CALL_NODE_TYPES:
                    out.append((f"gates/{gi}/guards/{i}/via/{j}", a, f"via is a {via.type}; anchor the call that "
                                "runs the function holding the exit (then its caller's call, and so on)"))
        for br in ("then", "else"):
            for j, p in enumerate((gate.get(br) or {}).get("payload") or []):
                node = parsed_node(work, prepared, cache, rec, p["sink"])
                if node is not None and node.type not in CALL_NODE_TYPES:
                    out.append((f"gates/{gi}/{br}/payload/{j}/sink", p, f"the sink is a {node.type}, not a call; "
                                "anchor the call that does the behaviour"))
                for k, hop in enumerate(p["witness"]):
                    if hop["hop"] != "bind":
                        continue
                    node = parsed_node(work, prepared, cache, rec, hop["anchor"])
                    is_arg = node is not None and node.parent is not None and \
                        node.parent.type in ("arguments", "argument_list")
                    if node is not None and node.type not in BIND_NODE_TYPES and not is_arg:
                        out.append((f"gates/{gi}/{br}/payload/{j}/witness/{k}", hop["anchor"],
                                    f"bind hop is a {node.type}; anchor the object key (pair), the assignment, the "
                                    "declaration or the call argument that stores the function or object"))
    return out


def record_refusals(work: Path, problems: list[tuple[str, dict, str]]) -> int:
    """Distinct anchors ever refused for this package (a retry with the same bad anchor counts once)."""
    log = work / "refusals.json"
    seen = set(json.loads(log.read_text())) if log.is_file() else set()
    seen |= {f"{a.get('file')}|{a.get('derived_from')}|{a.get('start_byte')}|{a.get('end_byte')}|{a.get('sha256')}"
             for _, a, _ in problems if a}
    log.write_text(json.dumps(sorted(seen)))
    return len(seen)


def refusal_count(work: Path) -> int:
    log = work / "refusals.json"
    return len(json.loads(log.read_text())) if log.is_file() else 0


def candidate_check(rec: dict, skeleton: dict, prepared: dict, refusals: int) -> dict:
    cited = {site["candidate"] for c in rec["conditions"] for site in c["sites"] if site.get("candidate")}
    guards = {q["candidate"] for g in rec["gates"] for q in g.get("guards") or [] if q.get("candidate")}
    return {
        "condition_candidates": sum(len(c["sites"]) for c in skeleton["conditions"]),
        "condition_sites_cited": len(cited),
        "guards_cited": len(guards),
        "candidates_dropped": len(rec["candidate_review"]["dropped"]),
        "conditions_in_set": sum(c["provenance"] == "in_set" for c in rec["conditions"]),
        "conditions_out_of_set": sum(c["provenance"] == "out_of_set" for c in rec["conditions"]),
        "guard_candidates": len((prepared.get("candidates") or {}).get("guards", [])),
        "gates_in_set": sum(g["provenance"] == "in_set" for g in rec["gates"]),
        "gates_out_of_set": sum(g["provenance"] == "out_of_set" for g in rec["gates"]),
        "out_of_set_ids": contract.out_of_set_ids(rec),
        "anchor_refusals": refusals,
    }


def normalisation(raw: dict | None, skeleton: dict) -> dict:
    """prepare.py's normalisation (its derivations and candidate set are not the analyst's to edit) plus the
    decode_spec derivations the analyst registered with tools/analysis/register_decode.py for hand-cracked ciphers. `raw`
    is the analyst's normalisation before defanging: replay parameters must stay byte-exact."""
    base = skeleton["normalisation"]
    taken = {d["id"] for d in base["derivations"]}
    added = [d for d in (raw or {}).get("derivations", []) if d.get("recipe") == "decode_spec"]
    clash = sorted(d["id"] for d in added if d["id"] in taken)
    if clash:
        raise AnchorError(f"decode_spec derivations reuse ids prepare.py assigned: {', '.join(clash)} "
                          "(run register_decode.py without --id to get a free one)")
    return {**base, "derivations": base["derivations"] + added}


def derive(rec: dict, skeleton: dict, prepared: dict | None = None, refusals: int = 0) -> dict:
    """Overwrites every field that follows from the rest of the record."""
    prepared = prepared or {}
    raw_normalisation = rec.get("normalisation")
    rec = {k: (v if k in ("package", "schema_version", "record_type") else defang_all(v)) for k, v in rec.items()}
    rec.setdefault("candidate_review", {"dropped": []})
    ground(rec, skeleton, prepared)
    missing = undisposed(rec, skeleton)
    if missing:
        raise AnchorError("prefilled candidates neither cited nor listed in candidate_review.dropped (keep each "
                          "with its id, or drop it with a reason_code): " + ", ".join(missing[:20]))
    rec["normalisation"] = normalisation(raw_normalisation, skeleton)
    for req in rec["requirements"]:
        if req["axis"] == "network":
            req["value"] = defang_hosts(req["value"])
    defang_recipe_hosts(rec)
    for c in rec["conditions"]:
        c["in_scope"] = c["category"] in contract.IN_SCOPE
        c["provenance"] = contract.condition_provenance(c)
    conds = {c["id"]: c for c in rec["conditions"]}
    for g in rec["gates"]:
        g["provenance"] = contract.gate_provenance(g, conds)
    for g in rec["gates"]:
        g["then"]["min_conditions"] = contract.min_conditions_of(g["expression"])
        if g["else"] is not None:
            g["else"]["min_conditions"] = contract.else_min_of(g["expression"], g["else"].get("requires") or [])
    rec["behaviours"]["gated"] = list(dict.fromkeys(
        b for g in rec["gates"] for br in contract.gate_branches(g) for b in br["behaviours"]))
    rec["label_disagreement"] = bool(rec["label_disagreement"]) or contract.label_disagrees(rec)
    reasons = rec.get("review_reasons") or []
    for r in contract.review_triggers(rec):
        if r not in reasons:
            reasons.append(r)
    rec["review_reasons"] = reasons
    rec["needs_manual_review"] = bool(rec["needs_manual_review"]) or bool(reasons)
    rec["candidate_check"] = candidate_check(rec, skeleton, prepared, refusals)
    return rec


def sections(md: str) -> dict:
    out, current = {}, None
    for line in md.splitlines():
        m = re.match(r"^##\s+(\w+)\s*$", line)
        if m:
            current = m.group(1).lower()
            out[current] = []
        elif current:
            out[current].append(line)
    return {k: defang("\n".join(v).strip()) for k, v in out.items()}


def cell(s: str) -> str:
    return s.replace("|", "\\|")


def condition_text(c: dict) -> str:
    value = c["value"]
    if isinstance(value, list):
        value = "[" + ", ".join(map(str, value)) + "]"
    subject = c["api"] if c["category"] in ("env_var", "ci_marker", "package_manager") else c["category"]
    return f"{subject} {c['operator']}" + ("" if value is None else f" {value}") + \
        (" [inherited]" if c.get("inherited") else "")


def recipe_text(r: dict) -> str:
    parts = []
    for k, v in r.items():
        if isinstance(v, dict):
            v = ", ".join(f"{n}={'(set)' if x is None else x}" for n, x in v.items())
        elif isinstance(v, list):
            v = ", ".join(map(str, v))
        parts.append(f"{k}={v}")
    return "; ".join(parts) or "(none)"


def render(rec: dict, prose: dict) -> str:
    p = rec["package"]
    conds = {c["id"]: c for c in rec["conditions"]}
    released = f"{p['released_at']} ({p['released_at_source']})" if p.get("released_at") else "not found"
    analysis = p["analysis_type"] + (f" ({p['model_name']})" if p.get("model_name") else "")
    lines = [f"# {p['ecosystem']} {p['name']}@{p['version']}", "",
             f"**Source:** {p['source_dataset']} · **Source label:** {p['source_label']} · **Released:** {released}"
             f" · **Assessment:** {rec['claude_assessment']} ({rec['confidence']})"
             f" · **Analysis:** {analysis}", "",
             "## Summary", "", prose["summary"], "", "## Execution", ""]
    for e in rec["execution"]["entry_points"]:
        extra = [f"runs on {e['runs_on'].replace('_', ' ')}"] if e["runs_on"] != "always" else []
        extra.append(f"{len(e['file_chain'])}-file chain" if len(e["file_chain"]) > 1 else
                     (f"runs {e['file_chain'][0]}" if e["file_chain"] else "no package files"))
        extra.append(", ".join(e["launch_style"]))
        if e["silent_failure"]:
            extra.append("errors hidden")
        lines.append(f"- **{e['hook']}** `{e['command']}`: {'; '.join(extra)}.")
    lines += ["", "## Gates", ""]
    if rec["gates"]:
        lines += ["| gate | hook | expression | branch | min | behaviours | recipe |",
                  "|---|---|---|---|---|---|---|"]
        for g in rec["gates"]:
            ids = list(dict.fromkeys(re.findall(r"c\d+", g["expression"])))
            detail = "; ".join(f"{i}: {condition_text(conds[i])}" for i in ids if i in conds)
            head = f"| {g['gate_id']} | {g['hook']} | {cell(g['expression'])} ({cell(detail)})"
            for name in ("then", "else"):
                br = g[name]
                if br is None:
                    continue
                beh = ", ".join(br["behaviours"]) or "-"
                lines.append(f"{head} | {name} | {br['min_conditions']} | {cell(beh)} | "
                             f"{cell(recipe_text(br['env_recipe']))} |")
                head = "| | | "  # the gate's identity spans its branch rows
        lines.append("")
        lines.append("Gate intent: " + "; ".join(f"{g['gate_id']} {g['polarity']}/{g['effect']}/{g['purpose']}"
                                                  for g in rec["gates"]))
        cc = rec["candidate_check"]
        lines.append("")
        lines.append(f"Grounding: {cc['conditions_in_set']} of {len(rec['conditions'])} conditions and "
                     f"{cc['gates_in_set']} of {len(rec['gates'])} gates from the candidate set"
                     + (f"; out of set, pending verification: {', '.join(cc['out_of_set_ids'])}"
                        if cc["out_of_set_ids"] else "") + ".")
    else:
        lines.append("None.")
    lines += ["", "## Requirements", ""]
    lines += [f"- {r['axis']}: {r['value'] if isinstance(r['value'], str) else ', '.join(r['value'])} "
              f"({r['reason']})" for r in rec["requirements"]] or ["None."]
    b = rec["behaviours"]
    lines += ["", "## Behaviour", "", f"- Ungated: {', '.join(b['ungated']) or 'none'}",
              f"- Gated: {', '.join(b['gated']) or 'none'}", "", "## Notes", "", prose.get("notes") or "None.", "",
              "## Record", "", "```json", json.dumps(rec, indent=2, ensure_ascii=False), "```", ""]
    return "\n".join(lines)


def report_path(p: dict) -> Path:
    return paths.REPORTS / p["ecosystem"] / f"{p['name'].replace('/', '__')}@{p['version']}.md"


def model_problems(package: dict, model_used: str | None) -> list[str]:
    """Why the record may not be written by a session running `model_used`, when that is given."""
    if not model_used:
        return []
    problems = []
    if package.get("model_name") != model_used:
        problems.append(f"package/model_name is {package.get('model_name')!r} but this session runs {model_used!r}")
    if package.get("analysis_type") != "ai":
        problems.append(f"package/analysis_type is {package.get('analysis_type')!r}; a model session writes 'ai'")
    return problems


def finish(work: Path, model_used: str | None = None) -> Path:
    model_used = model_used or os.environ.get(MODEL_ENV) or None
    prepared = json.loads((work / "prepared.json").read_text(encoding="utf-8"))
    validator = contract.load_validator()
    if (work / "skip.json").exists():
        choice = json.loads((work / "skip.json").read_text(encoding="utf-8"))
        package = {**prepared["package"], "analysis_type": "ai", "model_name": choice.get("model_name")}
        rec = {"schema_version": contract.SCHEMA_VERSION, "record_type": "skip", "package": package,
               "reason": choice.get("reason"), "note": defang(str(choice.get("note", "")))[:300]}
        problems = todo_paths(rec) + contract.validation_errors(validator, rec) + model_problems(package, model_used)
        if problems:
            raise SystemExit("not written:\n  " + "\n  ".join(problems))
        p = rec["package"]
        path = paths.REPORTS / "_skipped" / f"{p['ecosystem']}__{p['name'].replace('/', '__')}@{p['version'] or 'unknown'}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    rec = json.loads((work / "record.json").read_text(encoding="utf-8"))
    prose = sections((work / "summary.md").read_text(encoding="utf-8"))
    todos = todo_paths(rec) + [f"summary.md ## {k}" for k in ("summary", "notes") if prose.get(k) == "TODO"]
    if not prose.get("summary"):
        todos.append("summary.md ## Summary is empty")
    if todos:
        raise SystemExit("not written, still TODO:\n  " + "\n  ".join(todos))
    wrong_model = model_problems(rec.get("package") or {}, model_used)
    if wrong_model:
        raise SystemExit("not written:\n  " + "\n  ".join(wrong_model))
    try:
        rec = derive(rec, prepared["record"], prepared, refusal_count(work))
    except AnchorError as e:
        raise SystemExit(f"not written, candidate ids do not check out:\n  {e}")
    except (KeyError, TypeError, ValueError) as e:
        raise SystemExit(f"not written, record is malformed: {e!r}")
    errors = contract.validation_errors(validator, rec)
    if errors:
        raise SystemExit("not written:\n  " + "\n  ".join(errors))
    problems = anchor_problems(rec, work, prepared)
    if problems:
        total = record_refusals(work, problems)
        raise SystemExit(f"not written, {len(problems)} anchors do not match the package bytes ({total} refused so "
                         "far for this package; cite with tools/analysis/cite.py):\n  "
                         + "\n  ".join(f"{path}: {why}" for path, _, why in problems))
    guard_issues = guard_problems(rec, work, prepared)
    if guard_issues:
        raise SystemExit(f"not written, {len(guard_issues)} guard or sink anchors do not fit the code (re-cite them "
                         "with tools/analysis/cite.py):\n  "
                         + "\n  ".join(f"{path}: {why}" for path, _, why in guard_issues))
    path = report_path(rec["package"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(rec, prose), encoding="utf-8")
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    ap.add_argument("work", type=Path, help="the package's scratch/<key> folder")
    ap.add_argument("--model-used", help=f"refuse unless model_name is this model id (default: ${MODEL_ENV})")
    args = ap.parse_args()
    path = finish(paths.confine(args.work), args.model_used)
    print(f"wrote {path.relative_to(paths.ROOT)}")
    if path.suffix == ".md":
        rec = contract.read_record(path)
        cc = rec["candidate_check"]
        print(f"  conditions: {cc['conditions_in_set']} in set, {cc['conditions_out_of_set']} out of set"
              f"  |  gates: {cc['gates_in_set']} in set, {cc['gates_out_of_set']} out of set"
              f"  |  anchor refusals: {cc['anchor_refusals']}")
        if cc["out_of_set_ids"]:
            print(f"  out of set, pending verification: {', '.join(cc['out_of_set_ids'])}")
        if rec["review_reasons"]:
            print("  review: " + "; ".join(rec["review_reasons"]))


if __name__ == "__main__":
    main()
