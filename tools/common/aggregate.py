#!/usr/bin/env python3
"""
Collect every package record in reports/ into the TRIPWIRE dataset.

- reports/npm/*.md and reports/pypi/*.md : full reports, record = last ```json block
- reports/_skipped/*.json                : skip records
- reports/_draws/*.json                  : sample manifests (the stratified draw, the pinned pilot)
- reports/_shipped/*.json                : whether each archive ships the relative paths its recipes name

- reports/_verification/<key>/*.json      : verification sidecars (verdicts on each record's claims)

Writes:
  dataset/packages.jsonl   one line per analysed package
  dataset/gates.jsonl      one line per gate, with its conditions inlined
  dataset/members.jsonl    one line per member of a campaign (a package sharing a representative's install payload)
  dataset/skipped.jsonl    one line per skipped sample
  dataset/claims.jsonl     one line per claim with its final verification status
  dataset/verdicts.jsonl   one line per claim and verifier (latest non-stale verdict)
  dataset/summary.md       counts only, with denominators (no conclusions)
  dataset/verification.md  verification counts per layer and agreement statistics
  dataset/blindspot.jsonl  one line per profile and malicious payload: open, closed, unknown or not expressible
  dataset/tables/*.csv     the verification tables, prevalence.csv (design-weighted, per draw),
                           prevalence_with_rejected.csv (the same with rejected repairs clearing a gate),
                           prevalence_all_gates.csv (the same with every gate counted, excluded or not) and
                           blindspot*.csv

Every row of packages, members and skipped carries `key` (ecosystem__name@version, as gates, claims and verdicts
name their package), so the tables join on it.

Exit code is 1 if any record fails validation and 2 if jsonschema is missing or older than 4.18,
so it can run in CI or a pre-commit hook.

Usage: python tools/common/aggregate.py [--check] [--append-only] [--require-oos-verified]
  --check                 validate records and sidecars, write nothing
  --append-only           also fail when a committed sidecar run was edited or removed (pre-commit)
  --require-oos-verified  the release (freeze) check: also fail while an out-of-set L1-L3 claim is not settled
                          (verified, or refuted/disputed with a repair decision that keeps the record), or a member
                          has no analysed representative
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths, prevalence, profiles, shipped, verification  # noqa: E402
from tools.common.contract import (COND_ID, JSON_BLOCK, key_for, load_validator, min_conditions_excluding,  # noqa: E402
                                   normalise_name, validation_errors)


def read_records():
    """Yield (path, record or None, error or None)."""
    for eco in ("npm", "pypi"):
        for p in sorted((paths.REPORTS / eco).glob("*.md")):
            blocks = JSON_BLOCK.findall(p.read_text(encoding="utf-8"))
            if not blocks:
                yield p, None, "no ```json block"
                continue
            try:
                yield p, json.loads(blocks[-1]), None
            except json.JSONDecodeError as e:
                yield p, None, f"bad JSON: {e}"
    for sub in ("_skipped", "_members"):
        for p in sorted((paths.REPORTS / sub).glob("*.json")):
            try:
                yield p, json.loads(p.read_text(encoding="utf-8")), None
            except json.JSONDecodeError as e:
                yield p, None, f"bad JSON: {e}"


def pct(n, d):
    return f"{n} / {d} ({100 * n / d:.0f}%)" if d else f"{n} / 0"


def table(title, counter, total=None, limit=None):
    lines = [f"### {title}", "", "| value | count |", "|---|---|"]
    for k, v in sorted(counter.items(), key=lambda kv: (-kv[1], str(kv[0])))[:limit]:
        key = str(k).replace("|", "\\|")
        lines.append(f"| {key} | {v if total is None else pct(v, total)} |")
    if limit and len(counter) > limit:
        lines.append(f"| ({len(counter) - limit} more) | |")
    if not counter:
        lines.append("| (none) | 0 |")
    return "\n".join(lines) + "\n"


ENV_API = re.compile(r"process\.env\.(\w+)|os\.environ\[['\"]?(\w+)")


def compared_value(c: dict) -> str:
    """`NAME op value` for environment variables, `op value` otherwise."""
    value = c["value"]
    shown = "" if value is None else ", ".join(map(str, value)) if isinstance(value, list) else str(value)
    m = ENV_API.search(c["api"])
    prefix = f"{m.group(1) or m.group(2)} " if m else ""
    return f"{prefix}{c['operator']} {shown}".strip()


def recipe_axes(recipe: dict) -> int:
    """Environment axes a recipe sets; every env var name, file and host counts as its own axis."""
    return sum(len(v) if isinstance(v, (dict, list)) else 1 for v in recipe.values())


def split_table(packages, skipped, members=()) -> str:
    def group(pk):
        return pk.get("ecosystem") or "unknown", pk["source_label"]
    groups = sorted({group(p["package"]) for p in packages} | {group(s) for s in skipped} |
                    {group(m) for m in members})
    lines = ["### By ecosystem and source label", "",
             "| ecosystem / label | samples | analysed | members | with a gate | with an in-scope condition | skipped |",
             "|---|---|---|---|---|---|---|"]
    for g in groups:
        ps = [p for p in packages if group(p["package"]) == g]
        ms = sum(1 for m in members if group(m) == g)
        sk = sum(1 for s in skipped if group(s) == g)
        gated = sum(1 for p in ps if p["gates"])
        in_scope = sum(1 for p in ps if any(c["in_scope"] for c in p["conditions"]))
        lines.append(f"| {g[0]} / {g[1]} | {len(ps) + ms + sk} | {len(ps)} | {ms} | {pct(gated, len(ps))} | "
                     f"{pct(in_scope, len(ps))} | {sk} |")
    if not groups:
        lines.append("| (none) | 0 | 0 | 0 | 0 | 0 | 0 |")
    return "\n".join(lines) + "\n"


def grounding_lines(packages) -> list[str]:
    """How much of the labelled data the deterministic candidate set grounds (candidate_check, schema v3)."""
    checks = [p["candidate_check"] for p in packages if "candidate_check" in p]
    total = lambda k: sum(c[k] for c in checks)  # noqa: E731
    conds = total("conditions_in_set") + total("conditions_out_of_set")
    gates = total("gates_in_set") + total("gates_out_of_set")
    return ["## Grounding in the candidate set", "",
            "In-set claims cite a site or guard the deterministic generator proposed; out-of-set claims were added "
            "by the analyst and wait for the verification pass. Anchor refusals are cited code that did not match "
            "the package bytes when the record was written.", "",
            f"- Conditions in set: {pct(total('conditions_in_set'), conds)}  |  out of set: "
            f"{pct(total('conditions_out_of_set'), conds)}",
            f"- Gates in set: {pct(total('gates_in_set'), gates)}  |  out of set: {pct(total('gates_out_of_set'), gates)}",
            f"- Candidate condition sites cited: {pct(total('condition_sites_cited'), total('condition_candidates'))}",
            f"- Anchors refused at write time: {total('anchor_refusals')} (across {len(checks)} packages)", ""]


def campaign_lines(packages, members) -> list[str]:
    """Campaign = install-payload cluster. A member shares a representative's payload but was not re-analysed."""
    reps = {p["package"]["cluster_key"] for p in packages}
    member_counts = Counter(m["cluster_key"] for m in members)
    pkgs_per_campaign = Counter()
    for p in packages:
        pkgs_per_campaign[p["package"]["cluster_key"]] += 1
    for m in members:
        pkgs_per_campaign[m["cluster_key"]] += 1
    orphan = [ck for ck in member_counts if ck not in reps]
    gated_reps = {p["package"]["cluster_key"] for p in packages if p["gates"]}
    total_pkgs = len(packages) + len(members)
    lines = ["## Campaigns", "",
             "A campaign is one install-payload cluster. One representative is analysed in full; the rest are "
             "members. Per-package prevalence folds members into the denominator; per-campaign counts each "
             "cluster once.", "",
             f"- Distinct campaigns (analysed representatives): {len(reps)}",
             f"- Packages across all campaigns (representatives + members): {total_pkgs}",
             f"- Campaigns with a gate: {pct(len(gated_reps), len(reps))} (per campaign)",
             f"- Packages in a gated campaign: "
             f"{pct(sum(pkgs_per_campaign[ck] for ck in gated_reps), total_pkgs)} (per package)"]
    if orphan:
        lines.append(f"- Campaigns with members but no analysed representative (their drawn names count as "
                     f"non-response): {len(orphan)}")
    lines += ["", table("Packages per campaign (representative + members)",
                        Counter(pkgs_per_campaign.values()), len(pkgs_per_campaign))]
    return lines


def summary(packages, skipped, members, gates, prevalence_lines=(), blindspot_lines=()):
    excluded = [g for g in gates if g.get("verification", "ok") != "ok"]
    gates = [g for g in gates if g.get("verification", "ok") == "ok"]
    n_pkg, n_skip = len(packages), len(skipped)
    gated_pkgs = [p for p in packages if p["gates"]]
    in_scope_gate_pkgs = [p for p in packages
                          if any(c["in_scope"] for c in p["conditions"])]
    conds = [c for p in packages for c in p["conditions"]]
    out = [
        "# TRIPWIRE dataset summary",
        "",
        "Generated by `tools/common/aggregate.py`. Counts only. Read every number with its denominator; "
        "small samples say nothing about prevalence.",
        "",
        "## Samples",
        "",
        f"- Samples seen: {n_pkg + n_skip + len(members)}",
        f"- Analysed representatives (have install-time code): {n_pkg}",
        f"- Members (same payload as a representative): {len(members)}",
        f"- Skipped: {n_skip}",
        f"- Analysed packages with at least one gate: {pct(len(gated_pkgs), n_pkg)}",
        f"- Analysed packages with at least one in-scope condition: {pct(len(in_scope_gate_pkgs), n_pkg)}",
        f"- Distinct gates: {len(gates) + len(excluded)}  |  distinct conditions: {len(conds)}",
        f"- Gates left out of the gate tables below (a refuted, disputed or unanchored L1-L4 claim): "
        f"{len(excluded)}",
        "",
        *campaign_lines(packages, members),
        split_table(packages, skipped, members),
        table("Skip reasons by ecosystem", Counter(f"{s.get('ecosystem') or 'unknown'} / {s['reason']}"
                                                   for s in skipped), n_skip),
        table("Analysed packages by source dataset", Counter(p["package"]["source_dataset"] for p in packages),
              n_pkg),
        "## Gates",
        "",
        table("Condition category (in scope marked *)",
              Counter((c["category"] + (" *" if c["in_scope"] else "")) for c in conds), len(conds)),
        table("Compared values (packages with the condition)",
              Counter(k for p in packages for k in {f"{c['category']}: {compared_value(c)}" for c in p["conditions"]}),
              n_pkg, limit=40),
        table("Condition value recovered", Counter(c["value_recovered"] for c in conds), len(conds)),
        table("then.min_conditions per gate (activation strength)",
              Counter(g["then"]["min_conditions"] for g in gates), len(gates)),
        table("then.min_conditions per gate, inherited conditions excluded (copied from the impersonated package)",
              Counter(g.get("then_min_excluding_inherited", g["then"]["min_conditions"]) for g in gates), len(gates)),
        table("else.min_conditions per two-branch gate",
              Counter(g["else"]["min_conditions"] for g in gates if g["else"]),
              sum(1 for g in gates if g["else"])),
        table("Largest then.min_conditions per gated package",
              Counter(max(g["then"]["min_conditions"] for g in p["gates"]) for p in gated_pkgs), len(gated_pkgs)),
        table("Environment axes per gate then-recipe (each env var, file or host is one axis)",
              Counter(recipe_axes(g["then"]["env_recipe"]) for g in gates), len(gates)),
        table("Gate purpose / polarity", Counter(f"{g['purpose']} / {g['polarity']}" for g in gates), len(gates)),
        table("Gate purpose", Counter(g["purpose"] for g in gates), len(gates)),
        table("Gate polarity", Counter(g["polarity"] for g in gates), len(gates)),
        table("Gate effect", Counter(g["effect"] for g in gates), len(gates)),
        table("Gate hook", Counter(g["hook"] for g in gates), len(gates)),
        "## Behaviour (packages with the class)",
        "",
        table("Only behind a gate", Counter(b for p in packages
                                            for b in set(p["behaviours"]["gated"]) - set(p["behaviours"]["ungated"])), n_pkg),
        table("Ungated", Counter(b for p in packages for b in set(p["behaviours"]["ungated"])), n_pkg),
        "## Other",
        "",
        table("Needs a remote host to complete", Counter(p["reachability"]["needs_remote"] for p in packages), n_pkg),
        table("Obfuscation level", Counter(p["obfuscation"]["level"] for p in packages), n_pkg),
        f"- Packages with unrecovered code: {pct(sum(1 for p in packages if p['obfuscation']['unrecovered']), n_pkg)}",
        "",
        table("Family hint (campaign concentration)",
              Counter(p["family_hint"] for p in packages if p.get("family_hint")), n_pkg, limit=20),
        table("Assessment", Counter(p["claude_assessment"] for p in packages), n_pkg),
        *grounding_lines(packages),
        *prevalence_lines,
        *blindspot_lines,
        "## Needs manual review",
        "",
    ]
    review = [p for p in packages if p["needs_manual_review"] or p["label_disagreement"]]
    out += [f"- {p['package']['ecosystem']} {p['package']['name']}@{p['package']['version']}: "
            + "; ".join(p.get("review_reasons") or ["label disagreement"]) for p in review] or ["- none"]
    return "\n".join(out) + "\n"


def prevalence_of(gates: list[dict], packages: list[dict], manifests: dict, taken) -> tuple[list, dict, dict]:
    """(prevalence rows, left-out counts, gated campaign weights per draw), counting the gates marked ok."""
    ok_gates = {}
    for g in gates:
        if g["verification"] == "ok":
            lab = ok_gates.setdefault(g["cluster_key"], dict.fromkeys(prevalence.MEASURES, False))
            lab["gated"] = True
            lab["gated_in_scope"] |= any(c["in_scope"] for c in g["conditions"])
            lab["gated_env"] |= any(c["in_scope"] and c["category"] != "target_artifact" for c in g["conditions"])
            lab["gated_not_absence"] |= any(c["category"] != "file_or_dir_exists" or c["operator"] != "not_exists"
                                            for c in g["conditions"])
    labels_of = {p["package"]["cluster_key"]: ok_gates.get(p["package"]["cluster_key"],
                                                           dict.fromkeys(prevalence.MEASURES, False))
                 for p in packages}
    rows, left_out, draws = [], {}, {}
    for sid, m in manifests.items():
        if sid == "pilot" or not any(r.get("weight") for r in m["strata"]):
            continue
        us = prevalence.units(m, sid, taken, labels_of)
        table_rows, left_out[sid] = prevalence.table(m, sid, us)
        rows += table_rows
        draws[sid] = [(u["cluster_key"], w) for u, w in prevalence.weights(m, us) if u["gated"]]
    return rows, left_out, draws


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="validate only, write nothing")
    ap.add_argument("--append-only", action="store_true", help="fail when committed sidecar runs were changed")
    ap.add_argument("--require-oos-verified", action="store_true",
                    help="fail while an out-of-set L1-L3 claim is not verified or refuted")
    args = ap.parse_args()

    validator = load_validator()
    packages, skipped, members, gates, failures = [], [], [], [], 0
    keys = Counter()
    cluster_reps = Counter()
    for path, rec, err in read_records():
        rel = path.relative_to(paths.ROOT)
        errs = [err] if err else []
        if rec is not None:
            errs += validation_errors(validator, rec)
        if errs:
            failures += 1
            print(f"FAIL {rel}", file=sys.stderr)
            for e in errs[:15]:
                print(f"   - {e}", file=sys.stderr)
            continue
        pk = rec["package"]
        keys[(pk.get("ecosystem"), normalise_name(pk.get("ecosystem") or "", pk["name"]), pk.get("version"))] += 1
        if rec["record_type"] == "skip":
            skipped.append({**rec["package"], "reason": rec["reason"], "note": rec.get("note", "")})
            continue
        if rec["record_type"] == "member":
            members.append(rec["package"])
            continue
        packages.append(rec)
        cluster_reps[pk["cluster_key"]] += 1
        conds = {c["id"]: c for c in rec["conditions"]}
        inherited = {c["id"] for c in rec["conditions"] if c.get("inherited")}
        for g in rec["gates"]:
            gates.append({**g,
                          "package": f"{pk['ecosystem']}:{pk['name']}@{pk['version']}",
                          "key": key_for(pk["ecosystem"], pk["name"], pk["version"]),
                          "source_label": pk["source_label"], "cluster_key": pk["cluster_key"],
                          "then_min_excluding_inherited": min_conditions_excluding(g["expression"], inherited),
                          "conditions": [conds[c] for c in sorted(set(COND_ID.findall(g["expression"])))
                                         if c in conds]})

    for k, n in keys.items():
        if n > 1:
            failures += 1
            print(f"FAIL duplicate record for {k} ({n} files; PyPI names compare per PEP 503)", file=sys.stderr)
    reps = {p["package"]["cluster_key"] for p in packages}
    for m in members:
        if m.get("cluster_key") not in reps:
            # normal while a batch is still analysing the representative; a release (freeze) check fails on it
            level = "FAIL" if args.require_oos_verified else "WARN"
            failures += level == "FAIL"
            print(f"{level} member {m.get('ecosystem')}:{m['name']}@{m.get('version')} has no analysed "
                  f"representative (cluster {str(m.get('cluster_key'))[:12]}); analyse one copy in full",
                  file=sys.stderr)
    for ck, n in cluster_reps.items():
        if n > 1:
            print(f"WARN {n} full reports share cluster {ck[:12]}; demote all but one to a member", file=sys.stderr)

    claim_rows, verdict_rows, side_failures, side_warnings = verification.join(packages, paths.REPORTS,
                                                                                args.append_only)
    for path, errs in side_failures:
        failures += 1
        print(f"FAIL {path.relative_to(paths.ROOT)}", file=sys.stderr)
        for e in errs[:15]:
            print(f"   - {e}", file=sys.stderr)
    for w in side_warnings:
        print(f"WARN {w}", file=sys.stderr)
    blocked, unrejected = {}, {}
    for r in claim_rows:
        if verification.blocks_gate(r):
            blocked.setdefault(r["package"], set()).add(r["claim_id"].split(".")[0])
            if r.get("repair") != "rejected":
                unrejected.setdefault(r["package"], set()).add(r["claim_id"].split(".")[0])

    def hit(g, by_package):
        bad = by_package.get(g["key"], set())
        return g["gate_id"] in bad or any(c["id"] in bad for c in g["conditions"])
    for g in gates:
        g["verification"] = "excluded" if hit(g, blocked) else "ok"
        g["rejected_only"] = hit(g, blocked) and not hit(g, unrejected)
    manifests = {p.stem: json.loads(p.read_text(encoding="utf-8"))
                 for p in sorted((paths.REPORTS / "_draws").glob("*.json"))}
    taken, problems, unmatched = prevalence.label_rows(
        manifests, [("analysed", p) for p in packages] + [("member", m) for m in members] +
        [("skip", s) for s in skipped])
    for msg in problems:
        failures += 1
        print(f"FAIL {msg}", file=sys.stderr)
    if unmatched:
        print(f"WARN {unmatched} records match no manifest in reports/_draws/ (labelled pilot); pin them with "
              f"draw_sample.py", file=sys.stderr)
    prev_rows, left_out, draws = prevalence_of(gates, packages, manifests, taken)
    with_rejected = [{**g, "verification": "ok" if g["rejected_only"] else g["verification"]} for g in gates]
    rejected_rows = prevalence_of(with_rejected, packages, manifests, taken)[0]
    # the loosest rule: every gate counts, excluded or not (how far the exclusion rule moves the shares)
    all_gate_rows = prevalence_of([{**g, "verification": "ok"} for g in gates], packages, manifests, taken)[0]
    envs = profiles.load()
    ships, ship_warnings = shipped.join(packages, shipped.load())
    for w in ship_warnings:
        print(f"WARN {w}", file=sys.stderr)
    # the blind spot is a property of the malware: the benign control set is not scored
    malicious = [g for g in gates if g["source_label"] == "malicious"]
    blind_rows = profiles.evaluate(malicious, envs, ships, {key_for(p["package"]["ecosystem"], p["package"]["name"], p["package"]["version"]): p["requirements"]
                                                        for p in packages})
    gated_clusters = {g["cluster_key"] for g in malicious if g["verification"] == "ok"}
    gated_packages = [p["package"]["cluster_key"] for p in packages if p["package"]["cluster_key"] in gated_clusters]
    gated_packages += [m["cluster_key"] for m in members if m.get("cluster_key") in gated_clusters]
    blind = profiles.table(blind_rows, gated_packages, draws)
    blind_merge = profiles.merge_table(malicious, blind_rows, envs, ships)
    open_ = verification.open_refutations(claim_rows)
    if open_:
        print(f"WARN {len(open_)} refuted or disputed claims wait for the repair pass (skills/repair-gates)",
              file=sys.stderr)
    pending = verification.unverified_out_of_set(claim_rows)
    if args.require_oos_verified and pending:
        failures += 1
        print(f"FAIL {len(pending)} out-of-set claims are not closed (verified, or refuted/disputed with a repair decision that leaves them standing): {', '.join(pending[:10])}"
              + (" ..." if len(pending) > 10 else ""), file=sys.stderr)

    print(f"{len(packages)} analysed, {len(members)} members, {len(skipped)} skipped, {len(gates)} gates, "
          f"{len(claim_rows)} claims, {len(verdict_rows)} verdicts, {failures} failed", file=sys.stderr)
    if args.check:
        return 1 if failures else 0

    paths.DATASET.mkdir(exist_ok=True)
    for r in packages:
        r["key"] = key_for(r["package"]["ecosystem"], r["package"]["name"], r["package"]["version"])
    for r in (*members, *skipped):
        r["key"] = key_for(r["ecosystem"], r["name"], r.get("version"))
    for r in (*claim_rows, *verdict_rows):  # the join column every table shares; `package` holds the same key here
        r["key"] = r["package"]
        r["target"] = r["claim_id"].split(".")[0]  # the gate (g1), condition (c3) or dropped candidate it is about
    for name, rows in (("packages", packages), ("gates", gates), ("skipped", skipped), ("members", members),
                       ("claims", claim_rows), ("verdicts", verdict_rows)):
        with open(paths.DATASET / f"{name}.jsonl", "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    (paths.DATASET / "summary.md").write_text(summary(packages, skipped, members, gates,
                                                      prevalence.summary_lines(prev_rows, left_out),
                                                      profiles.summary_lines(blind, blind_merge)),
                                              encoding="utf-8")
    (paths.DATASET / "verification.md").write_text(verification.summary_md(claim_rows, verdict_rows, paths.REPORTS),
                                                   encoding="utf-8")
    verification.write_tables(paths.DATASET, claim_rows, verdict_rows)
    prevalence.write_table(paths.DATASET / "tables", prev_rows)
    prevalence.write_table(paths.DATASET / "tables", rejected_rows, "prevalence_with_rejected.csv")
    prevalence.write_table(paths.DATASET / "tables", all_gate_rows, "prevalence_all_gates.csv")
    profiles.write_tables(paths.DATASET / "tables", blind, blind_merge)
    with open(paths.DATASET / "blindspot.jsonl", "w", encoding="utf-8") as f:
        for r in blind_rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
