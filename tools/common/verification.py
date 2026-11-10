"""
Verification sidecars: reports/_verification/<key>/<method>__<by_slug>.json, one file per verifier per package,
holding append-only runs of verdicts on the record's claims (schema/verification.schema.json).

This module reads, validates and appends sidecars, decides which verdicts are stale, and picks each claim's final
status. aggregate.py turns that into dataset tables; the verify tools write through append_run().
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from tools.common import claims as claim_model
from tools.common.contract import key_for
from tools.common.paths import CODE_ROOT
from tools.common.sanitize import defang

SCHEMA = CODE_ROOT / "schema" / "verification.schema.json"
SCHEMA_VERSION = "1.0"
METHODS = ("deterministic", "agent")
SLUG = re.compile(r"[^a-z0-9._-]+")


def slug(by: str) -> str:
    """File-name slug for a verifier: 'verify' for the tool, else the model id."""
    s = SLUG.sub("-", by.split("@")[0].lower()).strip("-.")[:64]
    return s or "unknown"


def sidecar_dir(reports: Path, package: dict) -> Path:
    return reports / "_verification" / key_for(package["ecosystem"], package["name"], package["version"])


def sidecar_path(reports: Path, package: dict, method: str, by: str) -> Path:
    return sidecar_dir(reports, package) / f"{method}__{slug(by)}.json"


def load_validator():
    import jsonschema
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


def clean_evidence(text: str) -> str:
    """Defanged, at most 8 lines and 300 characters."""
    lines = defang(str(text)).splitlines()[:8]
    return "\n".join(lines)[:300]


def read_sidecars(reports: Path):
    """Yield (path, sidecar or None, error or None) for every sidecar file."""
    root = reports / "_verification"
    for p in sorted(root.glob("*/*.json")) if root.is_dir() else []:
        if p.name.startswith("repair__"):
            continue
        try:
            yield p, json.loads(p.read_text(encoding="utf-8")), None
        except json.JSONDecodeError as e:
            yield p, None, f"bad JSON: {e}"


def sidecar_errors(validator, side: dict, claims: dict[str, dict] | None) -> list[str]:
    """Schema errors, then the rules the schema cannot express. claims maps claim_id -> claim of the current
    record (None when the record is missing)."""
    errs = [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}" for e in validator.iter_errors(side)]
    if errs:
        return errs
    if claims is None:
        return ["no analysed record for this package"]
    for i, run in enumerate(side["runs"]):
        if side["method"] == "agent" and not run["blinded"]:
            errs.append(f"runs/{i}: agent runs must be blinded")
        for v in run["verdicts"]:
            cid = v["claim_id"]
            layer = claim_model.layer_of(cid)
            if side["method"] == "deterministic" and layer in claim_model.JUDGEMENT_ONLY:
                errs.append(f"runs/{i}: {cid} is a judgement claim; deterministic runs cannot rule on it")
            kind = claim_model.grade_kind(cid)
            if v["grade"] is not None and (kind is None or v["grade"] not in claim_model.GRADED[kind]):
                errs.append(f"runs/{i}: {cid} cannot take grade {v['grade']}")
    return errs


def is_stale(verdict: dict, claims: dict[str, dict]) -> bool:
    """A verdict whose claim changed or no longer exists stays in the history but is never counted."""
    c = claims.get(verdict["claim_id"])
    return c is None or c["claim_sha256"] != verdict["claim_sha256"]


# Reason codes that say the code contradicts the claim. They may only accompany `refuted`: a claim the checker
# could not decide carries an incompleteness reason instead (unresolved_binding, witness_gap, ...). Enforced on
# every run written from now on; earlier runs stay in the history as they were written.
REFUTE_REASONS = {"not_a_test", "api_mismatch", "value_mismatch", "operator_mismatch", "outside_region",
                  "broken_hop", "no_sink", "sink_kind_mismatch", "expression_mismatch"}


def reason_errors(verdicts: list[dict]) -> list[str]:
    """Verdicts whose reason code contradicts their verdict."""
    return [f"{v['claim_id']}: {v['reason_code']} only goes with refuted, not {v['verdict']}"
            for v in verdicts if v.get("reason_code") in REFUTE_REASONS and v["verdict"] != "refuted"]


def _write_atomic(path: Path, body: str) -> None:
    """Write via a temporary file and a rename, so a parallel reader never sees half a sidecar."""
    import os
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(body, encoding="utf-8")
    os.replace(tmp, path)


def append_run(reports: Path, package: dict, method: str, run: dict) -> Path:
    """Appends one run to the package's sidecar for this verifier, creating it if needed. Never rewrites a run."""
    if method not in METHODS:
        raise ValueError(f"method must be one of {METHODS}")
    path = sidecar_path(reports, package, method, run["by"])
    side = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {
        "schema_version": SCHEMA_VERSION, "method": method, "by_slug": slug(run["by"]),
        "package": {k: package.get(k) for k in ("ecosystem", "name", "version", "archive_sha256")}, "runs": []}
    for v in run["verdicts"]:
        v["evidence"] = clean_evidence(v.get("evidence", ""))
        v["evidence_refs"] = [defang(str(r))[:120] for r in v.get("evidence_refs", [])]
    side["runs"].append(run)
    errs = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in load_validator().iter_errors(side)]
    errs += reason_errors(run["verdicts"])
    if errs:
        raise ValueError("verification sidecar does not validate: " + "; ".join(errs[:5]))
    _write_atomic(path, json.dumps(side, indent=2, ensure_ascii=False) + "\n")
    return path


def appended_only(path: Path, side: dict) -> str | None:
    """Why the committed version of this sidecar is not a prefix of the current one, or None."""
    rel = path.resolve().relative_to(CODE_ROOT).as_posix()
    proc = subprocess.run(["git", "show", f"HEAD:{rel}"], cwd=CODE_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        return None  # not committed yet
    try:
        old = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None
    if side["runs"][:len(old.get("runs", []))] != old.get("runs", []):
        return "committed runs were edited or removed (sidecars are append-only)"
    return None


def latest(side: dict, claims: dict[str, dict]) -> dict[str, dict]:
    """claim_id -> the latest non-stale verdict in this sidecar. Runs are in the order they were appended."""
    out = {}
    for run in side["runs"]:
        for v in run["verdicts"]:
            if not is_stale(v, claims):
                out[v["claim_id"]] = {**v, "by": run["by"]}
    return out


DECISIVE = ("verified", "refuted")


def confirmed_refutation(final: str, by_method: dict[str, list[dict]]) -> bool:
    """A refutation the deterministic pass and an agent both gave. The repair pass must fix or escalate it, never
    reject it."""
    if final != "refuted":
        return False
    det = by_method.get("deterministic", [])
    return bool(det) and det[-1]["verdict"] == "refuted" and \
        any(v["verdict"] == "refuted" for v in by_method.get("agent", []))


def final_status(by_method: dict[str, list[dict]]) -> tuple[str, str]:
    """(verdict, source) for one claim from its non-stale verdicts grouped by method (one per verifier).

    1. Any contradiction between decisive verdicts (verified vs refuted) from the deterministic pass or any agent
       model is `disputed`: it goes to repair and is never resolved by trusting one side.
    2. Otherwise the decisive verdict: deterministic, then the agents (which agree with each other by step 1).
    3. With nothing decisive: an agent's verdict, then the deterministic verdict, else unverified."""
    det = by_method.get("deterministic", [])
    agents = by_method.get("agent", [])
    decisive = [("deterministic", v) for v in det[-1:] if v["verdict"] in DECISIVE] + \
        [("agent", v) for v in agents if v["verdict"] in DECISIVE]
    if len({v["verdict"] for _, v in decisive}) > 1:
        return "disputed", "disputed"
    if decisive:
        return decisive[0][1]["verdict"], decisive[0][0]
    if agents:
        return agents[-1]["verdict"], "agent"
    if det:
        return det[-1]["verdict"], "deterministic"
    return "unverified", "none"


# --- repair decisions --------------------------------------------------------------------------------------

REPAIR_SCHEMA = CODE_ROOT / "schema" / "repair.schema.json"
REPAIR_DECISIONS = ("fixed", "rejected", "escalated", "cleared", "kept_flag")


def repair_path(reports: Path, package: dict, by: str) -> Path:
    return sidecar_dir(reports, package) / f"repair__{slug(by)}.json"


def read_repairs(reports: Path):
    """Yield (path, repair log or None, error or None) for every repair log."""
    root = reports / "_verification"
    for p in sorted(root.glob("*/repair__*.json")) if root.is_dir() else []:
        try:
            yield p, json.loads(p.read_text(encoding="utf-8")), None
        except json.JSONDecodeError as e:
            yield p, None, f"bad JSON: {e}"


def append_repair(reports: Path, package: dict, run: dict) -> Path:
    """Appends one repair run (decisions on refuted/disputed claims and review flags). Never rewrites a run."""
    import jsonschema
    path = repair_path(reports, package, run["by"])
    log = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {
        "schema_version": SCHEMA_VERSION, "method": "repair", "by_slug": slug(run["by"]),
        "package": {k: package.get(k) for k in ("ecosystem", "name", "version", "archive_sha256")}, "runs": []}
    for d in run["decisions"]:
        d["reason"] = clean_evidence(d.get("reason", ""))
    log["runs"].append(run)
    errs = [f"{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in
            jsonschema.Draft202012Validator(json.loads(REPAIR_SCHEMA.read_text())).iter_errors(log)]
    if errs:
        raise ValueError("repair log does not validate: " + "; ".join(errs[:5]))
    _write_atomic(path, json.dumps(log, indent=2, ensure_ascii=False) + "\n")
    return path


def repair_decisions(reports: Path, claims_of: dict[str, dict[str, dict]], record_sha: dict[str, str] | None = None):
    """((package, claim_id) -> latest decision on the claim as it stands now, failures). A decision counts only
    while its claim_sha256 is the current one (a fix changes the claim, so its decision describes history); a
    decision on the record's review flags (claim_id 'record') only while the record is the one it left."""
    record_sha = record_sha or {}
    import jsonschema
    validator = jsonschema.Draft202012Validator(json.loads(REPAIR_SCHEMA.read_text()))
    out, failures = {}, []
    for path, log, err in read_repairs(reports):
        errs = [err] if err else [f"{'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
                                  for e in validator.iter_errors(log)]
        if errs:
            failures.append((path, errs))
            continue
        key = path.parent.name
        claims = claims_of.get(key, {})
        for run in log["runs"]:
            for d in run["decisions"]:
                c = claims.get(d["claim_id"])
                current = (record_sha.get(key) == run["record_sha256_after"]) if d["claim_id"] == "record" else \
                    (c is not None and c["claim_sha256"] == d["claim_sha256"])
                if current:
                    out[(key, d["claim_id"])] = {**d, "by": run["by"]}
    return out, failures


def join(records: list[dict], reports: Path, append_only: bool = False):
    """Joins every sidecar to its record's current claims.

    Returns (claim_rows, verdict_rows, failures, warnings): one claim row per claim with its final status,
    one verdict row per non-stale latest verdict per verifier, and messages for aggregate.py to print."""
    validator = load_validator()
    by_key, claims_of = {}, {}
    for rec in records:
        pk = rec["package"]
        k = key_for(pk["ecosystem"], pk["name"], pk["version"])
        by_key[k] = rec
        claims_of[k] = {c["claim_id"]: c for c in claim_model.enumerate_claims(rec)}
    failures, warnings, verdict_rows = [], [], []
    stale_total = stale_sidecars = 0
    grouped: dict[tuple[str, str], dict[str, list[dict]]] = {}
    for path, side, err in read_sidecars(reports):
        key = path.parent.name
        claims = claims_of.get(key)
        errs = [err] if err else sidecar_errors(validator, side, claims)
        if not errs and append_only:
            why = appended_only(path, side)
            errs = [why] if why else []
        if errs:
            failures.append((path, errs))
            continue
        stale = sum(is_stale(v, claims) for run in side["runs"] for v in run["verdicts"])
        stale_total += stale
        stale_sidecars += bool(stale)
        for cid, v in latest(side, claims).items():
            row = {"package": key, "claim_id": cid, "layer": claim_model.layer_of(cid), "method": side["method"],
                   **{k: v[k] for k in ("by", "verdict", "grade", "reason_code")}}
            verdict_rows.append(row)
            grouped.setdefault((key, cid), {}).setdefault(side["method"], []).append(v)
    if stale_total:
        warnings.append(f"{stale_total} stale verdicts in {stale_sidecars} sidecars ignored: their claims have changed "
                        "since")
    repairs, repair_failures = repair_decisions(reports, claims_of,
                                                {k: claim_model.record_sha(r) for k, r in by_key.items()})
    failures += repair_failures
    claim_rows = []
    for key, claims in sorted(claims_of.items()):
        rec = by_key[key]
        for c in claims.values():
            by_method = grouped.get((key, c["claim_id"]), {})
            final, source = final_status(by_method)
            det = by_method.get("deterministic", [])
            conf = confirmed_refutation(final, by_method)
            rep = repairs.get((key, c["claim_id"]))
            if rep is not None and (rep["final_seen"] != final or rep["confirmed"] != conf):
                rep = None  # the verdicts changed since the decision (e.g. a refutation was confirmed): reopen
            claim_rows.append({"package": key, "claim_id": c["claim_id"], "layer": c["layer"],
                               "provenance": c["provenance"], "ecosystem": rec["package"]["ecosystem"],
                               "source_label": rec["package"]["source_label"],
                               "obfuscation": rec["obfuscation"]["level"], "final": final, "final_source": source,
                               "deterministic": det[-1]["verdict"] if det else None,
                               "grade": det[-1]["grade"] if det else None,
                               "confirmed": conf, "repair": rep["decision"] if rep else None})
    return claim_rows, verdict_rows, failures, warnings


GATE_BLOCKING = ("refuted", "disputed", "unanchored")


def blocks_gate(r: dict) -> bool:
    """A gate stays out of the results while one of its L1-L4 claims is contradicted or cannot be tied to the code,
    whatever the repair decision: repair shares the analyst's model family, so its rejection does not clear a
    reviewer's refutation. Exclusivity (`.excl`) is a graded measurement, not a claim about the gate's existence."""
    return r["layer"] in ("L1", "L2", "L3", "L4") and r["final"] in GATE_BLOCKING \
        and not r["claim_id"].endswith(".excl")


def closed(r: dict) -> bool:
    """A claim is closed when it is verified, or when it is refuted or disputed and the repair pass has logged a
    decision that leaves it standing (rejected or escalated). A fixed claim is a new claim and needs verifying."""
    return r["final"] == "verified" or (r["final"] in ("refuted", "disputed")
                                        and r.get("repair") in ("rejected", "escalated"))


def unverified_out_of_set(claim_rows: list[dict]) -> list[str]:
    """Out-of-set L1-L3 claims that are not closed (release gate for the dataset)."""
    return [f"{r['package']} {r['claim_id']}" for r in claim_rows
            if r["provenance"] == "out_of_set" and r["layer"] in ("L1", "L2", "L3")
            and not r["claim_id"].endswith(".excl") and not closed(r)]


OOS_PENDING = "out-of-set claim pending verification"


def effective_review_reasons(rec: dict, claim_rows: list[dict]) -> list[str]:
    """The record's review reasons with the ones verification has since closed removed: the out-of-set reason
    goes once every out-of-set claim of the record is closed."""
    pk = rec["package"]
    key = key_for(pk["ecosystem"], pk["name"], pk["version"])
    rows = [r for r in claim_rows if r["package"] == key]
    pending = [r for r in rows if r["provenance"] == "out_of_set" and r["layer"] in ("L1", "L2", "L3")
               and not r["claim_id"].endswith(".excl") and not closed(r)]
    return [x for x in rec.get("review_reasons") or [] if not (x == OOS_PENDING and not pending)]


def open_refutations(claim_rows: list[dict]) -> list[dict]:
    """Refuted or disputed claims with no repair decision yet: the repair pass's work list. Exclusivity (`.excl`)
    is a graded measurement of the gate, not a claim the analyst made, so it is never a repair item."""
    return [r for r in claim_rows if r["final"] in ("refuted", "disputed") and r.get("repair") is None
            and not r["claim_id"].endswith(".excl")]


STATUSES = ("verified", "refuted", "disputed", "unanchored", "cannot_tell", "unverified")


def _pct(n: int, d: int) -> str:
    return f"{n} / {d} ({100 * n / d:.0f}%)" if d else f"{n} / 0"


def layer_table(rows: list[dict], key: str) -> list[list]:
    out = []
    for layer in claim_model.LAYERS:
        rs = [r for r in rows if r["layer"] == layer and not r["claim_id"].endswith(".excl")]
        out.append([layer, len(rs)] + [sum(1 for r in rs if (r[key] or "unverified") == s) for s in STATUSES])
    return out


def _agreement(pairs: list[tuple[str, str, str]]):
    """(n, percent agreement, kappa, ci) for (package, a, b) pairs; the CI resamples whole packages."""
    from tools.common.agreement import bootstrap_ci, cohen_kappa
    groups = {}
    for pkg, a, b in pairs:
        groups.setdefault(pkg, []).append((a, b))
    k = cohen_kappa([a for _, a, _ in pairs], [b for _, _, b in pairs])
    ci = bootstrap_ci(groups, lambda items: cohen_kappa([a for a, _ in items], [b for _, b in items]))
    pct = sum(a == b for _, a, b in pairs) / len(pairs) if pairs else None
    return len(pairs), pct, k, ci


def kappa_rows(verdict_rows: list[dict]) -> list[list]:
    """Per layer: every pair of verifiers (each agent model separately, never pooled, and the deterministic pass) on
    the claims both judged. Rows: [layer, comparison, n, percent agreement, kappa, ci]."""
    out = []
    for layer in claim_model.LAYERS:
        by_verifier = {}
        for v in verdict_rows:
            if v["layer"] == layer:
                name = v["by"] if v["method"] == "agent" else "deterministic"
                by_verifier.setdefault(name, {})[(v["package"], v["claim_id"])] = v["verdict"]
        names = sorted(by_verifier)
        for i, a in enumerate(names):
            for b in names[i + 1:]:
                va, vb = by_verifier[a], by_verifier[b]
                pairs = [(k[0], va[k], vb[k]) for k in sorted(va.keys() & vb.keys())]
                out.append([layer, f"{a} vs {b}", *_agreement(pairs)])
    return out


def repair_history(reports: Path) -> dict[str, int]:
    """decision -> how many were logged over every repair run (valid logs only)."""
    out: dict[str, int] = {}
    for _, log, err in read_repairs(reports):
        for run in (log or {}).get("runs", []) if not err else []:
            for d in run["decisions"]:
                out[d["decision"]] = out.get(d["decision"], 0) + 1
    return out


def summary_md(claim_rows: list[dict], verdict_rows: list[dict], reports: Path | None = None) -> str:
    def table(header, rows):
        lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
        for r in rows:
            lines.append("| " + " | ".join(str(x) for x in r) + " |")
        return lines

    def fmt(k):
        return "n/a" if k is None else f"{k:.2f}"

    lines = ["# Verification summary", "",
             "Generated by `tools/common/aggregate.py` from `reports/_verification/`. Counts only. A claim's final "
             "status is `disputed` when the deterministic pass or any agent model contradict each other (verified "
             "vs refuted); else the deterministic verified/refuted, the agents' verdict; else the open verdicts. "
             "Stale verdicts (on a claim that changed) are never counted.", "",
             f"- Claims: {len(claim_rows)} across {len({r['package'] for r in claim_rows})} records", ""]
    lines += ["## Final status by layer", ""] + table(["layer", "claims", *STATUSES], layer_table(claim_rows, "final"))
    lines += ["", "## Deterministic pass by layer", ""] + table(["layer", "claims", *STATUSES],
                                                                 layer_table(claim_rows, "deterministic"))
    for prov in ("in_set", "out_of_set"):
        rs = [r for r in claim_rows if r["provenance"] == prov]
        lines += ["", f"## Final status by layer, {prov.replace('_', '-')} claims", ""] + \
            table(["layer", "claims", *STATUSES], layer_table(rs, "final"))
    labels = sorted({r["source_label"] for r in claim_rows})
    if len(labels) > 1:  # a benign corpus next to the malicious one: base rates and false-positive rates
        for label in labels:
            rs = [r for r in claim_rows if r["source_label"] == label]
            lines += ["", f"## Final status by layer, source label {label}", ""] + \
                table(["layer", "claims", *STATUSES], layer_table(rs, "final"))
    excl = [r for r in claim_rows if r["claim_id"].endswith(".excl")]
    lines += ["", "## Payload exclusivity (deterministic grade)", ""]
    lines += [f"- {g}: {_pct(sum(1 for r in excl if r['grade'] == g), len(excl))}"
              for g in ("exclusive", "non_exclusive", "unknown")] if excl else ["- none"]
    n_settled = sum(1 for r in claim_rows if r["final_source"] == "deterministic" and r["final"] in DECISIVE)
    lines += ["", "## Residual trust", "",
              f"- Claims settled by the deterministic checker: {_pct(n_settled, len(claim_rows))}",
              f"- Claims resting on an agent verdict or on nothing: "
              f"{_pct(len(claim_rows) - n_settled, len(claim_rows))}", ""]
    opened = open_refutations(claim_rows)
    history = repair_history(reports) if reports is not None else {}
    lines += ["## Repair", "",
              f"- Refuted or disputed claims without a repair decision: {len(opened)}",
              "- Decisions logged over all repair runs (a fixed claim changes, so its decision is history):",
              *[f"  - `{d}`: {history.get(d, 0)}" for d in REPAIR_DECISIONS],
              "- Decisions that still stand on the claims as they are now:",
              *[f"  - `{d}`: {sum(1 for r in claim_rows if r.get('repair') == d)}" for d in REPAIR_DECISIONS], ""]
    lines += ["## Agreement", "", "Each pair of verifiers on the claims both judged.", ""] + \
        table(["layer", "comparison", "n", "agree", "kappa", "95% CI (package bootstrap)"],
              [[l, c, n, "n/a" if pct is None else f"{pct:.2f}", fmt(k),
                "n/a" if ci is None else f"{ci[0]:.2f} to {ci[1]:.2f}"]
               for l, c, n, pct, k, ci in kappa_rows(verdict_rows)])
    return "\n".join(lines) + "\n"


AGREEMENT_PAIR = ("claude-sonnet-5-5", "gpt-6.1-sol")  # the two reviewers that judged the most claims in common
ROW_GROUPS = ("L1", "L2", "L3", "L3 excl.", "L4", "L5", "L6 interp.", "L6 drop")


def row_group(claim_id: str, layer: str) -> str:
    """Table IV's row: exclusivity and dropped candidates apart from the rest of their layer."""
    if claim_id.endswith(".excl"):
        return "L3 excl."
    if layer == "L6":
        return "L6 drop" if claim_id.endswith(".drop") else "L6 interp."
    return layer


def agreement_by_row(claim_rows: list[dict], verdict_rows: list[dict], label: str = "malicious",
                     pair: tuple[str, str] = AGREEMENT_PAIR) -> list[list]:
    """Per Table IV row, on one label's claims: final-verdict counts, then the two reviewers' agreement on the claims
    both judged. Rows: [row, claims, verified, refuted, disputed, open, n, agree, kappa, ci]."""
    cs = [c for c in claim_rows if c["source_label"] == label]
    by = {name: {(v["package"], v["claim_id"]): v["verdict"] for v in verdict_rows
                 if v["method"] == "agent" and v["by"] == name} for name in pair}
    out = []
    for group in ROW_GROUPS:
        rs = [c for c in cs if row_group(c["claim_id"], c["layer"]) == group]
        n_final = {s: sum(1 for c in rs if c["final"] == s) for s in ("verified", "refuted", "disputed")}
        opened = sum(1 for c in rs if (c["final"] or "unverified") in ("unanchored", "cannot_tell", "unverified"))
        pairs = [(c["package"], by[pair[0]][k], by[pair[1]][k]) for c in rs
                 for k in [(c["package"], c["claim_id"])] if k in by[pair[0]] and k in by[pair[1]]]
        out.append([group, len(rs), n_final["verified"], n_final["refuted"], n_final["disputed"], opened,
                    *_agreement(pairs)])
    return out


def write_tables(dataset: Path, claim_rows: list[dict], verdict_rows: list[dict]) -> None:
    import csv
    tables = dataset / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    with open(tables / "verif_by_layer.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["subset", "layer", "claims", *STATUSES])
        subsets = [("all", claim_rows)] + [(p, [r for r in claim_rows if r["provenance"] == p])
                                           for p in ("in_set", "out_of_set")] + \
            [(f"label:{label}", [r for r in claim_rows if r["source_label"] == label])
             for label in sorted({r["source_label"] for r in claim_rows})]
        for name, rs in subsets:
            for row in layer_table(rs, "final"):
                w.writerow([name, *row])
    with open(tables / "agreement_by_row.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["row", "claims", "verified", "refuted", "disputed", "open", "comparison", "n", "agree", "kappa",
                    "ci_low", "ci_high"])
        for row, claims, ver, ref, disp, opened, n, pct, k, ci in agreement_by_row(claim_rows, verdict_rows):
            w.writerow([row, claims, ver, ref, disp, opened, " vs ".join(AGREEMENT_PAIR), n,
                        "" if pct is None else f"{pct:.4f}", "" if k is None else f"{k:.4f}",
                        *(["", ""] if ci is None else [f"{ci[0]:.4f}", f"{ci[1]:.4f}"])])
    with open(tables / "kappa.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["layer", "comparison", "n", "agree", "kappa", "ci_low", "ci_high"])
        for layer, comp, n, pct, k, ci in kappa_rows(verdict_rows):
            w.writerow([layer, comp, n, "" if pct is None else f"{pct:.4f}", "" if k is None else f"{k:.4f}",
                        *(["", ""] if ci is None else [f"{ci[0]:.4f}", f"{ci[1]:.4f}"])])
