#!/usr/bin/env python3
"""
The deterministic verification pass: rebuilds each record's package from samples/ (by archive_sha256), resolves
every anchor, re-derives from the syntax tree what each claim says, and appends one run of verdicts to
reports/_verification/<key>/deterministic__verify.json.

Verdicts: verified, refuted, unanchored (the claim cannot be tied to bytes; reason_code says why) and
cannot_tell (anchored, but outside what the checker decides). Judgement claims (L6) are left to agents.

Usage: python tools/verify/verify.py [REPORT ...] [--all] [--dry-run]
Never executes package code: archives are unpacked as data and parsed with tree-sitter.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import claims as claim_model  # noqa: E402
from tools.common import contract, paths, verification  # noqa: E402
from tools.verify import apimatch, checks, witness  # noqa: E402
from tools.verify.source import Package, Unanchored, sample_index  # noqa: E402

TOOL = "verify"


PARSERS = ("tree-sitter", "tree-sitter-javascript", "tree-sitter-python")


def environment() -> str:
    """The parts of the environment a verdict depends on besides the code: Python and the pinned parsers."""
    from importlib.metadata import PackageNotFoundError, version

    def v(name):
        try:
            return version(name)
        except PackageNotFoundError:
            return "none"
    py = ".".join(map(str, sys.version_info[:2]))
    return f"py{py}.ts{v(PARSERS[0])}.js{v(PARSERS[1])}.pyg{v(PARSERS[2])}"


def tool_version() -> str:
    return f"{TOOL}@{environment()}"


def open_grade(claim_id: str) -> str | None:
    """The grade a graded claim takes when it is left open."""
    return {"excl": "unknown", "L4": "cannot_tell", "L5": "cannot_tell"}.get(claim_model.grade_kind(claim_id))


def verdicts_for(rec: dict, index: dict) -> list[dict]:
    claims = claim_model.enumerate_claims(rec)
    try:
        pkg = Package(rec, index)
    except Unanchored as e:
        return [{"claim_id": c["claim_id"], "claim_sha256": c["claim_sha256"],
                 **checks.result("unanchored", e.reason, e.detail)}
                for c in claims if c["layer"] in claim_model.DETERMINISTIC_LAYERS]
    return package_verdicts(pkg, rec)


def package_verdicts(pkg, rec: dict) -> list[dict]:
    """Verdicts for every deterministic claim of a record against an already rebuilt package."""
    claims = claim_model.enumerate_claims(rec)
    conds = {c["id"]: c for c in rec["conditions"]}
    gates = {g["gate_id"]: g for g in rec["gates"]}

    def check(c: dict) -> dict:
        cid, layer = c["claim_id"], c["layer"]
        branch = cid.split(".")[1] if cid.split(".")[1] in ("then", "else") else None
        if layer == "L1":
            return apimatch.check_l1(pkg, conds[c["subject"]])
        if layer == "L2":
            return apimatch.check_l2(pkg, rec, conds[c["subject"]])
        if layer == "L3" and cid.endswith(".excl"):
            return witness.check_exclusive(pkg, rec, gates[c["subject"]], branch)
        if layer == "L3":
            return witness.check_l3(pkg, rec, gates[c["subject"]], branch)
        if layer == "L4":
            return witness.check_l4(pkg, rec, gates[c["subject"]])
        return witness.check_l5(pkg, gates[c["subject"]], branch)

    out = []
    for c in claims:
        if c["layer"] not in claim_model.DETERMINISTIC_LAYERS:
            continue  # L6 is judgement, for agents
        try:
            with checks.budget(checks.CLAIM_BUDGET):
                v = check(c)
        except checks.BudgetExceeded:
            v = checks.result("cannot_tell", "budget_exceeded",
                              f"stopped after {checks.CLAIM_BUDGET:,} syntax nodes; the code is too large to decide this "
                              "claim within the fixed budget", grade=open_grade(c["claim_id"]))
        except Unanchored as e:
            v = checks.result("unanchored", e.reason, e.detail, grade=open_grade(c["claim_id"]))
        except RecursionError:
            v = checks.result("cannot_tell", "budget_exceeded", "the code nests too deeply to decide this claim",
                              grade=open_grade(c["claim_id"]))
        except Exception as e:  # noqa: BLE001 - a checker fault is never evidence about the claim
            v = checks.result("cannot_tell", "checker_error", f"the checker failed on this claim ({type(e).__name__}); "
                              "this is a bug in the checker, not a finding", grade=open_grade(c["claim_id"]))
        out.append({"claim_id": c["claim_id"], "claim_sha256": c["claim_sha256"], **v})
    return out


def _same_as_last(rec: dict, by: str, verdicts: list[dict]) -> bool:
    """The last run in this record's sidecar came from the same environment on the same record and says the same:
    appending it again would add nothing."""
    path = verification.sidecar_path(paths.REPORTS, rec["package"], "deterministic", by)
    if not path.is_file():
        return False
    runs = json.loads(path.read_text(encoding="utf-8")).get("runs") or []
    if not runs:
        return False
    last = runs[-1]

    def core(vs):
        return [{k: v.get(k) for k in ("claim_id", "claim_sha256", "verdict", "grade", "reason_code")} for v in vs]
    return last["by"] == by and last["record_sha256"] == claim_model.record_sha(rec) and \
        core(last["verdicts"]) == core(verdicts)


def run(records: list[tuple[Path, dict]], dry_run: bool = False) -> list[tuple[Path, list[dict]]]:
    index = sample_index()
    by = tool_version()
    skipped = []
    done = []
    for path, rec in records:
        if rec.get("record_type") != "analysed":
            continue
        if not dry_run and rec["package"].get("archive_sha256") not in index:
            skipped.append(path)  # a verdict that only says the sample is absent would bury the real ones
            continue
        try:
            verdicts = verdicts_for(rec, index)
        except Exception as e:  # noqa: BLE001 - one broken record must not stop the batch
            verdicts = [{"claim_id": c["claim_id"], "claim_sha256": c["claim_sha256"],
                         **checks.result("cannot_tell", "checker_error", f"the checker failed on this record "
                                         f"({type(e).__name__}); this is a bug in the checker, not a finding",
                                         grade=open_grade(c["claim_id"]))}
                        for c in claim_model.enumerate_claims(rec) if c["layer"] in claim_model.DETERMINISTIC_LAYERS]
        if not dry_run and verdicts and not _same_as_last(rec, by, verdicts):
            run_ = {"by": by, "record_sha256": claim_model.record_sha(rec), "packet_sha256": None, "blinded": False,
                    "verdicts": verdicts}
            verification.append_run(paths.REPORTS, rec["package"], "deterministic", run_)
        done.append((path, verdicts))
    if skipped:
        print(f"skipped {len(skipped)} records with no sample under samples/ (nothing written for them)",
              file=sys.stderr)
    return done


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("reports", nargs="*", type=Path)
    ap.add_argument("--all", action="store_true", help="every report under reports/npm and reports/pypi")
    ap.add_argument("--dry-run", action="store_true", help="print verdicts, write nothing")
    args = ap.parse_args()
    files = list(args.reports)
    if args.all:
        files += sorted(p for eco in ("npm", "pypi") for p in (paths.REPORTS / eco).glob("*.md"))
    if not files:
        ap.error("name reports or pass --all")
    records = [(p, contract.read_record(p)) for p in files]
    totals = {}
    for path, verdicts in run(records, args.dry_run):
        for v in verdicts:
            totals[v["verdict"]] = totals.get(v["verdict"], 0) + 1
        if args.dry_run:
            print(json.dumps({"report": str(path), "verdicts": verdicts}, ensure_ascii=False))
    print(f"{len(records)} records: " + ", ".join(f"{n} {k}" for k, n in sorted(totals.items())), file=sys.stderr)


if __name__ == "__main__":
    main()
