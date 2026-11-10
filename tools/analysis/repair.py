#!/usr/bin/env python3
"""
The repair pass (skills/repair-gates): after verification, every refuted or disputed claim and every record still
flagged for manual review gets a logged decision. A fix goes through write_report.py like any analysis, so the
record keeps every check; the decision is appended to reports/_verification/<key>/repair__<by>.json.

  repair.py --list                      the work list: one JSON line per package with open items
  repair.py --reopen REPORT             rebuild scratch/<key>/ from the report (prepare.py on its sample, then the
                                        report's record and prose as record.json and summary.md)
  repair.py --brief KEY                 snapshot the package's open items, with each verifier's evidence, into
                                        scratch/<key>/repair_items.json (the record as it stands is the "before")
  repair.py --record KEY --by MODEL --decisions FILE
                                        log the decisions on the snapshotted items, after write_report.py ran

A decisions file is a JSON list of {"claim_id", "decision", "reason"}; claim_id "record" decides the review flag.
The tool, not the reviewer, fills in hashes and whether a refutation is confirmed, and refuses decisions that do
not fit what happened to the record:
  fixed      the claim changed (or is gone) since the snapshot; for "record", the record is no longer flagged
  rejected   the claim is unchanged; never for a confirmed refutation, never after round 2
  escalated  left unresolved (always allowed); a blocked gate stays out of the results
  cleared / kept_flag   for "record": the flag is gone / still there
A confirmed refutation (the deterministic pass and an agent agree) must be fixed or escalated. Nothing from a package is run.
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
from tools.common.contract import key_for  # noqa: E402

MAX_ROUNDS = 2
ITEMS = "repair_items.json"


def analysed_records() -> dict[str, tuple[Path, dict]]:
    out = {}
    for eco in ("npm", "pypi"):
        for p in sorted((paths.REPORTS / eco).glob("*.md")):
            rec = contract.read_record(p)
            if rec.get("record_type") == "analysed":
                pk = rec["package"]
                out[key_for(pk["ecosystem"], pk["name"], pk["version"])] = (p, rec)
    return out


def verdicts_by_claim(verdict_rows: list[dict]) -> dict[tuple[str, str], list[dict]]:
    out = {}
    for v in verdict_rows:
        out.setdefault((v["package"], v["claim_id"]), []).append(v)
    return out


def claim_rounds(key: str) -> dict[str, int]:
    """claim_id -> decisions already logged on it for this package (any repairer, any version of the claim). An
    item's round is that count plus one, so a claim that newly turns refuted starts at round 1 even in a package
    that was repaired before."""
    d = paths.REPORTS / "_verification" / key
    out: dict[str, int] = {}
    for p in sorted(d.glob("repair__*.json")) if d.is_dir() else []:
        for run in json.loads(p.read_text(encoding="utf-8")).get("runs", []):
            for dec in run["decisions"]:
                out[dec["claim_id"]] = out.get(dec["claim_id"], 0) + 1
    return out


def work_list() -> list[dict]:
    recs = analysed_records()
    rows, verdict_rows, failures, _ = verification.join([r for _, r in recs.values()], paths.REPORTS)
    if failures:
        raise SystemExit("fix the sidecars first (aggregate.py --check)")
    by_claim = verdicts_by_claim(verdict_rows)
    out = []
    for key, (path, rec) in sorted(recs.items()):
        items = []
        for r in verification.open_refutations([x for x in rows if x["package"] == key]):
            vs = by_claim.get((key, r["claim_id"]), [])
            items.append({"claim_id": r["claim_id"], "final": r["final"], "final_source": r["final_source"],
                          "confirmed": r["confirmed"],
                          "verdicts": [{k: v[k] for k in ("method", "by", "verdict", "reason_code")} for v in vs]})
        reasons = verification.effective_review_reasons(rec, rows)
        if rec.get("needs_manual_review") and reasons and not record_decided(key, rec):
            items.append({"claim_id": "record", "final": "flagged", "review_reasons": reasons})
        if items:
            done = claim_rounds(key)
            for it in items:
                it["round"] = done.get(it["claim_id"], 0) + 1
            out.append({"key": key, "report": path.relative_to(paths.ROOT).as_posix(),
                        "round": max(it["round"] for it in items), "items": items})
    return out


def record_decided(key: str, rec: dict) -> bool:
    """A repair decision already covers the record's review flag as it stands."""
    decisions, _ = verification.repair_decisions(paths.REPORTS, {key: {}}, {key: claim_model.record_sha(rec)})
    return (key, "record") in decisions


def reopen(report: Path) -> Path:
    """scratch/<key>/ rebuilt from a finished report: prepared.json from its sample (deterministic), the report's
    record as record.json and its prose as summary.md, ready for edits and write_report.py."""
    from tools.analysis import prepare
    from tools.analysis.write_report import sections
    from tools.verify.source import sample_index
    rec = contract.read_record(report)
    pk = rec["package"]
    sample = sample_index().get(pk.get("archive_sha256"))
    if sample is None:
        raise SystemExit(f"no sample under samples/ has sha256 {str(pk.get('archive_sha256'))[:12]}")
    res = prepare.prepare(sample, pk["source_dataset"], pk["source_label"], {},
                          model=pk.get("model_name"), allow_existing=True)
    if res.get("status") != "analyse":
        raise SystemExit(f"reopen failed: prepare.py says {res.get('status')}: {res.get('note', '')}")
    work = paths.SCRATCH / res["key"]
    replay_decodes(work, rec)
    (work / "record.json").write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    prose = sections(report.read_text(encoding="utf-8"))
    (work / "summary.md").write_text(f"## Summary\n\n{prose.get('summary', '')}\n\n## Notes\n\n"
                                     f"{prose.get('notes', '')}\n", encoding="utf-8")
    return work


def replay_decodes(work: Path, rec: dict) -> None:
    """Rebuild scratch/<key>/derived/<id> for the record's registered (decode_spec) derivations, in order, from the
    package bytes, and check each against its output_sha256, so the reopened folder cites exactly what the report
    cites."""
    from tools.analysis.register_decode import reader
    from tools.common import anchors, decode_spec
    prepared = json.loads((work / "prepared.json").read_text(encoding="utf-8"))
    read_bytes = reader(work, prepared)
    for d in rec["normalisation"]["derivations"]:
        if d.get("recipe") != decode_spec.RECIPE:
            continue
        out = decode_spec.replay(read_bytes, d)
        if anchors.digest(out) != d.get("output_sha256"):
            raise SystemExit(f"reopen failed: derivation {d['id']} no longer replays to its output_sha256")
        (work / "derived").mkdir(parents=True, exist_ok=True)
        (work / "derived" / d["id"]).write_bytes(out)


def brief(key: str) -> Path:
    item = next((w for w in work_list() if w["key"] == key), None)
    if item is None:
        raise SystemExit(f"{key}: nothing to repair")
    _, rec = analysed_records()[key]
    claims = {c["claim_id"]: c for c in claim_model.enumerate_claims(rec)}
    for it in item["items"]:
        it["claim_sha256"] = "record" if it["claim_id"] == "record" else claims[it["claim_id"]]["claim_sha256"]
    item["record_sha256_before"] = claim_model.record_sha(rec)
    evidence = {}
    for path, side, _ in verification.read_sidecars(paths.REPORTS):
        if path.parent.name != key or side is None:
            continue
        latest = verification.latest(side, claims)
        for cid, v in latest.items():
            evidence.setdefault(cid, []).append({"method": side["method"], "by": v["by"], "verdict": v["verdict"],
                                                 "reason_code": v["reason_code"], "evidence": v["evidence"],
                                                 "evidence_refs": v["evidence_refs"]})
    for it in item["items"]:
        it["evidence"] = evidence.get(it["claim_id"], [])
    work = paths.SCRATCH / key
    work.mkdir(parents=True, exist_ok=True)
    out = work / ITEMS
    out.write_text(json.dumps(item, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def check_decisions(item: dict, decisions: list, rec: dict) -> tuple[list[dict], list[str]]:
    """Decisions completed with hashes, and the problems that block logging them."""
    snap = {it["claim_id"]: it for it in item["items"]}
    now = {c["claim_id"]: c["claim_sha256"] for c in claim_model.enumerate_claims(rec)}
    out, problems = [], []
    if not isinstance(decisions, list):
        return [], ["decisions must be a JSON list"]
    given = set()
    for i, d in enumerate(decisions):
        cid = d.get("claim_id") if isinstance(d, dict) else None
        it = snap.get(cid)
        if it is None:
            problems.append(f"#{i}: {cid!r} is not an open item of this package")
            continue
        given.add(cid)
        dec, reason = d.get("decision"), str(d.get("reason") or "").strip()
        if not reason:
            problems.append(f"#{i}: {cid} needs a reason")
        if cid == "record":
            flagged = bool(rec.get("needs_manual_review"))
            ok = {"cleared": not flagged, "kept_flag": flagged, "fixed": not flagged}.get(dec)
            if ok is None:
                problems.append(f"#{i}: the record's flag takes cleared, kept_flag or fixed, not {dec!r}")
            elif not ok:
                problems.append(f"#{i}: {dec} does not fit: the record is {'still' if flagged else 'no longer'} "
                                "flagged")
        else:
            changed = now.get(cid) != it["claim_sha256"]
            if dec == "fixed" and not changed:
                problems.append(f"#{i}: {cid} is unchanged since the snapshot; fix the record first (write_report)")
            elif dec == "rejected":
                if changed:
                    problems.append(f"#{i}: {cid} changed since the snapshot, so it was not rejected")
                if it.get("confirmed"):
                    problems.append(f"#{i}: {cid} is a confirmed refutation: fix it or escalate it")
            rnd = it.get("round", item["round"])
            if rnd > MAX_ROUNDS and dec != "escalated":
                problems.append(f"#{i}: {cid} is in round {rnd}: after {MAX_ROUNDS} rounds only escalated is allowed")
            elif dec != "escalated" and dec not in ("fixed", "rejected"):
                problems.append(f"#{i}: decision must be fixed, rejected or escalated, not {dec!r}")
        out.append({"claim_id": cid, "claim_sha256": it["claim_sha256"],
                    "final_seen": it["final"] if cid != "record" else "flagged",
                    "confirmed": bool(it.get("confirmed")), "decision": dec, "reason": reason})
    missing = sorted(set(snap) - given)
    if missing:
        problems.append(f"no decision for {missing}")
    return out, problems


def record_decisions(key: str, by: str, decisions: list) -> Path:
    work = paths.SCRATCH / key
    item = json.loads((work / ITEMS).read_text(encoding="utf-8"))
    path, rec = analysed_records()[key]
    out, problems = check_decisions(item, decisions, rec)
    if problems:
        raise SystemExit("not logged:\n  " + "\n  ".join(problems))
    run = {"by": by, "record_sha256_before": item["record_sha256_before"],
           "record_sha256_after": claim_model.record_sha(rec), "round": item["round"], "decisions": out}
    return verification.append_repair(paths.REPORTS, rec["package"], run)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--list", action="store_true")
    g.add_argument("--reopen", type=Path, metavar="REPORT")
    g.add_argument("--brief", metavar="KEY")
    g.add_argument("--record", metavar="KEY")
    ap.add_argument("--by", help="with --record: the repairing model id, or a person's short name")
    ap.add_argument("--decisions", type=Path, help="with --record: the decisions file")
    args = ap.parse_args()
    if args.list:
        for w in work_list():
            print(json.dumps(w, ensure_ascii=False))
    elif args.reopen:
        print(f"reopened in {reopen(args.reopen).relative_to(paths.ROOT)}")
    elif args.brief:
        print(f"open items in {brief(args.brief).relative_to(paths.ROOT)}")
    else:
        if not (args.by and args.decisions):
            ap.error("--record needs --by and --decisions")
        decisions = json.loads(args.decisions.read_text(encoding="utf-8"))
        print(f"logged in {record_decisions(args.record, args.by, decisions).relative_to(paths.ROOT)}")


if __name__ == "__main__":
    main()
