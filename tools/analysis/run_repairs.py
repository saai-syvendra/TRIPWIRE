#!/usr/bin/env python3
"""
The repair pass as a batch (skills/repair-gates), in the same bubblewrap sandbox as run_analyses.py. For each
package on the repair work list (repair.py --list):

1. outside the sandbox: reopen the report into scratch/<key>/ (prepare.py on its sample, registered decodes
   replayed) and snapshot the open items into scratch/<key>/repair_items.json (repair.py --reopen, --brief);
2. one fresh headless session on one pinned model fixes what the code supports through write_report.py and
   writes a decision for every item to scratch/<key>/repair_decisions.json. It runs the analysis tools only:
   repair.py, prepare.py and the drivers are denied, so the session cannot reopen, snapshot or log;
3. outside the sandbox: the decisions are logged with repair.py's checks under the model the session log
   shows (repair__<model>.json), and every package whose record changed gets a deterministic run
   (verify.py). Review packets for the changed claims are built with packet.py --mode residual.

A session that hits a safeguard refusal or a model switch, writes no decisions, or changes the record's analyst
(package.model_name / analysis_type) is not logged; the report it may have rewritten is restored from the snapshot
taken before the session. Items past round 2 are not sent to a session: repair.py only accepts `escalated` then.

Usage: run_repairs.py --model MODEL_ID [--jobs N] [--timeout S] [--only KEY ...] [--dry-run] [--no-sandbox]
Results go to scratch/_runs/repairs.jsonl (one line per package) and the session logs to
scratch/_runs/<key>.repair.jsonl. Nothing from a package is run by this driver.
"""
from __future__ import annotations

import argparse
import datetime
import json
import shutil
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.analysis import repair, run_analyses  # noqa: E402
from tools.common import claims as claim_model  # noqa: E402
from tools.common import contract, paths  # noqa: E402

PROMPT = ("Repair the gate record of {key} with the repair-gates skill. scratch/{key}/ is already reopened and its "
          "open items, with every verifier's evidence, are in scratch/{key}/repair_items.json: do not run repair.py "
          "(the driver reopens, snapshots and logs), and read only scratch/{key}/. Where the code supports a fix, "
          "edit scratch/{key}/record.json and run .venv/bin/python tools/analysis/write_report.py scratch/{key}. "
          "Keep package.model_name and package.analysis_type as they are. Then write your decision for every open "
          "item to scratch/{key}/repair_decisions.json as the skill describes, and stop. "
          + run_analyses.TOOLS_NOTE)
DENY = ("tools/analysis/repair.py*", "tools/analysis/run_repairs.py*")
DECISIONS = "repair_decisions.json"
_lock = threading.Lock()


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def log_result(row: dict) -> None:
    with _lock:
        out = run_analyses.runs_dir() / "repairs.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "a", encoding="utf-8") as f:
            f.write(json.dumps(row) + "\n")


def repair_one(item: dict, model: str, claude: str, timeout: float) -> dict:
    key, report = item["key"], paths.ROOT / item["report"]
    row = {"key": key, "round": item["round"], "items": len(item["items"]), "requested_model": model,
           "started_at": now()}
    if all(it.get("round", item["round"]) > repair.MAX_ROUNDS for it in item["items"]):
        return {**row, "status": "skipped", "note": f"every item is past round {repair.MAX_ROUNDS}: only escalation is "
                "allowed"}
    before_text = report.read_text(encoding="utf-8")
    before = contract.read_record(report)
    try:
        work = repair.reopen(report)
        repair.brief(key)
    except SystemExit as e:
        return {**row, "status": "error", "note": f"reopen failed: {e}"}
    (work / DECISIONS).unlink(missing_ok=True)
    code, timed_out = run_analyses.run_session(key, model, claude, timeout, PROMPT, DENY, pin_model=False,
                                               log_name=f"{key}.repair")
    log = run_analyses.runs_dir() / f"{key}.repair.jsonl"
    facts = run_analyses.session_facts(log.read_text(encoding="utf-8", errors="replace"))
    models = facts["models"]
    after = contract.read_record(report) if report.is_file() else None

    def restore(why: str) -> dict:
        report.write_text(before_text, encoding="utf-8")
        return {**row, "status": why[0], "note": why[1], "model": models, "finished_at": now(), "exit": code}

    if not models and not (facts["refusal"] or facts["fallback"]):
        # no model answered (the API was unreachable, the login failed): nothing was decided, so retry it
        tail = str((facts["result"] or {}).get("result") or "")[-200:]
        return restore(("error", f"the session reached no model ({tail or 'no result'}); report restored"))
    if facts["refusal"] or facts["fallback"] or len(models) != 1:
        return restore(("blocked", f"session had a safeguard refusal, a model fallback or {len(models)} models; "
                                   "report restored"))
    if models[0] != model:
        return restore(("model_mismatch", f"the session ran {models[0]}, not {model}; report restored"))
    if after is None or {k: after["package"].get(k) for k in ("model_name", "analysis_type")} != \
            {k: before["package"].get(k) for k in ("model_name", "analysis_type")}:
        return restore(("error", "the session changed or removed the record's analyst; report restored"))
    path = work / DECISIONS
    if not timed_out and not path.is_file() and facts["stopped"]:
        return restore(("blocked", "a safeguard stopped a response and the session wrote no decisions; "
                                   "report restored"))
    if timed_out or not path.is_file():
        return restore(("timeout" if timed_out else "error", "no repair_decisions.json; report restored"))
    try:
        decisions = json.loads(path.read_text(encoding="utf-8"))
        repair.record_decisions(key, models[0], decisions)
    except (ValueError, SystemExit) as e:
        return restore(("error", f"decisions not logged: {str(e)[:300]}; report restored"))
    adopted, problems = run_analyses.adopt_decoders(key, run_analyses.cited_decoders(report))
    if problems:
        return restore(("error", "candidate decoder not adopted: " + "; ".join(problems)[:300] + "; report restored"))
    changed = claim_model.record_sha(after) != claim_model.record_sha(before)
    counts = {}
    for d in decisions:
        counts[d.get("decision")] = counts.get(d.get("decision"), 0) + 1
    return {**row, "status": "done", "model": models[0], "changed": changed, "decisions": counts,
            "decoders_adopted": adopted, "finished_at": now(), "exit": code}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", required=True, help="full model id every session runs on")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--timeout", type=float, default=run_analyses.DEFAULT_TIMEOUT)
    ap.add_argument("--only", nargs="+", metavar="KEY")
    ap.add_argument("--dry-run", action="store_true", help="list the work, run nothing")
    ap.add_argument("--claude", default="claude")
    ap.add_argument("--no-sandbox", action="store_true", help="run without bubblewrap (tests with a fake CLI only)")
    args = ap.parse_args()
    run_analyses.SANDBOX = not args.no_sandbox
    if run_analyses.SANDBOX and shutil.which("bwrap") is None:
        raise SystemExit("bwrap (bubblewrap) is not installed; it keeps each session to its own package")
    work = [w for w in repair.work_list() if not args.only or w["key"] in args.only]
    if args.dry_run:
        for w in work:
            print(f"{w['key']}  round {w['round']}: " + ", ".join(i["claim_id"] for i in w["items"]))
        return 0
    print(f"{len(work)} packages to repair, {args.jobs} at a time, model {args.model}", flush=True)

    def one(w):
        row = repair_one(w, args.model, args.claude, args.timeout)
        if row.get("changed"):  # verified as each repair lands, so a stopped batch leaves no changed record unchecked
            from tools.verify import verify
            report = paths.ROOT / w["report"]
            verify.run([(report, contract.read_record(report))])
        log_result(row)
        print(f"{row['status']:15} {w['key']}  {row.get('decisions') or row.get('note') or ''}", flush=True)
        return row
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        rows = list(pool.map(one, work))
    changed = [w for w, r in zip(work, rows) if r.get("changed")]
    if changed:
        print(f"re-verified {len(changed)} changed record(s); build review packets with "
              "packet.py --mode residual", flush=True)
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    print(f"{len(rows)} packages: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    return 0 if all(r["status"] in ("done", "skipped") for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
