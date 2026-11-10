"""The repair pass's decision rules (tools/analysis/repair.py) and its log (schema/repair.schema.json)."""
import copy

import pytest

from tools.analysis import repair
from tools.common import claims, paths, verification


def item(rec, cid="g1.then.L3", confirmed=False, round_=1, final="refuted"):
    c = next(c for c in claims.enumerate_claims(rec) if c["claim_id"] == cid)
    return {"key": "npm__demo-pkg@1.0.0", "round": round_, "record_sha256_before": claims.record_sha(rec),
            "items": [{"claim_id": cid, "claim_sha256": c["claim_sha256"], "final": final, "confirmed": confirmed}]}


def test_rejecting_needs_an_unchanged_claim_and_an_unconfirmed_refutation(record):
    out, problems = repair.check_decisions(item(record), [{"claim_id": "g1.then.L3", "decision": "rejected",
                                                           "reason": "the agent misread the else block"}], record)
    assert not problems and out[0]["decision"] == "rejected" and out[0]["final_seen"] == "refuted"
    _, problems = repair.check_decisions(item(record, confirmed=True),
                                         [{"claim_id": "g1.then.L3", "decision": "rejected", "reason": "x"}], record)
    assert any("confirmed refutation" in p for p in problems)
    _, problems = repair.check_decisions(item(record, round_=3),
                                         [{"claim_id": "g1.then.L3", "decision": "rejected", "reason": "x"}], record)
    assert any("only escalated" in p for p in problems)


def test_fixed_needs_the_claim_to_have_changed(record):
    snap = item(record)
    _, problems = repair.check_decisions(snap, [{"claim_id": "g1.then.L3", "decision": "fixed", "reason": "x"}],
                                         record)
    assert any("unchanged" in p for p in problems)
    fixed = copy.deepcopy(record)
    fixed["gates"][0]["then"]["payload"][0]["sink_kind"] = "exec"
    out, problems = repair.check_decisions(snap, [{"claim_id": "g1.then.L3", "decision": "fixed", "reason": "x"}],
                                           fixed)
    assert not problems


def test_every_open_item_needs_a_decision_with_a_reason(record):
    _, problems = repair.check_decisions(item(record), [], record)
    assert any("no decision" in p for p in problems)
    _, problems = repair.check_decisions(item(record), [{"claim_id": "g1.then.L3", "decision": "escalated"}], record)
    assert any("needs a reason" in p for p in problems)


def test_the_repair_log_validates_and_ties_decisions_to_the_current_claim(repo, record):
    snap = item(record)
    out, _ = repair.check_decisions(snap, [{"claim_id": "g1.then.L3", "decision": "rejected", "reason": "x"}],
                                    record)
    run = {"by": "claude-opus-5-5", "record_sha256_before": snap["record_sha256_before"], "record_sha256_after": claims.record_sha(record),
           "round": 1, "decisions": out}
    verification.append_repair(paths.REPORTS, record["package"], run)
    claims_of = {"npm__demo-pkg@1.0.0": {c["claim_id"]: c for c in claims.enumerate_claims(record)}}
    got, failures = verification.repair_decisions(paths.REPORTS, claims_of)
    assert not failures and got[("npm__demo-pkg@1.0.0", "g1.then.L3")]["decision"] == "rejected"
    bad = {**run, "decisions": [{**out[0], "confirmed": True}]}  # the schema forbids rejecting a confirmed one
    with pytest.raises(ValueError):
        verification.append_repair(paths.REPORTS, record["package"], bad)


def test_rounds_are_counted_per_claim(repo, record):
    snap = item(record)
    out, _ = repair.check_decisions(snap, [{"claim_id": "g1.then.L3", "decision": "escalated", "reason": "x"}], record)
    run = {"by": "m", "record_sha256_before": snap["record_sha256_before"],
           "record_sha256_after": claims.record_sha(record), "round": 1, "decisions": out}
    for _ in range(2):
        verification.append_repair(paths.REPORTS, record["package"], run)
    rounds = repair.claim_rounds("npm__demo-pkg@1.0.0")
    assert rounds == {"g1.then.L3": 2}  # another claim of the same package would start at round 1
    late = {**snap, "items": [{**snap["items"][0], "round": rounds["g1.then.L3"] + 1}]}
    _, problems = repair.check_decisions(late, [{"claim_id": "g1.then.L3", "decision": "fixed", "reason": "x"}],
                                         record)
    assert any("only escalated" in p for p in problems)
