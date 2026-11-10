import copy
import json

import pytest

from tools.common import aggregate, claims, contract, paths, verification
from tools.verify import record_verdict


def write_report(repo, rec):
    path = contract.report_path(repo / "reports", rec["package"]["ecosystem"], rec["package"]["name"],
                                rec["package"]["version"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# x\n\n```json\n" + json.dumps(rec) + "\n```\n")
    return path


def ids(rec):
    return [c["claim_id"] for c in claims.enumerate_claims(rec)]


def test_claims_are_enumerated_in_natural_order(record):
    assert ids(record) == ["c1.L1", "c1.L2", "c1.L6.category", "c2.L1", "c2.L2", "c2.L6.category",
                           "g1.then.L3", "g1.then.L3.excl", "g1.then.L5", "g1.L4",
                           "g1.L6.polarity", "g1.L6.effect", "g1.L6.purpose"]
    assert all(claims.CLAIM_ID.match(i) for i in ids(record))


def test_claim_hash_changes_only_with_its_fields(record):
    before = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(record)}
    changed = copy.deepcopy(record)
    changed["conditions"][0]["value"] = "linux"
    after = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(changed)}
    assert before["c1.L2"] != after["c1.L2"] and before["c1.L1"] == after["c1.L1"]
    assert before["c2.L2"] == after["c2.L2"]


def test_not_recovered_value_has_no_value_claim(record):
    record["conditions"][1]["value_recovered"] = "not_recovered"
    assert "c2.L2" not in ids(record)


def test_final_status_order():
    det_v = {"verdict": "verified"}
    assert verification.final_status({}) == ("unverified", "none")
    assert verification.final_status({"deterministic": [{"verdict": "cannot_tell"}],
                                      "agent": [{"verdict": "refuted"}]}) == ("refuted", "agent")
    # a contradiction between the deterministic pass and an agent is never settled by trusting one side
    assert verification.final_status({"deterministic": [det_v], "agent": [{"verdict": "refuted"}]}) == \
        ("disputed", "disputed")
    assert verification.final_status({"deterministic": [det_v], "agent": [{"verdict": "cannot_tell"}]}) == \
        ("verified", "deterministic")
    assert verification.final_status({"agent": [{"verdict": "verified"}, {"verdict": "refuted"}]}) == \
        ("disputed", "disputed")
    assert verification.final_status({"agent": [{"verdict": "verified"}, {"verdict": "verified"}]}) == \
        ("verified", "agent")


def verdict_for(rec, claim_id, verdict="verified", **extra):
    c = next(c for c in claims.enumerate_claims(rec) if c["claim_id"] == claim_id)
    return {"claim_id": claim_id, "claim_sha256": c["claim_sha256"], "verdict": verdict,
            "evidence": "see https://evil.example/x", **extra}


PACKET = "0" * 16


def test_agent_verdicts_are_appended_defanged_and_joined(repo, record):
    write_report(repo, record)
    path = record_verdict.record(record, "gpt-x", [verdict_for(record, "c1.L1"),
                                                   verdict_for(record, "g1.L6.purpose", "refuted")], PACKET)
    side = json.loads(path.read_text())
    assert path.name == "agent__gpt-x.json" and len(side["runs"]) == 1
    assert side["runs"][0]["verdicts"][0]["evidence"] == "see hxxps://evil[.]example/x"
    assert side["runs"][0]["verdicts"][1]["reason_code"] == "judgement"
    record_verdict.record(record, "gpt-x", [verdict_for(record, "c2.L1")], PACKET)
    assert len(json.loads(path.read_text())["runs"]) == 2
    rows, verdicts, failures, warnings = verification.join([record], paths.REPORTS)
    assert not failures and not warnings
    final = {r["claim_id"]: (r["final"], r["final_source"]) for r in rows}
    assert final["c1.L1"] == ("verified", "agent") and final["g1.L6.purpose"] == ("refuted", "agent")
    assert final["c1.L2"] == ("unverified", "none")


def test_stale_and_unknown_verdicts_are_refused(record, repo):
    stale = verdict_for(record, "c1.L2")
    stale["claim_sha256"] = "0" * 16
    with pytest.raises(SystemExit) as e:
        record_verdict.record(record, "gpt-x", [stale, {"claim_id": "c9.L1", "verdict": "verified"}], PACKET)
    assert "c1.L2 is stale" in str(e.value) and "'c9.L1' is not a claim" in str(e.value)


def test_reanalysed_record_makes_verdicts_stale(repo, record):
    write_report(repo, record)
    record_verdict.record(record, "gpt-x", [verdict_for(record, "c1.L2")], PACKET)
    changed = copy.deepcopy(record)
    changed["conditions"][0]["value"] = "linux"
    rows, _, failures, warnings = verification.join([changed], paths.REPORTS)
    assert not failures and warnings and "1 stale" in warnings[0]
    assert next(r for r in rows if r["claim_id"] == "c1.L2")["final"] == "unverified"


def test_deterministic_runs_cannot_rule_on_judgement(repo, record):
    run = {"by": "verify@abc", "record_sha256": claims.record_sha(record), "packet_sha256": None, "blinded": False,
           "verdicts": [verdict_for(record, "g1.L6.purpose", grade=None, reason_code=None, evidence_refs=[])]}
    path = verification.append_run(paths.REPORTS, record["package"], "deterministic", run)
    errs = verification.sidecar_errors(verification.load_validator(), json.loads(path.read_text()),
                                       {c["claim_id"]: c for c in claims.enumerate_claims(record)})
    assert any("judgement claim" in e for e in errs)


def test_aggregate_writes_verification_tables_and_gates_out_of_set(repo, record, monkeypatch, capsys):
    record["conditions"][1]["sites"][0]["candidate"] = None
    record["conditions"][1]["provenance"] = "out_of_set"
    record.update(needs_manual_review=True, review_reasons=["out-of-set claim pending verification"])
    write_report(repo, record)
    record_verdict.record(record, "gpt-x", [verdict_for(record, "c2.L1")], PACKET)
    monkeypatch.setattr("sys.argv", ["aggregate.py", "--require-oos-verified"])
    assert aggregate.main() == 1
    assert "out-of-set claims are not closed" in capsys.readouterr().err
    monkeypatch.setattr("sys.argv", ["aggregate.py"])
    assert aggregate.main() == 0
    md = (repo / "dataset" / "verification.md").read_text()
    assert "## Final status by layer" in md and "| L1 | 2 | 1 | 0 | 0 | 0 | 0 | 1 |" in md
    assert (repo / "dataset" / "tables" / "verif_by_layer.csv").read_text().startswith("subset,layer")
    rows = [json.loads(line) for line in (repo / "dataset" / "claims.jsonl").read_text().splitlines()]
    assert {r["claim_id"] for r in rows} >= {"c1.L1", "g1.L4"}
    # every table names its package by the same key, so they join
    pkgs = [json.loads(line) for line in (repo / "dataset" / "packages.jsonl").read_text().splitlines()]
    gates = [json.loads(line) for line in (repo / "dataset" / "gates.jsonl").read_text().splitlines()]
    assert {g["key"] for g in gates} | {r["package"] for r in rows} <= {p["key"] for p in pkgs}


def row(claim_id="g1.L4", layer="L4", final="refuted", repair=None):
    return {"claim_id": claim_id, "layer": layer, "final": final, "repair": repair}


@pytest.mark.parametrize("repair", [None, "rejected", "escalated"])
@pytest.mark.parametrize("final", ["refuted", "disputed", "unanchored"])
def test_a_contradicted_or_unanchored_claim_blocks_its_gate_whatever_the_repair(final, repair):
    assert verification.blocks_gate(row(final=final, repair=repair))


@pytest.mark.parametrize("r", [row(final="verified"), row(final="cannot_tell"), row(claim_id="g1.L6.purpose", layer="L6"),
                               row(claim_id="g1.then.L5", layer="L5"), row(claim_id="g1.then.L3.excl", layer="L3")])
def test_other_claims_leave_the_gate_in(r):
    assert not verification.blocks_gate(r)


@pytest.mark.parametrize("r, closed", [(row(final="verified"), True), (row(repair="rejected"), True),
                                       (row(repair="escalated"), True), (row(), False), (row(repair="fixed"), False),
                                       (row(final="cannot_tell"), False)])
def test_a_claim_is_closed_once_verified_or_left_standing_by_repair(r, closed):
    assert verification.closed(r) is closed


def test_a_refutation_is_confirmed_by_two_kinds_of_verifier():
    both = {"deterministic": [{"verdict": "refuted"}], "agent": [{"verdict": "refuted"}]}
    assert verification.confirmed_refutation(verification.final_status(both)[0], both)
    one = {"agent": [{"verdict": "refuted"}]}
    assert not verification.confirmed_refutation(verification.final_status(one)[0], one)


def test_exclusivity_is_never_a_repair_item():
    rows = [{"claim_id": "g1.then.L3.excl", "final": "refuted", "repair": None},
            {"claim_id": "g1.then.L3", "final": "disputed", "repair": None},
            {"claim_id": "g2.then.L3", "final": "refuted", "repair": "rejected"}]
    assert [r["claim_id"] for r in verification.open_refutations(rows)] == ["g1.then.L3"]


def test_moving_a_gate_region_changes_its_l4_claim(record):
    import copy
    before = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(record)}
    moved = copy.deepcopy(record)
    moved["gates"][0]["then"]["regions"][0]["end_byte"] += 1
    after = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(moved)}
    assert before["g1.L4"] != after["g1.L4"]  # L4 is read over the regions, so a region fix is a new claim


@pytest.mark.parametrize("mutate, claim_id", [
    (lambda r: r["gates"][0]["guards"][0].update(arm="else" if r["gates"][0]["guards"][0]["arm"] == "then" else "then"),
     "c1.L2"),                                                    # L2 reads the operator in the guard's sense
    (lambda r: r["conditions"][0].update(category="env_var"), "c1.L2"),       # L2 normalises values by category
    (lambda r: r["conditions"][0].update(value_recovered="decoded"), "c1.L1"),  # L1 holds decoded sites open
    (lambda r: r["conditions"][0]["sites"][0]["anchor"].update(end_byte=r["conditions"][0]["sites"][0]["anchor"]
                                                               ["end_byte"] + 1), "g1.L4"),  # L4 maps tests by site
])
def test_every_field_a_check_reads_is_part_of_its_claim(record, mutate, claim_id):
    import copy
    before = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(record)}
    changed = copy.deepcopy(record)
    mutate(changed)
    after = {c["claim_id"]: c["claim_sha256"] for c in claims.enumerate_claims(changed)}
    assert before[claim_id] != after[claim_id]


def test_a_reviewer_side_note_is_dropped_not_fatal(record):
    from tools.verify.record_verdict import check_verdicts
    v = verdict_for(record, "c1.L1", grades_note="n/a")
    out, problems = check_verdicts(record, [v], "agent")
    assert not problems and "grades_note" not in out[0]
    out, problems = check_verdicts(record, [verdict_for(record, "c1.L1", grades_allowed=[])], "agent")
    assert not problems and "grades_allowed" not in out[0]  # copied from the packet's claim
    _, problems = check_verdicts(record, [verdict_for(record, "c1.L1", confidence=0.9)], "agent")
    assert any("unknown fields" in p for p in problems)
