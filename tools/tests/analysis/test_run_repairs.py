"""run_repairs.py with a fake session: what is logged, what is restored. The reopen and snapshot steps are
stubbed (they are tested with repair.py), so these tests exercise the driver's own decisions."""
import json

import pytest

from tools.analysis import repair, run_analyses, run_repairs
from tools.common import claims, paths

KEY = "npm__demo-pkg@1.0.0"


@pytest.fixture
def setup(repo, record, monkeypatch):
    report = repo / "reports" / "npm" / "demo-pkg@1.0.0.md"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("# r\n\n```json\n" + json.dumps(record) + "\n```\n", encoding="utf-8")
    work = repo / "scratch" / KEY
    work.mkdir(parents=True)
    c = next(c for c in claims.enumerate_claims(record) if c["claim_id"] == "g1.then.L3")
    item = {"key": KEY, "report": "reports/npm/demo-pkg@1.0.0.md", "round": 1,
            "record_sha256_before": claims.record_sha(record),
            "items": [{"claim_id": "g1.then.L3", "claim_sha256": c["claim_sha256"], "final": "refuted",
                       "confirmed": False}]}
    (work / repair.ITEMS).write_text(json.dumps(item))
    monkeypatch.setattr(repair, "reopen", lambda report: work)
    monkeypatch.setattr(repair, "brief", lambda key: work / repair.ITEMS)

    def session(models, decisions=None, edit=None, refusal=False):
        def fake(key, model, claude, timeout, prompt, deny, pin_model, log_name):
            assert not pin_model and "repair.py" in " ".join(deny) and "repair-gates" in prompt
            lines = [{"type": "assistant", "message": {"model": m, "content": [],
                                                       "stop_reason": "refusal" if refusal else None}}
                     for m in models]
            (run_analyses.runs_dir()).mkdir(parents=True, exist_ok=True)
            (run_analyses.runs_dir() / f"{log_name}.jsonl").write_text("\n".join(json.dumps(x) for x in lines))
            if decisions is not None:
                (work / run_repairs.DECISIONS).write_text(json.dumps(decisions))
            if edit:
                report.write_text(edit(report.read_text()))
            return 0, False
        monkeypatch.setattr(run_analyses, "run_session", fake)
    return report, item, session


def test_a_clean_session_is_logged_under_its_model(setup):
    report, item, session = setup
    session(["claude-opus-5-5"], [{"claim_id": "g1.then.L3", "decision": "escalated", "reason": "needs a decoder"}])
    row = run_repairs.repair_one(item, "claude-opus-5-5", "claude", 60)
    assert row["status"] == "done" and row["decisions"] == {"escalated": 1} and not row["changed"]
    log = paths.REPORTS / "_verification" / KEY / "repair__claude-opus-5-5.json"
    assert json.loads(log.read_text())["runs"][0]["decisions"][0]["decision"] == "escalated"


@pytest.mark.parametrize("models, refusal, status", [(["claude-opus-5-5", "claude-opus-4-8"], False, "blocked"),
                                                     (["claude-opus-5-5"], True, "blocked"),
                                                     (["claude-opus-4-8"], False, "model_mismatch")])
def test_a_blocked_session_restores_the_report(setup, models, refusal, status):
    report, item, session = setup
    before = report.read_text()
    session(models, [{"claim_id": "g1.then.L3", "decision": "escalated", "reason": "x"}],
            edit=lambda t: t.replace('"demo-pkg"', '"demo-pkg"') + "\n<!-- edited -->\n", refusal=refusal)
    row = run_repairs.repair_one(item, "claude-opus-5-5", "claude", 60)
    assert row["status"] == status and report.read_text() == before


def test_a_session_that_reached_no_model_is_an_error_to_retry(setup, monkeypatch):
    report, item, session = setup
    before = report.read_text()
    session([])
    real = run_analyses.session_facts
    monkeypatch.setattr(run_analyses, "session_facts", lambda text: {**real(text), "result": {
        "result": "API Error: Can't reach the API server (EAI_AGAIN)"}})
    row = run_repairs.repair_one(item, "claude-opus-5-5", "claude", 60)
    assert row["status"] == "error" and "EAI_AGAIN" in row["note"] and report.read_text() == before


def test_a_safeguard_stop_without_decisions_is_blocked(setup, monkeypatch):
    report, item, session = setup
    session(["claude-opus-5-5"])
    real = run_analyses.session_facts
    monkeypatch.setattr(run_analyses, "session_facts", lambda text: {**real(text), "stopped": True})
    row = run_repairs.repair_one(item, "claude-opus-5-5", "claude", 60)
    assert row["status"] == "blocked" and "safeguard" in row["note"]


def test_changing_the_analyst_is_refused(setup):
    report, item, session = setup
    before = report.read_text()
    session(["claude-opus-5-5"], [{"claim_id": "g1.then.L3", "decision": "escalated", "reason": "x"}],
            edit=lambda t: t.replace('"analysis_type": "ai"', '"analysis_type": "tool"'))
    row = run_repairs.repair_one(item, "claude-opus-5-5", "claude", 60)
    assert row["status"] == "error" and "analyst" in row["note"] and report.read_text() == before


def test_rounds_past_the_limit_are_not_sent_to_a_session(setup):
    _, item, _ = setup
    row = run_repairs.repair_one({**item, "round": 3}, "claude-opus-5-5", "claude", 60)
    assert row["status"] == "skipped"
