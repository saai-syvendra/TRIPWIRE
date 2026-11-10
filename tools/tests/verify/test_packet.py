import json
import subprocess
import sys

import pytest

from tools.common import paths, reset
from tools.tests.verify.test_verify_gates import build
from tools.verify import packet, record_verdict, show, verify


@pytest.fixture
def reviewed(repo):
    rec = build(repo)
    report = next((repo / "reports" / "npm").glob("*.md"))
    verify.run([(report, rec)])
    return rec


def packets(repo):
    return sorted((repo / "scratch" / "verify").glob("p-*/packet.json"))


def test_packet_is_blind_and_deterministic(reviewed, repo):
    built = packet.build("all")
    assert len(built) == 1
    body = packets(repo)[0].read_text()
    data = json.loads(body)
    for leaked in ("two-way", "purpose_reason", "claude", "assessment", "provenance", "candidate", "out_of_set",
                   "verified", "https://", "datadog"):
        assert leaked not in body.replace('"verdicts_allowed": [\n        "verified"', ""), leaked
    assert {c["claim_id"] for c in data["claims"]} >= {"c1.L1", "g1.L6.purpose"}
    assert all("slice" in json.dumps(c["fields"]) or c["layer"] == "L6" for c in data["claims"])
    assert "hxxps://evil[.]example/x" in json.dumps(data["slices"])
    packet.build("all")
    assert packets(repo)[0].read_text() == body


def test_residual_and_out_of_set_modes(reviewed, repo):
    packet.build("residual")
    data = json.loads(packets(repo)[0].read_text())
    layers = {c["layer"] for c in data["claims"]}
    assert "L6" in layers and "L1" not in layers  # the deterministic pass settled L1 here
    oos = packet.build("out_of_set")
    assert len(oos) == 1  # g1 was cited by hand


def sample_inputs(repo):
    """The rows and claims packet.build() samples from, for the one package in the test repo."""
    from tools.common import claims as claim_model, contract, verification
    (rec,) = [contract.read_record(p) for p in (repo / "reports" / "npm").glob("*.md")]
    rows, _, _, _ = verification.join([rec], paths.REPORTS)
    return rows, {rows[0]["package"]: {c["claim_id"]: c for c in claim_model.enumerate_claims(rec)}}


def test_show_caps_defangs_and_logs(reviewed, repo, monkeypatch, capsys):
    pid = packet.build("all")[0]
    data = json.loads(packets(repo)[0].read_text())
    monkeypatch.setattr("sys.argv", ["show.py", pid, "--file", "f1", "--grep", "https"])
    show.main()
    out = capsys.readouterr().out
    assert "hxxps://evil[.]example" in out and "https://" not in out
    log = (repo / "scratch" / "verify" / pid / "access.log").read_text()
    assert "--grep" in log and data["files"][0]["id"] == "f1"


def test_show_bytes_windows_the_anchor(reviewed, repo, monkeypatch, capsys):
    pid = packet.build("all")[0]
    data = json.loads(packets(repo)[0].read_text())
    s = data["slices"][0]
    monkeypatch.setattr("sys.argv", ["show.py", pid, "--slice", s["id"], "--bytes", "40"])
    show.main()
    out = capsys.readouterr().out
    assert ">>>" in out and "<<<" in out  # the anchor bytes are marked
    assert f"anchor {s['start']}-{s['end']}" in out
    # the window is bounded by MAX_BYTES either side, not the whole file
    assert len(out) <= 2 * show.MAX_BYTES + (s["end"] - s["start"]) + 200


def agent_verdicts(data, verdict="verified"):
    return [{"claim_id": c["claim_id"], "claim_sha256": c["claim_sha256"], "verdict": verdict,
             "evidence": "checked at the slice"} for c in data["claims"] if c["layer"] == "L6"]


def test_agent_verdicts_go_through_the_sandboxed_review_with_an_audited_session_log(reviewed, repo, monkeypatch,
                                                                                    tmp_path_factory):
    from tools.tests.verify.test_transcript_audit import CLEAN_CODEX, PATCH, claude_log, codex_log
    from tools.verify import review_shell
    dest = tmp_path_factory.mktemp("review-dest")
    pid = packet.build("residual")[0]
    data = json.loads(packets(repo)[0].read_text())
    monkeypatch.setattr(review_shell, "runtime_binds", lambda cli: ("/usr/bin/true", [], []))

    def review(cli, log):
        run = review_shell.prepare(pid, cli, dest, fresh=True)
        (run / "review" / "verdicts.json").write_text(json.dumps(agent_verdicts(data)))
        where = run / "home" / (".claude/projects/-review/s.jsonl" if cli == "claude"
                                else ".codex/sessions/2026/10/06/rollout-1.jsonl")
        where.parent.mkdir(parents=True, exist_ok=True)
        where.write_text(log)
    argv = ["record_verdict.py", "--packet", pid, "--session-log", "auto", "--dest", str(dest)]
    review("codex", codex_log(CLEAN_CODEX + ["cat ../reports/npm/x.md"], patch=PATCH))
    monkeypatch.setattr("sys.argv", argv)
    with pytest.raises(SystemExit) as e:
        record_verdict.main()
    assert "blinding broken" in str(e.value) and "outside the review folder" in str(e.value)
    assert reset.pending_packets() == [pid]
    review("codex", codex_log(CLEAN_CODEX, patch=PATCH))
    monkeypatch.setattr("sys.argv", argv + ["--by", "someone-else"])
    with pytest.raises(SystemExit, match="does not match the model"):
        record_verdict.main()
    monkeypatch.setattr("sys.argv", argv)
    record_verdict.main()
    side = json.loads(next((repo / "reports" / "_verification").glob("*/agent__gpt-test.json")).read_text())
    run = side["runs"][0]
    assert run["blinded"] and run["packet_sha256"]
    assert reset.pending_packets() == []
    review("claude", claude_log([("Read", {"file_path": "packet.json"}),
                                 ("Write", {"file_path": "/review/verdicts.json", "content": "[]"})]))
    with pytest.raises(SystemExit, match="pass --cli"):
        record_verdict.main()
    monkeypatch.setattr("sys.argv", argv + ["--cli", "claude"])
    record_verdict.main()
    assert next((repo / "reports" / "_verification").glob("*/agent__claude-test-model.json"))


def test_plain_text_transcripts_are_refused_for_agents(reviewed, repo, monkeypatch, tmp_path):
    pid = packet.build("residual")[0]
    data = json.loads(packets(repo)[0].read_text())
    verdicts, log = tmp_path / "v.json", tmp_path / "session.txt"
    verdicts.write_text(json.dumps(agent_verdicts(data)))
    log.write_text("I read packet.json and wrote my verdicts.\n")
    monkeypatch.setattr("sys.argv", ["record_verdict.py", "--packet", pid, "--by", "gpt-test",
                                     "--verdicts", str(verdicts), "--session-log", str(log)])
    with pytest.raises(SystemExit, match="not JSON"):
        record_verdict.main()


def test_reset_refuses_while_packets_are_pending(reviewed, repo, monkeypatch):
    packet.build("residual")
    monkeypatch.setattr("sys.argv", ["reset.py"])
    assert reset.main() == 1


def test_cli_entry_points_run():
    for tool in ("packet", "show", "record_verdict", "verify", "review_shell"):
        proc = subprocess.run([sys.executable, str(paths.CODE_ROOT / "tools" / "verify" / f"{tool}.py"), "--help"],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr


def test_residual_leaves_out_claims_an_agent_already_reviewed():
    rows = [{"package": "k", "claim_id": "g1.L6.purpose", "layer": "L6", "provenance": "in_set",
             "deterministic": None},
            {"package": "k", "claim_id": "g1.L4", "layer": "L4", "provenance": "in_set",
             "deterministic": "cannot_tell"}]
    claims_of = {"k": {"g1.L6.purpose": {"claim_id": "g1.L6.purpose"}, "g1.L4": {"claim_id": "g1.L4"}}}
    out = packet.select("residual", rows, claims_of, None, {("k", "g1.L6.purpose")})
    assert [c["claim_id"] for c in out["k"]] == ["g1.L4"]
    assert len(packet.select("all", rows, claims_of, None, {("k", "g1.L6.purpose")})["k"]) == 2


def test_unreviewed_includes_claims_no_agent_reviewed():
    rows = [{"package": "k", "claim_id": "c1.L1", "layer": "L1", "provenance": "in_set",
             "deterministic": "verified"},
            {"package": "k", "claim_id": "g1.L6.purpose", "layer": "L6", "provenance": "in_set",
             "deterministic": None}]
    claims_of = {"k": {"c1.L1": {"claim_id": "c1.L1"}, "g1.L6.purpose": {"claim_id": "g1.L6.purpose"}}}
    reviewed = {("k", "g1.L6.purpose")}
    out = packet.select("unreviewed", rows, claims_of, None, reviewed)
    assert [c["claim_id"] for c in out["k"]] == ["c1.L1"]
    assert "k" not in packet.select("residual", rows, claims_of, None, reviewed)


def test_reviewer_counts_only_that_models_verdicts():
    rows = [{"package": "k", "claim_id": "g1.L4", "method": "agent", "by": "claude-sonnet-5-5"},
            {"package": "k", "claim_id": "g1.L6.purpose", "method": "agent", "by": "gpt-6.1-sol"},
            {"package": "k", "claim_id": "c1.L1", "method": "deterministic", "by": "verify@x"}]
    assert packet.reviewed_by(rows) == {("k", "g1.L4"), ("k", "g1.L6.purpose")}
    assert packet.reviewed_by(rows, "gpt-6.1-sol") == {("k", "g1.L6.purpose")}


def test_a_sample_missing_verdict_does_not_count_as_reviewed():
    rows = [{"package": "k", "claim_id": "c1.L1", "method": "agent", "by": "gpt-6.1-sol",
             "reason_code": "sample_missing"}]
    assert packet.reviewed_by(rows, "gpt-6.1-sol") == set()


def test_a_queued_packet_whose_record_changed_is_superseded_and_rebuilt(reviewed, repo):
    from tools.analysis import write_report
    from tools.verify import run_reviews
    (old,) = packet.build("all")
    work = next(p for p in (repo / "scratch").iterdir() if (p / "record.json").is_file())
    rec = json.loads((work / "record.json").read_text())
    rec["gates"][0]["purpose"] = "unclear"  # a repair changes one claim
    (work / "record.json").write_text(json.dumps(rec))
    write_report.finish(work)
    built = packet.build("residual")
    queue = [json.loads(line) for line in (repo / "scratch" / "verify" / "queue.jsonl").read_text().splitlines()]
    rows = {r["packet_id"]: r for r in queue}
    assert rows[old].get("superseded") is True
    fresh = [r for r in queue if r["mode"] == "all" and not r.get("superseded")]
    assert len(fresh) == 1 and fresh[0]["packet_id"] in built and fresh[0]["packet_id"] != old
    assert old not in run_reviews.pending(repo / "scratch" / "verify" / "queue.jsonl")
    assert old not in reset.pending_packets()
    # a second build finds nothing new to retire
    packet.build("residual")
    assert [json.loads(line) for line in (repo / "scratch" / "verify" / "queue.jsonl").read_text().splitlines()] \
        == queue
