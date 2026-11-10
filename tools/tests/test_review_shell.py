"""The bwrap command line review_shell builds for each CLI, interactive and headless."""
from tools.verify import review_shell as rs

PROMPT = "Review the packet."


def build(cli, monkeypatch, tmp_path, **kw):
    monkeypatch.setattr(rs, "runtime_binds", lambda c: (f"/opt/{c}", [], []))
    return rs.command("p-x", cli, tmp_path, tmp_path / "run", **kw)


def tail(cmd, exe):
    return cmd[cmd.index(exe) + 1:]


def test_claude_interactive_has_no_prompt(monkeypatch, tmp_path):
    assert tail(build("claude", monkeypatch, tmp_path), "/opt/claude") == []


def test_claude_headless_passes_the_prompt_with_p(monkeypatch, tmp_path):
    assert tail(build("claude", monkeypatch, tmp_path, headless_prompt=PROMPT, model="m1"), "/opt/claude") == \
        ["--model", "m1", "-p", PROMPT]


def test_codex_interactive_keeps_approval_never(monkeypatch, tmp_path):
    assert tail(build("codex", monkeypatch, tmp_path), "/opt/codex") == rs.CODEX_ARGS


def test_codex_headless_uses_exec_with_the_prompt_last(monkeypatch, tmp_path):
    got = tail(build("codex", monkeypatch, tmp_path, headless_prompt=PROMPT, model="m2"), "/opt/codex")
    assert got == [*rs.CODEX_EXEC_ARGS, "--model", "m2", PROMPT]
    assert got[0] == "exec" and "--ask-for-approval" not in got


def test_pending_skips_done_and_honours_only(tmp_path):
    from tools.verify.run_reviews import pending
    q = tmp_path / "queue.jsonl"
    q.write_text('{"packet_id": "a"}\n{"packet_id": "b", "status": "done"}\n{"packet_id": "c"}\n')
    assert pending(q) == ["a", "c"]
    assert pending(q, ["c", "b"]) == ["c"]


def test_the_queue_tracks_each_cli_separately(tmp_path):
    from tools.verify import run_reviews
    from tools.verify.record_verdict import done_by
    q = tmp_path / "queue.jsonl"
    q.write_text('{"packet_id": "p-a", "status": "done"}\n{"packet_id": "p-b", "done": ["codex"]}\n'
                 '{"packet_id": "p-c"}\n')
    assert run_reviews.pending(q, cli="claude") == ["p-b", "p-c"]
    assert run_reviews.pending(q, cli="codex") == ["p-a", "p-c"]
    assert done_by({"status": "done"}) == {"claude"} and done_by({"done": ["codex"]}) == {"codex"}
