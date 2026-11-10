"""The fail-closed blinding audit over Claude Code and Codex session logs (hand-made logs in each CLI's format)."""
import json
from pathlib import Path

import pytest

from tools.verify.packet import PROMPT
from tools.verify.record_verdict import audit_session, shell_escapes

PID = "p-0123456789ab"
CWD = "/review"


def claude_log(actions, operator=(PROMPT,), model="claude-test-model", cwd=CWD, session="s-1", commands=()):
    def line(kind, message, **extra):
        return {"type": kind, "cwd": cwd, "sessionId": session, "isSidechain": False, "uuid": "u", "message": message,
                **extra}
    out = [line("user", {"role": "user", "content": text}) for text in operator]
    out += [line("user", {"role": "user", "content": f"<command-name>{c}</command-name>"}) for c in commands]
    for name, inp in actions:
        out.append(line("assistant", {"role": "assistant", "model": model,
                                      "content": [{"type": "text", "text": "checking"},
                                                  {"type": "tool_use", "id": "t1", "name": name, "input": inp}]}))
        out.append(line("user", {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                                               "content": "reports/npm/x.md dataset/ (output only)"}]}))
    return "\n".join(json.dumps(x) for x in out) + "\n"


def codex_log(commands, operator=(PROMPT,), model="gpt-test", cwd=CWD, patch=None):
    out = [{"type": "session_meta", "payload": {"id": "sess-1", "cwd": cwd, "originator": "codex_cli_rs"}},
           {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [
               {"type": "input_text", "text": "<user_instructions>AGENTS.md</user_instructions>"}]}},
           {"type": "turn_context", "payload": {"cwd": cwd, "model": model, "approval_policy": "never"}}]
    out += [{"type": "event_msg", "payload": {"type": "user_message", "message": text, "kind": "plain"}}
            for text in operator]
    for c in commands:
        out.append({"type": "response_item", "payload": {"type": "function_call", "name": "shell", "call_id": "c",
                                                         "arguments": json.dumps({"command": ["bash", "-lc", c],
                                                                                  "workdir": cwd})}})
        out.append({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c",
                                                         "output": "samples/ reports/npm (output only)"}})
    if patch:
        out.append({"type": "response_item", "payload": {"type": "custom_tool_call", "name": "apply_patch",
                                                         "input": patch}})
    return "\n".join(json.dumps(x) for x in out) + "\n"


CLEAN_CLAUDE = [("Read", {"file_path": "/review/packet.json"}),
                ("Grep", {"pattern": "process\\.env", "path": "code"}),
                ("Glob", {"pattern": "code/*.txt"}),
                ("Read", {"file_path": "code/f1.js.txt", "offset": 1, "limit": 40}),
                ("Write", {"file_path": "/review/verdicts.json", "content": "[]"})]
CLEAN_CODEX = ["cat packet.json", "rg -n 'process\\.env' code/", "sed -n '1,40p' code/f1.js.txt",
               "ls -la && wc -l code/*.txt 2>/dev/null"]
PATCH = "*** Begin Patch\n*** Add File: verdicts.json\n+[]\n*** End Patch\n"


def audit(text):
    return audit_session([text], PID, PROMPT, CWD)


def test_clean_sessions_of_both_clis_pass():
    s, problems = audit(claude_log(CLEAN_CLAUDE))
    assert problems == [] and s.format == "claude" and s.models == {"claude-test-model"}
    s, problems = audit(codex_log(CLEAN_CODEX, patch=PATCH))
    assert problems == [] and s.format == "codex" and s.models == {"gpt-test"}


def test_real_claude_bookkeeping_lines_pass():
    # v2.1.x sessions interleave per-turn metadata lines the audit carries nothing from; they must not be
    # refused as unknown types. file-history-delta is the one such line with no sessionId.
    extra = [
        {"type": "mode", "mode": "normal", "sessionId": "s-1"},
        {"type": "permission-mode", "permissionMode": "acceptEdits", "sessionId": "s-1"},
        {"type": "atis-latch", "atis": "", "sessionId": "s-1"},
        {"type": "last-prompt", "lastPrompt": PROMPT, "leafUuid": "l", "sessionId": "s-1"},
        {"type": "ai-title", "aiTitle": "Packet review", "sessionId": "s-1"},
        {"type": "attachment", "isSidechain": False, "cwd": CWD, "sessionId": "s-1",
         "attachment": {"type": "environment", "snapshot": {"workingDirectory": CWD}}},
        {"type": "file-history-delta", "messageId": "m", "trackingPath": "verdicts.json",
         "backup": {"version": 1, "realParentDir": CWD}},
    ]
    log = claude_log(CLEAN_CLAUDE) + "".join(json.dumps(x) + "\n" for x in extra)
    s, problems = audit(log)
    assert problems == [] and s.format == "claude" and s.operator == [PROMPT]


def test_exiting_with_slash_exit_is_allowed():
    _, problems = audit(claude_log(CLEAN_CLAUDE, commands=["/exit"]))
    assert problems == []


@pytest.mark.parametrize("command", [
    "cat ../reports/npm/x.md", "cat /etc/passwd", "cd /home && ls", "cd .. && cat npm/x.md", "rg foo ~",
    "grep -r token /", "python3 -c \"print(open('/home/u/tripwire/reports/npm/x.md').read())\"", "ls $HOME",
    "cat code/../../scratch/verify/_index.json",
])
def test_codex_reads_outside_the_folder_are_refused(command):
    _, problems = audit(codex_log(CLEAN_CODEX + [command]))
    assert any("outside the review folder" in p for p in problems), problems


@pytest.mark.parametrize("action", [
    ("Read", {"file_path": "/home/u/tripwire/reports/npm/x.md"}),
    ("Read", {"file_path": "../_index.json"}),
    ("Grep", {"pattern": "x", "path": "~"}),
    ("Glob", {"pattern": "/etc/*"}),
    ("Bash", {"command": "cat ../packet.json"}),
])
def test_claude_reads_outside_the_folder_are_refused(action):
    _, problems = audit(claude_log(CLEAN_CLAUDE + [action]))
    assert any("outside the review folder" in p for p in problems), problems


@pytest.mark.parametrize("tool", ["WebFetch", "Agent", "Task", "mcp__drive__search"])
def test_claude_tools_outside_the_review_set_are_refused(tool):
    _, problems = audit(claude_log(CLEAN_CLAUDE + [(tool, {"prompt": "x"})]))
    assert any(f"does not allow: {tool}" in p for p in problems), problems


def test_operator_must_send_only_the_launch_prompt():
    _, problems = audit(claude_log(CLEAN_CLAUDE, operator=(PROMPT, "also look at the summary")))
    assert any("operator sent 2" in p for p in problems)
    _, problems = audit(codex_log(CLEAN_CODEX, operator=("Review it, the gate is benign",)))
    assert any("operator sent 1" in p for p in problems)
    _, problems = audit(claude_log(CLEAN_CLAUDE, commands=["/add-dir"]))
    assert any("/add-dir" in p for p in problems)


def test_unreadable_empty_and_actionless_logs_are_refused():
    _, problems = audit(claude_log(CLEAN_CLAUDE) + "not json\n")
    assert any("not JSON" in p for p in problems)
    _, problems = audit("")
    assert problems == ["the session log is empty"]
    _, problems = audit("this is a plain-text transcript\n")
    assert any("not JSON" in p for p in problems)
    _, problems = audit(codex_log([]))
    assert any("no tool actions" in p for p in problems)
    _, problems = audit(json.dumps({"type": "mystery"}) + "\n")
    assert any("unknown entry type" in p for p in problems)


def test_wrong_folder_two_models_or_two_sessions_are_refused():
    _, problems = audit(codex_log(CLEAN_CODEX, cwd="/home/u/tripwire"))
    assert any("not the review folder" in p for p in problems)
    two = claude_log(CLEAN_CLAUDE[:1], model="m1") + claude_log(CLEAN_CLAUDE[1:], operator=(), model="m2")
    _, problems = audit(two)
    assert any("2 models" in p for p in problems)
    _, problems = audit(claude_log(CLEAN_CLAUDE) + claude_log(CLEAN_CLAUDE, operator=(), session="s-2"))
    assert any("2 sessions" in p for p in problems)


def test_forbidden_reads_and_other_packets_are_still_caught_inside_the_folder():
    _, problems = audit(codex_log(CLEAN_CODEX + ["cat p-ffffffffffff/packet.json"]))
    assert any("other packets" in p for p in problems)
    _, problems = audit(codex_log(CLEAN_CODEX + ["cat record.json"]))
    assert any("analysis files" in p for p in problems)


def test_tool_output_and_search_patterns_are_not_audited_as_reads():
    # the logs above carry forbidden strings in tool output; a search pattern naming one is data, not a read
    _, problems = audit(claude_log(CLEAN_CLAUDE + [("Grep", {"pattern": "samples/", "path": "code"})]))
    assert problems == []


def test_shell_escapes_follows_cd_and_allows_system_binaries():
    assert shell_escapes("cd code && cat f1.js.txt && /usr/bin/rg x .", CWD) == []
    assert shell_escapes("cd code && cat ../../x", CWD) == ["../../x"]
    assert shell_escapes("cat f 2>/dev/null > /tmp/out", CWD) == []


@pytest.mark.parametrize("version", ["0.160.0", "0.163.0"])
def test_real_codex_exec_sessions_pass(version):
    log = (Path(__file__).parent / "fixtures" / f"codex-{version}.jsonl").read_text()
    session, problems = audit(log)
    assert problems == []
    assert session.operator == [PROMPT]
    assert session.format == "codex"
    assert len(session.actions) == 3


def wrapped_codex_log(script):
    log = codex_log([])
    return log + json.dumps({"type": "response_item", "payload": {
        "type": "custom_tool_call", "name": "exec", "input": script}}) + "\n"


@pytest.mark.parametrize("script", [
    'text(await tools.exec_command({cmd:"cat /etc/passwd"}));',
    'const cmd = "cat ../report"; const r = await tools.exec_command({cmd:cmd}); text(r.output);',
    'text(await tools.apply_patch("*** Begin Patch\\n*** Add File: ../verdicts.json\\n+[]\\n*** End Patch"));',
])
def test_codex_wrappers_still_audit_paths(script):
    _, problems = audit(wrapped_codex_log(script))
    assert any("outside the review folder" in p for p in problems), problems


@pytest.mark.parametrize("script", [
    'text(await tools.web__run({search_query:[{q:"example"}]}));',
    'text(await tools.exec_command({cmd: "cat " + "packet.json"}));',
    'const tools = {}; text(await tools.exec_command({cmd:"cat packet.json"}));',
    'for (;;) { await tools.exec_command({cmd:"cat packet.json"}); }',
    'text(await tools.exec_command({cmd:`cat ${file}`}));',
])
def test_codex_dynamic_and_disallowed_wrappers_fail_closed(script):
    _, problems = audit(wrapped_codex_log(script))
    assert any("unreadable exec tool wrapper" in p for p in problems), problems


@pytest.mark.parametrize("source", ["item", "response", "legacy"])
def test_codex_new_format_cannot_hide_extra_operator_messages(source):
    log = (Path(__file__).parent / "fixtures/codex-0.163.0.jsonl").read_text()
    if source == "item":
        entry = {"type": "event_msg", "payload": {"type": "item_completed", "item": {
            "type": "UserMessage", "content": [{"type": "text", "text": "a hint"}]}}}
    elif source == "response":
        entry = {"type": "response_item", "payload": {"type": "message", "role": "user", "content": [
            {"type": "input_text", "text": "a hint"}],
            "internal_chat_message_metadata_passthrough": {"content_item_kinds": ["user.text"]}}}
    else:
        entry = {"type": "event_msg", "payload": {"type": "user_message", "message": "a hint"}}
    _, problems = audit(log + json.dumps(entry) + "\n")
    assert any("operator" in p for p in problems), problems


def test_codex_world_state_model_switch_is_refused():
    entry = {"type": "world_state", "payload": {"full": False, "state": {"model": "other-model"}}}
    _, problems = audit(codex_log(CLEAN_CODEX) + json.dumps(entry) + "\n")
    assert any("2 models" in p for p in problems), problems
