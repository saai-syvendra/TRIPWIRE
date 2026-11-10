#!/usr/bin/env python3
"""
Records agent verdicts on a record's claims as a new run in its verification sidecar
(reports/_verification/<key>/agent__<by>.json). Checks every verdict against the record's current claims:
unknown claims and stale claim hashes are refused, evidence is defanged and capped.
Runs are appended, never edited.

Usage:
  record_verdict.py --packet <packet_id> --session-log auto [--cli claude|codex] [--dest DIR] [--by MODEL]
                    [--verdicts FILE]

FILE is a JSON list of {"claim_id", "claim_sha256", "verdict", "grade"?, "reason_code"?, "evidence",
"evidence_refs"?}. Verdicts must come from a review run in the sandbox (review_shell.py) and its session log,
which is audited and fails closed: an unknown log format, an unreadable line, no tool actions, more than one
session or model, any operator message other than the launch prompt, a working directory other than the review
folder, a path outside it, or a read the blinding forbids (reports, dataset, evals, samples, analysis scratch, the
packet index, other packets) and the run is refused. The model id is taken from the log.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import claims as claim_model  # noqa: E402
from tools.common import anchors, contract, paths, verification  # noqa: E402
from tools.verify import review_shell  # noqa: E402

FIELDS = ("claim_id", "claim_sha256", "verdict", "grade", "reason_code", "evidence", "evidence_refs")
PACKET_ECHO = {"verdicts_allowed", "grades_allowed"}  # claim fields of the packet, not of a verdict


def check_verdicts(rec: dict, verdicts: list, method: str) -> tuple[list[dict], list[str]]:
    """Normalised verdicts and the problems that block recording them."""
    claims = {c["claim_id"]: c for c in claim_model.enumerate_claims(rec)}
    out, problems = [], []
    if method == "deterministic":
        return [], ["deterministic verdicts are written by verify.py only"]
    if not isinstance(verdicts, list) or not verdicts:
        return [], ["verdicts must be a non-empty JSON list"]
    seen = set()
    for i, v in enumerate(verdicts):
        if not isinstance(v, dict):
            problems.append(f"#{i}: not an object")
            continue
        cid = v.get("claim_id")
        c = claims.get(cid)
        if c is None:
            problems.append(f"#{i}: {cid!r} is not a claim of this record")
            continue
        if cid in seen:
            problems.append(f"#{i}: {cid} appears twice")
        seen.add(cid)
        if v.get("claim_sha256") != c["claim_sha256"]:
            problems.append(f"#{i}: {cid} is stale (the claim changed since it was shown)")
        if v.get("verdict") not in claim_model.VERDICTS:
            problems.append(f"#{i}: verdict must be one of {claim_model.VERDICTS}")
        kind = claim_model.grade_kind(cid)
        grade = v.get("grade")
        if grade is not None and (kind is None or grade not in claim_model.GRADED[kind]):
            problems.append(f"#{i}: {cid} cannot take grade {grade!r}")
        if v.get("verdict") == "unanchored" and not v.get("reason_code"):
            problems.append(f"#{i}: an unanchored verdict needs a reason_code")
        # reviewers sometimes add a free-text side note (`grades_note`) or copy the packet's own claim fields
        # (`grades_allowed`); both are dropped, not a reason to throw the review away. Any other unknown field
        # still refuses the file.
        unknown = {k for k in set(v) - set(FIELDS) if not k.endswith("_note") and k not in PACKET_ECHO}
        if unknown:
            problems.append(f"#{i}: unknown fields {sorted(unknown)}")
        out.append({"claim_id": cid, "claim_sha256": c["claim_sha256"], "verdict": v.get("verdict"),
                    "grade": grade,
                    "reason_code": v.get("reason_code") or (None if v.get("verdict") == "verified" else "judgement"),
                    "evidence": v.get("evidence", ""), "evidence_refs": v.get("evidence_refs", [])})
    return out, problems


def record(rec: dict, by: str, verdicts: list, packet_sha: str) -> Path:
    clean, problems = check_verdicts(rec, verdicts, "agent")
    if problems:
        raise SystemExit("not recorded:\n  " + "\n  ".join(problems))
    run = {"by": by, "record_sha256": claim_model.record_sha(rec), "packet_sha256": packet_sha, "blinded": True,
           "verdicts": clean}
    return verification.append_run(paths.REPORTS, rec["package"], "agent", run)


FORBIDDEN = [
    (re.compile(r"reports/(npm|pypi|_verification)\b"), "read the analyst's reports or verdicts"),
    (re.compile(r"\bdataset/"), "read the aggregated dataset"),
    (re.compile(r"\bevals/"), "read the evals"),
    (re.compile(r"\bsamples/"), "read the samples directly"),
    (re.compile(r"scratch/verify/_(index|work)"), "read the packet index or the rebuilt package"),
    (re.compile(r"scratch/(npm|pypi)__"), "read an analysis scratch folder"),
    (re.compile(r"git\s+(log|show|diff|blame)\b[^\n]*reports"), "read the history of reports/"),
    (re.compile(r"\bsummary\.md\b|\bprepared\.json\b|\brecord\.json\b"), "read analysis files"),
]

# Session logs of the two supported CLIs, as their interactive sessions write them (assumptions are listed in
# skills/verify-gates/references/agent-runners.md; anything else is refused):
#   Claude Code: <config>/projects/<cwd slug>/<session>.jsonl, one JSON object per line with "type" (user, assistant,
#     summary, system, file-history-snapshot ...), "cwd", "sessionId", "isSidechain", "isMeta" and "message";
#     tool calls are assistant content blocks {"type": "tool_use", "name", "input"}; the model is message.model.
#     Real v2.1.x sessions also emit per-turn bookkeeping lines the audit carries no information from: mode,
#     permission-mode, atis-latch, last-prompt, ai-title, attachment (an environment snapshot; not a tool_use or an
#     operator message) and file-history-delta (a file-backup record, the one such line with no sessionId). They are
#     listed so an unseen type is still refused; operator messages and tool calls only ever ride on user/assistant.
#   Codex: <config>/sessions/YYYY/MM/DD/rollout-*.jsonl, lines {"type": session_meta|turn_context|response_item|
#     event_msg|compacted, "payload"}; tool calls are response_item payloads of type function_call (JSON-string
#     "arguments"), local_shell_call or custom_tool_call (apply_patch); typed prompts are event_msg user_message;
#     the model is turn_context.model.
CLAUDE_TYPES = {"user", "assistant", "summary", "system", "file-history-snapshot", "file-history-delta",
                "queue-operation", "mode", "permission-mode", "atis-latch", "last-prompt", "ai-title", "attachment"}
CODEX_TYPES = {"session_meta", "turn_context", "response_item", "event_msg", "compacted", "world_state",
               "token_usage_record"}
CLAUDE_READ = {"Read": ("file_path",), "Grep": ("path",), "Glob": ("path", "pattern"), "LS": ("path",),
               "Write": ("file_path",), "Edit": ("file_path",), "MultiEdit": ("file_path",)}
CLAUDE_INERT = {"TodoWrite", "ToolSearch"}
CODEX_SHELL = {"shell", "container.exec", "local_shell", "exec_command", "shell_command", "write_stdin"}
CODEX_INERT = {"update_plan"}
SAFE_PATHS = ("/dev/null", "/dev/stdout", "/dev/stderr", "/tmp")
EXEC_DIRS = ("/usr/bin/", "/bin/", "/usr/local/bin/", "/usr/sbin/", "/sbin/")
ABS_PATH = re.compile(r"(?:^|(?<=[\s'\"=(:<>|;&,]))(/[A-Za-z0-9_.@+-][^\s'\"`;|&<>(),]*|/(?=[\s'\";|&)]|$))")
SPLIT = re.compile(r"&&|\|\||[;|\n&]")


class Session:
    """What a reviewer's session did, read from its log: format, model ids, typed operator messages, and
    actions as (tool, text, paths) where paths are the paths the action names."""

    def __init__(self):
        self.format, self.models, self.operator, self.actions, self.cwds, self.problems = None, set(), [], [], set(), []
        self.sessions = set()
        self.codex_item_operator, self.codex_response_operator = [], []


def _blocks(content) -> list[dict]:
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def _claude_line(obj: dict, s: Session) -> None:
    if obj.get("cwd"):
        s.cwds.add(obj["cwd"])
    if obj.get("sessionId") and not obj.get("isSidechain"):
        s.sessions.add(obj["sessionId"])
    msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
    if obj.get("type") == "assistant":
        if msg.get("model") and msg["model"] != "<synthetic>":
            s.models.add(msg["model"])
        for b in _blocks(msg.get("content")):
            if b.get("type") != "tool_use":
                continue
            name, inp = b.get("name", ""), b.get("input") or {}
            if name in CLAUDE_INERT:
                continue
            if name == "Bash":
                s.actions.append(("Bash", str(inp.get("command", "")), None))
            elif name in CLAUDE_READ:
                named = [str(inp[k]) for k in CLAUDE_READ[name] if inp.get(k)]
                s.actions.append((name, json.dumps(inp, sort_keys=True), named or ["."]))
            else:
                s.problems.append(f"the reviewer used a tool the review does not allow: {name}")
    elif obj.get("type") == "user" and not obj.get("isMeta") and not obj.get("isSidechain"):
        texts = [b.get("text", "") for b in _blocks(msg.get("content")) if b.get("type") == "text"]
        if any(b.get("type") == "tool_result" for b in _blocks(msg.get("content"))) or not texts:
            return
        text = "\n".join(texts).strip()
        if text.startswith("<local-command-") or text.startswith("<command-message>"):
            return
        command = re.search(r"<command-name>\s*(/[^\s<]+)", text)
        if command:
            if command.group(1) not in ("/exit", "/quit"):
                s.problems.append(f"the operator ran {command.group(1)} during the review")
            return
        s.operator.append(text)


def _codex_line(obj: dict, s: Session) -> None:
    kind, p = obj.get("type"), obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
    if kind == "session_meta":
        s.sessions.add(p.get("id") or json.dumps(p, sort_keys=True)[:80])
        if p.get("cwd"):
            s.cwds.add(p["cwd"])
    elif kind == "turn_context":
        if p.get("cwd"):
            s.cwds.add(p["cwd"])
        if p.get("model"):
            s.models.add(p["model"])
    elif kind == "event_msg" and p.get("type") == "user_message":
        s.operator.append(str(p.get("message", "")).strip())
    elif kind == "world_state":
        state = p.get("state") or {}
        if isinstance(state.get("model"), str):
            s.models.add(state["model"])
    elif kind == "event_msg" and p.get("type") == "item_completed":
        item = p.get("item") or {}
        if item.get("type") == "UserMessage":
            s.codex_item_operator.append("\n".join(b.get("text", "") for b in _blocks(item.get("content"))
                                                   if b.get("type") == "text").strip())
    elif kind == "response_item":
        t = p.get("type")
        if t == "message" and p.get("role") == "user":
            metadata = p.get("internal_chat_message_metadata_passthrough") or {}
            kinds = set(metadata.get("content_item_kinds") or [])
            text = "\n".join(b.get("text", "") for b in _blocks(p.get("content"))
                             if b.get("type") in ("text", "input_text")).strip()
            injected = {"agents_md.instructions", "environments.environment_context"}
            if kinds and kinds <= injected:
                return
            # Older CLI logs identify injected instructions by this wrapper, without metadata.
            if not kinds and text.startswith("<user_instructions>") and text.endswith("</user_instructions>"):
                return
            s.codex_response_operator.append(text)
        elif t == "function_call":
            name = p.get("name", "")
            try:
                args = json.loads(p.get("arguments") or "{}")
            except ValueError:
                s.problems.append(f"unreadable arguments of a {name} call")
                return
            _codex_tool(name, args, s)
        elif t == "local_shell_call":
            action = p.get("action") or {}
            wd = action.get("working_directory")
            s.actions.append(("local_shell", _shell_text(action.get("command") or ""), [wd] if wd else None))
        elif t == "custom_tool_call":
            if p.get("name") == "exec":
                from tools.verify.codex_exec_audit import WrapperError, tool_calls
                try:
                    calls = tool_calls(p.get("input", ""), CODEX_SHELL | CODEX_INERT | {"apply_patch"})
                except WrapperError as e:
                    s.problems.append(f"unreadable exec tool wrapper: {e}")
                    return
                for name, args in calls:
                    _codex_tool(name, args, s)
            elif p.get("name") == "apply_patch":
                _codex_tool("apply_patch", p.get("input", ""), s)
            else:
                s.problems.append(f"the reviewer used a tool the review does not allow: {p.get('name')}")
        elif t in ("web_search_call", "image_generation_call"):
            s.problems.append(f"the reviewer used a tool the review does not allow: {t}")


def _codex_tool(name: str, args, s: Session) -> None:
    """Apply the same audit to direct tool calls and statically decoded exec wrappers."""
    if name == "apply_patch" and isinstance(args, str):
        named = re.findall(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$", args, re.M)
        s.actions.append((name, args[:2000], [a or b for a, b in named] or ["."]))
    elif name in CODEX_INERT:
        return
    elif name in CODEX_SHELL and isinstance(args, dict):
        cmd = args.get("command") or args.get("cmd") or args.get("chars") or ""
        s.actions.append((name, _shell_text(cmd), [args["workdir"]] if args.get("workdir") else None))
    else:
        s.problems.append(f"the reviewer used a tool the review does not allow: {name}")


def _shell_text(cmd) -> str:
    """The shell script of a command given as argv (`bash -lc SCRIPT` -> SCRIPT) or as a string."""
    if isinstance(cmd, list):
        argv = [str(a) for a in cmd]
        if len(argv) >= 3 and Path(argv[0]).name in ("bash", "sh", "zsh", "dash") and argv[1] in ("-lc", "-c"):
            return argv[2]
        return shlex.join(argv)
    return str(cmd)


def parse_session(texts: list[str]) -> Session:
    """Reads one or more session-log files of a single CLI; unreadable lines and unknown formats are problems."""
    s = Session()
    formats = set()
    for text in texts:
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                s.problems.append(f"line {n} of the session log is not JSON")
                continue
            if not isinstance(obj, dict):
                s.problems.append(f"line {n} of the session log is not a JSON object")
                continue
            if obj.get("type") in CODEX_TYPES:
                formats.add("codex")
                _codex_line(obj, s)
            elif obj.get("type") in CLAUDE_TYPES or "sessionId" in obj:
                formats.add("claude")
                _claude_line(obj, s)
            else:
                s.problems.append(f"line {n} of the session log has an unknown entry type {obj.get('type')!r}")
    if len(formats) != 1:
        s.problems.append("the session log is empty" if not formats else
                          f"the session log mixes formats: {sorted(formats)}")
    else:
        s.format = formats.pop()
    if s.format == "codex":
        # CLI versions log the prompt in different places. Cross-check duplicate representations,
        # rather than counting them twice or letting an extra message hide in a fallback stream.
        streams = [x for x in (s.operator, s.codex_item_operator, s.codex_response_operator) if x]
        if streams:
            norm = lambda xs: [" ".join(t.split()) for t in xs]  # noqa: E731
            if any(norm(xs) != norm(streams[0]) for xs in streams[1:]):
                s.problems.append("the Codex log's operator message streams disagree")
            s.operator = streams[0]
    return s


def _outside(path: str, cwd: str) -> bool:
    if path.startswith("~") or "$HOME" in path or "${HOME}" in path:
        return True
    p = Path(os.path.normpath(path if path.startswith("/") else f"{cwd}/{path}"))
    if str(p) in SAFE_PATHS or any(str(p).startswith(d + "/") for d in SAFE_PATHS[3:]):
        return False
    return not (p == Path(cwd) or p.is_relative_to(cwd))


def shell_escapes(script: str, cwd: str) -> list[str]:
    """Paths a shell script reaches outside cwd: path-like arguments, `cd` targets and absolute paths anywhere
    in the text (inline scripts included). The executable of each simple command may be a system binary."""
    out, here = [], cwd
    for part in SPLIT.split(script):
        try:
            argv = shlex.split(part, comments=True)
        except ValueError:
            argv = part.split()
        while argv and re.fullmatch(r"\w+=\S*", argv[0]):  # VAR=value prefixes
            argv = argv[1:]
        if not argv:
            continue
        if argv[0] == "cd":
            target = argv[1] if len(argv) > 1 else "~"
            if _outside(target, here):
                out.append(f"cd {target}")
            else:
                here = os.path.normpath(target if target.startswith("/") else f"{here}/{target}")
            continue
        for a in argv[1:]:
            a = a.split("=", 1)[1] if a.startswith("-") and "=" in a else a
            a = re.sub(r"^\d?[<>]+", "", a)
            if a.startswith(("~", "/", "..", "$HOME", "${HOME}")) or "/../" in f"/{a}/":
                if _outside(a, here):
                    out.append(a)
        if argv[0].startswith("/") and not argv[0].startswith(EXEC_DIRS):
            out.append(argv[0])
    for m in ABS_PATH.finditer(script):
        p = m.group(1)
        if not p.startswith(EXEC_DIRS) and _outside(p, cwd) and p not in out:
            out.append(p)
    return out


def audit_session(texts: list[str], packet_id: str, prompt: str, cwd: str) -> tuple[Session, list[str]]:
    """Blinding violations in a reviewer's session logs. Fails closed: anything the parser does not recognise, a
    second operator message, a working directory other than the review folder or a path outside it is refused."""
    s = parse_session(texts)
    problems = list(s.problems)
    if s.format is None:
        return s, problems
    if len(s.sessions) != 1:
        problems.append(f"the log holds {len(s.sessions)} sessions; review one packet in one session")
    if s.cwds != {cwd}:
        problems.append(f"the session ran in {sorted(s.cwds) or 'an unknown folder'}, not the review folder {cwd}")
    if len(s.models) != 1:
        problems.append(f"the log names {len(s.models)} models ({', '.join(sorted(s.models)) or 'none'}); "
                        "expected exactly one")
    norm = lambda t: " ".join(t.split())  # noqa: E731
    if [norm(t) for t in s.operator] != [norm(prompt)]:
        problems.append(f"the operator sent {len(s.operator)} message(s); the review allows only the launch prompt, "
                        "unchanged")
    if not s.actions:
        problems.append("the log shows no tool actions; nothing can be audited")
    texts_seen = []
    for tool, text, named in s.actions:
        shell = named is None or tool in CODEX_SHELL | {"Bash", "local_shell"}
        texts_seen.append(text if shell else "\n".join(named))  # search patterns and edits are not reads
        reached = shell_escapes(text, cwd) if shell else []
        for p in named or []:
            if _outside(p, cwd):
                reached.append(p)
        if reached:
            problems.append(f"the reviewer reached outside the review folder ({tool}: {', '.join(reached[:3])[:120]})")
    joined = "\n".join(texts_seen)
    problems += [f"transcript shows the reviewer tried to {why} ({m.group(0)[:60]})"
                 for rx, why in FORBIDDEN for m in [rx.search(joined)] if m]
    others = sorted(set(re.findall(r"p-[0-9a-f]{12}", joined)) - {packet_id})
    if others:
        problems.append(f"transcript opens other packets: {', '.join(others[:3])}")
    return s, problems


def locate_logs(pid: str, cli: str | None, dest: Path | None) -> tuple[str, list[Path]]:
    """(cli, session-log files) of a packet's sandboxed review (review_shell.py)."""
    found = {c: review_shell.session_files(review_shell.run_dir(pid, c, dest) / "home", c)
             for c in ([cli] if cli else review_shell.CLIS)}
    found = {c: fs for c, fs in found.items() if fs}
    if not found:
        raise SystemExit(f"no session log for {pid} under {review_shell.run_dir(pid, cli or '<cli>', dest)}/home")
    if len(found) > 1:
        raise SystemExit(f"{pid} was reviewed with {' and '.join(sorted(found))}; pass --cli")
    return next(iter(found.items()))


def read_logs(spec: str, pid: str, cli: str | None, dest: Path | None) -> tuple[list[Path], list[str], str]:
    """The log files and their texts."""
    if spec == "auto":
        _, files = locate_logs(pid, cli, dest)
    else:
        p = Path(spec)
        files = sorted(p.rglob("*.jsonl")) if p.is_dir() else [p]
    if not files:
        raise SystemExit(f"no session log at {spec}")
    blobs = [f.read_bytes() for f in files]
    return files, [b.decode("utf-8", "replace") for b in blobs]


def from_packet(pid: str) -> tuple[dict, dict, str]:
    root = paths.SCRATCH / "verify"
    body = (root / pid / "packet.json").read_text(encoding="utf-8")
    entry = json.loads((root / "_index.json").read_text())[pid]
    if anchors.digest(body.encode()) != entry["packet_sha256"]:
        raise SystemExit(f"{pid}: packet.json changed since it was built")
    return json.loads(body), contract.read_record(paths.ROOT / entry["report"]), entry["packet_sha256"]


def done_by(row: dict) -> set[str]:
    """The CLIs whose review of a queued packet is recorded. A row from before per-CLI marks (`status: done`) was
    reviewed by Claude."""
    out = set(row.get("done") or [])
    if row.get("status") == "done":
        out.add("claude")
    return out


def mark_done(pid: str, cli: str = "claude") -> None:
    """Marks the packet reviewed by this CLI, under a lock and with an atomic replace (parallel recorders)."""
    import fcntl
    import os
    queue = paths.SCRATCH / "verify" / "queue.jsonl"
    if not queue.is_file():
        return
    with open(queue.with_suffix(".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        rows = [json.loads(line) for line in queue.read_text().splitlines() if line.strip()]
        for r in rows:
            if r["packet_id"] == pid:
                r["done"] = sorted(done_by(r) | {cli})
                r.pop("status", None)
        tmp = queue.with_suffix(".tmp")
        tmp.write_text("".join(json.dumps(r) + "\n" for r in rows))
        os.replace(tmp, queue)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--packet", required=True)
    ap.add_argument("--by", help="model id; default: read from the session log")
    ap.add_argument("--verdicts", type=Path, help="default with --session-log auto: the review folder's verdicts.json")
    ap.add_argument("--session-log", required=True, help="auto (find it in the sandbox's config home), a log file or a folder")
    ap.add_argument("--cli", choices=review_shell.CLIS, help="with --session-log auto, when both CLIs reviewed it")
    ap.add_argument("--dest", type=Path, help="where review_shell.py put the review folders")
    args = ap.parse_args()
    packet, rec, packet_sha = from_packet(args.packet)
    by, verdicts_path = args.by, args.verdicts
    from tools.verify.packet import PROMPT
    _, texts = read_logs(args.session_log, args.packet, args.cli, args.dest)
    session, problems = audit_session(texts, args.packet, PROMPT, review_shell.SANDBOX_CWD)
    if session.format and len(session.models) == 1:
        model = next(iter(session.models))
        if by and by != model:
            problems.append(f"--by {by} does not match the model in the session log ({model})")
        by = by or model
    if problems:
        raise SystemExit("not recorded, blinding broken:\n  " + "\n  ".join(problems))
    if verdicts_path is None and args.session_log == "auto":
        cli, _ = locate_logs(args.packet, args.cli, args.dest)
        verdicts_path = review_shell.run_dir(args.packet, cli, args.dest) / "review" / "verdicts.json"
    if verdicts_path is None:
        ap.error("--verdicts is required")
    verdicts = json.loads(verdicts_path.read_text(encoding="utf-8"))
    asked = {c["claim_id"] for c in packet["claims"]}
    extra = sorted({v.get("claim_id") for v in verdicts if isinstance(v, dict)} - asked) \
        if isinstance(verdicts, list) else []
    if extra:
        raise SystemExit(f"not recorded: claims not in this packet: {extra}")
    given = {v.get("claim_id") for v in verdicts if isinstance(v, dict)} if isinstance(verdicts, list) else set()
    missing = sorted(asked - given)
    if missing:
        raise SystemExit(f"not recorded: the review leaves out claims of this packet: {missing[:10]}"
                         + (" ..." if len(missing) > 10 else ""))
    path = record(rec, by, verdicts, packet_sha)
    mark_done(args.packet, session.format or args.cli or "claude")
    print(f"recorded in {path.relative_to(paths.ROOT)}")


if __name__ == "__main__":
    main()
