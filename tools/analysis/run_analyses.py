#!/usr/bin/env python3
"""
Works through scratch/queue.jsonl: one fresh headless Claude Code session (`claude -p`) per queued package, on
one pinned model, started from the repo root so CLAUDE.md and the gate-analysis skill load. Every session gets
the same fixed launch prompt naming its key (PROMPT) and ends by running write_report.py.

Each session runs with --permission-mode dontAsk, so a tool call outside the allowlist fails instead of asking:
Read/Grep/Glob (other packages' scratch folders, scratch/verify, scratch/_runs, samples/, evals/ and dataset/
denied), Edit/Write only under scratch/<key>/, Bash only `.venv/bin/python [-I] tools/analysis/*` and
tools/common/decode.py (prepare.py and this driver denied), no web tools and no subagents. Only project settings
load (--setting-sources project) and no MCP servers, so user-level allow rules cannot widen the list. The session
log (stream-json) goes to scratch/_runs/<key>.jsonl, stderr next to it.

The driver sets TRIPWIRE_ANALYSIS_MODEL=<model> for the session, so write_report.py refuses a record whose model_name
is another model, and TRIPWIRE_ANALYSIS_KEY=<key>, so every tool the session may run (view.py, cite.py, decode.py,
register_decode.py, write_report.py) refuses a path outside scratch/<key>/ (paths.confine). After the session it reads the models the log actually used (record_verdict.parse_session)
and sets the row's status:
  done            a report or skip record appeared, written by exactly one model, the record's model_name
  blocked         a safeguard refusal, a model fallback, or more than one model in the log, or a safeguard stop
                  after which the session wrote no record
  model_mismatch  the log's one model is not the record's model_name (or not the requested model)
  timeout         no record after --timeout seconds (decides only whether a run finished, never a label)
  error           the session ended without a record (the log tail is in the row's note)
A record written by a blocked or mismatched session is moved out of reports/ to scratch/_runs/<key>.rejected.*.
Rows are updated under the queue lock (work_queue.py), so --jobs sessions can run in parallel; a row is
`running` while its session is live.

Usage: run_analyses.py --model MODEL_ID [--jobs N] [--timeout SECONDS] [--only KEY ...] [--retry] [--dry-run]
                       [--claude PATH]
Rows with status analyse or needs_skip_reason are run; --retry also reruns error, timeout and running rows.
Exit status 1 unless every run package ended done. Nothing from a package is run by this driver.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.analysis import work_queue  # noqa: E402
from tools.analysis.write_report import MODEL_ENV  # noqa: E402
from tools.common import contract, paths  # noqa: E402
from tools.common.contract import key_for  # noqa: E402

# Said in the prompt because a session that hits one denied shell command (cd, cat, a pipe) can wrongly conclude the
# repo tools are unavailable too and stop without a record.
TOOLS_NOTE = ("Bash runs only single .venv/bin/python commands of the repo tools (tools/analysis/*, "
              "tools/common/decode.py, aggregate.py --check), with no cd, cat, pipes or &&; read and search files with "
              "the Read, Grep and Glob tools. A denied shell command does not mean these tools are unavailable.")
PROMPT = ("Analyse the prepared package scratch/{key}/ with the gate-analysis skill. It is already prepared and "
          "queued: do not run reset.py or prepare.py, and read only scratch/{key}/, never another package's "
          "scratch folder. " + TOOLS_NOTE + " Finish by running "
          ".venv/bin/python tools/analysis/write_report.py scratch/{key}")
RUNNABLE = ("analyse", "needs_skip_reason")
RETRYABLE = ("error", "timeout", "running")
# A key goes into the prompt and into path rules, so it must be plain (a hostile package name never reaches them).
SAFE_KEY = re.compile(r"^(npm|pypi)__[A-Za-z0-9@._+-]+$")
PYTHON = ".venv/bin/python"
BASH_ALLOWED = ("tools/analysis/*", "tools/common/decode.py *", "tools/common/aggregate.py --check*")
BASH_DENIED = ("tools/analysis/prepare.py*", "tools/analysis/run_analyses.py*")
READ_DENIED = ("evals", "dataset", "samples", "scratch/verify", "scratch/_runs")
DEFAULT_TIMEOUT = 3600


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def abs_rule(path: Path) -> str:
    """An absolute path in permission-rule form (`//abs/path`)."""
    return "/" + path.resolve().as_posix()


def runs_dir() -> Path:
    return paths.SCRATCH / "_runs"


def other_keys(key: str) -> list[str]:
    """Every other package folder in scratch/ at launch time."""
    if not paths.SCRATCH.is_dir():
        return []
    return sorted(p.name for p in paths.SCRATCH.iterdir()
                  if p.is_dir() and p.name != key and SAFE_KEY.match(p.name))


def command(key: str, model: str, claude: str = "claude", prompt: str = PROMPT,
            deny_tools: tuple = ()) -> list[str]:
    """The claude command line for one package (run from the repo root). The repair driver passes its own prompt
    and denies its own tools on top of the analysis allowlist."""
    root = abs_rule(paths.ROOT)
    allow = ["Read", "Grep", "Glob", "TodoWrite", "Skill",
             f"Edit({root}/scratch/{key}/**)", f"Write({root}/scratch/{key}/**)",
             *[f"Bash({PYTHON} {flag}{tool})" for tool in BASH_ALLOWED for flag in ("", "-I ")]]
    deny = ["WebFetch", "WebSearch", "Agent", "Task", "NotebookEdit",
            # a path that climbs out of tools/ (`tools/analysis/../../samples/x/setup.py`) would run package code
            "Bash(*..*)",
            *[f"Bash({PYTHON} {flag}{tool})" for tool in BASH_DENIED + tuple(deny_tools) for flag in ("", "-I ")],
            *[f"Read({root}/{d}/**)" for d in READ_DENIED],
            *[f"Read({root}/scratch/{other}/**)" for other in other_keys(key)]]
    return [claude, "-p", prompt.format(key=key), "--model", model,
            "--output-format", "stream-json", "--verbose",
            "--permission-mode", "dontAsk", "--setting-sources", "project", "--strict-mcp-config",
            "--allowedTools", *allow, "--disallowedTools", *deny]


# Repo paths a session never sees: the samples, the reference answers, the aggregate, other packages' working
# folders (decoded payloads), the git history (earlier reports) and the verifiers' verdicts.
HIDDEN = ("samples", "evals", "dataset", ".git", "scratch", "reports/_verification", ".claude/worktrees")
SANDBOX = True  # tests with a fake CLI turn it off (--no-sandbox)


def session_home(key: str) -> Path:
    """A fresh config home for the session, outside the repo, with the login copied in at launch."""
    from tools.verify import review_shell
    home = review_shell.check_dest(review_shell.default_dest()) / f"analysis-{key}"
    if home.exists():
        shutil.rmtree(home)
    (home / ".claude").mkdir(parents=True, mode=0o700)
    root = str(paths.ROOT.resolve())
    state = json.dumps({"hasCompletedOnboarding": True, "autoUpdates": False,
                        "projects": {root: {"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True}}})
    for rel in (".claude/.claude.json", ".claude.json"):
        (home / rel).write_text(state, encoding="utf-8")
    cred = review_shell.credential("claude")
    if cred is not None:
        dest = home / review_shell.CREDENTIALS["claude"][0]
        shutil.copyfile(cred, dest)
        dest.chmod(0o600)
    return home


def sandboxed(key: str, model: str, claude: str, home: Path, prompt: str = PROMPT, deny_tools: tuple = (),
              pin_model: bool = True) -> list[str]:
    """The session's command inside bubblewrap: the repo read-only at its own path with HIDDEN covered by empty
    folders, reports/ writable (write_report.py), scratch/<key>/ the only scratch folder, network for the API."""
    from tools.verify import review_shell
    root = paths.ROOT.resolve()
    exe, binds, extra_path = review_shell.runtime_binds(Path(claude).name if "/" not in claude else claude) \
        if shutil.which(claude) else (claude, [], [])
    cmd = ["bwrap", "--die-with-parent", "--unshare-all", "--share-net", "--hostname", "analyst"]
    for d in review_shell.SYSTEM_DIRS:
        q = Path(d)
        if q.is_symlink():
            cmd += ["--symlink", os.readlink(q), d]
        elif q.is_dir():
            cmd += ["--ro-bind", d, d]
    for f in review_shell.ETC_FILES:
        if os.path.exists(f):
            cmd += ["--ro-bind", str(Path(f).resolve()), f]
    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for b in binds:
        cmd += ["--ro-bind", b, b]
    cmd += ["--ro-bind", str(root), str(root)]
    for h in HIDDEN:
        if (root / h).is_dir():
            cmd += ["--tmpfs", str(root / h)]
    cmd += ["--bind", str(root / "reports"), str(root / "reports")]
    if (root / "reports" / "_verification").is_dir():
        cmd += ["--tmpfs", str(root / "reports" / "_verification")]
    cmd += ["--bind", str(root / "scratch" / key), str(root / "scratch" / key),
            "--bind", str(home), str(home), "--chdir", str(root), "--clearenv"]
    env = {"HOME": str(home), "USER": "analyst", "LANG": "C.UTF-8", "CLAUDE_CONFIG_DIR": str(home / ".claude"),
           "PATH": ":".join(extra_path + ["/usr/local/bin", "/usr/bin", "/bin"]), "DISABLE_AUTOUPDATER": "1",
           paths.CONFINE_ENV: key, **({MODEL_ENV: model} if pin_model else {})}
    for k in review_shell.CREDENTIALS["claude"][1]:
        if os.environ.get(k):
            env[k] = os.environ[k]
    for k in sorted(env):
        cmd += ["--setenv", k, env[k]]
    return cmd + command(key, model, exe, prompt, deny_tools)


def run_session(key: str, model: str, claude: str, timeout: float, prompt: str = PROMPT, deny_tools: tuple = (),
                pin_model: bool = True, log_name: str | None = None) -> tuple[int | None, bool]:
    """(exit code, timed out). The whole process group is stopped on a timeout. pin_model sets MODEL_ENV, so
    write_report.py refuses a record naming another model (off for repairs, which keep the analyst's model)."""
    logs = runs_dir()
    logs.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, paths.CONFINE_ENV: key, "DISABLE_AUTOUPDATER": "1", **({MODEL_ENV: model} if pin_model else {})}
    if not pin_model:
        env.pop(MODEL_ENV, None)
    home = session_home(key) if SANDBOX else None
    name = log_name or key
    try:
        argv = sandboxed(key, model, claude, home, prompt, deny_tools, pin_model) if SANDBOX else \
            command(key, model, claude, prompt, deny_tools)
        with open(logs / f"{name}.jsonl", "w") as out, open(logs / f"{name}.stderr", "w") as err:
            proc = subprocess.Popen(argv, cwd=paths.ROOT, stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=err, env=env, start_new_session=True)
            try:
                return proc.wait(timeout=timeout), False
            except subprocess.TimeoutExpired:
                for sig, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, None)):
                    try:
                        os.killpg(proc.pid, sig)
                    except ProcessLookupError:
                        break
                    try:
                        proc.wait(timeout=wait)
                        break
                    except subprocess.TimeoutExpired:
                        continue
                return None, True
    finally:
        if home is not None:
            shutil.rmtree(home, ignore_errors=True)  # the copied login goes with it


def session_facts(text: str) -> dict:
    """What the log says about models: the assistant models (read as record_verdict reads Claude logs), whether
    the CLI fell back to another model or the model refused, whether a safeguard stopped a response mid-session (the
    CLI notes it and lets the session continue), and the final result line."""
    from tools.verify.record_verdict import parse_session
    facts = {"models": sorted(parse_session([text]).models), "fallback": False, "refusal": False, "stopped": False,
             "result": None}
    for line in text.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue
        kind = obj.get("type")
        msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
        if kind == "assistant" and msg.get("stop_reason") == "refusal":
            facts["refusal"] = True
        elif kind not in ("user", "assistant") and (
                "refusal_fallback" in line or "fallback" in str(obj.get("subtype") or "")):
            # the CLI's own events (model_refusal_fallback); package text only reaches user and assistant lines
            facts["fallback"] = True
        elif kind == "system" and obj.get("subtype") == "informational" and \
                "safeguards stopped" in str(obj.get("content") or ""):
            facts["stopped"] = True
        if kind == "result":
            facts["result"] = obj
    return facts


def record_of(key: str) -> tuple[Path | None, dict | None]:
    """The finished record for the queued package, and its package block."""
    prep = paths.SCRATCH / key / "prepared.json"
    try:
        pk = json.loads(prep.read_text(encoding="utf-8"))["package"]
    except (OSError, ValueError, KeyError, TypeError):
        return None, None
    path = contract.existing_record(paths.REPORTS, pk.get("ecosystem", ""), pk.get("name", ""), pk.get("version"))
    if path is None:
        return None, None
    try:
        return path, contract.read_record(path).get("package") or {}
    except (OSError, ValueError):
        return path, {}


def reject(path: Path, key: str) -> str:
    """Moves a record the session should not have written out of reports/; returns where it went."""
    dest = runs_dir() / f"{key}.rejected{path.suffix}"
    shutil.move(str(path), dest)
    return dest.relative_to(paths.ROOT).as_posix()


def judge(key: str, model: str, facts: dict, timed_out: bool, code: int | None) -> dict:
    """The row fields for a finished session."""
    models = facts["models"]
    path, pk = record_of(key)
    fields = {"model": models[0] if len(models) == 1 else models, "requested_model": model}
    if facts["refusal"] or facts["fallback"] or len(models) > 1:
        why = ("a safeguard refusal" if facts["refusal"] else "a model fallback" if facts["fallback"] else
               f"{len(models)} models ({', '.join(models)})")
        note = f"session had {why}"
        if path is not None:
            note += f"; its record was moved to {reject(path, key)}"
        return {**fields, "status": "blocked", "note": note}
    if path is not None:
        named = (pk or {}).get("model_name")
        if len(models) != 1 or named != models[0] or models[0] != model:
            note = (f"record names {named!r}, the log shows {models or 'no model'}, requested {model!r}; "
                    f"record moved to {reject(path, key)}")
            return {**fields, "status": "model_mismatch", "note": note}
        note = "a safeguard stopped a response; the session went on to write this record" if facts["stopped"] \
            else None
        return {**fields, "status": "done", "record": path.relative_to(paths.ROOT).as_posix(), "note": note}
    if len(models) == 1 and models[0] != model:
        return {**fields, "status": "model_mismatch", "note": f"the session ran {models[0]}, not {model}"}
    if facts["stopped"]:  # the session gave up after the stop; another model may get through
        return {**fields, "status": "blocked", "note": "a safeguard stopped a response and the session wrote no record"}
    if timed_out:
        return {**fields, "status": "timeout", "note": "no record before the timeout"}
    result = facts["result"] or {}
    tail = str(result.get("result") or result.get("subtype") or "")[-300:]
    return {**fields, "status": "error", "note": f"exit {code}, no record: {tail}" if tail else f"exit {code}, no record"}


def analyse(key: str, model: str, claude: str, timeout: float) -> str:
    """Runs one package and records its outcome in the queue; returns the status."""
    if not SAFE_KEY.match(key):
        work_queue.set_fields(key, {"status": "error", "note": "key is not plain; analyse it interactively"})
        return "error"
    if not (paths.SCRATCH / key / "prepared.json").is_file():
        work_queue.set_fields(key, {"status": "error", "note": "scratch/<key>/prepared.json is missing; prepare again"})
        return "error"
    path, _ = record_of(key)
    if path is not None:
        work_queue.set_fields(key, {"status": "done", "record": path.relative_to(paths.ROOT).as_posix(),
                                    "note": "record already present, not run"})
        return "done"
    work_queue.set_fields(key, {"status": "running", "started_at": now(), "requested_model": model})
    code, timed_out = run_session(key, model, claude, timeout)
    log = runs_dir() / f"{key}.jsonl"
    facts = session_facts(log.read_text(encoding="utf-8", errors="replace"))
    fields = judge(key, model, facts, timed_out, code)
    fields.update(finished_at=now(), exit=code, log=log.relative_to(paths.ROOT).as_posix())
    if fields["status"] == "done" and "/_skipped/" in fields.get("record", ""):
        moved = settle_members(paths.ROOT / fields["record"])
        if moved:
            fields["note"] = f"{len(moved)} member(s) of this skipped package written as skips too"
    if fields["status"] == "done":
        adopted, problems = adopt_decoders(key, cited_decoders(paths.ROOT / fields["record"]))
        if adopted:
            fields["decoders_adopted"] = adopted
        if problems:
            path, _ = record_of(key)
            moved = f"; record moved to {reject(path, key)}" if path is not None else ""
            fields.update(status="error", note="candidate decoder not adopted: " + "; ".join(problems)[:250] + moved)
    work_queue.set_fields(key, fields)
    return fields["status"]


def cited_decoders(record: Path) -> set[str]:
    """The decoder names the record's decode_spec derivations replay; empty for a skip record."""
    try:
        rec = contract.read_record(record)
    except (OSError, ValueError):
        return set()
    return {d["params"]["decoder"] for d in (rec.get("normalisation") or {}).get("derivations") or []
            if d.get("recipe") == "decode_spec" and isinstance(d.get("params"), dict) and "decoder" in d["params"]}


def adopt_decoders(key: str, cited: set[str]) -> tuple[list[str], list[str]]:
    """(adopted, problems): copy the candidate decoders a session wrote to scratch/<key>/decoders/ that the record
    cites into tools/common/decoders/, after the same static check register_decode.py --candidate made, so the
    verifier can replay the derivations that cite them. Uncited candidates (helpers, diagnostics, leftovers of an
    earlier attempt) are neither checked nor adopted. A name that already holds other code is a problem, never
    overwritten. Adopted decoders are new code a person reviews before it is committed."""
    from tools.common.decoders import _NAME, check_decoder_source
    src_dir = paths.SCRATCH / key / "decoders"
    repo = paths.CODE_ROOT / "tools" / "common" / "decoders"
    adopted, problems = [], []
    for cand in sorted(src_dir.glob("*.py")) if src_dir.is_dir() else []:
        if cand.name.startswith("test_"):
            continue
        name = cand.stem
        if name not in cited:
            continue
        if not _NAME.match(name):
            problems.append(f"{cand.name}: not a decoder name")
            continue
        issues = check_decoder_source(cand.read_text(encoding="utf-8"))
        if issues:
            problems.append(f"{name}: " + "; ".join(issues[:3]))
            continue
        dest = repo / cand.name
        if dest.is_file():
            if dest.read_bytes() != cand.read_bytes():
                problems.append(f"{name}: tools/common/decoders/{cand.name} already holds other code")
            continue
        shutil.copyfile(cand, dest)
        adopted.append(name)
    return adopted, problems


def settle_members(record: Path) -> list[str]:
    """When a representative ends as a skip, its members share its install code, so they take the same skip
    reason (as tool-written skip records) instead of staying members of a package with no report."""
    from tools.analysis.prepare import write_skip
    rec = json.loads(record.read_text(encoding="utf-8"))
    ck = (rec.get("package") or {}).get("cluster_key")
    if rec.get("record_type") != "skip" or not ck:
        return []
    rep = rec["package"]
    out = []
    for m in sorted((paths.REPORTS / "_members").glob("*.json")):
        member = json.loads(m.read_text(encoding="utf-8"))
        pk = member.get("package") or {}
        if member.get("record_type") != "member" or pk.get("cluster_key") != ck:
            continue
        note = f"same install code as {rep['ecosystem']}:{rep['name']}@{rep['version']}, skipped: {rec.get('note', '')}"
        write_skip({k: v for k, v in pk.items() if k not in ("analysis_type", "model_name")}, rec["reason"], note)
        m.unlink()
        out.append(key_for(pk["ecosystem"], pk["name"], pk["version"]))
    return out


def todo(rows: list[dict], retry: bool, only: list[str] | None, blocked: bool = False) -> list[str]:
    wanted = RUNNABLE + (RETRYABLE if retry else ()) + (("blocked", "model_mismatch") if blocked else ())
    keys = [r["key"] for r in rows if r.get("key") and r.get("status") in wanted]
    keys = list(dict.fromkeys(keys))
    return [k for k in keys if k in only] if only else keys


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--model", required=True, help="full model id every session runs on (e.g. claude-opus-5-5)")
    ap.add_argument("--jobs", type=int, default=2, help="sessions in parallel (default 2)")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"seconds per package before the session is stopped (default {DEFAULT_TIMEOUT})")
    ap.add_argument("--only", nargs="+", metavar="KEY", help="only these queue keys")
    ap.add_argument("--retry", action="store_true", help="also rerun rows that ended error, timeout or running")
    ap.add_argument("--include-blocked", action="store_true",
                    help="also rerun rows a safeguard blocked or that ran on the wrong model (usually with another "
                         "--model)")
    ap.add_argument("--dry-run", action="store_true", help="print the command for each package, run nothing")
    ap.add_argument("--claude", default="claude", help="the Claude Code executable (default: claude on PATH)")
    ap.add_argument("--no-sandbox", action="store_true", help="run without bubblewrap (tests with a fake CLI only)")
    args = ap.parse_args()
    global SANDBOX
    SANDBOX = not args.no_sandbox
    if SANDBOX and shutil.which("bwrap") is None:
        raise SystemExit("bwrap (bubblewrap) is not installed; it keeps each session to its own package")
    if not work_queue.queue_path().is_file():
        raise SystemExit("scratch/queue.jsonl is missing; run prepare.py --batch first")
    keys = todo(work_queue.read(), args.retry, args.only, args.include_blocked)
    if args.dry_run:
        for key in keys:
            argv = sandboxed(key, args.model, args.claude, Path("<home>")) if SANDBOX else \
                command(key, args.model, args.claude)
            print(shlex.join(argv))
        return 0
    if shutil.which(args.claude) is None:
        raise SystemExit(f"{args.claude} is not on PATH")
    print(f"{len(keys)} packages, {args.jobs} at a time, model {args.model}; logs in scratch/_runs/", flush=True)
    statuses: dict[str, str] = {}

    def one(key):
        status = analyse(key, args.model, args.claude, args.timeout)
        print(f"{status:15} {key}", flush=True)
        return key, status
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        statuses = dict(pool.map(one, keys))
    counts: dict[str, int] = {}
    for s in statuses.values():
        counts[s] = counts.get(s, 0) + 1
    print(f"{len(keys)} packages: " + (", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "nothing to do"))
    adopted = [d for r in work_queue.read() if r.get("key") in keys for d in r.get("decoders_adopted") or []]
    if adopted:
        print(f"new decoders in tools/common/decoders/ (review, add a round-trip test, then commit): "
              f"{', '.join(adopted)}")
    return 0 if all(s == "done" for s in statuses.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
