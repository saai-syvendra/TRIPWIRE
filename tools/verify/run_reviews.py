#!/usr/bin/env python3
"""
Runs the agent review pass over every packet in scratch/verify/queue.jsonl that this CLI has not reviewed yet:
the reviews in parallel (each in its own bubblewrap sandbox, headless, on the one fixed launch prompt), each one
recorded as soon as it finishes (record_verdict.py marks the queue under a lock), so an interrupted batch keeps
every review it finished.

Usage: run_reviews.py --cli claude|codex [--model M] [--jobs N] [--timeout S] [--only PACKET ...] [--logs DIR]
                      [--archive DIR]

Build the queue first (packet.py --mode residual / out_of_set / all). The queue tracks each CLI separately, so a
Codex pass after a Claude pass reviews the same packets; rows packet.py marked superseded are skipped. Before
starting a review, an earlier session of the packet that finished but was not recorded is recorded if it passes
the audit; otherwise the review starts --fresh. --timeout stops a hung session (it decides only whether a review
happened, never a verdict). A packet whose review or recording fails stays pending; the reasons are printed at
the end and the exit status is 1.
Per-packet output goes to LOGS/<packet_id>.log and .record (default $XDG_RUNTIME_DIR/tripwire-review/logs). Once a
review is recorded its run folder moves to --archive (default ~/.cache/tripwire-review-archive, on disk): the runtime
tmpfs holds only a few hundred review folders, and the folder keeps the only copy of the audited session log.
Nothing from the package is executed. See skills/verify-gates/references/agent-runners.md.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402
from tools.verify import review_shell  # noqa: E402

PY = sys.executable
QUEUE = paths.ROOT / "scratch" / "verify" / "queue.jsonl"


def pending(queue: Path = QUEUE, only: list[str] | None = None, cli: str = "claude") -> list[str]:
    from tools.verify.record_verdict import done_by
    rows = [json.loads(line) for line in queue.read_text().splitlines() if line.strip()]
    ids = [r["packet_id"] for r in rows if cli not in done_by(r) and not r.get("superseded")]
    return [p for p in ids if p in only] if only else ids


def tail(path: Path, n: int = 3) -> str:
    lines = [ln.strip() for ln in path.read_text(errors="replace").splitlines() if ln.strip()]
    return " | ".join(lines[-n:])[:400]


def review(pid: str, cli: str, model: str | None, logs: Path, timeout: float | None = None) -> int | None:
    """The review session's exit code, or None when it ran past the timeout (its process group is stopped)."""
    import os
    import signal
    cmd = [PY, str(paths.ROOT / "tools/verify/review_shell.py"), pid, "--cli", cli, "--print", "--run", "--fresh"]
    if model:
        cmd += ["--model", model]
    with open(logs / f"{pid}.log", "w") as f:
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT, cwd=paths.ROOT,
                                start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return None


def finished_unrecorded(pid: str, cli: str) -> bool:
    """An earlier session of this packet left a verdicts.json (it finished, but was never recorded)."""
    return (review_shell.run_dir(pid, cli) / "review" / "verdicts.json").is_file()


def record(pid: str, cli: str, logs: Path) -> bool:
    cmd = [PY, str(paths.ROOT / "tools/verify/record_verdict.py"), "--packet", pid, "--session-log", "auto", "--cli", cli]
    with open(logs / f"{pid}.record", "w") as f:
        return subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=f, stderr=subprocess.STDOUT,
                              cwd=paths.ROOT).returncode == 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cli", choices=review_shell.CLIS, required=True)
    ap.add_argument("--model", help="run every session on this model (needed to avoid mid-session fallbacks)")
    ap.add_argument("--jobs", type=int, default=4, help="reviews in parallel (default 4)")
    ap.add_argument("--only", nargs="+", metavar="PACKET", help="only these packet ids")
    ap.add_argument("--timeout", type=float, default=3600, help="seconds before a hung review is stopped")
    ap.add_argument("--logs", type=Path, default=review_shell.default_dest() / "logs")
    ap.add_argument("--archive", type=Path, default=review_shell.default_archive(),
                    help="where recorded run folders are moved (default %(default)s)")
    args = ap.parse_args()
    if not QUEUE.is_file():
        raise SystemExit(f"{QUEUE} is missing; build it with packet.py --mode residual / out_of_set")
    review_shell.credential(args.cli)  # fail early on a missing login
    args.logs.mkdir(parents=True, exist_ok=True)
    todo = pending(only=args.only, cli=args.cli)
    print(f"{len(todo)} packets pending for {args.cli}, {args.jobs} at a time; logs in {args.logs}", flush=True)
    failed: dict[str, str] = {}
    lock = threading.Lock()

    def one(pid: str) -> bool:
        # a session that finished before an interruption is recorded, not thrown away
        if finished_unrecorded(pid, args.cli):
            with lock:
                if record(pid, args.cli, args.logs):
                    review_shell.archive(pid, args.cli, root=args.archive)
                    return True
        rc = review(pid, args.cli, args.model, args.logs, args.timeout)
        if rc is None:
            failed[pid] = f"review stopped after {args.timeout:.0f}s"
            return False
        if rc:
            failed[pid] = f"review exited {rc}: {tail(args.logs / (pid + '.log'))}"
            return False
        if not finished_unrecorded(pid, args.cli):
            failed[pid] = f"no verdicts.json (stopped before writing): {tail(args.logs / (pid + '.log'))}"
            return False
        with lock:  # one recorder at a time: each appends to a sidecar and rewrites the queue
            ok = record(pid, args.cli, args.logs)
        if ok:
            review_shell.archive(pid, args.cli, root=args.archive)
        else:
            failed[pid] = f"not recorded: {tail(args.logs / (pid + '.record'))}"
        return ok

    done = 0
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for pid, ok in zip(todo, pool.map(one, todo)):
            done += ok
            print(f"{pid}: {'recorded' if ok else failed.get(pid, 'failed')}", flush=True)
    print(f"recorded {done} of {len(todo)}; {len(failed)} stay pending")
    for pid, why in failed.items():
        print(f"  {pid}: {why}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
