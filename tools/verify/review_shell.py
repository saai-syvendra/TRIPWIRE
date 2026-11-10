#!/usr/bin/env python3
"""
Starts an agent CLI (Claude Code or Codex, interactive or with --print headless) on one exported review packet, inside a bubblewrap
sandbox where the only package-related thing it can see is that packet's review folder. Both CLIs get the same
folder, the same instructions (AGENTS.md, imported by CLAUDE.md), the same single prompt (PROMPT.txt) and an
empty config home, so no user-level instructions, memory, plugins, MCP servers or earlier sessions load.

Layout under DEST (default $XDG_RUNTIME_DIR/tripwire-review, outside the repo):
  review-<packet_id>/              the pristine export (packet.py --export), never mounted
  review-<packet_id>.<cli>/review  a copy, mounted read-write at /review (the reviewer's working directory)
  review-<packet_id>.<cli>/home    the CLI's config home, mounted at /home/reviewer; holds the session log, which
                                   record_verdict.py --session-log auto reads afterwards

Usage: review_shell.py <packet_id> --cli claude|codex [--run] [--print] [--fresh] [--model M] [--dest DIR]
Without --run the command is only printed (nothing is copied to the config home). With --run the CLI's
credential file is copied in for the session and removed when it ends. Nothing from the package is executed.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import paths  # noqa: E402

SANDBOX_CWD = "/review"
SANDBOX_HOME = "/home/reviewer"
CLIS = ("claude", "codex")
# Credential files copied into the empty config home for the session (an API key in the environment also works).
CREDENTIALS = {"claude": (".claude/.credentials.json", ("ANTHROPIC_API_KEY",)),
               "codex": (".codex/auth.json", ("OPENAI_API_KEY", "CODEX_API_KEY"))}
CONFIG_DIR = {"claude": ("CLAUDE_CONFIG_DIR", ".claude"), "codex": ("CODEX_HOME", ".codex")}
# Codex: no approval prompts, writes only in the working directory, no network for the commands it runs.
CODEX_ARGS = ["--sandbox", "workspace-write", "--ask-for-approval", "never"]
# Headless Codex (`codex exec PROMPT`) never asks for approval, so only the sandbox is set; /review is not a git repo.
CODEX_EXEC_ARGS = ["exec", "--sandbox", "workspace-write", "--skip-git-repo-check"]
SYSTEM_DIRS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32")
ETC_FILES = ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/passwd", "/etc/group", "/etc/localtime",
             "/etc/ssl", "/etc/ca-certificates", "/etc/alternatives", "/etc/ld.so.cache")


def default_dest() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    return Path(base) / "tripwire-review" if base else Path("/tmp") / f"tripwire-review-{os.getuid()}"


def check_dest(dest: Path) -> Path:
    dest = dest.expanduser().resolve()
    root = paths.ROOT.resolve()
    if dest == root or dest.is_relative_to(root):
        raise SystemExit(f"{dest} is inside the repo; review folders must live outside it")
    return dest


def default_archive() -> Path:
    """Where recorded run folders go: on disk, since the default destination is a small tmpfs."""
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "tripwire-review-archive"


def archive(pid: str, cli: str, dest: Path | None = None, root: Path | None = None) -> Path | None:
    """Moves a recorded review's run folder (with the session logs, the only copy of the audited transcript) to
    the archive and drops the packet's export, which prepare() rebuilds byte-identical. A second review of the
    same packet is kept beside the first (`.1`, `.2`, ...). Returns where the run folder went."""
    root = check_dest(root or default_archive())
    run = run_dir(pid, cli, dest)
    shutil.rmtree(export_dir(pid, dest), ignore_errors=True)
    if not run.is_dir():
        return None
    root.mkdir(parents=True, exist_ok=True)
    target, n = root / run.name, 0
    while target.exists():
        n += 1
        target = root / f"{run.name}.{n}"
    shutil.move(str(run), str(target))
    return target


def export_dir(pid: str, dest: Path | None = None) -> Path:
    return check_dest(dest or default_dest()) / f"review-{pid}"


def run_dir(pid: str, cli: str, dest: Path | None = None) -> Path:
    return check_dest(dest or default_dest()) / f"review-{pid}.{cli}"


def session_files(home: Path, cli: str) -> list[Path]:
    """The session logs a CLI wrote in its config home (all of them; the audit decides what is allowed)."""
    if cli == "claude":
        return sorted((home / ".claude" / "projects").rglob("*.jsonl"))
    return sorted((home / ".codex" / "sessions").rglob("rollout-*.jsonl"))


def settings(cli: str) -> dict[str, str]:
    """Config files (relative to the config home) that make the CLI ask nothing and load nothing else."""
    if cli == "claude":
        from tools.verify.packet import CLAUDE_SETTINGS
        state = json.dumps({"hasCompletedOnboarding": True, "autoUpdates": False,
                            "projects": {SANDBOX_CWD: {"hasTrustDialogAccepted": True,
                                                       "hasCompletedProjectOnboarding": True}}},
                           indent=2, sort_keys=True) + "\n"
        return {".claude/settings.json": CLAUDE_SETTINGS, ".claude/.claude.json": state, ".claude.json": state}
    from tools.verify.packet import CODEX_CONFIG
    return {".codex/config.toml": CODEX_CONFIG + f'\n[projects."{SANDBOX_CWD}"]\ntrust_level = "trusted"\n'}


def runtime_binds(cli: str) -> tuple[str, list[str], list[str]]:
    """(executable inside the sandbox, read-only bind sources, extra PATH entries) for the CLI."""
    found = shutil.which(cli)
    if not found:
        raise SystemExit(f"{cli} is not on PATH; install it first")
    exe = Path(found).resolve()
    binds, extra_path = [str(exe.parent)], []
    head = exe.read_bytes()[:128] if exe.is_file() else b""
    if head.startswith(b"#!") and b"node" in head.split(b"\n", 1)[0]:  # an npm-installed script run by node
        pkg = next((p for p in [exe.parent, *exe.parents][:5] if (p / "package.json").is_file()), exe.parent)
        binds = [str(pkg)]
        node = shutil.which("node")
        if not node:
            raise SystemExit(f"{cli} runs on node, which is not on PATH")
        node_real = Path(node).resolve()
        if not any(str(node_real).startswith(d + "/") for d in SYSTEM_DIRS):
            binds.append(str(node_real.parent.parent))
        extra_path.append(str(node_real.parent))
    return str(exe), binds, extra_path


def command(pid: str, cli: str, dest: Path | None = None, run: Path | None = None,
            headless_prompt: str | None = None, model: str | None = None) -> list[str]:
    """The bwrap command line that starts the CLI on the packet's review copy. With headless_prompt the CLI is
    run non-interactively on that prompt (claude -p, codex exec) instead of starting an interactive session; the
    prompt is the one operator message, exactly as an interactive paste would be."""
    run = run or run_dir(pid, cli, dest)
    exe, binds, extra_path = runtime_binds(cli)
    cmd = ["bwrap", "--die-with-parent", "--unshare-all", "--share-net", "--hostname", "reviewer"]
    for d in SYSTEM_DIRS:
        p = Path(d)
        if p.is_symlink():
            cmd += ["--symlink", os.readlink(p), d]
        elif p.is_dir():
            cmd += ["--ro-bind", d, d]
    for f in ETC_FILES:
        if os.path.exists(f):
            cmd += ["--ro-bind", str(Path(f).resolve()), f]
    cmd += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for b in binds:
        cmd += ["--ro-bind", b, b]
    cmd += ["--bind", str(run / "review"), SANDBOX_CWD, "--bind", str(run / "home"), SANDBOX_HOME,
            "--chdir", SANDBOX_CWD, "--clearenv"]
    env = {"HOME": SANDBOX_HOME, "USER": "reviewer", "LANG": "C.UTF-8",
           "PATH": ":".join(extra_path + ["/usr/local/bin", "/usr/bin", "/bin"]),
           "TERM": os.environ.get("TERM", "xterm-256color"),
           CONFIG_DIR[cli][0]: f"{SANDBOX_HOME}/{CONFIG_DIR[cli][1]}"}
    if os.environ.get("COLORTERM"):
        env["COLORTERM"] = os.environ["COLORTERM"]
    if cli == "claude":
        env["DISABLE_AUTOUPDATER"] = "1"
    for key in CREDENTIALS[cli][1]:
        if os.environ.get(key):
            env[key] = os.environ[key]
    for k in sorted(env):
        cmd += ["--setenv", k, env[k]]
    cmd += [exe]
    if cli == "codex":
        cmd += CODEX_EXEC_ARGS if headless_prompt is not None else CODEX_ARGS
    if model is not None:
        cmd += ["--model", model]
    if headless_prompt is not None:
        cmd += [headless_prompt] if cli == "codex" else ["-p", headless_prompt]
    return cmd


def prepare(pid: str, cli: str, dest: Path | None = None, fresh: bool = False) -> Path:
    """Creates the run folder: a fresh copy of the export and an empty config home with the CLI's settings."""
    from tools.verify import packet
    src = export_dir(pid, dest)
    built = paths.SCRATCH / "verify" / pid / "packet.json"
    if not (src / "packet.json").is_file() or (src / "packet.json").read_bytes() != built.read_bytes():
        # an export left from an earlier build of the same packet id can hold other claims (the id hashes the
        # record, not the claim model), and its verdicts would be refused as stale
        packet.export(pid, dest)
    run = run_dir(pid, cli, dest)
    if run.exists():
        if session_files(run / "home", cli) and not fresh:
            raise SystemExit(f"{run} already holds a session; record it, or pass --fresh to discard it")
        shutil.rmtree(run)
    shutil.copytree(src, run / "review")
    home = run / "home"
    home.mkdir(mode=0o700)
    for rel, body in settings(cli).items():
        p = home / rel
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        p.write_text(body, encoding="utf-8")
    return run


def credential(cli: str) -> Path | None:
    """The CLI's credential file on the host, or None when an API key in the environment is used instead."""
    rel, keys = CREDENTIALS[cli]
    p = Path.home() / rel
    if p.is_file():
        return p
    if any(os.environ.get(k) for k in keys):
        return None
    raise SystemExit(f"no {cli} login: {p} is missing and none of {', '.join(keys)} is set. Log in to {cli} "
                     "outside the sandbox first.")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("packet_id")
    ap.add_argument("--cli", choices=CLIS, required=True)
    ap.add_argument("--run", action="store_true", help="start the CLI (default: print the command)")
    ap.add_argument("--fresh", action="store_true", help="discard an earlier unrecorded session of this packet")
    ap.add_argument("--print", dest="headless", action="store_true",
                    help="run the CLI non-interactively on the prompt (claude -p, codex exec) instead of an interactive session")
    ap.add_argument("--model", help="run the CLI on this model for the whole session (default: the CLI's own default)")
    ap.add_argument("--dest", type=Path)
    args = ap.parse_args()
    if shutil.which("bwrap") is None:
        raise SystemExit("bwrap (bubblewrap) is not installed")
    cred = credential(args.cli)
    run = prepare(args.packet_id, args.cli, args.dest, args.fresh)
    prompt = (run / "review" / "PROMPT.txt").read_text(encoding="utf-8").strip()
    cmd = command(args.packet_id, args.cli, args.dest, run, prompt if args.headless else None, args.model)
    print(f"review folder: {run / 'review'}  (mounted at {SANDBOX_CWD})\n")
    if args.headless:
        print(f"headless: the CLI is run on this one prompt and exits on its own:\n\n    {prompt}\n")
    else:
        print("Paste exactly this prompt, send nothing else (no follow-ups, no slash commands except /exit), and "
              "exit once verdicts.json is written:\n")
        print(f"    {prompt}\n")
    record = (f".venv/bin/python tools/verify/record_verdict.py --packet {args.packet_id} "
              f"--session-log auto --cli {args.cli}" + (f" --dest {args.dest}" if args.dest else ""))
    if not args.run:
        print("command (run it with --run, which also copies the login in):\n")
        print(shlex.join(cmd) + "\n")
        print(f"afterwards: {record}")
        return
    copied = None
    if cred is not None:
        copied = run / "home" / CREDENTIALS[args.cli][0]
        copied.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(cred, copied)
        copied.chmod(0o600)
    try:
        code = subprocess.run(cmd).returncode
    finally:
        if copied is not None and copied.exists():
            copied.unlink()
    print(f"\nsession ended ({code}). Now: {record}")
    if code:
        raise SystemExit(code)  # a failed session must not look like a finished review to run_reviews.py


if __name__ == "__main__":
    main()
