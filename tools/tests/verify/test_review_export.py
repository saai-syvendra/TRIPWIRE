"""Review folders (packet.py --export) and the sandboxed launch (review_shell.py), without starting any CLI."""
import json
import os
import shutil
from pathlib import Path

import pytest

from tools.tests.verify.test_packet import reviewed  # noqa: F401 (fixture)
from tools.verify import packet, review_shell


@pytest.fixture
def dest(tmp_path_factory):
    return tmp_path_factory.mktemp("review-dest")


def files_of(folder: Path) -> dict[str, bytes]:
    return {p.relative_to(folder).as_posix(): p.read_bytes() for p in sorted(folder.rglob("*")) if p.is_file()}


def test_export_is_self_contained_blind_and_deterministic(reviewed, repo, dest):  # noqa: F811
    pid = packet.build("all")[0]
    out = packet.export(pid, dest)
    assert out == dest / f"review-{pid}"
    files = files_of(out)
    assert set(files) == {"packet.json", "AGENTS.md", "CLAUDE.md", "PROMPT.txt", ".claude/settings.json",
                          ".codex/config.toml", "code/f1.js.txt"}
    assert files["packet.json"] == (repo / "scratch" / "verify" / pid / "packet.json").read_bytes()
    code = files["code/f1.js.txt"].decode()
    assert "hxxps://evil[.]example/x" in code and "https://" not in code
    assert "os.platform() === 'win32'" in code
    for name, body in files.items():
        text = body.decode().lower()
        for leaked in ("two-way", "datadog", "purpose_reason", "assessment", "claude-test", "out_of_set",
                       "provenance", "candidate"):
            assert leaked not in text, (name, leaked)
    agents = files["AGENTS.md"].decode()
    assert "claude" not in agents.lower() and "\n### L1: existence\n" in agents  # the reference, one level down
    assert agents.count("\n# ") == 0 and agents.startswith("# Reviewing one packet")
    for repo_path in ("tools/", "scratch/", "reports/", ".venv", "skills/"):
        assert repo_path not in agents
    packet.export(pid, dest)
    assert files_of(out) == files


def test_both_clis_read_the_same_instructions_and_prompt(reviewed, repo, dest):  # noqa: F811
    out = packet.export(packet.build("all")[0], dest)
    assert (out / "CLAUDE.md").read_text() == "@AGENTS.md\n"
    assert (out / "PROMPT.txt").read_text().strip() == packet.PROMPT
    settings = json.loads((out / ".claude" / "settings.json").read_text())
    assert {"Bash", "Agent", "WebFetch", "WebSearch"} <= set(settings["permissions"]["deny"])


def test_export_refuses_a_destination_inside_the_repo(reviewed, repo):  # noqa: F811
    pid = packet.build("all")[0]
    with pytest.raises(SystemExit, match="inside the repo"):
        packet.export(pid, repo / "review")


@pytest.fixture
def fake_cli(tmp_path_factory, monkeypatch):
    """A fake claude binary and a fake npm-installed codex, and a home with both logins."""
    base = tmp_path_factory.mktemp("cli")
    claude = base / "share" / "claude" / "versions" / "9.9.9"
    claude.parent.mkdir(parents=True)
    claude.write_bytes(b"\x7fELF fake")
    pkg = base / "npm" / "lib" / "node_modules" / "codex"
    (pkg / "bin").mkdir(parents=True)
    (pkg / "package.json").write_text("{}")
    (pkg / "bin" / "codex.js").write_text("#!/usr/bin/env node\n")
    node = base / "nodejs" / "bin" / "node"
    node.parent.mkdir(parents=True)
    node.write_bytes(b"\x7fELF")
    home = base / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / ".credentials.json").write_text("{}")
    which = {"claude": str(claude), "codex": str(pkg / "bin" / "codex.js"), "node": str(node)}
    monkeypatch.setattr(shutil, "which", lambda name: which.get(name))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CODEX_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    return {"claude": claude, "codex_pkg": pkg, "node": node, "home": home}


def binds(cmd):
    return [(cmd[i], cmd[i + 1], cmd[i + 2]) for i, a in enumerate(cmd) if a in ("--bind", "--ro-bind")]


@pytest.mark.parametrize("cli", ["claude", "codex"])
def test_launch_mounts_only_the_review_copy_config_home_and_runtime(reviewed, repo, dest, fake_cli, cli):  # noqa: F811
    pid = packet.build("all")[0]
    run = review_shell.prepare(pid, cli, dest)
    cmd = review_shell.command(pid, cli, dest)
    assert cmd[0] == "bwrap" and "--unshare-all" in cmd and "--share-net" in cmd and "--clearenv" in cmd
    rw = {(src, dst) for kind, src, dst in binds(cmd) if kind == "--bind"}
    assert rw == {(str(run / "review"), "/review"), (str(run / "home"), "/home/reviewer")}
    runtime = {str(fake_cli["claude"].parent)} if cli == "claude" else \
        {str(fake_cli["codex_pkg"]), str(fake_cli["node"].parent.parent)}
    # /etc/resolv.conf may resolve into /run on systems using systemd-resolved.
    etc_binds = {(str(Path(f).resolve()), f) for f in review_shell.ETC_FILES if os.path.exists(f)}
    for kind, src, dst in binds(cmd):
        if kind == "--ro-bind":
            assert src.startswith(("/usr", "/etc", "/bin", "/sbin", "/lib")) or src in runtime or \
                (src, dst) in etc_binds, src
        assert not Path(src).resolve().is_relative_to(repo) and Path(src) != fake_cli["home"]
    assert cmd[cmd.index("--chdir") + 1] == "/review"
    env = {cmd[i + 1]: cmd[i + 2] for i, a in enumerate(cmd) if a == "--setenv"}
    assert env["HOME"] == "/home/reviewer"
    assert env.get("CLAUDE_CONFIG_DIR" if cli == "claude" else "CODEX_HOME", "").startswith("/home/reviewer/")
    assert files_of(run / "review") == files_of(packet.export(pid, dest))
    if cli == "claude":
        assert json.loads((run / "home" / ".claude" / "settings.json").read_text())["permissions"]["deny"]
    else:
        assert '[projects."/review"]' in (run / "home" / ".codex" / "config.toml").read_text()
        assert cmd[-4:] == review_shell.CODEX_ARGS


def test_prepare_keeps_an_unrecorded_session_unless_fresh(reviewed, repo, dest, fake_cli):  # noqa: F811
    pid = packet.build("all")[0]
    run = review_shell.prepare(pid, "claude", dest)
    log = run / "home" / ".claude" / "projects" / "-review" / "s.jsonl"
    log.parent.mkdir(parents=True)
    log.write_text("{}\n")
    with pytest.raises(SystemExit, match="already holds a session"):
        review_shell.prepare(pid, "claude", dest)
    review_shell.prepare(pid, "claude", dest, fresh=True)
    assert not log.exists()


def test_prepare_replaces_an_export_left_from_another_build(reviewed, repo, dest, fake_cli):  # noqa: F811
    pid = packet.build("all")[0]
    old = packet.export(pid, dest)
    (old / "packet.json").write_text('{"claims": "from an earlier build"}')
    run = review_shell.prepare(pid, "claude", dest)
    built = (repo / "scratch" / "verify" / pid / "packet.json").read_bytes()
    assert (run / "review" / "packet.json").read_bytes() == built == (old / "packet.json").read_bytes()


def test_missing_login_is_refused(fake_cli, monkeypatch):
    os.remove(fake_cli["home"] / ".claude" / ".credentials.json")
    with pytest.raises(SystemExit, match="no claude login"):
        review_shell.credential("claude")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    assert review_shell.credential("claude") is None
    with pytest.raises(SystemExit, match="no codex login"):
        review_shell.credential("codex")


def test_dropped_candidate_claims_get_a_slice_and_a_neutral_question(reviewed, repo):  # noqa: F811
    from tools.verify.source import sample_index
    site = reviewed["conditions"][0]["sites"][0]["anchor"]
    drop = {"claim_id": "k_0123456789.L6.drop", "layer": "L6", "claim_sha256": "ab" * 32,
            "fields": {"candidate": "k_0123456789", "anchor": site, "reason_code": "library_code",
                       "note": "colour support check in a bundled logger"}}
    keep = {"claim_id": "c1.L1", "layer": "L1", "claim_sha256": "cd" * 32, "fields": {"api": "os.platform()"}}
    _, data = packet.build_packet(reviewed, [drop, keep], "all", sample_index())
    assert [c["claim_id"] for c in data["claims"]] == ["c1.L1", "k_0123456789.L6.drop"]
    item = data["claims"][1]
    assert "library_code" in item["question"] and "not part of a gate" in item["question"]
    # the analyst's note is their reasoning, so it never reaches the reviewer
    assert item["fields"] == {"anchor": {"slice": item["fields"]["anchor"]["slice"]}, "reason_code": "library_code"}
    assert "colour support" not in json.dumps(data)
    assert any(s["id"] == item["fields"]["anchor"]["slice"] and "os.platform()" in s["text"] for s in data["slices"])


def test_a_recorded_run_folder_is_archived_and_its_export_rebuilt(reviewed, repo, dest, fake_cli,  # noqa: F811
                                                                  tmp_path_factory):
    pid = packet.build("all")[0]
    store = tmp_path_factory.mktemp("archive")
    first = []
    for _ in range(2):  # a second review of the same packet is kept beside the first
        run = review_shell.prepare(pid, "claude", dest)
        log = run / "home" / ".claude" / "projects" / "-review" / "s.jsonl"
        log.parent.mkdir(parents=True)
        log.write_text("{}\n")
        first.append(review_shell.archive(pid, "claude", dest, store))
        assert not run.exists() and not review_shell.export_dir(pid, dest).exists()
    assert [p.name for p in first] == [f"review-{pid}.claude", f"review-{pid}.claude.1"]
    assert (first[0] / "home" / ".claude" / "projects" / "-review" / "s.jsonl").read_text() == "{}\n"
    with pytest.raises(SystemExit, match="inside the repo"):
        review_shell.archive(pid, "claude", dest, repo / "archive")
