import json
import os
import stat

import pytest

from tools.analysis import prepare
from tools.common import reset
from tools.tests.helpers import NPM, sample, tgz


@pytest.fixture
def env(repo):
    (repo / "dataset").mkdir()
    (repo / "dataset" / "packages.jsonl").write_text("{}\n")
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/demo.tgz", tgz(NPM)), None, None)
    return repo, repo / "scratch" / res["key"]


def run(monkeypatch, *flags):
    monkeypatch.setattr("sys.argv", ["reset.py", *flags])
    return reset.main()


def test_untouched_scratch_and_dataset_are_cleared(env, monkeypatch, capsys):
    repo, work = env
    (repo / "scratch" / "queue.jsonl").write_text("{}\n")
    (repo / "scratch" / "_unpack_abc").mkdir()
    (repo / "reports" / "npm").mkdir(parents=True)
    (repo / "reports" / "npm" / "kept@1.md").write_text("x")
    assert reset.in_progress(work) is None
    assert run(monkeypatch) == 0
    assert list((repo / "scratch").iterdir()) == [] and list((repo / "dataset").iterdir()) == []
    assert (repo / "reports" / "npm" / "kept@1.md").exists() and (repo / "samples").exists()
    assert "cleared 3 entries in scratch/ and 1 in dataset/" in capsys.readouterr().out


def test_interrupted_analysis_blocks_until_forced(env, monkeypatch, capsys):
    repo, work = env
    rec = json.loads((work / "record.json").read_text())
    rec["attack_type"] = "typosquat"
    (work / "record.json").write_text(json.dumps(rec))
    (work / "summary.md").write_text("## Summary\n\nhalf written\n")
    assert run(monkeypatch) == 1
    assert work.exists() and (repo / "dataset" / "packages.jsonl").exists()
    assert "record.json, summary.md edited" in capsys.readouterr().err
    assert run(monkeypatch, "--force") == 0
    assert not work.exists()


def test_finished_analysis_is_not_in_progress(env):
    repo, work = env
    (work / "summary.md").write_text("## Summary\n\ndone\n")
    (repo / "reports" / "npm").mkdir(parents=True)
    (repo / "reports" / "npm" / "demo-pkg@1.0.0.md").write_text("x")
    assert reset.in_progress(work) is None


def test_skip_choice_counts_as_work(repo, monkeypatch):
    res = prepare.prepare(sample(repo, "npm/b.tgz", tgz({"package.json": json.dumps({"name": "b", "version": "1"})})),
                          "t", None, None)
    work = repo / "scratch" / res["key"]
    assert reset.in_progress(work) is None
    (work / "skip.json").write_text(json.dumps({"reason": "import_time_only", "note": "TODO"}))
    assert reset.in_progress(work) == "skip.json edited, no record in reports/"


def test_dry_run_deletes_nothing(env, monkeypatch, capsys):
    repo, work = env
    assert run(monkeypatch, "--dry-run") == 0
    assert work.exists() and (repo / "dataset" / "packages.jsonl").exists()
    assert "would delete scratch/npm__demo-pkg@1.0.0" in capsys.readouterr().out


def test_read_only_unpacked_tree_and_links_are_removed(env, monkeypatch, tmp_path_factory):
    repo, work = env
    outside = tmp_path_factory.mktemp("outside")
    (outside / "keep.txt").write_text("x")
    locked = work / "unpacked" / "locked"
    locked.mkdir()
    (locked / "f.js").write_text("x")
    os.symlink(outside, work / "unpacked" / "link")
    os.chmod(locked, stat.S_IRUSR | stat.S_IXUSR)
    assert run(monkeypatch) == 0
    assert not work.exists() and (outside / "keep.txt").exists()


def test_unfinished_queue_blocks(env, monkeypatch, capsys):
    repo, work = env
    entry = {"key": work.name, "status": "analyse", "prepared": f"scratch/{work.name}/prepared.json", "sample": "x"}
    (repo / "scratch" / "queue.jsonl").write_text(json.dumps(entry) + "\n")
    assert reset.pending_queue() == [work.name]
    assert run(monkeypatch) == 1 and work.exists()
    assert "1 queued packages have no record yet: npm__demo-pkg@1.0.0" in capsys.readouterr().err
    (repo / "reports" / "npm").mkdir(parents=True)
    (repo / "reports" / "npm" / "demo-pkg@1.0.0.md").write_text("x")
    assert reset.pending_queue() == [] and run(monkeypatch) == 0
