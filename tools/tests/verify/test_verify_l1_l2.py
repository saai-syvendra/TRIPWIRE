import copy
import json

from tools.analysis import prepare, write_report
from tools.common import claims, contract, paths
from tools.tests.helpers import NPM, cite, complete, sample, tgz
from tools.verify import checks, verify
from tools.verify.source import Package, sample_index


def analysed(repo, files=NPM, finish=complete):
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/demo.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    finish(work)
    path = write_report.finish(work)
    return path, contract.read_record(path)


def by_claim(rec):
    return {v["claim_id"]: v for v in verify.verdicts_for(rec, sample_index())}


def test_generator_claims_verify_and_a_bogus_addition_is_refuted(repo):
    _, rec = analysed(repo)
    v = by_claim(rec)
    assert v["c1.L1"]["verdict"] == "verified", v["c1.L1"]
    assert v["c1.L2"]["verdict"] == "verified", v["c1.L2"]  # code tests !== 'win32' before an exit: positive ==
    assert v["c2.L1"]["verdict"] == "refuted" and v["c2.L1"]["reason_code"] == "not_a_test"
    # the site is not a comparison, so the value cannot be read there: cannot_tell, not a contradiction
    assert v["c2.L2"]["verdict"] == "cannot_tell"
    assert not any(k.startswith("g1.L6") for k in v)


def test_wrong_operator_and_wrong_value_are_refuted(repo):
    _, rec = analysed(repo)
    flipped = copy.deepcopy(rec)
    flipped["conditions"][0]["operator"] = "!="
    assert by_claim(flipped)["c1.L2"]["reason_code"] == "operator_mismatch"
    other = copy.deepcopy(rec)
    other["conditions"][0]["value"] = "darwin"
    assert by_claim(other)["c1.L2"]["reason_code"] == "value_mismatch"
    wrong_api = copy.deepcopy(rec)
    wrong_api["conditions"][0]["api"] = "os.hostname()"
    assert by_claim(wrong_api)["c1.L1"]["reason_code"] == "api_mismatch"


def test_missing_sample_and_changed_bytes_are_unanchored(repo):
    path, rec = analysed(repo)
    gone = copy.deepcopy(rec)
    gone["package"]["archive_sha256"] = "ff" * 32
    assert {v["reason_code"] for v in by_claim(gone).values()} == {"sample_missing"}
    moved = copy.deepcopy(rec)
    moved["conditions"][0]["sites"][0]["anchor"]["start_byte"] += 1
    assert by_claim(moved)["c1.L1"]["reason_code"] == "anchor_hash_mismatch"


def test_aliases_are_followed_within_scope_only(repo):
    files = {"package.json": json.dumps({"name": "alias", "version": "1.0.0", "scripts": {"postinstall": "node i.js"}}),
             "i.js": "function a() { const p = process.platform; if (p === 'linux') run('x'); }\n"
                     "function b() { const p = 'darwin'; if (p === 'linux') run('y'); }\n"}
    res = prepare.prepare(sample(repo, "npm/alias.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    pkg = Package({"package": json.loads((work / "prepared.json").read_text())["package"],
                   "normalisation": {"derivations": []}}, sample_index())

    def cond(line):
        return {"id": "c1", "api": "process.platform", "category": "os",
                "sites": [{"anchor": cite(work, "i.js", line, "p === 'linux'")}]}
    assert checks.check_l1(pkg, cond(1))["verdict"] == "verified"
    assert checks.check_l1(pkg, cond(2))["verdict"] == "refuted"  # b's p is a literal, not the platform


def test_cli_appends_a_deterministic_run(repo, monkeypatch):
    path, rec = analysed(repo)
    monkeypatch.setattr(verify, "tool_version", lambda: "verify@py3.13")
    verify.run([(path, rec)])
    verify.run([(path, rec)])  # same environment, same record, same verdicts: nothing new to append
    side = next((repo / "reports" / "_verification").glob("*/deterministic__verify.json"))
    assert len(json.loads(side.read_text())["runs"]) == 1
    monkeypatch.setattr(verify, "tool_version", lambda: "verify@py3.14")
    verify.run([(path, rec)])
    data = json.loads(side.read_text())
    assert len(data["runs"]) == 2 and data["runs"][0]["by"].startswith("verify@")
    ids = {v["claim_id"] for v in data["runs"][0]["verdicts"]}
    assert ids == {c["claim_id"] for c in claims.enumerate_claims(rec) if c["layer"] in claims.DETERMINISTIC_LAYERS}
    assert paths.REPORTS == repo / "reports"


def prepared_pkg(repo, rel, files):
    res = prepare.prepare(sample(repo, rel, tgz(files, prefix="")), None, None)
    work = repo / "scratch" / res["key"]
    prep = json.loads((work / "prepared.json").read_text())
    return work, prep, Package({"package": prep["package"], "normalisation": prep["record"]["normalisation"]},
                               sample_index())


def test_python_negations_and_try_probes(repo):
    setup = ("import os, sys\n"
             "from setuptools import setup\n"
             "if not sys.platform.startswith('linux'):\n"
             "    raise SystemExit(0)\n"
             "try:\n"
             "    open('/.dockerenv').read()\n"
             "    in_docker = True\n"
             "except OSError:\n"
             "    in_docker = False\n"
             "setup(name='demo', version='1.0')\n")
    work, prep, pkg = prepared_pkg(repo, "pypi/demo-1.0.tar.gz", {"demo-1.0/setup.py": setup,
                                                                  "demo-1.0/PKG-INFO": "Name: demo\nVersion: 1.0\n"})
    plat = {"id": "c1", "api": "sys.platform", "category": "os", "operator": "startswith", "value": "linux",
            "value_recovered": "plain", "sites": [{"anchor": cite(work, "setup.py", 3,
                                                                  "sys.platform.startswith('linux')")}]}
    guard = {"conditions": ["c1"], "arm": "else", "site": cite(work, "setup.py", 3, "if not", node_type="if_statement")}
    rec = {"gates": [{"guards": [guard]}]}
    assert checks.check_l1(pkg, plat)["verdict"] == "verified"
    v = checks.check_l2(pkg, rec, plat)
    assert v["verdict"] == "verified", v  # `not ...startswith` before an exit: positive startswith
    probe = {"id": "c2", "api": "open", "category": "vm_sandbox_artifact", "operator": "exists",
             "value": "/.dockerenv", "value_recovered": "plain",
             "sites": [{"anchor": cite(work, "setup.py", 6, "open('/.dockerenv')")}]}
    assert checks.check_l1(pkg, probe)["verdict"] == "verified"


def test_inline_hook_code_is_rebuilt_from_the_manifest(repo):
    files = {"package/package.json": json.dumps({
        "name": "inline", "version": "2.0.0",
        "scripts": {"preinstall": "node -e \"if (process.platform === 'win32') require('child_process').exec('x')\""}})}
    work, prep, pkg = prepared_pkg(repo, "npm/inline.tgz", files)
    cond = next(c for c in prep["record"]["conditions"] if c["api"] == "process.platform")
    assert cond["sites"][0]["anchor"]["derived_from"] == "d1"
    assert checks.check_l1(pkg, cond)["verdict"] == "verified"
    tampered = Package({"package": prep["package"], "normalisation": {"derivations": [
        {**prep["record"]["normalisation"]["derivations"][0], "output_sha256": "0" * 16}]}}, sample_index())
    assert checks.check_l1(tampered, cond)["reason_code"] == "recipe_failed"


def test_a_record_with_no_sample_gets_no_run(repo, monkeypatch, capsys):
    path, rec = analysed(repo)
    monkeypatch.setattr(verify, "sample_index", dict)
    assert verify.run([(path, rec)]) == []
    assert "skipped 1 records" in capsys.readouterr().err
    assert not list((repo / "reports" / "_verification").glob("*/deterministic__verify.json"))
