import json

import pytest

from tools.analysis import prepare, write_report
from tools.common import contract
from tools.tests.helpers import NPM, cite, complete, guard, payload, sample, tgz


@pytest.fixture
def work(repo):
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/demo.tgz", tgz(NPM)), None, None)
    return repo / "scratch" / res["key"]


def test_report_is_derived_rendered_and_valid(work, repo):
    complete(work)
    path = write_report.finish(work)
    assert path == repo / "reports" / "npm" / "demo-pkg@1.0.0.md"
    md = path.read_text()
    rec = json.loads(contract.JSON_BLOCK.findall(md)[-1])
    assert contract.validation_errors(contract.load_validator(), rec) == []
    g = rec["gates"][0]
    assert g["then"]["min_conditions"] == 2 and rec["conditions"][0]["in_scope"] is True
    assert rec["behaviours"]["gated"] == ["exfil"]
    assert rec["reachability"]["endpoints"][0]["indicator"] == "hxxps://evil[.]example/c"
    assert rec["candidate_check"] == {
        "condition_candidates": 1, "condition_sites_cited": 1, "guards_cited": 0, "candidates_dropped": 1,
        "conditions_in_set": 1, "conditions_out_of_set": 1, "guard_candidates": 1, "gates_in_set": 0, "gates_out_of_set": 1, "out_of_set_ids": ["c2", "g1"],
        "anchor_refusals": 0}
    assert rec["conditions"][1]["provenance"] == "out_of_set" and rec["gates"][0]["provenance"] == "out_of_set"
    assert "out-of-set claim pending verification" in rec["review_reasons"] and rec["needs_manual_review"]
    assert "hxxps://evil[.]example/c" in md and "https://evil.example" not in md
    assert "| g1 | postinstall | c1 && c2 (c1: os == win32; c2: username == admin) | then | 2 | exfil | os=win32 |" in md
    assert "**Released:** not found" in md and "**Analysis:** ai (claude-test)" in md
    assert "Grounding: 1 of 2 conditions and 0 of 1 gates from the candidate set; out of set, pending " \
           "verification: c2, g1." in md
    assert rec["package"]["analysis_type"] == "ai" and rec["package"]["released_at"] is None


def test_header_shows_release_date_and_source(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["package"].update(released_at="2025-11-24", released_at_source="registry")
    (work / "record.json").write_text(json.dumps(rec))
    md = write_report.finish(work).read_text()
    assert "**Released:** 2025-11-24 (registry)" in md and "**Analysis:** ai (claude-test)" in md


def test_model_name_must_be_filled(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["package"]["model_name"] = "TODO"
    (work / "record.json").write_text(json.dumps(rec))
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "package/model_name" in str(e.value)


def test_network_requirement_hosts_are_defanged():
    assert write_report.defang_hosts(["api.github.com:443", "transfer.sh:443", "dl.dropboxusercontent[.]com",
                                      "evil[.]example", "PyPI index", "10.0.0[.]1:80"]) == \
        ["api[.]github[.]com:443", "transfer[.]sh:443", "dl[.]dropboxusercontent[.]com", "evil[.]example",
         "PyPI index", "10.0.0[.]1:80"]
    assert write_report.defang_hosts("outbound HTTPS to registry.npmjs.org") == "outbound HTTPS to registry[.]npmjs[.]org"


def test_recipe_network_hosts_are_defanged():
    rec = {"gates": [{"then": {"env_recipe": {"network": {"evil.example.com:443": "reachable",
                                                          "10.1.2.3:80": "unreachable"}}},
                      "else": {"env_recipe": {"os": "linux"}}}]}
    want = {"evil[.]example[.]com:443": "reachable", "10[.]1[.]2[.]3:80": "unreachable"}
    write_report.defang_recipe_hosts(rec)
    assert rec["gates"][0]["then"]["env_recipe"]["network"] == want
    write_report.defang_recipe_hosts(rec)  # idempotent
    assert rec["gates"][0]["then"]["env_recipe"]["network"] == want
    assert rec["gates"][0]["else"]["env_recipe"] == {"os": "linux"}


def test_review_triggers_are_applied(work):
    complete(work, confidence="low")
    rec = json.loads(contract.JSON_BLOCK.findall(write_report.finish(work).read_text())[-1])
    assert rec["needs_manual_review"] is True and "low confidence" in rec["review_reasons"]


def test_two_branch_gate_derives_and_renders(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    g = rec["gates"][0]
    g["expression"] = "c1"
    g["effect"] = "selects"
    g["guards"] = [guard(work, ["c1"])]
    g["then"] = {"min_conditions": 9, "behaviours": ["exfil"], "env_recipe": {"os": "win32"},
                 "recipe_guessed_fields": [], "regions": g["then"]["regions"], "payload": [payload(work)]}
    g["else"] = {"min_conditions": 9, "behaviours": ["destructive"], "env_recipe": {"os": "linux"},
                 "recipe_guessed_fields": ["os"], "payload": [payload(work, "destructive")],
                 "regions": [cite(work, "lib/install.js", 4, "process.exit(0);")]}
    rec["conditions"] = [rec["conditions"][0]]
    rec["needs_manual_review"] = True
    (work / "record.json").write_text(json.dumps(rec))
    md = write_report.finish(work).read_text()
    out = json.loads(contract.JSON_BLOCK.findall(md)[-1])
    assert contract.validation_errors(contract.load_validator(), out) == []
    assert out["gates"][0]["then"]["min_conditions"] == 1 and out["gates"][0]["else"]["min_conditions"] == 1
    assert set(out["behaviours"]["gated"]) == {"exfil", "destructive"}
    assert "| then | 1 | exfil | os=win32 |" in md and "| else | 1 | destructive | os=linux |" in md


def test_todo_blocks_writing(work, repo):
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "still TODO" in str(e.value) and "gates/0/polarity" in str(e.value)
    assert not (repo / "reports" / "npm").exists()


def test_skip_choice_is_written(repo, monkeypatch):
    res = prepare.prepare(sample(repo, "npm/b.tgz", tgz({"package.json": json.dumps({"name": "b", "version": "1"})})),
                          "t", None, None)
    work = repo / "scratch" / res["key"]
    assert json.loads((work / "skip.json").read_text())["model_name"] == "TODO"
    (work / "skip.json").write_text(json.dumps({"reason": "import_time_only", "note": "steals at require time",
                                                "model_name": "claude-test"}))
    path = write_report.finish(work)
    rec = json.loads(path.read_text())
    assert path.name == "npm__b@1.json" and rec["reason"] == "import_time_only"
    assert rec["package"]["analysis_type"] == "ai" and rec["package"]["model_name"] == "claude-test"


def test_hallucinated_anchor_is_refused_and_counted(work, repo):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    site = rec["conditions"][1]["sites"][0]
    good = dict(site["anchor"])
    site["anchor"]["sha256"] = "0" * 16
    (work / "record.json").write_text(json.dumps(rec))
    for _ in range(2):  # a retry with the same bad anchor is counted once
        with pytest.raises(SystemExit) as e:
            write_report.finish(work)
        assert "conditions/1/sites/0/anchor: hash_mismatch" in str(e.value)
    assert not (repo / "reports" / "npm").exists()
    site["anchor"] = good
    (work / "record.json").write_text(json.dumps(rec))
    out = json.loads(contract.JSON_BLOCK.findall(write_report.finish(work).read_text())[-1])
    assert out["candidate_check"]["anchor_refusals"] == 1


def test_in_set_site_takes_the_generator_anchor(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    site = rec["conditions"][0]["sites"][0]
    site["anchor"] = {**site["anchor"], "start_byte": 0, "line": 99}
    (work / "record.json").write_text(json.dumps(rec))
    out = json.loads(contract.JSON_BLOCK.findall(write_report.finish(work).read_text())[-1])
    assert out["conditions"][0]["sites"][0]["anchor"]["line"] == 4


def test_unknown_candidate_is_refused(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["conditions"][1]["sites"][0]["candidate"] = "k_ffffffffff"
    (work / "record.json").write_text(json.dumps(rec))
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "c2: unknown candidate k_ffffffffff" in str(e.value)


def test_gate_guards_must_hold_its_conditions(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["gates"][0]["guards"] = [guard(work, ["c1"])]
    (work / "record.json").write_text(json.dumps(rec))
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "g1: guards hold ['c1'] but the expression uses ['c1', 'c2']" in str(e.value)


def test_prefilled_guard_makes_the_gate_in_set(work):
    rec = json.loads((work / "record.json").read_text())
    (g,) = rec["gates"]
    (q,) = g["guards"]
    assert q["candidate"].startswith("q_") and q["kind"] == "early_exit" and q["arm"] == "else"
    assert q["conditions"] == ["c1"]
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["conditions"] = rec["conditions"][:1]
    rec["gates"][0].update(expression="c1", guards=[{**q, "site": {**q["site"], "line": 1}}])
    (work / "record.json").write_text(json.dumps(rec))
    out = json.loads(contract.JSON_BLOCK.findall(write_report.finish(work).read_text())[-1])
    assert out["gates"][0]["provenance"] == "in_set" and out["gates"][0]["guards"][0]["site"]["line"] == 4
    assert out["candidate_check"]["gates_in_set"] == 1 and out["candidate_check"]["out_of_set_ids"] == []


def test_unreached_candidate_can_be_cited_by_id(work):
    # A candidate the generator found but did not prefill (e.g. in a not_chained payload) is in prepared.json;
    # the analyst must be able to cite it by id and have write_report fill its anchor.
    import json
    prep = json.loads((work / "prepared.json").read_text())
    extra = {"id": "c99", "category": "os", "api": "process.platform", "operator": "==", "value": "linux",
             "value_recovered": "plain", "in_scope": True, "provenance": "in_set",
             "sites": [{"candidate": "k_unreached1", "anchor": {"file": "lib/util.js", "derived_from": None,
                        "start_byte": 0, "end_byte": 1, "node_type": "x", "sha256": "0" * 16, "line": 1}}]}
    cand_anchor = cite(work, "lib/install.js", 4, "os.platform() !== 'win32'")
    prep.setdefault("candidates", {}).setdefault("conditions", []).append(
        {"id": "c99", "sites": [{"candidate": "k_unreached1", "anchor": cand_anchor}]})
    (work / "prepared.json").write_text(json.dumps(prep))
    from tools.analysis.write_report import candidate_anchors
    assert "k_unreached1" in candidate_anchors(prep["record"], prep)


def test_cli_help_exits_cleanly():
    import subprocess
    import sys
    from tools.common import paths
    out = subprocess.run([sys.executable, str(paths.CODE_ROOT / "tools" / "analysis" / "write_report.py"), "--help"],
                         capture_output=True, text=True)
    assert out.returncode == 0 and "scratch/<key>" in out.stdout


def test_prefilled_candidates_must_be_cited_or_dropped(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["candidate_review"]["dropped"] = []
    (work / "record.json").write_text(json.dumps(rec))
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "neither cited nor listed" in str(e.value)
    rec["candidate_review"]["dropped"] = [{"candidate": "q_0123456789", "reason_code": "library_code"}]
    (work / "record.json").write_text(json.dumps(rec))
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "unknown candidate q_0123456789" in str(e.value)


def test_dropped_candidates_get_their_anchor_and_become_claims(work):
    from tools.common import claims
    complete(work)
    rec = json.loads(contract.JSON_BLOCK.findall(write_report.finish(work).read_text())[-1])
    (d,) = rec["candidate_review"]["dropped"]
    assert d["anchor"]["node_type"] == "if_statement" and rec["candidate_check"]["candidates_dropped"] == 1
    ids = [c["claim_id"] for c in claims.enumerate_claims(rec)]
    assert f"{d['candidate']}.L6.drop" in ids and all(claims.CLAIM_ID.match(i) for i in ids)


def test_session_model_must_match_model_name(work, repo, monkeypatch):
    complete(work)
    with pytest.raises(SystemExit) as e:
        write_report.finish(work, model_used="claude-other")
    assert "model_name is 'claude-test' but this session runs 'claude-other'" in str(e.value)
    monkeypatch.setenv(write_report.MODEL_ENV, "claude-other")
    with pytest.raises(SystemExit):
        write_report.finish(work)
    assert not (repo / "reports" / "npm").exists()
    monkeypatch.setenv(write_report.MODEL_ENV, "claude-test")
    assert write_report.finish(work).is_file()


def test_session_model_is_checked_on_skips(repo, monkeypatch):
    res = prepare.prepare(sample(repo, "npm/b.tgz", tgz({"package.json": json.dumps({"name": "b", "version": "1"})})),
                          "t", None, None)
    work = repo / "scratch" / res["key"]
    (work / "skip.json").write_text(json.dumps({"reason": "no_install_code", "note": "plain library",
                                                "model_name": "claude-test"}))
    monkeypatch.setenv(write_report.MODEL_ENV, "claude-other")
    with pytest.raises(SystemExit) as e:
        write_report.finish(work)
    assert "this session runs 'claude-other'" in str(e.value)
    assert write_report.finish(work, model_used="claude-test").is_file()


def test_inherited_condition_is_shown(work):
    complete(work)
    rec = json.loads((work / "record.json").read_text())
    rec["conditions"][0]["inherited"] = True
    (work / "record.json").write_text(json.dumps(rec))
    md = write_report.finish(work).read_text()
    out = json.loads(contract.JSON_BLOCK.findall(md)[-1])
    assert out["schema_version"] == "3.2" and out["conditions"][0]["inherited"] is True
    assert "c1: os == win32 [inherited]" in md
