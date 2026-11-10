"""The verifier on large and generated code: a callee name shared by many definitions is not followed, every claim
runs under a fixed work budget, and the work an L5 claim does on a large single-line bundle does not grow with the
size of the file (it used to rescan the whole tree for every call it followed, which took hours on a 3.7 MB
bundle). Work is counted in syntax nodes visited, never timed, so these tests are deterministic."""
import pytest

from tools.common.tsparse import descendants
from tools.tests.verify.test_verify_regressions import cond, finished, gate, guard, region, sink
from tools.verify import checks, witness
from tools.verify.source import Package, sample_index

WRAPPERS = """const cp = require('child_process');
const api = { createRepo() { cp.exec('git push'); } };
const s1 = { create() { cp.exec('a'); } };
const s2 = { create() { cp.exec('b'); } };
const s3 = { create() { cp.exec('c'); } };
const s4 = { create() { cp.exec('d'); } };
if (process.env.CI) { api.createRepo(); store.create(); }
"""


def wrapper_gate(call):
    return ([cond("c1", "index.js", 7, "process.env.CI", "ci_marker", "process.env.CI", "truthy", None)],
            [gate("c1", [guard("index.js", 7, "if (process.env.CI)", ["c1"])],
                  [region("index.js", 7, "{ api.createRepo(); store.create(); }")],
                  [sink("index.js", 7, call, "spawn_process", "exec")], ["spawn_process"])])


@pytest.mark.parametrize("call,expected", [("api.createRepo()", ("verified", "consistent")),
                                           ("store.create()", ("cannot_tell", "cannot_tell"))])
def test_a_wrapper_is_followed_by_name_only_when_the_name_is_not_ambiguous(repo, call, expected):
    v = finished(repo, f"wrap-{call[:5]}", {"index.js": WRAPPERS}, *wrapper_gate(call))
    assert (v["g1.then.L5"]["verdict"], v["g1.then.L5"]["grade"]) == expected, v["g1.then.L5"]


def test_a_claim_over_its_budget_is_cannot_tell_with_its_layers_grade(repo, monkeypatch):
    monkeypatch.setattr(checks, "CLAIM_BUDGET", 5)
    v = finished(repo, "budget", {"index.js": WRAPPERS}, *wrapper_gate("api.createRepo()"))
    assert (v["c1.L1"]["verdict"], v["c1.L1"]["reason_code"], v["c1.L1"]["grade"]) == \
        ("cannot_tell", "budget_exceeded", None)
    assert (v["g1.then.L5"]["reason_code"], v["g1.then.L5"]["grade"]) == ("budget_exceeded", "cannot_tell")
    assert not [x for x in v.values() if x["verdict"] == "refuted"]


def bundle(namesakes: int) -> str:
    """A minified-style bundle on one line: many generated methods sharing one name, then a gated call of it."""
    parts = ["const cp=require('child_process');"]
    parts += [f"const m{i}={{create(){{cp.exec('x{i}');return {i};}},verify(){{return {i};}}}};" for i in range(namesakes)]
    parts.append("if(process.env.CI){store.create();}")
    return "".join(parts) + "\n"


def test_l5_work_on_a_large_single_line_bundle_does_not_scale_with_the_file(repo):
    _, out = finished(repo, "big-bundle", {"index.js": bundle(3000)},
                      [cond("c1", "index.js", 1, "process.env.CI", "ci_marker", "process.env.CI", "truthy", None)],
                      [gate("c1", [guard("index.js", 1, "if(process.env.CI)", ["c1"])],
                            [region("index.js", 1, "{store.create();}")],
                            [sink("index.js", 1, "store.create()", "spawn_process", "exec")], ["spawn_process"])],
                      with_record=True)
    pkg = Package(out, sample_index())
    _, tree, _ = pkg.tree("index.js", None)
    total = sum(1 for _ in descendants(tree.root_node))
    with checks.budget(10 ** 9) as meter:
        v = witness.check_l5(pkg, out["gates"][0], "then")
    assert v["verdict"] == "cannot_tell"  # 3000 namesakes: the wrapper is ambiguous, not followed
    assert total > 100_000 and meter.spent < total // 100, (meter.spent, total)
