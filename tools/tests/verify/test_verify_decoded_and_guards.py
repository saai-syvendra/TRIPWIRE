"""Regressions for the datadog compromised_lib batch: claims the verifier refuted although the code does not
contradict them. Decoded conditions (held open at an encoded site, verified through a replayed decode_spec
derivation), names computed by a call, guards cited on their test expression, early exits whose payload is the
fall-through, and a variable with a fallback assignment. Also the write-time lint that refuses guard and sink
anchors the verifier would reject outright."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tools.analysis import write_report
from tools.common.tsparse import PARSERS, descendants
from tools.tests.verify.test_verify_regressions import cond, finished, gate, guard, region, sink
from tools.verify import checks, verify, witness
from tools.verify.source import sample_index

ROOT = Path(__file__).resolve().parents[3]
KEY = bytes.fromhex("5a172c")
DECODED = (b"const os = require('os');\n"
           b"const cp = require('child_process');\n"
           b"if (os.platform() === 'linux') { cp.exec('id'); }\n")


def xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def register_decode(work, rec):
    """The analyst's capture step, through the exact command a verifier on another machine would trust."""
    run = subprocess.run([sys.executable, "-I", str(ROOT / "tools/analysis/register_decode.py"), str(work),
                          "--decoder", "example_xor", "--input", "payload.enc", "--lang", "js",
                          "--params", json.dumps({"key_hex": KEY.hex()})],
                         capture_output=True, text=True, check=True)
    rec.setdefault("normalisation", {}).setdefault("derivations", []).append(json.loads(run.stdout.splitlines()[0]))


ENCODED_FILES = {"index.js": "module.exports = 0;\n", "payload.enc": xor(DECODED, KEY)}
DECODED_CONDS = [cond("c1", "payload.enc", 3, "os.platform() === 'linux'", "os", "os.platform()", "==", "linux",
                      value_recovered="decoded", derived="d1")]
DECODED_GATES = [gate("c1", [guard("payload.enc", 3, "if (os.platform() === 'linux')", ["c1"], derived="d1")],
                      [region("payload.enc", 3, "{ cp.exec('id'); }", derived="d1")],
                      [sink("payload.enc", 3, "cp.exec('id')", "spawn_process", "exec", derived="d1")],
                      ["spawn_process"])]


def test_a_decoded_condition_verifies_through_its_replayed_decode(repo):
    v = finished(repo, "decoded", ENCODED_FILES, DECODED_CONDS, DECODED_GATES, setup=register_decode)
    for cid in ("c1.L1", "c1.L2", "g1.then.L3", "g1.L4"):
        assert v[cid]["verdict"] == "verified", (cid, v[cid])


@pytest.mark.parametrize("tamper", [
    lambda d: d.update(output_sha256="0" * 16),
    lambda d: d["params"].update(key_hex="ffffff"),
    lambda d: d["params"].update(decoder="no_such_cipher"),
])
def test_a_decode_that_does_not_replay_is_recipe_failed(repo, tamper):
    _, out = finished(repo, "decoded", ENCODED_FILES, DECODED_CONDS, DECODED_GATES, setup=register_decode,
                      with_record=True)
    tamper(out["normalisation"]["derivations"][-1])
    v = {x["claim_id"]: x for x in verify.verdicts_for(out, sample_index())}
    assert (v["c1.L1"]["verdict"], v["c1.L1"]["reason_code"]) == ("unanchored", "recipe_failed")


ENCODED_SITE = """const cp = require('child_process');
function d(s) { return s; }
if (d('R0lUSFVCX1RPS0VO')) { cp.exec('id'); }
"""


@pytest.mark.parametrize("recovered,expected", [("decoded", ("cannot_tell", "encoded_unchecked")),
                                                ("plain", ("cannot_tell", "witness_gap"))])
def test_a_decoded_condition_at_an_encoded_site_is_held_open(repo, recovered, expected):
    v = finished(repo, f"enc-{recovered}", {"index.js": ENCODED_SITE},
                 [cond("c1", "index.js", 3, "d('R0lUSFVCX1RPS0VO')", "env_var", "process.env.GITHUB_TOKEN",
                       "truthy", None, value_recovered=recovered)],
                 [gate("c1", [guard("index.js", 3, "if (d(", ["c1"])], [region("index.js", 3, "{ cp.exec('id'); }")],
                       [sink("index.js", 3, "cp.exec('id')", "spawn_process", "exec")], ["spawn_process"])])
    assert (v["c1.L1"]["verdict"], v["c1.L1"]["reason_code"]) == expected
    if recovered == "decoded":
        assert (v["c1.L2"]["verdict"], v["c1.L2"]["reason_code"]) == ("cannot_tell", "encoded_unchecked")


COMPUTED = """const cp = require('child_process');
function d(s) { return s; }
if ((process.env[d('TENfQUxM')] || '')[d('aW5jbHVkZXM=')]('ru')) { cp.exec('a'); }
if ((process.env.HOME || '').includes('ru')) { cp.exec('b'); }
"""


def test_a_name_computed_by_a_call_is_held_but_a_readable_mismatch_is_refuted(repo):
    v = finished(repo, "computed", {"index.js": COMPUTED},
                 [cond("c1", "index.js", 3, "(process.env[d('TENfQUxM')] || '')[d('aW5jbHVkZXM=')]('ru')",
                       "locale_language", "process.env.LC_ALL", "includes", "ru"),
                  cond("c2", "index.js", 4, "(process.env.HOME || '').includes('ru')", "locale_language",
                       "process.env.LC_ALL", "includes", "ru")],
                 [gate("c1 || c2", [guard("index.js", 3, "if ((process.env", ["c1"]),
                                    guard("index.js", 4, "if ((process.env", ["c2"])],
                       [region("index.js", 3, "{ cp.exec('a'); }"), region("index.js", 4, "{ cp.exec('b'); }")],
                       [sink("index.js", 3, "cp.exec('a')", "spawn_process", "exec")], ["spawn_process"])])
    assert (v["c1.L1"]["verdict"], v["c1.L1"]["reason_code"]) == ("cannot_tell", "encoded_unchecked")
    # the value 'ru' is readable, but the method testing it is named by a call: neither verified nor refuted
    assert (v["c1.L2"]["verdict"], v["c1.L2"]["reason_code"]) == ("cannot_tell", "encoded_unchecked")
    assert (v["c2.L1"]["verdict"], v["c2.L1"]["reason_code"]) == ("refuted", "api_mismatch")


PER_OS = """const os = require('os');
const cp = require('child_process');
if (os.platform() === 'linux') { cp.exec('a'); }
else if (os.platform() === 'win32') { cp.exec('b'); }
else if (os.platform() === 'darwin') { cp.exec('c'); }
"""


def per_os(expression, min_conditions):
    conds = [cond(f"c{i}", "index.js", line, f"os.platform() === '{osv}'", "os", "os.platform()", "==", osv)
             for i, (line, osv) in enumerate([(3, "linux"), (4, "win32"), (5, "darwin")], 1)]
    guards = [guard("index.js", line, f"os.platform() === '{osv}'", [f"c{i}"], node_type="binary_expression")
              for i, (line, osv) in enumerate([(3, "linux"), (4, "win32"), (5, "darwin")], 1)]
    regions = [region("index.js", line, f"{{ cp.exec('{x}'); }}") for line, x in [(3, "a"), (4, "b"), (5, "c")]]
    return conds, [gate(expression, guards, regions, [sink("index.js", 3, "cp.exec('a')", "spawn_process", "exec")],
                        ["spawn_process"], min_conditions=min_conditions)]


def test_guards_cited_on_their_test_expression_read_as_alternatives(repo):
    v = finished(repo, "per-os", {"index.js": PER_OS}, *per_os("c1 || c2 || c3", 1))
    for cid in ("g1.then.L3", "g1.L4", "c1.L2", "c2.L2", "c3.L2"):
        assert v[cid]["verdict"] == "verified", (cid, v[cid])
    assert v["g1.L4"]["grade"] == "consistent"


def test_and_claimed_for_test_cited_alternatives_is_refuted(repo):
    v = finished(repo, "per-os-and", {"index.js": PER_OS}, *per_os("c1 && c2 && c3", 3))
    assert (v["g1.L4"]["verdict"], v["g1.L4"]["reason_code"]) == ("refuted", "expression_mismatch")


EARLY_EXIT = """const os = require('os');
const cp = require('child_process');
if (os.platform() !== 'win32') process.exit(0);
cp.exec('payload');
"""


def test_an_early_exit_cited_on_its_test_guards_the_fall_through(repo):
    v = finished(repo, "early-exit", {"index.js": EARLY_EXIT},
                 [cond("c1", "index.js", 3, "os.platform() !== 'win32'", "os", "os.platform()", "==", "win32")],
                 [gate("c1", [guard("index.js", 3, "os.platform() !== 'win32'", ["c1"], kind="early_exit",
                                    arm="else", node_type="binary_expression")],
                       [region("index.js", 4, "cp.exec('payload');", node_type="expression_statement")],
                       [sink("index.js", 4, "cp.exec('payload')", "spawn_process", "exec")], ["spawn_process"])])
    for cid in ("c1.L2", "g1.then.L3", "g1.L4"):
        assert v[cid]["verdict"] == "verified", (cid, v[cid])


FALLBACK = """const fs = require('fs');
const cp = require('child_process');
let tok = process.env.NPM_TOKEN;
if (!tok) tok = fs.readFileSync('/root/.npmrc', 'utf8');
if (tok) { cp.exec('a'); }
"""


def test_a_variable_with_a_fallback_reaches_both_of_its_sources(repo):
    v = finished(repo, "fallback", {"index.js": FALLBACK},
                 [cond("c1", "index.js", 3, "process.env.NPM_TOKEN", "env_var", "process.env.NPM_TOKEN", "truthy",
                       None)],
                 [gate("c1", [guard("index.js", 5, "if (tok)", ["c1"])], [region("index.js", 5, "{ cp.exec('a'); }")],
                       [sink("index.js", 5, "cp.exec('a')", "spawn_process", "exec")], ["spawn_process"])])
    assert v["c1.L1"]["verdict"] == "verified", v["c1.L1"]
    assert v["c1.L2"]["verdict"] == "verified", v["c1.L2"]


VALUE_SOURCE = """const cp = require('child_process');
const t = process.env.CI;
if (t) { cp.exec('a'); }
"""


@pytest.mark.parametrize("guard_at,sink_text", [((2, "process.env.CI", "member_expression"), "cp.exec('a')"),
                                                ((3, "if (t)", "if_statement"), "'a'")])
def test_guard_and_sink_anchors_the_verifier_would_reject_are_refused_at_write_time(repo, guard_at, sink_text):
    line, text, node_type = guard_at
    with pytest.raises(SystemExit, match="guard or sink anchors do not fit the code"):
        finished(repo, "lint", {"index.js": VALUE_SOURCE},
                 [cond("c1", "index.js", 2, "process.env.CI", "ci_marker", "process.env.CI", "truthy", None)],
                 [gate("c1", [guard("index.js", line, text, ["c1"], node_type=node_type)],
                       [region("index.js", 3, "{ cp.exec('a'); }")],
                       [sink("index.js", 3, sink_text, "spawn_process", "exec")], ["spawn_process"])])


MIXED = {"js": b"""if (a && b()) x(); else if (c) y();
const z = p ? q : r; while (n > 0) n--; switch (k) { case 1: f(); }
try { g(); } catch (e) {} if (!(await h())) { i(); } u ?? v;
""", "py": b"""if a and b():
    x()
elif c:
    y()
z = q if p else r
while n > 0:
    n -= 1
try:
    g()
except Exception:
    pass
"""}


@pytest.mark.parametrize("lang", ["js", "py"])
def test_write_time_lint_and_verifier_agree_on_guard_structure(lang):
    assert write_report.GUARD_NODE_TYPES == witness.GUARD_TYPES
    assert write_report.CALL_NODE_TYPES == witness.CALLS
    tree = PARSERS[lang].parse(MIXED[lang])
    for n in descendants(tree.root_node):
        if not n.is_named:
            continue
        mine, theirs = write_report.decision_test(n), checks.guard_test(n)
        assert (mine is None) == (theirs is None) and (mine is None or (mine.start_byte, mine.end_byte, mine.type)
                                                       == (theirs.start_byte, theirs.end_byte, theirs.type)), n.type
        for kind, types in witness.GUARD_TYPES.items():
            assert write_report.governs(n, types) == (witness.decision_node(n, kind) is not None), (n.type, kind)
