import io
import json
import textwrap
import zipfile

from tools.analysis import prepare
from tools.tests.helpers import NPM, prepared, sample, tgz, zipcrypto


def test_datadog_password_zip_around_tgz(repo):
    archive = repo / "samples" / "datadog" / "npm" / "malicious_intent" / "demo-pkg" / "1.0.0" / "demo.zip"
    archive.parent.mkdir(parents=True)
    zipcrypto(archive, {"demo-pkg-1.0.0.tgz": tgz(NPM)})
    res = prepare.prepare(archive, None, None)
    assert res["status"] == "analyse" and res["key"] == "npm__demo-pkg@1.0.0"
    p = prepared(repo, res)
    rec = p["record"]
    assert rec["package"]["source_dataset"] == "datadog" and rec["package"]["source_label"] == "malicious"
    ep = rec["execution"]["entry_points"][0]
    assert ep["hook"] == "postinstall" and ep["file_chain"] == ["lib/install.js", "lib/util.js"]
    assert ep["silent_failure"] is True and ep["launch_style"] == ["direct_script"]
    assert [(c["category"], c["operator"], c["value"]) for c in rec["conditions"]] == [("os", "==", "win32")]
    assert rec["gates"][0]["then"]["env_recipe"] == {"os": "win32"} and rec["gates"][0]["purpose"] == "TODO"
    assert rec["reachability"]["endpoints"] == [{"indicator": "hxxps://evil[.]example/c", "role": "TODO"}]
    sink = next(s for s in p["hints"]["sinks"] if s["kind"] == "network")
    assert sink["gate"] == "g1"


def test_unsafe_member_is_refused_with_files_missing(repo):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.js", "x")
    res = prepare.prepare(sample(repo, "npm/evil.zip", buf.getvalue()), None, None)
    assert res["status"] == "skipped" and res["reason"] == "files_missing"
    rec = json.loads((repo / res["record"]).read_text())
    assert "unsafe member path" in rec["note"]


def test_not_a_package(repo):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("SKILL.md", "# a skill file")
    res = prepare.prepare(sample(repo, "other/skill.zip", buf.getvalue()), None, None)
    assert res == {"status": "skipped", "reason": "not_a_package", "record": res["record"]}


def test_inline_eval_and_manifest_os(repo):
    pkg = {"package.json": json.dumps({
        "name": "inline", "version": "2.0.0", "os": ["win32"],
        "scripts": {"preinstall": "node -e \"if (process.platform === 'win32') require('child_process').exec('x')\""}})}
    res = prepare.prepare(sample(repo, "npm/inline.tgz", tgz(pkg)), "openssf", "malicious")
    rec = prepared(repo, res)["record"]
    ep = rec["execution"]["entry_points"][0]
    assert ep["launch_style"] == ["inline_eval"] and ep["interpreter"] == "node"
    conds = {c["id"]: c for c in rec["conditions"]}
    (site,) = conds["c1"]["sites"]
    assert site["candidate"].startswith("k_") and site["anchor"]["file"] == "package.json"
    (d,) = rec["normalisation"]["derivations"]
    assert site["anchor"]["derived_from"] == d["id"] and d["recipe"] == "inline_script"
    code = (repo / "scratch" / res["key"] / "derived" / d["id"]).read_bytes()
    a = site["anchor"]
    assert code[a["start_byte"]:a["end_byte"]] == b"process.platform === 'win32'"
    resolve = next(g for g in rec["gates"] if g["hook"] == "resolve")
    manifest = conds[resolve["expression"]]
    assert manifest["api"] == "package.json#os" and manifest["sites"][0]["anchor"]["node_type"] == "text"
    raw = (repo / "scratch" / res["key"] / "unpacked" / rec["package"]["package_root"] / "package.json").read_bytes()
    m = manifest["sites"][0]["anchor"]
    assert raw[m["start_byte"]:m["end_byte"]] == b'"os": ["win32"]'
    assert resolve["then"]["env_recipe"] == {"os": "win32"} and resolve["else"] is None


def test_node_script_without_extension(repo):
    pkg = {"package.json": json.dumps({"name": "noext", "version": "1.0.0",
                                       "scripts": {"postinstall": "node ./bin/post-install || exit 0"}}),
           "bin/post-install.js": "if (process.env.CI) process.exit(0);\nrequire('child_process').exec('x');\n"}
    rec = prepared(repo, prepare.prepare(sample(repo, "npm/noext.tgz", tgz(pkg)), None, None))["record"]
    ep = rec["execution"]["entry_points"][0]
    assert ep["file_chain"] == ["bin/post-install.js"] and ep["silent_failure"] is True
    assert rec["gates"][0]["then"]["env_recipe"] == {"env_var_absent": ["CI"]}


def test_implicit_node_gyp(repo):
    pkg = {"package.json": json.dumps({"name": "native", "version": "1.0.0"}), "binding.gyp": "{}"}
    rec = prepared(repo, prepare.prepare(sample(repo, "npm/native.tgz", tgz(pkg)), None, None))["record"]
    ep = rec["execution"]["entry_points"][0]
    assert ep["hook"] == "node_gyp_implicit" and ep["launch_style"] == ["native_build"]


def test_no_install_hooks_needs_a_skip_reason(repo):
    pkg = {"package.json": json.dumps({"name": "plain", "version": "1.0.0", "main": "index.js"}), "index.js": "x"}
    res = prepare.prepare(sample(repo, "npm/plain.tgz", tgz(pkg)), None, None)
    p = prepared(repo, res)
    assert res["status"] == "needs_skip_reason" and p["facts"]["import_entry_files"] == ["index.js"]


def test_wheel_needs_a_skip_reason(repo):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/__init__.py", "import os\n")
        zf.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
    res = prepare.prepare(sample(repo, "pypi/demo-1.0-py3-none-any.whl", buf.getvalue()), None, None)
    assert res["status"] == "needs_skip_reason" and res["key"] == "pypi__demo@1.0"


def test_wheel_under_a_tar_gz_name_is_unpacked_by_content(repo):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("demo/__init__.py", "import os\n")
        zf.writestr("demo-1.0.dist-info/METADATA", "Name: demo\nVersion: 1.0\n")
    res = prepare.prepare(sample(repo, "pypi/demo-1.0-py3-none-any.tar.gz", buf.getvalue()), None, None)
    assert res["status"] == "needs_skip_reason" and res["key"] == "pypi__demo@1.0"


def test_sdist_with_cmdclass(repo):
    files = {
        "PKG-INFO": "Name: pyevil\nVersion: 0.1\n",
        "setup.py": """
            import os, sys
            from setuptools import setup
            from setuptools.command.install import install

            class Post(install):
                def run(self):
                    install.run(self)
                    if os.name == 'nt':
                        os.system('calc')

            setup(name='pyevil', version='0.1', cmdclass={'install': Post})
        """,
    }
    res = prepare.prepare(sample(repo, "pypi/pyevil-0.1.tar.gz", tgz(files, "pyevil-0.1/")), None, None)
    rec = prepared(repo, res)["record"]
    hooks = [e["hook"] for e in rec["execution"]["entry_points"]]
    assert hooks == ["cmdclass", "setup_py"]
    assert rec["gates"][0]["hook"] == "cmdclass" and rec["gates"][0]["then"]["env_recipe"] == {"os": "win32"}


def test_duplicate_is_reported_not_overwritten(repo):
    (repo / "reports" / "npm").mkdir(parents=True)
    (repo / "reports" / "npm" / "demo-pkg@1.0.0.md").write_text("existing")
    res = prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None)
    assert res["status"] == "duplicate"
    assert (repo / "reports" / "npm" / "demo-pkg@1.0.0.md").read_text() == "existing"


def clone(name, version):
    pkg = {**NPM}
    pkg["package.json"] = json.dumps({"name": name, "version": version, "scripts": {
        "postinstall": "npm run setup", "setup": "node lib/install.js || true", "test": "jest"}})
    return pkg


def test_release_date_and_analysis_fields(repo):
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/2025-11-24-demo-pkg-v1.0.0.tgz", tgz(NPM)),
                          None, None, model="claude-test", registry=True)
    pkg = prepared(repo, res)["record"]["package"]
    # The registry is unreachable in tests, so the archive name's date is used.
    assert (pkg["released_at"], pkg["released_at_source"]) == ("2025-11-24", "dataset")
    assert (pkg["analysis_type"], pkg["model_name"]) == ("ai", "claude-test")
    res = prepare.prepare(sample(repo, "npm/plain.tgz", tgz({"package.json": '{"name": "p", "version": "1"}'})),
                          None, None)
    assert prepared(repo, res)["package"]["released_at"] is None


def test_skip_written_by_prepare_carries_release_date(repo):
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/2024-02-03-broken-v1.tgz", b"not an archive"),
                          None, None)
    rec = json.loads((repo / res["record"]).read_text())
    assert rec["schema_version"] == "3.2" and rec["package"]["released_at"] == "2024-02-03"
    assert rec["package"]["analysis_type"] == "tool" and "model_name" not in rec["package"]


def test_skeleton_has_cluster_key(repo):
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/a.tgz", tgz(NPM)), None, None)
    rec = prepared(repo, res)["record"]
    assert len(rec["package"]["cluster_key"]) == 64


def test_identical_payload_groups_as_one_campaign(repo, monkeypatch, capsys):
    # Same install files and commands, different package name: second is a member of the first.
    sample(repo, "datadog/npm/malicious_intent/one.tgz", tgz(clone("pkg-one", "1.0.0")))
    sample(repo, "datadog/npm/malicious_intent/two.tgz", tgz(clone("pkg-two", "2.0.0")))
    monkeypatch.setattr("sys.argv", ["prepare.py", str(repo / "samples"), "--batch"])
    prepare.main()
    members = list((repo / "reports" / "_members").glob("*.json"))
    assert len(members) == 1
    member = json.loads(members[0].read_text())
    assert member["record_type"] == "member" and member["package"]["name"] == "pkg-two"
    rep_record = json.loads((repo / "scratch" / "npm__pkg-one@1.0.0" / "record.json").read_text())
    assert member["package"]["cluster_key"] == rep_record["package"]["cluster_key"]
    queue = [json.loads(line) for line in (repo / "scratch" / "queue.jsonl").read_text().splitlines()]
    assert [q["key"] for q in queue if q["status"] == "analyse"] == ["npm__pkg-one@1.0.0"]


def test_member_of_an_existing_report(repo, monkeypatch):
    # An analysed report already on disk; a new package with the same payload becomes its member.
    first = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/one.tgz", tgz(clone("pkg-one", "1.0.0"))),
                            None, None)
    ck = prepared(repo, first)["record"]["package"]["cluster_key"]
    (repo / "reports" / "npm").mkdir(parents=True, exist_ok=True)
    (repo / "reports" / "npm" / "pkg-one@1.0.0.md").write_text(
        "```json\n" + json.dumps({"package": {"ecosystem": "npm", "name": "pkg-one", "version": "1.0.0",
                                              "cluster_key": ck}}) + "\n```\n")
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/two.tgz", tgz(clone("pkg-two", "2.0.0"))),
                          None, None)
    assert res["status"] == "member" and res["representative"] == "npm:pkg-one@1.0.0"


def loader(name="loader", version="1.0.0", payload="if (process.env.CI) require('https').get('https://x.example/');\n"):
    # A launcher that hands a joined path to a runtime held in a variable, so no import reaches the payload.
    return {
        "package.json": json.dumps({"name": name, "version": version, "scripts": {"preinstall": "node setup.js"}}),
        "setup.js": "const { spawn } = require('child_process');\n"
                    "const path = require('path');\n"
                    "const runtime = process.argv0;\n"
                    "const script = path.join(__dirname, 'payload.js');\n"
                    "spawn(runtime, [script], { stdio: 'ignore' });\n",
        "payload.js": payload,
    }


def test_launch_target_named_by_path_is_flagged_not_walked(repo):
    p = prepared(repo, prepare.prepare(sample(repo, "npm/loader.tgz", tgz(loader())), None, None))
    assert p["hints"]["not_chained"] == [{"file": "payload.js", "kind": "js", "bytes": len(loader()["payload.js"]),
                                          "named_at": ["setup.js:4"], "hooks": ["preinstall"]}]
    rec = p["record"]
    assert rec["execution"]["entry_points"][0]["file_chain"] == ["setup.js"]
    assert [u["file"] for u in rec["obfuscation"]["unrecovered"]] == ["payload.js"]
    assert any(n.startswith("possible launch target not chained: payload.js") for n in rec["execution"]["notes"])
    assert not any(s.startswith("payload.js") for c in rec["conditions"] for s in c["sites"])
    assert "unrecovered code" in prepare.contract.review_triggers(rec)


def test_launch_target_content_is_in_cluster_key(repo):
    seen = {}
    one = prepare.prepare(sample(repo, "npm/one.tgz", tgz(loader("one"))), None, None, seen)
    two = prepare.prepare(sample(repo, "npm/two.tgz", tgz(loader("two", payload="other();\n"))), None, None, seen)
    three = prepare.prepare(sample(repo, "npm/three.tgz", tgz(loader("three"))), None, None, seen)
    assert one["status"] == two["status"] == "analyse"
    assert prepared(repo, one)["package"]["cluster_key"] != prepared(repo, two)["package"]["cluster_key"]
    assert three["status"] == "member" and three["representative"] == "npm:one@1.0.0"


def test_chained_self_named_and_data_files_are_not_flagged(repo):
    files = {
        "package.json": json.dumps({"name": "quiet", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}),
        "setup.js": "const cp = require('child_process');\n"
                    "require('./lib/a');\n"
                    "cp.fork('worker.js');\n"
                    "cp.exec('echo setup.js');\n"
                    "const names = ['config.json', 'README.md', '/etc/passwd', '../../x.js', 'missing.js'];\n",
        "lib/a.js": "a();\n", "worker.js": "w();\n", "config.json": "{}", "README.md": "# readme\n",
    }
    p = prepared(repo, prepare.prepare(sample(repo, "npm/quiet.tgz", tgz(files)), None, None))
    assert p["hints"]["not_chained"] == [] and p["record"]["obfuscation"]["unrecovered"] == []


def test_no_process_start_means_no_flag(repo):
    files = {**loader(), "setup.js": "const path = require('path');\nconsole.log(path.join(__dirname, 'payload.js'));\n"}
    p = prepared(repo, prepare.prepare(sample(repo, "npm/noexec.tgz", tgz(files)), None, None))
    assert p["hints"]["not_chained"] == []


def test_command_string_in_inline_code_names_a_script(repo):
    pkg = {"package.json": json.dumps({"name": "inl", "version": "1.0.0", "scripts": {
        "preinstall": "node -e \"require('child_process').execSync('bash hidden/run.sh')\""}}),
        "hidden/run.sh": "#!/bin/sh\necho hi\n"}
    p = prepared(repo, prepare.prepare(sample(repo, "npm/inl.tgz", tgz(pkg)), None, None))
    assert [(x["file"], x["kind"], x["named_at"]) for x in p["hints"]["not_chained"]] == \
        [("hidden/run.sh", "sh", ["<preinstall -e>:1"])]


def test_setup_py_launch_target_and_read_only_literal(repo):
    files = {
        "PKG-INFO": "Name: pyloader\nVersion: 0.1\n",
        "setup.py": "import os, subprocess, sys\n"
                    "from setuptools import setup\n"
                    "version = open('pkg/version.py').read()\n"
                    "here = os.path.dirname(__file__)\n"
                    "subprocess.Popen([sys.executable, os.path.join(here, 'helper.py')])\n"
                    "setup(name='pyloader', version='0.1')\n",
        "helper.py": "import os\nif os.name == 'nt':\n    os.system('calc')\n",
        "pkg/version.py": "VERSION = '0.1'\n", "pkg/__init__.py": "",
    }
    p = prepared(repo, prepare.prepare(sample(repo, "pypi/pyloader-0.1.tar.gz", tgz(files, "pyloader-0.1/")),
                                       None, None))
    assert [(x["file"], x["named_at"], x["hooks"]) for x in p["hints"]["not_chained"]] == \
        [("helper.py", ["setup.py:5"], ["setup_py"])]


def test_cluster_key_unchanged_without_launch_targets(repo):
    import hashlib
    import textwrap
    res = prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None)
    files = sorted(hashlib.sha256(textwrap.dedent(NPM[f]).encode()).hexdigest()
                   for f in ("lib/install.js", "lib/util.js"))
    blob = json.dumps({"files": files, "commands": ["npm run setup"]}, sort_keys=True)
    assert prepared(repo, res)["package"]["cluster_key"] == hashlib.sha256(blob.encode()).hexdigest()


def test_batch_writes_queue(repo, monkeypatch, capsys):
    sample(repo, "npm/a.tgz", tgz(NPM))
    sample(repo, "npm/b.tgz", tgz({"package.json": json.dumps({"name": "b", "version": "1.0.0"})}))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes.txt", "x")
    sample(repo, "npm/c.zip", buf.getvalue())
    monkeypatch.setattr("sys.argv", ["prepare.py", str(repo / "samples"), "--batch"])
    prepare.main()
    queue = [json.loads(line) for line in (repo / "scratch" / "queue.jsonl").read_text().splitlines()]
    assert sorted((q["key"], q["status"]) for q in queue) == [("npm__b@1.0.0", "needs_skip_reason"),
                                                              ("npm__demo-pkg@1.0.0", "analyse")]
    assert "3 samples" in capsys.readouterr().out


def test_launched_file_is_recovered_and_walked_but_not_prefilled(repo):
    from tools.tests.obfio import obfuscate
    worm = obfuscate({"os": "os", "p": "platform", "w": "win32", "h": "https", "u": "https://evil.example/x"},
                     "const os=require({os});\nif(os[{p}]()==={w}){{require({h}).get({u});}}\n")
    pkg = {"package.json": json.dumps({"name": "launch", "version": "1.0.0",
                                       "scripts": {"preinstall": "node setup.js"}}),
           "setup.js": "const cp = require('child_process');\nconst rt = process.env.RT || 'bun';\n"
                       "cp.spawn(rt, ['worm.js'], {detached: true});\n",
           "worm.js": worm}
    res = prepare.prepare(sample(repo, "npm/launch.tgz", tgz(pkg)), None, None)
    p = prepared(repo, res)
    assert [i["file"] for i in p["hints"]["not_chained"]] == ["worm.js"]
    (d,) = p["record"]["normalisation"]["derivations"]
    assert d["recipe"] == "obfuscatorio_strings" and d["input"]["file"] == "worm.js"
    worm_conds = [c for c in p["candidates"]["conditions"] if c["sites"][0]["anchor"]["file"] == "worm.js"]
    assert [(c["category"], c["value"], c["reached"]) for c in worm_conds] == [("os", "win32", False)]
    assert all(c["sites"][0]["anchor"]["file"] != "worm.js" for c in p["record"]["conditions"])


def test_two_inline_scripts_in_one_hook_are_both_analysed_and_rebuilt(repo):
    from tools.common import hooks
    cmd = ("node -e \"if (process.platform === 'win32') require('child_process').exec('a')\" && "
           "node -e \"if (process.arch === 'arm64') require('child_process').exec('b')\"")
    pkg = {"package.json": json.dumps({"name": "two-e", "version": "1.0.0", "scripts": {"preinstall": cmd}})}
    res = prepare.prepare(sample(repo, "npm/two-e.tgz", tgz(pkg)), None, None)
    rec = prepared(repo, res)["record"]
    assert {c["category"] for c in rec["conditions"]} == {"os", "arch"}
    ds = rec["normalisation"]["derivations"]
    assert sorted(d["params"]["flag"] for d in ds) == ["-e", "-e #2"]
    root = repo / "scratch" / res["key"] / "unpacked" / rec["package"]["package_root"]
    manifest = json.loads((root / "package.json").read_text())
    assert "arm64" in hooks.inline_code(manifest, root, "preinstall", "-e #2")


def test_manifest_gate_id_is_unique_when_candidate_gates_are_left_out(repo):
    files = {"package.json": json.dumps({"name": "m", "version": "1.0.0", "os": ["linux"],
                                         "scripts": {"postinstall": "node index.js"}}),
             "index.js": "function never() { if (process.env.CI) require('child_process').exec('a'); }\n"
                         "if (process.platform === 'linux') require('child_process').exec('b');\n"}
    rec = prepared(repo, prepare.prepare(sample(repo, "npm/m.tgz", tgz(files)), None, None))["record"]
    ids = [g["gate_id"] for g in rec["gates"]]
    assert len(ids) == len(set(ids)) and any(g["hook"] == "resolve" for g in rec["gates"])


def test_record_carries_a_units_summary_truncation_and_an_empty_dropped_list(repo):
    prep = prepared(repo, prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None))
    n = prep["record"]["normalisation"]
    assert "units" not in n and n["units_summary"] == [] and n["truncation"] == {"walk_limit": False,
                                                                                 "context_limited_files": 0}
    assert prep["record"]["candidate_review"] == {"dropped": []}
    assert prep["truncation"]["walk_limit"] is False and prep["units"] == []


def test_truncation_is_noted(repo, monkeypatch):
    from tools.analysis import gate_extract
    monkeypatch.setattr(gate_extract, "MAX_WALKS", 0)
    prep = prepared(repo, prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None))
    assert prep["truncation"]["walk_limit"] is True
    assert any(n.startswith("generator truncated: walk budget") for n in prep["record"]["execution"]["notes"])


def test_generator_id_names_the_generator_source(monkeypatch, tmp_path):
    from tools.common import paths
    gid = prepare.generator_id()
    assert gid.startswith("gate_extract@") and len(gid) == len("gate_extract@") + 10
    fake = tmp_path / "tools"
    (fake / "analysis").mkdir(parents=True)
    (fake / "common").mkdir()
    (fake / "analysis" / "gate_extract.py").write_text("changed")
    monkeypatch.setattr(paths, "CODE_ROOT", tmp_path)
    assert prepare.generator_id() != gid


def test_unknown_bundle_gates_near_the_entry_are_prefilled():
    gates = [{"gate_id": f"g{i}", "reached": True, "role": role, "unit_depth": depth,
              "then": {"sinks": sinks}, "else": None}
             for i, (role, depth, sinks) in enumerate([("package", 0, []), ("unknown", 2, ["exec"]),
                                                       ("unknown", 1, ["network"]), ("unknown", None, ["exec"]),
                                                       ("unknown", 1, []), ("library", 0, ["exec"])], start=1)]
    assert [g["gate_id"] for g in prepare.prefilled_gates(gates)] == ["g1", "g2", "g3"]
