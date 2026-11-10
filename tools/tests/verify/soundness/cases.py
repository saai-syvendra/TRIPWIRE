"""
The soundness corpus: one small synthetic package per construct, with claims about it.

Each case returns (package, record, want, false_claims):
  want          claim id -> the verdict the checker should reach (pinned so it cannot pass by deciding nothing);
                "open" means the claim is true but the checker is not expected to decide it.
  false_claims  claim ids in the record that are false: they must never come out verified.
Every other claim in the record is true and must never come out refuted. Mutants of true records are generated
by harness.mutants.

Snippets are inert: placeholder commands ('x'), reserved hosts (example.invalid), no real behaviour.
"""
from __future__ import annotations

from tools.tests.verify.soundness.harness import (MemPackage, at, branch, cond, enclosing, gate, guard, hop, payload,
                                                  record, stmts)

CASES = {}


def case(fn):
    CASES[fn.__name__] = fn
    return fn


def simple_if(pkg, test, sink, c, kind="if", arm="then", expr="c1", behaviour="spawn_process", sink_kind="exec"):
    """One guard over one block holding one sink, no witness hops."""
    g = gate([guard(enclosing(pkg, test, "if_statement"), kind, arm)], expr,
             branch([enclosing(pkg, sink, "statement_block")],
                    [payload(at(pkg, sink), behaviour, sink_kind)]))
    return record(c, [g])


@case
def direct_if():
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        if (os.platform() === 'linux') {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "os.platform() === 'linux'", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, "os.platform() === 'linux'")])])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified", "g1.L4": "verified",
                      "g1.then.L5": "verified", "g1.then.L3.excl": "verified"}, []


@case
def early_exit_negated():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.platform !== 'win32') process.exit(0);
        cp.exec('x');
    """})
    test = "process.platform !== 'win32'"
    g = gate([guard(enclosing(pkg, test, "if_statement"), "early_exit", "else")], "c1",
             branch([stmts(pkg, "cp.exec('x')")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.platform", "==", "win32", [at(pkg, test)])], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified", "g1.L4": "verified",
                      "g1.then.L5": "verified"}, []


@case
def string_method_any_receiver():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function getToken() { return process.env.TOKEN_X || ''; }
        const t = getToken();
        if (t.startsWith('abc_')) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "t.startsWith('abc_')", "cp.exec('x')",
                    [cond("c1", "String.startsWith", "startswith", "abc_", [at(pkg, "t.startsWith('abc_')")],
                          category="env_var")])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified"}, []


@case
def webpack_module_ids():
    pkg = MemPackage({"b.js": """
        (() => {
          var m = {
            101: (e, t, n) => { e.exports = require("os"); },
            202: (e, t, n) => {
              const F = n(101);
              const C = n(303);
              if ("linux" === F.platform()) {
                C.exec("x");
              }
            },
            303: (e, t, n) => { e.exports = require("child_process"); },
          };
          var c = {};
          function n(i) { var o = c[i]; if (o !== undefined) return o.exports; var r = c[i] = { exports: {} }; m[i](r, r.exports, n); return r.exports; }
          n(202);
        })();
    """})
    rec = simple_if(pkg, '"linux" === F.platform()', 'C.exec("x")',
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, '"linux" === F.platform()')])])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified",
                      "g1.then.L5": "verified"}, []


@case
def value_through_variable_then_tested():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function getToken() {
          const t = process.env.GH_X;
          if (t) return t;
          return null;
        }
        if (getToken()) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "if (getToken())", "cp.exec('x')",
                    [cond("c1", "process.env.GH_X", "truthy", None, [at(pkg, "process.env.GH_X")],
                          category="env_var")])
    return pkg, rec, {"c1.L1": "verified"}, []


@case
def hoisted_one_line_helper():
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        if (isLinux()) {
          cp.exec('x');
        }
        function isLinux() { return 'linux' === os.platform(); }
    """})
    rec = simple_if(pkg, "isLinux()", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, "'linux' === os.platform()")])])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified", "g1.L4": "verified"}, []


@case
def destructured_sibling_is_not_the_api():
    pkg = MemPackage({"i.js": """
        const { platform, homedir } = require('os');
        const cp = require('child_process');
        if (homedir() === '/root') {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "homedir() === '/root'", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "/root", [at(pkg, "homedir() === '/root'")])])
    return pkg, rec, {"c1.L1": "refuted"}, ["c1.L1"]


@case
def comment_does_not_name_the_api():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.HOME /* CI */ === 'x') {
          cp.exec('x');
        }
    """})
    site = "process.env.HOME /* CI */ === 'x'"
    rec = simple_if(pkg, site, "cp.exec('x')",
                    [cond("c1", "process.env.CI", "==", "x", [at(pkg, site)], category="ci_marker")])
    return pkg, rec, {"c1.L1": "refuted"}, ["c1.L1"]


@case
def value_is_not_a_substring_match():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.LANG === 'true') {
          cp.exec('x');
        }
    """})
    site = "process.env.LANG === 'true'"
    rec = simple_if(pkg, site, "cp.exec('x')",
                    [cond("c1", "process.env.LANG", "==", "ru", [at(pkg, site)], category="locale_language")])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "refuted"}, ["c1.L2"]


@case
def index_of_means_includes():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.LANG.indexOf('ru') !== -1) {
          cp.exec('x');
        }
    """})
    site = "process.env.LANG.indexOf('ru') !== -1"
    rec = simple_if(pkg, site, "cp.exec('x')",
                    [cond("c1", "process.env.LANG", "includes", "ru", [at(pkg, site)], category="locale_language")])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified"}, []


@case
def typeof_means_exists():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (typeof Bun !== 'undefined') {
          cp.exec('x');
        }
    """})
    site = "typeof Bun !== 'undefined'"
    rec = simple_if(pkg, site, "cp.exec('x')",
                    [cond("c1", "Bun", "exists", None, [at(pkg, site)], category="runtime_version")])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified"}, []


@case
def regex_is_not_includes():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        const line = process.env.RC_LINE || '';
        if (/_authToken=(\\w+)/.test(line)) {
          cp.exec('x');
        }
    """})
    site = "/_authToken=(\\w+)/.test(line)"
    rec = simple_if(pkg, site, "cp.exec('x')",
                    [cond("c1", "RegExp.test", "includes", "_authToken", [at(pkg, site)], category="env_var")])
    # regex and includes are both positive membership tests, not equivalent and not contradictory: the honest
    # verdict is cannot_tell, never verified
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "cannot_tell"}, ["c1.L2"]


@case
def bare_declaration_does_not_crash():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        let r;
        r = process.env.USER_X;
        if (process.env.CI && r) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "process.env.CI && r", "cp.exec('x')",
                    [cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI", nth=0)],
                          category="ci_marker"),
                     cond("c2", "process.env.USER_X", "truthy", None, [at(pkg, "process.env.USER_X")],
                          category="env_var")], expr="c1 && c2")
    rec["gates"][0]["guards"][0]["conditions"] = ["c1", "c2"]
    rec["gates"][0]["then"]["min_conditions"] = 2
    return pkg, rec, {"c1.L1": "verified", "c2.L1": "verified"}, []


@case
def python_elif_else():
    pkg = MemPackage({"setup.py": """
        import sys, subprocess
        if sys.platform == 'win32':
            pass
        elif sys.platform == 'darwin':
            pass
        else:
            subprocess.run(['x'])
    """})
    g = gate([guard(enclosing(pkg, "sys.platform == 'win32'", "if_statement"), "if", "else", ["c1"]),
              guard(enclosing(pkg, "sys.platform == 'darwin'", "elif_clause"), "elif", "else", ["c2"])],
             "c1 && c2", branch([enclosing(pkg, "subprocess.run(['x'])", "block")],
                                [payload(at(pkg, "subprocess.run(['x'])"))], min_conditions=2))
    rec = record([cond("c1", "sys.platform", "!=", "win32", [at(pkg, "sys.platform == 'win32'")]),
                  cond("c2", "sys.platform", "!=", "darwin", [at(pkg, "sys.platform == 'darwin'")])], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "c2.L2": "verified", "g1.then.L3": "verified",
                      "g1.L4": "verified", "g1.then.L5": "verified"}, []


@case
def short_circuit_exit():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        process.platform === 'linux' || process.exit(0);
        cp.exec('x');
    """})
    test = "process.platform === 'linux'"
    g = gate([guard(at(pkg, "process.platform === 'linux' || process.exit(0)"), "short_circuit", "then")], "c1",
             branch([stmts(pkg, "cp.exec('x')")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.platform", "==", "linux", [at(pkg, test)])], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified"}, []


@case
def switch_on_discriminant():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        switch (process.platform) {
          case 'win32':
            cp.exec('x');
            break;
          default:
            break;
        }
    """})
    g = gate([guard(enclosing(pkg, "case 'win32'", "switch_case"), "switch_case", "then")], "c1",
             branch([enclosing(pkg, "case 'win32'", "switch_case")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.platform", "==", "win32", [at(pkg, "process.platform")])], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "g1.then.L3": "verified"}, []


@case
def hoisted_function_runs_before_the_guard():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function m() {
          run();
          if (!process.env.CI) return;
          function run() { cp.exec('x'); }
        }
        m();
    """})
    g = gate([guard(enclosing(pkg, "!process.env.CI", "if_statement"), "early_exit", "else")], "c1",
             branch([stmts(pkg, "function run()")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"c1.L1": "verified"}, ["g1.then.L3", "g1.then.L3.excl"]


@case
def call_tied_by_name_only():
    pkg = MemPackage({"i.js": """
        const https = require('https');
        class Sender { send() { https.get('https://example.invalid/'); } }
        if (process.env.CI) {
          process.send(1);
        }
    """})
    sink = "https.get('https://example.invalid/')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "process.send(1)", "statement_block")],
                    [payload(at(pkg, sink), "exfil", "network",
                             [hop("call", at(pkg, "process.send(1)")),
                              hop("def", enclosing(pkg, sink, "method_definition"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"c1.L1": "verified"}, ["g1.then.L3"]


@case
def call_tied_by_receiver_class():
    pkg = MemPackage({"i.js": """
        const https = require('https');
        class Sender { send() { https.get('https://example.invalid/'); } }
        const s = new Sender();
        if (process.env.CI) {
          s.send();
        }
    """})
    sink = "https.get('https://example.invalid/')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "s.send()", "statement_block")],
                    [payload(at(pkg, sink), "exfil", "network",
                             [hop("call", at(pkg, "s.send()")),
                              hop("def", enclosing(pkg, sink, "method_definition"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"c1.L1": "verified", "g1.then.L3": "verified", "g1.then.L5": "verified"}, []


@case
def wrapper_sink_kind():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        const api = { update(p) { return cp.exec('x ' + p); } };
        if (process.env.CI) {
          api.update('y');
        }
    """})
    rec = simple_if(pkg, "process.env.CI", "api.update('y')",
                    [cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")])
    return pkg, rec, {"c1.L1": "verified", "g1.then.L3": "verified"}, []


@case
def payload_also_called_outside():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function go() { cp.exec('x'); }
        if (process.env.CI) {
          go();
        }
        go();
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "go();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=1)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified", "g1.then.L3.excl": "refuted"}, ["g1.then.L3.excl"]


@case
def exported_payload_is_not_exclusive():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function go() { cp.exec('x'); }
        exports.go = go;
        if (process.env.CI) {
          go();
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "go();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=1)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified"}, ["g1.then.L3.excl"]


@case
def nested_uncalled_function_is_not_reached():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.CI) {
          const later = function () { cp.exec('x'); };
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "const later", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("def", enclosing(pkg, sink, "function_expression"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {}, ["g1.then.L3"]


# --- overclaim audit (2026-10-20): shapes where the checker once verified or refuted without proof ------------

@case
def python_with_before_guards():
    # a `with` block early in a setup.py once stopped the CFG walk, so the later `if` was not seen as a guard and
    # L4 refuted a true `c1 && c2`
    pkg = MemPackage({"setup.py": """
        import os, sys, subprocess
        with open('x.txt') as f:
            data = f.read()
        if sys.version_info < (3, 7):
            sys.exit(1)
        if os.name == 'nt':
            subprocess.Popen('x')
    """})
    g = gate([guard(enclosing(pkg, "sys.version_info < (3, 7)", "if_statement"), "early_exit", "else", ["c1"]),
              guard(enclosing(pkg, "os.name == 'nt'", "if_statement"), "if", "then", ["c2"])],
             "c1 && c2", branch([enclosing(pkg, "subprocess.Popen('x')", "block")],
                                [payload(at(pkg, "subprocess.Popen('x')"))], min_conditions=2))
    rec = record([cond("c1", "sys.version_info", ">=", [3, 7], [at(pkg, "sys.version_info < (3, 7)")],
                       category="runtime_version"),
                  cond("c2", "os.name", "==", "nt", [at(pkg, "os.name == 'nt'")])], [g])
    return pkg, rec, {"c2.L1": "verified", "c2.L2": "verified", "g1.then.L3": "verified", "g1.L4": "verified"}, []


@case
def else_region_inside_outer_then():
    # the else block of the inner test runs only when the outer test holds, so the outer guard controls no region
    # on the else side: `g1.else` (gate fails -> y) is false
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.CI) {
          if (process.platform === 'linux') {
            cp.exec('x');
          } else {
            cp.exec('y');
          }
        }
    """})
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"), "if", "then", ["c1"]),
              guard(enclosing(pkg, "process.platform === 'linux'", "if_statement"), "if", "then", ["c2"])],
             "c1 && c2", branch([enclosing(pkg, "cp.exec('x')", "statement_block")],
                                [payload(at(pkg, "cp.exec('x')"))], min_conditions=2),
             else_=branch([enclosing(pkg, "cp.exec('y')", "statement_block")], [payload(at(pkg, "cp.exec('y')"))]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker"),
                  cond("c2", "process.platform", "==", "linux", [at(pkg, "process.platform === 'linux'")])], [g])
    return pkg, rec, {"g1.then.L3": "verified", "g1.L4": "verified", "g1.else.L3": "refuted"}, ["g1.else.L3"]


@case
def eval_sink_is_open():
    # a decoded payload run through exec() can do anything: its sink kind never contradicts a behaviour
    pkg = MemPackage({"setup.py": """
        import os, base64
        if os.name == 'nt':
            exec(base64.b64decode('eA=='))
    """})
    g = gate([guard(enclosing(pkg, "os.name == 'nt'", "if_statement"))], "c1",
             branch([enclosing(pkg, "exec(base64", "block")],
                    [payload(at(pkg, "exec(base64.b64decode('eA=='))"), "write_file", "eval")]))
    rec = record([cond("c1", "os.name", "==", "nt", [at(pkg, "os.name == 'nt'")])], [g])
    return pkg, rec, {"g1.then.L3": "verified", "g1.then.L5": "open"}, []


@case
def redacted_username_value():
    pkg = MemPackage({"setup.py": """
        import os, subprocess
        if os.getlogin() != 'somehandle':
            subprocess.run(['x'])
    """})
    g = gate([guard(enclosing(pkg, "os.getlogin() != 'somehandle'", "if_statement"))], "c1",
             branch([enclosing(pkg, "subprocess.run(['x'])", "block")], [payload(at(pkg, "subprocess.run(['x'])"))]))
    rec = record([cond("c1", "os.getlogin()", "!=", "<author handle, redacted>",
                       [at(pkg, "os.getlogin() != 'somehandle'")], category="username")], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "cannot_tell"}, []


@case
def switch_second_case_and_default():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        switch (process.platform) {
          case 'darwin':
            break;
          case 'win32':
            cp.exec('x');
            break;
          default:
            cp.exec('y');
        }
    """})
    g1 = gate([guard(enclosing(pkg, "case 'win32'", "switch_case"), "switch_case", "then")], "c1",
              branch([enclosing(pkg, "case 'win32'", "switch_case")], [payload(at(pkg, "cp.exec('x')"))]))
    g2 = gate([guard(enclosing(pkg, "default:", "switch_default"), "switch_default", "then", ["c2"])], "c2",
              branch([enclosing(pkg, "default:", "switch_default")], [payload(at(pkg, "cp.exec('y')"))]), gid="g2")
    rec = record([cond("c1", "process.platform", "==", "win32", [at(pkg, "process.platform")]),
                  cond("c2", "process.platform", "not_in", ["darwin", "win32"], [at(pkg, "process.platform")])],
                 [g1, g2])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "verified", "c2.L2": "open"}, []


@case
def api_inside_unknown_predicate():
    # the API is an argument of a helper the checker cannot see into: neither the operator nor the API's role is
    # proven, and nothing is contradicted
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        const check = require('./check');
        if (check(process.platform)) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "check(process.platform)", "cp.exec('x')",
                    [cond("c1", "process.platform", "!=", "win32", [at(pkg, "check(process.platform)")])])
    return pkg, rec, {"c1.L2": "open"}, []


@case
def api_as_argument_of_a_test_call():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        const os = require('os');
        if (['linux', 'darwin'].includes(os.platform())) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "['linux', 'darwin'].includes(os.platform())", "cp.exec('x')",
                    [cond("c1", "os.platform()", "in", ["linux", "darwin"],
                          [at(pkg, "['linux', 'darwin'].includes(os.platform())")])])
    return pkg, rec, {"c1.L1": "verified"}, []


@case
def value_handed_to_a_function():
    # the cited site passes the value on; whether the callee tests it is not visible, so L1 is not refuted
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const decide = require('./decide');
        decide(os.platform());
    """})
    rec = record([cond("c1", "os.platform()", "==", "linux", [at(pkg, "os.platform()")])], [])
    return pkg, rec, {"c1.L1": "open"}, []


@case
def regexp_exec_is_not_the_probe():
    pkg = MemPackage({"i.js": """
        const s = process.argv[2] || '';
        if (/x/.exec(s)) {
          console.log(1);
        }
    """})
    rec = record([cond("c1", "child_process.exec", "exists", None, [at(pkg, "/x/.exec(s)")], category="tool_present",
                       probe={"kind": "exec", "callee": "child_process.exec", "target": None, "accessor": None})], [])
    return pkg, rec, {}, ["c1.L1"]


@case
def early_exit_then_nested_function_region():
    # the region is a function defined after the exit and called there; the exit still guards it
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function main() {
          if (process.platform !== 'linux') return;
          const run = () => {
            cp.exec('x');
          };
          run();
        }
        main();
    """})
    test = "process.platform !== 'linux'"
    g = gate([guard(enclosing(pkg, test, "if_statement"), "early_exit", "else")], "c1",
             branch([enclosing(pkg, "cp.exec('x')", "statement_block")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.platform", "==", "linux", [at(pkg, test)])], [g])
    return pkg, rec, {"c1.L2": "verified"}, []


@case
def version_mirrored_compare():
    pkg = MemPackage({"setup.py": """
        import sys, subprocess
        if (3, 7) <= sys.version_info:
            subprocess.run(['x'])
    """})
    rec = record([cond("c1", "sys.version_info", ">=", [3, 7], [at(pkg, "(3, 7) <= sys.version_info")],
                       category="runtime_version")], [])
    return pkg, rec, {"c1.L1": "verified"}, []


@case
def inherited_method_is_not_refuted():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        class Base { send() { cp.exec('x'); } }
        class Sub extends Base {}
        const s = new Sub();
        if (process.env.CI) {
          s.send();
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "s.send();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "s.send()")),
                                                     hop("def", enclosing(pkg, sink, "method_definition"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "open"}, []


@case
def esm_exported_payload_is_not_exclusive():
    pkg = MemPackage({"i.mjs": """
        import { exec } from 'child_process';
        export function go() { exec('x'); }
        if (process.env.CI) {
          go();
        }
    """})
    sink = "exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "go();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=1)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {}, ["g1.then.L3.excl"]


@case
def payload_named_in_another_file_is_not_exclusive():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function go() { cp.exec('x'); }
        if (process.env.CI) {
          go();
        }
    """, "other.js": """
        // may reach go through some loader the checker does not parse
        global.go && global.go();
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "go();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=1)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified"}, ["g1.then.L3.excl"]


@case
def payload_also_called_inside_another_function_is_held_open():
    # the second call sits in a function that may itself only run behind the gate: not proof of a way around it
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function go() { cp.exec('x'); }
        function retry() { go(); }
        if (process.env.CI) {
          go();
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "go();", "statement_block", nth=1)],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=2)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified", "g1.then.L3.excl": "cannot_tell"}, []


@case
def awaited_sink_is_a_call():
    pkg = MemPackage({"i.mjs": """
        import { exec } from 'child_process';
        async function main() {
          if (process.env.CI) {
            await exec('x');
          }
        }
        main();
    """})
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "await exec('x')", "statement_block")],
                    [payload(at(pkg, "await exec('x')"))]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified"}, []


@case
def merged_condition_over_two_sites():
    # one condition merged from two tests of different values: each site compares against one claimed value
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.platform === 'linux') { cp.exec('x'); }
        if (process.platform === 'darwin') { cp.exec('y'); }
    """})
    g = gate([guard(enclosing(pkg, "process.platform === 'linux'", "if_statement")),
              guard(enclosing(pkg, "process.platform === 'darwin'", "if_statement"))], "c1",
             branch([enclosing(pkg, "cp.exec('x')", "statement_block"), enclosing(pkg, "cp.exec('y')", "statement_block")],
                    [payload(at(pkg, "cp.exec('x')")), payload(at(pkg, "cp.exec('y')"))]))
    rec = record([cond("c1", "process.platform", "in", ["linux", "darwin"],
                       [at(pkg, "process.platform === 'linux'"), at(pkg, "process.platform === 'darwin'")])], [g])
    return pkg, rec, {"c1.L1": "verified", "g1.then.L3": "verified"}, []


@case
def wrapper_found_only_by_name_is_not_refuted():
    pkg = MemPackage({"i.js": """
        const https = require('https');
        const lib = require('./lib');
        function send() { https.get('https://example.invalid/'); }
        if (process.env.CI) {
          lib.send();
        }
    """})
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "lib.send();", "statement_block")],
                    [payload(at(pkg, "lib.send()"), "spawn_process", "exec")]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L5": "open"}, []


@case
def else_requires_the_outer_guard():
    # the same shape as else_region_inside_outer_then, recorded with else.requires: the else side keeps c1
    pkg, rec, _, _ = CASES["else_region_inside_outer_then"]()
    rec["gates"][0]["else"]["requires"] = ["c1"]
    rec["gates"][0]["else"]["min_conditions"] = 2
    return pkg, rec, {"g1.then.L3": "verified", "g1.else.L3": "verified"}, []


# --- second review (2026-10-20) ------------------------------------------------------------------------------

@case
def else_if_exit_does_not_guard_the_code_after():
    # the exit sits in an else-if arm: code after the whole if runs whenever A holds, so B guards nothing there
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (process.env.A) {
          console.log(1);
        } else if (process.platform !== 'linux') {
          return;
        }
        cp.exec('x');
    """})
    test = "process.platform !== 'linux'"
    g = gate([guard(enclosing(pkg, test, "if_statement", nth=0), "early_exit", "else")], "c1",
             branch([stmts(pkg, "cp.exec('x')")], [payload(at(pkg, "cp.exec('x')"))]))
    rec = record([cond("c1", "process.platform", "==", "linux", [at(pkg, test)])], [g])
    return pkg, rec, {}, ["g1.then.L3"]


@case
def api_read_through_a_helper_result():
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        function get() { return os.platform(); }
        const p = get();
        if (p === 'linux') {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "p === 'linux'", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, "p === 'linux'")])])
    return pkg, rec, {"c1.L1": "open"}, []


@case
def api_read_through_a_local_module():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        if (require('./plat').get() === 'linux') {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "require('./plat').get() === 'linux'", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, "require('./plat').get() === 'linux'")])])
    return pkg, rec, {"c1.L1": "open"}, []


@case
def builtin_method_inside_a_member_helper():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        const utils = require('./utils');
        if (utils.isPrefixed(process.env.TOKEN_X)) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "utils.isPrefixed(process.env.TOKEN_X)", "cp.exec('x')",
                    [cond("c1", "String.startsWith", "startswith", "abc_",
                          [at(pkg, "utils.isPrefixed(process.env.TOKEN_X)")], category="env_var")])
    return pkg, rec, {"c1.L1": "open"}, []


@case
def ordered_compare_with_unknown_api_side():
    pkg = MemPackage({"i.js": """
        const count = require('./count');
        const n = count();
        if (n < 2) process.exit(0);
        require('child_process').exec('x');
    """})
    rec = record([cond("c1", "os.cpus().length", ">=", 2, [at(pkg, "n < 2")], category="hardware")], [])
    return pkg, rec, {"c1.L2": "open"}, []


@case
def value_from_an_unresolved_fallback():
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        const want = process.env.T || 'linux';
        if (os.platform() === want) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "os.platform() === want", "cp.exec('x')",
                    [cond("c1", "os.platform()", "==", "linux", [at(pkg, "os.platform() === want")])])
    return pkg, rec, {"c1.L2": "open"}, ["c1.L2"]


@case
def prototype_assigned_method_is_not_refuted():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        class Base { send() { cp.exec('x'); } }
        class Other {}
        Other.prototype.send = Base.prototype.send;
        const s = new Other();
        if (process.env.CI) {
          s.send();
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement"))], "c1",
             branch([enclosing(pkg, "s.send();", "statement_block")],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "s.send()")),
                                                     hop("def", enclosing(pkg, sink, "method_definition"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI")], category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "open"}, []


@case
def guarded_call_in_a_declaration_is_not_unguarded():
    pkg = MemPackage({"i.js": """
        const cp = require('child_process');
        function go() { cp.exec('x'); }
        const r = process.env.CI && go();
        if (process.env.CI) {
          go();
        }
    """})
    sink = "cp.exec('x')"
    g = gate([guard(enclosing(pkg, "process.env.CI", "if_statement", nth=1))], "c1",
             branch([enclosing(pkg, "go();", "statement_block", nth=1)],
                    [payload(at(pkg, sink), witness=[hop("call", at(pkg, "go()", nth=2)),
                                                     hop("def", enclosing(pkg, sink, "function_declaration"))])]))
    rec = record([cond("c1", "process.env.CI", "truthy", None, [at(pkg, "process.env.CI", nth=1)],
                       category="ci_marker")],
                 [g])
    return pkg, rec, {"g1.then.L3": "verified", "g1.then.L3.excl": "cannot_tell"}, []


# --- found on the redone batch (2026-10-20) ------------------------------------------------------------------

@case
def copying_a_credential_file_is_cred_read():
    pkg = MemPackage({"setup.py": """
        import os, shutil, base64
        if os.name == 'nt':
            shutil.copy2('Login Data', 'tmp.db')
            key = base64.b64decode('a2V5')
    """})
    g = gate([guard(enclosing(pkg, "os.name == 'nt'", "if_statement"))], "c1",
             branch([enclosing(pkg, "shutil.copy2", "block")],
                    [payload(at(pkg, "shutil.copy2('Login Data', 'tmp.db')"), "cred_read", "fs_read"),
                     payload(at(pkg, "base64.b64decode('a2V5')"), "cred_read", "other")]))
    rec = record([cond("c1", "os.name", "==", "nt", [at(pkg, "os.name == 'nt'")])], [g])
    return pkg, rec, {"g1.then.L5": "open"}, []


@case
def a_number_written_as_a_string():
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        if (os.cpus().length >= 4) {
          cp.exec('x');
        }
    """})
    rec = simple_if(pkg, "os.cpus().length >= 4", "cp.exec('x')",
                    [cond("c1", "os.cpus().length", ">=", "4", [at(pkg, "os.cpus().length >= 4")],
                          category="hardware")])
    return pkg, rec, {"c1.L2": "verified"}, []


@case
def helper_that_returns_false_on_the_test():
    # `if (cpus < 4) return false;` inside the helper flips the test with no `!`: the gate needs >= 4
    pkg = MemPackage({"i.js": """
        const os = require('os');
        const cp = require('child_process');
        function ok() {
          if (os.cpus().length < 4) return false;
          return true;
        }
        function main() {
          if (!ok()) return;
          cp.exec('x');
        }
        main();
    """})
    rec = record([cond("c1", "os.cpus().length", ">=", 4, [at(pkg, "os.cpus().length < 4")], category="hardware")],
                 [gate([guard(enclosing(pkg, "!ok()", "if_statement"), "early_exit", "else")], "c1",
                       branch([stmts(pkg, "cp.exec('x')")], [payload(at(pkg, "cp.exec('x')"))]))])
    return pkg, rec, {"c1.L2": "open"}, []


@case
def endswith_written_as_regex():
    # the operator list has no endswith: str.endswith('.lnk') is recorded as regex `\.lnk$`, which says the same
    pkg = MemPackage({"setup.py": """
        import subprocess
        for f in ['a']:
            if f.endswith('.lnk'):
                subprocess.run(['x'])
    """})
    g = gate([guard(enclosing(pkg, "f.endswith('.lnk')", "if_statement"))], "c1",
             branch([enclosing(pkg, "subprocess.run(['x'])", "block")], [payload(at(pkg, "subprocess.run(['x'])"))]))
    site = [at(pkg, "f.endswith('.lnk')")]
    rec = record([cond("c1", "str.endswith", "regex", r"\.lnk$", site, category="target_artifact"),
                  cond("c2", "str.endswith", "regex", r"^\.lnk", site, category="target_artifact")], [g])
    return pkg, rec, {"c1.L2": "verified"}, ["c2.L2"]


@case
def exists_compared_to_false():
    # `exists(p) == False` tests the path, not the constant False
    pkg = MemPackage({"setup.py": """
        import os, subprocess
        if os.path.exists('/tmp/x') == False:
            subprocess.run(['x'])
    """})
    test = "os.path.exists('/tmp/x') == False"
    g = gate([guard(enclosing(pkg, test, "if_statement"))], "c1",
             branch([enclosing(pkg, "subprocess.run(['x'])", "block")], [payload(at(pkg, "subprocess.run(['x'])"))]))
    rec = record([cond("c1", "os.path.exists", "not_exists", "/tmp/x", [at(pkg, test)],
                       category="file_or_dir_exists")], [g])
    return pkg, rec, {"c1.L1": "verified", "c1.L2": "open"}, []


@case
def bind_into_a_library_call():
    # the callback is handed to a library constructor (threading.Thread) that is not on the witness: the path
    # cannot be followed, which is a gap, not a contradiction
    pkg = MemPackage({"setup.py": """
        import os, subprocess, threading
        def work():
            subprocess.run(['x'])
        if os.name == 'nt':
            t = threading.Thread(target=work)
            t.start()
    """})
    g = gate([guard(enclosing(pkg, "os.name == 'nt'", "if_statement"))], "c1",
             branch([enclosing(pkg, "t = threading.Thread(target=work)", "block")],
                    [payload(at(pkg, "subprocess.run(['x'])"),
                             witness=[hop("bind", at(pkg, "target=work")),
                                      hop("def", enclosing(pkg, "def work", "function_definition"))])]))
    rec = record([cond("c1", "os.name", "==", "nt", [at(pkg, "os.name == 'nt'")])], [g])
    return pkg, rec, {"c1.L2": "verified", "g1.then.L3": "open"}, []


@case
def redacted_probe_target():
    # the record redacts an author handle in the probed path; the probe cannot be compared, which is not a mismatch
    pkg = MemPackage({"setup.py": """
        import os, subprocess
        if os.path.exists('hifromsomehandle'):
            exit(0)
        subprocess.run(['x'])
    """})
    test = "os.path.exists('hifromsomehandle')"
    g = gate([guard(enclosing(pkg, test, "if_statement"), "early_exit", "else")], "c1",
             branch([stmts(pkg, "subprocess.run(['x'])")], [payload(at(pkg, "subprocess.run(['x'])"))]))
    rec = record([cond("c1", "os.path.exists", "not_exists", "hifrom<author handle, redacted>", [at(pkg, test)],
                       category="file_or_dir_exists",
                       probe={"kind": "file", "callee": "os.path.exists", "target": "hifrom<author handle, redacted>",
                              "accessor": None})], [g])
    return pkg, rec, {"c1.L2": "cannot_tell"}, []
