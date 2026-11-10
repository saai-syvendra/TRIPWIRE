import pytest

from tools.common.recipe import build_recipe
from tools.common.tsparse import PARSERS, descendants, pure_alias, static_key, static_member_name


def first(lang, src, kind):
    return next(n for n in descendants(PARSERS[lang].parse(src.encode()).root_node) if n.type == kind)


@pytest.mark.parametrize("src,kind,name", [
    ("a.send(1)", "member_expression", "send"),
    ("a['send'](1)", "subscript_expression", "send"),
    ('a["send"](1)', "subscript_expression", "send"),
    ("a[`send`](1)", "subscript_expression", "send"),
    ('a["\\x73end"](1)', "subscript_expression", "send"),
    ("a[`s${x}`](1)", "subscript_expression", None),
    ("a[k](1)", "subscript_expression", None),
    ("a[dec(0x1f)](1)", "subscript_expression", None),
    ("a[0](1)", "subscript_expression", None),
])
def test_static_member_name_js(src, kind, name):
    assert static_member_name(first("js", src, kind)) == name


@pytest.mark.parametrize("src,kind,name", [
    ("sys.exit(1)", "attribute", "exit"),
    ("d['send'](1)", "subscript", "send"),
    ("d[f'{x}'](1)", "subscript", None),
])
def test_static_member_name_py(src, kind, name):
    assert static_member_name(first("py", src, kind)) == name


@pytest.mark.parametrize("src,kind,field,name", [
    ("o = {send: 1}", "pair", "key", "send"),
    ("o = {'send': 1}", "pair", "key", "send"),
    ("o = {['send']: 1}", "pair", "key", "send"),
    ("o = {[k]: 1}", "pair", "key", None),
    ("class C { ['send']() {} }", "method_definition", "name", "send"),
    ("class C { 'send'() {} }", "method_definition", "name", "send"),
    ("class C { send() {} }", "method_definition", "name", "send"),
])
def test_static_key(src, kind, field, name):
    assert static_key(first("js", src, kind).child_by_field_name(field)) == name


@pytest.mark.parametrize("src,alias", [
    ("const _0x51ad63 = _0x192368;", True),
    ("var a = b, c = d;", True),
    ("const a = {x: 1}, b = c;", False),
    ("const a = f();", False),
    ("let a;", False),
])
def test_pure_alias(src, alias):
    stmt = PARSERS["js"].parse(src.encode()).root_node.named_children[0]
    assert pure_alias(stmt) is alias


def cond(**kw):
    return {"id": "c1", "category": "env_var", "value": None, "env": None, "api": "x", **kw}


def test_recipes_for_excluding_operators_avoid_the_value():
    recipe, guessed, missing = build_recipe([cond(operator="not_startswith", value="ghp_decoy", env="GITHUB_TOKEN",
                                                  api="process.env.GITHUB_TOKEN")])
    assert recipe == {"env_var_absent": ["GITHUB_TOKEN"]} and guessed == ["env_var_absent"] and not missing
    recipe, guessed, _ = build_recipe([cond(category="locale_language", operator="not_startswith", value="ru",
                                            api="Intl.DateTimeFormat().resolvedOptions().locale")])
    assert recipe == {"locale": "en-US"} and guessed == ["locale"]
    recipe, _, _ = build_recipe([cond(category="locale_language", operator="not_startswith", value=["en", "ru"],
                                      api="process.env.LANG")])
    assert recipe == {"locale": "de-DE"}
    recipe, _, _ = build_recipe([cond(category="hostname", operator="not_includes", value="dev", api="os.hostname()")])
    assert recipe == {"hostname": "build-host"}
