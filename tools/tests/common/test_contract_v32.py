"""Schema v3.2: the inherited flag, analysis_type "tool", v3.1 records still valid, PEP 503 record lookup."""
import pytest

from tools.common import contract


def errors(rec):
    return contract.validation_errors(contract.load_validator(), rec)


def test_v31_records_stay_valid(record):
    assert record["schema_version"] == "3.1" and errors(record) == []


def test_inherited_condition_is_valid_in_v32(record):
    record["schema_version"] = "3.2"
    record["conditions"][0]["inherited"] = True
    assert errors(record) == []
    record["conditions"][0]["inherited"] = "yes"
    assert any("inherited" in e for e in errors(record))


def test_v32_fields_need_v32(record):
    record["conditions"][0]["inherited"] = True
    assert any("'inherited' needs schema_version 3.2" in e for e in errors(record))


def test_tool_is_only_for_skip_and_member_records(record):
    record["schema_version"] = "3.2"
    record["package"]["analysis_type"] = "tool"
    assert any("only for skip and member" in e for e in errors(record))
    member = {"schema_version": "3.2", "record_type": "member", "package": {**record["package"]}}
    assert errors(member) == []
    member["schema_version"] = "3.1"
    assert any("'tool' needs schema_version 3.2" in e for e in errors(member))


@pytest.mark.parametrize("expr, excluded, expected", [
    ("c1 && c2", {"c1"}, 1), ("c1 && c2", set(), 2), ("c1 || c2 && c3", {"c1"}, 0),
    ("(c1 || c2) && c3", {"c3"}, 1), ("c1 && c2 && c3", {"c1", "c2"}, 1)])
def test_min_conditions_excluding_inherited(expr, excluded, expected):
    assert contract.min_conditions_excluding(expr, excluded) == expected


def test_inherited_ids(record):
    record["conditions"][1]["inherited"] = True
    assert contract.inherited_ids(record) == {"c2"}


def test_normalise_name():
    assert contract.normalise_name("pypi", "Foo__Bar.baz-Qux") == "foo-bar-baz-qux"
    assert contract.normalise_name("npm", "Foo_Bar") == "Foo_Bar"


def test_existing_record_finds_members_and_pep503_spellings(tmp_path):
    (tmp_path / "_members").mkdir()
    (tmp_path / "_members" / "pypi__Foo_Bar@1.0.json").write_text("{}")
    (tmp_path / "npm").mkdir()
    (tmp_path / "npm" / "Foo_Bar@1.0.md").write_text("x")
    assert contract.existing_record(tmp_path, "pypi", "foo.bar", "1.0").name == "pypi__Foo_Bar@1.0.json"
    assert contract.existing_record(tmp_path, "pypi", "foo.bar", "1.1") is None
    assert contract.existing_record(tmp_path, "npm", "Foo_Bar", "1.0").name == "Foo_Bar@1.0.md"
    assert contract.existing_record(tmp_path, "npm", "foo-bar", "1.0") is None
