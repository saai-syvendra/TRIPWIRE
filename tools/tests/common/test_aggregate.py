import copy
import subprocess
import sys

import pytest

from tools.common import aggregate, contract, paths
from tools.tests.helpers import anchor


@pytest.mark.parametrize("expr, expected", [
    ("c1", 1),
    ("c1 && c2", 2),
    ("c1 || c2", 1),
    ("(c1 || c2) && c3", 2),
    ("c1 || c2 && c3", 1),
    ("(c1 && c2) || (c1 && c3 && c4)", 2),
    ("(c1 || c2) && (c1 || c3)", 1),
    ("c1&&c2", 2),
])
def test_min_conditions_of(expr, expected):
    assert contract.min_conditions_of(expr) == expected


@pytest.mark.parametrize("expr", ["", "c1 &&", "!c1", "c1 and c2", "(c1 || c2", "c1 c2", "c1 & c2"])
def test_min_conditions_of_rejects_bad_grammar(expr):
    with pytest.raises(ValueError):
        contract.min_conditions_of(expr)


@pytest.mark.parametrize("expr, expected", [
    ("c1", 1),
    ("c1 && c2", 1),
    ("c1 || c2", 2),
    ("(c1 || c2) && c3", 1),
    ("(c1 || c2) && (c3 || c4)", 2),
])
def test_min_false_of(expr, expected):
    assert contract.min_false_of(expr) == expected


def errors(rec):
    return contract.validation_errors(contract.load_validator(), rec)


def test_clean_record_passes(record):
    assert errors(record) == []


def test_duplicate_ids(record):
    record["conditions"].append(dict(record["conditions"][0]))
    assert "duplicate condition id c1" in errors(record)


def test_min_conditions_must_match_expression(record):
    record["gates"][0]["then"]["min_conditions"] = 1
    assert any("then.min_conditions 1 but expression gives 2" in e for e in errors(record))


def test_else_min_conditions_checked(record):
    g = record["gates"][0]
    g["expression"] = "c1 || c2"
    g["then"]["min_conditions"] = 1
    g["else"] = {"min_conditions": 1, "behaviours": ["destructive"], "env_recipe": {}, "recipe_guessed_fields": [],
                 "regions": [anchor(170, 200, "else_clause", 6)],
                 "payload": [{"behaviour": "destructive", "sink_kind": "fs_delete",
                              "sink": anchor(180, 195, "call_expression", 6), "witness": []}]}
    record["behaviours"]["gated"] = ["cred_read", "exfil", "destructive"]
    assert any("else.min_conditions 1 but the else side needs 2" in e for e in errors(record))


def test_else_requires_counts_the_enclosing_conditions(record):
    # if X { if Y {A} else {B} }: B needs X true and Y false
    g = record["gates"][0]
    g["expression"] = "c1 && c2"
    g["then"]["min_conditions"] = 2
    g["else"] = {"min_conditions": 1, "requires": ["c1"], "behaviours": ["destructive"], "env_recipe": {},
                 "recipe_guessed_fields": [], "regions": [anchor(170, 200, "else_clause", 6)],
                 "payload": [{"behaviour": "destructive", "sink_kind": "fs_delete",
                              "sink": anchor(180, 195, "call_expression", 6), "witness": []}]}
    record["schema_version"] = "3.2"
    record["behaviours"]["gated"] = ["cred_read", "exfil", "destructive"]
    assert any("else.min_conditions 1 but the else side needs 2" in e for e in errors(record))
    g["else"]["requires"] = ["c1", "c2"]
    assert any("cannot be false" in e for e in errors(record))


def test_bad_expression_grammar(record):
    record["gates"][0]["expression"] = "c1 and c2"
    assert any("bad expression" in e for e in errors(record))


def test_gate_hook_must_be_an_entry_point(record):
    record["gates"][0]["hook"] = "preinstall"
    assert any("not an entry point hook" in e for e in errors(record))


def test_gated_behaviours_must_match_gates(record):
    record["behaviours"]["gated"] = ["cred_read"]
    assert any("behaviours.gated" in e for e in errors(record))


def test_label_disagreement_required_on_hard_mismatch(record):
    record["claude_assessment"] = "benign"
    assert any("label_disagreement must be true" in e for e in errors(record))


def test_label_disagreement_may_be_flagged_by_analyst(record):
    record["claude_assessment"] = "suspicious"
    record["label_disagreement"] = True
    record["needs_manual_review"] = True
    assert errors(record) == []


def test_review_triggers_force_review(record):
    record["confidence"] = "low"
    assert any("needs_manual_review must be true: low confidence" in e for e in errors(record))


def test_schema_errors_skip_consistency_checks(record):
    del record["obfuscation"]
    errs = errors(record)
    assert errs and all("obfuscation" in e for e in errs)


def test_check_exits_2_without_jsonschema():
    code = ("import sys, runpy; sys.modules['jsonschema'] = None; sys.argv = ['aggregate.py', '--check']; "
            f"runpy.run_path({str(paths.CODE_ROOT / 'tools' / 'common' / 'aggregate.py')!r}, run_name='__main__')")
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 2
    assert "jsonschema is not installed" in proc.stderr


def test_summary_tables(record):
    import copy
    a, b = record, copy.deepcopy(record)
    a["candidate_check"].update(conditions_in_set=1, conditions_out_of_set=1, anchor_refusals=3)
    a["family_hint"] = "ssh-stealer"
    b["package"].update(ecosystem="pypi", source_label="benign", name="other", cluster_key="ef" * 32)
    b.update(conditions=[], gates=[], behaviours={"ungated": ["benign_build"], "gated": []}, family_hint=None)
    skip = {**a["package"], "ecosystem": "npm", "reason": "import_time_only", "note": ""}
    member = {**a["package"], "name": "demo-pkg-clone", "version": "1.0.1"}  # same cluster_key as a
    gates = [{**g, "conditions": a["conditions"]} for g in a["gates"]]
    md = aggregate.summary([a, b], [skip], [member], gates)
    assert "- Distinct campaigns (analysed representatives): 2" in md
    assert "- Packages across all campaigns (representatives + members): 3" in md
    assert "- Campaigns with a gate: 1 / 2 (50%) (per campaign)" in md
    assert "- Packages in a gated campaign: 2 / 3 (67%) (per package)" in md
    assert "| npm / malicious | 3 | 1 | 1 | 1 / 1 (100%) | 1 / 1 (100%) | 1 |" in md
    assert "| pypi / benign | 1 | 1 | 0 | 0 / 1 (0%) | 0 / 1 (0%) | 0 |" in md
    assert "| target_artifact: exists ~/.ssh | 1 / 2 (50%) |" in md
    assert "| os: == win32 | 1 / 2 (50%) |" in md
    assert "### Largest then.min_conditions per gated package\n\n| value | count |\n|---|---|\n| 2 | 1 / 1 (100%) |" in md
    assert "### Environment axes per gate then-recipe" in md and "| 2 | 1 / 1 (100%) |" in md
    assert "| targeting / activate | 1 / 1 (100%) |" in md
    assert "- Conditions in set: 3 / 4 (75%)  |  out of set: 1 / 4 (25%)" in md
    assert "- Anchors refused at write time: 3 (across 2 packages)" in md
    assert "| ssh-stealer | 1 / 2 (50%) |" in md


def test_compared_value_names_env_vars():
    c = {"api": "process.env.CI", "operator": "truthy", "value": None}
    assert aggregate.compared_value(c) == "CI truthy"
    c = {"api": "os.environ['LANG']", "operator": "startswith", "value": "ru"}
    assert aggregate.compared_value(c) == "LANG startswith ru"
    assert aggregate.recipe_axes({"os": "win32", "env_var": {"CI": None, "X": "1"}, "file_present": ["a"]}) == 4


def test_member_record_validates(record):
    member = {"schema_version": contract.SCHEMA_VERSION, "record_type": "member", "package": record["package"]}
    assert errors(member) == []
    del member["package"]["cluster_key"]
    assert any("cluster_key" in e for e in errors(member))


def test_analysis_provenance_is_required_on_analysed_records_only(record):
    del record["package"]["analysis_type"]
    assert any("analysis_type" in e for e in errors(record))
    member = {"schema_version": contract.SCHEMA_VERSION, "record_type": "member", "package": record["package"]}
    del member["package"]["model_name"]
    assert errors(member) == []


def test_package_fields_are_checked(record):
    for field, value in (("analysis_type", "robot"), ("released_at", "24/11/2025"),
                         ("released_at_source", "guess"), ("surprise", 1)):
        bad = copy.deepcopy(record)
        bad["package"][field] = value
        assert errors(bad), field
    record["package"].update(released_at=None, released_at_source=None, model_name=None, analysis_type="ai")
    assert errors(record) == []
    del record["package"]["released_at"]
    assert any("released_at" in e for e in errors(record))


def test_skip_record_package(record):
    skip = {"schema_version": contract.SCHEMA_VERSION, "record_type": "skip", "reason": "import_time_only", "note": "x",
            "package": {k: record["package"][k] for k in ("ecosystem", "name", "version", "source_dataset",
                                                          "source_label", "cluster_key",
                                                          "released_at", "released_at_source")}}
    assert errors(skip) == []
    skip["package"]["unexpected"] = True
    assert errors(skip)
