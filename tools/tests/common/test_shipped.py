"""The shipped-paths sidecar: built from the archive, bound to it, and joined by aggregate."""
import json

from tools.common import shipped
from tools.tests.verify.test_verify_gates import build
from tools.verify.source import sample_index


def with_recipe(rec, recipe):
    rec["gates"][0]["then"]["env_recipe"] = recipe
    return rec


def test_sidecar_records_only_the_named_paths_and_binds_the_archive(repo):
    rec = with_recipe(build(repo), {"file_absent": ["./tahg", "/etc/passwd", "../x"],
                                    "file_present": ["index.js"]})
    assert shipped.relative_paths(rec) == ["index.js", "tahg"]
    side = shipped.build(rec, sample_index())
    assert side["paths"] == {"index.js": True, "tahg": False}
    assert side["archive_sha256"] == rec["package"]["archive_sha256"] and side["tool"] == shipped.TOOL
    key = shipped.record_key(rec)
    ships, warnings = shipped.join([rec], {key: side})
    assert ships == {key: {"index.js": True, "tahg": False}} and warnings == []
    other = json.loads(json.dumps(side))
    other["archive_sha256"] = "0" * 64
    ships, warnings = shipped.join([rec], {key: other, "npm__gone@1": side})
    assert ships == {} and len(warnings) == 3  # rebound, uncovered, orphan
