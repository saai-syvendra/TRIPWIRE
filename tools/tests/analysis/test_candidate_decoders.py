"""Candidate decoders written in a batch session: the static check, registering from scratch, and adoption into
tools/common/decoders by the driver. Synthetic code only."""
import json
import subprocess
import sys

import pytest

from tools.analysis import run_analyses
from tools.common import paths
from tools.common.decoders import check_decoder_source, load_decoder_file

XOR = '''
def decode(input_bytes, params, read):
    key = bytes.fromhex(params["key_hex"])
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(input_bytes))
'''


@pytest.mark.parametrize("src, why", [
    ("import os\ndef decode(a, b, c):\n    return a\n", "import of os"),
    ("def decode(a, b, c):\n    return eval(a)\n", "eval"),
    ("def decode(a, b, c):\n    return a.__class__\n", "dunder"),
    ("from subprocess import run\ndef decode(a, b, c):\n    return a\n", "import of subprocess"),
    ("def decoder(a, b, c):\n    return a\n", "no top-level decode"),
])
def test_unsafe_or_malformed_decoders_are_refused(src, why):
    assert any(why in p for p in check_decoder_source(src))


def test_a_pure_decoder_passes_and_loads(tmp_path):
    f = tmp_path / "cand_xor.py"
    f.write_text("import base64\n" + XOR)
    assert check_decoder_source(f.read_text()) == []
    assert load_decoder_file(f)(bytes([1 ^ 7, 2 ^ 7]), {"key_hex": "07"}, None) == b"\x01\x02"


def test_the_driver_adopts_a_new_decoder_and_refuses_a_clash(repo, monkeypatch, tmp_path):
    decoders = tmp_path / "decoders"
    decoders.mkdir()
    monkeypatch.setattr(paths, "CODE_ROOT", tmp_path / "code")
    (tmp_path / "code" / "tools" / "common" / "decoders").mkdir(parents=True)
    work = paths.SCRATCH / "npm__a@1.0.0" / "decoders"
    work.mkdir(parents=True)
    (work / "cand_xor.py").write_text(XOR)
    (work / "test_cand_xor.py").write_text("def test_x():\n    pass\n")  # tests are not adopted
    assert run_analyses.adopt_decoders("npm__a@1.0.0", {"cand_xor"}) == (["cand_xor"], [])
    assert (tmp_path / "code" / "tools" / "common" / "decoders" / "cand_xor.py").read_text() == XOR
    assert run_analyses.adopt_decoders("npm__a@1.0.0", {"cand_xor"}) == ([], [])  # identical: nothing to do
    (work / "cand_xor.py").write_text(XOR + "\n# changed\n")
    adopted, problems = run_analyses.adopt_decoders("npm__a@1.0.0", {"cand_xor"})
    assert not adopted and "already holds other code" in problems[0]


def test_only_cited_candidates_are_checked_and_adopted(repo, monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "CODE_ROOT", tmp_path / "code")
    (tmp_path / "code" / "tools" / "common" / "decoders").mkdir(parents=True)
    work = paths.SCRATCH / "npm__a@1.0.0" / "decoders"
    work.mkdir(parents=True)
    (work / "cand_xor.py").write_text(XOR)
    (work / "probe.py").write_text("import sys\ndef decode(a, b, c):\n    return open(sys.argv[1]).read()\n")
    assert run_analyses.adopt_decoders("npm__a@1.0.0", set()) == ([], [])  # a leftover helper fails nothing
    assert not (tmp_path / "code" / "tools" / "common" / "decoders" / "cand_xor.py").exists()
    adopted, problems = run_analyses.adopt_decoders("npm__a@1.0.0", {"cand_xor", "probe"})
    assert adopted == ["cand_xor"] and problems and problems[0].startswith("probe:")


def test_cited_decoders_reads_decode_spec_derivations(tmp_path):
    rec = {"normalisation": {"derivations": [
        {"id": "d1", "recipe": "decode_spec", "params": {"decoder": "cand_xor"}},
        {"id": "d2", "recipe": "obfuscatorio_strings", "params": {"decoder": "_0xabc"}}]}}
    path = tmp_path / "r.md"
    path.write_text("# r\n\n```json\n" + json.dumps(rec) + "\n```\n")
    assert run_analyses.cited_decoders(path) == {"cand_xor"}
    assert run_analyses.cited_decoders(tmp_path / "missing.md") == set()


def test_include_blocked_reruns_blocked_and_mismatched_rows():
    rows = [{"key": "a", "status": "blocked"}, {"key": "b", "status": "model_mismatch"}, {"key": "c", "status": "done"},
            {"key": "d", "status": "analyse"}]
    assert run_analyses.todo(rows, False, None) == ["d"]
    assert run_analyses.todo(rows, False, None, blocked=True) == ["a", "b", "d"]


def test_register_decode_loads_a_candidate_from_scratch(repo, monkeypatch, capsys):
    from tools.analysis import prepare, register_decode
    from tools.tests.helpers import NPM, sample, tgz
    res = prepare.prepare(sample(repo, "datadog/npm/malicious_intent/demo.tgz", tgz(NPM)), None, None)
    work = repo / "scratch" / res["key"]
    (work / "decoders").mkdir()
    (work / "decoders" / "cand_xor.py").write_text(XOR)
    monkeypatch.setattr("sys.argv", ["register_decode.py", str(work), "--decoder", "cand_xor", "--candidate",
                                     "--input", "package.json", "--params", '{"key_hex": "00"}', "--lang", "js"])
    register_decode.main()
    spec = json.loads(capsys.readouterr().out.strip().splitlines()[0])
    assert spec["params"]["decoder"] == "cand_xor" and (work / "derived" / spec["id"]).is_file()
    (work / "decoders" / "eval_me.py").write_text("def decode(a, b, c):\n    return eval(a)\n")
    monkeypatch.setattr("sys.argv", ["register_decode.py", str(work), "--decoder", "eval_me", "--candidate",
                                     "--input", "package.json", "--lang", "js"])
    with pytest.raises(SystemExit, match="refused"):
        register_decode.main()
