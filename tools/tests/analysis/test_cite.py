import json
import subprocess
import sys

from tools.analysis import prepare
from tools.common import anchors, paths
from tools.tests.helpers import NPM, sample, tgz

CITE = str(paths.CODE_ROOT / "tools" / "analysis" / "cite.py")


def run(*args):
    return subprocess.run([sys.executable, CITE, *map(str, args)], capture_output=True, text=True)


def test_cites_nodes_ranges_and_refuses_misses(repo):
    res = prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None)
    work = repo / "scratch" / res["key"]
    root = json.loads((work / "prepared.json").read_text())["package"]["package_root"]
    raw = (work / "unpacked" / root / "lib/install.js").read_bytes()

    out = run(work, "lib/install.js", "--line", 4, "--text", "os.platform() !== 'win32'")
    assert out.returncode == 0, out.stderr
    a = json.loads(out.stdout)
    assert a["node_type"] == "binary_expression" and anchors.mismatch(a, raw) is None
    rng = json.loads(run(work, "lib/install.js", "--line", 4, "--to-line", 5).stdout)
    assert rng["node_type"] == anchors.RANGE and raw[rng["start_byte"]:rng["end_byte"]].endswith(b"util.send();")
    miss = run(work, "lib/install.js", "--line", 4, "--text", "linux")
    assert miss.returncode != 0 and "linux" in miss.stderr
    amb = run(work, "lib/install.js", "--line", 2, "--text", "o")
    assert amb.returncode != 0 and "--nth" in amb.stderr


def test_to_line_takes_the_innermost_run_and_refuses_a_whole_one_line_file(repo):
    files = dict(NPM)
    files["lib/install.js"] = ("function go() {\n  const a = 1;\n  const b = 2;\n}\ngo();\n")
    files["lib/min.js"] = "var a=1;if(a){a=2}"
    res = prepare.prepare(sample(repo, "npm/demo2.tgz", tgz(files)), None, None)
    work = repo / "scratch" / res["key"]
    root = json.loads((work / "prepared.json").read_text())["package"]["package_root"]
    raw = (work / "unpacked" / root / "lib/install.js").read_bytes()
    body = json.loads(run(work, "lib/install.js", "--line", 2, "--to-line", 3).stdout)
    assert raw[body["start_byte"]:body["end_byte"]] == b"const a = 1;\n  const b = 2;"
    nested = run(work, "lib/min.js", "--line", 1, "--to-line", 1)
    assert nested.returncode != 0 and "nested" in nested.stderr
    mixed = run(work, "lib/install.js", "--line", 2, "--to-line", 3, "--nth", 1)
    assert mixed.returncode != 0 and "--text only" in mixed.stderr
    out = run(work, "lib/install.js", "--line", 5, "--text", "go()")
    assert "bytes from line 5" in out.stderr
    assert run(work, "../../../etc/passwd", "--line", 1, "--text", "x").returncode != 0
