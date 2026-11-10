import subprocess
import sys

from tools.analysis import prepare
from tools.common import paths
from tools.tests.helpers import NPM, sample, tgz

VIEW = str(paths.CODE_ROOT / "tools" / "analysis" / "view.py")


def run(repo, *args):
    return subprocess.run([sys.executable, VIEW, *map(str, args)], capture_output=True, text=True)


def test_view_greps_and_windows(repo):
    res = prepare.prepare(sample(repo, "npm/demo.tgz", tgz(NPM)), None, None)
    work = repo / "scratch" / res["key"]
    g = run(repo, work, "lib/install.js", "--grep", "platform", "--context", "1")
    assert g.returncode == 0 and "os.platform()" in g.stdout and "line" in g.stdout
    b = run(repo, work, "lib/util.js", "--bytes", "0-40")
    assert b.returncode == 0 and "https" in b.stdout
    miss = run(repo, work, "lib/install.js", "--grep", "nonexistent_zzz")
    assert "no matches" in miss.stdout
    assert run(repo, work, "lib/install.js").returncode != 0  # needs a mode
