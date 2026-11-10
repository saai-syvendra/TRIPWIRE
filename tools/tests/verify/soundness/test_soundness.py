"""The checker's contract on the soundness corpus (see harness.py): true claims never refuted, false claims and
mutants never verified, no checker faults, and the pinned verdicts reached."""
import pytest

from tools.tests.verify.soundness.cases import CASES
from tools.tests.verify.soundness.harness import faults, mutants, run, show


class Built(dict):
    def __missing__(self, name):
        self[name] = CASES[name]()
        return self[name]


@pytest.fixture(scope="module")
def built():
    return Built()


@pytest.mark.parametrize("name", sorted(CASES))
def test_never_wrong(name, built):
    pkg, rec, _, false_claims = built[name]
    v = run(pkg, rec)
    assert not faults(v), faults(v)
    wrong = [f"{cid} is false but {show(x)}" for cid, x in v.items() if cid in false_claims and x["verdict"] == "verified"]
    wrong += [f"{cid} is true but {show(x)}" for cid, x in v.items()
              if cid not in false_claims and x["verdict"] == "refuted"]
    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize("name", sorted(CASES))
def test_mutants_never_verify(name, built):
    pkg, rec, _, false_claims = built[name]
    wrong = []
    for what, m, targets in mutants(rec):
        v = run(pkg, m)
        assert not faults(v), (what, faults(v))
        wrong += [f"{what}: {cid} {show(v[cid])}" for cid in targets
                  if cid in v and cid not in false_claims and v[cid]["verdict"] == "verified"]
    assert not wrong, "\n".join(wrong)


@pytest.mark.parametrize("name", sorted(CASES))
def test_pinned_verdicts(name, built):
    pkg, rec, want, _ = built[name]
    v = run(pkg, rec)
    missed = [f"{cid}: want {w}, got {show(v[cid])}" for cid, w in want.items() if w != "open" and v[cid]["verdict"] != w]
    assert not missed, "\n".join(missed)
