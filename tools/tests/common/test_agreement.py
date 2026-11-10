import pytest

from tools.common.agreement import bootstrap_ci, cohen_kappa


def test_cohen_kappa_textbook_two_by_two():
    a = ["y"] * 25 + ["n"] * 25
    b = ["y"] * 20 + ["n"] * 5 + ["y"] * 10 + ["n"] * 15
    assert cohen_kappa(a, b) == pytest.approx(0.4)


def test_cohen_kappa_edge_cases():
    assert cohen_kappa(["a", "b"], ["a", "b"]) == 1
    assert cohen_kappa(["a", "a"], ["a", "a"]) is None
    assert cohen_kappa([], []) is None


def test_bootstrap_is_deterministic_and_resamples_packages():
    groups = {"p1": [("a", "a")] * 3, "p2": [("a", "b")], "p3": [("b", "b")] * 2}
    stat = lambda items: cohen_kappa([x for x, _ in items], [y for _, y in items])  # noqa: E731
    assert bootstrap_ci(groups, stat, n=200) == bootstrap_ci(groups, stat, n=200)
    lo, hi = bootstrap_ci(groups, stat, n=200)
    assert -1 <= lo <= hi <= 1
