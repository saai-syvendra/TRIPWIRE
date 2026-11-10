"""
Agreement statistics for the verification pass: Cohen's kappa for two raters and a bootstrap confidence interval that resamples whole packages (claims from one package are not independent).
Pure functions; deterministic for a given seed.
"""
from __future__ import annotations

import random
from collections import Counter


def cohen_kappa(a: list, b: list) -> float | None:
    """Cohen's kappa for paired labels; None when undefined (no items, or chance agreement is 1)."""
    if len(a) != len(b):
        raise ValueError("rater lists differ in length")
    n = len(a)
    if n == 0:
        return None
    observed = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in ca.keys() | cb.keys()) / (n * n)
    if expected == 1:
        return None
    return (observed - expected) / (1 - expected)


def bootstrap_ci(groups: dict[str, list], stat, n: int = 2000, seed: int = 20261006,
                 alpha: float = 0.05) -> tuple[float, float] | None:
    """Percentile CI for stat(items) resampling the groups (packages) with replacement."""
    keys = sorted(groups)
    if not keys:
        return None
    rng = random.Random(seed)
    values = []
    for _ in range(n):
        sample = [item for k in (rng.choice(keys) for _ in keys) for item in groups[k]]
        v = stat(sample)
        if v is not None:
            values.append(v)
    if not values:
        return None
    values.sort()
    lo = values[int(alpha / 2 * (len(values) - 1))]
    hi = values[int((1 - alpha / 2) * (len(values) - 1))]
    return lo, hi
