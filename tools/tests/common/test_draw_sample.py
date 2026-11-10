"""The stratified draw on a synthetic frame: quotas, floors, one version per name, determinism, weights."""
import pytest

from tools.common import draw_sample as ds


def npm(label, year, name, version="1.0.0"):
    p = f"samples/npm/{label}/{name}/{version}/{year}-03-01-{name}-v{version}.zip"
    return {"path": p, "type": "blob", "sha": ds.blob_sha(p.encode()), "size": 1}


def pypi(name, version="1.0", ext=".tar.gz"):
    p = f"{name}/{version}/{name}-{version}{ext}"
    return {"path": p, "type": "blob", "sha": ds.blob_sha(p.encode()), "size": 1}


def ddpypi(label, name):
    p = f"samples/pypi/{label}/{name}/1.0/2025-05-01-{name}-v1.0.zip"
    return {"path": p, "type": "blob", "sha": ds.blob_sha(p.encode()), "size": 1}


def frames():
    dd = [ddpypi("compromised_lib", f"lib{i}") for i in range(5)] + [ddpypi("malicious_intent", f"p{i}")
                                                                    for i in range(40)]
    dd += [npm("malicious_intent", y, f"m{y}-{i}") for y, n in ((2024, 30), (2025, 300), (2026, 170))
          for i in range(n)]
    dd += [npm("compromised_lib", 2024, f"c24-{i}") for i in range(4)]
    dd += [npm("compromised_lib", y, f"c{y}-{i}", v) for y, n in ((2025, 80), (2026, 60)) for i in range(n)
           for v in ("1.0.0", "1.0.1")]  # two versions each: one may be drawn
    mr = [pypi(f"p{i}") for i in range(600)] + [pypi(f"w{i}", ext=".whl") for i in range(12)]
    mr += [pypi("dup", "2.0"), pypi("Dup", "3.0")]  # the same name spelled two ways
    return {"datadog": ds.frame("datadog", dd), "pypi_malregistry": ds.frame("pypi_malregistry", mr)}


def test_quotas_add_up_with_floors_and_oversampling():
    items, strata = ds.plan(frames(), 7, 120, 100, 40, 10)
    by = {(r["ecosystem"], r["stratum"]): r for r in strata}
    assert sum(r["drawn"] for r in strata if r["ecosystem"] == "npm") == 120
    assert sum(r["drawn"] for r in strata if r["ecosystem"] == "npm" and r["stratum"].startswith("compromised")) == 40
    assert by[("npm", "compromised_lib/2024")]["drawn"] == 4  # floor of 10, but only 4 names exist
    assert by[("npm", "malicious_intent/2024")]["drawn"] >= 10
    assert sum(r["drawn"] for r in strata if r["ecosystem"] == "pypi") == 100
    assert all(r["weight"] == r["names"] / r["drawn"] for r in strata if r["drawn"])


def test_one_version_per_name_and_names_compare_per_pep503():
    items, _ = ds.plan(frames(), 7, 120, 614, 40, 10)
    keys = [(e["ecosystem"], e["name"]) for e in items]
    assert len(keys) == len(set(keys))
    assert sum(1 for e in items if e["name"] == "dup") == 1


def test_the_draw_is_reproducible_and_depends_on_the_seed():
    a = [e["path"] for e in ds.plan(frames(), 7, 120, 100, 40, 10)[0]]
    b = [e["path"] for e in ds.plan(frames(), 7, 120, 100, 40, 10)[0]]
    c = [e["path"] for e in ds.plan(frames(), 8, 120, 100, 40, 10)[0]]
    assert a == b and a != c


def test_blob_sha_matches_git():
    assert ds.blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_datadog_pypi_compromised_is_taken_whole_and_names_are_shared_across_corpora():
    items, strata = ds.plan(frames(), 7, 120, 100, 40, 10)
    by = {(r["ecosystem"], r["stratum"]): r for r in strata}
    assert by[("pypi", "datadog-compromised_lib")]["drawn"] == 5
    py = [e["name"] for e in items if e["ecosystem"] == "pypi"]
    assert len(py) == len(set(py)) == 100  # p0..p39 exist in both corpora but are drawn once


def test_pilot_pins_undrawn_archives_by_destination_and_blob():
    fr = frames()
    drawn_e, pilot_e = fr["datadog"][0], fr["pypi_malregistry"][0]
    archives = {ds.local(drawn_e): drawn_e["blob"], ds.local(pilot_e): pilot_e["blob"]}
    (item,) = ds.pin_pilot(archives, fr, {ds.local(drawn_e)})
    assert item["path"] == pilot_e["path"] and item["stratum"] == "pilot" and item["weight"] is None
    assert ds.local(item) == ds.local(pilot_e)  # --fetch puts it back where the record found it
    with pytest.raises(SystemExit, match="byte for byte"):
        ds.pin_pilot({ds.local(pilot_e): ds.blob_sha(b"other bytes")}, fr, set())
