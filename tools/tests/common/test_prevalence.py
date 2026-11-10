"""Joining records to sample manifests and the design-weighted prevalence estimate, on synthetic draws."""
from tools.common import prevalence as pv


def item(eco, stratum, name, version, weight, dataset="datadog"):
    seg = name.replace("/", "@") if eco == "npm" else name
    path = (f"samples/{eco}/malicious_intent/{seg}/{version}/2025-01-01-{seg}-v{version}.zip" if dataset == "datadog"
            else f"{name}/{version}/{name}-{version}.tar.gz")
    return {"dataset": dataset, "ecosystem": eco, "label": "malicious_intent", "stratum": stratum, "name": seg,
            "path": path, "blob": "0" * 40, "size": None, "weight": weight}


def pkg(eco, name, version, sample_file=None, cluster=None):
    return {"ecosystem": eco, "name": name, "version": version, "cluster_key": cluster or name,
            "sample_path": f"datadog/{eco}/malicious_intent/{sample_file}" if sample_file else None}


def draw():
    items = [item("npm", "a", f"a{i}", "1.0.0", 10.0) for i in range(4)] + \
        [item("npm", "b", f"b{i}", "1.0.0", 1.0) for i in range(2)] + [item("npm", "@s/scoped", "@s/scoped", "2.0.0", 10.0)]
    items[-1]["stratum"] = "a"
    strata = [{"ecosystem": "npm", "stratum": "a", "names": 50, "drawn": 5, "weight": 10.0},
              {"ecosystem": "npm", "stratum": "b", "names": 2, "drawn": 2, "weight": 1.0},
              {"ecosystem": "npm", "stratum": "z", "names": 17, "drawn": 0, "weight": None}]
    return {"sample_id": "d", "strata": strata, "items": items}


def rows():
    an = lambda name, file: ("analysed", {"package": pkg("npm", name, "1.0.0", file)})  # noqa: E731
    return [
        an("a0", "2025-01-01-a0-v1.0.0.zip"),                                # joined by file name
        ("member", pkg("npm", "a1", "1.0.0", cluster="a0")),                 # by name and version; a0's labels
        ("skip", {**pkg("npm", "a2", "1.0.0"), "reason": "no_install_code"}),
        # a3 has no record: non-response
        an("b0", "2025-01-01-b0-v1.0.0.zip"),
        ("skip", {**pkg("npm", "b1", "1.0.0"), "reason": "files_missing"}),  # unreadable: non-response
        ("analysed", {"package": pkg("npm", "@s/scoped", "2.0.0")}),         # scoped name folded as @s@scoped
        ("analysed", {"package": pkg("npm", "elsewhere", "9.9.9")}),         # in no manifest: pilot
    ]


def joined():
    rs = rows()
    taken, problems, unmatched = pv.label_rows({"d": draw()}, rs)
    labels = {"a0": {"gated": True, "gated_in_scope": True}, "b0": {"gated": True, "gated_in_scope": False},
              "@s/scoped": {"gated": False, "gated_in_scope": False}, "elsewhere": {"gated": True,
                                                                                    "gated_in_scope": True}}
    return rs, taken, problems, unmatched, pv.units(draw(), "d", taken, labels)


def test_join_labels_rows_and_falls_back_to_name_and_version():
    rs, taken, problems, unmatched, us = joined()
    assert not problems and unmatched == 1
    assert [r[1].get("sample_id") for r in rs] == ["d"] * 6 + ["pilot"]
    assert rs[0][1]["stratum"] == "a" and rs[0][1]["weight"] == 10.0
    status = {u["path"].split("/")[3]: u["status"] for u in us}
    assert status == {"a0": "respondent", "a1": "respondent", "a2": "respondent", "a3": "no_record",
                      "b0": "respondent", "b1": "files_missing", "@s@scoped": "respondent"}
    member = next(u for u in us if "/a1/" in u["path"])
    assert member["gated"] and member["install_code"]  # a member takes its representative's labels


def test_a_draw_beats_the_pilot_and_two_records_on_one_item_fail():
    pilot = {"sample_id": "pilot", "strata": [], "items": [item("npm", "pilot", "a0", "1.0.0", None)]}
    rs = [("analysed", {"package": pkg("npm", "a0", "1.0.0", "2025-01-01-a0-v1.0.0.zip")})]
    pv.label_rows({"pilot": pilot, "d": draw()}, rs)
    assert rs[0][1]["sample_id"] == "d"
    _, problems, _ = pv.label_rows({"d": draw()}, rows()[:1] + [("member", pkg("npm", "a0", "1.0.0"))])
    assert problems and "two records" in problems[0]


def test_versionless_datadog_path_joins_by_name():
    it = item("pypi", "p", "paquete", "x", 1.0)
    it["path"] = "samples/pypi/malicious_intent/paquete/2022-12-01-paquete.zip"
    assert pv.item_name_version(it) == ("paquete", None)
    rs = [("member", pkg("pypi", "Paquete", "99.99.99"))]
    pv.label_rows({"d": {"sample_id": "d", "strata": [], "items": [it]}}, rs)
    assert rs[0][1]["sample_id"] == "d"


def test_weighted_shares_leave_out_unweighted_strata_and_count_nonresponse():
    *_, us = joined()
    out, left_out = pv.table(draw(), "d", us)
    cell = {(r["stratum"], r["denominator"], r["measure"]): r for r in out}
    a = cell[("a", "all_drawn", "gated")]
    assert (a["drawn"], a["responding"], a["nonresponse"], a["nonresponse_reasons"]) == (5, 4, 1, "no_record=1")
    assert a["share"] == 0.5  # a0 and its member gated, a2 skipped, the scoped one not gated
    assert cell[("a", "install_code", "gated")]["share"] == 2 / 3
    total = cell[("all", "all_drawn", "gated")]
    # stratum a: N=50 over 4 respondents, 2 gated; stratum b: N=2 over 1 respondent (b0), gated
    assert abs(total["share"] - (50 / 4 * 2 + 2 / 1 * 1) / (50 + 2)) < 1e-12
    assert total["names"] == 52 and total["nonresponse"] == 2
    assert cell[("all", "all_drawn", "gated_in_scope")]["share"] == (50 / 4 * 2) / 52
    assert left_out == ["npm z (N=17, drawn 0, responding 0)"]


def test_intervals_are_deterministic_and_hold_the_estimate():
    *_, us = joined()
    first = pv.table(draw(), "d", us)[0]
    assert first == pv.table(draw(), "d", us)[0]
    for r in first:
        if r["share"] is not None:
            assert r["ci_low"] <= r["share"] <= r["ci_high"]


def unit(i, gated, cluster=None):
    return {"ecosystem": "pypi", "stratum": "h", "path": f"p{i}", "cluster_key": cluster, "status": "respondent",
            "install_code": True, "gated": gated, "gated_in_scope": gated}


def test_one_large_campaign_widens_the_interval_and_counts_once_per_campaign():
    flood = [unit(i, True, "flood") for i in range(30)]
    rest = [unit(30 + i, i % 4 == 0, f"c{i}") for i in range(30)]
    iid = [unit(i, u["gated"]) for i, u in enumerate(flood + rest)]  # the same names, every one its own campaign
    _, ci_flood = pv.estimate({"h": flood + rest}, {"h": 600}, "gated", "install_code")
    _, ci_iid = pv.estimate({"h": iid}, {"h": 600}, "gated", "install_code")
    assert ci_flood[1] - ci_flood[0] > 2 * (ci_iid[1] - ci_iid[0])
    k, pos, share, _ = pv.campaign_estimate(flood + rest, "gated")
    assert (k, pos) == (31, 9) and share == 9 / 31
    assert pv.concentration({"h": flood + rest}, {"h": 600}) == (1, 30 / 38)


def test_non_response_bounds_count_every_absent_name_as_ungated_then_gated():
    us = [unit(i, i < 2) for i in range(4)]  # 2 of 4 respondents gate
    low, high = pv.bounds({"h": us}, {"h": 2}, {"h": 60}, "gated", "install_code")
    assert (low, high) == (2 / 6, 4 / 6)
    assert pv.bounds({"h": us}, {}, {"h": 60}, "gated", "install_code") == (0.5, 0.5)


def test_merging_the_campaigns_that_hold_half_the_weight_widens_the_interval():
    # one family split over three cluster keys, then many small campaigns
    family = [unit(i, True, f"fam{i % 3}") for i in range(30)]
    rest = [unit(30 + i, i % 3 != 0, f"c{i}") for i in range(30)]  # 20 gated: half the 50 needs all three keys
    groups, frame = {"h": family + rest}, {"h": 600}
    assert pv.top_campaigns(groups, frame) == frozenset({"fam0", "fam1", "fam2"})
    _, split = pv.estimate(groups, frame, "gated", "install_code")
    _, merged = pv.estimate(groups, frame, "gated", "install_code", merged=pv.top_campaigns(groups, frame))
    assert merged[1] - merged[0] > split[1] - split[0]


def test_the_all_rows_carry_bounds_and_a_merged_interval():
    us = [unit(i, i % 2 == 0, f"c{i}") for i in range(6)] + [
        {**unit(9, False), "status": "no_record", "install_code": False, "record": None}]
    manifest = {"strata": [{"ecosystem": "pypi", "stratum": "h", "names": 70, "drawn": 7, "weight": 10}]}
    rows, _ = pv.table(manifest, "d", [{**u, "gated_env": u["gated"], "gated_not_absence": u["gated"]} for u in us])
    total = [r for r in rows if r["stratum"] == "all" and r["denominator"] == "install_code"
             and r["measure"] == "gated"][0]
    assert (total["bound_low"], total["bound_high"]) == (3 / 7, 4 / 7)
    assert total["ci_low_merged"] <= total["share"] <= total["ci_high_merged"]
    assert {r["measure"] for r in rows} == {"gated", "gated_in_scope", "gated_env", "gated_not_absence"}


def test_a_label_split_by_year_gets_its_own_total():
    def u(i, stratum, gated):
        return {**unit(i, gated, f"c{i}"), "ecosystem": "npm", "stratum": stratum, "gated_env": gated,
                "gated_not_absence": gated}
    us = [u(0, "lib/2024", True), u(1, "lib/2024", False), u(2, "lib/2025", True), u(3, "lib/2025", True),
          u(4, "intent", False), u(5, "intent", False)]
    manifest = {"strata": [{"ecosystem": "npm", "stratum": h, "names": n, "drawn": 2, "weight": n / 2}
                           for h, n in (("lib/2024", 20), ("lib/2025", 60), ("intent", 400))]}
    rows, _ = pv.table(manifest, "d", us)
    cell = {(r["stratum"], r["denominator"], r["measure"]): r for r in rows}
    assert cell[("lib", "install_code", "gated")]["share"] == (20 / 2 * 1 + 60 / 2 * 2) / 80
    assert cell[("lib", "install_code", "gated")]["names"] == 80
    assert ("intent", "install_code", "gated") in cell and cell[("all", "install_code", "gated")]["names"] == 480
