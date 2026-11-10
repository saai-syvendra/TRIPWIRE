"""The profile evaluator and the greedy merge, on synthetic gates and a synthetic profile."""
from tools.common import profiles as pf

PROFILE = {
    "profile": "box", "sources": {},
    "axes": {
        "os": {"value": "linux"}, "privilege": {"value": "root_or_admin"}, "home_dir": {"value": "/root"},
        "hostname": {"value": "<container id>", "random": True}, "ci": {"value": "none"}, "locale": {"value": "C"},
        "network": {"egress": "open", "blocked": ["10.0.0.0/8"]},
        "env_var": {"set": {"HOME": "/root", "PATH": None}, "complete": True, "unknown_prefixes": []},
        "file": {"present": ["/etc/passwd", "~/.bashrc"], "absent_prefixes": ["~/", "/opt/"]},
        "installed_tool": {"present": ["curl"], "complete": True},
    },
    "ecosystems": {"npm": {"env_var": {"set": {"npm_lifecycle_event": "$hook"}, "unknown_prefixes": ["npm_config_"]},
                           "package_manager": {"value": "npm"}}},
}


def cond(cid, in_scope=True, category="synthetic", operator="==", value="linux"):
    # "synthetic" has no recipe axis to check against, so a test can pair it with any recipe
    return {"id": cid, "category": category, "operator": operator, "value": value, "in_scope": in_scope, "api": "x"}


def gate(expr, recipe, conds, guessed=(), else_branch=None, key="npm__p@1", gid="g1"):
    return {"key": key, "gate_id": gid, "cluster_key": key, "hook": "postinstall", "expression": expr,
            "verification": "ok", "conditions": conds, "else": else_branch,
            "then": {"behaviours": ["exfil"], "env_recipe": recipe, "recipe_guessed_fields": list(guessed)}}


def outcome(g, branch="then"):
    (row,) = [r for r in pf.evaluate([g], {"box": PROFILE}) if r["branch"] == branch]
    return row["outcome"], row["reason"], row["guessed"]


def test_axes_open_close_and_stay_unknown_where_undocumented():
    c = [cond("c1")]
    assert outcome(gate("c1", {"os": "linux"}, c))[0] == "open"
    assert outcome(gate("c1", {"os": "win32"}, c))[0] == "closed"
    assert outcome(gate("c1", {"env_var": {"GITHUB_TOKEN": None}}, c))[0] == "closed"     # complete env
    assert outcome(gate("c1", {"env_var_absent": ["npm_config_yes"]}, c))[:2] == ("unknown", "undocumented")
    assert outcome(gate("c1", {"env_var": {"npm_lifecycle_event": "postinstall"}}, c))[0] == "open"  # the hook
    assert outcome(gate("c1", {"file_present": ["~/.aws/credentials"]}, c))[0] == "closed"
    assert outcome(gate("c1", {"file_present": ["/root/.bashrc"]}, c))[0] == "open"        # ~ is the home dir
    assert outcome(gate("c1", {"file_absent": ["%APPDATA%/Exodus"]}, c))[0] == "open"      # no Windows paths
    assert outcome(gate("c1", {"file_absent": ["tahg"]}, c))[:2] == ("unknown", "relative_path")
    assert outcome(gate("c1", {"file_present": ["/var/x"]}, c))[:2] == ("unknown", "undocumented")
    assert outcome(gate("c1", {"package_manager": "pip running setup.py"}, c))[:2] == ("unknown", "uncomparable_value")
    assert outcome(gate("c1", {"network": {"10.1.2.3:443": "reachable"}}, c))[0] == "closed"
    assert outcome(gate("c1", {"network": {"10[.]1[.]2[.]3:443": "reachable"}}, c))[0] == "closed"  # defanged
    assert outcome(gate("c1", {"network": {"api.example:443": "reachable"}}, c))[0] == "open"
    assert outcome(gate("c1", {"locale": "en-US"}, c))[0] == "closed"
    assert outcome(gate("c1", {"ci": "true"}, c))[0] == "closed"
    assert outcome(gate("c1", {"cpu_count": 4}, c))[:2] == ("unknown", "undocumented")
    assert outcome(gate("c1", {}, c))[:2] == ("unknown", "empty_recipe")


def test_out_of_scope_conditions_make_a_branch_not_expressible():
    g = gate("c1 && c2", {"os": "linux"}, [cond("c1"), cond("c2", in_scope=False, category="server_response")])
    assert outcome(g)[0] == "not_expressible"
    # an out-of-scope condition outside the smallest term does not count
    g = gate("c1 || (c2 && c3)", {"os": "linux"}, [cond("c1"), cond("c2", in_scope=False), cond("c3")])
    assert outcome(g)[0] == "open"


def test_a_contradiction_with_another_way_in_is_unknown_not_closed():
    g = gate("c1 || c2", {"os": "win32"}, [cond("c1", value="win32"), cond("c2", category="ci_marker")])
    assert outcome(g)[:2] == ("unknown", "alternative_terms")
    # else branch of c1 && c2: falsifying c1 or c2 are two ways in
    e = {"behaviours": ["recon"], "env_recipe": {"os": "win32"}, "recipe_guessed_fields": []}
    g = gate("c1 && c2", {"os": "linux"}, [cond("c1"), cond("c2")], else_branch=e)
    assert outcome(g, "else")[:2] == ("unknown", "alternative_terms")
    g = gate("c1", {"os": "linux"}, [cond("c1")], else_branch=e)
    assert outcome(g, "else")[0] == "closed"


def test_guessed_marks_outcomes_resting_on_guessed_keys():
    c = [cond("c1", category="hostname", operator="!=", value="sandbox")]
    assert outcome(gate("c1", {"hostname": "dev-workstation"}, c, guessed=["hostname"])) == ("closed", None, True)
    assert outcome(gate("c1", {"os": "linux", "hostname": "x"}, c, guessed=["os"]))[2] is False  # hostname decides
    assert outcome(gate("c1", {"os": "linux"}, c, guessed=["os"]))[:2] == ("unknown", "recipe_gap")  # no hostname
    assert outcome(gate("c1", {"os": "linux"}, [cond("c1", category="os")], guessed=["os"])) == ("open", None, True)


def test_excluded_gates_are_left_out_and_packages_open_on_any_payload():
    g = gate("c1", {"os": "linux"}, [cond("c1")])
    assert pf.evaluate([{**g, "verification": "excluded"}], {"box": PROFILE}) == []
    assert pf.package_outcome(["closed", "unknown", "open"]) == "open"
    assert pf.package_outcome(["closed", "not_expressible"]) == "not_expressible"
    rows = pf.evaluate([g, gate("c1", {"os": "win32"}, [cond("c1")], gid="g2")], {"box": PROFILE})
    got = {(r["unit"], r["weighting"]): r for r in pf.table(rows, ["npm__p@1", "npm__p@1"],
                                                            {"d": [("npm__p@1", 3.0), ("npm__p@1", 3.0)]})}
    pay, pkg, drawn = got[("payload", "none")], got[("package", "none")], got[("package", "draw:d")]
    assert (pay["n_open"], pay["n_closed"], pay["units"]) == (1, 1, 2)
    assert (pkg["units"], pkg["n_open"], pkg["share_open"]) == (2, 2, 1.0)
    assert drawn["units"] == 2 and drawn["share_open"] == 1.0
    assert got[("campaign", "none")]["units"] == got[("campaign", "draw:d")]["units"] == 1  # one campaign, once


def test_greedy_merge_splits_only_on_conflicts():
    envs = pf.merge([{"os": "linux", "env_var": {"CI": None}}, {"os": "linux", "env_var": {"CI": "true"}},
                     {"os": "win32"}, {"env_var_absent": ["CI"]}, {"file_present": ["~/.ssh"]},
                     {"file_absent": ["~/.ssh"]}, {"cpu_count": 2}, {"cpu_count": 8}])
    assert [e["payloads"] for e in envs] == [5, 3]  # linux+CI+~/.ssh+cpu; win32, CI unset, no ~/.ssh
    assert envs[0]["recipe"]["env_var"] == {"CI": "true"} and envs[0]["recipe"]["cpu_count"] == 8
    assert pf.conflicts({"env_var": {"CI": "true"}}, {"env_var": {"CI": "1"}})
    assert not pf.conflicts({"env_var": {"CI": "true"}}, {"env_var": {"CI": None}})


def test_shipped_profiles_cite_a_source_for_every_axis():
    for name, prof in pf.load().items():
        for scope in [prof["axes"], *prof.get("ecosystems", {}).values()]:
            for key, entry in scope.items():
                cited = entry["source"] if isinstance(entry["source"], list) else [entry["source"]]
                assert cited and all(s in prof["sources"] for s in cited), (name, key)
        assert all("read" in s and "url" in s for s in prof["sources"].values()), name


def test_merge_counts_only_buildable_payloads():
    c = [cond("c1")]
    gates = [gate("c1", {"os": "linux"}, c, gid="g1"), gate("c1", {"os": "win32"}, c, gid="g2"),
             gate("c1", {}, c, gid="g3"), gate("c1", {"package_manager": "pip running setup.py"}, c, gid="g4"),
             gate("c1", {"file_absent": ["tahg"]}, c, gid="g5")]
    rows = pf.evaluate(gates, {"box": PROFILE})
    assert not pf.buildable(gates[2], gates[2]["then"], {"box": PROFILE})
    assert pf.buildable(gates[4], gates[4]["then"], {"box": PROFILE})  # a fresh install dir lacks it
    table = pf.merge_table(gates, rows, {"box": PROFILE})
    merged = [r for r in table if r["kind"] == "merged"]
    assert merged[-1]["buildable"] == 3 and merged[-1]["opened"] == 3 and len(merged) == 2
    (point,) = [r for r in table if r["kind"] == "profile"]
    assert point["opened"] == 1 and point["share"] == 1 / 3  # only g1 opens; g5 stays unknown


def test_the_shipped_paths_sidecar_settles_relative_paths():
    c = [cond("c1")]
    ships = {"npm__p@1": {"tahg": False, "scripts/deploy.js": True}}

    def scored(recipe):
        (row,) = pf.evaluate([gate("c1", recipe, c)], {"box": PROFILE}, ships)
        return row["outcome"], row["reason"]
    assert scored({"file_absent": ["tahg"]}) == ("open", None)
    assert scored({"file_present": ["./scripts/deploy.js"]}) == ("open", None)   # ./ is the install directory
    assert scored({"file_present": ["tahg/"]}) == ("closed", None)
    assert scored({"file_absent": ["scripts/deploy.js"]}) == ("closed", None)
    assert scored({"file_absent": ["other"]}) == ("unknown", "relative_path")     # the sidecar does not say
    assert scored({"file_absent": ["../tahg"]}) == ("unknown", "relative_path")   # outside the install directory
    assert scored({"file_present": ["$INIT_CWD/package.json"]}) == ("unknown", "uncomparable_value")  # not ours
    assert pf.relative("./a//b/") == "a/b" and pf.relative("../x") is None and pf.relative("./") is None


def test_merge_drops_settled_paths_and_leaves_out_payloads_they_close():
    c = [cond("c1")]
    gates = [gate("c1", {"os": "linux", "file_absent": ["tahg"]}, c, gid="g1"),
             gate("c1", {"file_present": ["tahg"]}, c, gid="g2", key="npm__q@1"),
             gate("c1", {"file_absent": ["shipped.js"]}, c, gid="g3"),
             gate("c1", {"file_absent": ["unsaid"]}, c, gid="g4")]
    ships = {"npm__p@1": {"tahg": False, "shipped.js": True}, "npm__q@1": {"tahg": True}}
    assert pf.settled(gates[0]["then"]["env_recipe"], ships["npm__p@1"]) == ({"os": "linux"}, True)
    assert pf.settled(gates[2]["then"]["env_recipe"], ships["npm__p@1"]) == ({}, False)
    rows = pf.evaluate(gates, {"box": PROFILE}, ships)
    table = pf.merge_table(gates, rows, {"box": PROFILE}, ships)
    merged = [r for r in table if r["kind"] == "merged"]
    # g3 wants a shipped file absent: no environment holds it; tahg in g1 and g2 is per package, so no conflict
    assert merged[-1]["buildable"] == 3 and len(merged) == 1
    (point,) = [r for r in table if r["kind"] == "profile"]
    assert point["opened"] == 2  # g1 and g2 open; g4 stays unknown


def test_a_closed_payload_names_the_axes_that_close_it():
    c = [cond("c1"), cond("c2", category="ci_marker")]
    rows = pf.evaluate([gate("c1 && c2", {"os": "win32", "ci": "github_actions", "privilege": "root_or_admin"}, c)],
                       {"box": PROFILE})
    assert [(r["outcome"], r["closed_on"]) for r in rows] == [("closed", ["ci", "os"])]
    (row,) = pf.evaluate([gate("c1", {"os": "linux"}, [cond("c1")])], {"box": PROFILE})
    assert (row["outcome"], row["closed_on"]) == ("open", [])


def test_the_merge_table_counts_campaigns_as_the_campaign_rows_do():
    c = [cond("c1")]
    gates = [gate("c1", {"os": "linux"}, c, key="npm__a@1"), gate("c1", {"os": "win32"}, c, key="npm__b@1"),
             {**gate("c1", {"os": "linux"}, c, key="npm__c@1"), "cluster_key": "npm__a@1"}]  # a member of a's campaign
    rows = pf.evaluate(gates, {"box": PROFILE})
    table = pf.merge_table(gates, rows, {"box": PROFILE})
    merged = [r for r in table if r["kind"] == "merged"]
    assert [(r["campaigns_opened"], r["campaigns"]) for r in merged] == [(1, 2), (2, 2)]
    (point,) = [r for r in table if r["kind"] == "profile"]
    assert (point["campaigns_opened"], point["campaign_share"]) == (1, 0.5)  # the linux box opens campaign a only


def test_a_payload_that_needs_another_os_is_closed_whatever_its_gate_says():
    g = gate("c1", {"file_absent": ["/opt/marker"]}, [cond("c1", category="target_artifact")])
    win = [{"axis": "os", "value": "win32", "reason": "PowerShell dropper"}]
    (row,) = pf.evaluate([g], {"box": PROFILE}, requirements={"npm__p@1": win})
    assert (row["outcome"], row["closed_on"]) == ("closed", ["os_requirement"])
    either = [{"axis": "os", "value": "linux, darwin or win32", "reason": "per-OS payloads"}]
    (row,) = pf.evaluate([g], {"box": PROFILE}, requirements={"npm__p@1": either})
    assert row["outcome"] == "open"
    assert pf.required_os([{"axis": "os", "value": ["linux", "darwin"]}]) == {"linux", "darwin"}
    assert pf.required_os([{"axis": "network", "value": "x"}]) is None


def test_a_recipe_that_leaves_out_a_needed_condition_does_not_open():
    conds = [cond("c1", category="os"), cond("c2", category="process_list", operator="includes", value="agent")]
    (row,) = pf.evaluate([gate("c1 && c2", {"os": "linux"}, conds)], {"box": PROFILE})
    assert (row["outcome"], row["reason"]) == ("unknown", "recipe_gap")
    conds = [cond("c1", category="os"), cond("c2", category="target_artifact", operator="exists", value="~/.npmrc")]
    (row,) = pf.evaluate([gate("c1 && c2", {"os": "linux"}, conds)], {"box": PROFILE})
    assert (row["outcome"], row["reason"]) == ("unknown", "recipe_gap")   # no file axis in the recipe
    (row,) = pf.evaluate([gate("c1 && c2", {"os": "win32"}, conds)], {"box": PROFILE})
    assert row["outcome"] == "closed"                                     # a contradiction still closes
