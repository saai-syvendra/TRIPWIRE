#!/usr/bin/env python3
"""
Writes paper/assets/numbers.tex: every number the paper quotes, as a macro, from dataset/ (run
tools/common/aggregate.py first), the manifests in reports/ and the decoder registry. Nothing is typed by hand: a
value that does not exist yet renders as \\pending{name}.

Usage: .venv/bin/python paper/make_numbers.py
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.common import paths, verification  # noqa: E402

DATASET, REPORTS, OUT = paths.DATASET, paths.REPORTS, ROOT / "paper" / "assets" / "numbers.tex"
DRAW = "strat"
WORDS = "Zero One Two Three Four Five Six Seven Eight Nine".split()
ARTIFACT = "https://github.com/saai-syvendra/TRIPWIRE"
ARTIFACT_DOI = None  # the Zenodo version DOI of the v1.0.0 release; renders as \pending until it is set
REVIEWERS = ("claude-sonnet-5-5", "gpt-6.1-sol")  # the pair that reviewed the most claims in common


def jsonl(name: str) -> list[dict]:
    p = DATASET / f"{name}.jsonl"
    return [json.loads(line) for line in p.open(encoding="utf-8")] if p.is_file() else []


def table(name: str, root: Path = DATASET / "tables") -> list[dict]:
    p = root / name
    return list(csv.DictReader(p.open(encoding="utf-8"))) if p.is_file() else []


def spell(text: str) -> str:
    """A macro-safe CamelCase name: digits spelled, other characters dropped."""
    out = "".join(WORDS[int(ch)] if ch.isdigit() else ch for ch in text)
    return "".join(part[:1].upper() + part[1:] for part in re.split(r"[^A-Za-z]+", out) if part)


def pct(x, digits: int = 1) -> str | None:
    return None if x in (None, "") else f"{100 * float(x):.{digits}f}\\%"


def share(n: int, d: int) -> str | None:
    return pct(n / d, 0) if d else None


def main() -> int:
    rows = {n: jsonl(n) for n in ("packages", "gates", "members", "skipped", "claims")}
    if not rows["packages"]:
        raise SystemExit("dataset/ is empty: run tools/common/aggregate.py first")
    # the corpus figures count the malware; the benign control set is reported on its own below
    label = lambda r: (r.get("package") if isinstance(r.get("package"), dict) else r)["source_label"]  # noqa: E731
    packages, gates, members, skipped, claims = ([r for r in rows[n] if label(r) == "malicious"] for n in rows)
    m: dict[str, object] = {}

    # Dataset size and composition
    m["NSamples"] = len(packages) + len(members) + len(skipped)
    m["NPkgs"], m["NMembers"], m["NSkipped"] = len(packages), len(members), len(skipped)
    for eco in ("npm", "pypi"):
        m[f"N{spell(eco)}"] = sum(1 for p in packages if p["package"]["ecosystem"] == eco)
    for reason, n in Counter(s["reason"] for s in skipped).items():
        m[f"NSkip{spell(reason)}"] = n
    m["NCampaigns"] = len({p["package"]["cluster_key"] for p in packages})
    for model, n in Counter(p["package"]["model_name"] for p in packages).items():
        m[f"NAnalyst{spell(model.removeprefix('claude-'))}"] = n
    m["NPilotPkgs"] = sum(1 for p in packages if p.get("sample_id") == "pilot")
    m["NSamplesDraw"] = sum(1 for r in packages + members + skipped if r.get("sample_id") == DRAW)
    m["NSamplesPilot"] = sum(1 for r in packages + members + skipped if r.get("sample_id") == "pilot")

    # Gates and conditions (kept gates only, as the dataset tables count them)
    kept = [g for g in gates if g.get("verification", "ok") == "ok"]
    m["NGatesAll"], m["NGates"], m["NGatesExcluded"] = len(gates), len(kept), len(gates) - len(kept)
    m["NGated"] = len({g["key"] for g in kept})
    conds = [c for p in packages for c in p["conditions"]]
    m["NConds"], m["NCondInScope"] = len(conds), sum(1 for c in conds if c["in_scope"])
    pol = Counter(g["polarity"] for g in kept)
    m["NActivate"], m["NEvade"] = pol.get("activate", 0), pol.get("evade", 0)
    mins = Counter(g["then"]["min_conditions"] for g in kept)
    for k in range(1, 5):
        m[f"NMin{WORDS[k]}"] = mins.get(k, 0)
    m["NMinFivePlus"] = sum(n for k, n in mins.items() if k >= 5)
    m["NMinMax"] = max(mins) if mins else 0
    m["NGatesTwoBranch"] = sum(1 for g in kept if g["else"])
    m["NGatesSingleOs"] = sum(1 for g in kept if len(g["conditions"]) == 1 and g["conditions"][0]["category"] == "os")
    for eco in ("npm", "pypi"):  # registry or archive release dates, for questions over time
        m[f"NReleased{spell(eco)}"] = sum(1 for p in packages if p["package"]["ecosystem"] == eco
                                          and p["package"].get("released_at"))
    by_campaign: dict[str, set] = {}
    for g in kept:
        by_campaign.setdefault(g["cluster_key"], set()).add(g["polarity"])
    m["NCampGated"] = len(by_campaign)
    m["NCampActivate"] = sum(1 for v in by_campaign.values() if "activate" in v)
    m["NCampEvade"] = sum(1 for v in by_campaign.values() if "evade" in v)
    m["NCampEvadeOnly"] = sum(1 for v in by_campaign.values() if v == {"evade"})

    # Evidence model
    derivations = [d for p in packages for d in p["normalisation"]["derivations"]]
    m["NDerivations"] = len(derivations)
    m["NDerivPkgs"] = sum(1 for p in packages if p["normalisation"]["derivations"])
    for recipe, n in Counter(d["recipe"] for d in derivations).items():
        m[f"NDeriv{spell(recipe)}"] = n
    m["NDecodeSpecPkgs"] = sum(1 for p in packages if any(d["recipe"] == "decode_spec"
                                                          for d in p["normalisation"]["derivations"]))
    m["NDecoders"] = sum(1 for f in (ROOT / "tools" / "common" / "decoders").glob("*.py")
                         if f.stem not in ("__init__", "example_xor"))
    m["NCondDerived"] = sum(1 for c in conds if c["sites"] and all(s["anchor"]["derived_from"] for s in c["sites"]))
    m["NGatesDerived"] = sum(1 for g in kept if g["guards"] and all(q["site"]["derived_from"] for q in g["guards"]))
    cc = [p["candidate_check"] for p in packages if "candidate_check" in p]
    tot = lambda k: sum(c[k] for c in cc)  # noqa: E731
    m["NCondInSet"], m["NCondOutSet"] = tot("conditions_in_set"), tot("conditions_out_of_set")
    m["NGateInSet"], m["NGateOutSet"] = tot("gates_in_set"), tot("gates_out_of_set")
    m["PctCondOutSet"] = share(m["NCondOutSet"], m["NCondInSet"] + m["NCondOutSet"])
    m["PctGateOutSet"] = share(m["NGateOutSet"], m["NGateInSet"] + m["NGateOutSet"])
    m["NCandDropped"], m["NRefusals"] = tot("candidates_dropped"), tot("anchor_refusals")

    # Prevalence over the draw (design-weighted), and its non-response
    prev = {(r["ecosystem"], r["stratum"], r["denominator"], r["measure"]): r
            for r in table("prevalence.csv") if r["sample_id"] == DRAW}
    for eco in ("npm", "pypi"):
        for denom, dn in (("all_drawn", "All"), ("install_code", "Code")):
            for measure, mn in (("gated", ""), ("gated_in_scope", "Scope"), ("gated_env", "Env"),
                                ("gated_not_absence", "NotAbsence")):
                r = prev.get((eco, "all", denom, measure))
                base = f"Prev{spell(eco)}{dn}{mn}"
                m[base] = pct(r["share"]) if r else None
                m[base + "CI"] = f"{pct(r['ci_low'])}--{pct(r['ci_high'])}" if r and r["ci_low"] else None
                # refused names counted as all ungated / all gated; the interval with the top campaigns as one
                m[base + "Bounds"] = (f"{pct(r['bound_low'])}--{pct(r['bound_high'])}"
                                      if r and r.get("bound_low") else None)
                m[base + "CIMerged"] = (f"{pct(r['ci_low_merged'])}--{pct(r['ci_high_merged'])}"
                                        if r and r.get("ci_low_merged") else None)
        r = prev.get((eco, "all", "campaigns", "gated"))  # every install-code campaign once
        m[f"Prev{spell(eco)}Camp"] = pct(r["share"]) if r else None
        m[f"Prev{spell(eco)}CampCI"] = f"{pct(r['ci_low'])}--{pct(r['ci_high'])}" if r and r["ci_low"] else None
        m[f"NCamp{spell(eco)}"], m[f"NCamp{spell(eco)}Gated"] = (int(r["units"]), int(r["positives"])) if r else (None, None)
        m[f"Prev{spell(eco)}HalfCamps"] = int(r["half_campaigns"]) if r and r["half_campaigns"] else None
        m[f"Prev{spell(eco)}TopCamp"] = pct(r["top_campaign_share"], 0) if r and r["top_campaign_share"] else None
        r = prev.get((eco, "all", "all_drawn", "gated"))
        m[f"NDrawn{spell(eco)}"] = int(r["drawn"]) if r else None
        m[f"NNonresp{spell(eco)}"] = int(r["nonresponse"]) if r else None
    # per stratum and per label (strata split by year are also summed per label): the gated share of names with
    # install code, and the share of the ecosystem's weighted install-code names each one holds
    for eco in ("npm", "pypi"):
        parts = {r["stratum"]: r for (e, h, d, ms), r in prev.items()
                 if e == eco and d == "install_code" and ms == "gated" and h != "all"}
        base = [h for h in parts if not any(k.startswith(h + "/") for k in parts)]  # not a per-label total
        mass = {h: int(parts[h]["names"]) * int(parts[h]["units"]) / int(parts[h]["responding"])
                for h in base if int(parts[h]["responding"])}
        for h, r in parts.items():
            if not r["share"]:
                continue
            m[f"Prev{spell(eco)}Code{spell(h)}"] = pct(r["share"])
            m[f"Prev{spell(eco)}Code{spell(h)}CI"] = f"{pct(r['ci_low'])}--{pct(r['ci_high'])}" if r["ci_low"] else None
            own = [k for k in mass if k == h or k.startswith(h + "/")]
            m[f"Pct{spell(eco)}CodeWeight{spell(h)}"] = share(round(sum(mass[k] for k in own)),
                                                              round(sum(mass.values()))) if own else None
    # non-response by reason, both ecosystems (no record at all, or a member whose campaign has no representative)
    reasons = Counter()
    for eco in ("npm", "pypi"):
        r = prev.get((eco, "all", "all_drawn", "gated"))
        for part in filter(None, (r or {}).get("nonresponse_reasons", "").split(";")):
            name, n = part.split("=")
            reasons[name] += int(n)
    m["NNoRecord"], m["NMemberUnrep"] = reasons.get("no_record", 0), reasons.get("member_unrepresented", 0)
    m["NNonrespTotal"] = sum(reasons.values())
    draw_manifest = json.loads((REPORTS / "_draws" / f"{DRAW}.json").read_text(encoding="utf-8"))
    m["NDrawn"], m["DrawSeed"] = len(draw_manifest["items"]), draw_manifest["seed"]

    # npm malicious-intent names with install code in the draw: how many gate, and what the ungated ones are
    attack = {p["package"]["cluster_key"]: p["attack_type"] for p in packages}
    gated_keys = {g["cluster_key"] for g in kept}
    mi = [r.get("package", r)["cluster_key"] for r in packages + members
          if r.get("sample_id") == DRAW and r.get("package", r)["ecosystem"] == "npm"
          and str(r.get("stratum", "")).startswith("malicious_intent") and r.get("package", r)["cluster_key"] in attack]
    m["NNpmIntentCode"], m["NNpmIntentUngated"] = len(mi), sum(1 for ck in mi if ck not in gated_keys)
    m["NNpmIntentUngatedDepConf"] = sum(1 for ck in mi if ck not in gated_keys and attack[ck] == "dependency_confusion")

    # Verification as it stands 
    status = Counter(c["final"] for c in claims)
    m["NClaims"], m["NClaimRecords"] = len(claims), len({c["package"] for c in claims})
    for s in ("verified", "refuted", "disputed"):
        m[f"NClaims{spell(s)}"] = status.get(s, 0)
    m["NClaimsOpen"] = sum(status.get(s, 0) for s in ("unanchored", "cannot_tell", "unverified"))
    m["PctClaimsVerified"] = share(status.get("verified", 0), len(claims))
    settled = sum(1 for c in claims if c["final_source"] == "deterministic" and c["final"] in ("verified", "refuted"))
    m["PctResidual"] = share(len(claims) - settled, len(claims))

    for r in table("verif_by_layer.csv"):
        if r["subset"] == "label:malicious":
            L = spell(r["layer"])
            m[f"Ver{L}Claims"], m[f"Ver{L}Verified"] = int(r["claims"]), int(r["verified"])
            m[f"Ver{L}Refuted"] = int(r["refuted"]) + int(r["disputed"])
            m[f"Ver{L}Open"] = int(r["unanchored"]) + int(r["cannot_tell"]) + int(r["unverified"])

    excl = [c for c in claims if c["claim_id"].endswith(".excl")]
    m["VerLThreeExclClaims"] = len(excl)
    m["VerLThreeExclVerified"] = sum(1 for c in excl if c["final"] == "verified")
    m["VerLThreeExclRefuted"] = sum(1 for c in excl if c["final"] in ("refuted", "disputed"))
    m["VerLThreeExclOpen"] = sum(1 for c in excl if c["final"] in ("unanchored", "cannot_tell", "unverified"))

    verdicts = jsonl("verdicts")
    current = {(c["package"], c["claim_id"]) for c in claims}
    family = lambda v: "gpt" if v["by"].startswith("gpt") else "claude"  # noqa: E731
    seen, decided = {}, {}
    for v in verdicts:
        k = (v["package"], v["claim_id"])
        if k in current and v["method"] == "agent":
            seen.setdefault(k, set()).add(family(v))
            if v["verdict"] in ("verified", "refuted"):
                decided.setdefault(k, set()).add(family(v))
    m["NClaimsGptSeen"] = sum(1 for f in seen.values() if "gpt" in f)
    m["NClaimsGptDecided"] = sum(1 for f in decided.values() if "gpt" in f)
    m["PctClaimsGptDecided"] = share(m["NClaimsGptDecided"], len(claims))
    m["NClaimsBothDecided"] = sum(1 for f in decided.values() if len(f) == 2)
    m["PctClaimsBothDecided"] = share(m["NClaimsBothDecided"], len(claims))
    m["PctClaimsDet"] = share(sum(1 for c in claims if c["final_source"] == "deterministic"), len(claims))

    # The checker as the one reference that is not an LLM: on the claims it decided, how often the reviewers agree
    final_of = {(c["package"], c["claim_id"]): c["final"] for c in claims}
    det = {(v["package"], v["claim_id"]): v["verdict"] for v in verdicts
           if v["method"] == "deterministic" and (v["package"], v["claim_id"]) in current}
    agent_on = {}
    for v in verdicts:
        k = (v["package"], v["claim_id"])
        if v["method"] == "agent" and det.get(k) in ("verified", "refuted"):
            agent_on.setdefault(k, []).append(v)
    for fam, fn in (("claude", "Claude"), ("gpt", "Gpt")):
        on_ver = [v for k, vs in agent_on.items() if det[k] == "verified" for v in vs if family(v) == fam]
        m[f"NDetVerAgent{fn}"] = len(on_ver)
        m[f"PctDetVerAgree{fn}"] = pct(sum(v["verdict"] == "verified" for v in on_ver) / len(on_ver)) if on_ver else None
    refuted = [k for k, d in det.items() if d == "refuted"]
    m["NDetRefuted"] = len(refuted)
    m["NDetRefutedAgentRefuted"] = sum(1 for k in refuted if any(v["verdict"] == "refuted" for v in agent_on.get(k, [])))
    m["NDetRefutedAgentVerified"] = sum(1 for k in refuted if any(v["verdict"] == "verified" for v in agent_on.get(k, [])))
    m["NDetRefutedContested"] = sum(1 for k in refuted if final_of[k] in ("refuted", "disputed"))
    repair_of = {(c["package"], c["claim_id"]): c.get("repair") for c in claims}
    m["NDetRefutedRepairRejected"] = sum(1 for k in refuted if repair_of.get(k) == "rejected")

    # Repair: every decision logged, what still stands, and what the strict gate rule costs
    history = verification.repair_history(REPORTS)
    for d in ("fixed", "rejected", "escalated", "cleared", "kept_flag"):
        m[f"NRepair{spell(d)}"] = history.get(d, 0)
    m["NClaimsRejected"] = sum(1 for c in claims if c.get("repair") == "rejected")
    m["NClaimsRejectedGpt"] = sum(1 for c in claims if c.get("repair") == "rejected" and (c["package"], c["claim_id"])
                                  in {(v["package"], v["claim_id"]) for v in verdicts
                                      if v["method"] == "agent" and family(v) == "gpt" and v["verdict"] == "refuted"})
    m["NClaimsNoRepair"] = len(verification.open_refutations(claims))
    m["NGatesRejectedOnly"] = sum(1 for g in gates if g.get("rejected_only"))
    m["NGatesWithRejected"] = m["NGates"] + m["NGatesRejectedOnly"]
    blocking = {}
    for c in claims:
        if c["layer"] in ("L1", "L2", "L3", "L4") and not c["claim_id"].endswith(".excl"):
            blocking.setdefault(c["package"], {}).setdefault(c["claim_id"].split(".")[0], []).append(c["final"])
    m["NGatesAllVerified"] = sum(
        1 for g in kept if all(f == "verified" for i in [g["gate_id"], *(x["id"] for x in g["conditions"])]
                               for f in blocking.get(g["key"], {}).get(i, [])))
    with_rejected = {(r["ecosystem"], r["denominator"]): r for r in table("prevalence_with_rejected.csv")
                     if r["sample_id"] == DRAW and r["stratum"] == "all" and r["measure"] == "gated"}
    for eco in ("npm", "pypi"):
        r = with_rejected.get((eco, "install_code"))
        m[f"Prev{spell(eco)}CodeWithRejected"] = pct(r["share"]) if r else None

    all_gates = {(r["ecosystem"], r["denominator"]): r for r in table("prevalence_all_gates.csv")
                 if r["sample_id"] == DRAW and r["stratum"] == "all" and r["measure"] == "gated"}
    for eco in ("npm", "pypi"):
        r = all_gates.get((eco, "install_code"))
        m[f"Prev{spell(eco)}CodeAllGates"] = pct(r["share"]) if r else None
    # excluded gates whose contested claims the repair pass has not decided yet
    undecided = {(c["package"], c["claim_id"].split(".")[0]) for c in claims if c["final"] in ("refuted", "disputed")
                 and c.get("repair") is None and c["layer"] in ("L1", "L2", "L3", "L4")
                 and not c["claim_id"].endswith(".excl")}
    excluded = [g for g in gates if g.get("verification") == "excluded"]
    m["NGatesExcludedUndecided"] = sum(
        1 for g in excluded if (g["key"], g["gate_id"]) in undecided
        or any((g["key"], x["id"]) in undecided for x in g["conditions"]))
    # negatives and denominators that no verifier looked at
    with_claims = {c["package"] for c in claims}
    keyed = lambda p: f'{p["package"]["ecosystem"]}__{p["package"]["name"].replace("/", "__")}@{p["package"]["version"]}'  # noqa: E731
    m["NRecordsNoClaims"] = sum(1 for p in packages if not p["gates"] and keyed(p) not in with_claims)
    m["NSkipsAi"] = sum(1 for s_ in skipped if s_.get("analysis_type") == "ai")
    m["NSkipsAiDraw"] = sum(1 for s_ in skipped if s_.get("analysis_type") == "ai" and s_.get("sample_id") == DRAW)
    m["NRecordsNoGate"] = sum(1 for p in packages if not p["gates"])
    # exclusion by polarity: verification removes evasive gates more often
    for pol, pn in (("evade", "Evade"), ("activate", "Activate")):
        gp = [g for g in gates if g["polarity"] == pol]
        m[f"PctExcluded{pn}"] = share(sum(1 for g in gp if g.get("verification") == "excluded"), len(gp))

    # Table IV: malicious claims only, L3 exclusivity and L6 dropped candidates on rows of their own, and the two main
    # reviewers' agreement with its package-bootstrap interval (dataset/tables/agreement_by_row.csv)
    names = {"L1": "LOne", "L2": "LTwo", "L3": "LThree", "L3 excl.": "LThreeExcl", "L4": "LFour", "L5": "LFive",
             "L6 interp.": "LSixInterp", "L6 drop": "LSixDrop"}
    tab_k = []
    for r in table("agreement_by_row.csv"):
        g = names[r["row"]]
        m[f"Tab{g}Claims"], m[f"Tab{g}Ver"] = int(r["claims"]), int(r["verified"])
        m[f"Tab{g}Ref"], m[f"Tab{g}Disp"], m[f"Tab{g}Open"] = int(r["refuted"]), int(r["disputed"]), int(r["open"])
        m[f"Tab{g}Agr"] = pct(r["agree"], 0)
        m[f"Tab{g}Kappa"] = f"{float(r['kappa']):.2f}" if r["kappa"] else "--"
        if r["kappa"]:
            tab_k.append(float(r["kappa"]))
    m["TabKappaRange"] = f"{min(tab_k):.2f}--{max(tab_k):.2f}" if tab_k else None

    # Dropped candidates: the only look at false negatives. A contested drop is one a verifier says was a real gate.
    drops = [c for c in claims if c["claim_id"].endswith(".L6.drop")]
    m["NDrops"] = len(drops)
    m["NDropsContested"] = sum(1 for c in drops if c["final"] in ("refuted", "disputed"))
    analysed_clusters = {p["package"]["cluster_key"] for p in packages}
    m["NMembersNoRep"] = sum(1 for r in members if r.get("cluster_key") not in analysed_clusters)

    # Stock environments (blind spot) and the greedy merge
    for r in table("blindspot.csv"):
        if r["unit"] == "package" and r["weighting"] == f"draw:{DRAW}":
            p = spell(r["profile"])
            for c in ("open", "closed", "unknown", "not_expressible"):
                m[f"Blind{p}{spell(c)}"] = pct(r[f"share_{c}"])
        if r["unit"] == "campaign" and r["weighting"] == "none":
            p = spell(r["profile"])
            for c in ("open", "closed", "unknown", "not_expressible"):
                m[f"BlindCamp{p}{spell(c)}"] = pct(r[f"share_{c}"])
            m["NBlindCampaigns"], m["NCampNoPayload"] = int(r["units"]), int(r["no_payload"])
        if r["unit"] == "payload" and r["weighting"] == "none":
            m[f"BlindPay{spell(r['profile'])}Open"] = pct(r["share_open"])
            m["NPayloads"] = int(r["units"])
    pay = [r for r in jsonl("blindspot") if r["outcome"] == "closed"]
    for prof in sorted({r["profile"] for r in pay}):
        mine = [r for r in pay if r["profile"] == prof]
        # the OS closes a payload through its gate's recipe (os) or through the payload's own need (os_requirement)
        on_os = lambda r: bool({"os", "os_requirement"} & set(r.get("closed_on", [])))  # noqa: E731
        m[f"BlindPay{spell(prof)}ClosedOs"] = share(sum(1 for r in mine if on_os(r)), len(mine))
        m[f"BlindPay{spell(prof)}ClosedOsOnly"] = share(sum(1 for r in mine if on_os(r) and set(r["closed_on"])
                                                            <= {"os", "os_requirement"}), len(mine))
        m[f"NPay{spell(prof)}ClosedOsRequirement"] = sum(1 for r in mine if "os_requirement" in r["closed_on"])
    # campaigns a Windows runner opens that no Linux or macOS profile does, and what OpenSSF and Windows open together
    by_camp: dict[str, dict[str, list]] = {}
    for r in jsonl("blindspot"):
        by_camp.setdefault(r["cluster_key"], {}).setdefault(r["profile"], []).append(r["outcome"])
    opens = lambda ck, prof: "open" in by_camp[ck].get(prof, [])  # noqa: E731 - a campaign opens on any payload
    if by_camp and all("github-windows" in v for v in by_camp.values()):
        others = {p for v in by_camp.values() for p in v} - {"github-windows"}
        m["NCampOnlyWindows"] = sum(1 for ck in by_camp if opens(ck, "github-windows")
                                    and not any(opens(ck, q) for q in others))
        m["BlindCampOssfOrWindowsOpen"] = pct(sum(1 for ck in by_camp if opens(ck, "github-windows")
                                                  or opens(ck, "ossf-package-analysis")) / len(by_camp))
        # the same count over campaigns with a name in the random draw (the pilot was taken alphabetically)
        draw_ck = {r.get("package", r)["cluster_key"] for r in packages + members if r.get("sample_id") == DRAW}
        m["NCampOnlyWindowsDraw"] = sum(1 for ck in by_camp if ck in draw_ck and opens(ck, "github-windows")
                                        and not any(opens(ck, q) for q in others))
        m["NBlindCampaignsDraw"] = sum(1 for ck in by_camp if ck in draw_ck)
    # profiles that never differ: the same outcome on every payload
    outcome_by = {}
    for r in jsonl("blindspot"):
        outcome_by.setdefault(r["profile"], {})[(r["key"], r["gate_id"], r["branch"])] = r["outcome"]
    if {"ossf-package-analysis", "docker-default"} <= set(outcome_by):
        a, b = outcome_by["ossf-package-analysis"], outcome_by["docker-default"]
        m["NPayloadsOssfDockerDiffer"] = sum(1 for k in a if a[k] != b.get(k))
    merged = [r for r in table("blindspot_merge.csv") if r["kind"] == "merged"]
    if merged:
        m["NMergeEnvs"], m["NMergeBuildable"] = len(merged), int(merged[-1]["buildable"])
        m["MergeFirstShare"] = pct(merged[0]["share"])
        m["MergeHalfEnvs"] = next((int(r["environments"]) for r in merged if float(r["share"]) >= 0.5), None)
        # the same merge counted in gated campaigns, as Fig. 3 plots it next to the profiles' campaign shares
        m["MergeCampFirstShare"], m["MergeCampTwoShare"] = pct(merged[0]["campaign_share"]), pct(merged[1]["campaign_share"])
        m["MergeCampMaxShare"], m["NMergeCampMax"] = pct(merged[-1]["campaign_share"]), int(merged[-1]["campaigns_opened"])

    # Agreement between the two families, per layer, on every claim both reviewers judged
    pair = f"{REVIEWERS[0]} vs {REVIEWERS[1]}"
    kappas = []
    for r in table("kappa.csv"):
        if r["comparison"] == pair:
            L = spell(r["layer"])
            m[f"Agr{L}"], m[f"Kappa{L}"] = pct(r["agree"], 0), f"{float(r['kappa']):.2f}" if r["kappa"] else None
            if r["kappa"]:
                kappas.append(float(r["kappa"]))
    m["KappaRange"] = f"{min(kappas):.2f}--{max(kappas):.2f}" if kappas else None

    # Benign control set
    benign = REPORTS / "_draws" / "benign.json"
    m["NBenign"] = len(json.loads(benign.read_text())["items"]) if benign.is_file() else None
    benign_pkgs = [p for p in rows["packages"] if p["package"]["source_label"] == "benign"]
    m["NBenignAnalysed"] = len(benign_pkgs) if benign_pkgs else None
    m["NBenignSkipped"] = sum(1 for r in rows["skipped"] if label(r) == "benign")
    m["NBenignMembers"] = sum(1 for r in rows["members"] if label(r) == "benign")
    benign_kept = [g for g in rows["gates"] if g["source_label"] == "benign" and g.get("verification", "ok") == "ok"]
    m["NBenignGated"] = len({g["key"] for g in benign_kept}) if benign_pkgs else None
    m["NBenignGates"] = len(benign_kept) if benign_pkgs else None
    # which axes gates test, as a share of kept gates per label (a gate counts once per category it tests)
    for lab, gs in (("Mal", kept), ("Benign", benign_kept)):
        for cat in ("env_var", "package_manager", "consuming_app", "os", "target_artifact"):
            n = sum(1 for g in gs if any(c["category"] == cat for c in g["conditions"]))
            m[f"PctGates{lab}{spell(cat)}"] = share(n, len(gs)) if benign_pkgs or lab == "Mal" else None
    m["ArtifactURL"] = f"\\url{{{ARTIFACT}}}"
    m["ArtifactDOI"] = f"\\href{{https://doi.org/{ARTIFACT_DOI}}}{{{ARTIFACT_DOI}}}" if ARTIFACT_DOI else None

    lines = ["% Generated by paper/make_numbers.py from dataset/ and reports/. Do not edit.",
             "\\providecommand{\\pending}[1]{\\textcolor{red}{\\textbf{[#1]}}}", ""]
    for name in sorted(m):
        v = m[name]
        if isinstance(v, int) and v >= 1000 and not name.endswith("Seed"):
            v = f"{v:,}".replace(",", "{,}")
        lines.append(f"\\newcommand{{\\{name}}}{{" + (f"\\pending{{{name}}}" if v is None else f"{v}") + "}")
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(m)} macros, {sum(v is None for v in m.values())} pending")
    return 0


if __name__ == "__main__":
    sys.exit(main())
