"""
The claims a record makes, one per verifiable statement, in a fixed order. A verdict names a claim by id and by
claim_sha256, a hash over exactly the fields the claim rests on, so re-analysing a record makes old verdicts
stale instead of silently re-attaching them.

Layers:
  L1  the condition's test exists at every cited site                         (deterministic)
  L2  the compared value and positive-form operator are what the code tests   (deterministic)
  L3  the branch's payload is reached from code the gate's guards control     (deterministic)
      .excl: the payload is reached only through that branch                  (graded)
  L4  the expression and min_conditions match how the guards combine         (graded)
  L5  the branch's behaviours rest on sinks of a matching kind                (graded)
  L6  interpretation: category, polarity, effect, purpose, and for each prefilled candidate the analyst
      dropped, that it really is not part of a gate (`<k_|q_ id>.L6.drop`)  (agent only)
"""
from __future__ import annotations

import json
import re

from tools.common.anchors import digest
from tools.common.contract import COND_ID

LAYERS = ("L1", "L2", "L3", "L4", "L5", "L6")
DETERMINISTIC_LAYERS = {"L1", "L2", "L3", "L4", "L5"}
JUDGEMENT_ONLY = {"L6"}
VERDICTS = ("verified", "refuted", "unanchored", "cannot_tell")
GRADED = {"L4": ("consistent", "inconsistent", "cannot_tell"), "L5": ("consistent", "inconsistent", "cannot_tell"),
          "excl": ("exclusive", "non_exclusive", "unknown")}
CLAIM_ID = re.compile(r"^(c\d+\.L[12]|c\d+\.L6\.category|g\d+\.L4|g\d+\.L6\.(polarity|effect|purpose)"
                      r"|g\d+\.(then|else)\.L[35](\.excl)?|[kq]_[0-9a-f]{10}\.L6\.drop)$")


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def record_sha(rec: dict) -> str:
    return digest(canonical(rec).encode())


def layer_of(claim_id: str) -> str:
    return re.search(r"L\d", claim_id).group(0)


def grade_kind(claim_id: str) -> str | None:
    if claim_id.endswith(".excl"):
        return "excl"
    return layer_of(claim_id) if layer_of(claim_id) in ("L4", "L5") else None


def _claim(claim_id: str, subject: str, fields: dict, provenance: str) -> dict:
    return {"claim_id": claim_id, "layer": layer_of(claim_id), "subject": subject, "fields": fields,
            "provenance": provenance, "claim_sha256": digest(canonical({"id": claim_id, "fields": fields}).encode())}


def _cond_brief(c: dict) -> dict:
    return {k: c[k] for k in ("id", "category", "api", "operator", "value")}


def enumerate_claims(rec: dict) -> list[dict]:
    """Every claim of an analysed record, conditions first (c1, c2, ...) then gates, in natural id order."""
    if rec.get("record_type") != "analysed":
        return []
    out = []
    conds = {c["id"]: c for c in rec["conditions"]}
    natural = lambda i: int(i[1:])  # noqa: E731
    for cid in sorted(conds, key=natural):
        c = conds[cid]
        sites = [s["anchor"] for s in c["sites"]]
        prov = c.get("provenance", "out_of_set")
        probe = {"probe": c["probe"]} if c.get("probe") else {}
        # every field a check reads is part of its claim, so changing any of them leaves the old verdicts stale:
        # L1 holds a decoded site open (value_recovered); L2 normalises values by category
        out.append(_claim(f"{cid}.L1", cid, {"category": c["category"], "api": c["api"], "sites": sites, **probe,
                                             "value_recovered": c["value_recovered"]}, prov))
        if c["value_recovered"] != "not_recovered":
            # the operator is read in the sense of the guards that test the condition, so their kind, arm and site
            # are part of the claim (an arm fix changes it, and leaves the old verdicts stale)
            tested_by = [{k: gd.get(k) for k in ("kind", "arm", "site")} for g in rec.get("gates", [])
                         for gd in g.get("guards") or [] if cid in gd.get("conditions", [])]
            out.append(_claim(f"{cid}.L2", cid, {
                "api": c["api"], "operator": c["operator"], "value": c["value"], "value_recovered": c["value_recovered"],
                "category": c["category"], "sites": sites, "value_site": c.get("value_site"), **probe,
                **({"guards": tested_by} if tested_by else {})},
                prov))
        out.append(_claim(f"{cid}.L6.category", cid, _cond_brief(c), prov))
    from tools.common.contract import iter_anchors  # the same file set witness.check_exclusive scans
    record_files = [list(x) for x in sorted({(a["file"], a.get("derived_from") or "") for _, a in iter_anchors(
        {k: v for k, v in rec.items() if k in ("conditions", "gates")})})]
    for g in sorted(rec["gates"], key=lambda g: natural(g["gate_id"])):
        gid, prov = g["gate_id"], g.get("provenance", "out_of_set")
        used = [_cond_brief(conds[i]) for i in dict.fromkeys(COND_ID.findall(g["expression"])) if i in conds]
        for name in ("then", "else"):
            br = g.get(name)
            if br is None or g["hook"] == "resolve":
                continue
            if br.get("payload"):
                l3 = {"guards": g["guards"], "regions": br["regions"], "payload": br["payload"], "branch": name,
                      **({"requires": br["requires"]} if br.get("requires") else {})}
                out.append(_claim(f"{gid}.{name}.L3", gid, l3, prov))
                # exclusivity scans every file the record cites for other callers
                out.append(_claim(f"{gid}.{name}.L3.excl", gid, {**l3, "record_files": record_files}, prov))
            if br["behaviours"]:
                out.append(_claim(f"{gid}.{name}.L5", gid, {
                    "behaviours": br["behaviours"], "payload": br.get("payload", []), "regions": br.get("regions", [])},
                    prov))
        if g["hook"] != "resolve":
            # how the guards combine is read over the branch regions, so they are part of the claim (a region fix
            # changes it, and leaves the old verdicts stale)
            out.append(_claim(f"{gid}.L4", gid, {
                "expression": g["expression"], "guards": g["guards"], "conditions": used,
                "condition_sites": {i: [s["anchor"] for s in conds[i]["sites"]]
                                    for i in dict.fromkeys(COND_ID.findall(g["expression"])) if i in conds},
                "then_min": g["then"]["min_conditions"], "then_regions": g["then"].get("regions", []),
                "else_min": g["else"]["min_conditions"] if g.get("else") else None,
                "else_regions": g["else"].get("regions", []) if g.get("else") else None}, prov))
        brief = {"expression": g["expression"], "conditions": used,
                 "then_behaviours": g["then"]["behaviours"],
                 "else_behaviours": g["else"]["behaviours"] if g.get("else") else None}
        for aspect in ("polarity", "effect", "purpose"):
            out.append(_claim(f"{gid}.L6.{aspect}", gid, {**brief, aspect: g[aspect]}, prov))
    for d in (rec.get("candidate_review") or {}).get("dropped", []):
        out.append(_claim(f"{d['candidate']}.L6.drop", d["candidate"],
                          {"candidate": d["candidate"], "anchor": d.get("anchor"), "reason_code": d["reason_code"],
                           "note": d.get("note")}, "in_set"))
    return out
