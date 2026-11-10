"""
Joins records to the sample manifests in reports/_draws/ and estimates gate prevalence over each draw, weighted by
design (paper/sampling.md, Estimates).

Join: a record belongs to the manifest item with the same ecosystem and archive file name, else the same name
(PEP 503 for PyPI) and version, else (records named after their archive, such as unreadable wheels) the item whose
file stem is the record's name, else the same name when the item's path carries no version. A draw wins over the pilot manifest. Records no manifest holds are labelled pilot.

Estimate, per draw: a drawn name is a respondent with a record (analysed, member or skip) or a non-response (no
record, an unreadable archive, a member whose campaign has no analysed representative). A member takes its
representative's labels. Gated: at least one gate the verification join keeps (`verification` ok); gated in scope:
such a gate with an in-scope condition; gated on the environment: such a gate with an in-scope condition that is not
a target artifact (the narrower sense in which earlier studies count environment checks); gated beyond absence: a
kept gate with a condition other than a check that a file is absent (such a check passes on any fresh machine). Two
denominators: every responding name, and the names with install-time code (analysed and members). In stratum h a
respondent counts N_h / r_h (r_h respondents); the ecosystem share is the weighted ratio over the strata with a
weight. Intervals are percentile bootstraps that resample whole campaigns (respondents sharing a cluster_key; a skip
is its own) within each stratum, since one campaign can fill a large share of a stratum and its names are not
independent; a campaign drawn in two strata is resampled in each. Strata that split one label by year
(`compromised_lib/2025`, ...) also get a total per label (`compromised_lib`).

Two checks on each ecosystem total. Non-response bounds recompute the share with every non-responding drawn name
counted as install-code and gated (high) or install-code and ungated (low), since refusals are not missing at
random. The merged interval repeats the bootstrap with the campaigns that hold half the weighted gated names folded
into one cluster, for when those campaigns are one family under several cluster keys.

Per campaign, per ecosystem: every campaign with a responding name in a weighted stratum counts once, unweighted,
over the install-code respondents (denominator `campaigns`), with a bootstrap over campaigns. `concentration`
gives the fewest campaigns that hold half the weighted gated names. Pure functions; deterministic for a given
seed.
"""
from __future__ import annotations

import csv
import random
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

from tools.common.contract import normalise_name

SEED = 20261024
REPLICATES = 2000
ARCHIVE_EXT = (".tar.gz", ".tgz", ".tar.bz2", ".zip", ".whl", ".egg", ".tar")
NO_INSTALL_CODE = {"no_install_code", "import_time_only", "payload_in_dependency", "not_a_package"}
NONRESPONSE_SKIPS = {"files_missing", "duplicate"}
MEASURES = ("gated", "gated_in_scope", "gated_env", "gated_not_absence")
DENOMINATORS = ("all_drawn", "install_code")
CAMPAIGNS = "campaigns"


def stem(file_name: str) -> str:
    low = file_name.lower()
    return next((file_name[:-len(e)] for e in ARCHIVE_EXT if low.endswith(e)), file_name)


def item_name_version(item: dict) -> tuple[str, str | None]:
    """(name as the registry spells it, version or None) of a manifest item. Datadog folds `@scope/name` into one
    path segment `@scope@name` and keeps the version as a folder (`samples/<eco>/<label>/<name>/<version>/<file>`),
    though some archives sit straight under the name; pypi_malregistry paths are `<name>/<version>/<file>`."""
    name = item["name"]
    if item["ecosystem"] == "npm" and name.startswith("@") and "@" in name[1:]:
        name = "@" + name[1:].replace("@", "/", 1)
    parts = PurePosixPath(item["path"]).parts
    if item.get("dataset") == "datadog":
        return name, parts[4] if len(parts) >= 6 else None
    return name, parts[-2] if len(parts) >= 3 else None


def join_keys(manifests: dict[str, dict]) -> list[tuple[str, dict]]:
    """Per manifest (draws first, the pilot last): sample id and its key -> item index."""
    out = []
    for sid in sorted(manifests, key=lambda s: (s == "pilot", s)):
        keys = {}
        for item in manifests[sid]["items"]:
            eco, file = item["ecosystem"], PurePosixPath(item["path"]).name
            name, version = item_name_version(item)
            for k in (("file", eco, file), ("nv", eco, normalise_name(eco, name), version), ("stem", eco, stem(file)),
                      *([("name", eco, normalise_name(eco, name))] if version is None else [])):
                keys.setdefault(k, item)
        out.append((sid, keys))
    return out


def match(pk: dict, keyed: list[tuple[str, dict]]) -> tuple[str, dict] | None:
    eco = pk.get("ecosystem")
    wanted = []
    if pk.get("sample_path"):
        wanted.append(("file", eco, PurePosixPath(pk["sample_path"]).name))
    if pk.get("version"):
        wanted.append(("nv", eco, normalise_name(eco or "", pk["name"]), pk["version"]))
    wanted += [("stem", eco, pk["name"]), ("name", eco, normalise_name(eco or "", pk["name"]))]
    for sid, keys in keyed:
        for k in wanted:
            if k in keys:
                return sid, keys[k]
    return None


def label_rows(manifests: dict[str, dict], rows: list[tuple[str, dict]]) \
        -> tuple[dict[tuple, tuple], list[str], int]:
    """Adds sample_id, stratum and weight to each (record type, row) row: a dict with its record's `package`, or
    the package itself. Returns (manifest item -> (record type, row), problems, rows no manifest holds); two
    records on one drawn item are a problem."""
    keyed = join_keys(manifests)
    taken, problems, unmatched = {}, [], 0
    for kind, row in rows:
        pk = row.get("package", row)
        hit = match(pk, keyed)
        if hit is None:
            row.update(sample_id="pilot", stratum="pilot", weight=None)
            unmatched += 1
            continue
        sid, item = hit
        row.update(sample_id=sid, stratum=item["stratum"], weight=item.get("weight"))
        k = (sid, item["path"])
        if k in taken and sid != "pilot":
            problems.append(f"{sid}: {item['path']} matches two records "
                            f"({taken[k][1].get('package', taken[k][1])['name']}, {pk['name']})")
        taken.setdefault(k, (kind, row))
    return taken, problems, unmatched


def units(manifest: dict, sid: str, taken: dict, labels_of: dict) -> list[dict]:
    """One unit per drawn item: ecosystem, stratum, status (`respondent` or a non-response reason), the record
    type, install_code, gated and gated_in_scope."""
    out = []
    for item in manifest["items"]:
        kind, row = taken.get((sid, item["path"]), (None, None))
        u = {"ecosystem": item["ecosystem"], "stratum": item["stratum"], "path": item["path"],
             "cluster_key": row.get("package", row).get("cluster_key") if row is not None else None, "record": None, "status": "no_record", "install_code": False, "gated": False, "gated_in_scope": False,
             "gated_env": False, "gated_not_absence": False}
        if row is not None:
            u["record"] = kind
            if kind == "skip":
                u["status"] = row["reason"] if row["reason"] in NONRESPONSE_SKIPS else "respondent"
            else:
                lab = labels_of.get(row.get("package", row).get("cluster_key"))
                if lab is None:
                    u["status"] = "member_unrepresented"
                else:
                    u.update(status="respondent", install_code=True, **lab)
        out.append(u)
    return out


def weights(manifest: dict, us: list[dict]) -> list[tuple[dict, float]]:
    """(unit, N_h / r_h) for each respondent in a stratum with a weight."""
    resp = defaultdict(list)
    for u in us:
        if u["status"] == "respondent":
            resp[(u["ecosystem"], u["stratum"])].append(u)
    out = []
    for r in manifest["strata"]:
        rs = resp.get((r["ecosystem"], r["stratum"]), [])
        if r.get("weight") is not None and rs:
            out += [(u, r["names"] / len(rs)) for u in rs]
    return out


def _share(groups: dict[str, list[dict]], frame: dict[str, int], measure: str, denom: str) -> float | None:
    num = den = 0.0
    for h, us in groups.items():
        if not us:
            continue
        w = frame[h] / len(us)
        num += w * sum(1 for u in us if u[measure])
        den += w * sum(1 for u in us if denom == "all_drawn" or u["install_code"])
    return num / den if den else None


def campaign_of(u: dict, merged: frozenset[str] = frozenset()) -> str:
    """The respondent's resampling cluster: its campaign, or one shared cluster for every campaign in `merged`."""
    key = u.get("cluster_key") or f"path:{u['path']}"
    return "merged:" if key in merged else key


def clusters(us: list[dict], merged: frozenset[str] = frozenset()) -> list[list[dict]]:
    """Respondents grouped by campaign, in a fixed order."""
    by = defaultdict(list)
    for u in us:
        by[campaign_of(u, merged)].append(u)
    return [by[k] for k in sorted(by)]


def interval(values: list[float]) -> tuple[float, float]:
    values = sorted(values)
    return values[int(0.025 * (len(values) - 1))], values[int(0.975 * (len(values) - 1))]


def estimate(groups: dict[str, list[dict]], frame: dict[str, int], measure: str, denom: str,
             seed: int = SEED, n: int = REPLICATES, merged: frozenset[str] = frozenset()) \
        -> tuple[float | None, tuple[float, float] | None]:
    """(weighted share, 95% percentile interval) over respondents grouped by stratum, frame[h] = N_h. Each
    replicate draws as many campaigns as stratum h holds, with replacement, and takes all their names; the
    campaigns in `merged` are drawn as one."""
    point = _share(groups, frame, measure, denom)
    if point is None:
        return None, None
    rng, values = random.Random(seed), []
    keys = sorted(h for h in groups if groups[h])
    cl = {h: clusters(groups[h], merged) for h in keys}
    for _ in range(n):
        v = _share({h: [u for _ in cl[h] for u in rng.choice(cl[h])] for h in keys}, frame, measure, denom)
        if v is not None:
            values.append(v)
    return point, interval(values) if values else None


def campaign_estimate(resp: list[dict], measure: str, seed: int = SEED, n: int = REPLICATES) \
        -> tuple[int, int, float | None, tuple[float, float] | None]:
    """(campaigns, positives, share, 95% interval) with every install-code campaign counted once."""
    camps = [c[0] for c in clusters([u for u in resp if u["install_code"]])]
    if not camps:
        return 0, 0, None, None
    pos = sum(1 for u in camps if u[measure])
    rng = random.Random(seed)
    values = [sum(1 for _ in camps if rng.choice(camps)[measure]) / len(camps) for _ in range(n)]
    return len(camps), pos, pos / len(camps), interval(values)


def concentration(groups: dict[str, list[dict]], frame: dict[str, int]) -> tuple[int, float] | None:
    """(the fewest campaigns holding half the weighted gated names, the share the largest one holds)."""
    weight = Counter()
    for h, us in groups.items():
        for u in us:
            if u["gated"]:
                weight[campaign_of(u)] += frame[h] / len(us)
    total = sum(weight.values())
    if not total:
        return None
    acc, k = 0.0, 0
    for _, w in sorted(weight.items(), key=lambda x: (-x[1], x[0])):
        acc, k = acc + w, k + 1
        if acc >= total / 2:
            break
    return k, max(weight.values()) / total


def top_campaigns(groups: dict[str, list[dict]], frame: dict[str, int]) -> frozenset[str]:
    """The fewest campaigns holding half the weighted gated names (the ones `concentration` counts)."""
    weight = Counter()
    for h, us in groups.items():
        for u in us:
            if u["gated"]:
                weight[campaign_of(u)] += frame[h] / len(us)
    total, acc, out = sum(weight.values()), 0.0, set()
    for key, w in sorted(weight.items(), key=lambda x: (-x[1], x[0])):
        if total and acc >= total / 2:
            break
        acc += w
        out.add(key)
    return frozenset(out)


def bounds(groups: dict[str, list[dict]], absent: dict[str, int], frame: dict[str, int], measure: str,
           denom: str) -> tuple[float | None, float | None]:
    """(low, high) share with the `absent[h]` non-responding names of each stratum counted as install-code names
    that are all ungated (low) or all gated (high); each stratum's weight spreads over respondents and absentees."""
    out = []
    for gated in (False, True):
        num = den = 0.0
        for h, us in groups.items():
            k = absent.get(h, 0)
            if not us and not k:
                continue
            w = frame[h] / (len(us) + k)
            num += w * (sum(1 for u in us if u[measure]) + (k if gated else 0))
            den += w * (sum(1 for u in us if denom == "all_drawn" or u["install_code"]) + k)
        out.append(num / den if den else None)
    return out[0], out[1]


def table(manifest: dict, sid: str, us: list[dict]) -> tuple[list[dict], list[str]]:
    """(rows of prevalence.csv for one draw, strata left out of the frame total)."""
    strata = {(r["ecosystem"], r["stratum"]): r for r in manifest["strata"]}
    by = defaultdict(list)
    for u in us:
        by[(u["ecosystem"], u["stratum"])].append(u)
    rows, left_out = [], []

    def emit(eco, stratum, N, members, groups, frame, checks=False):
        resp = [u for u in members if u["status"] == "respondent"]
        nonresp = Counter(u["status"] for u in members if u["status"] != "respondent")
        base = {"sample_id": sid, "ecosystem": eco, "stratum": stratum, "names": N, "drawn": len(members),
                "responding": len(resp), "nonresponse": sum(nonresp.values()),
                "nonresponse_reasons": ";".join(f"{k}={v}" for k, v in sorted(nonresp.items()))}
        for denom in DENOMINATORS:
            in_denom = [u for u in resp if denom == "all_drawn" or u["install_code"]]
            for measure in MEASURES:
                share, ci = estimate(groups, frame, measure, denom)
                row = {**base, "denominator": denom, "measure": measure, "units": len(in_denom),
                       "positives": sum(1 for u in in_denom if u[measure]), "share": share,
                       "ci_low": ci[0] if ci else None, "ci_high": ci[1] if ci else None}
                if checks:
                    absent = Counter(u["stratum"] for u in members if u["status"] != "respondent")
                    row["bound_low"], row["bound_high"] = bounds(groups, absent, frame, measure, denom)
                    _, mci = estimate(groups, frame, measure, denom, merged=top_campaigns(groups, frame))
                    row["ci_low_merged"], row["ci_high_merged"] = mci if mci else (None, None)
                rows.append(row)

    for eco in sorted({e for e, _ in strata}):
        weighted = {}
        for (e, h), r in sorted(strata.items()):
            if e != eco:
                continue
            members = by.get((e, h), [])
            resp = [u for u in members if u["status"] == "respondent"]
            if r.get("weight") is None or not resp:
                left_out.append(f"{eco} {h} (N={r['names']}, drawn {r['drawn']}, responding {len(resp)})")
                continue
            weighted[h] = (r["names"], members, resp)
            emit(eco, h, r["names"], members, {h: resp}, {h: r["names"]})
        labels = defaultdict(list)  # a label split by year, e.g. compromised_lib/2024 ... /2026
        for h in weighted:
            if "/" in h:
                labels[h.split("/", 1)[0]].append(h)
        for label, hs in sorted(labels.items()):
            if len(hs) > 1:
                emit(eco, label, sum(weighted[h][0] for h in hs), [u for h in hs for u in weighted[h][1]],
                     {h: weighted[h][2] for h in hs}, {h: weighted[h][0] for h in hs})
        if weighted:
            groups, frame = {h: resp for h, (_, _, resp) in weighted.items()}, {h: N for h, (N, _, _) in weighted.items()}
            members = [u for _, ms, _ in weighted.values() for u in ms]
            emit(eco, "all", sum(frame.values()), members, groups, frame, checks=True)
            resp = [u for g in groups.values() for u in g]
            conc = concentration(groups, frame)
            for measure in MEASURES:
                k, pos, share, ci = campaign_estimate(resp, measure)
                rows.append({**{c: rows[-1][c] for c in ("sample_id", "ecosystem", "stratum", "names", "drawn",
                                                         "responding", "nonresponse", "nonresponse_reasons")},
                             "denominator": CAMPAIGNS, "measure": measure, "units": k, "positives": pos,
                             "share": share, "ci_low": ci[0] if ci else None, "ci_high": ci[1] if ci else None,
                             "half_campaigns": conc[0] if conc and measure == "gated" else None,
                             "top_campaign_share": conc[1] if conc and measure == "gated" else None})
    return rows, left_out


COLUMNS = ["sample_id", "ecosystem", "stratum", "names", "drawn", "responding", "nonresponse", "nonresponse_reasons",
           "denominator", "measure", "units", "positives", "share", "ci_low", "ci_high", "half_campaigns",
           "top_campaign_share", "bound_low", "bound_high", "ci_low_merged", "ci_high_merged"]


def write_table(tables: Path, rows: list[dict], name: str = "prevalence.csv") -> None:
    tables.mkdir(parents=True, exist_ok=True)
    with open(tables / name, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else "" if v is None else v)
                        for k, v in {c: r.get(c) for c in COLUMNS}.items()})


def summary_lines(rows: list[dict], left_out: dict[str, list[str]]) -> list[str]:
    def pc(x):
        return "n/a" if x is None else f"{100 * x:.1f}%"
    out = ["## Prevalence over the draws (design-weighted)", "",
           "Per draw, from `reports/_draws/`. A respondent in stratum h counts N_h / r_h; the totals are weighted "
           "ratios over the strata with a weight. Gated: at least one gate the verification join keeps; in scope: "
           "such a gate with an in-scope condition. Intervals are 95% percentile bootstraps over whole campaigns "
           f"within each stratum ({REPLICATES} replicates, seed {SEED}); a stratum with few names or no positives "
           "gives a degenerate interval. Non-response is left out of every denominator and listed by reason. The "
           "pilot is not a draw and is never in these figures.", ""]
    for sid in sorted({r["sample_id"] for r in rows}):
        out += [f"### {sid}", "",
                "| ecosystem | stratum | N | drawn | responding | non-response | denominator | gated | gated, in scope |",
                "|---|---|---|---|---|---|---|---|---|"]
        cell = {(r["ecosystem"], r["stratum"], r["denominator"], r["measure"]): r for r in rows if r["sample_id"] == sid}
        for eco, stratum in dict.fromkeys((r["ecosystem"], r["stratum"]) for r in rows if r["sample_id"] == sid
                                          and r["denominator"] != CAMPAIGNS):
            for denom in DENOMINATORS:
                g, s = cell[(eco, stratum, denom, "gated")], cell[(eco, stratum, denom, "gated_in_scope")]

                def show(r):
                    ci = "" if r["ci_low"] is None else f" [{pc(r['ci_low'])}, {pc(r['ci_high'])}]"
                    return f"{pc(r['share'])}{ci} ({r['positives']}/{r['units']})"
                label = f"**{stratum}**" if stratum == "all" else stratum
                nr = f"{g['nonresponse']}" + (f" ({g['nonresponse_reasons']})" if g["nonresponse"] else "")
                out.append(f"| {eco} | {label} | {g['names']} | {g['drawn']} | {g['responding']} | {nr} | {denom} | "
                           f"{show(g)} | {show(s)} |")
        out.append("")
        for r in rows:
            if r["sample_id"] == sid and r["denominator"] == CAMPAIGNS and r["measure"] == "gated":
                out.append(f"- {r['ecosystem']}, per campaign (each once, unweighted): {r['positives']} of "
                           f"{r['units']} install-code campaigns gate, {pc(r['share'])} [{pc(r['ci_low'])}, "
                           f"{pc(r['ci_high'])}]; half the weighted gated names belong to {r['half_campaigns']} "
                           f"campaign(s), the largest holds {pc(r['top_campaign_share'])}")
        out.append("")
        if left_out.get(sid):
            out += ["Left out of the totals (no weight or no respondent): " + "; ".join(left_out[sid]), ""]
    return out
