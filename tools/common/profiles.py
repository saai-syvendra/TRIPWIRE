"""
Scores every gate branch with behaviours (a payload) against documented execution environments, and merges the
branch recipes into as few environments as a greedy pass finds.

Profiles live in tools/common/profiles/<name>.json: one value per recipe axis, each citing its source (repo and
commit, or docs page and date), with per-ecosystem overrides. Two absence rules make "not listed" mean something:
`env_var.complete` (a variable not listed is unset, apart from `unknown_prefixes`) and `file.absent_prefixes` (a
path under them is absent unless listed as present); `installed_tool.complete` does the same for tools. Anything
else a profile leaves out is undocumented.

A branch is scored from its `env_recipe`, the analyst's statement of the environment that reaches it (built for
the smallest DNF term of the gate, or the smallest falsifying set for an else branch):

- not_expressible: the conditions the recipe stands for include an out-of-scope one (a server response, a
  dependency tree), so no machine setting reaches the branch;
- closed: some recipe axis contradicts the profile, and the branch has no other way in (an expression with one
  DNF term, or one minimal falsifying set for an else branch); with another way in it is unknown
  (`alternative_terms`), since that way has no recipe;
- unknown: an axis the profile does not document (`undocumented`), a path relative to the install directory
  that the shipped-paths sidecar does not settle (`relative_path`), a recipe value that cannot be compared
  (`uncomparable_value`: free text, placeholders), an empty recipe (`empty_recipe`), or a recipe that would open
  but leaves out a condition the branch needs and no axis stands for (`recipe_gap`: a process check, or a
  condition whose axis the analyst did not fill). The check is per axis, not per condition: any env_var key covers
  every env-var, CI-marker and locale condition of the branch;
- open: every axis holds.

A record's own OS requirement (`requirements`, axis `os`: the payload needs that OS to run, whatever the gate
says) is checked first: a profile on another OS closes the payload (`closed_on` holds `os_requirement`). So an outcome
says whether the payload can start, its gate open on an OS it runs on. Requirements are analyst statements that no
claim layer verifies, like recipes.

The privilege axis has two values. `root_or_admin` in a profile means a step can act as root or administrator, which
includes passwordless sudo (the GitHub ubuntu and macOS runners); it would score a gate that tests `getuid() == 0`
open there, though no kept gate does.

A path relative to the install directory is settled by `shipped`, {record key: {path: shipped?}} from
reports/_shipped/ (tools/common/shipped.py): a fresh install directory holds exactly what the package ships, on
every profile, so a shipped path is present and any other absent.

`closed_on` lists the recipe axes that contradict the profile on a closed payload. `guessed` marks an outcome
that rests on a key in `recipe_guessed_fields` (for open, any recipe key; for closed, every contradicting key).
Gates the verification join excludes are left out. Pure functions; deterministic.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import posixpath
import re
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

from tools.common.contract import dnf_terms
from tools.common.tables import ARCH_VALUES, OS_VALUES

PROFILES = Path(__file__).resolve().parent / "profiles"
OUTCOMES = ("open", "closed", "unknown", "not_expressible")
REASONS = ("alternative_terms", "undocumented", "relative_path", "uncomparable_value", "empty_recipe", "recipe_gap")
# The recipe axes that can stand for a condition of each in-scope category. A category with no axis (a process
# list) is never represented. package_manager is left out: every profile fixes the installer per ecosystem.
CATEGORY_AXES = {
    "os": {"os"}, "arch": {"arch"}, "libc": {"libc"},
    "env_var": {"env_var", "env_var_absent", "ci"}, "ci_marker": {"env_var", "env_var_absent", "ci"},
    "hostname": {"hostname"}, "username": {"username"}, "timezone": {"timezone"}, "time_date": {"datetime"},
    "locale_language": {"locale", "env_var", "env_var_absent"},
    "target_artifact": {"file_present", "file_absent"}, "vm_sandbox_artifact": {"file_present", "file_absent"},
    "file_or_dir_exists": {"file_present", "file_absent"}, "file_content": {"file_present", "file_absent"},
    "home_or_path": {"home_dir", "file_present", "file_absent"},
    "installed_tool": {"installed_tool"}, "privilege": {"privilege"}, "runtime_version": {"runtime_version"},
    "hardware": {"cpu_count", "memory_mb"}, "uptime": {"uptime_s"},
    "network_reachability": {"network"}, "ip_or_geo_local": {"network", "locale"},
    "process_list": set(),
}
OS_NAMES = {"win32": "win32", "windows": "win32", "linux": "linux", "darwin": "darwin", "macos": "darwin"}


def required_os(requirements: list[dict] | None) -> set[str] | None:
    """The OSes a record's payload needs (`requirements`, axis `os`), or None when it names none."""
    names = set()
    for r in requirements or []:
        if r.get("axis") == "os":
            vals = r["value"] if isinstance(r["value"], list) else [r["value"]]
            names |= {OS_NAMES[w] for v in vals for w in re.findall(r"[a-z0-9]+", str(v).lower()) if w in OS_NAMES}
    return names or None
SCALAR = ("os", "arch", "libc", "hostname", "username", "home_dir", "locale", "timezone", "datetime", "privilege",
          "package_manager", "ci")
AT_LEAST = ("cpu_count", "memory_mb", "uptime_s")
MANAGERS = {"npm": "npm", "pip": "pip", "pip3": "pip", "yarn": "yarn", "pnpm": "pnpm", "bun": "bun"}
WINDOWS_PATH = re.compile(r"%[A-Za-z_]+%|^[A-Za-z]:[\\/]|\\|appdata", re.I)


def load(directory: Path = PROFILES) -> dict[str, dict]:
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.json"))}


def resolve(profile: dict, ecosystem: str) -> dict:
    """The profile's axes for one ecosystem: overrides replace scalar axes, and extend the env, file and tool
    lists."""
    axes = json.loads(json.dumps(profile["axes"]))
    for key, over in profile.get("ecosystems", {}).get(ecosystem, {}).items():
        base = axes.get(key)
        if key == "env_var" and base:
            base["set"].update(over.get("set", {}))
            base["unknown_prefixes"] = base.get("unknown_prefixes", []) + over.get("unknown_prefixes", [])
        elif key in ("file", "installed_tool") and base:
            base["present"] = base.get("present", []) + over.get("present", [])
            if "absent_prefixes" in over:
                base["absent_prefixes"] = base.get("absent_prefixes", []) + over["absent_prefixes"]
        else:
            axes[key] = over
    return axes


def version(text) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", str(text))
    return tuple(int(p) for p in parts) if parts else None


def norm_locale(text: str) -> str:
    return str(text).split(".")[0].replace("-", "_").lower()


def path_kind(path: str) -> str:
    """windows, uncomparable (placeholders, free text, a $VAR such as $INIT_CWD, which names another directory),
    relative (to the install directory) or posix."""
    if WINDOWS_PATH.search(path):
        return "windows"
    if "<" in path or ">" in path or " " in path or "$" in path:  # placeholders, free text, $VAR expansions
        return "uncomparable"
    return "posix" if path.startswith(("/", "~")) else "relative"


def tilde(path: str, home: str | None) -> str:
    return "~" + path[len(home):] if home and path.startswith(home.rstrip("/") + "/") else path


def relative(path: str) -> str | None:
    """A path relative to the install directory in normal form (no ./, no trailing /), or None when it leaves
    the directory or names the directory itself."""
    p = posixpath.normpath(path.strip())
    return None if p == "." or p == ".." or p.startswith("../") else p


def shipped_state(path: str, shipped: dict | None) -> bool | None:
    """Whether the package ships a relative path, or None when the sidecar does not say."""
    p = relative(path)
    return shipped.get(p) if shipped and p is not None else None


def file_state(path: str, axes: dict, shipped: dict | None = None) -> tuple[str, str | None]:
    """(present|absent|unknown, reason) of a path on the profile; `shipped` settles relative paths."""
    kind = path_kind(path)
    if kind == "windows":
        return ("absent", None) if axes.get("os", {}).get("value") != "win32" else ("unknown", "undocumented")
    if kind == "uncomparable":
        return "unknown", "uncomparable_value"
    if kind == "relative":
        state = shipped_state(path, shipped)
        return ("unknown", "relative_path") if state is None else ("present" if state else "absent", None)
    f = axes.get("file", {})
    home = axes.get("home_dir", {}).get("value")
    p = tilde(path.rstrip("/"), home)
    present = {tilde(x.rstrip("/"), home) for x in f.get("present", [])}
    if p in present:
        return "present", None
    if any(p.startswith(tilde(x, home)) for x in f.get("absent_prefixes", [])):
        return "absent", None
    return "unknown", "undocumented"


def env_state(name: str, axes: dict) -> tuple[str, object]:
    """(set|unset|unknown, the documented value or None)."""
    e = axes.get("env_var")
    if not e:
        return "unknown", None
    if name in e["set"]:
        return "set", e["set"][name]
    if any(name.startswith(p) for p in e.get("unknown_prefixes", [])) or not e.get("complete"):
        return "unknown", None
    return "unset", None


def axis(key: str, want, axes: dict, gate: dict, shipped: dict | None = None) -> list[tuple[str, str | None]]:
    """[(open|closed|unknown, reason)] for one recipe axis (one entry per variable, path, tool or host)."""
    if key == "env_var":
        out = []
        for name, value in want.items():
            state, have = env_state(name, axes)
            if state == "unset":
                out.append(("closed", None))
            elif state == "unknown":
                out.append(("unknown", "undocumented"))
            elif value is None:
                out.append(("open", None))
            elif "<" in str(value):
                out.append(("unknown", "uncomparable_value"))
            elif have is None:
                out.append(("unknown", "undocumented"))
            else:
                have = gate.get("hook") if have == "$hook" else have
                out.append(("open" if str(have) == str(value) else "closed", None))
        return out
    if key == "env_var_absent":
        out = []
        for name in want:
            state, _ = env_state(name, axes)
            out.append({"set": ("closed", None), "unset": ("open", None)}.get(state, ("unknown", "undocumented")))
        return out
    if key in ("file_present", "file_absent"):
        out = []
        for path in want:
            state, reason = file_state(str(path), axes, shipped)
            if state == "unknown":
                out.append(("unknown", reason))
            else:
                out.append(("open" if (state == "present") == (key == "file_present") else "closed", None))
        return out
    if key == "installed_tool":
        t = axes.get("installed_tool", {})
        return [("open", None) if tool in t.get("present", []) else ("closed", None) if t.get("complete")
                else ("unknown", "undocumented") for tool in want]
    if key == "network":
        n = axes.get("network")
        if not n:
            return [("unknown", "undocumented")] * len(want)
        out = []
        for host, state in want.items():
            reach = n["egress"] == "open" and not blocked(host, n.get("blocked", []))
            out.append(("open" if reach == (state == "reachable") else "closed", None))
        return out
    have = axes.get(key, {}).get("value")
    if have is None:
        return [("unknown", "undocumented")]
    if key in AT_LEAST:
        return [("open" if int(have) >= int(want) else "closed", None)]
    if key == "runtime_version":
        ops = {c["operator"] for c in gate["conditions"] if c["category"] == "runtime_version"}
        if not ops or not ops <= {">=", ">"} or version(want) is None or version(have) is None:
            return [("unknown", "uncomparable_value")]
        return [("open" if version(have) >= version(want) else "closed", None)]
    if key == "os":
        w = OS_VALUES.get(str(want).lower())
        return [("open" if w == have else "closed", None)] if w else [("unknown", "uncomparable_value")]
    if key == "arch":
        w = ARCH_VALUES.get(str(want).lower())
        return [("open" if w == have else "closed", None)] if w else [("unknown", "uncomparable_value")]
    if key == "ci":
        w = str(want).lower()
        if w in ("true", "false"):
            return [("open" if (have != "none") == (w == "true") else "closed", None)]
        return [("open" if w in have or have in w else "closed", None)]
    if key == "package_manager":
        w = MANAGERS.get(str(want).strip().lower())
        return [("open" if w == have else "closed", None)] if w else [("unknown", "uncomparable_value")]
    if key == "locale":
        return [("open" if norm_locale(want) == norm_locale(have) else "closed", None)]
    if key == "timezone":
        same = str(want).lower().removeprefix("etc/") == str(have).lower().removeprefix("etc/")
        return [("open" if same else "closed", None)]
    if key == "hostname" and axes[key].get("random"):
        return [("closed", None)]  # a named host never equals a container's random id
    return [("open" if str(want) == str(have) else "closed", None)]


def blocked(host: str, cidrs: list[str]) -> bool:
    name = host.rsplit(":", 1)[0].replace("[.]", ".").strip("[]")  # recipe hosts are stored defanged
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(c) for c in cidrs)


def hitting_sets(terms: list[frozenset[str]], requires: set[str]) -> list[frozenset[str]]:
    """Inclusion-minimal sets of conditions (outside `requires`) whose falsity makes every term false."""
    terms = [t - requires for t in terms]
    ids = sorted(set().union(*terms)) if terms else []
    if len(ids) > 16:
        return [frozenset(ids)] * 2  # too many to enumerate; count as more than one way
    found = []
    for k in range(1, len(ids) + 1):
        for combo in combinations(ids, k):
            s = frozenset(combo)
            if all(t & s for t in terms) and not any(f <= s for f in found):
                found.append(s)
    return found


def branches(gate: dict) -> list[tuple[str, dict, set[str], bool]]:
    """(branch, branch dict, condition ids its recipe stands for, other ways in) for branches with behaviours."""
    terms = sorted(dnf_terms(gate["expression"]), key=lambda t: (len(t), sorted(t)))
    out = []
    if gate["then"]["behaviours"]:
        out.append(("then", gate["then"], set(terms[0]), len(terms) > 1))
    e = gate.get("else")
    if e and e["behaviours"]:
        req = set(e.get("requires") or [])
        hits = hitting_sets(terms, req)
        smallest = min(hits, key=lambda s: (len(s), sorted(s))) if hits else frozenset()
        out.append(("else", e, set(smallest) | req, len(hits) > 1))
    return out


def score(gate: dict, branch: dict, needed: set[str], alternatives: bool, axes: dict,
          shipped: dict | None = None, requirements: list[dict] | None = None) -> dict:
    conds = {c["id"]: c for c in gate["conditions"]}
    need_os, have_os = required_os(requirements), (axes.get("os") or {}).get("value")
    if need_os and have_os and have_os not in need_os:
        return {"outcome": "closed", "reason": None, "guessed": False, "closed_on": ["os_requirement"]}
    if any(not conds[c]["in_scope"] for c in needed if c in conds):
        return {"outcome": "not_expressible", "reason": None, "guessed": False}
    recipe, guessed_keys = branch["env_recipe"], set(branch.get("recipe_guessed_fields") or [])
    if not recipe:
        return {"outcome": "unknown", "reason": "empty_recipe", "guessed": False}
    results = {k: axis(k, v, axes, gate, shipped) for k, v in recipe.items()}
    closed = [k for k, rs in results.items() if any(o == "closed" for o, _ in rs)]
    unknown = [r for rs in results.values() for o, r in rs if o == "unknown"]
    if closed:
        if alternatives:
            return {"outcome": "unknown", "reason": "alternative_terms", "guessed": False}
        return {"outcome": "closed", "reason": None, "guessed": all(k in guessed_keys for k in closed),
                "closed_on": sorted(closed)}
    if unknown:
        reason = next(r for r in ("uncomparable_value", "relative_path", "undocumented") if r in unknown)
        return {"outcome": "unknown", "reason": reason, "guessed": False}
    gaps = [c for c in sorted(needed) if c in conds and conds[c]["category"] in CATEGORY_AXES
            and not CATEGORY_AXES[conds[c]["category"]] & set(recipe)]
    if gaps:
        return {"outcome": "unknown", "reason": "recipe_gap", "guessed": False}
    return {"outcome": "open", "reason": None, "guessed": bool(guessed_keys & set(recipe))}


def evaluate(gates: list[dict], profiles: dict[str, dict], shipped: dict[str, dict] | None = None,
             requirements: dict[str, list[dict]] | None = None) -> list[dict]:
    """One row per profile and payload (a kept gate's branch with behaviours). `shipped` maps a record key to
    its shipped-paths map, `requirements` a record key to the record's requirements."""
    shipped, requirements = shipped or {}, requirements or {}
    rows = []
    for name, prof in sorted(profiles.items()):
        resolved = {}
        for g in gates:
            if g.get("verification", "ok") != "ok":
                continue
            eco = g["key"].split("__", 1)[0]
            axes = resolved.setdefault(eco, resolve(prof, eco))
            for br, b, needed, alt in branches(g):
                rows.append({"profile": name, "key": g["key"], "gate_id": g["gate_id"], "branch": br,
                             "ecosystem": eco, "cluster_key": g["cluster_key"], "closed_on": [],
                             **score(g, b, needed, alt, axes, shipped.get(g["key"]), requirements.get(g["key"]))})
    return rows


def package_outcome(outcomes: list[str]) -> str:
    """A package opens when any of its payloads opens; else unknown, not expressible, closed, in that order."""
    return next(o for o in ("open", "unknown", "not_expressible", "closed") if o in outcomes)


CATEGORIES = [*OUTCOMES, "open_guessed", "closed_guessed", *(f"unknown_{r}" for r in REASONS)]


def tally(items: list[tuple[dict, float]]) -> dict:
    """{category: (count, weighted share)} over (row, weight) items."""
    total = sum(w for _, w in items)
    out = {}
    for c in CATEGORIES:
        hit = [(r, w) for r, w in items if category_of(r, c)]
        out[c] = (len(hit), sum(w for _, w in hit) / total if total else None)
    return out


def category_of(row: dict, c: str) -> bool:
    if c in OUTCOMES:
        return row["outcome"] == c
    if c.endswith("_guessed"):
        return row["outcome"] == c.removesuffix("_guessed") and row["guessed"]
    return row["outcome"] == "unknown" and row["reason"] == c.removeprefix("unknown_")


def table(rows: list[dict], packages: list[str], draws: dict[str, list[tuple[str, float]]]) -> list[dict]:
    """blindspot.csv rows: per profile, payloads; packages (every gated record, members included, by cluster);
    campaigns (each gated cluster once); and per draw, packages weighted by design and the draw's campaigns once
    each. A name-weighted share follows whichever campaigns fill the frame; the campaign rows do not. `packages` holds one cluster key per gated package; `draws` maps a
    sample id to (cluster key, weight) per gated respondent. A gated package whose kept gates guard no behaviour
    has nothing to open: it is left out of the units and counted in `no_payload`."""
    out = []
    for name in sorted({r["profile"] for r in rows}):
        mine = [r for r in rows if r["profile"] == name]
        per_cluster = defaultdict(list)
        for r in mine:
            per_cluster[r["cluster_key"]].append(r)

        def pkg(ck):
            rs = per_cluster.get(ck, [])
            o = package_outcome([r["outcome"] for r in rs]) if rs else None
            pick = [r for r in rs if r["outcome"] == o]
            return {"outcome": o, "guessed": bool(pick) and all(r["guessed"] for r in pick),
                    "reason": pick[0]["reason"] if pick else None}
        groups = [("payload", "none", [(r, 1.0) for r in mine]),
                  ("package", "none", [(pkg(ck), 1.0) for ck in packages if ck in per_cluster]),
                  ("campaign", "none", [(pkg(ck), 1.0) for ck in sorted(set(packages)) if ck in per_cluster])]
        for sid, units in sorted(draws.items()):
            groups += [("package", f"draw:{sid}", [(pkg(ck), w) for ck, w in units if ck in per_cluster]),
                       ("campaign", f"draw:{sid}",
                        [(pkg(ck), 1.0) for ck in sorted({c for c, _ in units}) if ck in per_cluster])]
        missing = {("payload", "none"): 0, ("package", "none"): sum(1 for ck in packages if ck not in per_cluster),
                   ("campaign", "none"): sum(1 for ck in set(packages) if ck not in per_cluster)}
        for sid, units in draws.items():
            missing[("package", f"draw:{sid}")] = sum(1 for ck, _ in units if ck not in per_cluster)
            missing[("campaign", f"draw:{sid}")] = sum(1 for ck in {c for c, _ in units} if ck not in per_cluster)
        for unit, weighting, items in groups:
            row = {"profile": name, "unit": unit, "weighting": weighting, "units": len(items),
                   "no_payload": missing[(unit, weighting)]}
            for c, (n, share) in tally(items).items():
                row[f"n_{c}"], row[f"share_{c}"] = n, share
            out.append(row)
    return out


def conflicts(env: dict, recipe: dict) -> bool:
    for k, v in recipe.items():
        if k in SCALAR and k in env and env[k] != v:
            return True
    for name, value in recipe.get("env_var", {}).items():
        if name in env.get("env_var_absent", ()):
            return True
        have = env.get("env_var", {}).get(name)
        if have is not None and value is not None and have != value:
            return True
    if set(recipe.get("env_var_absent", ())) & set(env.get("env_var", {})):
        return True
    if set(recipe.get("file_present", ())) & set(env.get("file_absent", ())) or \
            set(recipe.get("file_absent", ())) & set(env.get("file_present", ())):
        return True
    return any(env.get("network", {}).get(h, s) != s for h, s in recipe.get("network", {}).items())


def merge_into(env: dict, recipe: dict) -> None:
    for k, v in recipe.items():
        if k in SCALAR:
            env[k] = v
        elif k in AT_LEAST:
            env[k] = max(env.get(k, v), v)
        elif k == "runtime_version":
            env[k] = max(env.get(k, v), v, key=lambda x: version(x) or ())
        elif k in ("env_var", "network"):
            for name, value in v.items():
                if value is not None or name not in env.setdefault(k, {}):
                    env.setdefault(k, {})[name] = value
        else:
            env[k] = sorted(set(env.get(k, [])) | set(v))


def merge(recipes: list[dict]) -> list[dict]:
    """Greedy first fit: each recipe joins the first environment it does not conflict with (a different OS or
    other scalar, an env var set two ways or set and unset, a file present and absent, a host reachable and not).
    Returns the environments with the count of recipes each holds (and their indices in `members`), most first:
    an upper bound on the minimum."""
    envs = []
    for i, r in enumerate(recipes):
        for e in envs:
            if not conflicts(e["recipe"], r):
                merge_into(e["recipe"], r)
                e["payloads"] += 1
                e["members"].append(i)
                break
        else:
            env = {"recipe": {}, "payloads": 1, "members": [i]}
            merge_into(env["recipe"], r)
            envs.append(env)
    return sorted(envs, key=lambda e: -e["payloads"])


def settled(recipe: dict, shipped: dict | None) -> tuple[dict, bool]:
    """(the recipe without the relative paths `shipped` settles, whether every settled path holds). What the
    package ships is the same in every environment, so a settled path never constrains a build; one that does
    not hold (a shipped path wanted absent, an unshipped one wanted present) no environment can change."""
    out, holds = dict(recipe), True
    for key in ("file_present", "file_absent"):
        if key not in recipe:
            continue
        kept = []
        for path in recipe[key]:
            state = shipped_state(str(path), shipped) if path_kind(str(path)) == "relative" else None
            if state is None:
                kept.append(path)
            elif state != (key == "file_present"):
                holds = False
        if kept:
            out[key] = kept
        else:
            del out[key]
    return out, holds


def buildable(gate: dict, branch: dict, profiles: dict[str, dict], shipped: dict | None = None) -> bool:
    """A recipe an environment can be built from: not empty, no value any profile finds uncomparable (free
    text, placeholders), and every relative path `shipped` settles holds. A relative path it does not settle is
    buildable: a fresh install directory lacks it unless the package ships it."""
    recipe = branch["env_recipe"]
    if not recipe or not settled(recipe, shipped)[1]:
        return False
    eco = gate["key"].split("__", 1)[0]
    return not any(r == "uncomparable_value" for prof in profiles.values() for k, v in recipe.items()
                   for _, r in axis(k, v, resolve(prof, eco), gate, shipped))


def merge_table(gates: list[dict], rows: list[dict], profiles: dict[str, dict],
                shipped: dict[str, dict] | None = None) -> list[dict]:
    """blindspot_merge.csv: buildable payloads (expressible, see buildable()) that k merged environments hold,
    against k, an upper bound on what they open; and each profile's open count over the same payloads, a lower
    bound. Each row also counts gated campaigns (those with a payload, each once, as blindspot.csv's campaign rows
    do): a campaign opens when one of its payloads does, so a profile's campaign share equals its open share there.
    Relative paths the shipped-paths sidecar settles are dropped before merging (settled())."""
    shipped = shipped or {}
    expressible = {(r["key"], r["gate_id"], r["branch"]) for r in rows if r["outcome"] != "not_expressible"}
    built = [((g["key"], g["gate_id"], br), settled(b["env_recipe"], shipped.get(g["key"]))[0])
             for g in sorted(gates, key=lambda g: (g["key"], int(g["gate_id"][1:])))
             if g.get("verification", "ok") == "ok"
             for br, b, _, _ in branches(g) if (g["key"], g["gate_id"], br) in expressible and
             buildable(g, b, profiles, shipped.get(g["key"]))]
    ids, total = {i for i, _ in built}, len(built)
    cluster = {g["key"]: g["cluster_key"] for g in gates}
    first = min((r["profile"] for r in rows), default=None)
    camps = len({r["cluster_key"] for r in rows if r["profile"] == first})
    out, opened, held = [], 0, set()
    for k, e in enumerate(merge([r for _, r in built]), 1):
        opened += e["payloads"]
        held |= {cluster[built[i][0][0]] for i in e["members"]}
        out.append({"kind": "merged", "name": f"env{k}", "environments": k, "opened": opened,
                    "buildable": total, "expressible": len(expressible), "share": opened / total if total else None,
                    "campaigns_opened": len(held), "campaigns": camps,
                    "campaign_share": len(held) / camps if camps else None})
    for name in sorted({r["profile"] for r in rows}):
        n = sum(1 for r in rows if r["profile"] == name and r["outcome"] == "open"
                and (r["key"], r["gate_id"], r["branch"]) in ids)
        c = len({r["cluster_key"] for r in rows if r["profile"] == name and r["outcome"] == "open"})
        out.append({"kind": "profile", "name": name, "environments": 1, "opened": n, "buildable": total,
                    "expressible": len(expressible), "share": n / total if total else None,
                    "campaigns_opened": c, "campaigns": camps, "campaign_share": c / camps if camps else None})
    return out


def write_tables(tables: Path, blind: list[dict], merged: list[dict]) -> None:
    tables.mkdir(parents=True, exist_ok=True)
    for name, rows in (("blindspot.csv", blind), ("blindspot_merge.csv", merged)):
        with open(tables / name, "w", newline="", encoding="utf-8") as f:
            if not rows:
                continue
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            for r in rows:
                w.writerow({k: (f"{v:.4f}" if isinstance(v, float) else "" if v is None else v)
                            for k, v in r.items()})


def summary_lines(blind: list[dict], merged: list[dict]) -> list[str]:
    def pc(x):
        return "n/a" if x is None else f"{100 * x:.1f}%"
    out = ["## Stock environments against the gates", "",
           "Each payload (a kept gate's branch with behaviours) scored on its recipe against the documented "
           "profiles in `tools/common/profiles/`. Unknown means the profile does not document an axis, the recipe "
           "value cannot be compared, or the branch has another way in that has no recipe. A package opens when "
           "any payload opens. Draw rows are weighted by design over the gated respondents.", "",
           "| profile | unit | weighting | units | open | closed | unknown | not expressible | open, guessed |",
           "|---|---|---|---|---|---|---|---|---|"]
    for r in blind:
        cell = lambda c: f"{pc(r[f'share_{c}'])} ({r[f'n_{c}']})"  # noqa: E731
        out.append(f"| {r['profile']} | {r['unit']} | {r['weighting']} | {r['units']} | {cell('open')} | "
                   f"{cell('closed')} | {cell('unknown')} | {cell('not_expressible')} | {cell('open_guessed')} |")
    for r in blind:
        if r["unit"] in ("package", "campaign") and r["weighting"].startswith("draw:"):
            out.append(f"- {r['profile']}, {r['unit']}, {r['weighting']}: unknown by reason: " + ", ".join(
                f"{x.replace('_', ' ')} {pc(r[f'share_unknown_{x}'])} ({r[f'n_unknown_{x}']})" for x in REASONS))
    m = [r for r in merged if r["kind"] == "merged"]
    if m:
        half = next((r["environments"] for r in m if r["share"] >= 0.5), None)
        points = ", ".join(f"{r['name']} {r['opened']} ({pc(r['share'])})" for r in merged if r["kind"] == "profile")
        out += [f"- Greedy merge over the {m[-1]['buildable']} buildable payloads (of {m[-1]['expressible']} "
                f"expressible; empty recipes and uncomparable values left out): {len(m)} environments hold them "
                f"all, an upper bound on the minimum; the first holds {m[0]['opened']}; half need {half}. The "
                f"profiles open {points}, a lower bound (open only)."]
    left = {f"{r['unit']} {r['weighting']}": r["no_payload"] for r in blind
            if r["unit"] in ("package", "campaign") and r["no_payload"]}
    if left:
        out.append("- Gated packages with no payload (their kept gates guard no behaviour), left out of the package "
                   "units: " + ", ".join(f"{k} {v}" for k, v in sorted(left.items())))
    return out + [""]
