"""
Environment recipes: the machine settings (OS, env vars, files, tools, ...) that make a set of conditions hold
or fail. Used for gate branches when records are written.
"""
from __future__ import annotations

import re

from tools.common.tables import ARCH_VALUES, NEGATE, OS_APIS, OS_VALUES

EXCLUDING = {"!=", "not_in", "not_startswith", "not_includes", "not_regex"}
# Values to try for an identity a condition excludes, first one the condition allows wins (always a guess).
STAND_INS = {"hostname": ["dev-workstation", "build-host"], "username": ["developer", "builder"],
             "locale_language": ["en-US", "de-DE"], "timezone": ["UTC", "Europe/Berlin"]}


def allows(op: str, excluded, candidate: str) -> bool:
    """`candidate` satisfies an excluding condition on `excluded` (a value or list). A regex is not evaluated, so
    any candidate that does not contain it literally is taken (and marked guessed by the caller)."""
    values = [str(x).lower() for x in (excluded if isinstance(excluded, list) else [excluded]) if x is not None]
    c = candidate.lower()
    if op == "not_startswith":
        return not any(c.startswith(v) for v in values)
    if op in ("not_includes", "not_regex"):
        return not any(v in c for v in values)
    return c not in values


def negate_condition(cond: dict) -> dict:
    """The condition in the sense that makes it false, so build_recipe produces the falsifying environment."""
    return {**cond, "operator": NEGATE.get(cond["operator"], "other")}


def build_recipe(conds: list[dict]) -> tuple[dict, list[str], list[str]]:
    """env_recipe for one set of conditions that must all hold; returns (recipe, guessed keys, condition ids
    the recipe could not express)."""
    recipe, guessed, missing = {}, [], []

    def put(key, value, guess=False):
        if key in ("env_var",):
            recipe.setdefault("env_var", {}).update(value)
        elif key in ("env_var_absent", "file_present", "file_absent", "installed_tool"):
            recipe.setdefault(key, [])
            recipe[key] += [v for v in value if v not in recipe[key]]
        elif key in recipe and recipe[key] != value:
            guess = True
        else:
            recipe[key] = value
        if guess and key not in guessed:
            guessed.append(key)

    for c in conds:
        op, v, cat, api = c["operator"], c["value"], c["category"], " / ".join(c.get("apis", [c.get("api", "")]))
        first = v[0] if isinstance(v, list) and v else v
        env = c.get("env")
        if env:
            if op in ("truthy", "exists"):
                put("env_var", {env: None})
            elif op in ("falsy", "not_exists"):
                put("env_var_absent", [env])
            elif op in ("==", "in") and first is not None:
                put("env_var", {env: str(first)})
            elif op in ("!=", "not_in", "includes", "startswith"):
                put("env_var", {env: None if op in ("!=", "not_in") else str(v)}, guess=True)
            elif op in ("not_startswith", "not_includes", "not_regex"):
                put("env_var_absent", [env], guess=True)  # unset never matches the excluded value
            else:
                missing.append(c["id"])
            continue
        if cat == "os" and OS_APIS.search(api):
            pick = None
            if op in ("==", "in", "includes", "startswith") and first is not None:
                pick = OS_VALUES.get(str(first).lower())
            elif op in ("!=", "not_in"):
                excluded = {OS_VALUES.get(str(x).lower()) for x in (v if isinstance(v, list) else [v])}
                pick = next((o for o in ("linux", "win32", "darwin") if o not in excluded), None)
            if pick:
                put("os", pick, guess=op in ("!=", "not_in") or str(first).lower() == "posix")
            else:
                missing.append(c["id"])
        elif cat == "arch" and op in ("==", "in", "includes") and str(first).lower() in ARCH_VALUES:
            put("arch", ARCH_VALUES[str(first).lower()])
        elif cat in ("hostname", "username", "locale_language", "timezone") and \
                op in ("==", "in", "includes", "startswith") and isinstance(first, str):
            put({"locale_language": "locale"}.get(cat, cat), first)
        elif cat in STAND_INS and op in EXCLUDING:
            pick = next((x for x in STAND_INS[cat] if allows(op, v, x)), None)
            if pick:
                put({"locale_language": "locale"}.get(cat, cat), pick, guess=True)
            else:
                missing.append(c["id"])
        elif cat in ("target_artifact", "vm_sandbox_artifact", "file_or_dir_exists") and v is not None:
            put("file_present" if op == "exists" else "file_absent", [v], guess=c["value_recovered"] == "partial")
        elif cat == "installed_tool" and op in ("exists", "truthy") and v is not None:
            put("installed_tool", [v])
        elif cat == "privilege" and op in ("==", "!=", ">", "truthy", "falsy"):
            root = (op == "==" and v == 0) or (op == "truthy" and "IsUserAnAdmin" in api)
            put("privilege", "root_or_admin" if root else "normal_user")
        elif cat == "home_or_path" and "homedir" in api and op in ("==", "startswith", "includes") and v:
            put("home_dir", v)
        elif cat == "runtime_version" and op in ("==", ">=", "startswith") and v is not None:
            put("runtime_version", ".".join(map(str, v)) if isinstance(v, list) else str(v))
        elif cat == "hardware" and re.search(r"cpus|cpu_count|availableParallelism", api) and \
                isinstance(v, int) and op in (">=", ">", "=="):
            put("cpu_count", v + 1 if op == ">" else v)
        elif cat == "uptime" and isinstance(v, (int, float)) and op in (">=", ">") and "boot_time" not in api:
            put("uptime_s", int(v) + (1 if op == ">" else 0))
        else:
            missing.append(c["id"])
    return recipe, guessed, missing
