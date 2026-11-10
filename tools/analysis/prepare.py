#!/usr/bin/env python3
"""
Deterministic part of the gate-analysis skill: archive in, prepared package out.

Unpacks a sample into scratch/<key>/unpacked/, identifies it, triages it, finds the install entry points and the
files they reach, runs gate_extract on them, and writes scratch/<key>/prepared.json with the facts, the
extractor candidates and a schema v3 skeleton record. Files that the install path names and may start but
does not import are flagged as not chained (hints.not_chained, a note and an obfuscation.unrecovered entry) and
hashed into the cluster key, never walked. Claude fills the "TODO" judgement fields in
scratch/<key>/record.json and summary.md (or skip.json), then runs write_report.py.
Writes the skip record itself for not_a_package and files_missing, and the member record for a package whose
install payload matches an analysed one (both with analysis_type "tool"). Never runs package code. Asks the npm
or PyPI registry for the version's publish date (release_date.py), once the package is known not to be a
duplicate, unless --no-registry is given.

Never deletes a scratch/<key>/ that holds analyst edits (reset.in_progress): such a package is reported as
in_progress and left alone. In a batch, a failure on one sample becomes an `error` row and the batch carries on;
a second archive of the same package (ecosystem, name, version; PyPI names compared per PEP 503) is folded into
the first one's row: noted when it is byte-identical, status duplicate_key (for a person to resolve) when not.
Rows are merged into scratch/queue.jsonl (work_queue.py), never overwriting rows of other packages.

Usage: python tools/analysis/prepare.py <archive or folder> [--source DATASET] [--label LABEL]
                               [--model MODEL_ID] [--no-registry]
       python tools/analysis/prepare.py <directory of archives> --batch   (merges into scratch/queue.jsonl)
Exit status 1 when any sample ended in error.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import tomllib
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.analysis import work_queue  # noqa: E402
from tools.analysis.gate_extract import Extractor  # noqa: E402
from tools.analysis.release_date import release_date  # noqa: E402
from tools.common import anchors, contract, paths, reset  # noqa: E402
from tools.common.contract import COND_ID, key_for  # noqa: E402
from tools.common.hooks import CODE_KINDS, file_kind, parse_command  # noqa: E402
from tools.common.sanitize import defang  # noqa: E402
from tools.common.tsparse import EXTENSIONS, field, text  # noqa: E402
from tools.common.unpack import (  # noqa: E402
    UnpackError, find_root, is_archive, reached_file_digests, sha256, unpack, unwrap)

SCHEMA = json.loads(paths.SCHEMA.read_text())
DATASETS = SCHEMA["$defs"]["package"]["properties"]["source_dataset"]["enum"]
NPM_HOOKS = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare")
PREPARE_HOOKS = ("preprepare", "prepare", "postprepare")
SETUPTOOLS_BACKENDS = ("setuptools.build_meta", "setuptools.build_meta:__legacy__")
TODO = "TODO"
MANIFEST_PICKS = {"os": ["linux", "win32", "darwin"], "arch": ["x64", "arm64", "ia32"], "libc": ["glibc", "musl"]}


def sample_path(path: Path) -> str | None:
    """The archive's path under samples/, a hint for the verifier (archive_sha256 is what it trusts)."""
    try:
        return path.resolve().relative_to(paths.SAMPLES.resolve()).as_posix()
    except ValueError:
        return None


def infer_source(path: Path) -> tuple[str, str]:
    """(source_dataset, source_label) from the folders above the sample."""
    parts = [p.lower() for p in path.resolve().parts]
    if paths.SAMPLES.resolve().as_posix().lower() in path.resolve().as_posix().lower():
        parts = [p.lower() for p in path.resolve().relative_to(paths.SAMPLES.resolve()).parts]
    dataset = next((p for p in parts if p in DATASETS), "unknown")
    if any(p in ("malicious_intent", "compromised_lib", "malicious") for p in parts):
        label = "malicious"
    elif dataset == "benign_sample" or "benign" in parts:
        label = "benign"
    else:
        label = "unknown"
    return dataset, label


def read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None


def header(path: Path, key: str) -> str | None:
    if not path.is_file():
        return None
    m = re.search(rf"^{key}:\s*(.+?)\s*$", path.read_text(errors="replace"), re.M)
    return m.group(1) if m else None


def setup_call(ex: Extractor) -> dict:
    """Literal keyword arguments of the setup() call in setup.py, read from the syntax tree."""
    fi = ex.file("setup.py", "py")
    out = {"cmdclass": {}, "setup_requires": None}
    if fi is None:
        return out
    from tools.common.tsparse import descendants
    for n in descendants(fi.tree.root_node):
        if n.type != "call" or not (fi.canon(field(n, "function")) or "").endswith("setup"):
            continue
        args = field(n, "arguments")
        for kw in (a for a in (args.named_children if args is not None else []) if a.type == "keyword_argument"):
            key, value = text(field(kw, "name")), field(kw, "value")
            if value is not None and value.type == "identifier" and value in fi.assigned:
                value = fi.assigned.get(value)
            if key in ("name", "version"):
                lit = fi.literal(value)
                if lit and isinstance(lit[0], (str, int, float)):
                    out[key] = str(lit[0])
            elif key == "cmdclass" and value is not None:
                out["cmdclass"].update(cmdclass_pairs(fi, value))
            elif key == "setup_requires":
                lit = fi.literal(value)
                out["setup_requires"] = lit[0] if lit else text(value)[:200]
        break
    return out


def cmdclass_pairs(fi, value) -> dict:
    pairs = {}
    if value.type == "dictionary":
        for p in value.named_children:
            if p.type == "pair":
                key = fi.literal(field(p, "key"))
                if key and isinstance(key[0], str):
                    pairs[key[0]] = text(field(p, "value"))
    elif value.type == "call" and text(field(value, "function")) == "dict":
        args = field(value, "arguments")
        for kw in (a for a in (args.named_children if args is not None else []) if a.type == "keyword_argument"):
            pairs[text(field(kw, "name"))] = text(field(kw, "value"))
    return pairs


def npm_entries(root: Path, manifest: dict, ex: Extractor) -> tuple[list[dict], list[str]]:
    scripts = manifest.get("scripts") if isinstance(manifest.get("scripts"), dict) else {}
    scripts = {k: v for k, v in scripts.items() if isinstance(v, str)}
    hooks = [(h, scripts[h]) for h in NPM_HOOKS if h in scripts]
    if (root / "binding.gyp").is_file() and "install" not in scripts and "preinstall" not in scripts:
        hooks.append(("node_gyp_implicit", "node-gyp rebuild"))
    entries, notes = [], []
    for hook, cmd in hooks:
        parsed = parse_command(cmd, hook, root, scripts)
        for name, code, lang in parsed["inline"]:
            ex.add_inline(name, code, lang)
        entry_files = [rel for rel, kind in parsed["files"] if kind in ("js", "py")]
        chain = []
        for rel, kind in parsed["files"]:
            for r in (ex.chain(rel, kind) if kind in ("js", "py") else [rel]):
                if r not in chain:
                    chain.append(r)
        entries.append({
            "hook": hook, "command": defang(cmd), "runs_on": "git_or_local_install_only" if hook in PREPARE_HOOKS
            else "always", "file_chain": chain, "interpreter": parsed["interpreter"] or "sh",
            "launch_style": parsed["launch_style"] or ["inline_shell"], "silent_failure": parsed["silent"],
            "_lang": "py" if entry_files and all(r.endswith(".py") for r in entry_files) else "js",
            "_entry_files": entry_files + [name for name, _, _ in parsed["inline"]], "_entry_functions": []})
        notes += parsed["notes"]
    if isinstance(manifest.get("bin"), (dict, str)):
        names = list(manifest["bin"]) if isinstance(manifest["bin"], dict) else [manifest["name"]]
        notes.append(f"bin commands not analysed (run only when invoked): {', '.join(map(str, names))[:200]}")
    for kind in ("dependencies", "optionalDependencies"):
        deps = manifest.get(kind) if isinstance(manifest.get(kind), dict) else {}
        odd = [f"{n} ({defang(str(v))})" for n, v in deps.items()
               if re.match(r"^(git|https?|file|github|gitlab|bitbucket):|^[\w-]+/[\w.-]+(#.*)?$|\.tgz$", str(v))]
        if odd:
            notes.append(f"non-registry {kind} (dependency tree): {', '.join(odd)[:250]}")
    if isinstance(manifest.get("optionalDependencies"), dict) and manifest["optionalDependencies"]:
        notes.append("optionalDependencies (platform picks belong to the dependency tree): "
                     + ", ".join(list(manifest["optionalDependencies"])[:10]))
    return entries, notes


def manifest_anchor(root: Path, key: str) -> dict:
    """Text anchor on the `"key": [...]` entry of package.json (the whole file if the entry can't be found)."""
    raw = (root / "package.json").read_bytes()
    m = re.search(rb'"' + re.escape(key.encode()) + rb'"\s*:\s*(\[[^\]]*\]|"[^"]*")', raw)
    start, end = (m.start(), m.end()) if m else (0, len(raw))
    return anchors.range_anchor("package.json", raw, start, end, anchors.TEXT)


def manifest_conditions(manifest: dict, root: Path) -> list[dict]:
    """The package's own os/cpu/libc fields: npm refuses to install on a mismatch, so no hook runs."""
    out = []
    for key, category in (("os", "os"), ("cpu", "arch"), ("libc", "libc")):
        values = manifest.get(key)
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list) or not values:
            continue
        allow = [v for v in values if isinstance(v, str) and not v.startswith("!")]
        deny = [v[1:] for v in values if isinstance(v, str) and v.startswith("!")]
        op, value = ("in", allow) if allow else ("not_in", deny)
        anchor = manifest_anchor(root, key)
        out.append({"category": category, "api": f"package.json#{key}", "operator": op, "value": value,
                    "value_recovered": "plain", "in_scope": True,
                    "sites": [{"candidate": anchors.candidate_id("k", anchor, category), "anchor": anchor}],
                    "provenance": "in_set"})
    return out


def save_derivations(found: dict, ex: Extractor, out: Path) -> list[dict]:
    """Every derived file the analysis reads, saved as out/<id>: string tables the extractor recovered
    (deobf.py), and hook commands with inline code (`node -e`, `python -c`), which the extractor parsed as
    pseudo-files named like `<postinstall -e>`. Each inline script becomes a derivation of package.json and
    anchors into it are rewritten to name the derivation, so a verifier can rebuild the code from the
    manifest."""
    derivations, ids = [], {}
    for did, data in ex.derived_bytes.items():  # recovered string tables
        out.mkdir(parents=True, exist_ok=True)
        (out / did).write_bytes(data)
    first = len(ex.derivations) + 1
    for name, fi in ex.files.items():
        if fi is None or not name.startswith("<"):
            continue
        ids[name] = f"d{first + len(derivations)}"
        hook, _, flag = name.strip("<>").partition(" ")
        out.mkdir(parents=True, exist_ok=True)
        (out / ids[name]).write_bytes(fi.src)
        derivations.append({"id": ids[name], "recipe": "inline_script", "recipe_version": 1,
                            "input": {"file": "package.json", "derived_from": None},
                            "params": {"hook": hook, "flag": flag}, "output_sha256": anchors.digest(fi.src)})

    def fix(value):
        if isinstance(value, dict):
            if value.get("file") in ids and "sha256" in value:
                value["derived_from"], value["file"] = ids[value["file"]], "package.json"
            for v in value.values():
                fix(v)
        elif isinstance(value, list):
            for v in value:
                fix(v)
    fix(found)
    return ex.derivations + derivations


def pypi_entries(root: Path, ex: Extractor, setup: dict) -> tuple[list[dict], list[str]]:
    entries, notes = [], []
    pyproject = {}
    if (root / "pyproject.toml").is_file():
        try:
            pyproject = tomllib.loads((root / "pyproject.toml").read_text(errors="replace"))
        except tomllib.TOMLDecodeError:
            notes.append("pyproject.toml does not parse")
    build = pyproject.get("build-system", {}) if isinstance(pyproject.get("build-system"), dict) else {}
    backend = build.get("build-backend")
    backend_path = build.get("backend-path")
    if backend_path and backend:
        mod = backend.split(":")[0].replace(".", "/")
        for base in backend_path if isinstance(backend_path, list) else [backend_path]:
            for cand in (f"{base}/{mod}.py", f"{base}/{mod}/__init__.py"):
                if (root / cand).is_file():
                    rel = Path(cand).as_posix().lstrip("./")
                    entries.append(py_entry("build_backend", f"in-tree build backend {backend}", rel, ex))
                    break
    runs_setup = (root / "setup.py").is_file() and (backend is None or backend in SETUPTOOLS_BACKENDS)
    if (root / "setup.py").is_file() and not runs_setup:
        notes.append(f"setup.py present but build backend {backend} does not run it")
    if runs_setup:
        setup_fi = ex.file("setup.py", "py")
        for command, cls in setup["cmdclass"].items():
            rel, qual = "setup.py", f"{cls}.run"
            if setup_fi is not None and cls in setup_fi.imported:
                rel, name = setup_fi.imported[cls]
                qual = f"{name}.run"
            e = py_entry("cmdclass", f"cmdclass[{command}] = {cls}", "setup.py", ex)
            e["_entry_files"] = []
            e["_entry_functions"] = [(rel, qual)]
            if rel not in e["file_chain"]:
                e["file_chain"].append(rel)
            entries.append(e)
        entries.append(py_entry("setup_py", "python setup.py (pip install from sdist)", "setup.py", ex))
    if setup.get("setup_requires"):
        notes.append(f"setup_requires (dependency tree): {defang(str(setup['setup_requires']))[:200]}")
    return entries, notes


def py_entry(hook: str, command: str, rel: str, ex: Extractor) -> dict:
    return {"hook": hook, "command": command, "runs_on": "always", "file_chain": ex.chain(rel, "py"),
            "interpreter": "python", "launch_style": ["direct_script"], "silent_failure": False,
            "_lang": "py", "_entry_files": [rel], "_entry_functions": []}


def existing_record(ecosystem: str, name: str, version: str | None) -> Path | None:
    return contract.existing_record(paths.REPORTS, ecosystem, name, version)


def not_chained(entries: list[dict], root: Path, ex: Extractor) -> list[dict]:
    """Code files in the package that an install-reached file names by path while starting processes, but that no
    followed import reaches (e.g. a path handed to a runtime held in a variable). Flagged, and walked as
    unreached: their candidates exist but are not prefilled; the analyst reads them and adds them to file_chain if
    the install runs them."""
    chained = {r for e in entries for r in e["file_chain"]}
    found: dict[str, dict] = {}
    for e in entries:
        sources = list(e["file_chain"]) + [n for n in e["_entry_files"] if n.startswith("<")]
        for src in dict.fromkeys(sources):
            fi = ex.files[src] if src in ex.files else ex.file(src)
            if fi is None:
                continue
            for rel, line in fi.launch_targets():
                if rel in chained:
                    continue
                path = root / rel
                kind = EXTENSIONS.get(path.suffix.lower()) or file_kind(path)
                if kind not in CODE_KINDS:
                    continue
                item = found.setdefault(rel, {"file": rel, "kind": kind, "bytes": path.stat().st_size,
                                              "named_at": [], "hooks": []})
                if f"{src}:{line}" not in item["named_at"]:
                    item["named_at"].append(f"{src}:{line}")
                if e["hook"] not in item["hooks"]:
                    item["hooks"].append(e["hook"])
    return list(found.values())


def size_text(n: int) -> str:
    return f"{n / 1e6:.1f} MB" if n >= 1e6 else f"{max(1, round(n / 1e3))} KB"


def flag_not_chained(launched: list[dict], notes: list[str], found: dict) -> None:
    """Puts each not-chained file in front of the analyst: a hint, a note, and an unrecovered entry, which forces
    manual review until the analyst has read it and removed the entry."""
    found["hints"]["not_chained"] = launched
    for item in launched:
        where = ", ".join(item["named_at"][:3])
        notes.append(f"possible launch target not chained: {item['file']} ({item['kind']}, "
                     f"{size_text(item['bytes'])}) is named at {where} in a file that starts processes; "
                     f"not followed by the extractor, listed in obfuscation.unrecovered")
        found["unrecovered"].append({
            "file": item["file"],
            "reason": f"not read yet: named at {where}, which starts processes, but no followed import reaches it. "
                      f"Read it, add it to the entry's file_chain if the install runs it, then remove this entry"})


def cluster_key_of(entries: list[dict], root: Path, package: dict, extra_files=()) -> str:
    """Campaign key: the install payload's content, not its name. Same reached files + commands = same campaign.
    Neither ecosystem hashes its name or descriptive metadata: npm's package.json is never a reached file, and on
    PyPI the literal setup() metadata arguments are masked (unpack.mask_setup_metadata). `extra_files` are not-chained launch targets: their content counts, so a shared loader with a different
    payload is a different campaign.

    A package with no reached install files (pure delegation to node-gyp etc.) has no payload to fingerprint, so
    it stays its own cluster and never groups with another."""
    digests = reached_file_digests(root, [e["file_chain"] for e in entries] + [list(extra_files)],
                                   mask_setup=package["ecosystem"] == "pypi")
    if not digests:
        seed = f"{package['ecosystem']}:{package['name']}@{package['version']}"
        return hashlib.sha256(seed.encode()).hexdigest()
    blob = json.dumps({"files": digests, "commands": sorted(e["command"] for e in entries)}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()


def existing_clusters() -> dict[str, str]:
    """cluster_key -> 'eco:name@version' for every analysed report on disk."""
    index = {}
    for eco in ("npm", "pypi"):
        for p in sorted((paths.REPORTS / eco).glob("*.md")):
            blocks = contract.JSON_BLOCK.findall(p.read_text(encoding="utf-8"))
            if not blocks:
                continue
            try:
                rec = json.loads(blocks[-1])
            except json.JSONDecodeError:
                continue
            ck = rec.get("package", {}).get("cluster_key")
            if ck:
                pk = rec["package"]
                index[ck] = f"{pk['ecosystem']}:{pk['name']}@{pk['version']}"
    return index


def write_member(package: dict) -> Path:
    rec = {"schema_version": contract.SCHEMA_VERSION, "record_type": "member",
           "package": {**package, "analysis_type": "tool"}}
    errs = contract.validation_errors(contract.load_validator(), rec)
    if errs:
        raise ValueError(f"member record does not validate: {errs}")
    path = paths.REPORTS / "_members" / f"{key_for(package['ecosystem'], package['name'], package['version'])}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def discard(path: Path) -> None:
    """Deletes a working folder of prepare's own (read-only folders from an archive included), if it exists."""
    if path.exists() or path.is_symlink():
        reset.remove(path)


def skip(package: dict, reason: str, note: str, work: Path | None = None) -> dict:
    """Writes a deterministic skip record unless one already exists for the package."""
    if work is not None:
        discard(work)
    existing = existing_record(package["ecosystem"], package["name"], package["version"])
    if existing:
        return {"status": "duplicate", "record": str(existing.relative_to(paths.ROOT))}
    path = write_skip(package, reason, note)
    return {"status": "skipped", "reason": reason, "record": str(path.relative_to(paths.ROOT))}


def write_skip(package: dict, reason: str, note: str) -> Path:
    rec = {"schema_version": contract.SCHEMA_VERSION, "record_type": "skip",
           "package": {**package, "analysis_type": "tool"}, "reason": reason, "note": defang(note)[:300]}
    errs = contract.validation_errors(contract.load_validator(), rec)
    if errs:
        raise ValueError(f"skip record does not validate: {errs}")
    path = paths.REPORTS / "_skipped" / f"{key_for(package['ecosystem'], package['name'], package['version'])}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def skeleton_branch(branch: dict | None) -> dict | None:
    """Schema-valid gate branch from an extractor branch: its recipe and regions kept, behaviours and the
    payload (sinks with their witness path) left for the analyst."""
    if branch is None:
        return None
    return {"min_conditions": branch["min_conditions"], "behaviours": TODO,
            "env_recipe": branch["env_recipe"], "recipe_guessed_fields": branch["recipe_guessed_fields"],
            "regions": branch.get("regions", []), "payload": TODO}


UNKNOWN_PREFILL = 20


def prefilled_gates(gates: list[dict]) -> list[dict]:
    live = [g for g in gates if g.get("reached", True)]
    own = [g for g in live if g.get("role", "package") == "package"]
    unknown = sorted((g for g in live if g.get("role") == "unknown" and g.get("unit_depth") is not None
                      and (g["then"].get("sinks") or (g.get("else") or {}).get("sinks"))),
                     key=lambda g: (g["unit_depth"], int(g["gate_id"][1:])))[:UNKNOWN_PREFILL]
    keep = {g["gate_id"] for g in own + unknown}
    return [g for g in gates if g["gate_id"] in keep]


def skeleton(package: dict, entries: list[dict], notes: list[str], found: dict, manifest_conds: list[dict],
             model: str | None = None) -> dict:
    # Candidates found only in functions no install path was seen to call, or only inside library bundle units,
    # stay in prepared.json (the analyst can still cite them by id) but are not prefilled, so library code does
    # not flood the record. In numbered bundles most units are `unknown`; of those, gates with sinks in units
    # reached from the bundle entry are prefilled too, nearest the entry first, at most UNKNOWN_PREFILL.
    reached = prefilled_gates(found["gates"])
    used = {c for g in reached for c in COND_ID.findall(g["expression"])}
    conditions = [{k: v for k, v in c.items() if k not in ("hook", "reached", "role")} for c in found["conditions"]
                  if c["id"] in used]
    gates = [{"gate_id": g["gate_id"], "hook": g["hook"], "expression": g["expression"],
              "guards": g.get("guards") or TODO, "provenance": "in_set",
              "polarity": TODO, "effect": TODO, "purpose": TODO, "purpose_reason": TODO,
              "then": skeleton_branch(g["then"]), "else": skeleton_branch(g["else"])} for g in reached]
    next_id = max((int(c["id"][1:]) for c in found["conditions"]), default=0) + 1
    if manifest_conds:
        ids, recipe, guessed = [], {}, []
        for c in manifest_conds:
            ids.append(f"c{next_id}")
            next_id += 1
            conditions.append({"id": ids[-1], **c})
            key = c["category"]
            if c["operator"] == "in":
                recipe[key] = c["value"][0]
            else:
                recipe[key] = next((v for v in MANIFEST_PICKS[key] if v not in c["value"]), MANIFEST_PICKS[key][0])
                guessed.append(key)
        # Numbered past every candidate gate, kept or not, so ids stay unique and candidate ids stay citeable.
        gate_no = max((int(g["gate_id"][1:]) for g in found["gates"]), default=0) + 1
        gates.append({"gate_id": f"g{gate_no}", "hook": "resolve", "expression": " && ".join(ids),
                      "guards": [], "provenance": "in_set",
                      "polarity": TODO, "effect": "enables", "purpose": TODO, "purpose_reason": TODO,
                      "then": {"min_conditions": len(ids), "behaviours": TODO, "env_recipe": recipe,
                               "recipe_guessed_fields": guessed, "regions": [], "payload": []},
                      "else": None})
    hints = found["hints"]
    delays = [{"site": d["site"], "seconds": d["seconds"]} for d in hints["delays"]]
    techniques = sorted({s for signals in hints["obfuscation_signals"].values() for s in signals})
    return {
        "schema_version": contract.SCHEMA_VERSION, "record_type": "analysed",
        "package": {**package, "analysis_type": "ai", "model_name": model or TODO},
        "execution": {"entry_points": [{k: v for k, v in e.items() if not k.startswith("_")} for e in entries],
                      "delays": delays, "notes": [n[:300] for n in notes]},
        "requirements": TODO,
        "conditions": conditions,
        "gates": gates,
        "behaviours": {"ungated": TODO, "gated": []},
        "obfuscation": {"level": TODO, "techniques": techniques, "decoded": None,
                        "unrecovered": found["unrecovered"]},
        "reachability": {"needs_remote": TODO,
                         "endpoints": [{"indicator": e["indicator"], "role": TODO} for e in hints["endpoints"]]},
        "attack_type": TODO, "family_hint": TODO, "claude_assessment": TODO, "assessment_reason": TODO,
        "label_disagreement": False, "confidence": TODO, "needs_manual_review": False, "review_reasons": [],
        "normalisation": {"derivations": found.get("derivations", []), "candidate_set": candidate_set(found),
                          "units_summary": found.get("units_summary", []),
                          "truncation": {"walk_limit": found.get("truncation", {}).get("walk_limit", False),
                                         "context_limited_files":
                                             len(found.get("truncation", {}).get("context_limited_files", []))}},
        "candidate_review": {"dropped": []},
    }


def generator_id() -> str:
    """gate_extract@<digest of the generator's source and the shared code it uses>, so a record names the exact
    generator that proposed its candidates and any change to it shows."""
    files = [paths.CODE_ROOT / "tools" / "analysis" / "gate_extract.py",
             *sorted((paths.CODE_ROOT / "tools" / "common").glob("*.py"))]
    return "gate_extract@" + anchors.digest(b"".join(f.name.encode() + b"\0" + f.read_bytes() for f in files))[:10]


def candidate_set(found: dict) -> dict:
    """Identity of the candidate set the analyst chose from, so a record can be tied to the generator run."""
    body = json.dumps({"conditions": found["conditions"], "gates": found["gates"]}, sort_keys=True, default=str)
    return {"generator": generator_id(), "sha256": anchors.digest(body.encode())}


def truncation_note(t: dict) -> str | None:
    if not (t["walk_limit"] or t["context_limited_files"]):
        return None
    parts = [f"walk budget ({t['max_walks']}) used up"] if t["walk_limit"] else []
    if t["context_limited_files"]:
        parts.append(f"some helpers walked under only {t['max_contexts']} guard contexts in "
                     + ", ".join(t["context_limited_files"][:5]) + (" …" if len(t["context_limited_files"]) > 5 else ""))
    return ("generator truncated: " + "; ".join(parts) + "; candidates there may be missing")[:300]


def import_time_facts(root: Path, eco: str, manifest: dict | None) -> dict:
    """What a judge of import_time_only / payload_in_dependency / no_install_code needs to look at."""
    if eco == "npm":
        mains = [m for m in (manifest.get("main"), manifest.get("module"), "index.js") if isinstance(m, str)]
        deps = {k: v for k, v in (manifest.get("dependencies") or {}).items()} if isinstance(
            manifest.get("dependencies"), dict) else {}
        return {"import_entry_files": [m for m in dict.fromkeys(mains) if (root / m).is_file()],
                "dependencies": {k: defang(str(v)) for k, v in list(deps.items())[:50]},
                "scripts": sorted((manifest.get("scripts") or {}).keys()) if isinstance(manifest.get("scripts"), dict)
                else []}
    inits = sorted(p.relative_to(root).as_posix() for p in root.rglob("__init__.py")
                   if len(p.relative_to(root).parts) <= 3)
    return {"import_entry_files": inits[:20]}


def lookup_release(package: dict, sample: Path, registry: bool) -> None:
    """Asks the registry for the publish date. Only for a package that is prepared or recorded as a member, so
    duplicates and folders left in progress never cost a lookup."""
    if registry:
        package["released_at"], package["released_at_source"] = release_date(
            package["ecosystem"], package["name"], package["version"], sample.name, registry=True)


def prepare(sample: Path, source: str | None, label: str | None, seen: dict | None = None, *,
            model: str | None = None, registry: bool = False, batch: dict | None = None,
            allow_existing: bool = False) -> dict:
    """Prepares one sample. `seen` maps cluster keys to representatives (members are detected against it), `batch`
    maps (ecosystem, normalised name, version) to the first sample of that package in this batch."""
    work = paths.SCRATCH / f"_unpack_{hashlib.sha1(str(sample.resolve()).encode()).hexdigest()[:12]}"
    try:
        return _prepare(sample, source, label, seen, model, registry, batch, work, allow_existing)
    finally:
        discard(work)  # already gone unless the sample was turned away or something failed


def _prepare(sample: Path, source: str | None, label: str | None, seen: dict | None,
             model: str | None, registry: bool, batch: dict | None, work: Path, allow_existing: bool = False) -> dict:
    sample = sample.resolve()
    dataset, inferred_label = infer_source(sample)
    dataset, label = source or dataset, label or inferred_label
    archive_sha = sha256(sample) if sample.is_file() else None
    path_parts = [p.lower() for p in sample.parts]
    guess_eco = "npm" if "npm" in path_parts else "pypi" if "pypi" in path_parts else "unknown"
    stem = re.sub(r"(\.tar\.gz|\.tgz|\.zip|\.whl|\.tar|\.tar\.bz2|\.egg)$", "", sample.name, flags=re.I)
    package = {"ecosystem": guess_eco, "name": stem, "version": None, "archive_sha256": archive_sha,
               "source_dataset": dataset, "source_label": label}
    # The dated archive name is all an early skip has; the registry is asked once name and version are known.
    package["released_at"], package["released_at_source"] = release_date(guess_eco, None, None, sample.name)

    discard(work)
    try:
        if sample.is_dir():
            shutil.copytree(sample, work / "layer0", symlinks=False)
            unpacked = work / "layer0"
        else:
            unpack(sample, work / "layer0")
            unpacked = unwrap(work / "layer0")
    except UnpackError as e:
        return skip(package, "files_missing", f"archive could not be unpacked: {e}", work)

    if not any(p.is_file() for p in unpacked.rglob("*")):
        return skip(package, "files_missing", "archive is empty", work)
    eco, root, kind = find_root(unpacked)
    if eco is None:
        return skip(package, "not_a_package", "no package.json, setup.py, pyproject.toml or PKG-INFO", work)

    ex = Extractor(root)
    manifest = setup = None
    if eco == "npm":
        manifest = read_json(root / "package.json")
        if not isinstance(manifest, dict):
            package["ecosystem"] = "npm"
            return skip(package, "files_missing", "package.json is not valid JSON", work)
        name, version = manifest.get("name"), manifest.get("version")
    elif kind == "wheel":
        meta = next(root.glob("*.dist-info/METADATA"), None)
        name, version = (header(meta, "Name"), header(meta, "Version")) if meta is not None else (None, None)
    else:
        setup = setup_call(ex)
        project = {}
        if (root / "pyproject.toml").is_file():
            try:
                project = tomllib.loads((root / "pyproject.toml").read_text(errors="replace")).get("project", {})
            except tomllib.TOMLDecodeError:
                project = {}
        name = header(root / "PKG-INFO", "Name") or project.get("name") or setup.get("name")
        version = header(root / "PKG-INFO", "Version") or project.get("version") or setup.get("version")
    package.update(ecosystem=eco, name=str(name) if name else stem, version=str(version) if version else None)

    key = key_for(eco, package["name"], package["version"])
    if batch is not None:
        ident = (eco, contract.normalise_name(eco, package["name"]), package["version"])
        first = batch.get(ident)
        if first is not None:
            same = archive_sha is not None and archive_sha == first["archive_sha256"]
            note = (f"same package as {first['sample']}: " +
                    ("byte-identical archive, not prepared again" if same else
                     "a different archive; decide which one to analyse"))
            return {"status": "same_archive" if same else "duplicate_key", "key": first["key"],
                    "archive_sha256": archive_sha, "note": note}
        batch[ident] = {"key": key, "archive_sha256": archive_sha, "sample": str(sample)}
    existing = existing_record(eco, package["name"], package["version"])
    if existing and not allow_existing:  # the repair pass reopens a finished report (tools/analysis/repair.py)
        return {"status": "duplicate", "key": key, "record": str(existing.relative_to(paths.ROOT))}

    dest = paths.SCRATCH / key
    if dest.exists():
        why = reset.in_progress(dest)
        if why:
            return {"status": "in_progress", "key": key, "note": f"not prepared again: {why}",
                    "prepared": str((dest / "prepared.json").relative_to(paths.ROOT))}
        discard(dest)
    dest.mkdir(parents=True)
    shutil.move(str(work), dest / "unpacked")
    root = dest / "unpacked" / root.relative_to(work)
    package["sample_path"] = sample_path(sample)
    package["package_root"] = root.relative_to(dest / "unpacked").as_posix()
    ex = Extractor(root)
    if eco == "npm":
        entries, notes = npm_entries(root, manifest, ex)
        manifest_conds = manifest_conditions(manifest, root)
    elif kind == "wheel":
        entries, notes, manifest_conds = [], ["wheel: installing it runs no package code"], []
    else:
        entries, notes = pypi_entries(root, ex, setup_call(ex))
        manifest_conds = []

    launched = not_chained(entries, root, ex) if entries else []
    if entries:
        cluster = cluster_key_of(entries, root, package, [item["file"] for item in launched])
        package["cluster_key"] = cluster
        index = existing_clusters() if seen is None else seen
        rep = index.get(cluster)
        if rep is not None:
            lookup_release(package, sample, registry)
            path = write_member(package)
            discard(dest)
            return {"status": "member", "key": key, "cluster_key": cluster, "representative": rep,
                    "record": str(path.relative_to(paths.ROOT))}
        if seen is not None:
            seen[cluster] = f"{eco}:{package['name']}@{package['version']}"
    lookup_release(package, sample, registry)

    prepared = {"key": key, "archive": str(sample), "package_root": str(root.relative_to(paths.ROOT)),
                "package": package, "kind": kind}
    if not entries:
        prepared.update(status="needs_skip_reason", notes=notes,
                        facts=import_time_facts(root, eco, manifest),
                        skip_choices=["no_install_code", "import_time_only", "payload_in_dependency"])
    else:
        found = ex.run([{"hook": e["hook"], "lang": e["_lang"], "entry_files": e["_entry_files"],
                         "chain": e["file_chain"], "entry_functions": e["_entry_functions"],
                         "launched": [i["file"] for i in launched if e["hook"] in i["hooks"] and i["kind"] in ("js", "py")
                                      and i["kind"] == e["_lang"]]}
                        for e in entries])
        found["derivations"] = save_derivations(found, ex, dest / "derived")
        for e in entries:
            if found["hints"]["silent_failure"].get(e["hook"]):
                e["silent_failure"] = True
        flag_not_chained(launched, notes, found)
        if truncation_note(found["truncation"]):
            notes.append(truncation_note(found["truncation"]))
        prepared.update(status="analyse", notes=notes, truncation=found["truncation"], units=found["units"],
                        candidates={"conditions": found["conditions"], "gates": found["gates"],
                                    "guards": found["guards"]},
                        hints=found["hints"], files=found["files"],
                        record=skeleton(package, entries, notes, found, manifest_conds, model))
    (dest / "prepared.json").write_text(json.dumps(prepared, indent=2, ensure_ascii=False, default=str) + "\n",
                                        encoding="utf-8")
    # The files Claude edits; write_report.py reads them back.
    if prepared["status"] == "analyse":
        (dest / "record.json").write_text(json.dumps(prepared["record"], indent=2, ensure_ascii=False) + "\n",
                                          encoding="utf-8")
        (dest / "summary.md").write_text("## Summary\n\nTODO\n\n## Notes\n\nTODO\n", encoding="utf-8")
    else:
        (dest / "skip.json").write_text(json.dumps({"reason": TODO, "note": TODO, "model_name": model or TODO}, indent=2) + "\n",
                                        encoding="utf-8")
    return {"status": prepared["status"], "key": key, "prepared": str((dest / "prepared.json").relative_to(paths.ROOT))}


QUEUED = ("analyse", "needs_skip_reason", "in_progress", "error")


def merge_queue(rows: list[dict], results: list[dict]) -> list[dict]:
    """The queue after this batch: each result's row added, replacing the earlier row of its key or sample; a
    second archive of a package folded into that package's row; every other row kept. The row of a package left
    in progress is never replaced (it belongs to the run still working on it)."""
    def find(key):
        return next((r for r in rows if key is not None and r.get("key") == key), None)

    for res in results:
        status, sample, key = res["status"], res["sample"], res.get("key")
        if status in QUEUED:
            if status == "in_progress" and find(key) is not None:
                continue
            row = {"key": key, "status": status, "sample": sample}
            row.update({k: res[k] for k in ("prepared", "error", "note") if res.get(k)})
            rows = [r for r in rows if not ((key is not None and r.get("key") == key) or r.get("sample") == sample)]
            rows.append(row)
        elif status in ("same_archive", "duplicate_key"):
            dup = {"sample": sample, "archive_sha256": res.get("archive_sha256"), "identical": status == "same_archive"}
            row = find(key)
            if row is None:
                rows.append({"key": key, "status": status, "sample": sample, "note": res["note"], "duplicates": [dup]})
                continue
            if not any(d.get("sample") == sample for d in row.get("duplicates", [])):
                row.setdefault("duplicates", []).append(dup)
            if status == "duplicate_key":
                row.update(status="duplicate_key", note=res["note"])
        else:  # skipped, member, duplicate: no row, and an earlier failure of this sample is resolved
            rows = [r for r in rows if not (r.get("sample") == sample and r.get("status") == "error")]
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("sample", type=Path)
    ap.add_argument("--source", choices=DATASETS)
    ap.add_argument("--label", choices=["malicious", "benign", "unknown"])
    ap.add_argument("--batch", action="store_true", help="prepare every archive under the directory")
    ap.add_argument("--model", help="model id of the analyst model, for package.model_name")
    ap.add_argument("--no-registry", action="store_true", help="do not ask the registry for the publish date")
    args = ap.parse_args()

    samples = sorted(p for p in args.sample.rglob("*") if is_archive(p)) if args.batch else [args.sample]
    seen = existing_clusters()
    batch: dict = {}
    results = []
    for s in samples:
        try:
            r = prepare(s, args.source, args.label, seen, model=args.model,
                        registry=not args.no_registry, batch=batch)
        except Exception as e:  # one bad sample must not stop the batch; its row says what went wrong
            r = {"status": "error", "key": None, "error": f"{type(e).__name__}: {e}"[:300]}
        r["sample"] = str(s)
        results.append(r)
        detail = r.get("prepared") or r.get("record", "")
        if r["status"] == "member":
            detail = f"-> {r['representative']}  {r['record']}"
        elif r["status"] in ("error", "in_progress", "same_archive", "duplicate_key"):
            detail = r.get("error") or r.get("note", "")
        print(f"{r['status']:18} {r.get('key') or r.get('reason') or s}  {detail}")
    if args.batch:
        rows = work_queue.update(lambda old: merge_queue(old, results))
        counts = {}
        for r in results:
            counts[r["status"]] = counts.get(r["status"], 0) + 1
        todo = sum(r.get("status") in ("analyse", "needs_skip_reason") for r in rows)
        print(f"\n{len(results)} samples: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
              + f". Queue: scratch/queue.jsonl ({todo} for Claude"
              + (f", {counts['duplicate_key']} duplicate_key for a person" if counts.get("duplicate_key") else "")
              + ")")
    return 1 if any(r["status"] == "error" for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
