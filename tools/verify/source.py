"""
Rebuilds a record's package from samples/ and resolves its anchors back to syntax nodes, for the verifier.

The archive is found by archive_sha256 (samples/ is hashed once and the index cached), unpacked the way
prepare.py unpacks it into scratch/verify/_work/<key>/, and every derivation in the record is rebuilt with its
recipe and checked against output_sha256. Nothing in the package is executed: files are unpacked as data and
parsed with tree-sitter.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.common import anchors, decode_spec, deobf, hooks, paths
from tools.common.contract import key_for
from tools.common.tsparse import EXTENSIONS, PARSERS
from tools.common.unpack import UnpackError, is_archive, sha256, unpack, unwrap


class Unanchored(Exception):
    """An anchor that cannot be checked; .reason is a verification reason_code."""

    def __init__(self, reason: str, detail: str = ""):
        super().__init__(detail or reason)
        self.reason, self.detail = reason, detail


def sample_index() -> dict[str, Path]:
    """archive sha256 -> path for every archive under samples/ (cached by path, size and mtime)."""
    cache_path = paths.SCRATCH / "verify" / "_sample_index.json"
    cache = json.loads(cache_path.read_text()) if cache_path.is_file() else {}
    fresh, out = {}, {}
    for p in sorted(paths.SAMPLES.rglob("*")) if paths.SAMPLES.is_dir() else []:
        if not is_archive(p):
            continue
        rel, st = p.relative_to(paths.SAMPLES).as_posix(), p.stat()
        hit = cache.get(rel)
        digest = hit["sha256"] if hit and hit["size"] == st.st_size and hit["mtime"] == st.st_mtime else sha256(p)
        fresh[rel] = {"size": st.st_size, "mtime": st.st_mtime, "sha256": digest}
        out.setdefault(digest, p)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(fresh, indent=1, sort_keys=True))
    return out


def lang_of(file: str, derivation: dict | None) -> str | None:
    if derivation is not None and derivation["recipe"] == "inline_script":
        return "py" if str(derivation["params"].get("flag", "")).startswith("-c") else "js"
    if derivation is not None and derivation["recipe"] == "decode_spec" and derivation["params"].get("lang"):
        return derivation["params"]["lang"]
    return EXTENSIONS.get(Path(file).suffix.lower())


class Package:
    """One record's package, rebuilt from its sample. Raises Unanchored (sample_missing) when it cannot be."""

    def __init__(self, rec: dict, index: dict[str, Path] | None = None):
        pk = rec["package"]
        self.key = key_for(pk["ecosystem"], pk["name"], pk["version"])
        self.derivations = {d["id"]: d for d in rec["normalisation"]["derivations"]}
        self._bytes, self._trees, self._failed = {}, {}, {}
        self.cache: dict = {}  # per-file indexes the checks build once (e.g. witness.defs_index)
        sha = pk.get("archive_sha256")
        sample = (index if index is not None else sample_index()).get(sha) if sha else None
        if sample is None:
            raise Unanchored("sample_missing", f"no archive with sha256 {str(sha)[:12]}… under samples/")
        work = paths.SCRATCH / "verify" / "_work" / self.key
        marker = work / "archive_sha256"
        if not (marker.is_file() and marker.read_text() == sha):
            if work.exists():
                shutil.rmtree(work)
            try:
                unpack(sample, work / "unpacked" / "layer0")
                unwrap(work / "unpacked" / "layer0")
            except UnpackError as e:
                raise Unanchored("sample_missing", f"archive could not be unpacked: {e}")
            marker.write_text(sha)
        self.root = work / "unpacked" / (pk.get("package_root") or "")
        if not self.root.is_dir():
            raise Unanchored("sample_missing", f"package_root {pk.get('package_root')} not in the archive")

    SOURCE_SUFFIXES = (".js", ".mjs", ".cjs", ".py")

    def source_files(self) -> list[str]:
        """Every parseable source file of the package, as sorted relative paths (deterministic)."""
        if not hasattr(self, "_sources"):
            root = self.root.resolve()
            self._sources = sorted(q.relative_to(root).as_posix() for q in root.rglob("*")
                                   if q.suffix in self.SOURCE_SUFFIXES and q.is_file() and not q.is_symlink())
        return self._sources

    def bytes(self, file: str, derived_from: str | None) -> bytes:
        key = (file, derived_from)
        if key in self._failed:
            raise self._failed[key]
        if key not in self._bytes:
            try:
                self._bytes[key] = self._derive(derived_from) if derived_from else self._read(file)
            except Unanchored as e:
                self._failed[key] = e
                raise
        return self._bytes[key]

    def _read(self, file: str) -> bytes:
        path = (self.root / file).resolve()
        if not path.is_relative_to(self.root.resolve()) or not path.is_file():
            raise Unanchored("no_anchor", f"{file} is not in the package")
        return path.read_bytes()

    def _derive(self, did: str) -> bytes:
        d = self.derivations.get(did)
        if d is None:
            raise Unanchored("recipe_failed", f"unknown derivation {did}")
        if d["recipe"] == "inline_script":
            manifest = json.loads(self.bytes("package.json", None))
            code = hooks.inline_code(manifest, self.root, d["params"].get("hook", ""), d["params"].get("flag", ""))
            out = code.encode() if code is not None else None
        elif d["recipe"] == "obfuscatorio_strings":
            got = deobf.derive(self.bytes(d["input"]["file"], d["input"]["derived_from"]))
            out = got[0] if got else None
            if got and got[1] != d["params"]:
                raise Unanchored("recipe_failed", f"derivation {did} rebuilt with different parameters")
        elif d["recipe"] == "decode_spec":
            try:
                out = decode_spec.replay(self.bytes, d)
            except Unanchored:
                raise
            except Exception as e:  # noqa: BLE001 - any decoder failure is a failed rebuild
                raise Unanchored("recipe_failed", f"derivation {did} decode failed: {e}")
        else:
            raise Unanchored("recipe_failed", f"no rebuild for recipe {d['recipe']}")
        if out is None or anchors.digest(out) != d["output_sha256"]:
            raise Unanchored("recipe_failed", f"derivation {did} did not rebuild to its output_sha256")
        return out

    def tree(self, file: str, derived_from: str | None):
        """(src, tree, lang) for a parsed file, or (src, None, None) for a file that is not code."""
        key = (file, derived_from)
        if key not in self._trees:
            src = self.bytes(file, derived_from)
            lang = lang_of(file, self.derivations.get(derived_from) if derived_from else None)
            self._trees[key] = (src, PARSERS[lang].parse(src) if lang else None, lang)
        return self._trees[key]

    def node(self, anchor: dict):
        """(node or None, src, lang) at the anchor. The bytes must hash to the anchor; for code files the node
        must span exactly the anchor's range with its node type (a stmt_range anchor returns None)."""
        src, tree, lang = self.tree(anchor["file"], anchor["derived_from"])
        why = anchors.mismatch(anchor, src)
        if why:
            raise Unanchored("anchor_hash_mismatch", why)
        if tree is None or anchor["node_type"] in (anchors.RANGE, anchors.TEXT):
            return None, src, lang
        n = tree.root_node.descendant_for_byte_range(anchor["start_byte"], anchor["end_byte"])
        while n is not None and (n.start_byte, n.end_byte) == (anchor["start_byte"], anchor["end_byte"]):
            if n.type == anchor["node_type"]:
                return n, src, lang
            n = n.parent
        raise Unanchored("parse_failed", f"no {anchor['node_type']} node spans the anchor")
