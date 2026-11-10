"""
Safe unpacking of untrusted sample archives (zip, ZipCrypto/AES zips, tar, wheels) and locating the package
root inside them. Archive members are only extracted as data; nothing in them is run.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from pathlib import Path

ARCHIVE_SUFFIXES = (".zip", ".tgz", ".tar.gz", ".tar", ".whl", ".tar.bz2", ".tbz2", ".egg")
# Untrusted archives: a cap keeps a zip bomb from filling the disk.
MAX_BYTES = 500 * 1024 * 1024
ZIP_PASSWORD = b"infected"


class UnpackError(Exception):
    """The archive itself is unusable (corrupt, unsafe, too big): a property of the sample."""


class MissingTool(Exception):
    """A tool this machine lacks (7-Zip): a property of the machine, never of the sample, so it must not become a
    skip record."""


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_archive(path: Path) -> bool:
    return path.is_file() and path.name.lower().endswith(ARCHIVE_SUFFIXES)


def unpack(archive: Path, dest: Path) -> None:
    """By content, not name: pypi_malregistry stores some wheels under a .tar.gz name."""
    dest.mkdir(parents=True, exist_ok=True)
    with open(archive, "rb") as f:
        is_zip = f.read(4) == b"PK\x03\x04"
    if is_zip or (archive.name.lower().endswith((".zip", ".whl", ".egg")) and zipfile.is_zipfile(archive)):
        unpack_zip(archive, dest)
    else:
        unpack_tar(archive, dest)


def unpack_zip(archive: Path, dest: Path) -> None:
    try:
        zf = zipfile.ZipFile(archive)
    except (zipfile.BadZipFile, OSError) as e:
        raise UnpackError(f"unreadable zip: {e}") from e
    with zf:
        members = zf.infolist()
        if sum(m.file_size for m in members) > MAX_BYTES:
            raise UnpackError("archive expands beyond the size cap")
        for m in members:
            if m.filename.startswith(("/", "\\")) or ".." in Path(m.filename).parts or re.match(r"^[A-Za-z]:", m.filename):
                raise UnpackError(f"unsafe member path {m.filename!r}")
            if stat.S_ISLNK(m.external_attr >> 16):
                raise UnpackError(f"link member {m.filename!r}")
        encrypted = any(m.flag_bits & 0x1 for m in members)
        try:
            zf.extractall(dest, pwd=ZIP_PASSWORD if encrypted else None)
        except NotImplementedError:
            unpack_7z(archive, dest)
        except (RuntimeError, zipfile.BadZipFile, OSError, EOFError) as e:
            raise UnpackError(f"zip extraction failed: {e}") from e


def unpack_7z(archive: Path, dest: Path) -> None:
    """AES-encrypted zips, which Python's zipfile cannot read."""
    exe = shutil.which("7zz") or shutil.which("7z")
    if exe is None:
        raise MissingTool(f"{archive.name} needs 7-Zip for AES decryption (brew install sevenzip)")
    proc = subprocess.run([exe, "x", "-y", f"-p{ZIP_PASSWORD.decode()}", f"-o{dest}", str(archive)],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise UnpackError(f"7-Zip failed: {proc.stderr.strip()[:200]}")
    root = dest.resolve()
    for p in dest.rglob("*"):
        if p.is_symlink() or not p.resolve().is_relative_to(root):
            raise UnpackError(f"unsafe member {p.relative_to(dest)}")


def unpack_tar(archive: Path, dest: Path) -> None:
    try:
        with tarfile.open(archive, "r:*") as tf:
            members = tf.getmembers()
            if sum(m.size for m in members) > MAX_BYTES:
                raise UnpackError("archive expands beyond the size cap")
            for m in members:
                if m.issym() or m.islnk():
                    raise UnpackError(f"link member {m.name!r}")
            tf.extractall(dest, filter="data")
    except (tarfile.TarError, OSError, EOFError) as e:
        raise UnpackError(f"tar extraction failed: {e}") from e


def unwrap(dest: Path) -> Path:
    """Unpacks archives that only contain another archive (Datadog zips around an npm tgz)."""
    for depth in range(3):
        files = [p for p in dest.rglob("*") if p.is_file() and "__MACOSX" not in p.parts]
        if len(files) != 1 or not is_archive(files[0]):
            return dest
        inner = dest.parent / f"layer{depth + 1}"
        unpack(files[0], inner)
        dest = inner
    return dest


def find_root(unpacked: Path) -> tuple[str | None, Path | None, str | None]:
    """(ecosystem, package root, kind) where kind is npm, sdist or wheel."""
    candidates = []
    for p in unpacked.rglob("*"):
        if "__MACOSX" in p.parts or "node_modules" in p.relative_to(unpacked).parts:
            continue
        depth = len(p.relative_to(unpacked).parts)
        if p.name == "package.json" and p.is_file():
            candidates.append((depth, 0, "npm", p.parent, "npm"))
        elif p.name in ("PKG-INFO", "setup.py", "pyproject.toml", "setup.cfg") and p.is_file():
            candidates.append((depth, 1, "pypi", p.parent, "sdist"))
        elif p.name == "METADATA" and p.parent.name.endswith(".dist-info"):
            candidates.append((depth, 2, "pypi", p.parent.parent, "wheel"))
    if not candidates:
        return None, None, None
    _, _, eco, root, kind = min(candidates, key=lambda c: (c[0], c[1]))
    return eco, root, kind


def reached_file_digests(root: Path, file_chains, mask_setup: bool = False) -> list[str]:
    """Sorted content SHA-256 of every install-reached file, for the campaign cluster key. With `mask_setup`
    (PyPI), a Python file's setup() metadata literals are masked first (mask_setup_metadata), so typosquats that
    differ only in their name, version or description fall into one campaign, as npm packages do whose
    package.json is never hashed."""
    digests = set()
    for rel in {r for chain in file_chains for r in chain}:
        path = root / rel
        if path.is_file():
            data = path.read_bytes()
            if mask_setup and path.suffix.lower() == ".py":
                data = mask_setup_metadata(data)
            digests.add(hashlib.sha256(data).hexdigest())
    return sorted(digests)


# setup() keyword arguments that only describe the package. Their literal values are masked for the cluster key.
# Arguments that change what the build does (cmdclass, packages, install_requires, python_requires, ...) are not.
SETUP_METADATA = frozenset({
    "name", "version", "description", "long_description", "long_description_content_type", "author",
    "author_email", "maintainer", "maintainer_email", "url", "download_url", "keywords", "classifiers", "license",
    "project_urls", "platforms"})
SETUP_CALLEES = frozenset({"setup", "setuptools.setup", "distutils.core.setup"})
METADATA_MASK = b"<setup-metadata>"
_LITERAL_LEAVES = frozenset({"integer", "float", "true", "false", "none"})


def masked_literal(node) -> bool:
    """A value that holds no code: a string without interpolation, a number, True/False/None, implicitly
    concatenated strings, a list/tuple/set/dict of such values, or a bare name (`__version__`), whose assignment
    elsewhere in the file stays hashed. Calls (`open('README').read()`), attributes, subscripts, operators,
    f-strings with substitutions and splats are code, never masked."""
    t = node.type
    if t == "string":
        return not any(c.type == "interpolation" for c in node.named_children)
    if t in _LITERAL_LEAVES or t == "identifier":
        return True
    if t == "concatenated_string":
        return all(masked_literal(c) for c in node.named_children if c.type != "comment")
    if t == "parenthesized_expression":
        inner = [c for c in node.named_children if c.type != "comment"]
        return len(inner) == 1 and masked_literal(inner[0])
    if t in ("list", "tuple", "set"):
        return all(masked_literal(c) for c in node.named_children if c.type != "comment")
    if t == "dictionary":
        pairs = [c for c in node.named_children if c.type != "comment"]
        return all(c.type == "pair" and masked_literal(c.child_by_field_name("key"))
                   and masked_literal(c.child_by_field_name("value")) for c in pairs)
    return False


def mask_setup_metadata(src: bytes) -> bytes:
    """`src` with the value of every metadata keyword argument (SETUP_METADATA) of a `setup(...)`,
    `setuptools.setup(...)` or `distutils.core.setup(...)` call replaced by METADATA_MASK, when that value is a
    literal (masked_literal). Every other byte is kept, so two files match only if their code matches. Parsed
    with tree-sitter as data; a file with no such call is returned unchanged."""
    from tools.common.tsparse import PARSERS, descendants
    if b"setup" not in src:
        return src
    tree = PARSERS["py"].parse(src)
    spans = []
    for n in descendants(tree.root_node):
        if n.type != "call":
            continue
        fn, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
        if fn is None or args is None or fn.type not in ("identifier", "attribute") or \
                fn.text.decode("utf-8", "replace") not in SETUP_CALLEES:
            continue
        for kw in args.named_children:
            if kw.type != "keyword_argument":
                continue
            name, value = kw.child_by_field_name("name"), kw.child_by_field_name("value")
            if name is not None and value is not None and name.text.decode("utf-8", "replace") in SETUP_METADATA \
                    and masked_literal(value):
                spans.append((value.start_byte, value.end_byte))
    out, pos = [], 0
    for start, end in sorted(spans):
        if start < pos:
            continue  # nested in a span already masked
        out += [src[pos:start], METADATA_MASK]
        pos = end
    return b"".join(out) + src[pos:]
