"""
Registry of hand-cracked decoders for the `decode_spec` derivation recipe.

Each decoder is one module in this package exposing

    def decode(input_bytes: bytes, params: dict, read) -> bytes: ...

a PURE function that turns the encoded `input_bytes` into decoded source. `params` carries the
cipher's arguments (iteration counts, salts, table sizes, ...). `read(anchor)` returns the bytes of
an in-package anchor ``{file, derived_from, start_byte, end_byte}`` so key material embedded in the
package can be pulled as DATA. A decoder must never import, execute or eval package code, open the
network, or touch the filesystem; it only transforms bytes it is handed.

This is the extension point: to make a new hand-cracked cipher replayable, drop a module here and
name it from a `decode_spec` derivation's ``params.decoder``. A module is one CIPHER, never one package: when
another package uses the same cipher, its derivation names the same module with its own ``params`` (keys, salts,
the decode function's minified name). Name a module after the technique, and open its docstring with
``Family:``, ``Reverses:`` and ``Per sample:`` lines so the next analyst can find it. Both the analyst tool
(``tools/analysis/register_decode.py``) and the verifier (``tools/verify/source.py``) resolve and run it
through :func:`load_decoder`, so the same bytes come out on any machine and are gated by
``output_sha256``.
"""
from __future__ import annotations

import importlib
import re
from typing import Callable

_NAME = re.compile(r"^[a-z][a-z0-9_]*$")

Decoder = Callable[[bytes, dict, Callable[[dict], bytes]], bytes]


def load_decoder(name: str) -> Decoder:
    """The ``decode`` function of the registered decoder module, or a ValueError if there is none.

    Only a bare ``[a-z][a-z0-9_]*`` name is accepted and it is resolved strictly inside this package,
    so a spec can never point the loader at an arbitrary import path."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError(f"not a decoder name: {name!r}")
    try:
        mod = importlib.import_module(f"{__name__}.{name}")
    except ModuleNotFoundError:
        raise ValueError(f"unknown decoder {name!r} (add tools/common/decoders/{name}.py)")
    fn = getattr(mod, "decode", None)
    if not callable(fn):
        raise ValueError(f"decoder {name!r} has no decode() function")
    return fn


# --- candidate decoders written in a sandboxed batch session ----------------------------------------------
#
# A driver session cannot write into this package (the repo is read-only there), so it writes a new decoder to
# scratch/<key>/decoders/<name>.py instead. register_decode.py --candidate loads it from there, and the driver
# copies it in here after the session. Both go through check_decoder_source first: a decoder is pure data
# transformation, so anything that could reach the system, the network, files or other code is refused.

ALLOWED_IMPORTS = {"base64", "binascii", "codecs", "zlib", "gzip", "bz2", "lzma", "hashlib", "hmac", "struct", "re",
                   "string", "itertools", "functools", "math", "typing", "collections", "dataclasses", "json",
                   "io", "tokenize", "__future__", "tools.common.tsparse", "tools.common.decoders",
                   "tools.common.deobf", "tools.common.sanitize", "tools.common.decode"}
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__", "open", "input", "globals", "locals", "vars", "getattr",
                   "setattr", "delattr", "breakpoint", "memoryview", "importlib", "os", "sys", "subprocess", "socket",
                   "shutil", "pathlib", "pickle", "marshal", "ctypes", "urllib", "http", "requests"}


def check_decoder_source(src: str) -> list[str]:
    """Why a decoder's source may not be loaded: imports outside the allowlist, a forbidden name, a dunder
    attribute, or no top-level decode(input_bytes, params, read). Empty when it may."""
    import ast
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return [f"does not parse: {e}"]
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            # `from tools.common import deobf` imports the module tools.common.deobf
            mods = ([f"{node.module}.{a.name}" if node.module == "tools.common" else node.module for a in node.names]
                    if node.level == 0 else ["<relative import>"])
        else:
            mods = []
        for m in mods:
            if not any(m == a or m.startswith(a + ".") for a in ALLOWED_IMPORTS):
                problems.append(f"line {node.lineno}: import of {m} is not allowed in a decoder")
        if isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES:
            problems.append(f"line {node.lineno}: {node.id} is not allowed in a decoder")
        if isinstance(node, ast.Attribute) and node.attr.startswith("__") and node.attr.endswith("__"):
            problems.append(f"line {node.lineno}: dunder attribute {node.attr} is not allowed in a decoder")
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "decode"]
    if not fns or len(fns[0].args.args) != 3:
        problems.append("no top-level decode(input_bytes, params, read)")
    return problems


def load_decoder_file(path) -> Decoder:
    """The decode function of a candidate decoder file, after check_decoder_source; ValueError when it fails."""
    import importlib.util
    from pathlib import Path
    path = Path(path)
    if not _NAME.match(path.stem):
        raise ValueError(f"not a decoder name: {path.stem!r}")
    problems = check_decoder_source(path.read_text(encoding="utf-8"))
    if problems:
        raise ValueError("candidate decoder refused: " + "; ".join(problems[:5]))
    spec = importlib.util.spec_from_file_location(f"_candidate_{path.stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.decode
