#!/usr/bin/env python3
"""
Replay a hand-cracked decode and register it as a `decode_spec` derivation, so the verifier can
rebuild the decoded source deterministically on any machine (gated by output_sha256).

Use this when you have cracked a package's bespoke cipher by hand: write the decoder as a pure module
under tools/common/decoders/ (interface: `decode(input_bytes, params, read) -> bytes`), then run

  register_decode.py scratch/<key> --decoder NAME --input FILE [--input-derived dN] [--lang js|py] [--id dN] \
                     [--params '{"iterations": 100000, "key_site": {...anchor from cite.py...}}']

It reads package bytes AS DATA (never runs package code), runs the decoder, writes the decoded source
to scratch/<key>/derived/dN, and prints the derivation JSON to add to the record's
normalisation.derivations[]. Then cite claims into the decoded file with
`cite.py scratch/<key> FILE --derived dN ...`.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.common import anchors, decode_spec, paths  # noqa: E402
from tools.common.sanitize import defang  # noqa: E402
from tools.common.tsparse import EXTENSIONS, PARSERS  # noqa: E402

PREVIEW = 200


def reader(work: Path, prepared: dict):
    """read_bytes(file, derived_from) over the unpacked package and earlier derivations, as data."""
    root = (work / "unpacked" / prepared["package"]["package_root"]).resolve()

    def read_bytes(file: str, derived_from: str | None) -> bytes:
        if derived_from:
            path = work / "derived" / derived_from
        else:
            path = (root / file).resolve()
            if not path.is_relative_to((work / "unpacked").resolve()):
                raise SystemExit(f"{file} escapes the package")
        if not path.is_file():
            raise SystemExit(f"no such file: {path}")
        return path.read_bytes()

    return read_bytes


def next_id(work: Path, prepared: dict) -> str:
    used = {int(p.name[1:]) for p in (work / "derived").glob("d*") if re.fullmatch(r"d\d+", p.name)}
    records = [prepared.get("record") or {}]
    if (work / "record.json").is_file():
        records.append(json.loads((work / "record.json").read_text(encoding="utf-8")))
    used |= {int(d["id"][1:]) for rec in records for d in rec.get("normalisation", {}).get("derivations", [])}
    return f"d{(max(used) + 1) if used else 1}"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0].strip())
    ap.add_argument("work", type=Path, help="the package's scratch/<key> folder")
    ap.add_argument("--decoder", required=True, help="a module name under tools/common/decoders/")
    ap.add_argument("--input", required=True, help="the encoded file (relative to the package root)")
    ap.add_argument("--input-derived", help="read the input from this earlier derivation instead of the package file")
    ap.add_argument("--params", default="{}", help="cipher arguments as a JSON object (anchors for key material too)")
    ap.add_argument("--lang", help="language of the decoded source (js/py); taken from --input's extension otherwise")
    ap.add_argument("--id", dest="did", help="the derivation id (dN); the next free one otherwise")
    ap.add_argument("--candidate", action="store_true",
                    help="load the decoder from scratch/<key>/decoders/<name>.py (a batch session cannot write to "
                         "tools/); the driver adds it to tools/common/decoders/ after the session")
    args = ap.parse_args()

    paths.confine(args.work)
    prepared = json.loads((args.work / "prepared.json").read_text(encoding="utf-8"))
    try:
        params = json.loads(args.params)
    except ValueError as e:
        ap.error(f"--params is not valid JSON: {e}")
    if not isinstance(params, dict):
        ap.error("--params must be a JSON object")
    params["decoder"] = args.decoder
    lang = args.lang or EXTENSIONS.get(Path(args.input).suffix.lower())
    if lang not in PARSERS:
        ap.error("cannot tell the decoded source's language from --input; pass --lang js or --lang py")
    params["lang"] = lang  # recorded so cite.py, write_report.py and the verifier all parse it the same way

    did = args.did or next_id(args.work, prepared)
    if not re.fullmatch(r"d\d+", did):
        ap.error("--id must look like d1, d2, ...")
    if did in {d["id"] for d in (prepared.get("record") or {}).get("normalisation", {}).get("derivations", [])}:
        ap.error(f"{did} is a derivation prepare.py made; leave out --id to get a free one")
    derivation = {"id": did, "recipe": decode_spec.RECIPE, "recipe_version": decode_spec.RECIPE_VERSION,
                  "input": {"file": args.input, "derived_from": args.input_derived}, "params": params}

    read_bytes = reader(args.work, prepared)
    decode_fn = None
    if args.candidate:
        from tools.common.decoders import load_decoder_file
        cand = args.work / "decoders" / f"{args.decoder}.py"
        repo = paths.CODE_ROOT / "tools" / "common" / "decoders" / f"{args.decoder}.py"
        if not cand.is_file():
            ap.error(f"no candidate decoder at {cand}")
        if repo.is_file() and repo.read_bytes() != cand.read_bytes():
            ap.error(f"tools/common/decoders/{args.decoder}.py already exists with other code; pick another name")
        try:
            decode_fn = load_decoder_file(cand)
        except ValueError as e:
            raise SystemExit(str(e))
    try:
        out = decode_spec.replay(read_bytes, derivation, decode_fn)
    except (ValueError, KeyError) as e:
        raise SystemExit(f"decode failed: {e}")
    derivation["output_sha256"] = anchors.digest(out)

    (args.work / "derived").mkdir(parents=True, exist_ok=True)
    (args.work / "derived" / did).write_bytes(out)

    preview = defang(out[:PREVIEW].decode("utf-8", "replace"))
    print(json.dumps(derivation))
    print(f"# wrote derived/{did} ({len(out)} bytes), output_sha256 {derivation['output_sha256']}", file=sys.stderr)
    print(f"# add this to the record's normalisation.derivations[]; cite into it with "
          f"cite.py {args.work} {args.input} --derived {did} ...", file=sys.stderr)
    print(f"# preview: {preview}{' …' if len(out) > PREVIEW else ''}", file=sys.stderr)


if __name__ == "__main__":
    main()
