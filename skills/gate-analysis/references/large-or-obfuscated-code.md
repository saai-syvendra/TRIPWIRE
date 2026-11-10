# Large, bundled or obfuscated code

How to reach the Step 3 coverage rule (read in full, audited, or unread) when an install-reached file is too big or too scrambled to read top to bottom. Read it when a file is large, minified, bundled or obfuscated, or when `hints.not_chained` lists files. Format details for specific bundlers and packers are in the ecosystem reference.

## Contents

- Why partial reads fail
- Procedure
- Package code or library code
- Sink inventory
- Decoys and dead code
- Decoding a string table
- Extractor candidates on bundles
- Recording coverage

## Why partial reads fail

Malicious bundles hide a small payload among megabytes of legitimate libraries, split it across helper classes, and launch it through files the import walk never sees. Reading only the gate regions the extractor found, or only the entry function, misses whole behaviours that sit in helpers it calls. The procedure below keeps the work bounded without leaving silent gaps.

## Procedure

1. **Measure.** Size, line count, longest line, `hints.obfuscation_signals`, parse error ratio. Note whether the file is a bundle (many modules in one file), obfuscated (scrambled names, string tables, constant-condition branches), or both.
2. **Make it readable, as data.** Decode string tables first (see below) into a scratch copy. Reformat only with your own Python or the repo's tree-sitter parsers (`tools/analysis/gate_extract.py` has them) on that scratch copy: splitting on statement boundaries is enough. Never pass the file to the package's language runtime or to tools that load it through that runtime.
3. **Segment.** Split the file into units: bundler modules or wrappers (formats in the ecosystem reference), otherwise top-level declarations from the syntax tree. Record each unit's offset and size so every byte belongs to some unit.
4. **Find the package's own code.** Start from the entry point (trailing top-level code, the bundler's entry module) and follow what it references, transitively. Embedded strings that are scripts, workflow files or source text of other files are package code too.
5. **Classify every unit** as package code or library code (next section). Package code is read in full, every line, including every helper and class it calls. Library code is audited with the sink inventory.
6. **Inventory sinks** across the whole file, attribute every hit to a unit, and re-classify any library unit with an unexplained hit as package code.
7. **Record** the result (last section) and the conditions, gates and behaviours you found.

## Package code or library code

Library code is a unit you can name (from its strings, error messages, licence banners, path comments or API shape) that does only what that library is for. Everything else is package code, including:
- glue between libraries and the entry point;
- unnamed or renamed units you cannot attribute;
- anything that touches install context, environment variables, tokens or credential files, process launch, or the network in a way the library would not;
- strings that hold scripts, commands or configuration for other systems.

When unsure, read it. Recognisable libraries can still be tampered with; the inventory is what makes "audited" trustworthy, so do not skip it because a unit looks familiar.

**When tracing from the entry reaches almost everything.** In single-scope bundles (one big closure, all helpers and libraries side by side) following references from the entry pulls in nearly every unit, so reachability does not separate the two. Classify by content instead:
- Start from the payload's own sinks: the sink inventory hits that no library explains (process launches with literal commands, requests to hosts no library would contact, reads of credential files and token variables). The units holding them, and the units that call those, are package code.
- Author fingerprints mark package code: consistent custom log or error strings (often numbered), class and method names that describe the attack rather than an API, embedded scripts or configuration for other systems, campaign strings repeated across units.
- A unit whose strings, error messages and API shape match one library, and that touches none of the above, is library code.
- Read each package unit in full, then read every function it calls, wherever it sits, until the calls lead only into library code.

## Sink inventory

Search the whole file (all units) with your own scratch script and list, per hit, the unit and a one-line attribution:
- process launch and shell execution;
- file writes, deletes, permission changes;
- network calls (HTTP clients, sockets, DNS), and hard-coded hosts and IPs;
- environment variable names read (list them all; library variables are expected, unusual ones are leads);
- sensitive paths (SSH, cloud and package-manager credential files, browser and wallet profiles, CI and container paths);
- dynamic evaluation, decoding calls and runtime code loading;
- timers and long sleeps;
- process exit and detach patterns.

Every hit gets "library behaviour (which library, why)" or "package code (read)". A hit nobody can explain moves its unit to package code.

## Decoys and dead code

Obfuscators add branches under conditions that are constant (two different string literals compared for equality, arithmetic that always holds) and copy real payload snippets into the dead side, so a text search finds "payload" in places that never run. Before counting code as live, show statically that its branch can be taken. Payload copies in dead branches are mentioned once in `execution.notes` and never counted as gates or behaviours. Code defined but never called is not reached; leave it out, with a note if it looks malicious.

## Decoding a string table

Typical layout: one function returning an array of strings, a self-invoking block that rotates the array until a checksum expression equals a constant, and a decoder `f(i)` that returns `array[i - offset]` (sometimes base64 or RC4 decoded), called through many local aliases and wrapper functions.

`prepare.py` recovers this layout itself (`tools/common/deobf.py`, pure Python: it reads the table, offset, encoding and rotation from the syntax tree and only accepts a rotation whose checksum matches). When it succeeds:
- `normalisation.derivations` has an `obfuscatorio_strings` entry for the file, and the recovered copy is `scratch/<key>/derived/<id>`: the same code with every resolved decoder call replaced by its string.
- The candidates already come from the recovered copy and their anchors name the derivation. Read the recovered copy, and cite anything you add with `cite.py ... --derived <id>`. The recovered copy is usually one very long line; read it in windows with `tools/analysis/view.py scratch/<key> <file> --derived <id> --grep REGEX`, not all at once.
- `stats.unresolved` counts decoder calls it could not resolve (computed indexes); look at those by hand.

When it fails (no derivation for an obfuscated file), decode by hand:
1. Extract the array, the rotation target, the checksum expression, the offset and the decoder transform as text.
2. Re-implement the transform in a scratch Python script. Compute the checksum with your own small arithmetic parser over the extracted tokens; never evaluate package expressions with any `eval`, including Python's.
3. Rotate until your checksum equals the target. A match confirms the decode; no match means the decode is wrong, so stop and keep the file unread.
4. Substitute decoder calls with their strings in a scratch copy, then read the result. Keep the original untouched.
5. If only part decodes, record values as `partial` and keep an `unrecovered` entry for what remains.

The same applies to a bespoke cipher (a key derived with pbkdf2, a custom S-box, a CBC, CTR or Feistel layer): re-implement it in Python from the code, as data, and confirm it with whatever check the code itself makes (a checksum, a magic prefix, a decrypted string that parses).

**Register the decode so the verifier can replay it.** A scratch copy is yours alone; anchors cannot point into it and nobody can re-check it. Turn the decode into a derivation instead:
0. Look for a decoder that already reverses this transform: `.venv/bin/python tools/analysis/list_decoders.py [word ...]` prints the `Family`, `Reverses` and `Per sample` lines of every registered decoder (e.g. `list_decoders.py caesar`, `list_decoders.py fernet`). If one fits, skip step 1 and register it with this package's own params. Extend nothing and copy nothing: a second module for a transform that already has one is refused at review. Probe and diagnostic scripts go elsewhere in `scratch/<key>/`, never in `decoders/`.
1. Otherwise write the transform as a module `tools/common/decoders/<name>.py` exposing `decode(input_bytes, params, read) -> bytes`. It returns the input file with every encoded part replaced by its plaintext (like the string-table recovery), so the result is code that parses. Keep it pure: no imports of package code, no `eval`, no network, no file access. It holds the algorithm only: take keys, tables, salts and iteration counts from `params`, and read anything embedded in the package with `read(anchor)` (an anchor from `cite.py`) rather than pasting it into the module. `tools/common/decoders/example_xor.py` is the pattern. Add a round-trip test under `tools/tests/` and run `.venv/bin/python -m pytest tools/tests -q`. In a batch (driver) session `tools/` is read-only: write the module to `scratch/<key>/decoders/<name>.py` instead, pass `--candidate` to `register_decode.py` below, and leave the test to the person who reviews it. Only the standard library's pure modules (base64, zlib, hashlib, hmac, struct, re, ...) and `tools.common.tsparse` may be imported, and no `eval`, `exec`, `open`, `getattr` or dunder attributes: the candidate is refused otherwise.
2. Run `.venv/bin/python tools/analysis/register_decode.py scratch/<key> --decoder <name> --input <file> [--params JSON] [--lang js|py]` (`--params` carries the cipher's arguments and the anchors of any key material, e.g. `{"key_site": {...}}`). It writes `scratch/<key>/derived/<id>` and prints a `decode_spec` derivation; add it to `record.json` `normalisation.derivations` (`write_report.py` keeps it next to the tool's own).
3. Read and cite the decoded copy like a recovered string table: `cite.py ... --derived <id>`. Conditions read there set `value_recovered` to `decoded`. The verifier rebuilds the copy by running the same decoder over the package bytes and refuses it unless it hashes to `output_sha256`, then checks the claims against the plaintext.

Only when the decode cannot be replayed from the package alone (the key is fetched at run time, say) cite the original bytes instead (the obfuscated test expression with its decoder calls, in the package file) and set `value_recovered` to `decoded`; the verification pass holds such a claim open (`encoded_unchecked`) rather than checking it. Either way, say in `execution.notes` that the tool did not recover the file, why, and which decoder (if any) you registered.

## Extractor candidates on bundles

On bundles the extractor often reports conditions from library code: feature detection, platform branches in SDKs, parser internals comparing characters, colour-support checks reading CI variables. Drop each in `candidate_review.dropped` with `reason_code` `library_code` (and a short note naming the library when you know it) once you have confirmed it is library behaviour. Then add the real conditions from the package code as out-of-set sites (`"candidate": null`, anchor from `cite.py`).

## Recording coverage

One line per large or bundled file in `execution.notes`, for example:

- "`<file>`: decoded string table (rotation checksum matched); package code read in full (entry, helpers, embedded scripts); remaining units audited by sink inventory, all hits library behaviour; not diffed against upstream releases."
- "`<file>`: not decodable statically (reason); left unread, listed in obfuscation.unrecovered."

Add the matching techniques (string table, opaque predicates, dead-code injection, bundling) to `obfuscation.techniques`, and say in Notes if anything was audited rather than read.
