# TRIPWIRE

A code-anchored dataset of install-time environment gates in malicious npm and PyPI packages: for each campaign
representative, every condition a package tests before its payload runs, the value it compares, how the conditions
combine, and an environment that reaches each branch. Every claim cites a hashed byte range and carries the verdicts
of a deterministic checker and blinded LLM reviewers from two model families.

This repository holds the records, schema, verification sidecars, sample manifests and the tools that build and
check them. No malware is included. Using the data needs neither malware nor an LLM. `PROJECT_CONTEXT.md` defines
the terms, `docs/data-dictionary.md` describes every table, and `CITATION.cff` says how to cite it.

## Using the data

The tables are in `dataset/`, ready to load. To rebuild them from the records (Python 3.11 or newer; no samples
needed):

```
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python tools/common/aggregate.py        # writes dataset/*.jsonl and dataset/tables/*.csv
```

Every table is JSON Lines, one object per line, and names its package by `key` (`ecosystem__name@version`), so the
tables join on it. `pandas.read_json(path, lines=True)` loads any of them (pandas is not a requirement; the example below uses only
the standard library). Every column of every table is described in `docs/data-dictionary.md`.

| Table | One row per | Main fields |
|---|---|---|
| `packages.jsonl` | analysed campaign representative | `key`; `package` (name, version, archive SHA-256, `cluster_key`, `released_at`, `model_name`); `execution`; `conditions`; `gates`; `obfuscation`; `normalisation.derivations`; `sample_id`, `stratum`, `weight` |
| `gates.jsonl` | gate | `key`, `gate_id`, `hook`, `expression`, `polarity` (activate/evade), `effect`, `purpose`, `conditions` (each with `category`, `api`, `operator`, `value`, `in_scope` and the anchored `sites`), `then` / `else` branches (`min_conditions`, `behaviours`, `env_recipe`), `verification` (`ok` or `excluded` after a refutation) |
| `members.jsonl` | package that shares a representative's install payload | `key`, name, version, archive SHA-256, `cluster_key`, `sample_id`, `stratum`, `weight` |
| `skipped.jsonl` | sample with nothing to analyse at install time | `key`, name, version, archive SHA-256, `reason`, `sample_id`, `stratum`, `weight` |
| `claims.jsonl` | claim a record makes (layers L1 to L6) | `key`, `claim_id`, `target` (gate or condition), `layer`, `final` verdict, `final_source` (deterministic, agent, disputed, none), `provenance` |
| `verdicts.jsonl` | claim and verifier | `key`, `claim_id`, `target`, `method` (deterministic, agent), `by`, `verdict` |
| `blindspot.jsonl` | payload and environment profile | `profile`, `key`, `gate_id`, `branch`, `outcome` (open, closed, unknown, not_expressible), `closed_on` |

`dataset/tables/` holds the CSV tables behind every figure in the paper, among them `prevalence.csv` (design-weighted,
with campaign-level intervals, per-label totals, non-response bounds and a family-merged interval) and `blindspot.csv`. The record
contract is `schema/record.schema.json`; `PROJECT_CONTEXT.md` defines condition, gate, polarity, effect and
`min_conditions`. Malicious and benign rows are told apart by `source_label`.

A worked example: what kept malicious npm gates test, one gate in full, and the claims the checker settled.

```python
import json
from collections import Counter

def rows(name):
    with open(f"dataset/{name}.jsonl", encoding="utf-8") as f:
        return [json.loads(line) for line in f]

packages = {p["key"]: p for p in rows("packages")}
gates = [g for g in rows("gates") if g["source_label"] == "malicious" and g["verification"] == "ok"]
print(Counter(c["category"] for g in gates if g["key"].startswith("npm__") for c in g["conditions"]).most_common(3))
# [('env_var', 62), ('target_artifact', 57), ('os', 43)]

g = next(g for g in gates if g["key"] == "npm__@asyncapi__specs@6.8.2" and g["gate_id"] == "g1")  # Shai-Hulud
print(g["expression"], g["then"]["min_conditions"], g["then"]["env_recipe"])
# c7 && c8 && c9 && c10 4 {'os': 'linux', 'ci': 'true', 'env_var': {'GITHUB_ACTIONS': 'true', 'RUNNER_OS': 'Linux'}, 'privilege': 'root_or_admin'}
print(packages[g["key"]]["package"]["released_at"])
# 2025-11-24

settled = [c for c in rows("claims") if c["final_source"] == "deterministic" and c["final"] in ("verified", "refuted")]
```

A gate with `verification: excluded` has a refuted, disputed or unanchored L1 to L4 claim and is left out of every
result, though it stays in `gates.jsonl`. `rejected_only` marks the excluded gates whose every such claim had its
refutation rejected by the repair pass; `prevalence_with_rejected.csv` shows the shares if those gates counted.

Prevalence figures must be weighted: unweighted counts over-represent the oversampled compromised-library strata
(`paper/sampling.md`). `prevalence.csv` holds the released estimates, which weight each responding name by N_h / r_h
(frame names over respondents in its stratum); the `weight` column holds the design weight N_h / n_h. Records with `sample_id` `pilot` are not part of the draw.



## Data sources

TRIPWIRE ships no package code: records reference each sample by its archive SHA-256 and its path in the source
corpus, with short defanged excerpts. The samples come from two public corpora, each pinned at one commit (the
commits are also in `reports/_draws/strat.json` and `pilot.json`):

| Corpus | Commit | License | Cite |
|---|---|---|---|
| [DataDog/malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset) | `8a74a4c8ee0e1a2927f0419e0710968702ded609` | Apache-2.0 | Datadog Security Labs |
| [lxyeternal/pypi_malregistry](https://github.com/lxyeternal/pypi_malregistry) | `5f2592d2d750a1beb68e8ed1a5a63fcd1905899c` | none published | Guo et al., "An Empirical Study of Malicious Code In PyPI Ecosystem", ASE 2023 |

The benign control set lists the most-downloaded npm and PyPI packages that run code at install time, ranked from
the npm-high-impact download list and the top-pypi-packages 30-day list (Hugo van Kemenade). Its manifest,
`reports/_draws/benign.json` (built by `tools/common/draw_benign.py`), pins each package by version and archive hash.

## Reproduce

System requirements: Python 3.11 or newer and git. Level 2 also needs 7-Zip for AES-encrypted archives; Level 3
needs Linux with bubblewrap and a Claude Code or Codex CLI login.

Three levels, each needing more than the last. Levels 2 and 3 handle real malware: use a machine set aside for it.
Nothing here ever installs, imports or runs a package, but archives on disk still trip antivirus and carry risk if
opened by hand.

### Level 1: rebuild every table and number, no malware

```
python3 -m venv .venv            # Python 3.11 or newer (or: uv venv -p 3.11 .venv)
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python -m pytest tools/tests -q                  # synthetic packages only
.venv/bin/python tools/common/aggregate.py --check         # validates every record and sidecar
.venv/bin/python tools/common/aggregate.py                 # dataset/*.jsonl, dataset/tables/*.csv, summary.md
.venv/bin/python paper/make_numbers.py                     # every number the paper quotes
```

Running example, on an inert synthetic package (a postinstall script whose comments try to steer the analyst):

```
.venv/bin/python tools/analysis/prepare.py evals/gate-analysis/fixtures/misleading-text --no-registry
.venv/bin/python -m json.tool scratch/npm__eval-misleading-text@0.0.1/prepared.json | less
```

`prepare.py` unpacks it as data, finds the install path and writes the candidate conditions and gates, each with a
byte anchor, plus a record skeleton, to `scratch/<key>/`; nothing in the package is run.

`aggregate.py --check` exits 0 and prints a few `WARN` lines that describe the release rather than errors: members
whose campaign has no analysed representative (counted as non-response), verdicts made stale by later record fixes
(kept in the sidecars' history, never counted), two records whose recipe path no shipped-paths sidecar covers, and
the contested claims still waiting for a repair decision (their gates stay excluded).

### Level 2: re-check the records against the package bytes

Fetch the samples by hash from the pinned dataset commits, then run the deterministic checker. It rebuilds each
package, replays every derivation and decides L1 to L5. `--dry-run` writes nothing; without it, a record whose sample
is absent is skipped.

```
.venv/bin/python tools/common/draw_sample.py --sample-id strat --fetch    # blob-checked
.venv/bin/python tools/common/draw_sample.py --sample-id pilot --fetch
.venv/bin/python tools/common/draw_benign.py --sample-id benign --fetch   # SHA-256-checked
.venv/bin/python tools/verify/verify.py --dry-run reports/npm/@asyncapi__specs@6.8.2.md
```

Archives are found by `archive_sha256`. Datadog zips use the password `infected`, which `unpack.py` applies; an
AES-encrypted archive needs 7-Zip. Samples removed from a corpus since its pinned commit stay reachable at that commit.

### Level 3: run the blinded LLM review

Needs Linux with [bubblewrap](https://github.com/containers/bubblewrap), the samples, and the Claude Code or Codex CLI
logged in with your own account (`~/.claude/.credentials.json`, `~/.codex/auth.json`, or `ANTHROPIC_API_KEY`,
`OPENAI_API_KEY` or `CODEX_API_KEY`). Each packet is exported to a folder outside the repo, and the reviewer runs
sandboxed on that folder alone. Its session log is audited before its verdicts are recorded, and the audit fails
closed, so a newer CLI whose log format has changed is refused until `record_verdict.py` learns it.

```
.venv/bin/python tools/verify/packet.py --mode unreviewed --reviewer <your-model-id>
.venv/bin/python tools/verify/run_reviews.py --cli codex --model <your-model-id> --jobs 2
.venv/bin/python tools/common/aggregate.py --check
```

For a model that has reviewed nothing, `--mode unreviewed` queues every claim (about 170 packets), so try one packet
first with `run_reviews.py --only <packet_id>`; packet ids are in `scratch/verify/queue.jsonl`.

For a single packet by hand, `tools/verify/review_shell.py <packet_id> --cli codex --print --run --model <id>` runs the
session and `tools/verify/record_verdict.py --packet <packet_id> --session-log auto --cli codex` records it. New
verdicts are appended to `reports/_verification/<key>/` and join the existing ones on the next `aggregate.py`.
`skills/verify-gates/SKILL.md` is the full procedure, and `skills/verify-gates/references/agent-runners.md` covers
the sandbox and the log formats. The session logs behind the released verdicts are not published.

## Running the analysis pipeline

`docs/pipeline.md` covers analysing new samples end to end: preparing archives, the sandboxed analysis driver, the
deterministic and blinded verification passes, the repair pass, and the rules the tools enforce. The procedures
themselves are the skills in `skills/` (`gate-analysis`, `verify-gates`, `repair-gates`).

## Layout

```
PROJECT_CONTEXT.md               scope, definitions, ground rules
CITATION.cff, .zenodo.json       citation and archive metadata
CHANGELOG.md                     what changed in each release
CLAUDE.md, .claude/skills/       repository instructions and skill links for Claude Code (used by the drivers)
skills/gate-analysis/            the analysis procedure (SKILL.md) and per-ecosystem references
skills/verify-gates/             the verification procedure (deterministic and agent passes), model-agnostic
skills/repair-gates/             the repair pass: fix or reject each refuted or disputed claim, logged
evals/gate-analysis/fixtures/    an inert synthetic package for the running example and skill checks
schema/                          JSON Schemas: records (v3.2), verification sidecars, repair logs
reports/npm/, reports/pypi/      one Markdown report per analysed package (campaign representative), JSON record inside
reports/_skipped/                one JSON skip record per sample with nothing to analyse at install time
reports/_members/                one JSON per package sharing a representative's install payload (a campaign)
reports/_verification/<key>/     one sidecar per verifier per package (<method>__<by>.json) and repair logs
reports/_draws/                  sample manifests: the stratified draw, the pinned pilot and the benign set
reports/_shipped/                per record, whether its archive ships each install-directory path its recipes name
dataset/                         the JSON Lines and CSV tables, generated by tools/common/aggregate.py
docs/                            data dictionary and pipeline guide
tools/common/                    shared code (imported as tools.common.*)
  paths.py, contract.py          repo locations; record rules: schema validation, gate expression maths
  sanitize.py, anchors.py        defanging and redaction; byte-range anchors with a content hash
  tsparse.py, tables.py          tree-sitter parsers; API, sink and value vocabularies
  recipe.py, unpack.py, hooks.py environment recipes; safe archive unpacking; install hooks as data
  decode.py, deobf.py            pure string decoders; obfuscator.io string-array recovery as a derivation
  decode_spec.py, decoders/      replays a registered hand-cracked decoder (one pure module per cipher)
  bundles.py                     module units in webpack/esbuild/browserify bundles
  aggregate.py                   validates every record and sidecar, builds dataset/
  claims.py, verification.py     the claims a record makes; reading, joining and summarising verdicts
  agreement.py, prevalence.py    Cohen's kappa; design-weighted prevalence with campaign bootstrap
  profiles.py, profiles/         scores payload recipes against five documented environments, each axis sourced
  draw_sample.py, draw_benign.py the stratified draw and pilot; the benign set (--fetch downloads and hash-checks)
  fetch_samples.py, shipped.py   corpus download; writes reports/_shipped/ from samples/
  reset.py                       clears scratch/ and dataset/ before a session
tools/analysis/                  the gate-analysis tools: prepare.py, gate_extract.py, write_report.py, cite.py,
                                 view.py, register_decode.py, list_decoders.py, release_date.py, work_queue.py,
                                 run_analyses.py (batch driver), repair.py and run_repairs.py (repair pass)
tools/verify/                    verify.py (deterministic pass), source.py, checks.py, witness.py, cfg.py,
                                 resolve.py, apimatch.py, packet.py and show.py (blinded packets), review_shell.py
                                 and run_reviews.py (sandboxed review sessions), record_verdict.py and
                                 codex_exec_audit.py (session-log audit)
tools/tests/                     pytest suite on synthetic packages (config in pytest.ini)
paper/make_numbers.py            every number the paper quotes, from dataset/ and reports/
paper/figures/make_figures.py    the paper's figures, written to paper/assets/
paper/sampling.md                the sampling rule behind reports/_draws/
scratch/, samples/               local working state and malware archives, never committed
```

## License

Data (`reports/`, the generated `dataset/`) and the JSON Schemas in `schema/` are licensed CC BY 4.0
(`reports/LICENSE`). Code is Apache-2.0 (`LICENSE`). Copyright 2026 the TRIPWIRE authors (`NOTICE`).

## Citation

Cite the dataset release with `CITATION.cff` (GitHub shows it under "Cite this repository"). Each tagged release
is archived on Zenodo with a DOI.
