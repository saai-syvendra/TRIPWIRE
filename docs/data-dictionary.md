# Data dictionary

Every file in `dataset/` is rebuilt from `reports/` by `tools/common/aggregate.py`. The JSON Lines tables hold one
JSON object per line and name their package by `key` (`<ecosystem>__<name>@<version>`, with `/` in scoped npm names
written as `__`), so any two tables join on it. `pandas.read_json(path, lines=True)` loads any of them.

Data under `reports/` and `dataset/`, and the JSON Schemas under `schema/`, are licensed CC BY 4.0. Code is
Apache-2.0.

Terms used below (see `PROJECT_CONTEXT.md` for the full definitions):

- **name**: one package name, the unit of the stratified draw (`paper/sampling.md`).
- **record**: what a drawn or pilot sample produced: an *analysed* record (a campaign representative), a
  *member* record or a *skip* record.
- **campaign**: packages whose install-time payload hashes to the same `cluster_key`. One package of each campaign
  is analysed in full (the representative); the others become members.
- **payload**: a gate branch with at least one behaviour.

## Common fields

| Field | Type | Meaning |
|---|---|---|
| `key` | string | Package key, the join column. |
| `source_label` | `malicious` / `benign` | Malicious corpora or the benign control set. Filter on it before any malicious-only figure. In `packages.jsonl` it sits under `package` (`row["package"]["source_label"]`). |
| `sample_id` | `strat` / `pilot` / `benign` | Which sample a record comes from: the stratified draw, the alphabetical pilot (never in prevalence) or the benign control set. |
| `stratum` | string | Draw stratum, e.g. `compromised_lib/2025`, `malregistry-sdist`; `pilot` or `benign-top-npm`/`benign-top-pypi` otherwise. |
| `weight` | number or null | Design weight N_h / n_h (frame names over drawn names in the stratum) for draw records; null for pilot and benign. The released estimates in `prevalence.csv` reweight over respondents, N_h / r_h, so that non-response does not shrink a stratum; quote those, or reweight the same way. |
| `cluster_key` | hex string | Campaign key: hash of the install-time code a package reaches. |
| `archive_sha256` | hex string | SHA-256 of the archive as stored in the source corpus; `tools/common/draw_sample.py --fetch` refetches by it. |

## `packages.jsonl`: one row per analysed record (campaign representative)

The full analysed record as validated by `schema/record.schema.json` (schema v3.2), plus `key`, `sample_id`,
`stratum` and `weight`. Main top-level fields:

| Field | Meaning |
|---|---|
| `package` | Ecosystem, name, version, `archive_sha256`, `cluster_key`, `source_dataset`, `source_label`, `sample_path`, `released_at` (+ `released_at_source`: `registry` or `dataset`), `analysis_type` and `model_name` (the analyst model). |
| `execution` | Install hooks (`entry_points`: hook, command, file chain, launch style, whether errors are hidden). |
| `conditions` | Every condition: `id`, `category`, `api`, `operator`, `value`, `value_recovered`, `in_scope`, `provenance` (`in_set` from the extractor, `out_of_set` added by the analyst) and anchored `sites`. |
| `gates` | Every gate (same content as `gates.jsonl`, without the join columns). |
| `requirements` | Things a payload needs that are not gates (network endpoint, runtime, tool), with a reason. |
| `behaviours` | `ungated` and `gated` behaviour lists. |
| `obfuscation` | `level` (`none`, `light`, `moderate`, `heavy`) and techniques. |
| `normalisation.derivations` | Decoded files: input file and hash, recipe (`obfuscatorio_strings` or `decode_spec`), parameters, output hash. Anchors with `derived_from` point into these. |
| `reachability` | Whether the payload needs a remote endpoint, with defanged indicators. |
| `attack_type`, `family_hint` | Analyst's attack type and campaign family name, if known. |
| `claude_assessment`, `confidence`, `assessment_reason`, `label_disagreement` | The analyst's own verdict on the package and whether it disagrees with the corpus label. |
| `needs_manual_review`, `review_reasons` | Flags raised by the writer (for example out-of-set gates). |
| `candidate_review`, `candidate_check` | Extractor candidates the analyst dropped, with reason codes, and counts of candidates used. |

## `gates.jsonl`: one row per gate

| Field | Type | Meaning |
|---|---|---|
| `key`, `package` | string | Package key; `package` is `<ecosystem>:<name>@<version>`. |
| `gate_id` | string | `g1`, `g2`, ... within the record. |
| `hook` | enum | Install hook the gate sits in: `preinstall`, `install`, `postinstall`, `prepare`, `node_gyp_implicit`, `setup_py`, `cmdclass`, `build_backend`. |
| `expression` | string | Boolean combination of condition ids with `&&` and `\|\|`, e.g. `c3 && c6 && (c8 \|\| c14)`. |
| `conditions` | list | The conditions the expression uses, each with `id`, `category`, `api`, `operator`, `value`, `in_scope` and anchored `sites`. |
| `guards` | list | The guard nodes in code (`if`, ternary, early exit, ...), each anchored, with the conditions it tests. |
| `then`, `else` | object / null | Branches. Each has `min_conditions` (smallest number of conditions that must hold together), `behaviours`, `env_recipe` (an environment that reaches the branch, over fixed axes: `os`, `arch`, `env_var`, `env_var_absent`, `file_present`, `file_absent`, `package_manager`, `runtime_version`, `installed_tool`, `privilege`, `locale`, `cpu_count`, `username`, `ci`, `network`), `regions` and `payload` anchors, and `recipe_guessed_fields`. Network hosts are defanged (`api[.]github[.]com:443`). |
| `then_min_excluding_inherited` | int | `min_conditions` of `then` without conditions inherited from an enclosing gate. |
| `polarity` | `activate` / `evade` | Runs on a target, or backs off on suspected analysis. |
| `effect` | `enables` / `selects` / `modifies` | Turns a payload on, picks a different payload per branch, or changes its target. |
| `purpose`, `purpose_reason` | enum, text | `targeting`, `anti_analysis`, `portability`, `data_availability`, `unclear`, with the analyst's reason. |
| `provenance` | `in_set` / `out_of_set` | Proposed by the extractor, or added by the analyst. |
| `verification` | `ok` / `excluded` | `excluded` when any L1 to L4 claim of the gate is refuted, disputed or unanchored. Excluded gates are left out of every result. |
| `rejected_only` | bool | Excluded, but every such claim had its refutation rejected by the repair pass (see `prevalence_with_rejected.csv`). |

## `members.jsonl`: one row per member record

A package whose install payload has the same `cluster_key` as an analysed representative. Fields: `ecosystem`,
`name`, `version`, `archive_sha256`, `source_dataset` (`datadog`, `pypi_malregistry`, `benign_sample`),
`source_label`, `released_at`, `released_at_source`, `sample_path` (path in the source corpus), `package_root`
(path of the package inside the archive), `cluster_key`, `analysis_type` (`tool`), `sample_id`, `stratum`,
`weight`, `key`. A member takes its representative's labels. Three draw members belong to campaigns with no analysed
representative; prevalence counts them as non-response.

## `skipped.jsonl`: one row per skip record

Samples with nothing to analyse at install time. Same identity fields as `members.jsonl`, plus `reason`
(`import_time_only`, `no_install_code`, `payload_in_dependency`), `note` (one line on why), `analysis_type`
(`tool` when `prepare.py` decided without judgement, `ai` when the analyst did) and `model_name`.

## `claims.jsonl`: one row per claim

Each analysed record splits into claims at six layers: L1 the test exists at the cited site; L2 its value and
operator; L3 the payload is reached from code the gate controls (`.L3`) and only through it (`.L3.excl`); L4 the
expression and `min_conditions`; L5 branch behaviours rest on sinks of a matching kind; L6 interpretation
(category, polarity, effect, purpose, dropped candidates).

| Field | Meaning |
|---|---|
| `key`, `package` | Package key (the join column; `package` holds the same value). |
| `claim_id`, `target`, `layer` | Claim id and the gate, condition or dropped candidate it is about (`target`). Ids read `<target>.<layer>` for conditions (`c3.L1`, `c3.L2`, `c3.L6.category`), `<gate>.<branch>.L3` and `.L3.excl`, `<gate>.<branch>.L5`, `<gate>.L4` and `<gate>.L6.<polarity|effect|purpose>` for gates, and `<candidate>.L6.drop` for a dropped extractor candidate. |
| `ecosystem`, `source_label`, `obfuscation`, `provenance` | Copied from the record for filtering. |
| `final` | `verified`, `refuted`, `disputed` (verifiers contradict each other), `unanchored` (the cited bytes do not show the claim) or `cannot_tell`. |
| `final_source` | `deterministic` (the checker decided), `agent` (only LLM reviewers decided) or `disputed`. |
| `deterministic` | The checker's own verdict, or null where it could not decide. |
| `grade` | Graded result for L3 exclusivity, L4 and L5 (`consistent`, `inconsistent`, `exclusive`, ...). |
| `confirmed` | A refutation both the checker and an LLM reviewer gave; the repair pass may not reject it. |
| `repair` | Repair decision on a contested claim: `rejected` (refutation rejected with a written reason), `escalated`, or null. Fixed claims are re-reviewed and carry their new verdicts. |

## `verdicts.jsonl`: one row per claim and verifier

| Field | Meaning |
|---|---|
| `key`, `package`, `claim_id`, `target`, `layer` | As in `claims.jsonl`. |
| `method` | `deterministic` or `agent`. |
| `by` | Verifier id: the checker stamped with its Python and parser versions, or the reviewer model (`claude-sonnet-5-5`, `claude-opus-4-8`, `gpt-6.1-sol`, `gpt-6-luna`). |
| `verdict` | `verified`, `refuted`, `unanchored` or `cannot_tell`. |
| `grade`, `reason_code` | Graded result and, for a refutation, the reason (`value_mismatch`, `expression_mismatch`, `no_sink`, ...). |

Only the latest non-stale verdict of each verifier is released here; the full history is in
`reports/_verification/<key>/`.

## `blindspot.jsonl`: one row per payload and environment profile

| Field | Meaning |
|---|---|
| `profile` | `ossf-package-analysis`, `docker-default`, `github-ubuntu`, `github-windows`, `github-macos` (`tools/common/profiles/`). |
| `key`, `gate_id`, `branch`, `ecosystem`, `cluster_key` | The payload. |
| `outcome` | `open` (every recipe axis holds), `closed` (an axis contradicts the profile and there is no other way in), `unknown`, `not_expressible` (the recipe needs an out-of-scope condition such as a server response). |
| `reason` | For `unknown`: `undocumented` (the profile does not document an axis), `alternative_terms` (another way in has no recipe), `relative_path`, `uncomparable_value`, `empty_recipe`, `recipe_gap` (the recipe would open but leaves out a condition the branch needs, such as a process check). |
| `closed_on` | Recipe axes that contradict the profile on a closed payload, or `os_requirement` when the record says the payload itself needs another OS (whatever its gate says). |
| `guessed` | The outcome rests on a recipe field the analyst marked as guessed. |

Outcomes are scored from recipes against documented settings; nothing is executed. Recipes are the analyst's
statement of an environment that reaches the branch and are not verified claim by claim. Kept malicious gates only,
pilot included, unweighted.

## CSV tables (`dataset/tables/`)

### `prevalence.csv`, `prevalence_with_rejected.csv` and `prevalence_all_gates.csv`

Design-weighted gate prevalence per draw, ecosystem and stratum (`stratum` `all` is the ecosystem total).
`prevalence_with_rejected.csv` is the same table counting the `rejected_only` gates as kept, and
`prevalence_all_gates.csv` counts every gate, excluded or not, as the loosest bound.

| Column | Meaning |
|---|---|
| `sample_id`, `ecosystem`, `stratum` | Draw, ecosystem, stratum (or a per-label total such as `compromised_lib`). |
| `names`, `drawn`, `responding`, `nonresponse` | Names in the frame (N_h), drawn (n_h), with a record, without one. |
| `nonresponse_reasons` | `no_record=k` (every analyst model refused) and `member_unrepresented=k`. |
| `denominator` | `all_drawn` (every responding name), `install_code` (analysed and members) or `campaigns` (each install-code campaign once, unweighted). |
| `measure` | `gated` (a kept gate), `gated_in_scope` (with an in-scope condition), `gated_env` (with an in-scope condition that is not a target artifact), `gated_not_absence` (with a condition other than a file-absence check). |
| `units`, `positives`, `share` | Denominator size, positives, share (0 to 1), weighted N_h / r_h over respondents (campaign rows are unweighted and describe the sample, not a population). |
| `ci_low`, `ci_high` | 95% percentile bootstrap, resampling whole campaigns within strata. |
| `half_campaigns`, `top_campaign_share` | Campaign rows: fewest campaigns holding half the weighted gated names, and the largest campaign's share. |
| `bound_low`, `bound_high` | Ecosystem totals: share with every non-responding name counted as ungated / gated install-code. |
| `ci_low_merged`, `ci_high_merged` | Ecosystem totals: bootstrap with the campaigns that hold half the weighted gated names folded into one cluster. |

### `blindspot.csv`

Outcome counts per profile. `unit` is `payload`, `package` (opens when any payload opens) or `campaign` (each once);
`weighting` is `none` (pilot included) or `draw:strat` (draw only). Columns `n_<outcome>` and `share_<outcome>` for
`open`, `closed`, `unknown`, `not_expressible`; `n_*_guessed` count outcomes resting on guessed recipe fields;
`n_unknown_<reason>` split the unknowns; `no_payload` counts units without one.

### `blindspot_merge.csv`

Greedy merge of buildable payload recipes into k environments (`kind` `merged`, `name` `envk`) against each
profile's open count on the same payloads (`kind` `profile`). `opened` of `buildable` (recipes an environment can
be built from) of `expressible` payloads; `share` = opened / buildable; `campaigns_opened` of `campaigns`
(gated campaigns with a payload) and `campaign_share`.

### `agreement_by_row.csv`

The rows of the paper's Table IV, on malicious claims only: `row` (`L1`, `L2`, `L3`, `L3 excl.`, `L4`, `L5`,
`L6 interp.`, `L6 drop`), final-verdict counts (`claims`, `verified`, `refuted`, `disputed`, `open`, where open is
unanchored, cannot tell or unreviewed), then agreement of the two reviewers in `comparison` on the claims both judged:
`n`, `agree`, `kappa` and its package-bootstrap interval (`ci_low`, `ci_high`).

### `kappa.csv`

Pairwise agreement per layer. `comparison` names two verifiers; `n` claims both judged; `agree` raw agreement;
`kappa` Cohen's kappa with a package-level bootstrap interval (`ci_low`, `ci_high`). Rows pool malicious and benign
claims, and the L3 row pools L3 and L3 exclusivity claims.

### `verif_by_layer.csv`

Final verdict counts per layer for `subset` `all`, `in_set`, `out_of_set`, `label:malicious` and `label:benign`:
`claims`, `verified`, `refuted`, `disputed`, `unanchored`, `cannot_tell`, `unverified` (no verdict yet).

## Generated summaries

`dataset/summary.md` and `dataset/verification.md` are plain-text counts written by `aggregate.py` with every
denominator. They count all gates (kept and excluded) unless a line says otherwise; the paper and the CSV tables
use kept gates only.
