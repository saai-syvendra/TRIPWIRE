# Running the TRIPWIRE pipeline

This guide is for analysing new samples or re-running verification. Using the released data needs none of it; see
the README. Levels 2 and 3 of the README's Reproduce section handle real malware: use a machine set aside for it.

## Setup

```
uv venv -p 3.11 .venv            # or: python3 -m venv .venv
uv pip install --python .venv/bin/python -r tools/requirements.txt
.venv/bin/python -m pytest tools/tests -q
```

Claude Code discovers the three repository skills (`gate-analysis`, `verify-gates`, `repair-gates`) through the
relative symlinks in `.claude/skills/`, which point at the shared `skills/` folders and work from any clone location.
Edit the source in `skills/`. The analysis and repair drivers launch Claude Code; the review driver also supports
the Codex CLI (`run_reviews.py --cli codex`). Each review packet carries its own instructions, so the reviewer needs
nothing from this repository.

Put samples under `samples/<dataset>/...` (git-ignored), e.g. `samples/datadog/npm/malicious_intent/...`; the
dataset and label are read from that path. Never commit archives or extracted package code, anywhere in the repo.

## Workflow

1. `.venv/bin/python tools/common/reset.py` clears the last session's `scratch/` and `dataset/` (it refuses while an analysis or queue is unfinished). Then `.venv/bin/python tools/analysis/prepare.py samples/datadog/npm --batch --model <model id>` prepares every archive, writes the skip and member records that need no judgement (`analysis_type: tool`), and merges the rest into `scratch/queue.jsonl`. It never deletes a `scratch/<key>/` with analyst edits (`in_progress`), turns a sample it cannot prepare into an `error` row and carries on, and folds a second archive of the same package into the first one's row (`duplicate_key` when the bytes differ: decide by hand which to keep). It asks the registry for release dates (retrying rate limits and timeouts) unless `--no-registry` is given.
2. Analyse the queue, either:
   - with the driver: `.venv/bin/python tools/analysis/run_analyses.py --model claude-opus-5-5 [--jobs 2] [--timeout 3600]`. Each queued package gets one fresh headless `claude -p` session started from the repo root, pinned to that model, in `dontAsk` permission mode with a tool allowlist (edits only under `scratch/<key>/`, Bash only `.venv/bin/python tools/analysis/*` and `tools/common/decode.py`, other packages' scratch folders, `samples/`, `evals/`, `dataset/` and `scratch/verify/` read-denied, no web tools, no subagents). Logs go to `scratch/_runs/<key>.jsonl`. The row's status becomes `done`, `blocked` (safeguard refusal, model fallback or two models in one log), `model_mismatch`, `timeout` or `error`; records from blocked or mismatched sessions are moved to `scratch/_runs/`. Rerun it to resume, `--retry` to rerun `error`/`timeout` rows, `--dry-run` to print the commands. Each session runs inside bubblewrap: the repo is read-only, `samples/`, `evals/`, `dataset/`, `.git`, other packages' scratch folders and the verification sidecars are hidden, and only `scratch/<key>/` and `reports/` are writable. Run it from a normal shell (default permission mode, not auto mode). A session that needs a new decoder writes it to `scratch/<key>/decoders/` and the driver adds it to `tools/common/decoders/` afterwards (listed at the end, for review before commit).
   - or interactively: open the repo in Claude and ask it to work through the queue (or to analyse one sample).

   Either way the `gate-analysis` skill reads `scratch/<key>/prepared.json`, fills the judgement fields in `record.json` and `summary.md` (or `skip.json`), and runs `tools/analysis/write_report.py`, which writes `reports/<ecosystem>/<name>@<version>.md` or `reports/_skipped/<...>.json`. Under the driver, `write_report.py` refuses a `model_name` other than the session's model (`TRIPWIRE_ANALYSIS_MODEL`, or `--model-used`).
3. Run `.venv/bin/python tools/common/aggregate.py --check`. It must pass before you commit.
4. Commit your own report files. File names are per package, so two people working on different packages never conflict. Pull before starting a batch so you don't duplicate someone's package (`prepare.py` also checks).
5. Anyone can run `.venv/bin/python tools/common/aggregate.py` to rebuild `dataset/` and `dataset/summary.md` from everyone's reports.

## Batch run, end to end

The order for a batch, from new samples to a dataset ready to freeze. Run each step from a normal shell in default
permission mode; the drivers run their sessions sandboxed and record as they go, so any step can be rerun to resume.

1. `.venv/bin/python tools/common/reset.py` (add `--force` only to discard unfinished work on purpose).
2. `.venv/bin/python tools/analysis/prepare.py samples --batch --model claude-opus-5-5`
3. `.venv/bin/python tools/analysis/run_analyses.py --model claude-opus-5-5 --jobs 3`, then for what is left:
   - `--retry` for `error`/`timeout` rows (a network drop, a session that stopped);
   - `--include-blocked --model claude-opus-4-8`, then `--model claude-sonnet-5-5`, for rows a safeguard
     blocked; the record keeps the model that wrote it;
   - review the decoders the driver adopted (listed at the end), add a round-trip test, commit.
4. `.venv/bin/python tools/verify/verify.py --all`; read every `refuted` verdict before trusting it (a new
   refutation pattern is as likely a checker bug as a record error).
5. `.venv/bin/python tools/verify/packet.py --mode all` (first pass: every claim gets a reviewer), then
   `.venv/bin/python tools/verify/run_reviews.py --cli claude --model claude-sonnet-5-5 --jobs 4`; rerun failed
   packets with `--only ... --model claude-opus-4-8`. Packets every Claude model refuses go to the Codex pass.
6. `.venv/bin/python tools/analysis/run_repairs.py --model claude-opus-5-5 --jobs 3`, then
   `packet.py --mode residual` and `run_reviews.py` for the claims the repairs changed; repeat until
   `run_repairs.py --dry-run` lists only kept review flags.
7. `.venv/bin/python tools/common/shipped.py` for recipes that name a path in the install directory (new or
   repaired; aggregate.py warns about any it does not cover), then
   `.venv/bin/python tools/common/aggregate.py --check --append-only`, commit, and at the freeze
   `--require-oos-verified`.

## Rules that the tools enforce

- Gates are deliberate checks only. Prerequisites go in `requirements`, and swallowed errors are `silent_failure`.
- Repeated checks are merged per hook, and conditions are written in positive form.
- Gate expressions use only `c<N>`, `&&`, `||` and parentheses; `min_conditions` must match the expression. A condition copied verbatim from the impersonated legitimate package carries `inherited: true` and stays in the expression.
- Recipe keys come from a fixed axis list; behaviour, category and operator values come from fixed lists.
- No maintainer identities, defanged indicators, short evidence only.
- Every cited code location is an anchor (file, byte range, node type, hash). `write_report.py` copies anchors for candidates the generator proposed, checks every anchor against the package bytes and refuses records whose anchors do not match; analysts get anchors from `tools/analysis/cite.py`.
- Claims outside the generator's candidate set are marked `out_of_set` and wait for the verification pass.
