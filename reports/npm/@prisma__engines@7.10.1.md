# npm @prisma/engines@7.10.1

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-15 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node scripts/postinstall.js`, which requires `dist/scripts/postinstall.js`. That script writes a `download-lock` file, calls `download()` from the `@prisma/fetch-engine` dependency to fetch the schema engine binary into the package folder, then deletes the lock; errors are swallowed. There is no environment gate. `PRISMA_CLI_BINARY_TARGETS`, when set, only fills the `binaryTargets` list passed to `download()`; the download call follows that `if` block and runs either way, so the check is configuration and its candidates are dropped. A dev-only branch (package version `0.0.0`) that would run `dist/scripts/localinstall.js` is dead for this release.

## Execution

- **postinstall** `node scripts/postinstall.js`: 2-file chain; direct_script; errors hidden.

## Gates

None.

## Requirements

- other: dependencies @prisma/debug, @prisma/engines-version and @prisma/fetch-engine resolvable (dist/scripts/postinstall.js requires them at top level; the engine download is done by @prisma/fetch-engine)
- other: network access to the engine download host configured in @prisma/fetch-engine (not named in this package) (the schema engine binary is fetched at install; failures are swallowed (failSilent))

## Behaviour

- Ungated: download, write_file, delete_file
- Gated: none

## Notes

- The lock-file check (skip when a lock under 20 s old exists) is a concurrency guard the script sets and clears itself, recorded as a note rather than a gate.
- The download host lives in `@prisma/fetch-engine`, not in this package, so no endpoint is recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@prisma/engines",
    "version": "7.10.1",
    "archive_sha256": "d19ab01ea2f5fda4df81bd5bf0622f8966be5a6fa6724dd688d6e6485f292edf",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-15",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/engines-7.10.1.tgz",
    "package_root": "layer0/package",
    "cluster_key": "64b535b3b9f2b360c6049b4a7af801eea7c8d864b5bb260c898ebf40ad0e629f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node scripts/postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/postinstall.js",
          "dist/scripts/postinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "scripts/postinstall.js and dist/scripts/postinstall.js read in full; no bundled third-party code in the install path; nothing unread.",
      "dist/scripts/localinstall.js (not_chained) does not run at install: it is launched only when require('../package.json').version === '0.0.0', a monorepo dev check that is false for 7.10.1 (execa is also only a devDependency).",
      "That version check is not a gate: it tests the package's own manifest, not the environment, and is constant for the published package.",
      "dist/scripts/postinstall.js skips the download when a download-lock file in the package root holds a timestamp under 20 s old. The script writes and removes this lock itself to stop concurrent runs; treated as a re-entry guard, not a gate.",
      "The engine download itself happens in the @prisma/fetch-engine dependency (download() with failSilent: true); its code and download host are out of scope.",
      "PRISMA_CLI_BINARY_TARGETS (line 41) only sets the binaryTargets list passed to download(); the download call at line 47 sits after the if block and runs either way with the same behaviour, so the check is configuration, not a gate (its candidates are dropped)."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "dependencies @prisma/debug, @prisma/engines-version and @prisma/fetch-engine resolvable",
      "reason": "dist/scripts/postinstall.js requires them at top level; the engine download is done by @prisma/fetch-engine"
    },
    {
      "axis": "other",
      "value": "network access to the engine download host configured in @prisma/fetch-engine (not named in this package)",
      "reason": "the schema engine binary is fetched at install; failures are swallowed (failSilent)"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
      "write_file",
      "delete_file"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall hook only runs Prisma's own script, which writes a short-lived lock file and calls @prisma/fetch-engine to download the schema engine binary for the platform into the package folder, then removes the lock. The dev-only branch that would run localinstall.js is dead for this published version.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@5e69ae7222",
      "sha256": "09088a3756de9b45"
    },
    "units_summary": [
      {
        "file": "dist/scripts/localinstall.js",
        "derived_from": null,
        "bundler": "esbuild",
        "count": 34,
        "entry": "../../node_modules/.pnpm/execa@5.1.1/node_modules/execa/index.js",
        "by_role": {
          "library": 34
        }
      }
    ],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_2b0b49b763",
        "reason_code": "other",
        "note": "PRISMA_CLI_BINARY_TARGETS only fills the binaryTargets option of download(); the download at line 47 runs whether or not it is set, so no behaviour depends on it (configuration, not a gate)",
        "anchor": {
          "file": "dist/scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 2000,
          "end_byte": 2037,
          "node_type": "member_expression",
          "sha256": "2a2078766cecc8b3",
          "line": 41
        }
      },
      {
        "candidate": "q_13dfe7c570",
        "reason_code": "other",
        "note": "the if at line 41 guards only the assignment binaryTargets = ...split(','); the download call follows the block and is unconditional",
        "anchor": {
          "file": "dist/scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 1996,
          "end_byte": 2118,
          "node_type": "if_statement",
          "sha256": "7a6a650597ea3ebc",
          "line": 41
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
