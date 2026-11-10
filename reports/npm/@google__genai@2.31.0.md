# npm @google/genai@2.31.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-23 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

At install, npm runs one `preinstall` hook, `echo 'preinstall: no-op'`, which only prints a line. The `prepare` hook (`node scripts/prepare.js`) runs only for git or local installs, and that script is not in the tarball. There are no gates: no conditions in the hook strings, no manifest platform restrictions and no package code on the install path. Nothing runs that depends on the environment.

## Execution

- **preinstall** `echo 'preinstall: no-op'`: no package files; inline_shell.
- **prepare** `node scripts/prepare.js`: runs on git or local install only; no package files; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- The tarball contains only `package.json`, `README.md` and `LICENSE`. The `dist/` files that `main`, `exports` and `files` name are missing. This only matters at load time, but a reviewer may want to confirm the sample archive is complete.
- Dependencies (`google-auth-library`, `p-retry`, `protobufjs`, `ws`) are plain registry semver ranges.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@google/genai",
    "version": "2.31.0",
    "archive_sha256": "dfc7a74e63005b9d5024d4508af69905ef39038d11247fab2c12e3399baed6c5",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-23",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/genai-2.31.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "c1db6cb1db16b921b35fc5b444ec84e870d353f19ac3a2beff37c0a682a36d28",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "echo 'preinstall: no-op'",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      },
      {
        "hook": "prepare",
        "command": "node scripts/prepare.js",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "prepare: 'scripts/prepare.js' is not a file in the package",
      "preinstall: the hook is a bare shell echo with no condition and no file; it only prints text, so no behaviour is recorded.",
      "prepare: runs only for git or local installs, and its script is absent from the tarball, so nothing from this package runs there.",
      "package.json: read in full. No os/cpu/libc fields, so no manifest gate. engines node>=20 is advisory. Dependencies are plain registry semver ranges.",
      "The archive holds only package.json, README.md and LICENSE; the dist/ files named in main/exports/files are absent. That affects load time only, not install."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The only install-time code is a preinstall hook that echoes a fixed string. The prepare hook points to a script missing from the tarball and only runs for git or local installs. There are no conditions, network calls or file operations at install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "428960f5b8cf6c20"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": []
  },
  "candidate_check": {
    "condition_candidates": 0,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
