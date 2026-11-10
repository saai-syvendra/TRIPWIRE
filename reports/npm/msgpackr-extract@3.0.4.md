# npm msgpackr-extract@3.0.4

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-05-25 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

At install npm runs the `install` hook `node-gyp-build-optional-packages`, the bin of a pinned dependency that loads a prebuilt binary from the platform-specific optional packages or falls back to compiling `binding.gyp`. The package itself ships no install-time script. There are no gates: the OS and gcc-version conditions in `binding.gyp` only choose compiler flags and defines. No network endpoints or package-written payloads are involved.

## Execution

- **install** `node-gyp-build-optional-packages`: no package files; inline_shell, native_build.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The delegated helper's code is out of scope; only the command is recorded.
- `binding.gyp` command expansions are `echo` of `ENABLE_V8_FUNCTIONS` and `gcc -dumpversion`, used on the fallback build only.
- `bin/download-prebuilds.js` (runs `prebuildify-ci download`) is only run when invoked by a user, not at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "msgpackr-extract",
    "version": "3.0.4",
    "archive_sha256": "9ff0ecee067891669e77a79ba8fef390a8374a6690c09816bb3ca66dd976b028",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-05-25",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/msgpackr-extract-3.0.4.tgz",
    "package_root": "layer0/package",
    "cluster_key": "688fc0339b19adba951ab91f9169781186e231bf6519bd9ff6f6e1f27661edd1",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "install",
        "command": "node-gyp-build-optional-packages",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell",
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "install: runs 'node-gyp-build-optional-packages' from a dependency or the system; its code is out of scope",
      "bin commands not analysed (run only when invoked): download-msgpackr-prebuilds",
      "optionalDependencies (platform picks belong to the dependency tree): @msgpackr-extract/msgpackr-extract-darwin-arm64, @msgpackr-extract/msgpackr-extract-darwin-x64, @msgpackr-extract/msgpackr-extract-linux-arm, @msgpackr-extract/msgpackr-extract-linux-arm64, @msgpackr-extract/msgpackr-extract-linux-",
      "The install hook is the delegated native build helper node-gyp-build-optional-packages (pinned dependency); it loads a prebuilt platform package or falls back to building binding.gyp. Its code is out of scope.",
      "binding.gyp read in full: OS and gcc-version conditions only pick compiler flags and defines; command expansions are echo of ENABLE_V8_FUNCTIONS and gcc -dumpversion. Build config, not gates.",
      "index.js (main) and bin/download-prebuilds.js are not run at install; src/extract.cpp is the addon source compiled only on the fallback build."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "benign_build"
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
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The only install hook delegates to the pinned native build helper node-gyp-build-optional-packages, which loads a prebuilt binary or compiles the addon from binding.gyp. The package ships no install-time script of its own and binding.gyp only sets compiler flags.",
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
