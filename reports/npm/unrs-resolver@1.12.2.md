# npm unrs-resolver@1.12.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-05-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node postinstall.js`, a five-line script that requires the `napi-postinstall` dependency and calls `checkAndPreparePackage(packageJson, true)` with the package's own manifest. That delegated call makes sure the platform-specific native binding (shipped as `@unrs/resolver-binding-*` optional dependencies) is in place. The package's own install code has no gates; platform selection happens through optionalDependencies, which belong to the dependency tree. Nothing is downloaded, written or executed by package code directly.

## Execution

- **postinstall** `node postinstall.js`: runs postinstall.js; direct_script.

## Gates

None.

## Requirements

- other: dependency napi-postinstall installed (postinstall.js requires napi-postinstall; the hook throws if it is missing)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The dependency's code (`napi-postinstall`) is out of scope; any fallback fetch of a missing binding would happen there.
- No manifest `os`/`cpu`/`libc` restrictions, so no resolve gate.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "unrs-resolver",
    "version": "1.12.2",
    "archive_sha256": "22203fe39b7626e2679fa74d6c2e9985e52b5cbf79ed27f8dc0439b3255c9778",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-05-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/unrs-resolver-1.12.2.tgz",
    "package_root": "layer0/package",
    "cluster_key": "22601772f4d4caf1901372ef643612df76f9ac17a307107e93d829eeed741c04",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "postinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "optionalDependencies (platform picks belong to the dependency tree): @unrs/resolver-binding-darwin-arm64, @unrs/resolver-binding-android-arm64, @unrs/resolver-binding-win32-arm64-msvc, @unrs/resolver-binding-linux-arm64-gnu, @unrs/resolver-binding-linux-arm64-musl, @unrs/resolver-binding-openharmony",
      "postinstall.js: read in full (5 lines); it requires the dependency napi-postinstall and calls checkAndPreparePackage(packageJson, true). No other package code runs at install.",
      "Delegated command: the platform binding check and any fallback fetch happen inside the napi-postinstall dependency, which is out of scope as code."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "dependency napi-postinstall installed",
      "reason": "postinstall.js requires napi-postinstall; the hook throws if it is missing"
    }
  ],
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
  "assessment_reason": "The postinstall hook only hands the package manifest to napi-postinstall so it can check the platform-specific native binding is present. There is no environment check, network call or file write in the package's own install code.",
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
