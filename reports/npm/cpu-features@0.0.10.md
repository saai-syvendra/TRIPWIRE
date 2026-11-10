# npm cpu-features@0.0.10

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-05-03 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `install` hook runs `node buildcheck.js > buildcheck.gypi && node-gyp rebuild`. `buildcheck.js` uses the `buildcheck` dependency to probe the C compiler for `dlfcn.h` and `getauxval`, then prints a gyp config that node-gyp includes when it compiles the bundled cpu_features library and the addon. There are no gates: the compiler probe and the OS/arch conditions in the gyp files only choose defines and source files. Any environment with Python, make and a C/C++ compiler completes the build.

## Execution

- **install** `node buildcheck.js > buildcheck.gypi && node-gyp rebuild`: runs buildcheck.js; direct_script, native_build.

## Gates

None.

## Requirements

- installed_tool: python3 (node-gyp rebuild needs Python)
- installed_tool: make (node-gyp build on POSIX)
- installed_tool: cc (C/C++ compiler for buildcheck probes and the native addon)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

No candidates were extracted and none were added. The gyp files have no actions. The `buildcheck` and `nan` dependencies are out of scope as code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "cpu-features",
    "version": "0.0.10",
    "archive_sha256": "58a4cea14b272b9845e25b31aef88026eaabc641a308c00270c0ed2e95777ad4",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-05-03",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/cpu-features-0.0.10.tgz",
    "package_root": "layer0/mscdex-cpu-features-c6f574c",
    "cluster_key": "98028104d325a1e995620e50199f6bbd55a81d74128d0927551929464c4a3eb3",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "install",
        "command": "node buildcheck.js > buildcheck.gypi && node-gyp rebuild",
        "runs_on": "always",
        "file_chain": [
          "buildcheck.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "install: delegates to node-gyp; code inside that dependency is out of scope",
      "buildcheck.js: read in full. It uses the buildcheck dependency to probe the C compiler for dlfcn.h and getauxval and prints gyp config, which the hook redirects into buildcheck.gypi.",
      "The getauxval probe only adds a compiler define, and the OS/target_arch condition in the printed gyp config only picks sources; both are build plumbing, not gates.",
      "binding.gyp and deps/cpu_features/cpu_features.gyp read in full: no actions, only sources, defines and arch conditions. binding.gyp runs node -e \"require('nan')\" to get the nan include path (dependency code).",
      "lib/index.js runs only when the package is loaded; not install-time."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "python3",
      "reason": "node-gyp rebuild needs Python"
    },
    {
      "axis": "installed_tool",
      "value": "make",
      "reason": "node-gyp build on POSIX"
    },
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "C/C++ compiler for buildcheck probes and the native addon"
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
  "assessment_reason": "The install hook generates a gyp include from compiler feature probes and then compiles the bundled cpu_features C library with node-gyp. No network, credential access or environment gating.",
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
