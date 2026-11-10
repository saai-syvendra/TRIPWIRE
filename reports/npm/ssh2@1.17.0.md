# npm ssh2@1.17.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2025-08-20 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `install` hook runs `node install.js`, which calls `node-gyp rebuild` in `lib/protocol/crypto` to compile an optional native crypto binding (`binding.gyp`, `src/binding.cc`). It exits 0 whether or not the build succeeds, so a build failure is silent. There are no gates: the only environment check, `CI_CHECK_FAIL === 'ssh2'`, just makes a failed build exit with code 1, and no behaviour depends on it. The install does a benign native build and nothing else.

## Execution

- **install** `node install.js`: runs install.js; direct_script, native_build; errors hidden.

## Gates

None.

## Requirements

- installed_tool: node-gyp (install.js runs node-gyp rebuild through the shell; npm normally provides node-gyp on PATH. A missing tool only makes the optional build fail silently.)
- installed_tool: python3, make, c++ compiler (node-gyp needs a Python and a C++ toolchain to compile the optional crypto binding.)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The two prefilled candidates (the `CI_CHECK_FAIL` test and its `if`) were dropped because they only change the exit code.
- `binding.gyp` only uses the standard nan include lookup; nothing else runs during the build.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "ssh2",
    "version": "1.17.0",
    "archive_sha256": "8bf2fff9c148973ed24a95087c0b4cea9b8f07a61621c8ab3ded453e3cbcd7d7",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2025-08-20",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/ssh2-1.17.0.tgz",
    "package_root": "layer0/mscdex-ssh2-5c506eb",
    "cluster_key": "ab46af09613863fff6f35eea147f2a0aeec2d57870b2916993b349fde1a547bf",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "install",
        "command": "node install.js",
        "runs_on": "always",
        "file_chain": [
          "install.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "native_build"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "optionalDependencies (platform picks belong to the dependency tree): cpu-features, nan",
      "install.js read in full (27 lines): runs node-gyp rebuild in lib/protocol/crypto via spawnSync with shell:true, then exits 0 whether or not the build succeeded.",
      "lib/protocol/crypto/binding.gyp read in full: one target compiling src/binding.cc (crypto binding); its only command expansion is the standard nan include lookup via node -e require('nan').",
      "CI_CHECK_FAIL == 'ssh2' only turns a failed build into exit code 1 instead of 0; no behaviour changes, so it is not a gate (dropped as other).",
      "src/binding.cc is compiled at install but not executed; it is only loaded when the library is used."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "node-gyp",
      "reason": "install.js runs node-gyp rebuild through the shell; npm normally provides node-gyp on PATH. A missing tool only makes the optional build fail silently."
    },
    {
      "axis": "installed_tool",
      "value": "python3, make, c++ compiler",
      "reason": "node-gyp needs a Python and a C++ toolchain to compile the optional crypto binding."
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
  "assessment_reason": "The install hook only runs node-gyp rebuild for an optional native crypto binding and exits 0 regardless of the result. No network, credential, or file access beyond the normal native build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "cc85c066266ce6b2"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_0306aded0e",
        "reason_code": "other",
        "note": "CI_CHECK_FAIL == 'ssh2' only decides exit code 1 vs 0 after a failed optional build; no behaviour depends on it.",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 92,
          "end_byte": 128,
          "node_type": "binary_expression",
          "sha256": "117ae06e0ee14798",
          "line": 5
        }
      },
      {
        "candidate": "q_3b6a3f1960",
        "reason_code": "other",
        "note": "if (forceFailOnNonZero) process.exit(1) only changes the exit status after a failed build; both sides end the install with no further behaviour.",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 573,
          "end_byte": 617,
          "node_type": "if_statement",
          "sha256": "ab68a10926b5c079",
          "line": 22
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
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
