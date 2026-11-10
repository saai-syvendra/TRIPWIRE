# npm @parcel/watcher@2.6.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-07-20 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `install` hook runs `node scripts/build-from-source.js`, a 16-line script. It has one gate: when `npm_config_build_from_source` equals `true` (set by `npm install --build-from-source`), it spawns `node-gyp rebuild` through a shell and exits with its code. Otherwise it does nothing, and the prebuilt binary comes from the platform-specific optional dependency. Nothing malicious happens at install.

## Execution

- **install** `node scripts/build-from-source.js`: runs scripts/build-from-source.js; direct_script, native_build.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | install | c1 (c1: process.env.npm_config_build_from_source == true) | then | 1 | benign_build | env_var=npm_config_build_from_source=true |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- installed_tool: node-gyp (spawned by name through a shell when building from source)
- installed_tool: python3, make, g++ (node-gyp needs Python and a C++ toolchain to compile the addon (MSVC on Windows, Xcode tools on macOS))

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- `binding.gyp` is a standard N-API addon config. Its only command expansion is the usual `node-addon-api` include_dir lookup.
- The `npm_config_build_from_source` gate is a user opt-in for a build, not evasion. It is classed as `package_manager` because npm sets it from a CLI flag.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@parcel/watcher",
    "version": "2.6.0",
    "archive_sha256": "ab42807be3df24a12d01e31568a7e61def1a4bee636a7c60a397319eff677e95",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-07-20",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/watcher-2.6.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "6058388d2c7e301c8dd98e8cf7b7d08afa162f7a4769dba1453019dc4be62918",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "install",
        "command": "node scripts/build-from-source.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/build-from-source.js"
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
      "scripts/build-from-source.js: read in full (16 lines). Only runs `node-gyp rebuild` (shell: true) when npm_config_build_from_source is 'true', and exits with node-gyp's exit code; otherwise does nothing.",
      "binding.gyp read in full: plain native addon targets; its only command expansion is the standard node-addon-api include_dir lookup. Compiled C++ sources under src/ are the addon itself, not install logic.",
      "index.js and wrapper.js are load-time only (main), not reached at install.",
      "optionalDependencies (platform picks belong to the dependency tree): @parcel/watcher-darwin-x64, @parcel/watcher-darwin-arm64, @parcel/watcher-win32-x64, @parcel/watcher-win32-arm64, @parcel/watcher-linux-x64-glibc, @parcel/watcher-linux-x64-musl, @parcel/watcher-linux-arm64-glibc, @parcel/watcher-l"
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "node-gyp",
      "reason": "spawned by name through a shell when building from source"
    },
    {
      "axis": "installed_tool",
      "value": "python3, make, g++",
      "reason": "node-gyp needs Python and a C++ toolchain to compile the addon (MSVC on Windows, Xcode tools on macOS)"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "process.env.npm_config_build_from_source",
      "operator": "==",
      "value": "true",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_0b888764f2",
          "anchor": {
            "file": "scripts/build-from-source.js",
            "derived_from": null,
            "start_byte": 68,
            "end_byte": 119,
            "node_type": "binary_expression",
            "sha256": "21c2cc884b0ad2ae",
            "line": 5
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "install",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_e71e36a668",
          "site": {
            "file": "scripts/build-from-source.js",
            "derived_from": null,
            "start_byte": 64,
            "end_byte": 135,
            "node_type": "if_statement",
            "sha256": "dbf4061c53c2de10",
            "line": 5
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "User opt-in to compile the native addon from source instead of using the prebuilt platform optional dependency.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "env_var": {
            "npm_config_build_from_source": "true"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/build-from-source.js",
            "derived_from": null,
            "start_byte": 121,
            "end_byte": 135,
            "node_type": "statement_block",
            "sha256": "8aa38e27f3262555",
            "line": 5
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/build-from-source.js",
              "derived_from": null,
              "start_byte": 158,
              "end_byte": 221,
              "node_type": "call_expression",
              "sha256": "7720b30d6a182a59",
              "line": 10
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/build-from-source.js",
                  "derived_from": null,
                  "start_byte": 125,
                  "end_byte": 132,
                  "node_type": "call_expression",
                  "sha256": "b70ef1dfa184d8cb",
                  "line": 6
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/build-from-source.js",
                  "derived_from": null,
                  "start_byte": 137,
                  "end_byte": 299,
                  "node_type": "function_declaration",
                  "sha256": "55c89bd3fd7c8b59",
                  "line": 9
                }
              }
            ]
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "benign_build"
    ]
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
  "assessment_reason": "The install hook only runs node-gyp rebuild when the user sets npm_config_build_from_source=true, and otherwise does nothing. No network, credential or file access beyond the standard native build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "79fa0fd36d7d6563"
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
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
