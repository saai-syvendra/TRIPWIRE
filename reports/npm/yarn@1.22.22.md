# npm yarn@1.22.22

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-03-09 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node ./preinstall.js` in a subshell with output discarded and `|| true`, so any failure is silent. The script does nothing unless `npm_config_global` is set (a global `npm install -g`). On a global install it runs `node <npm_execpath> bin -g` to find npm's global bin folder, then for each of the package's bin names (yarn, yarnpkg) reads the symlink there and deletes it only if it points into `../lib/node_modules/corepack/`. So the gates are c1 (global install) for the process spawn, and c1 && link exists && link target is Corepack for the file deletion.

## Execution

- **preinstall** `:; (node ./preinstall.js > /dev/null 2>&1 || true)`: runs preinstall.js; inline_shell, direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: process.env.npm_config_global truthy) | then | 1 | spawn_process | env_var=npm_config_global=true |
| g2 | preinstall | c1 && c2 && c3 (c1: process.env.npm_config_global truthy; c2: file_or_dir_exists exists; c3: file_content startswith ../lib/node_modules/corepack/) | then | 3 | delete_file | env_var=npm_config_global=true; file_present=<npm global bin>/yarn as a symlink whose target starts with ../lib/node_modules/corepack/ |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability

Grounding: 0 of 3 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c1, c2, c3, g1, g2.

## Requirements

- installed_tool: node (the hook command runs node ./preinstall.js)
- other: env var npm_execpath set to an npm CLI path (execFileSync(process.execPath, [npm_execpath, 'bin', '-g']) must succeed to find the global bin folder; otherwise the outer catch ends the script)

## Behaviour

- Ungated: none
- Gated: spawn_process, delete_file

## Notes

- The extractor did not chain preinstall.js because the hook starts with the shell no-op `:;`; every condition and gate here was added by hand and is out of set.
- The deletion is the legitimate Corepack shim cleanup of yarn 1.x; nothing reaches the network.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "yarn",
    "version": "1.22.22",
    "archive_sha256": "c17d3797fb9a9115bf375e31bfd30058cac6bc9c3b8807a3d8cb2094794b51ca",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-03-09",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/yarn-1.22.22.tgz",
    "package_root": "layer0/package",
    "cluster_key": "8262075db0cd659b8a9cfd7d5a2a7fd93b625ad258d909472d73765301de4bd3",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": ":; (node ./preinstall.js > /dev/null 2>&1 || true)",
        "runs_on": "always",
        "file_chain": [
          "preinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "inline_shell",
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "preinstall: the tool read ':' (the shell no-op) as the executable; the hook actually runs 'node ./preinstall.js' in a subshell with all output to /dev/null and '|| true'. preinstall.js added to file_chain by hand.",
      "preinstall.js: read in full (60 lines, plain JS, no candidates were extracted because the tool never chained it). All conditions and gates are out of set for that reason.",
      "preinstall.js: the outer try around execFileSync(node, [npm_execpath, 'bin', '-g']) only needs the command to work and swallows errors; treated as a requirement and silent_failure, not a gate.",
      "preinstall.js: binNames comes from the package's own package.json bin keys (yarn, yarnpkg), not the environment; the forEach loop is not a gate.",
      "bin commands not analysed (run only when invoked): yarn, yarnpkg. lib/cli.js and lib/v8-compile-cache.js are only loaded by the bin and are not install-reached."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "node",
      "reason": "the hook command runs node ./preinstall.js"
    },
    {
      "axis": "other",
      "value": "env var npm_execpath set to an npm CLI path",
      "reason": "execFileSync(process.execPath, [npm_execpath, 'bin', '-g']) must succeed to find the global bin folder; otherwise the outer catch ends the script",
      "sites": [
        {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1291,
          "end_byte": 1460,
          "node_type": "call_expression",
          "sha256": "9768d29b3abf06ac",
          "line": 27
        }
      ]
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "process.env.npm_config_global",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1123,
            "end_byte": 1152,
            "node_type": "member_expression",
            "sha256": "a205e71ab43f4d30",
            "line": 21
          }
        }
      ]
    },
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "fs.readlinkSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.readlinkSync",
        "target": "<npm global bin>/yarn, <npm global bin>/yarnpkg",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1953,
            "end_byte": 1977,
            "node_type": "call_expression",
            "sha256": "a197c625a9842948",
            "line": 44
          }
        }
      ]
    },
    {
      "id": "c3",
      "category": "file_content",
      "api": "fs.readlinkSync",
      "operator": "startswith",
      "value": "../lib/node_modules/corepack/",
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.readlinkSync",
        "target": "<npm global bin>/yarn, <npm global bin>/yarnpkg",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 2062,
            "end_byte": 2115,
            "node_type": "call_expression",
            "sha256": "35b76d29dfa0391b",
            "line": 49
          }
        }
      ]
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1",
      "provenance": "out_of_set",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1119,
            "end_byte": 2341,
            "node_type": "if_statement",
            "sha256": "491ffb8417c6ac77",
            "line": 21
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the script only acts on global installs (npm install -g), where npm's bin folder can hold a Corepack shim",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "env_var": {
            "npm_config_global": "true"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1160,
            "end_byte": 2339,
            "node_type": "stmt_range",
            "sha256": "2f77ffd22cf4617d",
            "line": 22
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 1291,
              "end_byte": 1460,
              "node_type": "call_expression",
              "sha256": "9768d29b3abf06ac",
              "line": 27
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c1 && c2 && c3",
      "provenance": "out_of_set",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1119,
            "end_byte": 2341,
            "node_type": "if_statement",
            "sha256": "491ffb8417c6ac77",
            "line": 21
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 1919,
            "end_byte": 2044,
            "node_type": "try_statement",
            "sha256": "b52e6c4bc3f54fee",
            "line": 43
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 2058,
            "end_byte": 2276,
            "node_type": "if_statement",
            "sha256": "da08b61cbbfd2680",
            "line": 49
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "only deletes a yarn/yarnpkg bin entry that exists as a symlink into Corepack, so npm can then link the real yarn binary",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "delete_file"
        ],
        "env_recipe": {
          "env_var": {
            "npm_config_global": "true"
          },
          "file_present": [
            "<npm global bin>/yarn as a symlink whose target starts with ../lib/node_modules/corepack/"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 2135,
            "end_byte": 2262,
            "node_type": "try_statement",
            "sha256": "389454c265523366",
            "line": 50
          }
        ],
        "payload": [
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 2161,
              "end_byte": 2183,
              "node_type": "call_expression",
              "sha256": "b0cf11daf3f02ad2",
              "line": 51
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "spawn_process",
      "delete_file"
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
  "assessment_reason": "The preinstall script only runs on global npm installs, asks npm for its global bin folder, and removes yarn/yarnpkg symlinks that point into Corepack so the real yarn can be linked. No network, no data collection, no writes outside that.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@97d6974e53",
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
    "conditions_out_of_set": 3,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
