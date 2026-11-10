# npm vue-demi@0.14.10

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-07-25 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node -e` that requires `scripts/postinstall.js` inside an empty try/catch. The script tries to load `vue` from the consuming project and, depending on whether its version starts with `2.7.`, `2.` or `3.`, copies the matching `lib/v*/index.{cjs,mjs,d.ts}` files over `lib/` (gate g1). For Vue 2 below 2.7 it also rewrites `lib/index.mjs` to re-export `@vue/composition-api`, but only when that plugin can be loaded (gate g2). All gates are dependency-tree checks (out of scope); no machine-environment check exists, and the work is a benign build step.

## Execution

- **postinstall** `node -e "try{require('./scripts/postinstall.js')}catch(e){}"`: 2-file chain; inline_eval; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && (c2 \|\| c3 \|\| c4) (c1: dependency_tree exists vue; c2: dependency_tree startswith 2.7.; c3: dependency_tree startswith 2.; c4: dependency_tree startswith 3.) | then | 2 | benign_build | (none) |
| g2 | postinstall | c1 && c6 && c3 && c5 (c1: dependency_tree exists vue; c6: dependency_tree not_startswith 2.7.; c3: dependency_tree startswith 2.; c5: dependency_tree exists @vue/composition-api) | then | 4 | benign_build | (none) |

Gate intent: g1 activate/enables/portability; g2 activate/enables/portability

Grounding: 1 of 6 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, c6, g1, g2.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- All conditions except c1 are out of set: the extractor did not emit candidates for the version tests in `scripts/postinstall.js` or the plugin test in `updateVue2API`. c6 shares its site with c2.
- The else-if chain means c3 only applies when c2 is false. g2 states this with c6 (version does not start with `2.7.`), the else side of the line 8 test; g1 needs no exclusion because every matching version reaches a copy region (see execution notes).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "vue-demi",
    "version": "0.14.10",
    "archive_sha256": "b239890af0797bac06350b2e78d9030aff37824b03f74711130bd9dcf3198e19",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-07-25",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/vue-demi-0.14.10.tgz",
    "package_root": "layer0/package",
    "cluster_key": "fd78f54960159b52d1f72b4b7e15cdb3363cc68abf049bf46d46752f0efb96b8",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node -e \"try{require('./scripts/postinstall.js')}catch(e){}\"",
        "runs_on": "always",
        "file_chain": [
          "scripts/postinstall.js",
          "scripts/utils.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "inline_eval"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): vue-demi-fix, vue-demi-switch",
      "Coverage: inline hook, scripts/postinstall.js and scripts/utils.js read in full; nothing bundled, nothing unread.",
      "The version tests are an else-if chain: c3 (2.x) is only reached when c2 (2.7.x) is false, and c4 (3.x) only when both are false. g1 needs no exclusions: every version matching c2, c3 or c4 reaches a copy region.",
      "g2 runs only via switchVersion(2), i.e. Vue 2.x but not 2.7.x; switchVersion(2.7) skips updateVue2API because version === 2 is false. c6 is the else side of the line 8 test (same site as c2), written positively, so g2 states the exclusion.",
      "typeof Vue.version !== 'string' on line 5 is a presence check in front of the startsWith tests of the same value, so it is part of those tests and not a separate condition.",
      "loadModule's try/catch only turns a failed require into undefined; the decisions are the if tests in postinstall.js and updateVue2API, so the try candidate is dropped."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "dependency_tree",
      "api": "require",
      "operator": "exists",
      "value": "vue",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_c369245a2f",
          "anchor": {
            "file": "scripts/utils.js",
            "derived_from": null,
            "start_byte": 152,
            "end_byte": 165,
            "node_type": "call_expression",
            "sha256": "ba0f2213e279c1cc",
            "line": 8
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "dependency_tree",
      "api": "Vue.version.startsWith",
      "operator": "startswith",
      "value": "2.7.",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 235,
            "end_byte": 265,
            "node_type": "call_expression",
            "sha256": "030da8c79656f027",
            "line": 8
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "dependency_tree",
      "api": "Vue.version.startsWith",
      "operator": "startswith",
      "value": "2.",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 301,
            "end_byte": 329,
            "node_type": "call_expression",
            "sha256": "0e2073f4c0cd7805",
            "line": 11
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "dependency_tree",
      "api": "Vue.version.startsWith",
      "operator": "startswith",
      "value": "3.",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 363,
            "end_byte": 391,
            "node_type": "call_expression",
            "sha256": "817bcb023cc09796",
            "line": 14
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "dependency_tree",
      "api": "require",
      "operator": "exists",
      "value": "@vue/composition-api",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/utils.js",
            "derived_from": null,
            "start_byte": 660,
            "end_byte": 694,
            "node_type": "call_expression",
            "sha256": "affa4740b2cd8af8",
            "line": 29
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "dependency_tree",
      "api": "Vue.version.startsWith",
      "operator": "not_startswith",
      "value": "2.7.",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 235,
            "end_byte": 265,
            "node_type": "call_expression",
            "sha256": "030da8c79656f027",
            "line": 8
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1 && (c2 || c3 || c4)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 89,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "7be34173419d2c91",
            "line": 5
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 231,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "4814f6201668cbac",
            "line": 8
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 297,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "c003676399d8b39b",
            "line": 11
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 359,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "27a8be4717b638ad",
            "line": 14
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "Copies the lib/v2.7, lib/v2 or lib/v3 entry files over lib/ to match the Vue version installed next to it; nothing is written when Vue is missing or unsupported.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 271,
            "end_byte": 289,
            "node_type": "expression_statement",
            "sha256": "01490a44f46805e5",
            "line": 9
          },
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 335,
            "end_byte": 351,
            "node_type": "expression_statement",
            "sha256": "66b1becd6b92c481",
            "line": 12
          },
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 397,
            "end_byte": 413,
            "node_type": "expression_statement",
            "sha256": "cf92db00fb4e0ebb",
            "line": 15
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/utils.js",
              "derived_from": null,
              "start_byte": 531,
              "end_byte": 571,
              "node_type": "call_expression",
              "sha256": "bfee2fe531e276e2",
              "line": 24
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 271,
                  "end_byte": 289,
                  "node_type": "call_expression",
                  "sha256": "01490a44f46805e5",
                  "line": 9
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/utils.js",
                  "derived_from": null,
                  "start_byte": 1299,
                  "end_byte": 1484,
                  "node_type": "function_declaration",
                  "sha256": "f03e94d5d6830270",
                  "line": 51
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/utils.js",
                  "derived_from": null,
                  "start_byte": 1340,
                  "end_byte": 1371,
                  "node_type": "call_expression",
                  "sha256": "2fd8bb773e576804",
                  "line": 52
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/utils.js",
                  "derived_from": null,
                  "start_byte": 210,
                  "end_byte": 573,
                  "node_type": "function_declaration",
                  "sha256": "76d2b84b870d1041",
                  "line": 14
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c1 && c6 && c3 && c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 89,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "7be34173419d2c91",
            "line": 5
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 231,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "4814f6201668cbac",
            "line": 8
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 297,
            "end_byte": 499,
            "node_type": "if_statement",
            "sha256": "c003676399d8b39b",
            "line": 11
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/utils.js",
            "derived_from": null,
            "start_byte": 697,
            "end_byte": 849,
            "node_type": "if_statement",
            "sha256": "c94450750016b665",
            "line": 30
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "For Vue 2.x below 2.7, rewrites lib/index.mjs to re-export @vue/composition-api only when that plugin is installed.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/utils.js",
            "derived_from": null,
            "start_byte": 853,
            "end_byte": 1292,
            "node_type": "stmt_range",
            "sha256": "c01c707e2deb3f18",
            "line": 35
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/utils.js",
              "derived_from": null,
              "start_byte": 1249,
              "end_byte": 1292,
              "node_type": "call_expression",
              "sha256": "01bbf7c7ce2d7078",
              "line": 47
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
  "assessment_reason": "The postinstall script only detects the installed Vue version and copies the matching prebuilt entry files inside the package's own lib/ folder, optionally rewriting index.mjs exports for @vue/composition-api. No network, process launch or access outside the package.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "inline_script",
        "recipe_version": 1,
        "input": {
          "file": "package.json",
          "derived_from": null
        },
        "params": {
          "hook": "postinstall",
          "flag": "-e"
        },
        "output_sha256": "2aa151576e425d85"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "42b7b649bd73d388"
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
        "candidate": "q_252e2ae770",
        "reason_code": "other",
        "note": "try/catch in loadModule only converts a failed require into undefined (plumbing); the decisions on the result are the if tests in postinstall.js line 5 and utils.js line 30, recorded as g1/g2 guards.",
        "anchor": {
          "file": "scripts/utils.js",
          "derived_from": null,
          "start_byte": 135,
          "end_byte": 206,
          "node_type": "try_statement",
          "sha256": "165a909e40edf8d7",
          "line": 7
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 0,
    "candidates_dropped": 1,
    "conditions_in_set": 1,
    "conditions_out_of_set": 5,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
