# npm @firebase/util@1.15.3

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-08-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node ./postinstall.js`, the official Firebase script that bakes a default web app config into `dist/postinstall.js` and `dist/postinstall.mjs`. Those two files are always written (benign_build, ungated). When `FIREBASE_WEBAPP_CONFIG` is set (g2), the config is parsed from inline JSON or read from the file it names. When that config exists, `X_GOOGLE_TARGET_PLATFORM` is not `fah`, the project id does not start with `demo-` and the config has `appId` and `apiKey` (g1), the script fetches the full config from the Firebase webConfig API. Nothing malicious; all gates are ordinary config handling.

## Execution

- **postinstall** `node ./postinstall.js`: runs postinstall.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c2 && c1 && c4 && c5 && c6 (c2: process.env.FIREBASE_WEBAPP_CONFIG truthy; c1: process.env.X_GOOGLE_TARGET_PLATFORM != fah; c4: partialConfig.projectId not_startswith demo-; c5: partialConfig.appId truthy; c6: partialConfig.apiKey truthy) | then | 5 | benign_build | env_var=FIREBASE_WEBAPP_CONFIG={"projectId":"p","appId":"a","apiKey":"k"}; env_var_absent=X_GOOGLE_TARGET_PLATFORM |
| g2 | postinstall | c2 (c2: process.env.FIREBASE_WEBAPP_CONFIG truthy) | then | 1 | benign_build | env_var=FIREBASE_WEBAPP_CONFIG=(set) |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 2 of 5 conditions and 1 of 2 gates from the candidate set; out of set, pending verification: c4, c5, c6, g1.

## Requirements

- network: firebase[.]googleapis[.]com:443 (config refresh fetch on the g1 branch; failure is swallowed and the install still completes)
- runtime_version: node>=18 (uses the global fetch and optional chaining)

## Behaviour

- Ungated: benign_build
- Gated: benign_build

## Notes

- Condition ids skip c3: the JSON-vs-path test (k_fe169d0b26 / q_c0cb4022cc) was dropped as plumbing.
- c4, c5 and c6 test the `projectId`, `appId` and `apiKey` fields of the parsed config, which comes from `FIREBASE_WEBAPP_CONFIG` inline or from the file it names. The line 62 guard reads the parsed config. These are out of set.
- c4, c5 and c6 keep category `env_var` because no category covers parsed config fields; this choice is escalated to a person.
- The fetch endpoint is not listed under reachability because no role fits a benign config fetch; it is a network requirement instead, and its failure is swallowed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@firebase/util",
    "version": "1.15.3",
    "archive_sha256": "0a812b12ea0d186c2c864417140ef27954dc28bf9cbb6097dc5cb447a24be877",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-08-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/util-1.15.3.tgz",
    "package_root": "layer0/package",
    "cluster_key": "6132a973d28ca7c8b0e7e8fa2853d41b00d1e5dcb7fd52ddc3f819616908cb55",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node ./postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "postinstall.js"
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
      "postinstall.js: package code, read in full (154 lines). No other file is reached at install.",
      "The script always writes dist/postinstall.js and dist/postinstall.mjs exporting getDefaultsFromPostinstall(); the embedded defaults are the resolved Firebase config, or undefined when no config is found.",
      "g1 guard at line 62 tests partialConfig, which is only set when FIREBASE_WEBAPP_CONFIG is non-empty and parses (c2), so it is cited as a c2 guard.",
      "c4, c5 and c6 test fields of the parsed config (partialConfig.projectId, appId, apiKey), not the raw env string. A missing projectId falls back to '-', which passes c4. Line 78 tests appId and apiKey separately, so they are two conditions.",
      "c4, c5 and c6 keep category env_var: FIREBASE_WEBAPP_CONFIG supplies the config inline or by naming a file, and no category covers parsed config fields. Escalated for a person to confirm.",
      "The JSON-literal vs file-path test (line 33, startsWith '{\"') only picks how the config value is parsed; both sides feed the same config, so it is treated as plumbing and dropped.",
      "The config fetch goes to the firebase googleapis webConfig endpoint with the user's own apiKey; it fetches JSON config, not code. No endpoint role fits a benign config fetch, so the endpoint list is left empty; see requirements.",
      "Errors are swallowed: every failure path warns and returns undefined, and handleUnexpectedError calls process.exit(0)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "firebase[.]googleapis[.]com:443",
      "reason": "config refresh fetch on the g1 branch; failure is swallowed and the install still completes"
    },
    {
      "axis": "runtime_version",
      "value": "node>=18",
      "reason": "uses the global fetch and optional chaining"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.X_GOOGLE_TARGET_PLATFORM",
      "operator": "!=",
      "value": "fah",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_fd2938e904",
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2030,
            "end_byte": 2076,
            "node_type": "binary_expression",
            "sha256": "1ac9f478455415e3",
            "line": 67
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.FIREBASE_WEBAPP_CONFIG",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_93d5de87f8",
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 915,
            "end_byte": 926,
            "node_type": "identifier",
            "sha256": "84bd8ddef205c9f0",
            "line": 27
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "partialConfig.projectId",
      "operator": "not_startswith",
      "value": "demo-",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2291,
            "end_byte": 2320,
            "node_type": "call_expression",
            "sha256": "c905b44273bf2ced",
            "line": 73
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "partialConfig.appId",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2436,
            "end_byte": 2442,
            "node_type": "unary_expression",
            "sha256": "385e4d0cc2e02df1",
            "line": 78
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "partialConfig.apiKey",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2446,
            "end_byte": 2453,
            "node_type": "unary_expression",
            "sha256": "37b8b62fea689cd1",
            "line": 78
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
      "expression": "c2 && c1 && c4 && c5 && c6",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 1801,
            "end_byte": 1848,
            "node_type": "if_statement",
            "sha256": "f7fecc9c8b1d587a",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": "q_466c3803a6",
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2026,
            "end_byte": 2109,
            "node_type": "if_statement",
            "sha256": "07fa0f9b66592d43",
            "line": 67
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2287,
            "end_byte": 2353,
            "node_type": "if_statement",
            "sha256": "5e8dadabe1ebc41f",
            "line": 73
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2432,
            "end_byte": 2607,
            "node_type": "if_statement",
            "sha256": "5486c19c4519b028",
            "line": 78
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the config refresh only runs when a non-App-Hosting, non-demo Firebase config with appId and apiKey is supplied",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "env_var": {
            "FIREBASE_WEBAPP_CONFIG": "{\"projectId\":\"p\",\"appId\":\"a\",\"apiKey\":\"k\"}"
          },
          "env_var_absent": [
            "X_GOOGLE_TARGET_PLATFORM"
          ]
        },
        "recipe_guessed_fields": [
          "env_var"
        ],
        "regions": [
          {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2611,
            "end_byte": 3378,
            "node_type": "stmt_range",
            "sha256": "6747e09505517bf8",
            "line": 85
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "network",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 2748,
              "end_byte": 2811,
              "node_type": "call_expression",
              "sha256": "425bd41d44dea8e6",
              "line": 88
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c2",
      "guards": [
        {
          "candidate": "q_a3fd032172",
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 910,
            "end_byte": 955,
            "node_type": "if_statement",
            "sha256": "1592037933dc759a",
            "line": 27
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "config is only parsed (inline JSON or a file at the given path) when FIREBASE_WEBAPP_CONFIG is set",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "env_var": {
            "FIREBASE_WEBAPP_CONFIG": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 1111,
            "end_byte": 1748,
            "node_type": "stmt_range",
            "sha256": "73f6c24a6aec9da8",
            "line": 33
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "fs_read",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 1520,
              "end_byte": 1546,
              "node_type": "call_expression",
              "sha256": "9cd451551f5887db",
              "line": 50
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [
      "benign_build"
    ],
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
  "assessment_reason": "The postinstall script resolves an optional Firebase web app config from FIREBASE_WEBAPP_CONFIG (inline JSON or a file path), optionally refreshes it from the official Firebase webConfig API, and writes it into two generated dist modules. No credential theft, process launch or code download.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "815c8187a2325291"
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
        "candidate": "k_fe169d0b26",
        "reason_code": "other",
        "note": "format dispatch: inline JSON vs file path for the same config value; both sides feed the same config, plumbing not a gate",
        "anchor": {
          "file": "postinstall.js",
          "derived_from": null,
          "start_byte": 1115,
          "end_byte": 1143,
          "node_type": "call_expression",
          "sha256": "415c0dc65068799e",
          "line": 33
        }
      },
      {
        "candidate": "q_c0cb4022cc",
        "reason_code": "other",
        "note": "guard of the dropped k_fe169d0b26 format dispatch (JSON literal vs path); plumbing",
        "anchor": {
          "file": "postinstall.js",
          "derived_from": null,
          "start_byte": 1111,
          "end_byte": 1363,
          "node_type": "if_statement",
          "sha256": "bf4df83ccc040136",
          "line": 33
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 2,
    "conditions_in_set": 2,
    "conditions_out_of_set": 3,
    "guard_candidates": 3,
    "gates_in_set": 1,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c4",
      "c5",
      "c6",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
