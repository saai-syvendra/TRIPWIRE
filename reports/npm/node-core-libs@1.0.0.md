# npm node-core-libs@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-22 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node scripts/postinstall.js`, which exits at once unless `process.platform` is `win32` (g1). On Windows it fetches `/nl` over plain HTTP from an XOR-hidden host (node22.lunes[.]host:3258). When the body is at least 16 bytes (g4, a server-response check), it writes it to `%TMP%/ms_<hex>.js`, drops a VBS that runs it with `node` through `wscript //B` hidden and detached, then deletes its own script. On every Windows path it also calls `_tidy()`, which rewrites `node-fetch-utils/package.json` if that sibling package is installed (g2), strips the install hooks from its own `package.json` (g3), and writes the project root to `%TMP%/.nfc_root`. A Windows VM with the C2 reachable opens all gates.

## Execution

- **postinstall** `node scripts/postinstall.js`: runs scripts/postinstall.js; direct_script, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: os == win32) | then | 1 | download, write_file | os=win32 |
| g2 | postinstall | c1 && c2 (c1: os == win32; c2: file_or_dir_exists exists ./../../node-fetch-utils/package.json) | then | 2 | modify_other_packages | os=win32; file_present=./../../node-fetch-utils/package.json |
| g3 | postinstall | c1 && c3 (c1: os == win32; c3: file_or_dir_exists exists ./../package.json) | then | 2 | defense_evasion | os=win32; file_present=./../package.json |
| g4 | postinstall | c1 && c4 (c1: os == win32; c4: server_response >= 16) | then | 2 | write_file, exec_downloaded, defense_evasion, delete_file | os=win32; network=node22[.]lunes[.]host:3258=reachable |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability

Grounding: 3 of 4 conditions and 3 of 4 gates from the candidate set; out of set, pending verification: c4, g4.

## Requirements

- network: node22[.]lunes[.]host:3258 (plain HTTP GET /nl fetches the second-stage JS; a failed or short response ends in _tidy only)
- installed_tool: wscript.exe, node (the dropped VBS is run by wscript.exe and launches the stage with node from PATH)

## Behaviour

- Ungated: none
- Gated: download, write_file, modify_other_packages, defense_evasion, exec_downloaded, delete_file

## Notes

- The host, port and an unused key (`changeme-spectre`) are XOR 0x5A byte arrays, decoded with `decode.py`.
- The `node-fetch-utils` block re-serialises the JSON without changing anything, though its comment says it removes the postinstall entry. It is recorded as misleading text.
- The `.nfc_root` marker is for a `node_launcher.js` that is not in this package. We only know this from a comment, so it is probably the second stage.
- c4/g4 are out of set. No candidate covered the early exit inside the async IIFE.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "node-core-libs",
    "version": "1.0.0",
    "archive_sha256": "fed0f5b410cf6d312f0e5c40be26e00deb3278477a3757814a2dfc437e22fdbe",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-22",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-06-22-node-core-libs-v1.0.0.zip",
    "package_root": "layer0/tmp/tmpusmlujn_/node-core-libs/package",
    "cluster_key": "4ee304eefdc4866740be54dd4cf6612566e29df050cee3b84de9b58f01468181",
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
          "scripts/postinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "scripts/postinstall.js: package code read in full (51 lines). index.js is the main entry, only loaded on require, and holds plain utility helpers. Nothing unread.",
      "Host, port and an unused 16-byte key are XOR 0x5A byte arrays (lines 5-7), decoded with decode.py: host node22.lunes[.]host, port 3258. The key string is never used.",
      "The downloaded body is written to %TMP%/ms_<hex>.js and started by a dropped %TMP%/mv_<hex>.vbs via wscript //B, which runs it with node, hidden and detached. The VBS deletes itself.",
      "_tidy() runs on every path after the win32 check (short or failed response, catch handler, after the launch), so its writes sit under g1/g2/g3, not under g4.",
      "In _tidy the node-fetch-utils/package.json block re-serialises the JSON unchanged: the dependencies check on line 19 has an empty body and no field is removed, although the comment says it removes postinstall.",
      "Line 33 comment says the %TMP%/.nfc_root marker (project root path) is for a node_launcher.js that patches lock files. That file is not in this package (per comment only), likely the second stage.",
      "The 15000 ms value on http.get is a socket timeout, not a delay."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "node22[.]lunes[.]host:3258",
      "reason": "plain HTTP GET /nl fetches the second-stage JS; a failed or short response ends in _tidy only"
    },
    {
      "axis": "installed_tool",
      "value": [
        "wscript.exe",
        "node"
      ],
      "reason": "the dropped VBS is run by wscript.exe and launches the stage with node from PATH"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_693a951555",
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 17,
            "end_byte": 43,
            "node_type": "binary_expression",
            "sha256": "7f3fbb7c15a46838",
            "line": 2
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "./../../node-fetch-utils/package.json",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_aeeac66d82",
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1022,
            "end_byte": 1038,
            "node_type": "call_expression",
            "sha256": "258b9aa99c92b3cc",
            "line": 17
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "./../package.json",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_824e1c2614",
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1439,
            "end_byte": 1455,
            "node_type": "call_expression",
            "sha256": "1c66b237957fedb3",
            "line": 27
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "server_response",
      "api": "http.get response body length",
      "operator": ">=",
      "value": 16,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1930,
            "end_byte": 1945,
            "node_type": "binary_expression",
            "sha256": "452ce8882af19ecd",
            "line": 40
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
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_72f952f4b9",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 14,
            "end_byte": 62,
            "node_type": "if_statement",
            "sha256": "213b8cfeb1c5aa2a",
            "line": 2
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the whole payload (wscript/VBS launcher, Windows temp paths) exists only for Windows; other platforms exit at once",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 63,
            "end_byte": 2557,
            "node_type": "stmt_range",
            "sha256": "e94c48e75b351ef3",
            "line": 3
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 526,
              "end_byte": 652,
              "node_type": "call_expression",
              "sha256": "fce5fb5ec500ab45",
              "line": 8
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1886,
                  "end_byte": 2556,
                  "node_type": "call_expression",
                  "sha256": "1c57bebe983894f7",
                  "line": 38
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1887,
                  "end_byte": 2553,
                  "node_type": "arrow_function",
                  "sha256": "2f87a15dfcff59e3",
                  "line": 38
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1916,
                  "end_byte": 1925,
                  "node_type": "call_expression",
                  "sha256": "4a28388c84613550",
                  "line": 39
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 493,
                  "end_byte": 712,
                  "node_type": "arrow_function",
                  "sha256": "88de2daf337acfe5",
                  "line": 8
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 1795,
              "end_byte": 1854,
              "node_type": "call_expression",
              "sha256": "a4e5cc8cbfd9a0b8",
              "line": 34
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1886,
                  "end_byte": 2556,
                  "node_type": "call_expression",
                  "sha256": "1c57bebe983894f7",
                  "line": 38
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1887,
                  "end_byte": 2553,
                  "node_type": "arrow_function",
                  "sha256": "2f87a15dfcff59e3",
                  "line": 38
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 1947,
                  "end_byte": 1954,
                  "node_type": "call_expression",
                  "sha256": "72e94e37c57618ec",
                  "line": 40
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/postinstall.js",
                  "derived_from": null,
                  "start_byte": 715,
                  "end_byte": 1884,
                  "node_type": "function_declaration",
                  "sha256": "fb4e6d8bb0fa7c5c",
                  "line": 10
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
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": "q_72f952f4b9",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 14,
            "end_byte": 62,
            "node_type": "if_statement",
            "sha256": "213b8cfeb1c5aa2a",
            "line": 2
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_249d058a6e",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1019,
            "end_byte": 1308,
            "node_type": "if_statement",
            "sha256": "b71b7c1c59d073fd",
            "line": 17
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "rewrites the sibling package node-fetch-utils/package.json only when it is installed next to this one",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "modify_other_packages"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "./../../node-fetch-utils/package.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1039,
            "end_byte": 1308,
            "node_type": "statement_block",
            "sha256": "67f4a3a58804da4b",
            "line": 17
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 1246,
              "end_byte": 1297,
              "node_type": "call_expression",
              "sha256": "7f8654bf23da306c",
              "line": 22
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c1 && c3",
      "guards": [
        {
          "candidate": "q_72f952f4b9",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 14,
            "end_byte": 62,
            "node_type": "if_statement",
            "sha256": "213b8cfeb1c5aa2a",
            "line": 2
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_064317bf85",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1436,
            "end_byte": 1681,
            "node_type": "if_statement",
            "sha256": "907bdd94c24c0351",
            "line": 27
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "strips the install and postinstall scripts from its own package.json when that file exists, hiding the hook after the fact",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "./../package.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1456,
            "end_byte": 1681,
            "node_type": "statement_block",
            "sha256": "f6e17fc52138282f",
            "line": 27
          }
        ],
        "payload": [
          {
            "behaviour": "defense_evasion",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 1619,
              "end_byte": 1670,
              "node_type": "call_expression",
              "sha256": "3dda96e56c7fa9dc",
              "line": 30
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c1 && c4",
      "guards": [
        {
          "candidate": "q_72f952f4b9",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 14,
            "end_byte": 62,
            "node_type": "if_statement",
            "sha256": "213b8cfeb1c5aa2a",
            "line": 2
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
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1927,
            "end_byte": 1979,
            "node_type": "if_statement",
            "sha256": "99bc350d682a0ae7",
            "line": 40
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the stage is dropped and run only when the server returns a body of at least 16 bytes; otherwise the script tidies up and exits",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file",
          "exec_downloaded",
          "defense_evasion",
          "delete_file"
        ],
        "env_recipe": {
          "os": "win32",
          "network": {
            "node22[.]lunes[.]host:3258": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 1980,
            "end_byte": 2516,
            "node_type": "stmt_range",
            "sha256": "42d86def2fb14177",
            "line": 41
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 2125,
              "end_byte": 2145,
              "node_type": "call_expression",
              "sha256": "5fdbf743311f7989",
              "line": 43
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 2147,
              "end_byte": 2333,
              "node_type": "call_expression",
              "sha256": "f4154d88012426fd",
              "line": 44
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 2344,
              "end_byte": 2436,
              "node_type": "call_expression",
              "sha256": "aaaae249036ed6ce",
              "line": 45
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 2344,
              "end_byte": 2436,
              "node_type": "call_expression",
              "sha256": "aaaae249036ed6ce",
              "line": 45
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 2463,
              "end_byte": 2487,
              "node_type": "call_expression",
              "sha256": "e3528bef1427f126",
              "line": 48
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
      "download",
      "write_file",
      "modify_other_packages",
      "defense_evasion",
      "exec_downloaded",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "XOR 0x5A byte arrays hiding the C2 host, port and an unused key string",
      "minified one-letter identifiers",
      "self-deleting VBS launcher and self-deleting install script",
      "misleading text"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://node22.lunes[.]host:3258/nl",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the postinstall script downloads JavaScript from an XOR-hidden host, writes it to the temp folder and runs it hidden and detached through a dropped self-deleting VBS. It then strips its own install hooks from package.json and deletes itself to hide the install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: the comment above the node-fetch-utils/package.json block says it removes the postinstall entry, but the code rewrites the file unchanged",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44c82ac8af",
      "sha256": "7a90c3b0b70cc641"
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
    "condition_candidates": 3,
    "condition_sites_cited": 3,
    "guards_cited": 3,
    "candidates_dropped": 0,
    "conditions_in_set": 3,
    "conditions_out_of_set": 1,
    "guard_candidates": 3,
    "gates_in_set": 3,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c4",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
