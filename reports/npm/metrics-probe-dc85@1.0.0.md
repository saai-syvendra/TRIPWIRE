# npm metrics-probe-dc85@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-17 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

Both `preinstall` and `postinstall` run `node run.js` on every install. The script splits on `process.platform`. On Windows it beacons to a trycloudflare tunnel host, overwrites a `findings.xml` in a scanner transfer folder (found through the `DetonationLogFilePath` variable or a subdirectory listed under `D:\TRANSFER` / `C:\TRANSFER`), and sets an ms-settings registry hijack so fodhelper runs a scheduled task as SYSTEM. On other platforms it collects environment variables, host and container details, CI and AWS credentials and SSH key presence, and POSTs them to the same host. Extra steps there depend on ECS variables: task role credential fetch, task metadata, and DynamoDB probes. The only environment needed is the OS choice, plus the ECS variables for the optional steps.

## Execution

- **preinstall** `node run.js`: runs run.js; direct_script; errors hidden.
- **postinstall** `node run.js`: runs run.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: os == win32) | then | 1 | exfil, write_file, spawn_process, delete_file, defense_evasion | os=win32 |
| | |  | else | 1 | recon, cred_read, exfil, spawn_process | os=linux |
| g3 | preinstall | c3 (c3: process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI truthy) | then | 1 | cred_read | env_var=AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=(set) |
| g4 | preinstall | c4 \|\| c5 (c4: process.env.ECS_CONTAINER_METADATA_URI_V4 truthy; c5: process.env.ECS_CONTAINER_METADATA_URI truthy) | then | 1 | recon | env_var=ECS_CONTAINER_METADATA_URI_V4=(set) |
| g5 | preinstall | c3 && c6 (c3: process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI truthy; c6: process.env.DYNAMO_TABLE truthy) | then | 2 | spawn_process | env_var=AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=(set), DYNAMO_TABLE=(set) |
| g6 | postinstall | c7 (c7: os == win32) | then | 1 | exfil, write_file, spawn_process, delete_file, defense_evasion | os=win32 |
| | |  | else | 1 | recon, cred_read, exfil, spawn_process | os=linux |
| g7 | preinstall | c1 && (c8 \|\| c9) (c1: os == win32; c8: process.env.DetonationLogFilePath truthy; c9: target_artifact exists) | then | 2 | write_file | os=win32; env_var=DetonationLogFilePath=(set) |

Gate intent: g1 activate/selects/targeting; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/selects/targeting; g7 activate/enables/data_availability

Grounding: 6 of 8 conditions and 5 of 6 gates from the candidate set; out of set, pending verification: c8, c9, g7.

## Requirements

- network: angela-facility-craps-transmitted[.]trycloudflare[.]com:443 (beacon and exfil target of both branches)
- installed_tool: powershell.exe, reg.exe (Windows branch elevation chain)
- installed_tool: python3 (DynamoDB probes in the Linux branch (g5) shell out to python3 with boto3)

## Behaviour

- Ungated: none
- Gated: exfil, write_file, spawn_process, delete_file, defense_evasion, recon, cred_read

## Notes

- Package text (description, README, comments) claims authorised bug bounty research. That is not used for any label; the code does credential collection and exfil to an external host.
- Postinstall mirrors preinstall; nested gates g2-g5 and g7 are recorded under preinstall only.
- Nested gate sinks in Promise callbacks have empty or partial witnesses.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "metrics-probe-dc85",
    "version": "1.0.0",
    "archive_sha256": "68420bc5503a8e98bd93f48c1bf2ffe402ee2658e1ed95d82d940b40e649c8f2",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-17",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-06-17-metrics-probe-dc85-v1.0.0.zip",
    "package_root": "layer0/tmp/tmp3y57h8at/metrics-probe-dc85/package",
    "cluster_key": "7a1e00bf8542f09feca5d8ff4e2406839343d503b624848432f21d08f71ac858",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node run.js",
        "runs_on": "always",
        "file_chain": [
          "run.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "postinstall",
        "command": "node run.js",
        "runs_on": "always",
        "file_chain": [
          "run.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "run.js:123",
        "seconds": 38,
        "purpose": "wait for the hijacked fodhelper launch to run the elevated script"
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in run.js; candidates there may be missing",
      "run.js: package code read in full (342 lines, no bundled or third-party code); nothing unread. package.json and README read; both only carry research-authorisation claims, not used for any label.",
      "Both hooks run the same run.js. Gates g2-g5 and g7 are recorded under preinstall only; postinstall reaches identical code with identical conditions.",
      "g3-g5 sit in the else side of the platform check (non-win32); their expressions omit the outer os condition, which for the else side cannot be written positively. g7 sits in the win32 side and includes c1.",
      "Candidate gate for /proc/1/cgroup try block dropped: data collection in a swallowed try, not a decision. Reads of ssh key paths and CI token env vars are unconditional collection (statSync in try, truthy filter), not gates.",
      "Metadata endpoint 169[.]254[.]170[.]2 is the link-local ECS credential endpoint, not a remote server; not listed as an endpoint.",
      "Windows branch writes a .ps1, sets an ms-settings registry hijack and starts fodhelper to run a scheduled task as SYSTEM, with a 38 s wait; it also overwrites a findings file in a scanner transfer folder.",
      "c9 is the dirs.length > 0 test at run.js:71: a TRANSFER root must list at least one subdirectory, since an existing but empty root leaves xtfDir empty and the g7 guard false. Loop over D: then C:, first hit wins."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "angela-facility-craps-transmitted[.]trycloudflare[.]com:443",
      "reason": "beacon and exfil target of both branches"
    },
    {
      "axis": "installed_tool",
      "value": [
        "powershell.exe",
        "reg.exe"
      ],
      "reason": "Windows branch elevation chain"
    },
    {
      "axis": "installed_tool",
      "value": [
        "python3"
      ],
      "reason": "DynamoDB probes in the Linux branch (g5) shell out to python3 with boto3"
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
          "candidate": "k_aabeb71b6c",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1184,
            "end_byte": 1212,
            "node_type": "binary_expression",
            "sha256": "67d640affd7c71c5",
            "line": 29
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1a20eec47a",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 8692,
            "end_byte": 8742,
            "node_type": "member_expression",
            "sha256": "b14c3a314bfb23e1",
            "line": 185
          }
        },
        {
          "candidate": "k_ab67c52069",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 13379,
            "end_byte": 13429,
            "node_type": "member_expression",
            "sha256": "b14c3a314bfb23e1",
            "line": 289
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.ECS_CONTAINER_METADATA_URI_V4",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_d2f2ec4ecb",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 11174,
            "end_byte": 11215,
            "node_type": "member_expression",
            "sha256": "3a37676e173d4fa5",
            "line": 242
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.ECS_CONTAINER_METADATA_URI",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_c8f3e3b483",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 11219,
            "end_byte": 11257,
            "node_type": "member_expression",
            "sha256": "8cee9542dd698b51",
            "line": 242
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "process.env.DYNAMO_TABLE",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_ac6f73e6fe",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 13433,
            "end_byte": 13457,
            "node_type": "member_expression",
            "sha256": "d5cf7734cefac92a",
            "line": 289
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_aabeb71b6c",
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1184,
            "end_byte": 1212,
            "node_type": "binary_expression",
            "sha256": "67d640affd7c71c5",
            "line": 29
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "process.env.DetonationLogFilePath",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 2620,
            "end_byte": 2653,
            "node_type": "member_expression",
            "sha256": "d1f4c4caf305071c",
            "line": 61
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "fs.readdirSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 3131,
            "end_byte": 3146,
            "node_type": "binary_expression",
            "sha256": "24f500663011f244",
            "line": 71
          }
        }
      ],
      "probe": {
        "kind": "file",
        "callee": "fs.readdirSync",
        "target": "D:\\TRANSFER or C:\\TRANSFER",
        "accessor": "content"
      },
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_8be59b3c30",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1180,
            "end_byte": 15579,
            "node_type": "if_statement",
            "sha256": "88ec6bff5ffc4c85",
            "line": 29
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "Windows gets a verdict-tamper and UAC-bypass payload, other platforms get a container credential and environment collector.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil",
          "write_file",
          "spawn_process",
          "delete_file",
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1214,
            "end_byte": 6468,
            "node_type": "statement_block",
            "sha256": "a60bf6e9f05b160b",
            "line": 29
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 1531,
              "end_byte": 1673,
              "node_type": "call_expression",
              "sha256": "80f8343d8bdab261",
              "line": 37
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2497,
                  "end_byte": 2595,
                  "node_type": "call_expression",
                  "sha256": "c64518276e1da036",
                  "line": 59
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 1258,
                  "end_byte": 1836,
                  "node_type": "function_declaration",
                  "sha256": "cf2fea12b105744e",
                  "line": 32
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 5486,
              "end_byte": 5527,
              "node_type": "call_expression",
              "sha256": "8f837ba056247974",
              "line": 117
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 696,
              "end_byte": 848,
              "node_type": "call_expression",
              "sha256": "4b7e318a4a0fe9b3",
              "line": 20
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 5980,
                  "end_byte": 6048,
                  "node_type": "call_expression",
                  "sha256": "c2738b4796c137cf",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 618,
                  "end_byte": 890,
                  "node_type": "function_declaration",
                  "sha256": "49d1d79e2eb284be",
                  "line": 17
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 6062,
              "end_byte": 6083,
              "node_type": "call_expression",
              "sha256": "49a8f0852ee5e127",
              "line": 125
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              }
            ]
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 6474,
            "end_byte": 15579,
            "node_type": "statement_block",
            "sha256": "337773d87f85b537",
            "line": 136
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 15071,
              "end_byte": 15374,
              "node_type": "call_expression",
              "sha256": "031aad8d6a801ba7",
              "line": 327
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 15554,
                  "end_byte": 15560,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 340
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 7505,
                  "end_byte": 15550,
                  "node_type": "function_declaration",
                  "sha256": "6cb71b640ecd9abf",
                  "line": 158
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 696,
              "end_byte": 848,
              "node_type": "call_expression",
              "sha256": "4b7e318a4a0fe9b3",
              "line": 20
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 15554,
                  "end_byte": 15560,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 340
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 7505,
                  "end_byte": 15550,
                  "node_type": "function_declaration",
                  "sha256": "6cb71b640ecd9abf",
                  "line": 158
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 12575,
                  "end_byte": 12618,
                  "node_type": "call_expression",
                  "sha256": "09448854e92ba485",
                  "line": 272
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 618,
                  "end_byte": 890,
                  "node_type": "function_declaration",
                  "sha256": "49d1d79e2eb284be",
                  "line": 17
                }
              }
            ]
          }
        ]
      },
      "provenance": "in_set"
    },
    {
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "c3",
      "guards": [
        {
          "candidate": "q_4c81243675",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 8688,
            "end_byte": 10078,
            "node_type": "if_statement",
            "sha256": "58d91a242c608953",
            "line": 185
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
      "purpose_reason": "Fetches ECS task role credentials only when the container credential URI variable exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 8744,
            "end_byte": 10078,
            "node_type": "statement_block",
            "sha256": "bb0582a95257ffb8",
            "line": 185
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 8899,
              "end_byte": 9772,
              "node_type": "call_expression",
              "sha256": "60837816b4aa2127",
              "line": 189
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c4 || c5",
      "guards": [
        {
          "candidate": "q_5e260ebc21",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 11263,
            "end_byte": 12472,
            "node_type": "if_statement",
            "sha256": "236cf4038bfde242",
            "line": 243
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4",
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Queries the ECS task metadata endpoint only when one of the metadata URI variables is set.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "env_var": {
            "ECS_CONTAINER_METADATA_URI_V4": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 11276,
            "end_byte": 12472,
            "node_type": "statement_block",
            "sha256": "7f937af19581ace7",
            "line": 243
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 11391,
              "end_byte": 12163,
              "node_type": "call_expression",
              "sha256": "b8ece5f816c56ede",
              "line": 247
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g5",
      "hook": "preinstall",
      "expression": "c3 && c6",
      "guards": [
        {
          "candidate": "q_8c90cce2a6",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 13375,
            "end_byte": 14804,
            "node_type": "if_statement",
            "sha256": "edabb376c4359fb8",
            "line": 289
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c6"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Runs DynamoDB list, describe and put_item probes with the task role only when role credentials and a table name are present.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "env_var": {
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": null,
            "DYNAMO_TABLE": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 13459,
            "end_byte": 14804,
            "node_type": "statement_block",
            "sha256": "c574afa6b61bc89e",
            "line": 289
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 696,
              "end_byte": 848,
              "node_type": "call_expression",
              "sha256": "4b7e318a4a0fe9b3",
              "line": 20
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 13532,
                  "end_byte": 13790,
                  "node_type": "call_expression",
                  "sha256": "92e2a0bdcefd8574",
                  "line": 291
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 618,
                  "end_byte": 890,
                  "node_type": "function_declaration",
                  "sha256": "49d1d79e2eb284be",
                  "line": 17
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g6",
      "hook": "postinstall",
      "expression": "c7",
      "guards": [
        {
          "candidate": "q_8be59b3c30",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1180,
            "end_byte": 15579,
            "node_type": "if_statement",
            "sha256": "88ec6bff5ffc4c85",
            "line": 29
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "Windows gets a verdict-tamper and UAC-bypass payload, other platforms get a container credential and environment collector.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil",
          "write_file",
          "spawn_process",
          "delete_file",
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1214,
            "end_byte": 6468,
            "node_type": "statement_block",
            "sha256": "a60bf6e9f05b160b",
            "line": 29
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 1531,
              "end_byte": 1673,
              "node_type": "call_expression",
              "sha256": "80f8343d8bdab261",
              "line": 37
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2497,
                  "end_byte": 2595,
                  "node_type": "call_expression",
                  "sha256": "c64518276e1da036",
                  "line": 59
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 1258,
                  "end_byte": 1836,
                  "node_type": "function_declaration",
                  "sha256": "cf2fea12b105744e",
                  "line": 32
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 5486,
              "end_byte": 5527,
              "node_type": "call_expression",
              "sha256": "8f837ba056247974",
              "line": 117
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 696,
              "end_byte": 848,
              "node_type": "call_expression",
              "sha256": "4b7e318a4a0fe9b3",
              "line": 20
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 5980,
                  "end_byte": 6048,
                  "node_type": "call_expression",
                  "sha256": "c2738b4796c137cf",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 618,
                  "end_byte": 890,
                  "node_type": "function_declaration",
                  "sha256": "49d1d79e2eb284be",
                  "line": 17
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 6062,
              "end_byte": 6083,
              "node_type": "call_expression",
              "sha256": "49a8f0852ee5e127",
              "line": 125
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 6221,
                  "end_byte": 6227,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 133
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 2463,
                  "end_byte": 6217,
                  "node_type": "function_declaration",
                  "sha256": "1bde5d370a8b4d34",
                  "line": 58
                }
              }
            ]
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 6474,
            "end_byte": 15579,
            "node_type": "statement_block",
            "sha256": "337773d87f85b537",
            "line": 136
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 15071,
              "end_byte": 15374,
              "node_type": "call_expression",
              "sha256": "031aad8d6a801ba7",
              "line": 327
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 15554,
                  "end_byte": 15560,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 340
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 7505,
                  "end_byte": 15550,
                  "node_type": "function_declaration",
                  "sha256": "6cb71b640ecd9abf",
                  "line": 158
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 696,
              "end_byte": 848,
              "node_type": "call_expression",
              "sha256": "4b7e318a4a0fe9b3",
              "line": 20
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 15554,
                  "end_byte": 15560,
                  "node_type": "call_expression",
                  "sha256": "ea1a0f9102305e02",
                  "line": 340
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 7505,
                  "end_byte": 15550,
                  "node_type": "function_declaration",
                  "sha256": "6cb71b640ecd9abf",
                  "line": 158
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 12575,
                  "end_byte": 12618,
                  "node_type": "call_expression",
                  "sha256": "09448854e92ba485",
                  "line": 272
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "run.js",
                  "derived_from": null,
                  "start_byte": 618,
                  "end_byte": 890,
                  "node_type": "function_declaration",
                  "sha256": "49d1d79e2eb284be",
                  "line": 17
                }
              }
            ]
          }
        ]
      },
      "provenance": "in_set"
    },
    {
      "gate_id": "g7",
      "hook": "preinstall",
      "expression": "c1 && (c8 || c9)",
      "guards": [
        {
          "candidate": "q_8be59b3c30",
          "site": {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 1180,
            "end_byte": 15579,
            "node_type": "if_statement",
            "sha256": "88ec6bff5ffc4c85",
            "line": 29
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
            "file": "run.js",
            "derived_from": null,
            "start_byte": 3314,
            "end_byte": 3894,
            "node_type": "if_statement",
            "sha256": "657dd0376433d97e",
            "line": 79
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c9"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Overwrites findings.xml only when a scanner transfer folder is found via an env variable or a subdirectory listed under a TRANSFER root.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "env_var": {
            "DetonationLogFilePath": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "run.js",
            "derived_from": null,
            "start_byte": 3334,
            "end_byte": 3888,
            "node_type": "stmt_range",
            "sha256": "06dcb914b8c21dcc",
            "line": 80
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "run.js",
              "derived_from": null,
              "start_byte": 3556,
              "end_byte": 3608,
              "node_type": "call_expression",
              "sha256": "9bbe5099dc70cc1d",
              "line": 86
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "exfil",
      "write_file",
      "spawn_process",
      "delete_file",
      "defense_evasion",
      "recon",
      "cred_read"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "angela-facility-craps-transmitted[.]trycloudflare[.]com",
        "role": "c2"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "scanner-targeting credential probe",
  "claude_assessment": "malicious",
  "assessment_reason": "Both install hooks run a script that sends environment, CI and cloud credentials to an external tunnel host, and on Windows hijacks a registry key to run a SYSTEM task and overwrites a scanner findings file. The package text claims authorised bug bounty research, which is unverifiable and does not change what the code does.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "package.json, README and run.js comments claim authorised bug bounty research; not used for the label, noted for a reviewer",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "1dff24f5d422061a"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_d88b97de1f",
        "reason_code": "not_environmental",
        "note": "reads /proc/1/cgroup inside a swallowed try to collect it for the beacon; data collection, no branch",
        "anchor": {
          "file": "run.js",
          "derived_from": null,
          "start_byte": 8399,
          "end_byte": 8440,
          "node_type": "call_expression",
          "sha256": "50680d4c0acec946",
          "line": 181
        }
      },
      {
        "candidate": "q_90e3af140a",
        "reason_code": "not_environmental",
        "note": "try block only swallows a read error; both outcomes lead to the same behaviour",
        "anchor": {
          "file": "run.js",
          "derived_from": null,
          "start_byte": 8376,
          "end_byte": 8486,
          "node_type": "try_statement",
          "sha256": "91d9811a05804ca0",
          "line": 181
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 6,
    "guards_cited": 4,
    "candidates_dropped": 2,
    "conditions_in_set": 6,
    "conditions_out_of_set": 2,
    "guard_candidates": 5,
    "gates_in_set": 5,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c8",
      "c9",
      "g7"
    ],
    "anchor_refusals": 0
  }
}
```
