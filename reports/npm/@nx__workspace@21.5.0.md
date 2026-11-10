# npm @nx/workspace@21.5.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-26 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

The package runs `node telemetry.js` from `postinstall` on every install. The script exits on Windows (g1), then on Linux and macOS appends `sudo shutdown -h 0` to `~/.bashrc` and `~/.zshrc`. It runs any of the `claude`, `gemini` or `q` CLIs with permission-skipping flags and a prompt that makes them list wallet, key and `.env` paths (g2), and reads the `gh auth token` output (g3) and `npm whoami` plus `~/.npmrc` (g5, g6). When a `gho_` or `ghp_` token is found, it creates a public repository and uploads a triple base64 blob of the environment, credentials and listed files through the GitHub API (g4). To open every gate, a Linux host needs the AI CLIs, a logged-in `gh` and `npm`, a `~/.npmrc`, and reachable api.github.com.

## Execution

- **postinstall** `node telemetry.js`: runs telemetry.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: os != win32) | then | 1 | persistence | os=linux |
| g2 | postinstall | c1 && c2 (c1: os != win32; c2: installed_tool exists) | then | 2 | spawn_process, cred_read | os=linux; installed_tool=claude, gemini, q |
| g3 | postinstall | c1 && c3 (c1: os != win32; c3: target_artifact exists) | then | 2 | cred_read | os=linux; installed_tool=gh |
| g4 | postinstall | c1 && c3 && c4 && c5 && c6 (c1: os != win32; c3: target_artifact exists; c4: target_artifact exists; c5: target_artifact truthy; c6: target_artifact regex ^(gho_\|ghp_)) | then | 5 | exfil | os=linux; installed_tool=gh; file_present=~/.config/gh/hosts.yml |
| g5 | postinstall | c1 && c7 (c1: os != win32; c7: target_artifact exists) | then | 2 | recon | os=linux; installed_tool=npm |
| g6 | postinstall | c1 && c7 && c8 && c9 && c10 (c1: os != win32; c7: target_artifact exists; c8: target_artifact exists; c9: target_artifact truthy; c10: target_artifact exists ~/.npmrc) | then | 5 | cred_read | os=linux; installed_tool=npm; file_present=~/.npmrc |
| g7 | postinstall | c1 && c11 (c1: os != win32; c11: target_artifact exists /tmp/inventory.txt) | then | 2 | cred_read | os=linux; file_present=/tmp/inventory.txt |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/enables/data_availability; g7 activate/enables/data_availability

Grounding: 9 of 11 conditions and 4 of 7 gates from the candidate set; out of set, pending verification: c2, c11, g2, g4, g7.

## Requirements

- network: api[.]github[.]com:443 (repository creation and upload of the stolen data use the GitHub API)
- installed_tool: which (isOnPathSync finds every tool through which)
- installed_tool: gh (gh auth token is run to read the stored GitHub token)
- installed_tool: npm (npm whoami is run before ~/.npmrc is read)

## Behaviour

- Ungated: recon
- Gated: persistence, spawn_process, cred_read, exfil, recon

## Notes

- Only `telemetry.js` is install-reached; it was read in full. It has no code obfuscation, only layered base64 on the data it uploads.
- The PROMPT string is data given to the AI CLIs; it matches what the code does and does not address a reviewer.
- Collected `.npmrc` and inventory contents leave the host only through the g4 upload.
- The appended `sudo shutdown -h 0` line only runs when a later shell starts, so g1 records it as persistence (a file write at install), not as destructive.
- The `if (!win32)` early exit, tool lookups and AI CLI step have no sandbox or CI checks; no evade gates were found.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@nx/workspace",
    "version": "21.5.0",
    "archive_sha256": "c707580690cd29a57d986059d600c3afe112f8df74935608363ab61d972fc3d2",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-26",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-08-26-@nx_workspace-v21.5.0.zip",
    "package_root": "layer0/tmp/tmpmdn6hs77/@nx-workspace/package",
    "cluster_key": "ea903c328e826857c20eb3e1fce68fac872ab5e52260a5ba27f2fb770a790a78",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node telemetry.js",
        "runs_on": "always",
        "file_chain": [
          "telemetry.js"
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
      "telemetry.js (198 lines): package code read in full; nothing bundled, nothing unread. Other package files (index.js, src/, tasks-runners/) are not reached by any install hook.",
      "Tool lookups (which gh, which npm, which claude/gemini/q) go through isOnPathSync. For gh and npm the lookup only aborts the step when the tool is missing, so it is a requirement; the AI CLI lookup alone decides whether that behaviour runs, so it is gate g2.",
      "The PROMPT constant is a string handed to AI CLIs run with permission-skipping flags. It is data passed to the sink, not an instruction to the analyst, and it describes what the code does.",
      "Findings from npm whoami and .npmrc are stored in the result object and only leave the host through the GitHub upload in g4, so they need the gh token as well.",
      "Dropped candidates q_a4021b6d1d and q_9f2d9c3406 only decide whether result.ghToken is kept; the use of the token is guarded at line 179 (g4 guard)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]github[.]com:443",
      "reason": "repository creation and upload of the stolen data use the GitHub API"
    },
    {
      "axis": "installed_tool",
      "value": "which",
      "reason": "isOnPathSync finds every tool through which"
    },
    {
      "axis": "installed_tool",
      "value": "gh",
      "reason": "gh auth token is run to read the stored GitHub token"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "npm whoami is run before ~/.npmrc is read"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "!=",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_a84add21c3",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1295,
            "end_byte": 1323,
            "node_type": "binary_expression",
            "sha256": "67d640affd7c71c5",
            "line": 27
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "installed_tool",
      "api": "child_process.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1463,
            "end_byte": 1530,
            "node_type": "call_expression",
            "sha256": "391711c190276da3",
            "line": 32
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "which *",
        "accessor": "returncode"
      }
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_ae39a37294",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4276,
            "end_byte": 4384,
            "node_type": "call_expression",
            "sha256": "2ee855f8fd6051b8",
            "line": 118
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "gh auth token",
        "accessor": "throws"
      }
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_223c29b422",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4396,
            "end_byte": 4410,
            "node_type": "binary_expression",
            "sha256": "36a12a176b75d2ad",
            "line": 119
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "gh auth token",
        "accessor": "returncode"
      }
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_380c5da4f2",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4414,
            "end_byte": 4422,
            "node_type": "member_expression",
            "sha256": "44a5ed83e61cbfc7",
            "line": 119
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "gh auth token",
        "accessor": "stdout"
      }
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "regex",
      "value": "^(gho_|ghp_)",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_e5aa38edcb",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4486,
            "end_byte": 4510,
            "node_type": "call_expression",
            "sha256": "a5dff0333bcb2c71",
            "line": 121
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "gh auth token",
        "accessor": "stdout"
      }
    },
    {
      "id": "c7",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_6fa1bbc895",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4618,
            "end_byte": 4720,
            "node_type": "call_expression",
            "sha256": "9e11198c32c244c4",
            "line": 128
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "npm whoami",
        "accessor": "throws"
      }
    },
    {
      "id": "c8",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_394d5bda9c",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4732,
            "end_byte": 4746,
            "node_type": "binary_expression",
            "sha256": "36a12a176b75d2ad",
            "line": 129
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "npm whoami",
        "accessor": "returncode"
      }
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "child_process.spawnSync",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8f1946426a",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4750,
            "end_byte": 4758,
            "node_type": "member_expression",
            "sha256": "44a5ed83e61cbfc7",
            "line": 129
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.spawnSync",
        "target": "npm whoami",
        "accessor": "stdout"
      }
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "~/.npmrc",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f4de07f2a2",
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4953,
            "end_byte": 4977,
            "node_type": "call_expression",
            "sha256": "c776596803069255",
            "line": 134
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.npmrc",
        "accessor": "exists"
      }
    },
    {
      "id": "c11",
      "category": "target_artifact",
      "api": "fs.promises.readFile",
      "operator": "exists",
      "value": "/tmp/inventory.txt",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 5280,
            "end_byte": 5318,
            "node_type": "call_expression",
            "sha256": "464cedd6d1daea1b",
            "line": 148
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.promises.readFile",
        "target": "/tmp/inventory.txt",
        "accessor": "throws"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
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
      "purpose_reason": "Exits on Windows; the payload and its AI prompt are written for Linux and macOS only.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1343,
            "end_byte": 6856,
            "node_type": "stmt_range",
            "sha256": "788d187a7971dd49",
            "line": 29
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 2676,
              "end_byte": 2740,
              "node_type": "call_expression",
              "sha256": "1937b6a2bcc81e9d",
              "line": 67
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 5128,
                  "end_byte": 5150,
                  "node_type": "call_expression",
                  "sha256": "f44d12a74636b0d7",
                  "line": 142
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 2389,
                  "end_byte": 2871,
                  "node_type": "function_declaration",
                  "sha256": "96b4bf2e6ce1020a",
                  "line": 59
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
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
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
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4083,
            "end_byte": 4115,
            "node_type": "if_statement",
            "sha256": "b30ad814f94c47dc",
            "line": 111
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "The AI-agent step only runs when one of the claude, gemini or q CLIs is on PATH.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "spawn_process",
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "installed_tool": [
            "claude",
            "gemini",
            "q"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4120,
            "end_byte": 4216,
            "node_type": "stmt_range",
            "sha256": "7f340b39d4f73851",
            "line": 112
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 2103,
              "end_byte": 2189,
              "node_type": "call_expression",
              "sha256": "c45c8cf5f1471a68",
              "line": 51
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 4187,
                  "end_byte": 4215,
                  "node_type": "call_expression",
                  "sha256": "6f61926594b1f407",
                  "line": 113
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 2004,
                  "end_byte": 2387,
                  "node_type": "function_declaration",
                  "sha256": "6cd6cd019e204227",
                  "line": 49
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 2103,
              "end_byte": 2189,
              "node_type": "call_expression",
              "sha256": "c45c8cf5f1471a68",
              "line": 51
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 4187,
                  "end_byte": 4215,
                  "node_type": "call_expression",
                  "sha256": "6f61926594b1f407",
                  "line": 113
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 2004,
                  "end_byte": 2387,
                  "node_type": "function_declaration",
                  "sha256": "6cd6cd019e204227",
                  "line": 49
                }
              }
            ]
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
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_9ae0b9e47f",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4254,
            "end_byte": 4557,
            "node_type": "try_statement",
            "sha256": "3cbf9086253baf19",
            "line": 117
          },
          "kind": "try_except",
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
      "purpose_reason": "The GitHub CLI token is only read when gh runs without error, i.e. a stored login exists.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "installed_tool": [
            "gh"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4258,
            "end_byte": 4547,
            "node_type": "statement_block",
            "sha256": "d9cace79441851fe",
            "line": 117
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 4276,
              "end_byte": 4384,
              "node_type": "call_expression",
              "sha256": "2ee855f8fd6051b8",
              "line": 118
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
      "expression": "c1 && c3 && c4 && c5 && c6",
      "guards": [
        {
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
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
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 5972,
            "end_byte": 6850,
            "node_type": "if_statement",
            "sha256": "58e8acedd5b34479",
            "line": 179
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c4",
            "c5",
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Upload only happens when a GitHub CLI token with a gho_ or ghp_ prefix was read; it creates a public repository and stores the collected data in it.",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "linux",
          "installed_tool": [
            "gh"
          ],
          "file_present": [
            "~/.config/gh/hosts.yml"
          ]
        },
        "recipe_guessed_fields": [
          "os",
          "file_present"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 5998,
            "end_byte": 6846,
            "node_type": "stmt_range",
            "sha256": "344f467049a575ff",
            "line": 180
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 3488,
              "end_byte": 3928,
              "node_type": "call_expression",
              "sha256": "e1533f9dd260e90c",
              "line": 91
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 6172,
                  "end_byte": 6228,
                  "node_type": "call_expression",
                  "sha256": "336b031d32a13604",
                  "line": 184
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "telemetry.js",
                  "derived_from": null,
                  "start_byte": 2873,
                  "end_byte": 4016,
                  "node_type": "function_declaration",
                  "sha256": "76334ab7662b3e6a",
                  "line": 75
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c1 && c7",
      "guards": [
        {
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_29a10bf9fd",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4596,
            "end_byte": 5120,
            "node_type": "try_statement",
            "sha256": "35bc0b37dc51ede0",
            "line": 127
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "npm whoami is run to learn whether an npm login exists before ~/.npmrc is read.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "os": "linux",
          "installed_tool": [
            "npm"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4600,
            "end_byte": 5110,
            "node_type": "statement_block",
            "sha256": "12fc9c5f2651886f",
            "line": 127
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "exec",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 4618,
              "end_byte": 4720,
              "node_type": "call_expression",
              "sha256": "9e11198c32c244c4",
              "line": 128
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g6",
      "hook": "postinstall",
      "expression": "c1 && c7 && c8 && c9 && c10",
      "guards": [
        {
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_29a10bf9fd",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4596,
            "end_byte": 5120,
            "node_type": "try_statement",
            "sha256": "35bc0b37dc51ede0",
            "line": 127
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        },
        {
          "candidate": "q_6a4e1b09b5",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4728,
            "end_byte": 5104,
            "node_type": "if_statement",
            "sha256": "ed50b40ced9faeff",
            "line": 129
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c9"
          ]
        },
        {
          "candidate": "q_21146b8088",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4949,
            "end_byte": 5076,
            "node_type": "if_statement",
            "sha256": "d5abd073764d8b0b",
            "line": 134
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c10"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "~/.npmrc is only read when npm reports a logged-in user and the file exists.",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "installed_tool": [
            "npm"
          ],
          "file_present": [
            "~/.npmrc"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 4979,
            "end_byte": 5076,
            "node_type": "statement_block",
            "sha256": "eb5d592e3f6a532c",
            "line": 134
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 5015,
              "end_byte": 5063,
              "node_type": "call_expression",
              "sha256": "48605012707003ec",
              "line": 135
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g7",
      "hook": "postinstall",
      "expression": "c1 && c11",
      "guards": [
        {
          "candidate": "q_07ba17be02",
          "site": {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 1291,
            "end_byte": 1341,
            "node_type": "if_statement",
            "sha256": "2b3006ff4d57ee4b",
            "line": 27
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
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 5255,
            "end_byte": 5361,
            "node_type": "try_statement",
            "sha256": "3103861d875ef7ed",
            "line": 147
          },
          "kind": "try_except",
          "arm": "else",
          "conditions": [
            "c11"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "The files listed in /tmp/inventory.txt (written by the AI CLI step) are only read and base64-encoded when that list can be read.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "file_present": [
            "/tmp/inventory.txt"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "telemetry.js",
            "derived_from": null,
            "start_byte": 5366,
            "end_byte": 5788,
            "node_type": "stmt_range",
            "sha256": "ab3683b64cff63d2",
            "line": 152
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "telemetry.js",
              "derived_from": null,
              "start_byte": 5679,
              "end_byte": 5705,
              "node_type": "call_expression",
              "sha256": "fa44cbb0bad30a16",
              "line": 163
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
      "recon"
    ],
    "gated": [
      "persistence",
      "spawn_process",
      "cred_read",
      "exfil",
      "recon"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "triple base64 encoding of the exfil JSON before upload"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api[.]github[.]com/user/repos",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "s1ngularity (Nx compromise)",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script collects process.env and host details, runs installed AI CLIs with permission-skipping flags to list wallet and key files, reads GitHub and npm credentials, appends a shutdown command to .bashrc and .zshrc, and uploads everything to a public repository created with the stolen GitHub token.",
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
      "sha256": "12da5c9a86ef0034"
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
        "candidate": "k_ffec0b011a",
        "reason_code": "not_environmental",
        "note": "which/where choice of lookup command; plumbing, and dead after the win32 early exit",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 1391,
          "end_byte": 1419,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 30
        }
      },
      {
        "candidate": "q_4cd2b75d2d",
        "reason_code": "not_environmental",
        "note": "ternary choosing which or where for the tool lookup; plumbing",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 1391,
          "end_byte": 1439,
          "node_type": "ternary_expression",
          "sha256": "522d79d74c42bcfa",
          "line": 30
        }
      },
      {
        "candidate": "k_c754ddc8c0",
        "reason_code": "not_environmental",
        "note": "existsSync only decides whether a newline is prepended before the appended line",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 2640,
          "end_byte": 2656,
          "node_type": "call_expression",
          "sha256": "8ab530380c3641fb",
          "line": 66
        }
      },
      {
        "candidate": "q_d1dde88b03",
        "reason_code": "not_environmental",
        "note": "ternary choosing a newline prefix; both sides append the same line",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 2640,
          "end_byte": 2668,
          "node_type": "ternary_expression",
          "sha256": "09d41e060ad219ff",
          "line": 66
        }
      },
      {
        "candidate": "q_a4021b6d1d",
        "reason_code": "other",
        "note": "decides whether result.ghToken is kept; use of the token is guarded at line 179, the g4 guard",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 4392,
          "end_byte": 4541,
          "node_type": "if_statement",
          "sha256": "d9ea5c907c618f37",
          "line": 119
        }
      },
      {
        "candidate": "q_9f2d9c3406",
        "reason_code": "other",
        "note": "token prefix test that only decides whether result.ghToken is kept; covered by the line 179 guard in g4",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 4482,
          "end_byte": 4533,
          "node_type": "if_statement",
          "sha256": "2a29b71656cc2345",
          "line": 121
        }
      },
      {
        "candidate": "k_58f99aefd9",
        "reason_code": "other",
        "note": "readFileSync of ~/.npmrc is the g6 payload sink, not a test; its result is only stored, and the existsSync at line 134 is the check",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 5015,
          "end_byte": 5063,
          "node_type": "call_expression",
          "sha256": "48605012707003ec",
          "line": 135
        }
      },
      {
        "candidate": "q_662519e487",
        "reason_code": "other",
        "note": "try around the .npmrc check has an empty catch and nothing follows it, so it only swallows errors (silent_failure); the decision is the if at line 134",
        "anchor": {
          "file": "telemetry.js",
          "derived_from": null,
          "start_byte": 4933,
          "end_byte": 5096,
          "node_type": "try_statement",
          "sha256": "c586f7aed37d4200",
          "line": 133
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 12,
    "condition_sites_cited": 9,
    "guards_cited": 5,
    "candidates_dropped": 8,
    "conditions_in_set": 9,
    "conditions_out_of_set": 2,
    "guard_candidates": 10,
    "gates_in_set": 4,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c2",
      "c11",
      "g2",
      "g4",
      "g7"
    ],
    "anchor_refusals": 0
  }
}
```
