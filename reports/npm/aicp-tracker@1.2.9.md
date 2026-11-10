# npm aicp-tracker@1.2.9

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-08 (registry) · **Assessment:** benign (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node bin/setup.js`. It exits at once when `CI` or `npm_config_yes` is set. Otherwise, because `npm_lifecycle_event` is `postinstall`, it enters a block that, when `INIT_CWD` is set, writes the install directory into `~/.aicp-tracker/config.json` (merging any existing config) and then always calls `process.exit(0)`. One gate (`c1 && c2 && c3 && c4`) guards that local file write, and any normal non-CI npm install opens it. The setup wizard, the registration with a duckdns host, the per-OS login auto-start and the Claude Code log upload are never reached at install.

## Execution

- **postinstall** `node bin/setup.js`: 2-file chain; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 && c4 (c1: process.env.CI falsy; c2: process.env.npm_config_yes falsy; c3: process.env.npm_lifecycle_event == postinstall; c4: process.env.INIT_CWD truthy) | then | 4 | write_file | env_var_absent=CI, npm_config_yes; env_var=npm_lifecycle_event=postinstall, INIT_CWD=(set) |

Gate intent: g1 evade/enables/portability

Grounding: 4 of 4 conditions and 1 of 1 gates from the candidate set.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: write_file

## Notes

- The `main()` call at setup.js:203 looks like it runs on postinstall, but the earlier `process.exit(0)` at line 26 or 30 always ends the process first.
- The runtime code (bin command `aicp-tracker start` / `setup`) reads `~/.claude/projects` session logs and posts usage records, including file paths and git branches, to hxxps://aicp-tracker[.]duckdns[.]org, and installs auto-start entries (Startup folder .cmd, LaunchAgent, systemd user unit). That is probably why the package is labelled malicious, but none of it runs at install.
- The CI skip may be an ordinary non-interactive skip rather than deliberate evasion; it is recorded as evade/anti_analysis because it hides the install step from CI-based scanners.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "aicp-tracker",
    "version": "1.2.9",
    "archive_sha256": "69f07b17dc085678c06da0d033ac4bd728ce25b83eedc9d7eaf4b27ba0760db0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-08",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-05-08-aicp-tracker-v1.2.9.zip",
    "package_root": "layer0/tmp/tmp11nq5i_9/aicp-tracker/package",
    "cluster_key": "76c8b4b97c0c00694146c4276fd2ae97d4b4e43a94f9ac405c668a8367b28620",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node bin/setup.js",
        "runs_on": "always",
        "file_chain": [
          "bin/setup.js",
          "src/config.js"
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
      "bin commands not analysed (run only when invoked): aicp-tracker",
      "bin/setup.js and src/config.js read in full. Under postinstall the block at setup.js:11 always ends in process.exit(0) (line 26 or 30), so lines 35-207 (wizard, registration, auto-start, daemon start) never run at install.",
      "bin/aicp-tracker.js read in full: it is the bin command; setup.js only names it as the target of a login auto-start entry written by installAutoStart(), which runs only from the setup wizard. Not run at install.",
      "src/daemon.js, daemon-worker.js, log-scanner.js, log-parser.js, wal.js, sender.js, state.js are never loaded at install (only required after line 35 or by the bin command). Removed from file_chain; the generator truncation note concerns those files plus config.js, which was read in full.",
      "Outside install (bin command / wizard): reads Claude Code session logs under ~/.claude/projects and POSTs usage records (models, tokens, file paths, git branches) with the user's email to hxxps://aicp-tracker[.]duckdns[.]org, and adds a login auto-start entry per OS.",
      "c3 (npm_lifecycle_event == postinstall) is always true when npm runs this hook, so the else side of setup.js:11 is dead at install; the call of main() at line 203 is unreachable because of the earlier process.exit.",
      "The postinstall step records INIT_CWD (the directory where npm install was run) into ~/.aicp-tracker/config.json, merging any existing config. Errors are swallowed by an empty catch."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_6bad810693",
          "anchor": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 107,
            "end_byte": 121,
            "node_type": "member_expression",
            "sha256": "b6be09f9287c0ede",
            "line": 5
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "package_manager",
      "api": "process.env.npm_config_yes",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_df8d032bf0",
          "anchor": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 125,
            "end_byte": 151,
            "node_type": "member_expression",
            "sha256": "d92b0704b481476d",
            "line": 5
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "package_manager",
      "api": "process.env.npm_lifecycle_event",
      "operator": "==",
      "value": "postinstall",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_bae6f30d5c",
          "anchor": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 297,
            "end_byte": 346,
            "node_type": "binary_expression",
            "sha256": "13349cb3954dab33",
            "line": 10
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "package_manager",
      "api": "process.env.INIT_CWD",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_76e227520d",
          "anchor": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 659,
            "end_byte": 670,
            "node_type": "identifier",
            "sha256": "2d16def9ea9dc4f2",
            "line": 17
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1 && c2 && c3 && c4",
      "guards": [
        {
          "candidate": "q_8b0831ddea",
          "site": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 103,
            "end_byte": 169,
            "node_type": "if_statement",
            "sha256": "2c61083c11d965e2",
            "line": 5
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2"
          ]
        },
        {
          "candidate": "q_dc7fafc20e",
          "site": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 348,
            "end_byte": 1151,
            "node_type": "if_statement",
            "sha256": "d60dac2f2cc15766",
            "line": 11
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": "q_bac6498aed",
          "site": {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 655,
            "end_byte": 819,
            "node_type": "if_statement",
            "sha256": "422c46033377f7ec",
            "line": 17
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "Skips the postinstall in CI or non-interactive (npm_config_yes) installs and otherwise records INIT_CWD into the tool's own config; nothing harmful is hidden, it adapts to the install mode.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "CI",
            "npm_config_yes"
          ],
          "env_var": {
            "npm_lifecycle_event": "postinstall",
            "INIT_CWD": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/setup.js",
            "derived_from": null,
            "start_byte": 672,
            "end_byte": 819,
            "node_type": "statement_block",
            "sha256": "58efd639ff47d7f8",
            "line": 17
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "src/config.js",
              "derived_from": null,
              "start_byte": 496,
              "end_byte": 563,
              "node_type": "call_expression",
              "sha256": "d68e891b79c91d49",
              "line": 21
            },
            "witness": [
              {
                "hop": "import",
                "anchor": {
                  "file": "bin/setup.js",
                  "derived_from": null,
                  "start_byte": 695,
                  "end_byte": 719,
                  "node_type": "call_expression",
                  "sha256": "2e1bb70c7b6e645e",
                  "line": 18
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bin/setup.js",
                  "derived_from": null,
                  "start_byte": 771,
                  "end_byte": 812,
                  "node_type": "call_expression",
                  "sha256": "fccf3f516deb5869",
                  "line": 20
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "src/config.js",
                  "derived_from": null,
                  "start_byte": 458,
                  "end_byte": 566,
                  "node_type": "function_declaration",
                  "sha256": "614e961a30336d28",
                  "line": 19
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
      "write_file"
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
  "attack_type": "unknown",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "At install the postinstall only records the npm install directory (INIT_CWD) into ~/.aicp-tracker/config.json and exits; it skips entirely in CI. The registration, auto-start persistence and Claude Code log upload to a dynamic-DNS host run only through the bin command or setup wizard, not at install.",
  "label_disagreement": true,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "source label malicious likely rests on runtime code (Claude Code usage and file-path upload to a duckdns host, login auto-start) that is not reached at install; install-time code only writes a local config",
    "label disagreement"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "879d79576ba24fcd"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 2
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_09d70ceb8d",
        "reason_code": "dead_branch",
        "note": "setup.js:203 is never reached under postinstall: the block at line 11 always calls process.exit(0) first",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 7464,
          "end_byte": 7513,
          "node_type": "binary_expression",
          "sha256": "13349cb3954dab33",
          "line": 203
        }
      },
      {
        "candidate": "k_c9d1468013",
        "reason_code": "other",
        "note": "config.load checks the package's own config file only to merge it; both outcomes end in the same config.save, plumbing",
        "anchor": {
          "file": "src/config.js",
          "derived_from": null,
          "start_byte": 355,
          "end_byte": 381,
          "node_type": "call_expression",
          "sha256": "0dbff3b633b4985f",
          "line": 15
        }
      },
      {
        "candidate": "k_77a2b5ffdc",
        "reason_code": "other",
        "note": "ensureDir creates ~/.aicp-tracker when missing before the same write, plumbing",
        "anchor": {
          "file": "src/config.js",
          "derived_from": null,
          "start_byte": 253,
          "end_byte": 278,
          "node_type": "call_expression",
          "sha256": "9b74ba9a0c792179",
          "line": 11
        }
      },
      {
        "candidate": "k_de74ee80c0",
        "reason_code": "not_install_time",
        "note": "installAutoStart runs only from main(), which is unreachable at install",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 2030,
          "end_byte": 2058,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 60
        }
      },
      {
        "candidate": "k_eeb70bae91",
        "reason_code": "not_install_time",
        "note": "installAutoStart runs only from main(), which is unreachable at install",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 2511,
          "end_byte": 2540,
          "node_type": "binary_expression",
          "sha256": "58c601c101556765",
          "line": 66
        }
      },
      {
        "candidate": "k_094ced4256",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1325,
          "end_byte": 1370,
          "node_type": "call_expression",
          "sha256": "089ff9a680b4a3b3",
          "line": 40
        }
      },
      {
        "candidate": "k_95f3a42a5d",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1374,
          "end_byte": 1411,
          "node_type": "call_expression",
          "sha256": "f0d1b9162ed132e8",
          "line": 40
        }
      },
      {
        "candidate": "k_1239834643",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1102,
          "end_byte": 1135,
          "node_type": "call_expression",
          "sha256": "32e753b118802514",
          "line": 34
        }
      },
      {
        "candidate": "k_6c61e5ee5f",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1583,
          "end_byte": 1608,
          "node_type": "call_expression",
          "sha256": "8dffed6c872ffc48",
          "line": 47
        }
      },
      {
        "candidate": "k_a1cea2dea1",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1088,
          "end_byte": 1113,
          "node_type": "call_expression",
          "sha256": "8dffed6c872ffc48",
          "line": 30
        }
      },
      {
        "candidate": "k_01a7667ff5",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 534,
          "end_byte": 562,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 16
        }
      },
      {
        "candidate": "k_41c233e6d4",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1281,
          "end_byte": 1308,
          "node_type": "call_expression",
          "sha256": "a0ceec6ff2f3057f",
          "line": 35
        }
      },
      {
        "candidate": "k_1d50ce13c4",
        "reason_code": "not_install_time",
        "note": "src/log-parser.js is not loaded at install",
        "anchor": {
          "file": "src/log-parser.js",
          "derived_from": null,
          "start_byte": 4707,
          "end_byte": 4728,
          "node_type": "call_expression",
          "sha256": "314f4d1d6c1665ae",
          "line": 115
        }
      },
      {
        "candidate": "k_a51868ffb8",
        "reason_code": "not_install_time",
        "note": "src/wal.js is not loaded at install",
        "anchor": {
          "file": "src/wal.js",
          "derived_from": null,
          "start_byte": 501,
          "end_byte": 534,
          "node_type": "call_expression",
          "sha256": "bf45683bb2ca2a47",
          "line": 15
        }
      },
      {
        "candidate": "q_85acc468ea",
        "reason_code": "dead_branch",
        "note": "false side of setup.js:11 never taken under postinstall; the same decision is kept as q_dc7fafc20e",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 348,
          "end_byte": 1151,
          "node_type": "if_statement",
          "sha256": "d60dac2f2cc15766",
          "line": 11
        }
      },
      {
        "candidate": "q_f6ccd36f95",
        "reason_code": "other",
        "note": "config.load existence check on the package's own config, plumbing before the same write",
        "anchor": {
          "file": "src/config.js",
          "derived_from": null,
          "start_byte": 350,
          "end_byte": 395,
          "node_type": "if_statement",
          "sha256": "a2de487d403827cb",
          "line": 15
        }
      },
      {
        "candidate": "q_539d6597a2",
        "reason_code": "other",
        "note": "ensureDir mkdir guard, plumbing before the same write",
        "anchor": {
          "file": "src/config.js",
          "derived_from": null,
          "start_byte": 248,
          "end_byte": 326,
          "node_type": "if_statement",
          "sha256": "1d186348aeae208d",
          "line": 11
        }
      },
      {
        "candidate": "q_73d2312bfc",
        "reason_code": "dead_branch",
        "note": "setup.js:203 is never reached under postinstall because of the earlier process.exit",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 7433,
          "end_byte": 7658,
          "node_type": "if_statement",
          "sha256": "7b9ef5946247741b",
          "line": 203
        }
      },
      {
        "candidate": "q_d3354ce534",
        "reason_code": "not_install_time",
        "note": "installAutoStart runs only from main(), unreachable at install",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 2026,
          "end_byte": 3827,
          "node_type": "if_statement",
          "sha256": "6e144a7cd94f02d5",
          "line": 60
        }
      },
      {
        "candidate": "q_7c8153f5c8",
        "reason_code": "not_install_time",
        "note": "installAutoStart runs only from main(), unreachable at install",
        "anchor": {
          "file": "bin/setup.js",
          "derived_from": null,
          "start_byte": 2507,
          "end_byte": 3827,
          "node_type": "if_statement",
          "sha256": "5b8c7b5968cb27f0",
          "line": 66
        }
      },
      {
        "candidate": "q_11613f3d70",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1415,
          "end_byte": 1574,
          "node_type": "if_statement",
          "sha256": "85d2ab61c2f7ff35",
          "line": 41
        }
      },
      {
        "candidate": "q_018c488651",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1666,
          "end_byte": 1688,
          "node_type": "ternary_expression",
          "sha256": "a830e5ea612650e3",
          "line": 49
        }
      },
      {
        "candidate": "q_c6102e1049",
        "reason_code": "not_install_time",
        "note": "src/daemon.js is not loaded at install",
        "anchor": {
          "file": "src/daemon.js",
          "derived_from": null,
          "start_byte": 1080,
          "end_byte": 1166,
          "node_type": "try_statement",
          "sha256": "71875ab00ca079ce",
          "line": 34
        }
      },
      {
        "candidate": "q_8075be8f65",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1578,
          "end_byte": 1625,
          "node_type": "if_statement",
          "sha256": "e80583dc58e4c101",
          "line": 47
        }
      },
      {
        "candidate": "q_270eb2b29e",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1067,
          "end_byte": 1127,
          "node_type": "if_statement",
          "sha256": "1d9977d08e5653ea",
          "line": 30
        }
      },
      {
        "candidate": "q_a8a6f576a5",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 530,
          "end_byte": 730,
          "node_type": "if_statement",
          "sha256": "1a84e76e1483bb76",
          "line": 16
        }
      },
      {
        "candidate": "q_bad001f289",
        "reason_code": "not_install_time",
        "note": "src/log-scanner.js is not loaded at install",
        "anchor": {
          "file": "src/log-scanner.js",
          "derived_from": null,
          "start_byte": 1277,
          "end_byte": 1384,
          "node_type": "if_statement",
          "sha256": "41045b1bb92f018a",
          "line": 35
        }
      },
      {
        "candidate": "q_7b364f84c1",
        "reason_code": "not_install_time",
        "note": "src/log-parser.js is not loaded at install",
        "anchor": {
          "file": "src/log-parser.js",
          "derived_from": null,
          "start_byte": 4694,
          "end_byte": 4752,
          "node_type": "try_statement",
          "sha256": "a36bc7940a463425",
          "line": 115
        }
      },
      {
        "candidate": "q_69d3315884",
        "reason_code": "not_install_time",
        "note": "src/wal.js is not loaded at install",
        "anchor": {
          "file": "src/wal.js",
          "derived_from": null,
          "start_byte": 477,
          "end_byte": 572,
          "node_type": "try_statement",
          "sha256": "bb38ceb9b0c8a525",
          "line": 15
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 19,
    "condition_sites_cited": 4,
    "guards_cited": 3,
    "candidates_dropped": 29,
    "conditions_in_set": 4,
    "conditions_out_of_set": 0,
    "guard_candidates": 19,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
