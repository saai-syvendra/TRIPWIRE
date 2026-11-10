# npm @emilgroup/discount-sdk@1.5.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-03-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

The postinstall hook runs `node index.js`. It unconditionally writes a Python file and a systemd user unit under the home directory and enables and starts the unit (persistence). It then collects npm tokens from `.npmrc` files, `NPM_*TOKEN*` env vars and `npm config`. If any token is found and `scripts/deploy.js` exists, it starts that script as a detached child with the tokens in its environment. The script validates each token against the npm registry, lists the packages the token owner maintains and runs `npm publish` on each one with this package's code. The only environment that opens the worm is a host with an npm token plus registry access; the persistence part has no gate.

## Execution

- **postinstall** `node index.js`: 2-file chain; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c1 \|\| c4 \|\| c5) && c2 (c1: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c4: process.env.NPM_TOKEN truthy; c5: target_artifact truthy; c2: file_or_dir_exists exists ./scripts/deploy.js) | then | 2 | spawn_process | env_var=NPM_TOKEN=(set); file_present=./scripts/deploy.js |
| g2 | postinstall | (c1 \|\| c4 \|\| c5) && c2 && c3 (c1: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c4: process.env.NPM_TOKEN truthy; c5: target_artifact truthy; c2: file_or_dir_exists exists ./scripts/deploy.js; c3: server_response truthy) | then | 3 | self_propagation, modify_other_packages, write_file | network=registry[.]npmjs[.]org:443=reachable; env_var=NPM_TOKEN=(set); file_present=./scripts/deploy.js |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 2 of 5 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c1, c3, c4, g1, g2.

## Requirements

- installed_tool: systemctl (user systemd unit is enabled and started for persistence)
- installed_tool: python3 (the unit runs the dropped service.py with python3)
- installed_tool: npm (deploy.js runs npm publish; npm config is also read for tokens)
- network: registry[.]npmjs[.]org:443 (token validation, owner search, metadata fetch and publish all use the npm registry)
- os: linux (persistence uses systemd user units under ~/.config/systemd/user)

## Behaviour

- Ungated: cred_read, write_file, persistence, spawn_process
- Gated: spawn_process, self_propagation, modify_other_packages, write_file

## Notes

- The dropped service body is the literal `hello123` run through base64, so it decodes to junk. The persistence mechanics still run.
- The whoami validity check (c3) is a server response, out of scope for Phase 2, and recorded for completeness.
- The npm registry endpoints are the real registry, used as the destination for stolen-token publishing; no separate C2 exists.
- The three token sources are separate conditions joined with `||` (c1 `.npmrc`, c4 env vars, c5 `npm config`); the decision on the merged set is `tokens.length > 0`, cited as their guard. The remaining `npm config` filters are dropped as duplicates of c5, and the README restore checks as plumbing.
- `ownedPackages.length === 0` (`scripts/deploy.js:111`) is another server-side early return before publish. It is not recorded as a condition; a reviewer may want to add it.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@emilgroup/discount-sdk",
    "version": "1.5.1",
    "archive_sha256": "7812ba81af2c2139b4ff186e75d5fb583834a3d28226a9f562d5aac842c7991b",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-03-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-03-20-@emilgroup_discount-sdk-v1.5.1.zip",
    "package_root": "layer0/tmp/tmpue0nzdg1/@emilgroup-discount-sdk/package",
    "cluster_key": "b8153464fa004f67ba0cd553ab2951e231cfd7c139cdc2aac355a14ad0b67f8c",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js",
          "scripts/deploy.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js and scripts/deploy.js read in full; no bundled or third-party code; nothing unread.",
      "scripts/deploy.js is started by index.js as a detached child (spawn of process.execPath), so it is in the install chain.",
      "BASE64_PAYLOAD in index.js is the literal 'hello123', so the dropped service.py holds decoded junk; the persistence mechanics still run.",
      "The systemctl calls are not in a gate; if they throw, the outer try swallows it and the token-theft part is skipped.",
      "findNpmTokens merges three credential sources into one set: .npmrc (c1), NPM token env vars (c4), npm config (c5). The decision on the set is tokens.length > 0 at index.js:88, the guard for all three, so any one source opens the gate.",
      "c1 reads ~/.npmrc, ./.npmrc and /etc/npmrc in one loop; the probe target names the first. A value starting with ${ is skipped at line 21. c4 covers any env var named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN (line 28).",
      "deploy.js has no install path except the spawn at index.js:91, so g2's chain starts in index.js. Its own check for an empty token list (line 190) always passes there, because index.js only spawns it with a non-empty NPM_TOKENS.",
      "deploy.js reads and restores README.md and package.json around each publish; that is plumbing for the publish, not a gate.",
      "g1 recipe: index.js line 28 matches the env var name NPM_TOKEN literally and lines 31-34 add any non-empty value, so NPM_TOKEN set to anything non-empty satisfies c4 (read, not guessed). g2's env_var stays guessed: c3 needs a token the registry accepts at /-/whoami, a value the recipe cannot give.",
      "g2 recipe: file_present ./scripts/deploy.js is listed for c2 (index.js:90), which is in g2's expression (read, not guessed). The registry host is read from the fetchJson URL at deploy.js:87."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "systemctl",
      "reason": "user systemd unit is enabled and started for persistence"
    },
    {
      "axis": "installed_tool",
      "value": "python3",
      "reason": "the unit runs the dropped service.py with python3"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "deploy.js runs npm publish; npm config is also read for tokens"
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "token validation, owner search, metadata fetch and publish all use the npm registry"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "persistence uses systemd user units under ~/.config/systemd/user"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "fs.readFileSync",
      "operator": "regex",
      "value": "(?:_authToken\\s*=\\s*|:_authToken=)([^\\s]+)",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 531,
            "end_byte": 587,
            "node_type": "call_expression",
            "sha256": "71e15d28790b6959",
            "line": 20
          }
        }
      ],
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "~/.npmrc",
        "accessor": "content"
      },
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "./scripts/deploy.js",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_6efa4c415c",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2912,
            "end_byte": 2939,
            "node_type": "call_expression",
            "sha256": "af7226c4526ac718",
            "line": 90
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "server_response",
      "api": "whoami.username",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 2478,
            "end_byte": 2494,
            "node_type": "unary_expression",
            "sha256": "d32bb4da2ad4df16",
            "line": 93
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 916,
            "end_byte": 932,
            "node_type": "subscript_expression",
            "sha256": "0a727da07ddee12f",
            "line": 31
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b09f29b842",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1092,
            "end_byte": 1211,
            "node_type": "call_expression",
            "sha256": "cc9add250a73145b",
            "line": 38
          }
        },
        {
          "candidate": "k_40b927fb03",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1239,
            "end_byte": 1250,
            "node_type": "identifier",
            "sha256": "d1201a3f814e9bd7",
            "line": 41
          }
        }
      ],
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "npm config get //registry.npmjs.org/:_authToken 2>/dev/null",
        "accessor": "stdout"
      },
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "(c1 || c4 || c5) && c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2804,
            "end_byte": 3144,
            "node_type": "if_statement",
            "sha256": "6924e192c123c8dc",
            "line": 88
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c4",
            "c5"
          ]
        },
        {
          "candidate": "q_2c5ac6a170",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2908,
            "end_byte": 3138,
            "node_type": "if_statement",
            "sha256": "46ce81c44ce89ca8",
            "line": 90
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the republishing worm only starts when at least one npm token was found on the host",
      "then": {
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "env_var": {
            "NPM_TOKEN": null
          },
          "file_present": [
            "./scripts/deploy.js"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2941,
            "end_byte": 3138,
            "node_type": "statement_block",
            "sha256": "0ca728ba75cfbe2a",
            "line": 90
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 2951,
              "end_byte": 3121,
              "node_type": "call_expression",
              "sha256": "f7b1f520ef5ce62c",
              "line": 91
            },
            "witness": []
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "(c1 || c4 || c5) && c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2804,
            "end_byte": 3144,
            "node_type": "if_statement",
            "sha256": "6924e192c123c8dc",
            "line": 88
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c4",
            "c5"
          ]
        },
        {
          "candidate": "q_2c5ac6a170",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2908,
            "end_byte": 3138,
            "node_type": "if_statement",
            "sha256": "46ce81c44ce89ca8",
            "line": 90
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
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 2463,
            "end_byte": 2607,
            "node_type": "if_statement",
            "sha256": "b7ba5bc2da31c8fc",
            "line": 93
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "publishing only proceeds when the registry accepts a stolen token (whoami returns a username)",
      "then": {
        "behaviours": [
          "self_propagation",
          "modify_other_packages",
          "write_file"
        ],
        "env_recipe": {
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          },
          "env_var": {
            "NPM_TOKEN": null
          },
          "file_present": [
            "./scripts/deploy.js"
          ]
        },
        "recipe_guessed_fields": [
          "env_var"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2835,
            "end_byte": 2901,
            "node_type": "lexical_declaration",
            "sha256": "b487d10ffa5a0bc2",
            "line": 89
          },
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2941,
            "end_byte": 3138,
            "node_type": "statement_block",
            "sha256": "0ca728ba75cfbe2a",
            "line": 90
          },
          {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 2611,
            "end_byte": 5725,
            "node_type": "stmt_range",
            "sha256": "8a93859848d13689",
            "line": 98
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 226,
              "end_byte": 270,
              "node_type": "call_expression",
              "sha256": "c9170ed5236671d4",
              "line": 10
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2951,
                  "end_byte": 3121,
                  "node_type": "call_expression",
                  "sha256": "f7b1f520ef5ce62c",
                  "line": 91
                }
              },
              {
                "hop": "run_file",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2856,
                  "end_byte": 2900,
                  "node_type": "call_expression",
                  "sha256": "15c5f00d2e1aa912",
                  "line": 89
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 6974,
                  "end_byte": 7022,
                  "node_type": "call_expression",
                  "sha256": "1c28e9e82e227e6e",
                  "line": 211
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 2111,
                  "end_byte": 5727,
                  "node_type": "function_declaration",
                  "sha256": "71a4a059b8d81dd2",
                  "line": 83
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 4891,
                  "end_byte": 5000,
                  "node_type": "call_expression",
                  "sha256": "f694186e626f4058",
                  "line": 155
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 157,
                  "end_byte": 273,
                  "node_type": "function_declaration",
                  "sha256": "1c08df3dcb908c66",
                  "line": 8
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 226,
              "end_byte": 270,
              "node_type": "call_expression",
              "sha256": "c9170ed5236671d4",
              "line": 10
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2951,
                  "end_byte": 3121,
                  "node_type": "call_expression",
                  "sha256": "f7b1f520ef5ce62c",
                  "line": 91
                }
              },
              {
                "hop": "run_file",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2856,
                  "end_byte": 2900,
                  "node_type": "call_expression",
                  "sha256": "15c5f00d2e1aa912",
                  "line": 89
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 6974,
                  "end_byte": 7022,
                  "node_type": "call_expression",
                  "sha256": "1c28e9e82e227e6e",
                  "line": 211
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 2111,
                  "end_byte": 5727,
                  "node_type": "function_declaration",
                  "sha256": "71a4a059b8d81dd2",
                  "line": 83
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 4891,
                  "end_byte": 5000,
                  "node_type": "call_expression",
                  "sha256": "f694186e626f4058",
                  "line": 155
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 157,
                  "end_byte": 273,
                  "node_type": "function_declaration",
                  "sha256": "1c08df3dcb908c66",
                  "line": 8
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 4798,
              "end_byte": 4872,
              "node_type": "call_expression",
              "sha256": "02e88ede3f6254b8",
              "line": 152
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2951,
                  "end_byte": 3121,
                  "node_type": "call_expression",
                  "sha256": "f7b1f520ef5ce62c",
                  "line": 91
                }
              },
              {
                "hop": "run_file",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2856,
                  "end_byte": 2900,
                  "node_type": "call_expression",
                  "sha256": "15c5f00d2e1aa912",
                  "line": 89
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 6974,
                  "end_byte": 7022,
                  "node_type": "call_expression",
                  "sha256": "1c28e9e82e227e6e",
                  "line": 211
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 2111,
                  "end_byte": 5727,
                  "node_type": "function_declaration",
                  "sha256": "71a4a059b8d81dd2",
                  "line": 83
                }
              }
            ]
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "cred_read",
      "write_file",
      "persistence",
      "spawn_process"
    ],
    "gated": [
      "spawn_process",
      "self_propagation",
      "modify_other_packages",
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
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/$",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/-/v1/search?text=maintainer:$",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/-/whoami",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "npm token worm (republishes owned packages)",
  "claude_assessment": "malicious",
  "assessment_reason": "postinstall installs a systemd user service for persistence, harvests npm tokens from .npmrc files, env vars and npm config, and spawns a detached script that uses them to republish every package the token owns with this code.",
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
      "sha256": "9fa1947b7d0b8b77"
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
        "candidate": "k_fa8a4fbbf3",
        "reason_code": "duplicate_of",
        "note": "duplicate of c5: rejects the string npm prints for an unset key, so it is part of the same test that npm config returned a token",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1254,
          "end_byte": 1281,
          "node_type": "binary_expression",
          "sha256": "84c511580c4fbccf",
          "line": 41
        }
      },
      {
        "candidate": "k_7f3aae8bfb",
        "reason_code": "duplicate_of",
        "note": "duplicate of c5: rejects the literal output 'null', so it is part of the same test that npm config returned a token",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1285,
          "end_byte": 1307,
          "node_type": "binary_expression",
          "sha256": "eb1b8431270e839d",
          "line": 41
        }
      },
      {
        "candidate": "q_c6a7742791",
        "reason_code": "duplicate_of",
        "note": "duplicate of c5: the try only swallows a failed npm config read, which leaves c5 false; the decision that acts on it is the guard at index.js:88",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1062,
          "end_byte": 1364,
          "node_type": "try_statement",
          "sha256": "197dc5b885117478",
          "line": 37
        }
      },
      {
        "candidate": "q_b30584949f",
        "reason_code": "duplicate_of",
        "note": "duplicate of c5: this if holds c5's test and only adds the token to the set; the decision that acts on the merged set is the guard at index.js:88",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1235,
          "end_byte": 1347,
          "node_type": "if_statement",
          "sha256": "1f32925fa5daad21",
          "line": 41
        }
      },
      {
        "candidate": "k_edf177b7ff",
        "reason_code": "other",
        "note": "README existence check that only picks whether to restore it after publish; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 3667,
          "end_byte": 3692,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 127
        }
      },
      {
        "candidate": "k_de022e6195",
        "reason_code": "other",
        "note": "README existence check in the finally block; plumbing for restore",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 5550,
          "end_byte": 5575,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 170
        }
      },
      {
        "candidate": "q_a78b614bc0",
        "reason_code": "other",
        "note": "ternary reading README or null; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 3667,
          "end_byte": 3749,
          "node_type": "ternary_expression",
          "sha256": "68ba6cd86b8ab108",
          "line": 127
        }
      },
      {
        "candidate": "q_ae5269520e",
        "reason_code": "other",
        "note": "else-if choosing to remove a temporary README; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 5530,
          "end_byte": 5696,
          "node_type": "if_statement",
          "sha256": "4d75e94b3f383156",
          "line": 170
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 7,
    "condition_sites_cited": 3,
    "guards_cited": 1,
    "candidates_dropped": 8,
    "conditions_in_set": 2,
    "conditions_out_of_set": 3,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c3",
      "c4",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
