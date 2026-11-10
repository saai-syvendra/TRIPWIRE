# npm @emilgroup/insurance-sdk@1.97.4

**Source:** datadog · **Source label:** malicious · **Released:** 2026-03-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`, which without any gate writes `~/.local/share/pgmon/service.py` and a `pgmon.service` systemd user unit, then reloads, enables and starts it with `systemctl --user`. It then collects npm auth tokens from `~/.npmrc`, `./.npmrc`, `/etc/npmrc`, env vars named like `NPM*TOKEN` and `npm config get`. Gate g1 (any token found) launches `scripts/deploy.js` as a detached child, which asks the registry who owns the token. Gate g2 adds two server-response checks (whoami returns a username, the account maintains packages) before it rewrites `package.json` with each owned package's name and a bumped version and runs `npm publish`. A Linux host with a working systemd user manager and an `NPM_TOKEN` (or an npmrc token) opens every path.

## Execution

- **postinstall** `node index.js`: 2-file chain; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c1 && c2 && c3) \|\| (c4 && c8) \|\| c5 (c1: target_artifact truthy; c2: target_artifact != undefined; c3: target_artifact != null; c4: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c8: target_artifact not_startswith ${; c5: Object.keys(process.env) other variable named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN, with a non-empty value) | then | 1 | spawn_process, recon | env_var=NPM_TOKEN=(set) |
| g2 | postinstall | ((c1 && c2 && c3) \|\| (c4 && c8) \|\| c5) && c6 && c7 (c1: target_artifact truthy; c2: target_artifact != undefined; c3: target_artifact != null; c4: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c8: target_artifact not_startswith ${; c5: Object.keys(process.env) other variable named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN, with a non-empty value; c6: server_response truthy; c7: server_response truthy) | then | 3 | self_propagation, write_file | env_var=NPM_TOKEN=(set); network=registry[.]npmjs[.]org:443=reachable |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 3 of 8 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, c8, g1, g2.

## Requirements

- os: linux (systemd user unit and systemctl --user; on other OSes execSync throws and the outer catch skips everything after it, including the worm)
- installed_tool: systemctl (daemon-reload, enable and start must succeed or the token harvest and worm launch never run)
- other: running systemd user manager (systemctl --user reachable) (systemctl --user fails without a user session bus, which aborts the rest of the payload)
- installed_tool: npm (npm config get for the token source and npm publish for propagation)
- network: registry[.]npmjs[.]org:443 (whoami, maintainer search, package metadata and publish)

## Behaviour

- Ungated: write_file, persistence, cred_read
- Gated: spawn_process, recon, self_propagation, write_file

## Notes

- The embedded payload is the placeholder `hello123`, so `service.py` is junk in this build. The persistence mechanism is still installed.
- If any `systemctl --user` call fails (containers, CI, no user session), the outer catch skips the token harvest and the worm. A scanner on a stock container will only see the file writes.
- An npmrc entry only counts as a token when its value does not start with the `${` placeholder prefix (c8), so an npmrc holding only `${NPM_TOKEN}` style lines opens nothing.
- c6 and c7 are out-of-scope `server_response` checks. They need a token that the registry accepts and that maintains at least one package, which Phase 2 cannot plant.
- The family hint comes from how the code is built (pgmon systemd unit plus the deploy.js token worm). No C2 or canister URL appears in this sample.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@emilgroup/insurance-sdk",
    "version": "1.97.4",
    "archive_sha256": "53e83534da0bf00d98afbcee0dce2dd84f085c0c86cd128c7f7a26a77daa4cba",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-03-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-03-20-@emilgroup_insurance-sdk-v1.97.4.zip",
    "package_root": "layer0/tmp/tmpm1ohtcw0/@emilgroup-insurance-sdk/package",
    "cluster_key": "a9a781844a977a77ea2fe0af272a8128be09edc04b71d1f5ce7316751593d009",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
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
      "index.js and scripts/deploy.js are small plain JS, both read in full; nothing unread. deploy.js is started by index.js:91 via spawn(process.execPath, [deploy.js]) detached and unref'd, so it outlives the install.",
      "index.js:54 `if (!BASE64_PAYLOAD) process.exit(0)` tests a constant, not the environment; not a gate. The constant is the placeholder 'hello123', so the dropped service.py is base64 junk, not a working Python script.",
      "The three systemctl --user calls (index.js:82-84) throw outside a running systemd user manager (most containers, CI, macOS, Windows); the outer catch then skips the token harvest and the worm. Recorded as requirements, not gates.",
      "deploy.js:77 `if (!tokens.length) process.exit(1)` reads NPM_TOKENS that index.js hands to the child; it is always true when launched by the install, so it is a handover guard, not a gate.",
      "g2's then-region is in deploy.js run(); its outer guard is index.js:88, reached through the detached launch of deploy.js. The README save/restore (deploy.js:58, :70), the readme write and latestVersion ternary are plumbing around the publish.",
      "Token sources (c1-c5, c8) are merged into one Set and tested once at index.js:88. c4 and c8 run in one loop over ~/.npmrc, ./.npmrc and /etc/npmrc, so probe target *npmrc stands for all three.",
      "The registry endpoints are the legitimate npm API used as the worm's control plane, so role c2 is approximate.",
      "An npmrc line yields a token only when the regex matches (c4) and the capture does not start with the ${ placeholder prefix (c8, index.js:21); m && m[1] is the presence check of that same value.",
      "c6 reads the awaited result of fetchJson (deploy.js:9, wraps https.get) and c7 the list returned by getOwned (deploy.js:37, built from fetchJson search responses); both are named by the wrapper the tested variable is bound to."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "systemd user unit and systemctl --user; on other OSes execSync throws and the outer catch skips everything after it, including the worm"
    },
    {
      "axis": "installed_tool",
      "value": "systemctl",
      "reason": "daemon-reload, enable and start must succeed or the token harvest and worm launch never run"
    },
    {
      "axis": "other",
      "value": "running systemd user manager (systemctl --user reachable)",
      "reason": "systemctl --user fails without a user session bus, which aborts the rest of the payload"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "npm config get for the token source and npm publish for propagation"
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "whoami, maintainer search, package metadata and publish"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
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
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "npm config get //registry.npmjs.org/:_authToken 2>/dev/null",
        "accessor": "stdout"
      }
    },
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "!=",
      "value": "undefined",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_fa8a4fbbf3",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1254,
            "end_byte": 1281,
            "node_type": "binary_expression",
            "sha256": "84c511580c4fbccf",
            "line": 41
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "npm config get //registry.npmjs.org/:_authToken 2>/dev/null",
        "accessor": "stdout"
      }
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "!=",
      "value": "null",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7f3aae8bfb",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1285,
            "end_byte": 1307,
            "node_type": "binary_expression",
            "sha256": "eb1b8431270e839d",
            "line": 41
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "npm config get //registry.npmjs.org/:_authToken 2>/dev/null",
        "accessor": "stdout"
      }
    },
    {
      "id": "c4",
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
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "*npmrc",
        "accessor": "content"
      }
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "Object.keys(process.env)",
      "operator": "other",
      "value": "variable named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN, with a non-empty value",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 778,
            "end_byte": 863,
            "node_type": "binary_expression",
            "sha256": "d725cd598ec96d67",
            "line": 28
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "server_response",
      "api": "fetchJson",
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
            "start_byte": 1681,
            "end_byte": 1708,
            "node_type": "binary_expression",
            "sha256": "91f6825027d1bb1b",
            "line": 52
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "getOwned",
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
            "start_byte": 1817,
            "end_byte": 1830,
            "node_type": "unary_expression",
            "sha256": "c36bff4c9ccacc6c",
            "line": 55
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "target_artifact",
      "api": "String.startsWith",
      "operator": "not_startswith",
      "value": "${",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 614,
            "end_byte": 636,
            "node_type": "unary_expression",
            "sha256": "f9689579229c5149",
            "line": 21
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "*npmrc",
        "accessor": "content"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "(c1 && c2 && c3) || (c4 && c8) || c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2808,
            "end_byte": 2825,
            "node_type": "binary_expression",
            "sha256": "1194f865766a3598",
            "line": 88
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4",
            "c5",
            "c8"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the worm stage only starts when at least one npm auth token was found in npm config, an npmrc file or an NPM*TOKEN env var",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process",
          "recon"
        ],
        "env_recipe": {
          "env_var": {
            "NPM_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2835,
            "end_byte": 3138,
            "node_type": "stmt_range",
            "sha256": "b4ccde3ec6c2d525",
            "line": 89
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
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 252,
              "end_byte": 509,
              "node_type": "call_expression",
              "sha256": "d8a4ba82c3b138b7",
              "line": 11
            },
            "witness": [
              {
                "hop": "run_file",
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
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 3112,
                  "end_byte": 3149,
                  "node_type": "call_expression",
                  "sha256": "2377039bdfceee6e",
                  "line": 80
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 1510,
                  "end_byte": 2773,
                  "node_type": "function_declaration",
                  "sha256": "e58deb6de34b5e05",
                  "line": 49
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 1594,
                  "end_byte": 1649,
                  "node_type": "call_expression",
                  "sha256": "f91522e4561cbd33",
                  "line": 51
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 171,
                  "end_byte": 538,
                  "node_type": "function_declaration",
                  "sha256": "df31eb613357b665",
                  "line": 9
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
      "expression": "((c1 && c2 && c3) || (c4 && c8) || c5) && c6 && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 2808,
            "end_byte": 2825,
            "node_type": "binary_expression",
            "sha256": "1194f865766a3598",
            "line": 88
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4",
            "c5",
            "c8"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1677,
            "end_byte": 1717,
            "node_type": "if_statement",
            "sha256": "6225437d7ce5e463",
            "line": 52
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1813,
            "end_byte": 1839,
            "node_type": "if_statement",
            "sha256": "86964cc132a948a9",
            "line": 55
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "publishing only proceeds when the registry accepts the stolen token (whoami returns a username) and the account maintains at least one package",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "self_propagation",
          "write_file"
        ],
        "env_recipe": {
          "env_var": {
            "NPM_TOKEN": null
          },
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1842,
            "end_byte": 2771,
            "node_type": "stmt_range",
            "sha256": "942794299aa1d9e9",
            "line": 56
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 2403,
              "end_byte": 2517,
              "node_type": "call_expression",
              "sha256": "9fa8b7bac2c3cb34",
              "line": 65
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 2285,
              "end_byte": 2385,
              "node_type": "call_expression",
              "sha256": "3ee4d868bee20c52",
              "line": 63
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
      "write_file",
      "persistence",
      "cred_read"
    ],
    "gated": [
      "spawn_process",
      "recon",
      "self_propagation",
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
        "role": "c2"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/-/v1/search?text=maintainer:$",
        "role": "c2"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/-/whoami",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "CanisterWorm",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall drops a python service under ~/.local/share/pgmon and installs, enables and starts it as a systemd user unit, then harvests npm tokens from npmrc files, npm config and env vars and launches a detached worm that republishes every package the token's account maintains with this payload.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "family hint CanisterWorm rests on code shape (pgmon systemd user service plus deploy.js npm-token worm); this build has a placeholder payload ('hello123') and no C2 in code",
    "g2's outer guard sits in index.js while its region is in the detached deploy.js; check the verifier accepts the cross-file guard",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "47ed4033a995d797"
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
        "candidate": "k_b09f29b842",
        "reason_code": "other",
        "note": "try probe on npm config get only needs npm on PATH, which always holds during an npm install; recorded as an npm requirement",
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
        "candidate": "q_c6a7742791",
        "reason_code": "other",
        "note": "try around npm config get is error swallowing for a prerequisite; the token decision is the index.js:88 guard",
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
        "note": "only adds the config token to the Set; the decision on the merged tokens is the index.js:88 guard of g1, which holds c1-c3",
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
        "candidate": "k_6efa4c415c",
        "reason_code": "not_environmental",
        "note": "checks the package's own shipped scripts/deploy.js, always present in the tarball",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2912,
          "end_byte": 2939,
          "node_type": "call_expression",
          "sha256": "af7226c4526ac718",
          "line": 90
        }
      },
      {
        "candidate": "q_2c5ac6a170",
        "reason_code": "not_environmental",
        "note": "guard of the existsSync check on the package's own deploy.js",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2908,
          "end_byte": 3138,
          "node_type": "if_statement",
          "sha256": "46ce81c44ce89ca8",
          "line": 90
        }
      },
      {
        "candidate": "k_99896657d4",
        "reason_code": "not_environmental",
        "note": "README.md is the package's own file; existence only decides whether the original README is saved for restore (plumbing)",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 1958,
          "end_byte": 1983,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 58
        }
      },
      {
        "candidate": "k_7fa98ccddd",
        "reason_code": "not_environmental",
        "note": "cleanup of the package's own README after publish; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2708,
          "end_byte": 2733,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 70
        }
      },
      {
        "candidate": "q_1e810a21cc",
        "reason_code": "not_environmental",
        "note": "ternary saving the package's own README for restore; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 1958,
          "end_byte": 2028,
          "node_type": "ternary_expression",
          "sha256": "e371a190f45cc7ff",
          "line": 58
        }
      },
      {
        "candidate": "q_e7d3dabfaa",
        "reason_code": "not_environmental",
        "note": "README cleanup branch in finally; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2694,
          "end_byte": 2761,
          "node_type": "if_statement",
          "sha256": "f67b09332785ce40",
          "line": 70
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 7,
    "condition_sites_cited": 3,
    "guards_cited": 0,
    "candidates_dropped": 9,
    "conditions_in_set": 3,
    "conditions_out_of_set": 5,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
