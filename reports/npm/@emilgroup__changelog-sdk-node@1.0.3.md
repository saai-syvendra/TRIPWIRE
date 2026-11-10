# npm @emilgroup/changelog-sdk-node@1.0.3

**Source:** datadog · **Source label:** malicious · **Released:** 2026-03-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`. Without any gate, it decodes a base64 Python script to `~/.local/share/pgmon/service.py`, writes a systemd user unit `pgmon.service` and runs `systemctl --user daemon-reload/enable/start`. The resulting persistent service waits 300 s, then polls an ICP canister for a link and downloads and runs whatever binary that link points to. Still without a gate, it collects npm tokens from `.npmrc` files, env vars and `npm config get`. Gate g1 checks that at least one token was found (most simply `NPM_TOKEN` set) and then spawns `scripts/deploy.js` detached. Inside that child, gate g2 (g1's token conditions plus registry replies: whoami returns a username and the account maintains packages) guards republishing every owned package with a patch-bumped version through `npm publish`.

## Execution

- **postinstall** `node index.js`: 2-file chain; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c7 && c8) \|\| c9 \|\| (c1 && c2 && c3 && c4) (c7: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c8: target_artifact not_startswith ${; c9: process.env other variable named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN, with a non-empty value; c1: target_artifact exists; c2: target_artifact truthy; c3: target_artifact != undefined; c4: target_artifact != null) | then | 1 | self_propagation | env_var=NPM_TOKEN=(set) |
| g2 | postinstall | ((c7 && c8) \|\| c9 \|\| (c1 && c2 && c3 && c4)) && c10 && c11 (c7: target_artifact regex (?:_authToken\s*=\s*\|:_authToken=)([^\s]+); c8: target_artifact not_startswith ${; c9: process.env other variable named NPM_TOKEN, NPM_TOKENS or containing both NPM and TOKEN, with a non-empty value; c1: target_artifact exists; c2: target_artifact truthy; c3: target_artifact != undefined; c4: target_artifact != null; c10: server_response truthy whoami.username; c11: server_response > 0) | then | 3 | self_propagation | env_var=NPM_TOKEN=(set); network=registry[.]npmjs[.]org:443=reachable |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 4 of 9 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c7, c8, c9, c10, c11, g1, g2.

## Requirements

- os: linux (persistence uses a systemd user unit and /usr/bin/python3; if systemctl fails, the outer catch also skips the token and worm stage)
- installed_tool: systemctl (systemctl --user daemon-reload/enable/start run via execSync with no own try; a failure aborts the rest of index.js)
- other: working systemd user session (user D-Bus / XDG_RUNTIME_DIR) so systemctl --user succeeds (without it execSync throws before findNpmTokens and the deploy.js spawn)
- file_present: /usr/bin/python3 (ExecStart of the pgmon.service unit runs the dropped service.py with this interpreter)
- network: registry[.]npmjs[.]org:443 (deploy.js validates the token (whoami), lists owned packages and runs npm publish against the registry)
- installed_tool: npm (token lookup via npm config get and republishing via npm publish)
- network: tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io:443 (persisted service.py polls this ICP canister for the second-stage link (after the 300 s delay))

## Behaviour

- Ungated: write_file, persistence, cred_read
- Gated: self_propagation

## Notes

- The systemctl calls are not individually caught. On hosts without a systemd user session they throw, and the outer catch silently skips the token and worm stage too. A Linux VM with a working `systemctl --user` and `/usr/bin/python3` is needed to see the whole chain.
- g2 only ever runs in the child that g1 starts, so its expression includes g1's conditions and it has `min_conditions` 3. Its own conditions c10 and c11 are server responses (out of scope), so the in-scope conditions on the path are g1's.
- The decoded service.py checks (link starts with http, differs from `/tmp/.pg_state`, does not contain youtube[.]com) act on C2 replies in the persisted service, not in install code. They are not recorded as gates.
- Registry endpoints in deploy.js are the legitimate npm registry, used with stolen tokens. They are listed as a network requirement, not as attacker endpoints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@emilgroup/changelog-sdk-node",
    "version": "1.0.3",
    "archive_sha256": "9f6b69a0e89749375c67df59c67435be4a33249c9a1e3d198dd05945d4b2a00c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-03-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-03-20-@emilgroup_changelog-sdk-node-v1.0.3.zip",
    "package_root": "layer0/tmp/tmpp7hs81cl/@emilgroup-changelog-sdk-node/package",
    "cluster_key": "35b8834250850ff47cf7ecb6b9347e456a8bba28e16a468e5c8ff03b50ffe1eb",
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
    "delays": [
      {
        "site": "service.py decoded from index.js:52, time.sleep(300) before first C2 poll",
        "seconds": 300,
        "purpose": "persisted backdoor waits 5 minutes after the service starts, then polls every 3000 s"
      }
    ],
    "notes": [
      "index.js and scripts/deploy.js: package code read in full; nothing bundled. The base64 literal at index.js:52 was decoded with decode.py (base64) to a Python script, read in full. Nothing unread.",
      "Ungated: index.js writes the decoded Python to ~/.local/share/pgmon/service.py and a systemd user unit ~/.config/systemd/user/pgmon.service (ExecStart=/usr/bin/python3, Restart=always), then runs systemctl --user daemon-reload, enable and start.",
      "service.py runs as the systemd service, outside the npm process: sleeps 300 s, then every 3000 s fetches a link from an ICP canister URL, downloads it to /tmp/pglog, chmods it and starts it detached, recording it in /tmp/.pg_state.",
      "service.py checks (link starts with http, differs from /tmp/.pg_state, does not contain youtube.com) act on the server reply inside the persisted service, not in the install hook, so they are not recorded as gates.",
      "The three systemctl execSync calls have no own try; without a working systemd user session they throw, the outer catch at index.js:99 swallows it and the token and worm stage never runs. Listed as requirements.",
      "findNpmTokens is called ungated (cred_read): reads ~/.npmrc, ./.npmrc and /etc/npmrc, env vars named NPM_TOKEN, NPM_TOKENS or containing NPM and TOKEN, and npm config get. Sources merge into one Set; tokens.length > 0 is the g1 guard.",
      "c7 and c8 test the content of one fs.readFileSync(rcPath) call inside a loop over ~/.npmrc, ./.npmrc and /etc/npmrc (index.js:11-18). The probe target *npmrc covers all three paths; any one of them holding a literal token satisfies c7 && c8.",
      "g1 spawns scripts/deploy.js detached with process.execPath and NPM_TOKENS in its env. In deploy.js, exit(1) on empty NPM_TOKENS/NPM_TOKEN is a hand-off check on the variable index.js always sets for the child; not a gate.",
      "g2 sits in the deploy.js child that only the index.js:88 guard launches at install (the deploy npm script is not a hook), so its expression nests g1's conditions. c10 and c11 are registry replies (whoami username, maintainer search results).",
      "deploy.js, per package the token owns: rewrites package.json name and a patch-bumped version, swaps README for the victim's registry README, runs npm publish, then restores both files. The README existsSync checks only back up and restore the package's own file.",
      "if (!BASE64_PAYLOAD) process.exit(0) at index.js:54 tests a constant literal, so it is not environmental and not recorded. The fs.existsSync on scripts/deploy.js tests a file the package ships, so it was dropped.",
      "The registry endpoints in deploy.js (whoami, maintainer search, package metadata) are the legitimate npm registry used with stolen tokens. They are left out of endpoints and listed as a network requirement instead."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "persistence uses a systemd user unit and /usr/bin/python3; if systemctl fails, the outer catch also skips the token and worm stage"
    },
    {
      "axis": "installed_tool",
      "value": [
        "systemctl"
      ],
      "reason": "systemctl --user daemon-reload/enable/start run via execSync with no own try; a failure aborts the rest of index.js"
    },
    {
      "axis": "other",
      "value": "working systemd user session (user D-Bus / XDG_RUNTIME_DIR) so systemctl --user succeeds",
      "reason": "without it execSync throws before findNpmTokens and the deploy.js spawn"
    },
    {
      "axis": "file_present",
      "value": [
        "/usr/bin/python3"
      ],
      "reason": "ExecStart of the pgmon.service unit runs the dropped service.py with this interpreter"
    },
    {
      "axis": "network",
      "value": [
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "deploy.js validates the token (whoami), lists owned packages and runs npm publish against the registry"
    },
    {
      "axis": "installed_tool",
      "value": [
        "npm"
      ],
      "reason": "token lookup via npm config get and republishing via npm publish"
    },
    {
      "axis": "network",
      "value": [
        "tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io:443"
      ],
      "reason": "persisted service.py polls this ICP canister for the second-stage link (after the 300 s delay)"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "exists",
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
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "npm config get //registry.npmjs.org/:_authToken 2>/dev/null",
        "accessor": "throws"
      }
    },
    {
      "id": "c2",
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
      "id": "c3",
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
      "id": "c4",
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
      "id": "c7",
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
      "id": "c8",
      "category": "target_artifact",
      "api": "fs.readFileSync",
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
            "start_byte": 615,
            "end_byte": 636,
            "node_type": "call_expression",
            "sha256": "582bf15921ce237d",
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
    },
    {
      "id": "c9",
      "category": "env_var",
      "api": "process.env",
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
      "id": "c10",
      "category": "server_response",
      "api": "https.get",
      "operator": "truthy",
      "value": "whoami.username",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1684,
            "end_byte": 1711,
            "node_type": "binary_expression",
            "sha256": "91f6825027d1bb1b",
            "line": 52
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "server_response",
      "api": "https.get",
      "operator": ">",
      "value": "0",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1820,
            "end_byte": 1833,
            "node_type": "unary_expression",
            "sha256": "c36bff4c9ccacc6c",
            "line": 55
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
      "expression": "(c7 && c8) || c9 || (c1 && c2 && c3 && c4)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 4408,
            "end_byte": 4425,
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
            "c7",
            "c8",
            "c9"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the worm stage only starts when at least one npm auth token was found in .npmrc files, env vars or npm config",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "self_propagation"
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
            "start_byte": 4435,
            "end_byte": 4738,
            "node_type": "stmt_range",
            "sha256": "b4ccde3ec6c2d525",
            "line": 89
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/deploy.js",
              "derived_from": null,
              "start_byte": 2459,
              "end_byte": 2573,
              "node_type": "call_expression",
              "sha256": "9fa8b7bac2c3cb34",
              "line": 66
            },
            "witness": [
              {
                "hop": "run_file",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 4551,
                  "end_byte": 4721,
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
                  "start_byte": 3188,
                  "end_byte": 3220,
                  "node_type": "call_expression",
                  "sha256": "4fabec6b7109423a",
                  "line": 81
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 1510,
                  "end_byte": 2833,
                  "node_type": "function_declaration",
                  "sha256": "e91a96d27b4553e4",
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
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "((c7 && c8) || c9 || (c1 && c2 && c3 && c4)) && c10 && c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 4408,
            "end_byte": 4425,
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
            "c7",
            "c8",
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1680,
            "end_byte": 1720,
            "node_type": "if_statement",
            "sha256": "6225437d7ce5e463",
            "line": 52
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c10"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1816,
            "end_byte": 1842,
            "node_type": "if_statement",
            "sha256": "86964cc132a948a9",
            "line": 55
          },
          "kind": "early_exit",
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
      "purpose_reason": "republishing only happens when a token was found, the registry accepts it and the account maintains at least one package",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "self_propagation"
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
            "file": "index.js",
            "derived_from": null,
            "start_byte": 4435,
            "end_byte": 4738,
            "node_type": "stmt_range",
            "sha256": "b4ccde3ec6c2d525",
            "line": 89
          },
          {
            "file": "scripts/deploy.js",
            "derived_from": null,
            "start_byte": 1845,
            "end_byte": 2831,
            "node_type": "stmt_range",
            "sha256": "dacca21eef07375c",
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
              "start_byte": 2459,
              "end_byte": 2573,
              "node_type": "call_expression",
              "sha256": "9fa8b7bac2c3cb34",
              "line": 66
            },
            "witness": [
              {
                "hop": "run_file",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 4551,
                  "end_byte": 4721,
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
                  "start_byte": 3188,
                  "end_byte": 3220,
                  "node_type": "call_expression",
                  "sha256": "4fabec6b7109423a",
                  "line": 81
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/deploy.js",
                  "derived_from": null,
                  "start_byte": 1510,
                  "end_byte": 2833,
                  "node_type": "function_declaration",
                  "sha256": "e91a96d27b4553e4",
                  "line": 49
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
    "ungated": [
      "write_file",
      "persistence",
      "cred_read"
    ],
    "gated": [
      "self_propagation"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "base64-encoded Python second stage in a string literal, decoded and written to disk at install"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io/",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "CanisterWorm (ICP canister C2, npm token worm)",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall drops a base64-decoded Python backdoor and installs it as a persistent systemd user service that polls an ICP canister for binaries to download and run. It then harvests npm tokens and, when any are found, launches a detached script that republishes every package the token's account maintains with this payload.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "c0834f759f5dfe94"
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
        "candidate": "q_c6a7742791",
        "reason_code": "duplicate_of",
        "note": "try around npm config get only adds to the token set; the decision is the tokens.length > 0 guard at index.js:88 (g1)",
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
        "note": "if on configToken only adds to the token set; the decision is the tokens.length > 0 guard at index.js:88 (g1)",
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
        "candidate": "k_4023412a83",
        "reason_code": "not_environmental",
        "note": "existsSync on scripts/deploy.js, a file the package ships; always true",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 4512,
          "end_byte": 4539,
          "node_type": "call_expression",
          "sha256": "af7226c4526ac718",
          "line": 90
        }
      },
      {
        "candidate": "q_7a5d11e5ee",
        "reason_code": "not_environmental",
        "note": "if on existsSync of the package's own scripts/deploy.js; always true",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 4508,
          "end_byte": 4738,
          "node_type": "if_statement",
          "sha256": "46ce81c44ce89ca8",
          "line": 90
        }
      },
      {
        "candidate": "k_bca9f38bb4",
        "reason_code": "not_environmental",
        "note": "existsSync of the package's own README.md to back it up before swapping it; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2060,
          "end_byte": 2085,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 60
        }
      },
      {
        "candidate": "k_36f8487214",
        "reason_code": "not_environmental",
        "note": "existsSync of the package's own README.md during cleanup after publish; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2768,
          "end_byte": 2793,
          "node_type": "call_expression",
          "sha256": "af6d6c5a21179766",
          "line": 71
        }
      },
      {
        "candidate": "q_1cf3c7b7df",
        "reason_code": "not_environmental",
        "note": "ternary backing up the package's own README.md; same behaviour either way",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2060,
          "end_byte": 2130,
          "node_type": "ternary_expression",
          "sha256": "e371a190f45cc7ff",
          "line": 60
        }
      },
      {
        "candidate": "q_505f4df0cc",
        "reason_code": "not_environmental",
        "note": "cleanup of a README the worm wrote itself; plumbing",
        "anchor": {
          "file": "scripts/deploy.js",
          "derived_from": null,
          "start_byte": 2754,
          "end_byte": 2821,
          "node_type": "if_statement",
          "sha256": "f67b09332785ce40",
          "line": 71
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 7,
    "condition_sites_cited": 4,
    "guards_cited": 0,
    "candidates_dropped": 8,
    "conditions_in_set": 4,
    "conditions_out_of_set": 5,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c7",
      "c8",
      "c9",
      "c10",
      "c11",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
