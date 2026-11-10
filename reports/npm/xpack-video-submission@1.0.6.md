# npm xpack-video-submission@1.0.6

**Source:** datadog · **Source label:** malicious · **Released:** 2026-02-07 (registry) · **Assessment:** suspicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

npm runs `node ./preinstall.js` on every install. With no gate in front, the script reads the user's GitHub username from `git config --global user.email`/`user.name`, `git remote get-url origin` and `ssh -T git@github.com`, hashes hostname plus platform into a device id, and POSTs both with the package's embedded project id and API key to hxxps://hack-money-xpack[.]vercel[.]app/api/install/start. All further behaviour depends on the server's answer (out-of-scope `server_response` conditions): a 402 opens a pay or help page in the browser (g1) and, unless the reason is about GitHub identity, polls `/api/install/status` with the same data for up to 5 minutes (g2); a 401 opens the dashboard (g4). Once the server reports `allowed`, and npm was started in a folder other than the project root (`INIT_CWD` set, existing and different from the root above `node_modules`), it reruns `npm init -y` / `npm install --ignore-scripts` there and exits 1 (g3). Any other outcome exits 1, so the install only completes after the server confirms payment.

## Execution

- **preinstall** `node ./preinstall.js`: runs preinstall.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c5 && c6 && c9 (c5: server_response not_startswith <!doctype; c6: server_response not_startswith <html; c9: server_response == 402) | then | 3 | spawn_process | network=hack-money-xpack[.]vercel[.]app:443=reachable |
| g2 | preinstall | c5 && c6 && c9 && c10 (c5: server_response not_startswith <!doctype; c6: server_response not_startswith <html; c9: server_response == 402; c10: server_response not_regex /github\|subscription/i) | then | 4 | exfil | network=hack-money-xpack[.]vercel[.]app:443=reachable |
| g3 | preinstall | c5 && c6 && ((c7 && c8) \|\| (c9 && c10 && c8)) && c1 && c2 && c3 && c4 (c5: server_response not_startswith <!doctype; c6: server_response not_startswith <html; c7: server_response == 200; c8: server_response == allowed; c9: server_response == 402; c10: server_response not_regex /github\|subscription/i; c1: home_or_path includes node_modules; c2: process.env.INIT_CWD truthy; c3: file_or_dir_exists exists %INIT_CWD%; c4: home_or_path != %INIT_CWD% (project root two levels above cwd differs from INIT_CWD)) | then | 8 | spawn_process | env_var=INIT_CWD=(set); file_present=%INIT_CWD%; installed_tool=npm; network=hack-money-xpack[.]vercel[.]app:443=reachable |
| g4 | preinstall | c5 && c6 && c11 (c5: server_response not_startswith <!doctype; c6: server_response not_startswith <html; c11: server_response == 401) | then | 3 | spawn_process | network=hack-money-xpack[.]vercel[.]app:443=reachable |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/unclear; g3 activate/enables/unclear; g4 activate/enables/unclear

Grounding: 3 of 11 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, c8, c9, c10, c11, g1, g2, g3, g4.

## Requirements

- network: hack-money-xpack[.]vercel[.]app:443 (POST to /api/install/start (and /api/install/status polling); a failed fetch rejects startInstall and the catch exits 1)
- runtime_version: node>=18 (uses the global fetch; on older node the call throws and the install exits 1)
- installed_tool: git, ssh (GitHub identity lookup; failures are swallowed but nothing is collected without them)
- installed_tool: npm (npm init / npm install --ignore-scripts in INIT_CWD (g3))
- installed_tool: xdg-open (browser open on linux (open on darwin, cmd start on win32) for g1 and g4)

## Behaviour

- Ungated: recon, exfil
- Gated: spawn_process, exfil

## Notes

- OS checks only pick the console device or the browser opener (`open`, `start`, `xdg-open`). I treated them as plumbing and dropped them, along with the `XPACK_DEBUG_OPEN` log switch.
- The browser opens from inside a `setTimeout` callback (non-TTY) or a readline `line` handler, Both callbacks sit inside `waitForEnterThenOpenUrl` and call `openInBrowser` directly, so the payload paths in g1 and g4 are traced to the `exec` sink.
- In g3, `npm init -y` runs only when the target folder has no `package.json`. I treated that check as plumbing, because the `npm install` spawn that follows runs either way.
- Every gate is out of set, because the decisions are server-response tests plus the install-root comparison at line 291.
- Labelling: this is a pay-to-install scheme that collects GitHub identity. It downloads and executes nothing and reads no secrets. I assessed it as suspicious, against the source label malicious.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "xpack-video-submission",
    "version": "1.0.6",
    "archive_sha256": "cab507bc6306c32019d4daa68eba2eadd1912c9b8f284512f1a39bb60ec484e8",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-02-07",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-02-07-xpack-video-submission-v1.0.6.zip",
    "package_root": "layer0/tmp/tmpnk_f0gk9/xpack-video-submission/package",
    "cluster_key": "cc889b14f361f1e0d09f6146cf31c4659a05091bcd3229703386b9af6f6480de",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node ./preinstall.js",
        "runs_on": "always",
        "file_chain": [
          "preinstall.js"
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
        "site": "preinstall.js:71",
        "seconds": 1.8
      },
      {
        "site": "preinstall.js:212",
        "seconds": 2.5
      }
    ],
    "notes": [
      "preinstall.js: package code, 603 lines, read in full; no bundled code, nothing unread.",
      "Ungated: getGitHubIdentity() runs git config --global user.email / user.name, git remote get-url origin and ssh -T git@github.com, then POSTs projectId, apiKey, a sha256 of hostname+platform and the GitHub username to <host>/api/install/start.",
      "Host, projectId and apiKey come from the package's own package.json xpack block (apiKey pay_c7d7…). The !projectId || !apiKey exit tests package data, not the environment, so it is not a gate.",
      "Every outcome except a server 'allowed' answer ends in process.exit(1), which fails the npm install: an install-time paywall. Browser opening (open/start/xdg-open) is plumbing per OS; same behaviour on all three.",
      "The identity source chain (noreply email, single-word user.name, origin remote, ssh greeting) is data collection: each branch only changes which username is sent.",
      "g3 sits partly in the 402 path after pollUntilPaid; installInDirectory runs npm init -y only when INIT_CWD lacks package.json (plumbing), then npm install --ignore-scripts <self> there either way; both are execSync spawns, no file write.",
      "Server-response conditions (status 200/402/401, data.status, payload.reason, HTML sniff) are out of scope but kept so Phase 2 sees that browser open, polling and reinstall need a cooperating server."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "hack-money-xpack[.]vercel[.]app:443",
      "reason": "POST to /api/install/start (and /api/install/status polling); a failed fetch rejects startInstall and the catch exits 1"
    },
    {
      "axis": "runtime_version",
      "value": "node>=18",
      "reason": "uses the global fetch; on older node the call throws and the install exits 1"
    },
    {
      "axis": "installed_tool",
      "value": [
        "git",
        "ssh"
      ],
      "reason": "GitHub identity lookup; failures are swallowed but nothing is collected without them"
    },
    {
      "axis": "installed_tool",
      "value": [
        "npm"
      ],
      "reason": "npm init / npm install --ignore-scripts in INIT_CWD (g3)"
    },
    {
      "axis": "installed_tool",
      "value": [
        "xdg-open"
      ],
      "reason": "browser open on linux (open on darwin, cmd start on win32) for g1 and g4"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "home_or_path",
      "api": "process.cwd()",
      "operator": "includes",
      "value": "node_modules",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_d4ba1acd08",
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 4480,
            "end_byte": 4508,
            "node_type": "call_expression",
            "sha256": "b87204ced1ab2474",
            "line": 130
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "package_manager",
      "api": "process.env.INIT_CWD",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_5946adfc6b",
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 4912,
            "end_byte": 4915,
            "node_type": "identifier",
            "sha256": "d7439bee24773bcb",
            "line": 144
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
      "value": "%INIT_CWD%",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b81b79f3ad",
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 5020,
            "end_byte": 5043,
            "node_type": "call_expression",
            "sha256": "141d045ea379d27b",
            "line": 147
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "home_or_path",
      "api": "path.resolve",
      "operator": "!=",
      "value": "%INIT_CWD% (project root two levels above cwd differs from INIT_CWD)",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 10214,
            "end_byte": 10265,
            "node_type": "binary_expression",
            "sha256": "d9fa11965970c711",
            "line": 291
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "server_response",
      "api": "response.text().startsWith",
      "operator": "not_startswith",
      "value": "<!doctype",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12409,
            "end_byte": 12467,
            "node_type": "call_expression",
            "sha256": "77651c734e0852f4",
            "line": 354
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "server_response",
      "api": "response.text().startsWith",
      "operator": "not_startswith",
      "value": "<html",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12474,
            "end_byte": 12528,
            "node_type": "call_expression",
            "sha256": "8e568dd70f2685b6",
            "line": 355
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "response.status",
      "operator": "==",
      "value": 200,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13316,
            "end_byte": 13339,
            "node_type": "binary_expression",
            "sha256": "586c7bac5e18f4ef",
            "line": 373
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "server_response",
      "api": "JSON.parse(response.text()).status",
      "operator": "==",
      "value": "allowed",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13404,
            "end_byte": 13429,
            "node_type": "binary_expression",
            "sha256": "82440c8c9d4db8f5",
            "line": 376
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 7283,
            "end_byte": 7308,
            "node_type": "binary_expression",
            "sha256": "82440c8c9d4db8f5",
            "line": 209
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "server_response",
      "api": "response.status",
      "operator": "==",
      "value": 402,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 14707,
            "end_byte": 14730,
            "node_type": "binary_expression",
            "sha256": "d1f20282d489f5f8",
            "line": 409
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "server_response",
      "api": "RegExp.test(payload.reason)",
      "operator": "not_regex",
      "value": "/github|subscription/i",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 15663,
            "end_byte": 15698,
            "node_type": "call_expression",
            "sha256": "a54fec861191c040",
            "line": 432
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "server_response",
      "api": "response.status",
      "operator": "==",
      "value": 401,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 20378,
            "end_byte": 20401,
            "node_type": "binary_expression",
            "sha256": "5e733a24ab45b77d",
            "line": 557
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c5 && c6 && c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12533,
            "end_byte": 13309,
            "node_type": "if_statement",
            "sha256": "96e6972fd216bc2e",
            "line": 357
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 14703,
            "end_byte": 20274,
            "node_type": "if_statement",
            "sha256": "bfd236574bfeb001",
            "line": 409
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "server answers 402 (payment required); the script then opens the pay or help page in the user's browser",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "network": {
            "hack-money-xpack[.]vercel[.]app:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 14736,
            "end_byte": 20271,
            "node_type": "stmt_range",
            "sha256": "2af758f23096efd7",
            "line": 410
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 1824,
              "end_byte": 2006,
              "node_type": "call_expression",
              "sha256": "023ea4077844688e",
              "line": 49
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 18289,
                  "end_byte": 18320,
                  "node_type": "call_expression",
                  "sha256": "30013272aaf72d33",
                  "line": 506
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 2409,
                  "end_byte": 3201,
                  "node_type": "function_declaration",
                  "sha256": "fc1c632acb670124",
                  "line": 63
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 2827,
                  "end_byte": 2845,
                  "node_type": "call_expression",
                  "sha256": "6ff4855725a4b33d",
                  "line": 72
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 1296,
                  "end_byte": 2009,
                  "node_type": "function_declaration",
                  "sha256": "2393f09d6dcebdae",
                  "line": 34
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
      "hook": "preinstall",
      "expression": "c5 && c6 && c9 && c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12533,
            "end_byte": 13309,
            "node_type": "if_statement",
            "sha256": "96e6972fd216bc2e",
            "line": 357
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 14703,
            "end_byte": 20274,
            "node_type": "if_statement",
            "sha256": "bfd236574bfeb001",
            "line": 409
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 15703,
            "end_byte": 16650,
            "node_type": "if_statement",
            "sha256": "6ea6eaa8f96551d1",
            "line": 434
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "402 with a session (reason not about GitHub identity) starts up to 5 minutes of status polling that resends the fingerprint and GitHub username",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "network": {
            "hack-money-xpack[.]vercel[.]app:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 18914,
            "end_byte": 18974,
            "node_type": "lexical_declaration",
            "sha256": "6efbc5f0c59b5ebd",
            "line": 523
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 7007,
              "end_byte": 7167,
              "node_type": "call_expression",
              "sha256": "3e7c3bf40be39a26",
              "line": 201
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 18936,
                  "end_byte": 18973,
                  "node_type": "call_expression",
                  "sha256": "b2c2511fa36a6c26",
                  "line": 523
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 6848,
                  "end_byte": 7425,
                  "node_type": "function_declaration",
                  "sha256": "e0cc276b15afad8e",
                  "line": 197
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
      "hook": "preinstall",
      "expression": "c5 && c6 && ((c7 && c8) || (c9 && c10 && c8)) && c1 && c2 && c3 && c4",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12533,
            "end_byte": 13309,
            "node_type": "if_statement",
            "sha256": "96e6972fd216bc2e",
            "line": 357
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13312,
            "end_byte": 14700,
            "node_type": "if_statement",
            "sha256": "ae74a0660dfb8003",
            "line": 373
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13392,
            "end_byte": 14533,
            "node_type": "if_statement",
            "sha256": "28a68d63829dc3c9",
            "line": 376
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13566,
            "end_byte": 14456,
            "node_type": "if_statement",
            "sha256": "16d714394f003ab7",
            "line": 378
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 14703,
            "end_byte": 20274,
            "node_type": "if_statement",
            "sha256": "bfd236574bfeb001",
            "line": 409
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 15703,
            "end_byte": 16650,
            "node_type": "if_statement",
            "sha256": "6ea6eaa8f96551d1",
            "line": 434
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
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 18977,
            "end_byte": 20128,
            "node_type": "if_statement",
            "sha256": "3d43f0b8fa202bca",
            "line": 524
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 19075,
            "end_byte": 19904,
            "node_type": "if_statement",
            "sha256": "8f5c0b2ede9a02b1",
            "line": 527
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "after the server allows the install, reinstalls the package with npm into the folder npm was started from when that differs from the project root, then aborts the original install",
      "then": {
        "min_conditions": 8,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "env_var": {
            "INIT_CWD": null
          },
          "file_present": [
            "%INIT_CWD%"
          ],
          "installed_tool": [
            "npm"
          ],
          "network": {
            "hack-money-xpack[.]vercel[.]app:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 13618,
            "end_byte": 14450,
            "node_type": "stmt_range",
            "sha256": "e723968f8d607d52",
            "line": 379
          },
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 19224,
            "end_byte": 19899,
            "node_type": "stmt_range",
            "sha256": "b97e50bcb8eb6154",
            "line": 529
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 6094,
              "end_byte": 6158,
              "node_type": "call_expression",
              "sha256": "f0a5bb8ca8550384",
              "line": 172
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 13857,
                  "end_byte": 13918,
                  "node_type": "call_expression",
                  "sha256": "e82707e717a699d6",
                  "line": 387
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 5520,
                  "end_byte": 6245,
                  "node_type": "function_declaration",
                  "sha256": "676237f769d82c57",
                  "line": 158
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c5 && c6 && c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 12533,
            "end_byte": 13309,
            "node_type": "if_statement",
            "sha256": "96e6972fd216bc2e",
            "line": 357
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 20374,
            "end_byte": 21210,
            "node_type": "if_statement",
            "sha256": "6b21199efacfa0b1",
            "line": 557
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "server answers 401 (bad project or key); the script opens the dashboard URL in the user's browser and exits 1",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "network": {
            "hack-money-xpack[.]vercel[.]app:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "preinstall.js",
            "derived_from": null,
            "start_byte": 20407,
            "end_byte": 21207,
            "node_type": "stmt_range",
            "sha256": "d3b106ad8c1e56c7",
            "line": 558
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "preinstall.js",
              "derived_from": null,
              "start_byte": 1824,
              "end_byte": 2006,
              "node_type": "call_expression",
              "sha256": "023ea4077844688e",
              "line": 49
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 21106,
                  "end_byte": 21139,
                  "node_type": "call_expression",
                  "sha256": "56d4bb185a0d4712",
                  "line": 580
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 2409,
                  "end_byte": 3201,
                  "node_type": "function_declaration",
                  "sha256": "fc1c632acb670124",
                  "line": 63
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 2827,
                  "end_byte": 2845,
                  "node_type": "call_expression",
                  "sha256": "6ff4855725a4b33d",
                  "line": 72
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "preinstall.js",
                  "derived_from": null,
                  "start_byte": 1296,
                  "end_byte": 2009,
                  "node_type": "function_declaration",
                  "sha256": "2393f09d6dcebdae",
                  "line": 34
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
      "recon",
      "exfil"
    ],
    "gated": [
      "spawn_process",
      "exfil"
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
        "indicator": "hxxps://hack-money-xpack[.]vercel[.]app/api/install/start",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://hack-money-xpack[.]vercel[.]app/api/install/status",
        "role": "c2"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "xpack install paywall",
  "claude_assessment": "suspicious",
  "assessment_reason": "The preinstall script fingerprints the device (sha256 of hostname and platform), harvests the user's GitHub username from git config, the origin remote and an ssh -T probe, and sends it with an embedded API key to a remote server. It fails the install unless the server reports payment, opens browser pages and can rerun npm in another folder; no code is downloaded or run and no secrets are read.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Paywall-style preinstall that collects GitHub identity: decide whether this belongs in the malicious set (source label malicious, assessment suspicious).",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "51fb2f42b91dd947"
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
        "candidate": "k_a07baa46f8",
        "reason_code": "log_only",
        "note": "win32 picks CON vs /dev/tty as the UI output stream",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 335,
          "end_byte": 363,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 11
        }
      },
      {
        "candidate": "q_01412ef4bc",
        "reason_code": "log_only",
        "note": "win32 picks CON vs /dev/tty as the UI output stream",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 331,
          "end_byte": 615,
          "node_type": "if_statement",
          "sha256": "7bbe94c838c52d70",
          "line": 11
        }
      },
      {
        "candidate": "k_0ef145f071",
        "reason_code": "log_only",
        "note": "win32 only adds a stderr line and flush",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 10836,
          "end_byte": 10864,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 303
        }
      },
      {
        "candidate": "q_b4b5d8a7a4",
        "reason_code": "log_only",
        "note": "win32 only adds a stderr line and flush",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 10832,
          "end_byte": 10942,
          "node_type": "if_statement",
          "sha256": "60efc1792127f5d6",
          "line": 303
        }
      },
      {
        "candidate": "k_b470b1c9e8",
        "reason_code": "other",
        "note": "plumbing: picks the OS browser opener (open/start/xdg-open); same behaviour on every OS",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1411,
          "end_byte": 1428,
          "node_type": "binary_expression",
          "sha256": "39ffb689a221f09a",
          "line": 38
        }
      },
      {
        "candidate": "q_c8dcab0872",
        "reason_code": "other",
        "note": "plumbing: picks the OS browser opener (open/start/xdg-open); same behaviour on every OS",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1407,
          "end_byte": 1717,
          "node_type": "if_statement",
          "sha256": "69a355b6dfe4f6d2",
          "line": 38
        }
      },
      {
        "candidate": "k_085813f98d",
        "reason_code": "other",
        "note": "plumbing: picks the OS browser opener (open/start/xdg-open); same behaviour on every OS",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1490,
          "end_byte": 1506,
          "node_type": "binary_expression",
          "sha256": "58b302b0e4817ccb",
          "line": 40
        }
      },
      {
        "candidate": "q_e20d794684",
        "reason_code": "other",
        "note": "plumbing: picks the OS browser opener (open/start/xdg-open); same behaviour on every OS",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1486,
          "end_byte": 1717,
          "node_type": "if_statement",
          "sha256": "2f34a43e51925f25",
          "line": 40
        }
      },
      {
        "candidate": "k_01cfd88f1c",
        "reason_code": "log_only",
        "note": "XPACK_DEBUG_OPEN only enables console.log lines",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 940,
          "end_byte": 976,
          "node_type": "binary_expression",
          "sha256": "27631924b3fa76b9",
          "line": 27
        }
      },
      {
        "candidate": "k_4efdc1ae62",
        "reason_code": "log_only",
        "note": "XPACK_DEBUG_OPEN only enables console.log lines",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 980,
          "end_byte": 1019,
          "node_type": "binary_expression",
          "sha256": "846a87e8244de669",
          "line": 27
        }
      },
      {
        "candidate": "q_4e2ff93596",
        "reason_code": "log_only",
        "note": "XPACK_DEBUG_OPEN only enables console.log lines",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1719,
          "end_byte": 1822,
          "node_type": "if_statement",
          "sha256": "62e1fe659208b899",
          "line": 46
        }
      },
      {
        "candidate": "q_0665c45202",
        "reason_code": "log_only",
        "note": "XPACK_DEBUG_OPEN only enables a stderr console.log",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 1933,
          "end_byte": 1998,
          "node_type": "if_statement",
          "sha256": "3cb5316ba4c3a349",
          "line": 52
        }
      },
      {
        "candidate": "k_a8fa080037",
        "reason_code": "other",
        "note": "plumbing: releasePackageDirLock chdirs out of node_modules/<pkg> so npm can rename it",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 6568,
          "end_byte": 6596,
          "node_type": "call_expression",
          "sha256": "b87204ced1ab2474",
          "line": 186
        }
      },
      {
        "candidate": "q_8c8f712047",
        "reason_code": "other",
        "note": "plumbing: releasePackageDirLock chdirs out of node_modules/<pkg> so npm can rename it",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 6564,
          "end_byte": 6685,
          "node_type": "if_statement",
          "sha256": "085dd9c2f03888bc",
          "line": 186
        }
      },
      {
        "candidate": "q_c826db2caa",
        "reason_code": "other",
        "note": "helper-internal test computing installRoot (c1); the decision is the installInSameDir if in g3",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 4476,
          "end_byte": 4556,
          "node_type": "if_statement",
          "sha256": "7bd5a8bf6a240366",
          "line": 130
        }
      },
      {
        "candidate": "q_d8dc1ce2c2",
        "reason_code": "other",
        "note": "helper-internal return in getInitCwd computing initCwd (c2); the decision is the installInSameDir if in g3",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 4907,
          "end_byte": 4956,
          "node_type": "if_statement",
          "sha256": "c6a99324db1408a6",
          "line": 144
        }
      },
      {
        "candidate": "q_65a367a22f",
        "reason_code": "other",
        "note": "helper-internal return in getInitCwd computing initCwd (c3); the decision is the installInSameDir if in g3",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 5004,
          "end_byte": 5061,
          "node_type": "if_statement",
          "sha256": "fa2f52a210166e9e",
          "line": 147
        }
      },
      {
        "candidate": "k_fab89e0c8c",
        "reason_code": "other",
        "note": "plumbing: npm init -y only creates the package.json the following npm install needs",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 5699,
          "end_byte": 5729,
          "node_type": "call_expression",
          "sha256": "8d6b5b49d010f2ac",
          "line": 161
        }
      },
      {
        "candidate": "q_3de2653ab9",
        "reason_code": "other",
        "note": "plumbing: npm init -y only creates the package.json the following npm install needs",
        "anchor": {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 5694,
          "end_byte": 5913,
          "node_type": "if_statement",
          "sha256": "59c77407845d6f92",
          "line": 161
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 11,
    "condition_sites_cited": 3,
    "guards_cited": 0,
    "candidates_dropped": 19,
    "conditions_in_set": 3,
    "conditions_out_of_set": 8,
    "guard_candidates": 11,
    "gates_in_set": 0,
    "gates_out_of_set": 4,
    "out_of_set_ids": [
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "c9",
      "c10",
      "c11",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
