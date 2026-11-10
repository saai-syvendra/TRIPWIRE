# npm @asyncapi/specs@6.8.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is the legitimate `@asyncapi/specs` package with the Shai-Hulud ("Sha1-Hulud: The Second Coming") worm injected. A `preinstall` hook runs `node setup_bun.js`, which installs the Bun runtime (via `curl|bash` on unix or `powershell irm|iex` on win32) and then launches the 10 MB, obfuscator.io-packed `bun_environment.js` under Bun. That worm is the payload: it harvests npm, GitHub and AWS/GCP/Azure credentials, exfiltrates them (triple base64) into attacker-created GitHub repos, trojanises the maintainer's other npm packages, and plants secret-stealing GitHub Actions workflows plus a self-hosted runner. Two real environment gates sit in the payload: on a Linux GitHub Actions runner where the StepSecurity Harden-Runner monitoring agent runs and sudo works, it stops systemd-resolved and flushes iptables to defeat DNS/egress controls (`g1`, activate); and when it has no working exfil repo (no GitHub token, or repo creation failed), no attacker C2 fallback token and no npm token, it recursively shreds the user's home directory instead of stealing (`g2`, destructive). Everything in `setup_bun.js` is Bun-runtime install/launch plumbing and was dropped as non-gates.

## Execution

- **preinstall** `node setup_bun.js`: 2-file chain; direct_script, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c7 && c8 && c9 && c10 (c7: process.env.GITHUB_ACTIONS truthy; c8: process.env.RUNNER_OS == Linux; c9: process_list exists; c10: privilege exists) | then | 4 | defense_evasion | os=linux; ci=true; env_var=GITHUB_ACTIONS=true, RUNNER_OS=Linux; privilege=root_or_admin |
| g2 | preinstall | ((c11 && c12) \|\| c16) && c15 && c13 && c14 (c11: Object.entries(process.env) not_startswith [ghp_, gho_]; c12: installed_tool not_startswith [gho_, ghp_]; c16: server_response falsy; c15: server_response falsy; c13: process.env.NPM_TOKEN falsy; c14: target_artifact falsy) | then | 4 | destructive | env_var_absent=NPM_TOKEN; file_absent=~/.npmrc, ./.npmrc |

Gate intent: g1 activate/enables/anti_analysis; g2 activate/enables/data_availability

Grounding: 4 of 10 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c11, c12, c13, c14, c15, c16, g1, g2.

## Requirements

- network: bun[.]sh:443, github[.]com:443, api[.]github[.]com:443, raw[.]githubusercontent[.]com:443, registry[.]npmjs[.]org:443 (Downloads the Bun runtime and GitHub Actions runner, discovers a fallback token, exfiltrates stolen data through attacker-created GitHub repos, and republishes trojanised packages to the npm registry.)
- installed_tool: curl (Downloads the Bun installer and runner/trufflehog tarballs on unix.)
- installed_tool: bash (Runs the Bun install script and the detached runner launch.)
- installed_tool: tar (Extracts the downloaded GitHub Actions runner and trufflehog archives.)

## Behaviour

- Ungated: recon, cred_read, exfil, download, exec_downloaded, spawn_process, write_file, self_propagation, persistence
- Gated: defense_evasion, destructive

## Notes

- The obfuscator.io string table decoded cleanly (derivation `d1`, rotation checksum matched, 180085/180085 decoder calls resolved); analysis is against that recovered copy. The worm code was read in full; bundled AWS/GCP/Azure/Octokit/undici/tar SDKs were audited by sink inventory with every network hit explained, so nothing is left unread. The prefilled `obfuscation.unrecovered` entries were removed on that basis.
- The prefilled endpoint list was almost entirely bundled-SDK documentation and metadata URLs; it was trimmed to the six channels the worm actually uses (bun.sh, GitHub web/API, raw.githubusercontent.com C2, npm registry, actions/runner download).
- Both gates are out of set (candidate `null`): the extractor never chained `bun_environment.js`, so its conditions and guards were added by hand. `g2`'s C2 condition (`c15`, a falsy result from `fetchToken()`, which searches GitHub, fetches and parses `contents.json` and validates the token) and repo-creation check (`c16`, `repoExists()` false after an authenticated `createRepo`) are `server_response` checks (out of scope). The wipe guard is `!isAuthenticated() || !repoExists()`, so either no GitHub token (`c11 && c12`: no environment value and no `gh auth token` output starts with `ghp_` or `gho_`) or a failed repo creation (`c16`) opens it, together with no C2 token and no npm token (`NPM_TOKEN` or an `_authToken` in `./.npmrc` or `~/.npmrc`, read with `fs/promises.readFile`).
- Entry `jy1()` either runs the payload in the foreground (any CI marker set) or respawns itself detached with `POSTINSTALL_BG=1`; that is foreground-vs-background plumbing and `POSTINSTALL_BG` is a re-entry guard, not a gate.
- Static analysis only; nothing was installed, run or fetched. The destructive wipe (`g2`) is a notable risk for a bare scanning VM, which by default has none of the four credential sources and no reachable C2.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@asyncapi/specs",
    "version": "6.8.2",
    "archive_sha256": "30ac614c0afa6ee935e1dd40ac14790453b59cd1d9ba00e85a23ed586ebfbe93",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-11-24-@asyncapi_specs-v6.8.2.zip",
    "package_root": "layer0/tmp/tmp2lgjiddf/@asyncapi-specs/package",
    "cluster_key": "41b6d04f32339b9bd0f5b0c9d17583f8190922879149752b2335185af17e83e2",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node setup_bun.js",
        "runs_on": "always",
        "file_chain": [
          "setup_bun.js",
          "bun_environment.js"
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
      "setup_bun.js: package code read in full. It installs Bun (curl|bash on unix, powershell irm|iex on win32) then runs bun_environment.js through Bun. Its platform/path/exists checks only locate or install the Bun runtime, so they are plumbing and were dropped, not gates.",
      "bun_environment.js (10.1 MB): obfuscator.io string array fully recovered (d1, checksum matched, 180085/180085 calls resolved). Worm package code read in full; bundled AWS/GCP/Azure/Octokit/undici/tar SDKs audited by sink inventory, all hits explained; nothing unread.",
      "not_chained resolved: setup_bun.js:182 runs bun_environment.js via Bun, so it is added to the preinstall file_chain.",
      "jy1() entry: if any CI marker (BUILDKITE/PROJECT_ID/GITHUB_ACTIONS/CODEBUILD/CIRCLE_SHA1) is set it runs aL0 in the foreground, else it respawns detached with POSTINSTALL_BG=1. That only changes foreground vs background (plumbing); POSTINSTALL_BG is a re-entry guard for its own child.",
      "g2 wipe picks a per-OS command (cmd.exe del + cipher on win32, bash shred on unix), portability within the same destructive behaviour; both are recorded as destructive sinks.",
      "El(npmToken) (npm worm propagation) is also called unconditionally later in aL0, so self_propagation is listed as ungated; the copy inside g2's credential branch is redundant.",
      "No live eval of unrecovered code: eval/Function/vm/child_process appear only inside the embedded setup_bun.js source string (carried for re-infection); the dynamic_eval signal originates in bundled SDKs.",
      "createRepo sleeps ~3s (setTimeout 3000) after creating the exfil repo and polls victim workflow runs on ~2s intervals up to ~30s; not recorded as gates."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "bun[.]sh:443",
        "github[.]com:443",
        "api[.]github[.]com:443",
        "raw[.]githubusercontent[.]com:443",
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "Downloads the Bun runtime and GitHub Actions runner, discovers a fallback token, exfiltrates stolen data through attacker-created GitHub repos, and republishes trojanised packages to the npm registry."
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "Downloads the Bun installer and runner/trufflehog tarballs on unix."
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "Runs the Bun install script and the detached runner launch."
    },
    {
      "axis": "installed_tool",
      "value": "tar",
      "reason": "Extracts the downloaded GitHub Actions runner and trufflehog archives."
    }
  ],
  "conditions": [
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1cd5d2d80d",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9315036,
            "end_byte": 9315068,
            "node_type": "subscript_expression",
            "sha256": "9871240e9d135b2b",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f77e593894",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9315070,
            "end_byte": 9315107,
            "node_type": "binary_expression",
            "sha256": "06025cefa0c4d1e8",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c9",
      "category": "process_list",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_6c5d51702a",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8808519,
            "end_byte": 8808572,
            "node_type": "call_expression",
            "sha256": "4c25ddb99e78903a",
            "line": 1
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "ps -axco command | grep \"/home/agent/agent\"",
        "accessor": "throws"
      }
    },
    {
      "id": "c10",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_9bf49f4b9b",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8809019,
            "end_byte": 8809041,
            "node_type": "call_expression",
            "sha256": "c376285de89a8a95",
            "line": 1
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "sudo -n true",
        "accessor": "throws"
      }
    },
    {
      "id": "c11",
      "category": "env_var",
      "api": "Object.entries(process.env)",
      "operator": "not_startswith",
      "value": [
        "ghp_",
        "gho_"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9029872,
            "end_byte": 9029906,
            "node_type": "call_expression",
            "sha256": "33119500fb159d6c",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "installed_tool",
      "api": "Bun.spawnSync",
      "operator": "not_startswith",
      "value": [
        "gho_",
        "ghp_"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9030157,
            "end_byte": 9030221,
            "node_type": "binary_expression",
            "sha256": "e375a10eb111fe8e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "Bun.spawnSync",
        "target": "gh auth token",
        "accessor": "stdout"
      }
    },
    {
      "id": "c13",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316344,
            "end_byte": 9316371,
            "node_type": "subscript_expression",
            "sha256": "7fd2bb3f0c6c093e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "target_artifact",
      "api": "fs/promises.readFile",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9296481,
            "end_byte": 9296510,
            "node_type": "call_expression",
            "sha256": "645cc4458ebdbaaf",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs/promises.readFile",
        "target": "~/.npmrc",
        "accessor": "content"
      }
    },
    {
      "id": "c15",
      "category": "server_response",
      "api": "fetchToken",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316614,
            "end_byte": 9316639,
            "node_type": "call_expression",
            "sha256": "bfea7d65c9eba733",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c16",
      "category": "server_response",
      "api": "repoExists",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316545,
            "end_byte": 9316570,
            "node_type": "call_expression",
            "sha256": "0f2a76b5cd48e686",
            "line": 1
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
      "expression": "c7 && c8 && c9 && c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9315033,
            "end_byte": 9315150,
            "node_type": "if_statement",
            "sha256": "3f1bee526771d9ab",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7",
            "c8"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9315109,
            "end_byte": 9315149,
            "node_type": "if_statement",
            "sha256": "7d0abbfaace97ecd",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9",
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "On a Linux GitHub Actions runner where the StepSecurity Harden-Runner agent (/home/agent/agent) is running and sudo works, it stops systemd-resolved and flushes iptables OUTPUT and DOCKER-USER, disabling the agent's DNS and egress filtering before acting.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "linux",
          "ci": "true",
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux"
          },
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9315137,
            "end_byte": 9315148,
            "node_type": "await_expression",
            "sha256": "5b04134fbc3e3266",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 8809904,
              "end_byte": 8809952,
              "node_type": "call_expression",
              "sha256": "73b0d33ff199aa89",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9315143,
                  "end_byte": 9315148,
                  "node_type": "call_expression",
                  "sha256": "153f29fd30826c3e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 8809570,
                  "end_byte": 8809967,
                  "node_type": "function_declaration",
                  "sha256": "298c0cbf8b43983d",
                  "line": 1
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
      "expression": "((c11 && c12) || c16) && c15 && c13 && c14",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316508,
            "end_byte": 9317581,
            "node_type": "if_statement",
            "sha256": "1709e3648d83eb47",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11",
            "c12",
            "c16"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316640,
            "end_byte": 9317416,
            "node_type": "if_statement",
            "sha256": "256de85575efaa81",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c15"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316655,
            "end_byte": 9317325,
            "node_type": "if_statement",
            "sha256": "730ba37b5f1cd938",
            "line": 1
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c13",
            "c14"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "When it has no usable GitHub exfil repo (no GitHub token from env ghp_/gho_ or gh CLI, or repo creation failed), no attacker C2 fallback token, and no npm token (NPM_TOKEN or .npmrc _authToken), it recursively shreds the user's home directory instead of exfiltrating.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "destructive"
        ],
        "env_recipe": {
          "env_var_absent": [
            "NPM_TOKEN"
          ],
          "file_absent": [
            "~/.npmrc",
            "./.npmrc"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9316837,
            "end_byte": 9317324,
            "node_type": "statement_block",
            "sha256": "14572efc819e7a93",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "destructive",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9317129,
              "end_byte": 9317301,
              "node_type": "call_expression",
              "sha256": "f9fcde4fc0dbccee",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "destructive",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9316905,
              "end_byte": 9317123,
              "node_type": "call_expression",
              "sha256": "482e339a134d2ac0",
              "line": 1
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
      "recon",
      "cred_read",
      "exfil",
      "download",
      "exec_downloaded",
      "spawn_process",
      "write_file",
      "self_propagation",
      "persistence"
    ],
    "gated": [
      "defense_evasion",
      "destructive"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "string array (obfuscator.io, recovered by matching the rotation checksum)",
      "opaque predicate dead branches (constant string comparisons)",
      "hex identifiers",
      "escaped string literals",
      "long base64/hex literals",
      "triple base64 layering of exfiltrated payloads",
      "bundled with cloud and GitHub SDKs",
      "very long single line"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://bun[.]sh/install",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/actions/runner/releases",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://raw[.]githubusercontent[.]com",
        "role": "c2"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/repos/",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud (Sha1-Hulud: The Second Coming)",
  "claude_assessment": "malicious",
  "assessment_reason": "A preinstall hook installs Bun and runs a 10 MB obfuscated worm that steals npm, GitHub and cloud (AWS/GCP/Azure) credentials, exfiltrates them to attacker-created GitHub repos, trojanises the maintainer's other npm packages and plants secret-stealing GitHub Actions workflows and a self-hosted runner. With no credentials present it instead shreds the user's home directory, and on Linux CI runners it disables DNS and firewall controls. This is the Shai-Hulud second-wave worm injected into the legitimate @asyncapi/specs package.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out-of-set gates: both environment gates in bun_environment.js (CI network-control evasion and the credential-absence wipe) were added by hand; their guards and the wipe conditions carry candidate null.",
    "g2 conditions c15 (C2 fallback token) and c16 (exfil repo creation failed) are server_response checks, out of scope; they help open the destructive branch.",
    "env_recipe for g1 cannot express the process-list (Harden-Runner agent) check, and for g2 cannot express the ghp_/gho_ env scan or the gh CLI token absence.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "obfuscatorio_strings",
        "recipe_version": 1,
        "input": {
          "file": "bun_environment.js",
          "derived_from": null
        },
        "params": {
          "provider": "a0_0x47b7",
          "decoder": "a0_0x1d8c",
          "offset": 109,
          "variant": "none",
          "form": "v2",
          "table_size": 24237,
          "rotations": 115,
          "checksum_target": 648178,
          "callables": 14022
        },
        "output_sha256": "e50bf41d709e7005",
        "stats": {
          "calls_total": 180085,
          "substituted": 180085,
          "unresolved": 0
        }
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "978eb5bbe72b5874"
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
        "candidate": "k_fb9a5db8df",
        "reason_code": "other",
        "note": "setup_bun.js platform check in isBunOnPath picks the lookup command (where bun or which bun); plumbing to find the runtime, both branches run the same lookup.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 210,
          "end_byte": 238,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 9
        }
      },
      {
        "candidate": "k_9f2314f1be",
        "reason_code": "other",
        "note": "setup_bun.js platform check in downloadAndSetupBun picks the per-OS Bun installer command; plumbing to install the runtime, both branches install Bun.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 2072,
          "end_byte": 2100,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 69
        }
      },
      {
        "candidate": "k_8243b60281",
        "reason_code": "other",
        "note": "setup_bun.js platform check in reloadPath; picks per-OS PATH refresh, plumbing to find the Bun runtime.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 434,
          "end_byte": 462,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 19
        }
      },
      {
        "candidate": "k_e0dfd8b59b",
        "reason_code": "other",
        "note": "setup_bun.js platform check in findBunExecutable paths; plumbing to locate the Bun runtime.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 2856,
          "end_byte": 2884,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 101
        }
      },
      {
        "candidate": "k_d36ad8d600",
        "reason_code": "other",
        "note": "setup_bun.js fs.existsSync on a shell profile file; plumbing to refresh PATH, both branches continue to the same payload.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 1237,
          "end_byte": 1263,
          "node_type": "call_expression",
          "sha256": "c71212927f1a7da1",
          "line": 41
        }
      },
      {
        "candidate": "k_997be1f6bc",
        "reason_code": "other",
        "note": "setup_bun.js fs.existsSync on a candidate bun path; plumbing to locate the Bun runtime.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 3501,
          "end_byte": 3523,
          "node_type": "call_expression",
          "sha256": "e59b9a241f35f5bf",
          "line": 125
        }
      },
      {
        "candidate": "k_50e0566ba2",
        "reason_code": "other",
        "note": "setup_bun.js fs.existsSync on ~/.bun/bin; plumbing to decide whether to add the Bun bin dir to PATH.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 1838,
          "end_byte": 1862,
          "node_type": "call_expression",
          "sha256": "9027b0f47426878e",
          "line": 59
        }
      },
      {
        "candidate": "k_7f3e4e84a7",
        "reason_code": "other",
        "note": "setup_bun.js PATH.includes(~/.bun/bin); plumbing for PATH refresh, not an environment gate.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 1867,
          "end_byte": 1903,
          "node_type": "call_expression",
          "sha256": "5b6cc47daf2bdfa5",
          "line": 59
        }
      },
      {
        "candidate": "k_8f3faff9a0",
        "reason_code": "other",
        "note": "setup_bun.js fs.existsSync on the shipped bun_environment.js before launching it; prerequisite/plumbing, the file always ships.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 4781,
          "end_byte": 4813,
          "node_type": "call_expression",
          "sha256": "ba53a73f09185f0a",
          "line": 181
        }
      },
      {
        "candidate": "q_85ff2db321",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js isBunOnPath lookup-command ternary (where bun or which bun); plumbing to find the Bun runtime.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 210,
          "end_byte": 266,
          "node_type": "ternary_expression",
          "sha256": "f940ca7f22f7ec10",
          "line": 9
        }
      },
      {
        "candidate": "q_d71e66e7e1",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js platform branch in downloadAndSetupBun that picks the per-OS Bun installer command; runtime-install plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 2068,
          "end_byte": 2329,
          "node_type": "if_statement",
          "sha256": "cda6b5855c483f73",
          "line": 69
        }
      },
      {
        "candidate": "q_53e1d98b0c",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js reloadPath platform branch; PATH-refresh plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 430,
          "end_byte": 1996,
          "node_type": "if_statement",
          "sha256": "b3662ca0a3d1e57b",
          "line": 19
        }
      },
      {
        "candidate": "q_fd4553b6fa",
        "reason_code": "other",
        "note": "Guard for a setup_bun.js platform branch choosing Bun paths; runtime-location plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 2852,
          "end_byte": 3324,
          "node_type": "if_statement",
          "sha256": "4db85fce860c9312",
          "line": 101
        }
      },
      {
        "candidate": "q_98259f004c",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js non-win32 reloadPath branch; PATH-refresh plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 430,
          "end_byte": 1996,
          "node_type": "if_statement",
          "sha256": "b3662ca0a3d1e57b",
          "line": 19
        }
      },
      {
        "candidate": "q_d012987235",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js profile-file existsSync branch; PATH-refresh plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 1233,
          "end_byte": 1678,
          "node_type": "if_statement",
          "sha256": "d65ee713ed1c03fb",
          "line": 41
        }
      },
      {
        "candidate": "q_e8c9ed15f1",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js ~/.bun/bin existsSync+PATH branch; PATH-refresh plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 1834,
          "end_byte": 1977,
          "node_type": "if_statement",
          "sha256": "4b86cbaf58ead841",
          "line": 59
        }
      },
      {
        "candidate": "q_af02d7c460",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js bun-path existsSync branch; runtime-location plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 3497,
          "end_byte": 3554,
          "node_type": "if_statement",
          "sha256": "3792818e41453049",
          "line": 125
        }
      },
      {
        "candidate": "q_ba68018d36",
        "reason_code": "other",
        "note": "Guard for the setup_bun.js bun_environment.js existsSync-before-launch branch; prerequisite/plumbing.",
        "anchor": {
          "file": "setup_bun.js",
          "derived_from": null,
          "start_byte": 4777,
          "end_byte": 4907,
          "node_type": "if_statement",
          "sha256": "d69fd304cc618579",
          "line": 181
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 10,
    "condition_sites_cited": 4,
    "guards_cited": 0,
    "candidates_dropped": 18,
    "conditions_in_set": 4,
    "conditions_out_of_set": 6,
    "guard_candidates": 71,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c11",
      "c12",
      "c13",
      "c14",
      "c15",
      "c16",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
