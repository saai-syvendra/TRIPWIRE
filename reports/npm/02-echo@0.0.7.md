# npm 02-echo@0.0.7

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`02-echo` is a compromised copy of a small `echo` package carrying the Shai-Hulud ("Sha1-Hulud: The Second Coming") worm. Its `preinstall` runs `node setup_bun.js`, which downloads the Bun runtime (`curl hxxps://bun[.]sh/install | bash`, or a PowerShell variant on Windows) and then runs the bundled 9.4 MB obfuscated `bun_environment.js` under Bun. The worm, which runs on every install, downloads the trufflehog binary, scans `$HOME` for secrets, enumerates AWS/GCP/Azure secrets, reads `.npmrc` and every env var, exfiltrates the loot to attacker-controlled GitHub repositories, and republishes the maintainer's other npm packages (self-propagation). A CI check only decides whether the worm runs inline or re-spawns itself detached to outlive the install; both sides run the same worm, so it is plumbing and not a gate. The install-time gates are: a GitHub-Actions-Linux-runner gate that, when the `/home/agent/agent` process is running and the sudo probe passes or its catch fallback ran, tampers with DNS and flushes iptables egress rules (g2); a sudoers write via a privileged docker container that runs on the same runner when the sudo probe throws, because it sits in that probe's catch handler (g4); and a credential-availability gate that destroys the user's home directory when no GitHub token or exfil repository is available and no GitHub or npm token can be recovered (g3).

## Execution

- **preinstall** `node setup_bun.js`: 2-file chain; direct_script, shell_pipe, download_then_exec, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g2 | preinstall | c3 && c6 && c7 && (c8 \|\| c14) (c3: process.env.GITHUB_ACTIONS truthy; c6: process.env.RUNNER_OS == Linux; c7: process_list exists; c8: privilege exists; c14: privilege not_exists) | then | 4 | defense_evasion | ci=true; env_var=GITHUB_ACTIONS=(set), RUNNER_OS=Linux; privilege=root_or_admin |
| g4 | preinstall | c3 && c6 && c7 && c14 (c3: process.env.GITHUB_ACTIONS truthy; c6: process.env.RUNNER_OS == Linux; c7: process_list exists; c14: privilege not_exists) | then | 4 | persistence | ci=true; env_var=GITHUB_ACTIONS=(set), RUNNER_OS=Linux; installed_tool=docker |
| g3 | preinstall | ((c9 && c10) \|\| c15) && c11 && c12 && c13 (c9: process.env not_startswith ghp_/gho_; c10: installed_tool not_startswith gho_/ghp_; c15: server_response falsy; c11: server_response not_exists; c12: process.env.NPM_TOKEN not_exists; c13: target_artifact not_regex (?:_authToken\|:_authToken)=([a-zA-Z0-9\-._~+/]+=*)) | then | 4 | destructive | env_var_absent=NPM_TOKEN; file_absent=~/.npmrc, ./.npmrc |

Gate intent: g2 evade/enables/anti_analysis; g4 activate/enables/targeting; g3 activate/enables/data_availability

Grounding: 4 of 11 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c9, c10, c11, c12, c13, c14, c15, g2, g4, g3.

## Requirements

- network: bun[.]sh:443, api[.]github[.]com:443, github[.]com:443, raw[.]githubusercontent[.]com:443 (Downloads the Bun runtime and the trufflehog binary, and reads/writes attacker GitHub repositories for token recovery and exfiltration.)
- installed_tool: curl (Linux Bun install runs curl hxxps://bun[.]sh/install | bash.)
- installed_tool: bash (Linux Bun install and the destructive shred command run via bash.)
- installed_tool: unzip (Extracts the downloaded trufflehog archive (tar is used for .tar.gz).)

## Behaviour

- Ungated: download, cred_read, recon, exfil, self_propagation, spawn_process
- Gated: defense_evasion, persistence, destructive

## Notes

- `setup_bun.js`'s platform and PATH branches are plumbing (locate/install Bun, refresh PATH); both sides reach the same behaviour, so the tool's prefilled `g1`-`g5` candidates were dropped rather than recorded as gates.
- The CI test in `jy1` was a gate (g1) until repair: its candidates are now dropped as launch plumbing, and the detached re-spawn stays as the ungated `spawn_process`.
- The real gates live in `bun_environment.js`, recovered via derivation `d1` (obfuscator.io string table, rotation checksum matched by `prepare.py`). Worm code was read in full; bundled cloud SDKs were audited as library code by sink inventory.
- `exfil` and `self_propagation` go through octokit/network calls that are not in the extractor's sink set, so they are listed as ungated behaviours (they actually require a stolen credential) rather than gated payloads; see execution notes.
- `g2`, `g3` and `g4` are out-of-set (added by hand from the decoded payload) and the record needs manual review. The destructive home-wipe (g3), the sudoers write (g4) and the DNS tamper (g2) are the highest-impact findings.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "02-echo",
    "version": "0.0.7",
    "archive_sha256": "a3fb60c049272535735cde0df929c982e36b46c494d3e44809f7b4fae3b7059a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-11-24-02-echo-v0.0.7.zip",
    "package_root": "layer0/tmp/tmp3q_od1s5/02-echo/package",
    "cluster_key": "66517858e072b8b19f32bbbd5470ae46664bc84ef0e39f5ebc50e742b28911ea",
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
          "shell_pipe",
          "download_then_exec",
          "dropped_binary",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup_bun.js (preinstall) downloads the Bun runtime (curl hxxps://bun[.]sh/install | bash, or powershell irm on Windows) then runs bun_environment.js under Bun via spawn; all errors are swallowed with process.exit(0).",
      "bun_environment.js added to the preinstall file_chain; it is the payload spawned by setup_bun.js.",
      "bun_environment.js: obfuscator.io string table recovered by prepare.py (d1, checksum matched). Worm code read in full (entry, aL0, Ry1 runner, trufflehog installer, GitHub/npm/cloud credential readers); bundled SDKs audited by sink inventory as library code; nothing unread.",
      "jy1 tests five CI variables: in CI it awaits aL0 inline, otherwise it re-spawns itself detached (Bun.spawn(...).unref()) with POSTINSTALL_BG=1 as a re-entry guard and the child awaits aL0. Both sides run the same worm, so this is launch plumbing, not a gate; candidates dropped.",
      "Ungated when the worm runs: downloads Bun and trufflehog, scans $HOME, enumerates AWS/GCP/Azure secrets, reads .npmrc and env, exfiltrates to attacker GitHub repos, republishes the maintainer's npm packages.",
      "exfil and self_propagation use octokit/network sinks absent from the extractor sink set, so they are listed as ungated behaviours even though they require a stolen credential.",
      "g2: gQ0 (called only when cQ0() && pQ0() is true) stops systemd-resolved, swaps /etc/systemd/resolved.conf and flushes iptables OUTPUT/DOCKER-USER (defense_evasion/DNS). pQ0 is true on a zero sudo exit (c8) or from its catch after the docker call (c14), so g2 reads c8 || c14.",
      "g4: the docker copy of /tmp/runner to /etc/sudoers.d (persistence) sits in the catch of pQ0, the c8 sudo probe, so it runs during the g2 test (after cQ0 is true) when the probe throws. Regions: the pQ0 call in Ry1 (c3, c6, c7) and the catch clause (c14).",
      "g3: the first guard is !isAuthenticated() || !repoExists(). c9 and c10 are the no-token side; c15 is the side where createRepo left gitRepo null, which also holds with a token when repository creation fails.",
      "c14 is the sudo -n true probe throwing; the code does not show why it would, since the shell call uses nothrow.",
      "c13: oL0 reads ./.npmrc then ~/.npmrc through mL0 ((await import('fs/promises')).readFile(path,'utf8')) and matches each line against the _authToken regex; its result is merged with process.env.NPM_TOKEN into one variable tested by if(_0x4692e0).",
      "g3 destructive region: Windows runs cmd.exe del /F /Q /S + cipher /W on %USERPROFILE% (recorded sink); Linux runs bash find $HOME | shred then deletes empty dirs (portability, same behaviour).",
      "g3 c11 fetchToken searches GitHub for repos titled 'Sha1-Hulud: The Second Coming.' and reads contents.json over raw.githubusercontent.com to recover a token: server_response, out of scope.",
      "setup_bun.js platform/PATH branches (tool-prefilled g1-g5) are plumbing that only locates or installs the Bun runtime and refreshes PATH; both sides reach the same behaviour, so their candidates were dropped, not recorded as gates.",
      "bin command 02-echo and lib/echo.js are the impersonated package's own files, not reached at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "bun[.]sh:443",
        "api[.]github[.]com:443",
        "github[.]com:443",
        "raw[.]githubusercontent[.]com:443"
      ],
      "reason": "Downloads the Bun runtime and the trufflehog binary, and reads/writes attacker GitHub repositories for token recovery and exfiltration."
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "Linux Bun install runs curl hxxps://bun[.]sh/install | bash."
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "Linux Bun install and the destructive shred command run via bash."
    },
    {
      "axis": "installed_tool",
      "value": "unzip",
      "reason": "Extracts the downloaded trufflehog archive (tar is used for .tar.gz)."
    }
  ],
  "conditions": [
    {
      "id": "c3",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b166e60983",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9403708,
            "end_byte": 9403740,
            "node_type": "subscript_expression",
            "sha256": "9871240e9d135b2b",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_9ff139d960",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9403742,
            "end_byte": 9403779,
            "node_type": "binary_expression",
            "sha256": "0a604416ad1db2b0",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "process_list",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8146dd1035",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919216,
            "end_byte": 8919269,
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
        "accessor": "stdout"
      }
    },
    {
      "id": "c8",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_78a5a57399",
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919641,
            "end_byte": 8919663,
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
        "accessor": "returncode"
      }
    },
    {
      "id": "c9",
      "category": "env_var",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ghp_/gho_",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9138284,
            "end_byte": 9138318,
            "node_type": "call_expression",
            "sha256": "617707b1a2be8924",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "installed_tool",
      "api": "Bun.spawnSync",
      "operator": "not_startswith",
      "value": "gho_/ghp_",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9138625,
            "end_byte": 9138682,
            "node_type": "call_expression",
            "sha256": "2649ddd5c985d31d",
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
      "id": "c11",
      "category": "server_response",
      "api": "fetchToken",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405494,
            "end_byte": 9405519,
            "node_type": "call_expression",
            "sha256": "70aa9a4ff3a8972d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405246,
            "end_byte": 9405273,
            "node_type": "subscript_expression",
            "sha256": "7fd2bb3f0c6c093e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "target_artifact",
      "api": "fs/promises.readFile",
      "operator": "not_regex",
      "value": "(?:_authToken|:_authToken)=([a-zA-Z0-9\\-._~+/]+=*)",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9383570,
            "end_byte": 9383609,
            "node_type": "call_expression",
            "sha256": "f07e3925a01793df",
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
      "id": "c14",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919641,
            "end_byte": 8919663,
            "node_type": "call_expression",
            "sha256": "c376285de89a8a95",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "sudo -n true",
        "accessor": "throws"
      }
    },
    {
      "id": "c15",
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
            "start_byte": 9405447,
            "end_byte": 9405472,
            "node_type": "call_expression",
            "sha256": "b422da825978d841",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c3 && c6 && c7 && (c8 || c14)",
      "guards": [
        {
          "candidate": "q_8116c95fa1",
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9403705,
            "end_byte": 9404054,
            "node_type": "if_statement",
            "sha256": "7b019cc2bba25f5a",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404012,
            "end_byte": 9404052,
            "node_type": "if_statement",
            "sha256": "7d0abbfaace97ecd",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7",
            "c8",
            "c14"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "On a Linux GitHub Actions runner, when the /home/agent/agent monitoring process is running and pQ0 returns true (sudo -n true exits 0, or its catch fallback ran), it stops systemd-resolved, swaps its config and flushes iptables OUTPUT/DOCKER-USER, disabling the DNS and egress controls that agent relies on.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "defense_evasion"
        ],
        "env_recipe": {
          "ci": "true",
          "env_var": {
            "GITHUB_ACTIONS": null,
            "RUNNER_OS": "Linux"
          },
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404040,
            "end_byte": 9404051,
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
              "start_byte": 8920063,
              "end_byte": 8920109,
              "node_type": "call_expression",
              "sha256": "353341125db00e2f",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9404046,
                  "end_byte": 9404051,
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
                  "start_byte": 8920010,
                  "end_byte": 8920407,
                  "node_type": "function_declaration",
                  "sha256": "60aaa6223fb2b957",
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
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c3 && c6 && c7 && c14",
      "guards": [
        {
          "candidate": "q_8116c95fa1",
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9403705,
            "end_byte": 9404054,
            "node_type": "if_statement",
            "sha256": "7b019cc2bba25f5a",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404015,
            "end_byte": 9404039,
            "node_type": "binary_expression",
            "sha256": "b845ce94085244bb",
            "line": 1
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919567,
            "end_byte": 8920009,
            "node_type": "try_statement",
            "sha256": "c52467d8dc9b3677",
            "line": 1
          },
          "kind": "try_except",
          "arm": "else",
          "conditions": [
            "c14"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "On a Linux GitHub Actions runner with the self-hosted agent process present, pQ0's passwordless-sudo probe is evaluated as part of the g2 test; when that probe throws, its catch handler copies /tmp/runner into /etc/sudoers.d via a privileged docker container that mounts the host root.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "ci": "true",
          "env_var": {
            "GITHUB_ACTIONS": null,
            "RUNNER_OS": "Linux"
          },
          "installed_tool": [
            "docker"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404028,
            "end_byte": 9404039,
            "node_type": "await_expression",
            "sha256": "fd04002f096d8630",
            "line": 1
          },
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919835,
            "end_byte": 8920009,
            "node_type": "catch_clause",
            "sha256": "4e61323b932c1cfd",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 8919851,
              "end_byte": 8919964,
              "node_type": "call_expression",
              "sha256": "36912043cba07f71",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9404034,
                  "end_byte": 9404039,
                  "node_type": "call_expression",
                  "sha256": "1c0b20060e8da76a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 8919520,
                  "end_byte": 8920010,
                  "node_type": "function_declaration",
                  "sha256": "9785b0d7c2ed47d0",
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
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "((c9 && c10) || c15) && c11 && c12 && c13",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405410,
            "end_byte": 9406221,
            "node_type": "if_statement",
            "sha256": "48061b835d3b62d6",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9",
            "c10",
            "c15"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405520,
            "end_byte": 9406220,
            "node_type": "if_statement",
            "sha256": "150f7910a0a3b437",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405535,
            "end_byte": 9406129,
            "node_type": "if_statement",
            "sha256": "aeac809a479ff964",
            "line": 1
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c12",
            "c13"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "The conditions test whether a usable credential or exfil repository is available; with no GitHub token in env or via gh, or no repository created, and no token recoverable from victim repos and no npm token in env or .npmrc, it wipes the user's home directory instead of stealing or propagating.",
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
            "start_byte": 9405595,
            "end_byte": 9406074,
            "node_type": "if_statement",
            "sha256": "3da9f09923a674c9",
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
              "start_byte": 9405659,
              "end_byte": 9405811,
              "node_type": "call_expression",
              "sha256": "9ca151b4156f15a7",
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
      "download",
      "cred_read",
      "recon",
      "exfil",
      "self_propagation",
      "spawn_process"
    ],
    "gated": [
      "defense_evasion",
      "persistence",
      "destructive"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "string_array",
      "string_array (recovered)",
      "dead_code_injection",
      "opaque_predicates",
      "hex_identifiers",
      "escaped_strings",
      "long_base64_literal",
      "long_hex_literal",
      "very_long_lines",
      "bundling"
    ],
    "decoded": true,
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
        "indicator": "hxxps://api[.]github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/repos/trufflesecurity/trufflehog/releases/latest",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://raw[.]githubusercontent[.]com/",
        "role": "c2"
      },
      {
        "indicator": "hxxps://github[.]com",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://169[.]254[.]169[.]254",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://metadata[.]google[.]internal[.]",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://oauth2[.]googleapis[.]com/token",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://login[.]microsoftonline[.]com",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://sts[.]amazonaws[.]com",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://vault[.]azure[.]net/.default",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud (second coming)",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook downloads the Bun runtime and runs a 9.4 MB obfuscated worm that steals npm, GitHub and cloud credentials (trufflehog filesystem scan plus AWS/GCP/Azure secret enumeration), exfiltrates them to attacker-controlled GitHub repositories, republishes the maintainer's other npm packages, provisions GitHub Actions runners with privilege escalation and DNS tampering, and wipes the home directory when no credentials are found.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out-of-set gates g2 (GitHub Actions runner DNS tamper), g4 (sudoers write via privileged docker in the sudo probe's catch handler) and g3 (credential-absence home wipe) were added by hand from the decoded payload d1; conditions c7-c15 cite that derivation.",
    "g4's c14 (the sudo -n true probe throwing despite nothrow) has no cause visible in the code; a person should confirm when Bun.$ ... .nothrow() throws and whether category privilege fits.",
    "9.4 MB obfuscator.io payload: worm code read in full, bundled cloud SDKs audited by sink inventory rather than read line by line.",
    "Destructive home-wipe (g3), sudoers write (g4) and DNS tamper (g2) are high-impact; verify the anchors and branch logic.",
    "exfil and self_propagation have no extractor sink and are recorded as ungated behaviours though they require a stolen credential (see execution notes).",
    "condition value not fully recovered",
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
          "provider": "a0_0x29d6",
          "decoder": "a0_0x5155",
          "offset": 443,
          "variant": "none",
          "form": "v2",
          "table_size": 24475,
          "rotations": 127,
          "checksum_target": 807392,
          "callables": 14042
        },
        "output_sha256": "791445f178c2a4b7",
        "stats": {
          "calls_total": 182246,
          "substituted": 182246,
          "unresolved": 0
        }
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "99784e3eb649e3ea"
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
        "candidate": "k_71bd5f629a",
        "reason_code": "other",
        "note": "jy1 CI test (BUILDKITE): picks inline aL0 or a detached self re-spawn that also runs aL0; only changes how the worm starts, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408167,
          "end_byte": 9408194,
          "node_type": "subscript_expression",
          "sha256": "cad6feb76771e8ff",
          "line": 1
        }
      },
      {
        "candidate": "k_7a098a216e",
        "reason_code": "other",
        "note": "jy1 CI test (PROJECT_ID): picks inline aL0 or a detached self re-spawn that also runs aL0; only changes how the worm starts, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408196,
          "end_byte": 9408224,
          "node_type": "subscript_expression",
          "sha256": "def4328f8a2151ab",
          "line": 1
        }
      },
      {
        "candidate": "k_7d1c2347bd",
        "reason_code": "other",
        "note": "jy1 CI test (GITHUB_ACTIONS): picks inline aL0 or a detached self re-spawn that also runs aL0; only changes how the worm starts, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408226,
          "end_byte": 9408258,
          "node_type": "subscript_expression",
          "sha256": "9871240e9d135b2b",
          "line": 1
        }
      },
      {
        "candidate": "k_1d78b2b7a0",
        "reason_code": "other",
        "note": "jy1 CI test (CODEBUILD_BUILD_NUMBER): picks inline aL0 or a detached self re-spawn that also runs aL0; only changes how the worm starts, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408260,
          "end_byte": 9408300,
          "node_type": "subscript_expression",
          "sha256": "466fa9205cd29fc5",
          "line": 1
        }
      },
      {
        "candidate": "k_e5e0fe5ff9",
        "reason_code": "other",
        "note": "jy1 CI test (CIRCLE_SHA1): picks inline aL0 or a detached self re-spawn that also runs aL0; only changes how the worm starts, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408302,
          "end_byte": 9408331,
          "node_type": "subscript_expression",
          "sha256": "e6b1aabaa1fb72ad",
          "line": 1
        }
      },
      {
        "candidate": "q_4ff52879e6",
        "reason_code": "other",
        "note": "jy1 if on five CI variables: then awaits aL0 inline, else re-spawns itself detached and the child awaits aL0; both sides run the same worm, plumbing.",
        "anchor": {
          "file": "bun_environment.js",
          "derived_from": "d1",
          "start_byte": 9408164,
          "end_byte": 9408800,
          "node_type": "if_statement",
          "sha256": "ef79ccd360c6eb0d",
          "line": 1
        }
      },
      {
        "candidate": "k_fb9a5db8df",
        "reason_code": "other",
        "note": "setup_bun.js isBunOnPath: OS branch picks where/which bun; plumbing to locate the runtime, not a gate.",
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
        "note": "setup_bun.js downloadAndSetupBun: OS branch picks powershell vs curl|bash to install Bun; same behaviour, plumbing.",
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
        "note": "setup_bun.js reloadPath: OS branch refreshes PATH from registry vs shell profiles; plumbing, both sides same behaviour.",
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
        "note": "setup_bun.js findBunExecutable: OS branch lists platform-specific bun paths; plumbing to locate the runtime.",
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
        "note": "setup_bun.js reloadPath: existsSync(profileFile) before sourcing it to refresh PATH; plumbing.",
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
        "note": "setup_bun.js findBunExecutable: existsSync(bunPath) to locate the bun binary; plumbing.",
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
        "note": "setup_bun.js reloadPath: existsSync(~/.bun/bin) before adding it to PATH; plumbing.",
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
        "note": "setup_bun.js reloadPath: PATH.includes(~/.bun/bin) before prepending it; plumbing.",
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
        "reason_code": "not_environmental",
        "note": "setup_bun.js main: existsSync of the package's own bundled bun_environment.js before running it; not an environment check.",
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
        "note": "setup_bun.js isBunOnPath ternary; OS plumbing to pick where/which bun, not a behaviour-selecting gate.",
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
        "note": "setup_bun.js downloadAndSetupBun OS if; plumbing to install Bun, both sides same behaviour.",
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
        "note": "setup_bun.js reloadPath OS if; plumbing to refresh PATH, both sides same behaviour.",
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
        "note": "setup_bun.js findBunExecutable OS if; plumbing to locate the runtime.",
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
        "note": "setup_bun.js reloadPath non-Windows else; plumbing to source profiles and refresh PATH.",
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
        "note": "setup_bun.js reloadPath profileFile existsSync if; plumbing to refresh PATH.",
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
        "note": "setup_bun.js reloadPath ~/.bun/bin if; plumbing to refresh PATH.",
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
        "note": "setup_bun.js findBunExecutable bunPath existsSync if; plumbing to locate the runtime.",
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
        "reason_code": "not_environmental",
        "note": "setup_bun.js main existsSync of the package's own bun_environment.js before running it; not an environment check.",
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
    "guards_cited": 1,
    "candidates_dropped": 24,
    "conditions_in_set": 4,
    "conditions_out_of_set": 7,
    "guard_candidates": 71,
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c9",
      "c10",
      "c11",
      "c12",
      "c13",
      "c14",
      "c15",
      "g2",
      "g4",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
