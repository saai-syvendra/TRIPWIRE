# npm @postman/node-keytar@7.9.5

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a trojanised copy of `@postman/node-keytar` carrying the Shai-Hulud ("Sha1-Hulud: The Second Coming") supply-chain worm. The `preinstall` hook runs `setup_bun.js`, which downloads the Bun runtime from bun.sh (curl|bash on unix, `irm|iex` on Windows) and then runs the 10 MB obfuscated `bun_environment.js` with Bun. That payload harvests GitHub, npm and cloud (AWS/GCP/Azure) credentials, downloads and runs trufflehog to scan the home directory for secrets, uploads everything to an attacker-created public GitHub repo, republishes the maintainer's own npm packages (self-propagation), and installs a self-hosted GitHub Actions runner named SHA1HULUD for persistence. The `setup_bun.js` os/path/file branches are all plumbing to obtain and launch Bun, so they are dropped as non-gates; the real gates live in `bun_environment.js` and are out-of-set (the extractor never walked that file). Three environmental gates stand out: a GitHub-Actions-Linux DNS/firewall tamper (needs the runner agent process and passwordless sudo), a per-OS destructive home-directory wipe that fires when no credentials are found, and a per-OS self-hosted-runner install behind the token's workflow scope.

## Execution

- **preinstall** `node setup_bun.js`: 2-file chain; direct_script, shell_pipe, download_then_exec, detached_child, decoded_eval; errors hidden.
- **install** `prebuild-install --verbose`: no package files; native_build.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 && c2 && c3 && (c4 \|\| (c14 && c15)) (c1: process.env.GITHUB_ACTIONS exists; c2: process.env.RUNNER_OS == Linux; c3: process_list != ; c4: privilege exists; c14: privilege not_exists; c15: privilege exists) | then | 4 | defense_evasion, spawn_process | ci=github_actions; env_var=GITHUB_ACTIONS=(set), RUNNER_OS=Linux; privilege=root_or_admin |
| g2 | preinstall | (c5 \|\| c6) && c7 && c8 && c9 && c10 (c5: target_artifact falsy; c6: server_response falsy; c7: server_response falsy; c8: process.env.NPM_TOKEN not_exists; c9: target_artifact not_exists; c10: os == win32) | then | 5 | destructive | os=win32; env_var_absent=NPM_TOKEN; file_absent=~/.npmrc |
| | |  | else | 5 | destructive | os=linux; env_var_absent=NPM_TOKEN; file_absent=~/.npmrc |
| g3 | preinstall | c11 && c13 && c12 (c11: server_response truthy; c13: server_response == 201; c12: os == linux) | then | 3 | persistence, download, exec_downloaded, spawn_process | os=linux |

Gate intent: g1 activate/enables/targeting; g2 activate/selects/portability; g3 activate/enables/portability

Grounding: 0 of 15 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, g1, g2, g3.

## Requirements

- network: bun[.]sh:443, github[.]com:443, api[.]github[.]com:443, raw[.]githubusercontent[.]com:443 (setup_bun.js fetches the Bun runtime from bun.sh; the payload downloads the GitHub Actions runner and trufflehog from github/api.github.com and reads other victims' exfil repos from raw.githubusercontent)
- installed_tool: bash, curl, tar (unix Bun install (curl|bash) and the actions-runner download/extract and run.sh launch use bash, curl and tar)

## Behaviour

- Ungated: recon, cred_read, exfil, download, exec_downloaded, spawn_process, write_file, modify_other_packages, self_propagation
- Gated: defense_evasion, spawn_process, destructive, persistence, download, exec_downloaded

## Notes

- Coverage: `bun_environment.js` string array recovered to derived `d1` (rotation checksum matched). The worm's own code (entry `jy1`/`aL0`, GitHub module `dq`, cloud wrappers, trufflehog class `Tl`, helpers `cQ0`/`pQ0`/`gQ0`, destructive/runner blocks) was read in full; the bundled AWS/Azure/GCP/octokit/grpc/protobuf SDKs were audited by sink inventory (the only exec/spawn sinks are in the worm's tail region ~bytes 9.1M-9.4M). Nothing was left unread.
- `jy1` re-spawns itself detached with `POSTINSTALL_BG=1` when not in CI (re-entry guard + launch plumbing, not a gate).
- All gates/conditions are out-of-set and rest partly on out-of-scope `server_response` conditions (repoExists, fetchToken, checkWorkflowScope, registration status); forced to manual review.
- The destructive wipe (g2) triggers purely on the absence of GitHub and npm credentials, so a bare scanner sandbox would likely trip it.
- The embedded "Discussion Create" workflow YAML (`runs-on: self-hosted`) and the runner named SHA1HULUD support the family label from the code, not just comments.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@postman/node-keytar",
    "version": "7.9.5",
    "archive_sha256": "d231ea190a11a2e551690ab1ee689d492fd99f67c856e8e4fd924a90982999d4",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-11-24-@postman_node-keytar-v7.9.5.zip",
    "package_root": "layer0/tmp/tmpcbedkx73/@postman-node-keytar/package",
    "cluster_key": "23fa73f7064a6cb9faa229e38ae958a345aba1a00b4609f6a3b0b7aeecac261b",
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
        "hook": "install",
        "command": "prebuild-install --verbose",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [
      {
        "site": "bun_environment.js:1",
        "seconds": 3,
        "purpose": "pause after creating the exfil repo, before registering the self-hosted runner"
      }
    ],
    "notes": [
      "install: delegates to prebuild-install; code inside that dependency is out of scope",
      "preinstall runs setup_bun.js, which downloads the Bun runtime (curl|bash from bun.sh on unix, powershell irm|iex on Windows) then runs bun_environment.js with Bun; the setup_bun.js os/path/file checks are plumbing to obtain and launch Bun and are dropped as non-gates",
      "bun_environment.js: string array recovered to derived d1 (checksum matched); the worm's own code (jy1/aL0, GitHub module dq, trufflehog class, cQ0/pQ0/gQ0, destructive/runner blocks) read in full",
      "bun_environment.js: bundled AWS/Azure/GCP/octokit/grpc SDKs audited by sink inventory (the only exec/spawn sinks are in the worm's tail region); nothing left unread",
      "jy1 entry: with a CI env var set it runs aL0 foreground; otherwise it re-spawns itself detached (Bun.spawn(...).unref()) with POSTINSTALL_BG=1 and returns. POSTINSTALL_BG is a re-entry guard and the foreground/detached split is launch plumbing, not a gate",
      "opaque predicates: constant string-comparison branches (e.g. 'BcRdZ'!=='sCHTZ', 'DZwVW'==='KDWFd') are always-taken or dead decoys from the obfuscator; the live payload sits on the taken side, including the destructive wipe",
      "g3 records the Linux self-hosted-runner branch; the else-if win32 and darwin branches install the equivalent runner via platform-specific download commands (not modelled separately)",
      "g1: aL0's own GITHUB_ACTIONS test only wraps the call of Ry1 (its sole caller), and Ry1 tests GITHUB_ACTIONS again, so the Ry1 guard carries c1 and the aL0 site stays as a c1 site without its own guard",
      "g1: pQ0 is true on sudo -n true exit 0, or, when that call throws (it uses nothrow, so a non-zero exit does not), when the privileged Docker copy into /etc/sudoers.d then does not throw; a non-zero sudo exit returns false",
      "g3 linux branch passes os.homedir uncalled (a0_0x5a88b3[\"homedir\"]+\"/.dev-env\") as cwd for curl, tar, config.sh and rm; the win32 branch calls homedir(). Whether Bun rejects that cwd, which would end the branch in the catch before the spawn, cannot be told statically",
      "c11 checkWorkflowScope stores whether x-oauth-scopes includes workflow but returns true after any successful HEAD / on the first call, so c11 really tests that the request succeeds, not the scope",
      "cloud credential harvesting (AWS/GCP/Azure) runs through the bundled SDK wrappers to provider APIs and cloud metadata (169[.]254[.]169[.]254); it returns empty and exfiltrates nothing when no cloud credentials are present"
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "bun[.]sh:443",
        "github[.]com:443",
        "api[.]github[.]com:443",
        "raw[.]githubusercontent[.]com:443"
      ],
      "reason": "setup_bun.js fetches the Bun runtime from bun.sh; the payload downloads the GitHub Actions runner and trufflehog from github/api.github.com and reads other victims' exfil repos from raw.githubusercontent"
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash",
        "curl",
        "tar"
      ],
      "reason": "unix Bun install (curl|bash) and the actions-runner download/extract and run.sh launch use bash, curl and tar"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9404649,
            "end_byte": 9404681,
            "node_type": "subscript_expression",
            "sha256": "7d88aa1eaff028b6",
            "line": 1
          }
        },
        {
          "candidate": null,
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
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
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
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "process_list",
      "api": "Bun.$",
      "operator": "!=",
      "value": "",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "ps -axco command | grep \"/home/agent/agent\"",
        "accessor": "stdout"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919209,
            "end_byte": 8919295,
            "node_type": "binary_expression",
            "sha256": "161f72733f5b13de",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "sudo -n true",
        "accessor": "returncode"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919641,
            "end_byte": 8919676,
            "node_type": "call_expression",
            "sha256": "09b22436681988bc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "GitHub.isAuthenticated",
      "operator": "falsy",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405414,
            "end_byte": 9405444,
            "node_type": "call_expression",
            "sha256": "5344a30c867402a3",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "server_response",
      "api": "GitHub.repoExists",
      "operator": "falsy",
      "value": null,
      "value_recovered": "not_recovered",
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
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "GitHub.fetchToken",
      "operator": "falsy",
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
      "id": "c8",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "not_recovered",
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
      "id": "c9",
      "category": "target_artifact",
      "api": "fs.readFile",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "fs.readFile",
        "target": "~/.npmrc",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405304,
            "end_byte": 9405309,
            "node_type": "call_expression",
            "sha256": "fd41f72f9f1d544e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405625,
            "end_byte": 9405658,
            "node_type": "binary_expression",
            "sha256": "75a4e97d2bf16124",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "server_response",
      "api": "GitHub.checkWorkflowScope",
      "operator": "truthy",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9142961,
            "end_byte": 9142989,
            "node_type": "call_expression",
            "sha256": "4ede8b5be49a1244",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143220,
            "end_byte": 9143255,
            "node_type": "binary_expression",
            "sha256": "f06225cd90c5be6d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "server_response",
      "api": "octokit.request",
      "operator": "==",
      "value": "201",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143149,
            "end_byte": 9143174,
            "node_type": "binary_expression",
            "sha256": "429fed8ec58a5a3f",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "sudo -n true",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919641,
            "end_byte": 8919676,
            "node_type": "call_expression",
            "sha256": "09b22436681988bc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c15",
      "category": "privilege",
      "api": "Bun.$",
      "operator": "exists",
      "value": null,
      "value_recovered": "not_recovered",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "Bun.$",
        "target": "docker run --rm --privileged -v /:/host ubuntu bash -c \"cp /host/tmp/runner /host/etc/sudoers.d/runner\"",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 8919851,
            "end_byte": 8919977,
            "node_type": "call_expression",
            "sha256": "a231dd028128acff",
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
      "expression": "c1 && c2 && c3 && (c4 || (c14 && c15))",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9403708,
            "end_byte": 9403779,
            "node_type": "binary_expression",
            "sha256": "38099a5e89c59f4b",
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
            "start_byte": 9404015,
            "end_byte": 9404039,
            "node_type": "binary_expression",
            "sha256": "b845ce94085244bb",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c4",
            "c14",
            "c15"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Tampers with DNS and firewall only on a GitHub Actions self-hosted Linux runner that has the runner agent process present and passwordless sudo available, or a Docker sudoers fallback when the sudo probe throws.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "defense_evasion",
          "spawn_process"
        ],
        "env_recipe": {
          "ci": "github_actions",
          "env_var": {
            "GITHUB_ACTIONS": null,
            "RUNNER_OS": "Linux"
          },
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [
          "privilege"
        ],
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
              "end_byte": 8920122,
              "node_type": "call_expression",
              "sha256": "3828b0957348aaac",
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
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "(c5 || c6) && c7 && c8 && c9 && c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405413,
            "end_byte": 9405472,
            "node_type": "binary_expression",
            "sha256": "3203298e3c017fe5",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405523,
            "end_byte": 9405533,
            "node_type": "unary_expression",
            "sha256": "3068bf78c1f12e3f",
            "line": 1
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
            "c8",
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405595,
            "end_byte": 9406074,
            "node_type": "if_statement",
            "sha256": "3da9f09923a674c9",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "When no GitHub or npm credentials are found the worm wipes the user's home directory; Windows uses cmd.exe del + cipher, other platforms use bash find + shred. The per-OS branch selects the destruction command.",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "destructive"
        ],
        "env_recipe": {
          "os": "win32",
          "env_var_absent": [
            "NPM_TOKEN"
          ],
          "file_absent": [
            "~/.npmrc"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405659,
            "end_byte": 9405811,
            "node_type": "call_expression",
            "sha256": "9ca151b4156f15a7",
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
      "else": {
        "min_conditions": 5,
        "behaviours": [
          "destructive"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var_absent": [
            "NPM_TOKEN"
          ],
          "file_absent": [
            "~/.npmrc"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "requires": [
          "c5",
          "c7",
          "c8",
          "c9"
        ],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405817,
            "end_byte": 9406073,
            "node_type": "call_expression",
            "sha256": "ada7a3ee7fa9d6b9",
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
              "start_byte": 9405817,
              "end_byte": 9406073,
              "node_type": "call_expression",
              "sha256": "ada7a3ee7fa9d6b9",
              "line": 1
            },
            "witness": []
          }
        ]
      }
    },
    {
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "c11 && c13 && c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9142854,
            "end_byte": 9146006,
            "node_type": "if_statement",
            "sha256": "4b69658e47b615ef",
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
            "start_byte": 9143146,
            "end_byte": 9145961,
            "node_type": "if_statement",
            "sha256": "ea9dafbcdd0cce82",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c13"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143217,
            "end_byte": 9145708,
            "node_type": "if_statement",
            "sha256": "3a0a50061893cdc7",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "After creating the exfil repo, when the stolen token has workflow scope and a runner registration token is obtained, installs a self-hosted GitHub Actions runner named SHA1HULUD; the Linux/Windows/macOS branches each download the matching runner binary.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence",
          "download",
          "exec_downloaded",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143303,
            "end_byte": 9143518,
            "node_type": "call_expression",
            "sha256": "c48b001d9f7ba847",
            "line": 1
          },
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143634,
            "end_byte": 9143838,
            "node_type": "call_expression",
            "sha256": "2c5427650fec0a20",
            "line": 1
          },
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9143941,
            "end_byte": 9144008,
            "node_type": "call_expression",
            "sha256": "79f7e93b4728dae1",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9143303,
              "end_byte": 9143518,
              "node_type": "call_expression",
              "sha256": "c48b001d9f7ba847",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9143634,
              "end_byte": 9143838,
              "node_type": "call_expression",
              "sha256": "2c5427650fec0a20",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9143941,
              "end_byte": 9144008,
              "node_type": "call_expression",
              "sha256": "79f7e93b4728dae1",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9143941,
              "end_byte": 9144008,
              "node_type": "call_expression",
              "sha256": "79f7e93b4728dae1",
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
      "modify_other_packages",
      "self_propagation"
    ],
    "gated": [
      "defense_evasion",
      "spawn_process",
      "destructive",
      "persistence",
      "download",
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "obfuscator.io string-array (recovered via rotation)",
      "string_array",
      "hex_identifiers",
      "escaped_strings",
      "long_base64_literal",
      "long_hex_literal",
      "very_long_lines",
      "opaque_predicates (constant string-comparison dead branches)",
      "bundled_sdks",
      "dynamic_eval (Function())"
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
        "indicator": "hxxps://raw[.]githubusercontent[.]com/",
        "role": "c2"
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
        "indicator": "hxxps://github[.]com/actions/runner/releases/download/v2.330.0/actions-runner-win-x64-2.330.0.zip",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/actions/runner/releases/download/v2.330.0/actions-runner-osx-arm64-2.330.0.tar.gz",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://169[.]254[.]169[.]254",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud (Sha1-Hulud: The Second Coming)",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook downloads the Bun runtime and runs a 10 MB obfuscated worm (Shai-Hulud, 'Sha1-Hulud: The Second Coming') that harvests GitHub, npm and cloud credentials, runs trufflehog over the home directory, exfiltrates everything to an attacker-created public GitHub repo, republishes the maintainer's npm packages, installs a self-hosted GitHub Actions runner for persistence, and wipes the home directory when no credentials are found. This is unambiguous install-time malware.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and gates are out-of-set (candidate null): the extractor did not walk bun_environment.js, so they were added by hand from the recovered string-array copy (derived d1)",
    "g2 and g3 include out-of-scope server_response conditions (repoExists, fetchToken, checkWorkflowScope, registration status) that a VM cannot set",
    "env_recipe fields guessed: privilege for g1 (passwordless sudo, sudo -n true) and os for g2's non-Windows else branch",
    "g2 destructive-wipe fires on the absence of GitHub and npm credentials, so a bare scanner sandbox with no credentials would likely trigger it",
    "setup_bun.js os/path/file candidates were dropped as plumbing; each drop is reviewed like any claim",
    "g3 linux and darwin branches pass os.homedir uncalled as the cwd of the runner steps; if Bun rejects that cwd, the download, config and spawn sinks after mkdir never run. Not decidable statically",
    "g2 else.requires lists only c5 of the c5 || c6 pair, because requires has no way to say or; c6 is the other way to open the same guard",
    "condition value not fully recovered",
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
        "reason_code": "other",
        "note": "setup_bun.js os check picks per-OS command to install/locate Bun; both branches launch the same payload, not behaviour-selecting",
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
        "note": "setup_bun.js os check picks the per-OS Bun install command (curl|bash vs powershell); plumbing to obtain the runtime",
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
        "note": "setup_bun.js os check selects the PATH-reload method; plumbing, both branches reach the same payload",
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
        "note": "setup_bun.js os check selects per-OS Bun executable search paths; plumbing to locate the runtime",
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
        "note": "setup_bun.js fs.existsSync on a shell profile file; plumbing to refresh PATH before finding Bun",
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
        "note": "setup_bun.js fs.existsSync on a candidate Bun path; plumbing to locate the runtime",
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
        "note": "setup_bun.js fs.existsSync on ~/.bun/bin; plumbing to refresh PATH",
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
        "note": "setup_bun.js PATH.includes(~/.bun/bin) check; plumbing to refresh PATH",
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
        "note": "setup_bun.js fs.existsSync on its own bun_environment.js, shipped beside it in the same package; reads no property of the victim environment, so no environment can flip it on an intact install",
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
        "note": "setup_bun.js ternary selecting which/where bun per OS; plumbing to locate the runtime",
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
        "note": "setup_bun.js if selecting per-OS Bun install command; plumbing to obtain the runtime",
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
        "note": "setup_bun.js if selecting per-OS PATH-reload method; plumbing",
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
        "note": "setup_bun.js if selecting per-OS Bun search paths; plumbing to locate the runtime",
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
        "note": "setup_bun.js non-Windows branch for PATH reload / Bun locate; plumbing",
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
        "note": "setup_bun.js if on shell-profile existence to refresh PATH; plumbing",
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
        "note": "setup_bun.js if adding ~/.bun/bin to PATH; plumbing to refresh PATH",
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
        "note": "setup_bun.js if returning a found Bun path; plumbing to locate the runtime",
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
        "note": "setup_bun.js if on its own shipped bun_environment.js: launches it, else process.exit(0). The else side only runs on a damaged package; no environment selects it",
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
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 18,
    "conditions_in_set": 0,
    "conditions_out_of_set": 15,
    "guard_candidates": 71,
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "c9",
      "c10",
      "c11",
      "c12",
      "c13",
      "c14",
      "c15",
      "g1",
      "g2",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
