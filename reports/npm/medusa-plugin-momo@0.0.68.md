# npm medusa-plugin-momo@0.0.68

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

This is a Shai-Hulud ("Sha1-Hulud: The Second Coming") worm shipped inside a package that borrows the name and metadata of a Medusa starter. The `preinstall` hook (`node setup_bun.js`, runs on every install) downloads the bun runtime (`curl hxxps://bun[.]sh/install | bash`, or a PowerShell installer on Windows) and launches the bundled 10.2 MB obfuscated `bun_environment.js` with bun. That payload runs on every platform with no environment gate: it reads npm, GitHub and cloud (AWS/GCP/Azure) credentials, runs trufflehog over the home directory, exfiltrates everything into attacker-created GitHub repositories, self-propagates by republishing the maintainer's npm packages with the same `preinstall`, and registers a self-hosted GitHub Actions runner for persistence. Two real environment gates sit inside the payload: on a GitHub Actions Linux runner that has the CI agent process and passwordless sudo it disables systemd-resolved and flushes iptables to blind monitoring (g1, defense evasion), and when no GitHub or campaign-repo token is found, an npm token selects republishing the victim's packages while no npm token shreds the user's home directory (g2, self-propagation or destructive). All of `setup_bun.js`'s own checks only bootstrap bun and locate the payload, so they were dropped as plumbing.

## Execution

- **preinstall** `node setup_bun.js`: 2-file chain; direct_script, shell_pipe, download_then_exec, detached_child; errors hidden.
- **prepare** `cross-env NODE_ENV=production yarn run build`: runs on git or local install only; no package files; inline_shell.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 && c2 && c3 && c4 (c1: process.env.GITHUB_ACTIONS truthy; c2: process.env.RUNNER_OS == Linux; c3: process_list exists; c4: privilege exists) | then | 4 | defense_evasion | env_var=GITHUB_ACTIONS=(set), RUNNER_OS=Linux; installed_tool=sudo; privilege=root_or_admin |
| g2 | preinstall | ((c5 && c9) \|\| c8) && c6 && c7 && c10 (c5: target_artifact not_startswith [gho_, ghp_]; c9: target_artifact not_startswith [ghp_, gho_]; c8: server_response falsy; c6: server_response falsy; c7: process.env.NPM_TOKEN falsy; c10: target_artifact not_regex (?:_authToken\|:_authToken)=([a-zA-Z0-9\-._~+/]+=*)) | then | 4 | destructive | env_var_absent=NPM_TOKEN; file_absent=~/.npmrc, .npmrc |
| | |  | else | 5 | self_propagation, modify_other_packages | env_var=NPM_TOKEN=(set) |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/selects/data_availability

Grounding: 4 of 10 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c5, c6, c7, c8, c9, c10, g1, g2.

## Requirements

- network: bun[.]sh:443, api[.]github[.]com:443, registry[.]npmjs[.]org:443, raw[.]githubusercontent[.]com:443, github[.]com:443 (Downloads the bun runtime, then contacts GitHub and the npm registry to exfiltrate data into attacker repos, create data repos, register a runner and republish the maintainer's packages.)
- installed_tool: bun, curl, bash (bun_environment.js is executed by the bun runtime (downloaded via curl|bash on non-Windows if bun is absent).)

## Behaviour

- Ungated: recon, cred_read, exfil, download, self_propagation, modify_other_packages, persistence, spawn_process
- Gated: defense_evasion, destructive, self_propagation, modify_other_packages

## Notes

- `bun_environment.js` was recovered from the obfuscator.io string table as derivation d1 (182246/182246 decoder calls substituted, 0 unresolved). The payload's own code was read in full; the bundled AWS/Azure/GCP/octokit/protobuf/tar SDKs were audited by sink inventory and every exec/network/fs hit belongs to the payload classes.
- Both gates are out-of-set: they come from the de-obfuscated bundle, which the extractor did not walk (it only prefilled the `setup_bun.js` plumbing gates, all dropped here).
- g2 is modelled at the innermost `if(npmToken){propagate}else{wipe}` decision. The enclosing conditions are "no GitHub token" from either local source (`gh auth token`, c5, and the env value scan for `ghp_`/`gho_`, c9) or no exfil repo (c8), and "no campaign-repo token" from `dq.fetchToken` (c6, server_response, out of scope). The npm token also has two sources, `NPM_TOKEN` (c7) and `.npmrc` in the working or home folder (c10), and both must be empty for the wipe. The else branch is anchored on `await El(token)`, which reaches the `npm publish` call in `Wl.updatePackage`. Its `else.min_conditions` of 5 is an upper figure: `else.requires` must list every condition of the outer guard, and the route through c8 alone needs 3. `El` also runs unconditionally near the end of the payload, so self-propagation stays listed as ungated too, and it publishes only after `Wl.validateToken` returns a user, a server-response test not modelled as a condition.
- Non-CI installs re-spawn `setup_bun.js` detached with `POSTINSTALL_BG=1` (a re-entry guard) and run the payload in the background; CI installs run it in the foreground. Same payload, so not a gate.
- `pQ0`, the passwordless-sudo probe behind g1, attempts a `docker run --privileged -v /:/host` escape only if the `sudo -n true` call throws. The call uses `.nothrow()`, so a plain non-zero exit returns false instead. The docker step is an escalation attempt whose result is unused, not a condition.
- Endpoint list pruned from the SDK/doc URLs to the hosts the install payload actually contacts (bun.sh, npm registry, GitHub, raw.githubusercontent, trufflehog/actions-runner downloads, and the cloud metadata/token endpoints hit during cloud secret theft). `hxxps://vault[.]azure[.]net/.default` was removed because it is an OAuth scope passed to `getToken`, not a contacted host. Hosts the bundled cloud SDKs choose at run time were not traced through the SDK code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "medusa-plugin-momo",
    "version": "0.0.68",
    "archive_sha256": "501bb62923ebec70efc926f8ada7bf60242d2d98bd01c12f50a3ab0c9f761058",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-11-24-medusa-plugin-momo-v0.0.68.zip",
    "package_root": "layer0/tmp/tmp1k_5e265/medusa-plugin-momo/package",
    "cluster_key": "d5a3ec59b5dd78b97ba748a1454675c0c746b20d6f3eeacc50dd8a73096af379",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
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
          "detached_child"
        ],
        "silent_failure": true
      },
      {
        "hook": "prepare",
        "command": "cross-env NODE_ENV=production yarn run build",
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
      "setup_bun.js: package code read in full. preinstall bootstraps the bun runtime (curl bun.sh install script piped to bash, or a powershell installer) then launches bun_environment.js with bun.",
      "setup_bun.js os/path/file checks only locate or install bun and refresh PATH, so they are plumbing and were dropped as candidates.",
      "bun_environment.js added to the preinstall file_chain: setup_bun.js:182 spawns bun with bun_environment.js. not_chained resolved; both obfuscation.unrecovered entries removed.",
      "bun_environment.js: 10.2 MB obfuscator.io bundle. String table recovered as derivation d1 (182246/182246 decoder calls substituted, 0 unresolved).",
      "bun_environment.js payload package code read in full: jy1, aL0, Ry1, cQ0, pQ0, gQ0, El, oL0, $y1, tL0, uy1, ky1 and classes dq, mq, Wl, WX/ck, Hw/zw, Eq/Tq, Tl.",
      "bun_environment.js: bundled AWS/Azure/GCP SDKs, octokit, protobufjs, tar, minipass audited by sink inventory; every exec/network/fs hit belongs to the payload classes. Nothing left unread; the Function('return this') probe at d1:265242 is a library global-this helper.",
      "jy1 entry: CI installs (BUILDKITE/PROJECT_ID/GITHUB_ACTIONS/CODEBUILD_BUILD_NUMBER/CIRCLE_SHA1) run the payload foreground; otherwise setup re-spawns itself detached with POSTINSTALL_BG=1 and runs it in the background.",
      "jy1 POSTINSTALL_BG=1 is a re-entry guard and the CI check only changes foreground vs detached launch; same payload either way, so not a gate.",
      "Opaque-predicate dead branches (for example 'kOIJC' !== 'kOIJC' and 'BcRdZ' !== 'sCHTZ') wrap the real code; counted as dead-code injection. The live code is the taken arm.",
      "g2 else side: with an npm token the same decision runs await El(token), which reaches Wl.updatePackage and its Bun.$ npm publish. The wipe side ends in process.exit(0), so everything after this block in aL0 runs only off g2's then side.",
      "g2 else.requires lists c5, c9, c8 and c6 because a guard keeps its side only when all its conditions are required. That counts else.min_conditions as 5; the route through c8 alone needs 3 (c8, c6, one npm token source). No field expresses an || inside requires.",
      "El also runs unconditionally near the end of aL0, so self_propagation and modify_other_packages stay under ungated as well as g2's else. El publishes only after Wl.validateToken returns a user, a server_response test that is not modelled as a condition.",
      "g2 enclosing condition c6 (campaign-repo token search) is server_response and out of scope; the destructive then-branch is the anchored side.",
      "g2 outer test is !isAuthenticated() || !repoExists(): c8 (repoExists, gitRepo set only when createRepo succeeded against the GitHub API) is server_response and out of scope, joined with c5 by ||.",
      "Persistence (self-hosted GitHub Actions runner named SHA1HULUD via nohup run.sh) runs inside dq.createRepo only when a stolen or local token carries the workflow scope (server_response); listed under ungated behaviours.",
      "g2 token sources: dq.token comes from getToken, which scans env values for ghp_/gho_ (c9) then runs gh auth token (c5). !isAuthenticated() needs both empty, so c5 && c9. The npm token variable is NPM_TOKEN (c7) then oL0 on cwd and home .npmrc (c10), so c7 && c10 on the same guard.",
      "g2 recipe: env_var_absent holds only NPM_TOKEN, the one variable the code names. The c9 scan matches any env value by prefix, so the GITHUB_TOKEN stand-in was removed. No recipe key expresses c9 or gh being logged out (c5).",
      "g1 recipe: privilege root_or_admin stays guessed because the code tests passwordless sudo (sudo -n true), which a normal user with NOPASSWD also passes. No recipe key expresses the agent process of c3. installed_tool sudo is read from the same test.",
      "reachability: hxxps://vault[.]azure[.]net/.default removed. Eq passes it to getToken as an OAuth scope; it is not a host the payload contacts.",
      "g1 pQ0: the deliberate test is the sudo -n true exit status. The docker run in its catch is an escalation attempt, not a test: its result is unused, and .nothrow() on the sudo call means a failing sudo returns false without entering the catch. Not a condition."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "bun[.]sh:443",
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "raw[.]githubusercontent[.]com:443",
        "github[.]com:443"
      ],
      "reason": "Downloads the bun runtime, then contacts GitHub and the npm registry to exfiltrate data into attacker repos, create data repos, register a runner and republish the maintainer's packages."
    },
    {
      "axis": "installed_tool",
      "value": [
        "bun",
        "curl",
        "bash"
      ],
      "reason": "bun_environment.js is executed by the bun runtime (downloaded via curl|bash on non-Windows if bun is absent)."
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
        "accessor": "throws"
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
        "accessor": "throws"
      }
    },
    {
      "id": "c5",
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
      "id": "c9",
      "category": "target_artifact",
      "api": "String.startsWith",
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
      "id": "c10",
      "category": "target_artifact",
      "api": "String.match",
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
            "start_byte": 9385179,
            "end_byte": 9385204,
            "node_type": "binary_expression",
            "sha256": "c73f091468d42804",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs/promises.readFile",
        "target": "*/.npmrc",
        "accessor": "content"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1 && c2 && c3 && c4",
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
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "On a GitHub Actions Linux runner that carries the CI agent process and passwordless sudo, it stops systemd-resolved and flushes the iptables OUTPUT and DOCKER-USER chains to blind network monitoring.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "defense_evasion"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": null,
            "RUNNER_OS": "Linux"
          },
          "installed_tool": [
            "sudo"
          ],
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
            "end_byte": 9404052,
            "node_type": "expression_statement",
            "sha256": "57ff3a62fefab653",
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
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "((c5 && c9) || c8) && c6 && c7 && c10",
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
            "c9",
            "c8"
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
      "effect": "selects",
      "purpose": "data_availability",
      "purpose_reason": "Decides on credential availability: with no ghp_/gho_ token in the environment or from gh auth token (or no exfil repo) and no token recovered from campaign repos, an npm token from NPM_TOKEN or .npmrc selects republishing the victim's packages, and no npm token selects shredding the user's home directory.",
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
            "start_byte": 9405572,
            "end_byte": 9406129,
            "node_type": "statement_block",
            "sha256": "467439bab9428748",
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
        "requires": [
          "c5",
          "c9",
          "c8",
          "c6"
        ],
        "min_conditions": 5,
        "behaviours": [
          "self_propagation",
          "modify_other_packages"
        ],
        "env_recipe": {
          "env_var": {
            "NPM_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bun_environment.js",
            "derived_from": "d1",
            "start_byte": 9405548,
            "end_byte": 9405568,
            "node_type": "expression_statement",
            "sha256": "4ca93c596caff17d",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9390922,
              "end_byte": 9390956,
              "node_type": "call_expression",
              "sha256": "e276692f75d33d78",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9405554,
                  "end_byte": 9405567,
                  "node_type": "call_expression",
                  "sha256": "887fff186fc37386",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9402942,
                  "end_byte": 9403658,
                  "node_type": "function_declaration",
                  "sha256": "01d73ddff68c5bde",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9403307,
                  "end_byte": 9403344,
                  "node_type": "call_expression",
                  "sha256": "f6513c4f4c753124",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9389200,
                  "end_byte": 9391284,
                  "node_type": "method_definition",
                  "sha256": "67957f21d6dc3086",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "exec",
            "sink": {
              "file": "bun_environment.js",
              "derived_from": "d1",
              "start_byte": 9390922,
              "end_byte": 9390956,
              "node_type": "call_expression",
              "sha256": "e276692f75d33d78",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9405554,
                  "end_byte": 9405567,
                  "node_type": "call_expression",
                  "sha256": "887fff186fc37386",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9402942,
                  "end_byte": 9403658,
                  "node_type": "function_declaration",
                  "sha256": "01d73ddff68c5bde",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9403307,
                  "end_byte": 9403344,
                  "node_type": "call_expression",
                  "sha256": "f6513c4f4c753124",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bun_environment.js",
                  "derived_from": "d1",
                  "start_byte": 9389200,
                  "end_byte": 9391284,
                  "node_type": "method_definition",
                  "sha256": "67957f21d6dc3086",
                  "line": 1
                }
              }
            ]
          }
        ]
      }
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read",
      "exfil",
      "download",
      "self_propagation",
      "modify_other_packages",
      "persistence",
      "spawn_process"
    ],
    "gated": [
      "defense_evasion",
      "destructive",
      "self_propagation",
      "modify_other_packages"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "string array",
      "string array (recovered)",
      "dynamic_eval",
      "dead-code injection",
      "opaque predicates",
      "hex_identifiers",
      "long_base64_literal",
      "long_hex_literal",
      "very_long_lines",
      "bundling"
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
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://api[.]github[.]com",
        "role": "c2"
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
        "indicator": "hxxp://169[.]254[.]169[.]254",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://oauth2[.]googleapis[.]com/token",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://sts[.]amazonaws[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://login[.]microsoftonline[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud-second-coming",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook downloads the bun runtime and runs a 10 MB obfuscated worm that reads npm, GitHub and cloud credentials (also running trufflehog over the home directory), exfiltrates them into attacker-created GitHub repos, self-propagates by republishing the maintainer's npm packages with the same preinstall, and registers a self-hosted GitHub Actions runner for persistence. On GitHub Actions Linux runners it tries privilege escalation and disables network monitoring, and when no credentials are found it shreds the home directory.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Gates g1 and g2 are out-of-set: g1's inner guard and all of g2's guards, plus c5 to c10, were added by hand from the de-obfuscated bun_environment.js. Only g1's outer guard and c1 to c4 are extractor candidates.",
    "g2 else.min_conditions is 5 because else.requires must list every condition of the outer guard; the route through c8 alone needs 3. Enclosing conditions c6 and c8 are server_response and out of scope.",
    "g1 privilege is guessed (the code tests passwordless sudo) and no recipe key expresses c3's agent process. g2's recipe cannot express c5 (gh logged out) or c9 (no env value with the prefix).",
    "self_propagation and modify_other_packages are listed ungated, but El publishes only after Wl.validateToken returns a user: a server_response test not modelled as a condition. A person should decide whether it needs its own gate.",
    "reachability.endpoints kept by reading the payload classes; hosts the bundled cloud SDKs choose at run time (for example the GoogleAuth metadata hosts) were not traced through the SDK code.",
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
        "note": "os==win32 check only picks where/which bun lookup; plumbing to locate bun, not a gate on the payload.",
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
        "note": "os==win32 check only selects the powershell vs curl bun installer command; plumbing, both arms bootstrap bun.",
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
        "note": "os==win32/!=win32 branch in reloadPath only chooses how to refresh PATH; plumbing, not an env gate.",
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
        "note": "os==win32 check in findBunExecutable only picks platform bun paths; plumbing to locate bun.",
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
        "note": "existsSync on shell profile files only to source them and refresh PATH; plumbing, not a gate.",
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
        "note": "existsSync on candidate bun binary paths only to locate bun; plumbing.",
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
        "note": "existsSync ~/.bun/bin only to decide whether to prepend it to PATH; plumbing.",
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
        "note": "PATH.includes(~/.bun/bin) only to avoid prepending twice; plumbing.",
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
        "note": "existsSync bun_environment.js only confirms the bundled payload shipped before launching it; prerequisite/plumbing.",
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
        "note": "ternary where/which bun; plumbing guard for locating bun.",
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
        "note": "win32 branch choosing the powershell bun installer; plumbing.",
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
        "note": "reloadPath win32/else branch choosing how to refresh PATH; plumbing.",
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
        "note": "findBunExecutable win32 branch picking platform bun paths; plumbing.",
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
        "note": "non-win32 branch of reloadPath only sources profiles/refreshes PATH; plumbing.",
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
        "note": "per-profile existsSync guard to source shell profiles; plumbing.",
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
        "note": "guard that prepends ~/.bun/bin to PATH when present and missing; plumbing.",
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
        "note": "guard returning a located bun binary path; plumbing to locate bun.",
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
        "note": "guard that launches bun_environment.js when the bundled payload exists; prerequisite/plumbing, the real gates are inside the payload.",
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
    "conditions_out_of_set": 6,
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
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
