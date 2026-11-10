# npm @antv/algorithm@0.3.26

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is a compromised release of the real `@antv/algorithm` graph library: the legitimate `lib/`, `es/` and `dist/` code is intact, but `package.json` gains a `preinstall` hook `bun run index.js`, and `index.js` is a ~500KB obfuscated Shai-Hulud "second coming" npm worm/stealer. At install the `IP()` entry first runs `YP()`, which applies evasion and reinfection checks, then harvests credentials from disk, shell (`gh auth token`, env), AWS (STS/Secrets Manager/SSM), Kubernetes, HashiCorp Vault, and local password managers, encrypts them (RSA + AES-GCM) and exfiltrates to `t[.]m-kosche[.]com` and attacker-created GitHub repos, self-propagates by trojanising the victim's npm packages and git repos, and installs persistence. The install gates are: a reinfection lock in tmpdir (exit when `tmp.0987654321.lock` exists and its owner PID is alive); a decoy-honeytoken evasion (exits if `GITHUB_TOKEN` starts with `ghp_decoyGitHubToken`); a Russian-locale exclusion (exits on `ru` locale/LANG); a persistence gate (install the kitty systemd/launchd C2 monitor only on non-CI hosts with >=4 CPUs); and a targeting gate that dumps the GitHub Actions `Runner.Worker` memory only on Linux Actions runners. A `SKIP_DOMAIN=true` switch changes the exfil channel to GitHub repos only. The environment that opens the full payload is any non-CI developer or CI machine whose `GITHUB_TOKEN` is not the decoy and whose locale is not Russian.

## Execution

- **preinstall** `bun run index.js`: runs index.js; direct_script, detached_child, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g2 | preinstall | c2 \|\| c10 (c2: file_or_dir_exists not_exists %TMP%/tmp.0987654321.lock; c10: process_list not_exists PID recorded in %TMP%/tmp.0987654321.lock) | then | 1 | recon, cred_read, exfil, download, write_file, self_propagation, spawn_process | file_absent=%TMP%/tmp.0987654321.lock |
| g7 | preinstall | c11 (c11: process.env.SKIP_DOMAIN == true) | then | 1 | exfil | env_var=SKIP_DOMAIN=true |
| | |  | else | 1 | exfil | env_var_absent=SKIP_DOMAIN |
| g3 | preinstall | c3 (c3: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken) | then | 1 | recon, cred_read, exfil, download, write_file, self_propagation, spawn_process | (none) |
| g4 | preinstall | c4 && c5 && c12 (c4: locale_language not_startswith ru; c5: locale_language not_startswith ru; c12: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, download, write_file, self_propagation, spawn_process | locale=en_US.UTF-8 |
| g5 | preinstall | c6 && c7 && c13 && c14 (c6: hardware >= 4; c7: process.env.CI != true; c13: process.env.GITHUB_ACTIONS != true; c14: process.env.JENKINS_HOME not_exists) | then | 4 | persistence | cpu_count=4; env_var_absent=CI, GITHUB_ACTIONS, JENKINS_HOME |
| g6 | preinstall | c8 && c9 (c8: process.env.GITHUB_ACTIONS == true; c9: process.env.RUNNER_OS == Linux) | then | 2 | cred_read, spawn_process | ci=github_actions; env_var=GITHUB_ACTIONS=true, RUNNER_OS=Linux |

Gate intent: g2 activate/enables/unclear; g7 activate/modifies/unclear; g3 evade/enables/anti_analysis; g4 activate/enables/targeting; g5 evade/enables/anti_analysis; g6 activate/enables/targeting

Grounding: 1 of 13 conditions and 0 of 6 gates from the candidate set; out of set, pending verification: c10, c11, c3, c4, c5, c6, c7, c12, c13, c14, c8, c9, g2, g7, g3, g4, g5, g6.

## Requirements

- network: t[.]m-kosche[.]com:443 (primary HTTPS exfil sink; DomainSender POSTs RSA+AES-GCM encrypted stolen secrets. api[.]github[.]com:443 and registry[.]npmjs[.]org:443 are also contacted for GitHub-repo exfil and npm self-propagation.)
- installed_tool: bun (preinstall hook runs `bun run index.js`; bun is a declared dependency and the payload downloads the bun runtime from github.com/oven-sh/bun if it is absent.)

## Behaviour

- Ungated: none
- Gated: recon, cred_read, exfil, download, write_file, self_propagation, spawn_process, persistence

## Notes

- `index.js` was decoded in three registered layers (`normalisation.derivations`): d1 obfuscator.io string array (`obfio_objprop`, rotation checksum matched), d2 a bespoke per-string substitution-permutation cipher (`scramble_feistel`, in-code key/salt, global fn `f2959c600`), d3 AES-256-GCM+gzip blobs (`aesgcm_gunzip`, fn `f`). All added conditions (g3-g6) are anchored into d3 with `value_recovered=decoded`, so they are out-of-set and flagged for review.
- All gates are out-of-set. The tool's lock gate (existsSync if inside `f6`) was rebuilt around the real decision, the `YP` early exit on `!f6()`, with `c10` (owner PID liveness via `process.kill(pid,0)`); the `_9()` lock cleanup candidates were dropped. `g7` (SKIP_DOMAIN) was added.
- All payload classes sit after the YP exits, so `behaviours.ungated` is empty and they are listed on g2-g4. `defense_evasion` was removed: the harden-runner code is never called.
- Dropped the prefilled `__DAEMONIZED` gate (k_c3d4066646 / q_13b92544b9): z6() re-spawns the process detached with `__DAEMONIZED=1`, and that check is a re-entry guard for its own child, not an environment gate.
- `DP('release.yml','/somerepository')` would OIDC-publish trojanised packages under GitHub Actions, but only when `GITHUB_REPOSITORY` includes the literal placeholder `/somerepository`, so it is inert on real victims (recorded as a note).
- Harden-runner/step-security disabling (docker.sock probe, privileged container escape, /etc/hosts blackhole) is defined but unreachable: `detectHardenRunner` is never called.
- Exfil payloads of g2/g3/g4 are traced from `IP()` through `A9.finalize`, `flush` and the bound `w9` dispatch arrow to `sender.send`; g7's are traced into each sender factory. The sender is chosen at run time from the senders array, so the last step stays `unresolved: dynamic_dispatch`.
- g4 joins three `ru` tests (ICU locale, the LC_ALL-first variable chain, the SystemRoot-only LANG-first chain). g5 joins the CPU test with three separate CI tests (`CI` and `GITHUB_ACTIONS` not `true`, `JENKINS_HOME` unset).
- `family_hint: shai-hulud` is grounded in code: the self-propagation repo description is `"niagA oG eW ereH :duluH-iahS"` (reversed "Shai-Hulud: Here We Go Again") and the generated repo names draw on Dune-themed word lists.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@antv/algorithm",
    "version": "0.3.26",
    "archive_sha256": "5b7a16dcd1fb5dad4426bb96eca6d530ac7a804bd4c995509e9ee666c1ce4ffa",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-05-19-@antv_algorithm-v0.3.26.zip",
    "package_root": "layer0/tmp/tmpodkq3u6r/@antv-algorithm/package",
    "cluster_key": "bf966d9da4cfb8f4d84036672e73de1b24d479e52ebf6ded8cfa99bdaaa71a62",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "bun run index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "sh",
        "launch_style": [
          "direct_script",
          "detached_child",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "non-registry optionalDependencies (dependency tree): @antv/setup (github:antvis/G2#1916faa365f2788b6e193514872d51a242876569)",
      "optionalDependencies (platform picks belong to the dependency tree): @antv/setup",
      "index.js: one ~500KB minified line, decoded in three registered layers: d1 obfuscator.io string-array (obfio_objprop, checksum matched); d2 bespoke per-string SPN cipher (scramble_feistel, in-code key/salt, fn f2959c600); d3 AES-256-GCM+gzip blobs (aesgcm_gunzip, fn f).",
      "index.js coverage: worm/stealer package code read in full; bundled node-tar/minipass/fflate audited by sink inventory (all hits library behaviour); nothing left unread.",
      "Entry IP() calls YP() first (evasion + reinfection guards), then collectors (BP + a second collector set) and senders; finally $g() persistence, lock cleanup, process.exit(0). The whole body is try/catch with exit(0), so failures are silent.",
      "Reinfection guard (g2): lock %TMP%/tmp.0987654321.lock; f6() returns false only when the lock exists and its recorded PID is alive (GP: process.kill(pid,0)); YP then exits. Otherwise f6 deletes a stale lock and writes its own PID.",
      "IP(): SKIP_DOMAIN=true (g7) routes exfil only through GitHub repo senders (a9); unset, the HTTPS DomainSender (p9) is tried first and GitHub senders are added when it is unhealthy.",
      "YP(): if(!Sg()&&z6())process.exit(0): on non-CI hosts the parent re-spawns itself detached and exits, on CI it runs inline. Same payload either way, so recorded as launch style (detached_child), not a gate.",
      "z6() re-spawns the process detached with env __DAEMONIZED=1 on non-CI hosts (detached_child that outlives the install); the __DAEMONIZED check inside z6 is a re-entry guard (dropped), not an environment gate.",
      "YP() also runs DP('release.yml','/somerepository'): under GITHUB_ACTIONS it OIDC-publishes trojanised packages via M9 only when GITHUB_REPOSITORY includes the literal placeholder '/somerepository', so it is inert on real victims (the other branch merely exits). Recorded as a note only.",
      "Harden-runner / step-security disabling (y6/wP/OP/VP: docker.sock probe, privileged container escape, /etc/hosts blackhole of stepsecurity.io) is defined but unreachable at install: detectHardenRunner is never called.",
      "Exfil path: A9.finalize -> flush -> this.dispatch (the w9 arrow bound in IP) -> sender.send. The sender is picked at run time from the senders array, so the last step to DomainSender (au) or GitHubSender (_u) stays dynamic_dispatch.",
      "Pw() also tests a module flag fg, set only after $g succeeds in the same process and $g runs once, so it is run state and not a condition. jg's third locale test only differs from '' when SystemRoot is set (Windows); recorded as c12.",
      "Self-propagation (ku worm): commits malicious .claude/.vscode SessionStart hooks and a CodeQL-named workflow (mg) that exfiltrates repo secrets to branches of victim repos.",
      "Self-propagation (g9/M9): downloads, trojanises (injects preinstall) and republishes the victim's own npm packages using stolen npm tokens or OIDC trusted publishing."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "t[.]m-kosche[.]com:443",
      "reason": "primary HTTPS exfil sink; DomainSender POSTs RSA+AES-GCM encrypted stolen secrets. api[.]github[.]com:443 and registry[.]npmjs[.]org:443 are also contacted for GitHub-repo exfil and npm self-propagation."
    },
    {
      "axis": "installed_tool",
      "value": "bun",
      "reason": "preinstall hook runs `bun run index.js`; bun is a declared dependency and the payload downloads the bun runtime from github.com/oven-sh/bun if it is absent."
    }
  ],
  "conditions": [
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "%TMP%/tmp.0987654321.lock",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7360973273",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494409,
            "end_byte": 494422,
            "node_type": "call_expression",
            "sha256": "9ac46e357e994172",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c10",
      "category": "process_list",
      "api": "process.kill",
      "operator": "not_exists",
      "value": "PID recorded in %TMP%/tmp.0987654321.lock",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 449677,
            "end_byte": 449707,
            "node_type": "call_expression",
            "sha256": "2a147129fe766633",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "env_var",
      "api": "process.env.SKIP_DOMAIN",
      "operator": "==",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451913,
            "end_byte": 451948,
            "node_type": "binary_expression",
            "sha256": "a2bdbe3318e200e5",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "not_startswith",
      "value": "ghp_decoyGitHubToken",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 405463,
            "end_byte": 405497,
            "node_type": "call_expression",
            "sha256": "5a468bcdb066b121",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat().resolvedOptions().locale",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 173778,
            "end_byte": 173876,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "locale_language",
      "api": "process.env.LC_ALL / process.env.LC_MESSAGES / process.env.LANGUAGE / process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 173899,
            "end_byte": 174037,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "hardware",
      "api": "os.cpus().length",
      "operator": ">=",
      "value": "4",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259269,
            "end_byte": 259294,
            "node_type": "binary_expression",
            "sha256": "ab43fe157de3ab2b",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259309,
            "end_byte": 259335,
            "node_type": "binary_expression",
            "sha256": "a1e133353ca470cc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "locale_language",
      "api": "process.env.LANG / process.env.LANGUAGE / process.env.LC_ALL",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 174052,
            "end_byte": 174191,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259337,
            "end_byte": 259375,
            "node_type": "binary_expression",
            "sha256": "40e7bb5a102680cb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "ci_marker",
      "api": "process.env.JENKINS_HOME",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259377,
            "end_byte": 259415,
            "node_type": "binary_expression",
            "sha256": "60afb22bc3c52114",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "==",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 406885,
            "end_byte": 406947,
            "node_type": "assignment_expression",
            "sha256": "52accd8ccfd307b4",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "env_var",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 406948,
            "end_byte": 407004,
            "node_type": "assignment_expression",
            "sha256": "7141cb4174362eef",
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
      "expression": "c2 || c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451106,
            "end_byte": 451205,
            "node_type": "if_statement",
            "sha256": "f57a0c5bd4eb3e61",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c10"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 451498,
              "end_byte": 451502,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "reinfection guard: YP() exits unless f6() succeeds, i.e. the tmpdir lock is absent or its recorded owner PID is no longer running.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "download",
          "write_file",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {
          "file_absent": [
            "%TMP%/tmp.0987654321.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451608,
            "end_byte": 451628,
            "node_type": "variable_declarator",
            "sha256": "8aa7c8450413a16f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 452454,
            "end_byte": 452536,
            "node_type": "variable_declarator",
            "sha256": "3e61d0fca836b73d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 453098,
            "end_byte": 453127,
            "node_type": "await_expression",
            "sha256": "bad28c1854e94ea3",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 440525,
              "end_byte": 440643,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 452502,
                  "end_byte": 452534,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 453104,
                  "end_byte": 453127,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 440289,
                  "end_byte": 440757,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g7",
      "hook": "preinstall",
      "expression": "c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451959,
            "end_byte": 452085,
            "node_type": "if_statement",
            "sha256": "dc9565fed506c7b5",
            "line": 1
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
      "effect": "modifies",
      "purpose": "unclear",
      "purpose_reason": "SKIP_DOMAIN=true sends stolen data only through attacker-created GitHub repos; otherwise the HTTPS DomainSender to t[.]m-kosche[.]com is tried first with GitHub as fallback.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var": {
            "SKIP_DOMAIN": "true"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451972,
            "end_byte": 452031,
            "node_type": "expression_statement",
            "sha256": "047ee4579e8aa1d6",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 445311,
              "end_byte": 445504,
              "node_type": "call_expression",
              "sha256": "1b4f88100ee6879b",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 451988,
                  "end_byte": 452030,
                  "node_type": "call_expression",
                  "sha256": "1d9705b9b37a311c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 447081,
                  "end_byte": 447277,
                  "node_type": "method_definition",
                  "sha256": "2d4af38fd960fc96",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 447239,
                  "end_byte": 447275,
                  "node_type": "call_expression",
                  "sha256": "8405c10acfb2fc99",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 448634,
                  "end_byte": 448894,
                  "node_type": "method_definition",
                  "sha256": "5a4766c50597678a",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SKIP_DOMAIN"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 452036,
            "end_byte": 452085,
            "node_type": "expression_statement",
            "sha256": "58ebc18adf4bf529",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 440525,
              "end_byte": 440643,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 452052,
                  "end_byte": 452084,
                  "node_type": "call_expression",
                  "sha256": "012cf3e653a614b6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 440853,
                  "end_byte": 441373,
                  "node_type": "method_definition",
                  "sha256": "0666f0d227ff2c78",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      }
    },
    {
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 450949,
            "end_byte": 450978,
            "node_type": "if_statement",
            "sha256": "b4cf7e9bb00709ff",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 451498,
              "end_byte": 451502,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "N6() exits if any configured env var (GITHUB_TOKEN) starts with the decoy honeytoken prefix ghp_decoyGitHubToken, backing off when it detects a planted analysis/honeypot token.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "download",
          "write_file",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451608,
            "end_byte": 451628,
            "node_type": "variable_declarator",
            "sha256": "8aa7c8450413a16f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 452454,
            "end_byte": 452536,
            "node_type": "variable_declarator",
            "sha256": "3e61d0fca836b73d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 453098,
            "end_byte": 453127,
            "node_type": "await_expression",
            "sha256": "bad28c1854e94ea3",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 440525,
              "end_byte": 440643,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 452502,
                  "end_byte": 452534,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 453104,
                  "end_byte": 453127,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 440289,
                  "end_byte": 440757,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c4 && c5 && c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 450978,
            "end_byte": 451049,
            "node_type": "if_statement",
            "sha256": "6f209f58a61aefe9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c5",
            "c12"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 451498,
              "end_byte": 451502,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "jg() exits if the ICU locale, the first set of LC_ALL/LC_MESSAGES/LANGUAGE/LANG, or (when SystemRoot is set) the first set of LANG/LANGUAGE/LC_ALL begins with 'ru', excluding Russian-locale machines from the victim set.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "download",
          "write_file",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {
          "locale": "en_US.UTF-8"
        },
        "recipe_guessed_fields": [
          "locale"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 451608,
            "end_byte": 451628,
            "node_type": "variable_declarator",
            "sha256": "8aa7c8450413a16f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 452454,
            "end_byte": 452536,
            "node_type": "variable_declarator",
            "sha256": "3e61d0fca836b73d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 453098,
            "end_byte": 453127,
            "node_type": "await_expression",
            "sha256": "bad28c1854e94ea3",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 440525,
              "end_byte": 440643,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 452502,
                  "end_byte": 452534,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 453104,
                  "end_byte": 453127,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 440289,
                  "end_byte": 440757,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "preinstall",
      "expression": "c6 && c7 && c13 && c14",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259561,
            "end_byte": 259577,
            "node_type": "if_statement",
            "sha256": "6ca019ce8a326442",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c6",
            "c7",
            "c13",
            "c14"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "Pw() installs the kitty systemd/launchd GitHub-commit C2 persistence only when the host has >=4 CPUs and is not CI (CI and GITHUB_ACTIONS not 'true', JENKINS_HOME unset), avoiding low-resource sandboxes and CI runners.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "env_var_absent": [
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_HOME"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259660,
            "end_byte": 259698,
            "node_type": "call_expression",
            "sha256": "4c54a6b9a2716d81",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 259713,
            "end_byte": 259804,
            "node_type": "call_expression",
            "sha256": "cb15028c9605d5c4",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 259713,
              "end_byte": 259804,
              "node_type": "call_expression",
              "sha256": "cb15028c9605d5c4",
              "line": 1
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g6",
      "hook": "preinstall",
      "expression": "c8 && c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 408238,
            "end_byte": 408337,
            "node_type": "if_statement",
            "sha256": "b1e511154a875204",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8",
            "c9"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "h9 dumps the GitHub Actions Runner.Worker process memory (privileged sudo python3 reading /proc/<pid>/mem) for CI secrets only on Linux Actions runners (GITHUB_ACTIONS=true and RUNNER_OS=Linux).",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read",
          "spawn_process"
        ],
        "env_recipe": {
          "ci": "github_actions",
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d3",
            "start_byte": 408449,
            "end_byte": 408469,
            "node_type": "call_expression",
            "sha256": "57b51004d0c39d8c",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 407658,
              "end_byte": 407729,
              "node_type": "call_expression",
              "sha256": "13fd80041bd10df5",
              "line": 1
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407731,
                  "end_byte": 408033,
                  "node_type": "method_definition",
                  "sha256": "661a24dc55eb4a8c",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407925,
                  "end_byte": 408000,
                  "node_type": "call_expression",
                  "sha256": "e3895ac5f0c64587",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407553,
                  "end_byte": 407731,
                  "node_type": "method_definition",
                  "sha256": "76bb507748551997",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d3",
              "start_byte": 407658,
              "end_byte": 407729,
              "node_type": "call_expression",
              "sha256": "13fd80041bd10df5",
              "line": 1
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407731,
                  "end_byte": 408033,
                  "node_type": "method_definition",
                  "sha256": "661a24dc55eb4a8c",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407925,
                  "end_byte": 408000,
                  "node_type": "call_expression",
                  "sha256": "e3895ac5f0c64587",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d3",
                  "start_byte": 407553,
                  "end_byte": 407731,
                  "node_type": "method_definition",
                  "sha256": "76bb507748551997",
                  "line": 1
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
      "recon",
      "cred_read",
      "exfil",
      "download",
      "write_file",
      "self_propagation",
      "spawn_process",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "obfuscator.io string-array with rotation checksum",
      "base64 string encoding",
      "bespoke per-string substitution-permutation cipher (pbkdf2+sha256 keystream)",
      "AES-256-GCM + gzip embedded payload blobs",
      "hex identifiers",
      "very long single-line file",
      "bundled third-party libraries (node-tar, minipass, fflate)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "t[.]m-kosche[.]com:443",
        "role": "exfil_sink"
      },
      {
        "indicator": "api[.]github[.]com",
        "role": "c2"
      },
      {
        "indicator": "registry[.]npmjs[.]org",
        "role": "c2"
      },
      {
        "indicator": "github[.]com/oven-sh/bun/releases",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The compromised @antv/algorithm adds a preinstall hook (bun run index.js) running a heavily obfuscated Shai-Hulud 'second coming' worm/stealer. At install it harvests filesystem credentials, cloud/CI secrets (AWS, k8s, Vault, GitHub/npm tokens, password managers), exfiltrates them encrypted to t[.]m-kosche[.]com and attacker-created GitHub repos, self-propagates by trojanising the victim's npm packages and repos, and installs persistence. The legitimate graph-algorithm library is still present, confirming a maintainer/package compromise rather than a new package.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out-of-set gates (g3-g6) added for the install-path evasion/targeting/persistence checks: decoy GITHUB_TOKEN honeytoken, Russian-locale exclusion, cpu>=4/non-CI persistence gate, and GitHub Actions Linux runner memory-dump.",
    "All out-of-set condition values recovered only after a three-layer custom decode (obfuscator.io string array, SPN cipher, AES-GCM blobs); value_recovered=decoded, anchored into derived d3.",
    "g2 rebuilt as out-of-set: guard is the YP early exit on !f6() (lock absent or owner PID dead), not the existsSync if inside f6; g7 (SKIP_DOMAIN exfil channel switch) added out-of-set.",
    "Exfil payload witness for g2/g3/g4/g7 is traced as far as the static code allows; the final step to the sender's send method is dynamic dispatch over the run-time senders array, left unresolved.",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": null
        },
        "params": {
          "decoder": "obfio_objprop",
          "lang": "js"
        },
        "output_sha256": "4e6e99960f741939"
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d1"
        },
        "params": {
          "key": "a8269c01069452afb8a54de904e6419578d155fdbdb9e566bab8576a4266b61e",
          "salt": "7f44e4ba6f6a71bd0f789e7f83bd3104",
          "fn": "f2959c600",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "99cf81e2b43f88a7"
      },
      {
        "id": "d3",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d2"
        },
        "params": {
          "fn": "f",
          "decoder": "aesgcm_gunzip",
          "lang": "js"
        },
        "output_sha256": "ee88e87786e6548a"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "802e30935ed6dc53"
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
        "candidate": "k_c3d4066646",
        "reason_code": "re_entry_guard",
        "note": "process.env.__DAEMONIZED check inside z6(); guards the detached re-spawn so the daemonized child does not re-daemonize. Re-entry guard, not an environment gate.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493488,
          "end_byte": 493512,
          "node_type": "member_expression",
          "sha256": "08e4ec2c1b30613e",
          "line": 1
        }
      },
      {
        "candidate": "q_13b92544b9",
        "reason_code": "re_entry_guard",
        "note": "if(process.env.__DAEMONIZED)return in z6(); re-entry guard for the payload's own detached child (__DAEMONIZED=1).",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493485,
          "end_byte": 493524,
          "node_type": "if_statement",
          "sha256": "5c2fbc3955369d6c",
          "line": 1
        }
      },
      {
        "candidate": "q_a503be1583",
        "reason_code": "duplicate_of",
        "note": "if(existsSync(lock)) inside helper f6(); its result is consumed by the YP early exit if(...,!f6())process.exit(0), cited as g2's guard. c2's site stays on the existsSync call.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 494406,
          "end_byte": 494526,
          "node_type": "if_statement",
          "sha256": "22def24b67717976",
          "line": 1
        }
      },
      {
        "candidate": "k_d8a35f6c4e",
        "reason_code": "not_environmental",
        "note": "existsSync(lock) in _9(): end-of-run cleanup that deletes the payload's own lock; it does not decide whether any behaviour runs.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 494644,
          "end_byte": 494657,
          "node_type": "call_expression",
          "sha256": "9ac46e357e994172",
          "line": 1
        }
      },
      {
        "candidate": "q_ccad5d9036",
        "reason_code": "not_environmental",
        "note": "if(existsSync(lock))unlinkSync(lock) in _9(): cleanup of the payload's own lock after the run, not a gate.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 494641,
          "end_byte": 494672,
          "node_type": "if_statement",
          "sha256": "93da865ef1b9fa01",
          "line": 1
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 1,
    "guards_cited": 0,
    "candidates_dropped": 5,
    "conditions_in_set": 1,
    "conditions_out_of_set": 12,
    "guard_candidates": 8,
    "gates_in_set": 0,
    "gates_out_of_set": 6,
    "out_of_set_ids": [
      "c10",
      "c11",
      "c3",
      "c4",
      "c5",
      "c6",
      "c7",
      "c12",
      "c13",
      "c14",
      "c8",
      "c9",
      "g2",
      "g7",
      "g3",
      "g4",
      "g5",
      "g6"
    ],
    "anchor_refusals": 0
  }
}
```
