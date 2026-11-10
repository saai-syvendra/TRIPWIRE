# npm @sentry/cli@3.8.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-22 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node ./scripts/install.js`, the official Sentry CLI fallback installer. It exits at once when `SENTRYCLI_SKIP_DOWNLOAD=1`, throws on an OS/arch pair it has no binary for, and exits 0 when the platform's optional dependency (`@sentry/cli-<platform>`) resolves, which is the normal case. Only when optional dependencies were omitted does it go on: with `SENTRYCLI_USE_LOCAL=1` it copies a `sentry-cli` found on PATH into the package, otherwise it downloads the matching binary from downloads[.]sentry-cdn[.]com, checks its checksum against `checksums.txt` and copies it into place. It then runs the binary with `--version` to confirm the version. The environment that opens the download is a supported OS/arch, no skip variable, and an install with optional dependencies left out.

## Execution

- **postinstall** `node ./scripts/install.js`: 3-file chain; direct_script, download_then_exec.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && (c2 \|\| ((c3 \|\| c4 \|\| c5) && (c6 \|\| c7 \|\| c8 \|\| c9 \|\| c10)) \|\| (c11 && (c6 \|\| c7 \|\| c8 \|\| c9))) && c14 (c1: process.env.SENTRYCLI_SKIP_DOWNLOAD != 1; c2: os == darwin; c3: os == linux; c4: os == freebsd; c5: os == android; c6: arch == x64; c7: arch == x86; c8: arch == ia32; c9: arch == arm64; c10: arch == arm; c11: os == win32; c14: dependency_tree not_exists) | then | 3 | exec_downloaded | env_var_absent=SENTRYCLI_SKIP_DOWNLOAD; os=linux; arch=x64 |
| g2 | postinstall | c1 && (c2 \|\| ((c3 \|\| c4 \|\| c5) && (c6 \|\| c7 \|\| c8 \|\| c9 \|\| c10)) \|\| (c11 && (c6 \|\| c7 \|\| c8 \|\| c9))) && c14 && c13 (c1: process.env.SENTRYCLI_SKIP_DOWNLOAD != 1; c2: os == darwin; c3: os == linux; c4: os == freebsd; c5: os == android; c6: arch == x64; c7: arch == x86; c8: arch == ia32; c9: arch == arm64; c10: arch == arm; c11: os == win32; c14: dependency_tree not_exists; c13: process.env.SENTRYCLI_USE_LOCAL == 1) | then | 4 | write_file | env_var=SENTRYCLI_USE_LOCAL=1; env_var_absent=SENTRYCLI_SKIP_DOWNLOAD; os=linux; arch=x64; installed_tool=sentry-cli |
| | |  | else | 4 | download, write_file | env_var_absent=SENTRYCLI_SKIP_DOWNLOAD, SENTRYCLI_USE_LOCAL; os=darwin; network=downloads[.]sentry-cdn[.]com:443=reachable |
| g3 | postinstall | c1 && (c2 \|\| ((c3 \|\| c4 \|\| c5) && (c6 \|\| c7 \|\| c8 \|\| c9 \|\| c10)) \|\| (c11 && (c6 \|\| c7 \|\| c8 \|\| c9))) && c14 && c15 (c1: process.env.SENTRYCLI_SKIP_DOWNLOAD != 1; c2: os == darwin; c3: os == linux; c4: os == freebsd; c5: os == android; c6: arch == x64; c7: arch == x86; c8: arch == ia32; c9: arch == arm64; c10: arch == arm; c11: os == win32; c14: dependency_tree not_exists; c15: process.env.SENTRYCLI_SKIP_CHECKSUM_VALIDATION != 1) | then | 4 | delete_file | env_var_absent=SENTRYCLI_SKIP_DOWNLOAD, SENTRYCLI_USE_LOCAL, SENTRYCLI_SKIP_CHECKSUM_VALIDATION; os=linux; arch=x64; network=downloads[.]sentry-cdn[.]com:443=reachable |

Gate intent: g1 activate/enables/portability; g2 activate/selects/unclear; g3 activate/enables/unclear

Grounding: 13 of 14 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c14, g1, g2, g3.

## Requirements

- network: downloads[.]sentry-cdn[.]com:443 (fallback download of the sentry-cli binary (CDN overridable by SENTRYCLI_CDNURL and similar env vars))
- other: optional dependency @sentry/cli-<platform> not installed (install exits 0 before any download when the optional dependency binary resolves)

## Behaviour

- Ungated: none
- Gated: exec_downloaded, write_file, download, delete_file

## Notes

- The optional-dependency check (c14) is out of scope (dependency_tree) and recorded out of set; it is the main reason a stock install never downloads anything.
- The platform guard is cited at `install.js:313` (`distributionPackageName === undefined`), which reads the OS/arch tests in `getDistributionForThisPlatform`; this guard and the try/catch guard at line 317 are out of set.
- Cache reuse, cache folder choice, `.exe` naming and `SENTRY_BINARY_PATH` are treated as plumbing and dropped with reasons.
- `SENTRYCLI_SKIP_CHECKSUM_VALIDATION` is gate g3: unless it is `1`, a download whose hash does not match is deleted and the install aborts before the copy and version run. A sink that serves anything but the real binary needs it set to reach those steps.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@sentry/cli",
    "version": "3.8.2",
    "archive_sha256": "bf41352446858449efcf8644a4c416c1e11210635b7f1c294340dac5daf9d9ac",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-22",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/cli-3.8.2.tgz",
    "package_root": "layer0/package",
    "cluster_key": "e69cd439a309a0ad2fa166787177c6b32cde21294315849d8283af979d116cb2",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node ./scripts/install.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/install.js",
          "js/helper.js",
          "js/logger.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): sentry-cli",
      "optionalDependencies (platform picks belong to the dependency tree): @sentry/cli-darwin, @sentry/cli-linux-arm, @sentry/cli-linux-arm64, @sentry/cli-linux-i686, @sentry/cli-linux-x64, @sentry/cli-win32-i686, @sentry/cli-win32-x64, @sentry/cli-win32-arm64",
      "bin/sentry-cli: read in full; it is the package's bin wrapper that spawns the resolved binary when a user runs sentry-cli. Install never runs it; helper.js:26 only names the optional dependency's bin/sentry-cli subpath.",
      "generator truncated: some helpers walked under only 2 guard contexts in js/helper.js; candidates there may be missing",
      "Coverage: scripts/install.js, js/helper.js and js/logger.js read in full (small, plain, unminified package code); nothing unread.",
      "Normal installs exit early: when the platform's optional dependency resolves (require.resolve at install.js:318), the script exits 0 and nothing is downloaded. The download only runs when optional deps were omitted.",
      "c14 (optional dependency not resolvable) is category dependency_tree and has no env_recipe key; Phase 2 needs an install with optional deps omitted (e.g. --omit=optional) to reach the gated behaviours.",
      "g2 else.requires lists c1, c2 (darwin) and c14 so else.min_conditions counts one platform path; any supported os/arch pair from the g1 expression works the same way.",
      "getDownloadUrl (install.js:55-87) switches on os/arch only to pick the platform-specific binary URL of the same download (portability); the same os/arch conditions are already in the gate expressions.",
      "Plumbing not recorded as gates: npm cache folder choice (npm_config_cache*, APPDATA), reuse of a cached download (existsSync at install.js:214), .exe suffix and subpath per OS, and SENTRY_BINARY_PATH / fallback-path lookup in getBinaryPath when checkVersion runs the binary.",
      "g3 (c15, SENTRYCLI_SKIP_CHECKSUM_VALIDATION): the delete and abort also need a hash mismatch (install.js:177), a test of the downloaded bytes not recorded as a condition. A sink reply that is not the real binary is stopped unless the variable is 1; a matching download passes either way.",
      "g3 sits on the false side of c13, which cannot be written positively in the expression; its recipe lists SENTRYCLI_USE_LOCAL as absent. Reusing a cached download (install.js:214) also returns before the check.",
      "The checksums.txt read (install.js:154) is not a gate: the file ships in the package, so the environment does not decide it.",
      "checkVersion runs the installed binary with --version via helper.execute -> execFile. On the SENTRYCLI_USE_LOCAL path that binary is a copy of a sentry-cli found on PATH rather than a download.",
      "g1 exec path: execute's body is a generator passed to the TypeScript __awaiter helper (helper.js:2-10), which starts it at once inside its Promise executor; the new Promise at helper.js:299 runs its executor at once too. checkVersion passes no live argument, so the execFile branch at line 315 runs."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "downloads[.]sentry-cdn[.]com:443",
      "reason": "fallback download of the sentry-cli binary (CDN overridable by SENTRYCLI_CDNURL and similar env vars)"
    },
    {
      "axis": "other",
      "value": "optional dependency @sentry/cli-<platform> not installed",
      "reason": "install exits 0 before any download when the optional dependency binary resolves"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.SENTRYCLI_SKIP_DOWNLOAD",
      "operator": "!=",
      "value": "1",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_c924bf938f",
          "anchor": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8651,
            "end_byte": 8694,
            "node_type": "binary_expression",
            "sha256": "5f0e0abf6318dd4c",
            "line": 305
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "darwin",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b31e233ded",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2671,
            "end_byte": 2692,
            "node_type": "binary_expression",
            "sha256": "919f0e281f95396c",
            "line": 55
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_84e101a593",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2759,
            "end_byte": 2779,
            "node_type": "binary_expression",
            "sha256": "f8935c1af1f85b89",
            "line": 58
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "freebsd",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_52a39488ce",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2783,
            "end_byte": 2805,
            "node_type": "binary_expression",
            "sha256": "a5c24de18dfd19e2",
            "line": 58
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "android",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_00c8b99465",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2809,
            "end_byte": 2831,
            "node_type": "binary_expression",
            "sha256": "45b87abcb3e186e7",
            "line": 58
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "x64",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7f8b763ef8",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2871,
            "end_byte": 2960,
            "node_type": "switch_case",
            "sha256": "a92374b6451aa1a6",
            "line": 60
          }
        },
        {
          "candidate": "k_7df40b8fb7",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3386,
            "end_byte": 3475,
            "node_type": "switch_case",
            "sha256": "e4ef2a1b8df939b8",
            "line": 77
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "x86",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b9090015e0",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2973,
            "end_byte": 2984,
            "node_type": "switch_case",
            "sha256": "89fda0c656a21757",
            "line": 63
          }
        },
        {
          "candidate": "k_719d76b506",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3488,
            "end_byte": 3499,
            "node_type": "switch_case",
            "sha256": "89fda0c656a21757",
            "line": 80
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c8",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "ia32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1cca4c87f0",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 2997,
            "end_byte": 3088,
            "node_type": "switch_case",
            "sha256": "acc2b39a452d09d8",
            "line": 64
          }
        },
        {
          "candidate": "k_e9a7886e55",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3512,
            "end_byte": 3603,
            "node_type": "switch_case",
            "sha256": "0b714f536314f161",
            "line": 81
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c9",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "arm64",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_61a6ff60a8",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3101,
            "end_byte": 3194,
            "node_type": "switch_case",
            "sha256": "2118c65d7cbfe206",
            "line": 67
          }
        },
        {
          "candidate": "k_2ffe739228",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3616,
            "end_byte": 3709,
            "node_type": "switch_case",
            "sha256": "f010e2a1789f7528",
            "line": 84
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c10",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "arm",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_37dc7fe384",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3207,
            "end_byte": 3296,
            "node_type": "switch_case",
            "sha256": "18d479ac157d51be",
            "line": 70
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c11",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1255b6af61",
          "anchor": {
            "file": "js/helper.js",
            "derived_from": null,
            "start_byte": 3326,
            "end_byte": 3346,
            "node_type": "binary_expression",
            "sha256": "a519771ad2d97f0b",
            "line": 75
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c13",
      "category": "env_var",
      "api": "process.env.SENTRYCLI_USE_LOCAL",
      "operator": "==",
      "value": "1",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_96e470537f",
          "anchor": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 5028,
            "end_byte": 5067,
            "node_type": "binary_expression",
            "sha256": "50c12ba6f9b6fcbb",
            "line": 192
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c14",
      "category": "dependency_tree",
      "api": "require.resolve",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "probe": {
        "kind": "file",
        "callee": "require.resolve",
        "target": "*/*",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 9020,
            "end_byte": 9088,
            "node_type": "call_expression",
            "sha256": "4d13e321fe00c5f0",
            "line": 318
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c15",
      "category": "env_var",
      "api": "process.env.SENTRYCLI_SKIP_CHECKSUM_VALIDATION",
      "operator": "!=",
      "value": "1",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_3e1b048d05",
          "anchor": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8124,
            "end_byte": 8178,
            "node_type": "binary_expression",
            "sha256": "cdf2eae4782adb11",
            "line": 287
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1 && (c2 || ((c3 || c4 || c5) && (c6 || c7 || c8 || c9 || c10)) || (c11 && (c6 || c7 || c8 || c9))) && c14",
      "guards": [
        {
          "candidate": "q_1382f4357a",
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8647,
            "end_byte": 8797,
            "node_type": "if_statement",
            "sha256": "9bfb580a58a65a60",
            "line": 305
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8926,
            "end_byte": 8963,
            "node_type": "binary_expression",
            "sha256": "35099b6f4697b69c",
            "line": 313
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c4",
            "c5",
            "c6",
            "c7",
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 9012,
            "end_byte": 10358,
            "node_type": "try_statement",
            "sha256": "f39f69518be4f23f",
            "line": 317
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
      "purpose": "portability",
      "purpose_reason": "Fallback that fetches and runs the platform-specific sentry-cli binary when the optional dependency for this OS/arch is missing; skipped on user opt-out or an unsupported platform.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "exec_downloaded"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SENTRYCLI_SKIP_DOWNLOAD"
          ],
          "os": "linux",
          "arch": "x64"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 9526,
            "end_byte": 10356,
            "node_type": "stmt_range",
            "sha256": "746f8e368f7bea46",
            "line": 324
          }
        ],
        "payload": [
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "js/helper.js",
              "derived_from": null,
              "start_byte": 13156,
              "end_byte": 13421,
              "node_type": "call_expression",
              "sha256": "b690af1e22cbc203",
              "line": 315
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/install.js",
                  "derived_from": null,
                  "start_byte": 10218,
                  "end_byte": 10232,
                  "node_type": "call_expression",
                  "sha256": "9967759e2ecb63b6",
                  "line": 331
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/install.js",
                  "derived_from": null,
                  "start_byte": 8337,
                  "end_byte": 8645,
                  "node_type": "function_declaration",
                  "sha256": "2f5e1cdf42d3377a",
                  "line": 296
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/install.js",
                  "derived_from": null,
                  "start_byte": 8392,
                  "end_byte": 8421,
                  "node_type": "call_expression",
                  "sha256": "71deede6d0c999e0",
                  "line": 297
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "js/helper.js",
                  "derived_from": null,
                  "start_byte": 11309,
                  "end_byte": 13458,
                  "node_type": "function_declaration",
                  "sha256": "d6feeecac90210e8",
                  "line": 265
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "js/helper.js",
                  "derived_from": null,
                  "start_byte": 11379,
                  "end_byte": 13455,
                  "node_type": "call_expression",
                  "sha256": "857e75408d84bbc9",
                  "line": 266
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "js/helper.js",
                  "derived_from": null,
                  "start_byte": 12486,
                  "end_byte": 13447,
                  "node_type": "new_expression",
                  "sha256": "2ad877ac8b365a2f",
                  "line": 299
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
      "expression": "c1 && (c2 || ((c3 || c4 || c5) && (c6 || c7 || c8 || c9 || c10)) || (c11 && (c6 || c7 || c8 || c9))) && c14 && c13",
      "guards": [
        {
          "candidate": "q_1382f4357a",
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8647,
            "end_byte": 8797,
            "node_type": "if_statement",
            "sha256": "9bfb580a58a65a60",
            "line": 305
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8926,
            "end_byte": 8963,
            "node_type": "binary_expression",
            "sha256": "35099b6f4697b69c",
            "line": 313
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c4",
            "c5",
            "c6",
            "c7",
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 9012,
            "end_byte": 10358,
            "node_type": "try_statement",
            "sha256": "f39f69518be4f23f",
            "line": 317
          },
          "kind": "try_except",
          "arm": "else",
          "conditions": [
            "c14"
          ]
        },
        {
          "candidate": "q_53eb025e48",
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 5024,
            "end_byte": 5648,
            "node_type": "if_statement",
            "sha256": "bc152d7c1920f44c",
            "line": 192
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c13"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "unclear",
      "purpose_reason": "User setting that chooses between copying a sentry-cli already on PATH and downloading the binary from the Sentry CDN.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var": {
            "SENTRYCLI_USE_LOCAL": "1"
          },
          "env_var_absent": [
            "SENTRYCLI_SKIP_DOWNLOAD"
          ],
          "os": "linux",
          "arch": "x64",
          "installed_tool": [
            "sentry-cli"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 5069,
            "end_byte": 5648,
            "node_type": "statement_block",
            "sha256": "4a1e5a09f7f76e28",
            "line": 192
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/install.js",
              "derived_from": null,
              "start_byte": 5321,
              "end_byte": 5357,
              "node_type": "call_expression",
              "sha256": "75bf9791d0add18f",
              "line": 198
            },
            "witness": []
          }
        ]
      },
      "else": {
        "min_conditions": 4,
        "requires": [
          "c1",
          "c2",
          "c14"
        ],
        "behaviours": [
          "download",
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SENTRYCLI_SKIP_DOWNLOAD",
            "SENTRYCLI_USE_LOCAL"
          ],
          "os": "darwin",
          "network": {
            "downloads[.]sentry-cdn[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 5652,
            "end_byte": 8333,
            "node_type": "stmt_range",
            "sha256": "54677758e46b98d0",
            "line": 208
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "scripts/install.js",
              "derived_from": null,
              "start_byte": 6285,
              "end_byte": 6356,
              "node_type": "call_expression",
              "sha256": "3b243db65facb828",
              "line": 231
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/install.js",
              "derived_from": null,
              "start_byte": 8268,
              "end_byte": 8305,
              "node_type": "call_expression",
              "sha256": "e88bd81122001b65",
              "line": 292
            },
            "witness": []
          }
        ]
      }
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c1 && (c2 || ((c3 || c4 || c5) && (c6 || c7 || c8 || c9 || c10)) || (c11 && (c6 || c7 || c8 || c9))) && c14 && c15",
      "guards": [
        {
          "candidate": "q_1382f4357a",
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8647,
            "end_byte": 8797,
            "node_type": "if_statement",
            "sha256": "9bfb580a58a65a60",
            "line": 305
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8926,
            "end_byte": 8963,
            "node_type": "binary_expression",
            "sha256": "35099b6f4697b69c",
            "line": 313
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c4",
            "c5",
            "c6",
            "c7",
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 9012,
            "end_byte": 10358,
            "node_type": "try_statement",
            "sha256": "f39f69518be4f23f",
            "line": 317
          },
          "kind": "try_except",
          "arm": "else",
          "conditions": [
            "c14"
          ]
        },
        {
          "candidate": "q_4ebe331368",
          "site": {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8120,
            "end_byte": 8223,
            "node_type": "if_statement",
            "sha256": "bf4402163c380b72",
            "line": 287
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c15"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "User setting that decides whether the downloaded binary is hash-checked; a mismatch deletes it and aborts before the copy and version run, and skipping lets any download through.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "delete_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SENTRYCLI_SKIP_DOWNLOAD",
            "SENTRYCLI_USE_LOCAL",
            "SENTRYCLI_SKIP_CHECKSUM_VALIDATION"
          ],
          "os": "linux",
          "arch": "x64",
          "network": {
            "downloads[.]sentry-cdn[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/install.js",
            "derived_from": null,
            "start_byte": 8180,
            "end_byte": 8223,
            "node_type": "statement_block",
            "sha256": "245b63d10c9a058f",
            "line": 287
          }
        ],
        "payload": [
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "scripts/install.js",
              "derived_from": null,
              "start_byte": 4657,
              "end_byte": 4680,
              "node_type": "call_expression",
              "sha256": "8276cfd6ff39b6a0",
              "line": 178
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/install.js",
                  "derived_from": null,
                  "start_byte": 8186,
                  "end_byte": 8218,
                  "node_type": "call_expression",
                  "sha256": "863fbb32466b7ba6",
                  "line": 288
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/install.js",
                  "derived_from": null,
                  "start_byte": 3820,
                  "end_byte": 4872,
                  "node_type": "function_declaration",
                  "sha256": "2d482e664c37bd32",
                  "line": 151
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
      "exec_downloaded",
      "write_file",
      "download",
      "delete_file"
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
        "indicator": "hxxps://downloads[.]sentry-cdn[.]com/sentry-cli",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall script is the official Sentry CLI fallback installer: when the platform's optional dependency is missing it downloads the matching sentry-cli binary from the Sentry CDN (or copies a local one), checks its checksum and runs it with --version. No credential access, exfiltration or persistence.",
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
      "sha256": "46a52fae3b6bfb00"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_8132379db6",
        "reason_code": "other",
        "note": "subpath switch (helper.js:94): only picks bin/sentry-cli vs .exe file name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3872,
          "end_byte": 3886,
          "node_type": "switch_case",
          "sha256": "a0e72fc79ef19b9e",
          "line": 94
        }
      },
      {
        "candidate": "k_a411cbdf01",
        "reason_code": "other",
        "note": "subpath switch (helper.js:95): only picks the binary file name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3895,
          "end_byte": 3908,
          "node_type": "switch_case",
          "sha256": "18b5187329e83f1f",
          "line": 95
        }
      },
      {
        "candidate": "k_bf18ae2bcb",
        "reason_code": "other",
        "note": "subpath switch (helper.js:96): only picks the binary file name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3917,
          "end_byte": 3932,
          "node_type": "switch_case",
          "sha256": "b70ef007fb3abbcf",
          "line": 96
        }
      },
      {
        "candidate": "k_f9e922de13",
        "reason_code": "other",
        "note": "subpath switch (helper.js:97): only picks the binary file name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3941,
          "end_byte": 4015,
          "node_type": "switch_case",
          "sha256": "b7136ede55f0f70f",
          "line": 97
        }
      },
      {
        "candidate": "k_81a1a97247",
        "reason_code": "other",
        "note": "subpath switch (helper.js:91): only picks the .exe file name on win32, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3787,
          "end_byte": 3863,
          "node_type": "switch_case",
          "sha256": "4f9598d845e0c535",
          "line": 91
        }
      },
      {
        "candidate": "k_1be48aaffa",
        "reason_code": "other",
        "note": "process.platform win32 ternary (helper.js:48) only adds .exe to the fallback binary file name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2438,
          "end_byte": 2466,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 48
        }
      },
      {
        "candidate": "k_bd74cec5d4",
        "reason_code": "other",
        "note": "subpath switch default (helper.js:100) sets the same subpath as the other cases; no behaviour change",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 4024,
          "end_byte": 4091,
          "node_type": "switch_default",
          "sha256": "e78117f8fc210447",
          "line": 100
        }
      },
      {
        "candidate": "k_27e6b846b9",
        "reason_code": "other",
        "note": "APPDATA only chooses the npm cache folder for the download cache, plumbing",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 3333,
          "end_byte": 3352,
          "node_type": "member_expression",
          "sha256": "da8ef70289b358e9",
          "line": 130
        }
      },
      {
        "candidate": "k_d766e6937c",
        "reason_code": "other",
        "note": "existsSync on cached download (install.js:214): reuses an already-downloaded copy instead of fetching, plumbing",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 5849,
          "end_byte": 5874,
          "node_type": "call_expression",
          "sha256": "efad34a413fc9287",
          "line": 214
        }
      },
      {
        "candidate": "k_6e3b371f18",
        "reason_code": "other",
        "note": "existsSync on fallback binary path in getBinaryPath: only locates which binary checkVersion runs, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 5141,
          "end_byte": 5174,
          "node_type": "call_expression",
          "sha256": "e3e71f467278e8f7",
          "line": 134
        }
      },
      {
        "candidate": "k_3708b8b76c",
        "reason_code": "other",
        "note": "checksums.txt read only decides whether integrity validation runs; same copy and exec follow either way",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 3912,
          "end_byte": 3977,
          "node_type": "call_expression",
          "sha256": "6d9c5990c0852693",
          "line": 154
        }
      },
      {
        "candidate": "k_13e24a6d7b",
        "reason_code": "other",
        "note": "SENTRY_BINARY_PATH override in getBinaryPath only locates which binary the --version check runs, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 4837,
          "end_byte": 4867,
          "node_type": "member_expression",
          "sha256": "a8cb7964e070cbca",
          "line": 126
        }
      },
      {
        "candidate": "q_bb2673ebe4",
        "reason_code": "other",
        "note": "if at helper.js:55 only assigns packageName; the decision is the packageName === undefined guard at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2667,
          "end_byte": 3725,
          "node_type": "if_statement",
          "sha256": "e13b317e301817a4",
          "line": 55
        }
      },
      {
        "candidate": "q_b9a3e5845f",
        "reason_code": "other",
        "note": "if at helper.js:58 only assigns packageName; the decision is the packageName === undefined guard at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2755,
          "end_byte": 3725,
          "node_type": "if_statement",
          "sha256": "7cdb00b0b760fdfc",
          "line": 58
        }
      },
      {
        "candidate": "q_972a018caa",
        "reason_code": "other",
        "note": "switch case helper.js:60 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2871,
          "end_byte": 2960,
          "node_type": "switch_case",
          "sha256": "a92374b6451aa1a6",
          "line": 60
        }
      },
      {
        "candidate": "q_c03cfc30a3",
        "reason_code": "other",
        "note": "switch case helper.js:64 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2997,
          "end_byte": 3088,
          "node_type": "switch_case",
          "sha256": "acc2b39a452d09d8",
          "line": 64
        }
      },
      {
        "candidate": "q_1a444f1190",
        "reason_code": "other",
        "note": "switch case helper.js:67 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3101,
          "end_byte": 3194,
          "node_type": "switch_case",
          "sha256": "2118c65d7cbfe206",
          "line": 67
        }
      },
      {
        "candidate": "q_a1bd6ae45d",
        "reason_code": "other",
        "note": "switch case helper.js:70 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3207,
          "end_byte": 3296,
          "node_type": "switch_case",
          "sha256": "18d479ac157d51be",
          "line": 70
        }
      },
      {
        "candidate": "q_bd2a531cf7",
        "reason_code": "other",
        "note": "if at helper.js:75 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3322,
          "end_byte": 3725,
          "node_type": "if_statement",
          "sha256": "03db46ef7adf0e79",
          "line": 75
        }
      },
      {
        "candidate": "q_b069d83008",
        "reason_code": "other",
        "note": "switch case helper.js:77 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3386,
          "end_byte": 3475,
          "node_type": "switch_case",
          "sha256": "e4ef2a1b8df939b8",
          "line": 77
        }
      },
      {
        "candidate": "q_e3418a4968",
        "reason_code": "other",
        "note": "switch case helper.js:81 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3512,
          "end_byte": 3603,
          "node_type": "switch_case",
          "sha256": "0b714f536314f161",
          "line": 81
        }
      },
      {
        "candidate": "q_24cde2b84a",
        "reason_code": "other",
        "note": "switch case helper.js:84 only assigns packageName; decision is at install.js:313",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3616,
          "end_byte": 3709,
          "node_type": "switch_case",
          "sha256": "f010e2a1789f7528",
          "line": 84
        }
      },
      {
        "candidate": "q_f85512edee",
        "reason_code": "other",
        "note": "subpath switch case: binary file name only, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3787,
          "end_byte": 3863,
          "node_type": "switch_case",
          "sha256": "4f9598d845e0c535",
          "line": 91
        }
      },
      {
        "candidate": "q_91898e70c0",
        "reason_code": "other",
        "note": "subpath switch case: binary file name only, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 3941,
          "end_byte": 4015,
          "node_type": "switch_case",
          "sha256": "b7136ede55f0f70f",
          "line": 97
        }
      },
      {
        "candidate": "q_96bdec3f53",
        "reason_code": "other",
        "note": "subpath switch default: same subpath as other cases, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 4024,
          "end_byte": 4091,
          "node_type": "switch_default",
          "sha256": "e78117f8fc210447",
          "line": 100
        }
      },
      {
        "candidate": "q_61d4e46955",
        "reason_code": "other",
        "note": "ternary adds .exe suffix to the fallback binary name, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 2438,
          "end_byte": 2480,
          "node_type": "ternary_expression",
          "sha256": "36b4a4bf7b5f0593",
          "line": 48
        }
      },
      {
        "candidate": "q_4f40fc1876",
        "reason_code": "other",
        "note": "SENTRY_BINARY_PATH early return: locates which binary the version check runs, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 4833,
          "end_byte": 4923,
          "node_type": "if_statement",
          "sha256": "453c2e52289779e3",
          "line": 126
        }
      },
      {
        "candidate": "q_a3c4af0012",
        "reason_code": "other",
        "note": "fallback binary existsSync early return in getBinaryPath: binary lookup, plumbing",
        "anchor": {
          "file": "js/helper.js",
          "derived_from": null,
          "start_byte": 5137,
          "end_byte": 5354,
          "node_type": "if_statement",
          "sha256": "71768ff2bb921499",
          "line": 134
        }
      },
      {
        "candidate": "q_4cf8bc4688",
        "reason_code": "other",
        "note": "APPDATA early return in npmCache: cache folder choice, plumbing",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 3329,
          "end_byte": 3415,
          "node_type": "if_statement",
          "sha256": "6f338d2821aa6317",
          "line": 130
        }
      },
      {
        "candidate": "q_36aecfad5d",
        "reason_code": "other",
        "note": "try around checksums.txt read: integrity check toggle, not a behaviour change",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 3884,
          "end_byte": 4405,
          "node_type": "try_statement",
          "sha256": "8db7ab907c171df0",
          "line": 153
        }
      },
      {
        "candidate": "q_d87641f5f5",
        "reason_code": "other",
        "note": "cached download reuse (install.js:214): plumbing, both sides end with the binary copied into place",
        "anchor": {
          "file": "scripts/install.js",
          "derived_from": null,
          "start_byte": 5845,
          "end_byte": 5992,
          "node_type": "if_statement",
          "sha256": "28d67c6b6003cd02",
          "line": 214
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 29,
    "condition_sites_cited": 17,
    "guards_cited": 3,
    "candidates_dropped": 31,
    "conditions_in_set": 13,
    "conditions_out_of_set": 1,
    "guard_candidates": 22,
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c14",
      "g1",
      "g2",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
