# npm @anthropic-ai/claude-code@2.1.310

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-23 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node install.cjs`, which builds a platform key from `process.platform`, `os.arch()` and a musl check, then hard-links (or copies) the native `claude` binary from the matching platform optional dependency over the `bin/claude.exe` stub. That placement (g2) only happens on linux, darwin or win32 with x64 or arm64, not android, and only when the platform package resolves; otherwise the script prints instructions and returns. On x64 macOS, g1 runs `sysctl -n sysctl.proc_translated` to detect Rosetta 2 and prefer the arm64 binary. A stock Linux x64 sandbox with the optional dependency installed opens g2. The `prepare` hook only blocks publishing from a checkout unless `AUTHORIZED` is set.

## Execution

- **postinstall** `node install.cjs`: runs install.cjs; direct_script; errors hidden.
- **prepare** `node -e "if (!process.env.AUTHORIZED) { console.error('ERROR: Direct publishing is not allowed.\nPlease see the release workflow documentation to publish this package.'); process.exit(1); }"`: runs on git or local install only; no package files; inline_eval.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c4 && c5 (c1: os != android; c2: os != linux; c4: os == darwin; c5: arch == x64) | then | 4 | spawn_process | os=darwin; arch=x64 |
| g2 | postinstall | c17 && c18 && c20 && c19 (c17: os in [linux, darwin, win32, android]; c18: arch in [x64, arm64]; c20: dependency_tree includes @anthropic-ai/claude-code-<platformKey>; c19: dependency_tree exists) | then | 4 | write_file | os=linux; arch=x64 |

Gate intent: g1 activate/enables/portability; g2 activate/enables/portability

Grounding: 4 of 8 conditions and 1 of 2 gates from the candidate set; out of set, pending verification: c17, c18, c19, c20, g2.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: spawn_process, write_file

## Notes

- g2's platform and arch conditions (c17, c18) are out of set: the decision is the `if (!info)` lookup in the PLATFORMS table, which the extractor did not see as a condition. Android passes that lookup but fails the `optionalDeps[info.pkg]` check (c20), because the android keys are not listed in the package's own optionalDependencies. That check tests the manifest, not `process.platform`, so g2 cites c20 rather than c1.
- c19 (native package resolves) and c20 (key listed in optionalDependencies) are dependency-tree conditions and out of scope.
- `cli-wrapper.cjs` is only named in a printed fallback message and is not run at install.
- The npm_config_omit check is dead code because FAIL_ON_MISSING_NATIVE is the constant false.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@anthropic-ai/claude-code",
    "version": "2.1.310",
    "archive_sha256": "d696314076114df499ba88e117000a24a9d7ab4f502dcaefba52c83fd22acfbd",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-23",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/claude-code-2.1.310.tgz",
    "package_root": "layer0/package",
    "cluster_key": "1b530a0968fefdd875e75f63ff76ba458190f5b26b2dbbb9be18736e2e8792ce",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node install.cjs",
        "runs_on": "always",
        "file_chain": [
          "install.cjs"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "prepare",
        "command": "node -e \"if (!process.env.AUTHORIZED) { console.error('ERROR: Direct publishing is not allowed.\\nPlease see the release workflow documentation to publish this package.'); process.exit(1); }\"",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "inline_eval"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): claude",
      "optionalDependencies (platform picks belong to the dependency tree): @anthropic-ai/claude-code-darwin-arm64, @anthropic-ai/claude-code-darwin-x64, @anthropic-ai/claude-code-linux-x64, @anthropic-ai/claude-code-linux-arm64, @anthropic-ai/claude-code-linux-x64-musl, @anthropic-ai/claude-code-linux-arm",
      "install.cjs: read in full (250 lines, plain package code, nothing bundled or unread).",
      "cli-wrapper.cjs: read in full; not run at install. install.cjs only prints its path in a 'Fallback: node ...' console.error message (lines 227 and 244); it is a manual fallback launcher.",
      "getPlatformKey builds a platform key from process.platform, os.arch() and a musl check (process.report glibcVersionRuntime). The musl and linux/android branches only choose which native binary key is used: plumbing, not gates.",
      "g1: c1 (not android) and c2 (not linux) are early returns inside getPlatformKey that come before the darwin test; they are implied by c4 but kept as the code tests them.",
      "FAIL_ON_MISSING_NATIVE is the constant 'false' === 'true', so failInstallUnlessOptionalOmitted always returns at once; its npm_config_omit test is dead code.",
      "Missing native package or unsupported platform only prints messages and returns with exit code 0; a failed placeBinary sets process.exitCode = 1. The stub restore write in placeBinary swallows its own error.",
      "prepare hook: exits 1 with an error unless AUTHORIZED is set, to block direct publishing from a checkout. Neither side runs a behaviour, so it is not recorded as a gate."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "!=",
      "value": "android",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7551c7c583",
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3013,
            "end_byte": 3035,
            "node_type": "binary_expression",
            "sha256": "45b87abcb3e186e7",
            "line": 86
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "os",
      "api": "process.platform",
      "operator": "!=",
      "value": "linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b6061c9852",
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3088,
            "end_byte": 3108,
            "node_type": "binary_expression",
            "sha256": "f8935c1af1f85b89",
            "line": 89
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "darwin",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8a0c36c663",
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3345,
            "end_byte": 3366,
            "node_type": "binary_expression",
            "sha256": "919f0e281f95396c",
            "line": 94
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "arch",
      "api": "os.arch()",
      "operator": "==",
      "value": "x64",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7b179814f2",
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3370,
            "end_byte": 3383,
            "node_type": "binary_expression",
            "sha256": "a6283b4861528b7a",
            "line": 94
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c17",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "linux",
        "darwin",
        "win32",
        "android"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 5703,
            "end_byte": 5725,
            "node_type": "subscript_expression",
            "sha256": "5810a1a61d075113",
            "line": 167
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c18",
      "category": "arch",
      "api": "os.arch()",
      "operator": "in",
      "value": [
        "x64",
        "arm64"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 5703,
            "end_byte": 5725,
            "node_type": "subscript_expression",
            "sha256": "5810a1a61d075113",
            "line": 167
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c19",
      "category": "dependency_tree",
      "api": "require.resolve",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "probe": {
        "kind": "file",
        "callee": "require.resolve",
        "target": "*/package.json",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 6644,
            "end_byte": 6687,
            "node_type": "call_expression",
            "sha256": "6c018eeb3274c284",
            "line": 198
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c20",
      "category": "dependency_tree",
      "api": "require('./package.json').optionalDependencies",
      "operator": "includes",
      "value": "@anthropic-ai/claude-code-<platformKey>",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 6220,
            "end_byte": 6242,
            "node_type": "subscript_expression",
            "sha256": "5f67856c210979b4",
            "line": 183
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
      "expression": "c1 && c2 && c4 && c5",
      "guards": [
        {
          "candidate": "q_9f8e966c6f",
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3009,
            "end_byte": 3081,
            "node_type": "if_statement",
            "sha256": "5ac51cc8e67953a6",
            "line": 86
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_69d515e51a",
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3084,
            "end_byte": 3173,
            "node_type": "if_statement",
            "sha256": "f65af0f9917d307d",
            "line": 89
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": "q_060e1b7468",
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3341,
            "end_byte": 3553,
            "node_type": "if_statement",
            "sha256": "a7245d9faccbc501",
            "line": 94
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4",
            "c5"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "On x64 macOS it runs sysctl to detect Rosetta 2 so the arm64 binary is picked instead of the x64 one.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "darwin",
          "arch": "x64"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 3385,
            "end_byte": 3553,
            "node_type": "statement_block",
            "sha256": "e563af348974dc73",
            "line": 94
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "install.cjs",
              "derived_from": null,
              "start_byte": 3401,
              "end_byte": 3487,
              "node_type": "call_expression",
              "sha256": "cf047520170a3f4a",
              "line": 95
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c17 && c18 && c20 && c19",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 5729,
            "end_byte": 6135,
            "node_type": "if_statement",
            "sha256": "67498c74d163484b",
            "line": 169
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c17",
            "c18"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 6215,
            "end_byte": 6592,
            "node_type": "if_statement",
            "sha256": "d97bc6140d8ddf31",
            "line": 183
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c20"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 6606,
            "end_byte": 7744,
            "node_type": "try_statement",
            "sha256": "d6b59c37f06361a7",
            "line": 197
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c19"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "The native binary is only placed on a platform with a shipped build (linux, darwin, win32 on x64 or arm64) whose key has a package listed in its own optionalDependencies (the android keys are not listed, so android returns early) and that npm installed.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "linux",
          "arch": "x64"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.cjs",
            "derived_from": null,
            "start_byte": 8043,
            "end_byte": 8364,
            "node_type": "stmt_range",
            "sha256": "c1c778fb0288d58d",
            "line": 236
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "install.cjs",
              "derived_from": null,
              "start_byte": 3947,
              "end_byte": 3966,
              "node_type": "call_expression",
              "sha256": "fa85bbed2ed1fb73",
              "line": 111
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.cjs",
                  "derived_from": null,
                  "start_byte": 8111,
                  "end_byte": 8133,
                  "node_type": "call_expression",
                  "sha256": "acf7da5548dc3925",
                  "line": 239
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.cjs",
                  "derived_from": null,
                  "start_byte": 3587,
                  "end_byte": 4965,
                  "node_type": "function_declaration",
                  "sha256": "c402def380871382",
                  "line": 105
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
      "spawn_process",
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
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall script detects the platform and hard-links or copies the matching native claude binary from its platform optional dependency over the bin/claude.exe stub. It contacts no network, reads no credentials and runs only sysctl on x64 macOS to detect Rosetta.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "inline_script",
        "recipe_version": 1,
        "input": {
          "file": "package.json",
          "derived_from": null
        },
        "params": {
          "hook": "prepare",
          "flag": "-e"
        },
        "output_sha256": "2bc21461602e7fe4"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@97d6974e53",
      "sha256": "3cb5f5f0686f1647"
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
        "candidate": "k_e4047fa2b3",
        "reason_code": "other",
        "note": "plumbing: linux test inside detectMusl only decides whether the musl binary key is used; same write_file behaviour either way",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 2462,
          "end_byte": 2490,
          "node_type": "binary_expression",
          "sha256": "509d45665cb75a4d",
          "line": 70
        }
      },
      {
        "candidate": "q_da765b690e",
        "reason_code": "other",
        "note": "plumbing: early return in detectMusl, only picks the musl or glibc binary key",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 2458,
          "end_byte": 2514,
          "node_type": "if_statement",
          "sha256": "485abec146997b7c",
          "line": 70
        }
      },
      {
        "candidate": "q_52c06eb181",
        "reason_code": "other",
        "note": "plumbing: linux branch of getPlatformKey only builds the linux binary key (with musl suffix); same behaviour on every supported platform",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 3084,
          "end_byte": 3173,
          "node_type": "if_statement",
          "sha256": "f65af0f9917d307d",
          "line": 89
        }
      },
      {
        "candidate": "k_89a691a4be",
        "reason_code": "log_only",
        "note": "freebsd test only prints an extra hint before the unsupported-platform return",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 5937,
          "end_byte": 5967,
          "node_type": "binary_expression",
          "sha256": "5d093a1fb7fa186e",
          "line": 174
        }
      },
      {
        "candidate": "q_7c42a5cc39",
        "reason_code": "log_only",
        "note": "freebsd branch only prints a console.error message",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 5933,
          "end_byte": 6120,
          "node_type": "if_statement",
          "sha256": "779ce66c912c5bc8",
          "line": 174
        }
      },
      {
        "candidate": "k_46fd690464",
        "reason_code": "dead_branch",
        "note": "npm_config_omit is only tested after !FAIL_ON_MISSING_NATIVE, which is always true because the constant is 'false' === 'true'",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 5423,
          "end_byte": 5479,
          "node_type": "call_expression",
          "sha256": "bb4a82a8c97a62cc",
          "line": 155
        }
      },
      {
        "candidate": "q_ba51612188",
        "reason_code": "dead_branch",
        "note": "failInstallUnlessOptionalOmitted always returns at its first test; setting exitCode = 1 is unreachable",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 5383,
          "end_byte": 5500,
          "node_type": "if_statement",
          "sha256": "930997e4dedcae0d",
          "line": 153
        }
      },
      {
        "candidate": "k_7160e5b745",
        "reason_code": "log_only",
        "note": "darwin-arm64 with x64 node test in the missing-package handler only chooses which messages to print; both sides return",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 6885,
          "end_byte": 6901,
          "node_type": "binary_expression",
          "sha256": "5a9393f73b48b0e7",
          "line": 204
        }
      },
      {
        "candidate": "q_e92342e67e",
        "reason_code": "log_only",
        "note": "Rosetta hint branch in the catch handler prints messages and returns; the other side prints messages and calls the dead failInstallUnlessOptionalOmitted",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 6847,
          "end_byte": 7383,
          "node_type": "if_statement",
          "sha256": "3f71cb3391c21bf6",
          "line": 204
        }
      },
      {
        "candidate": "k_e514ff693f",
        "reason_code": "other",
        "note": "plumbing: non-win32 test only adds chmod 755 after the binary is linked or copied; the write_file behaviour is the same on all platforms",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 4901,
          "end_byte": 4929,
          "node_type": "binary_expression",
          "sha256": "05dbbdd00d49d713",
          "line": 142
        }
      },
      {
        "candidate": "q_91dc654eaf",
        "reason_code": "other",
        "note": "plumbing: chmod of the placed binary on non-Windows, same write_file behaviour",
        "anchor": {
          "file": "install.cjs",
          "derived_from": null,
          "start_byte": 4897,
          "end_byte": 4963,
          "node_type": "if_statement",
          "sha256": "1e78425a65314b2e",
          "line": 142
        }
      },
      {
        "candidate": "k_af8df88d92",
        "reason_code": "other",
        "note": "prepare hook AUTHORIZED test: the then side only prints an error and exits 1 to block publishing; neither side runs a behaviour",
        "anchor": {
          "file": "package.json",
          "derived_from": "d1",
          "start_byte": 5,
          "end_byte": 27,
          "node_type": "member_expression",
          "sha256": "e64f2c39bf7f1486",
          "line": 1
        }
      },
      {
        "candidate": "q_699cd39b89",
        "reason_code": "other",
        "note": "prepare hook guard: only an error message and exit 1, no behaviour on either side",
        "anchor": {
          "file": "package.json",
          "derived_from": "d1",
          "start_byte": 0,
          "end_byte": 180,
          "node_type": "if_statement",
          "sha256": "2bc21461602e7fe4",
          "line": 1
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 11,
    "condition_sites_cited": 4,
    "guards_cited": 3,
    "candidates_dropped": 13,
    "conditions_in_set": 4,
    "conditions_out_of_set": 4,
    "guard_candidates": 17,
    "gates_in_set": 1,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c17",
      "c18",
      "c19",
      "c20",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
