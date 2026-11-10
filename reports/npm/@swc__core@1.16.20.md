# npm @swc/core@1.16.20

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-22 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node postinstall.js`, the upstream swc install check. It requires `binding.js`, the napi-rs generated loader, which picks a native binary for the current platform, arch and libc from the optional `@swc/core-<platform>` dependencies. One gate (g1) decides whether anything else happens: INIT_CWD must point at a project with a package.json whose name is not `@swc/core` or `@swc/workspace`, the native binding must fail to load, `SWC_BINARY_PATH` must be unset, and `@swc/wasm` must not already resolve. Only then does it run the system `npm install @swc/wasm@<version>` in a temporary folder inside the package, move the result into `$INIT_CWD/node_modules`, and delete the temporary folder.

## Execution

- **postinstall** `node postinstall.js`: 2-file chain; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 && c4 && c5 (c1: process.env.INIT_CWD exists; c2: consuming_app not_in [@swc/core, @swc/workspace]; c3: dependency_tree not_exists ./binding.js; c4: process.env.SWC_BINARY_PATH falsy; c5: dependency_tree not_exists @swc/wasm) | then | 5 | spawn_process, download, write_file, delete_file | env_var=INIT_CWD=(set); env_var_absent=SWC_BINARY_PATH; installed_tool=npm; file_present=$INIT_CWD/package.json |

Gate intent: g1 activate/enables/portability

Grounding: 2 of 5 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c2, c3, c5, g1.

## Requirements

- network: registry[.]npmjs[.]org:443 (fallback branch runs npm install @swc/wasm, which fetches from the configured npm registry (default registry assumed))
- installed_tool: npm (fallback branch shells out to the system npm via child_process.execSync)

## Behaviour

- Ungated: none
- Gated: spawn_process, download, write_file, delete_file

## Notes

- The platform, arch, musl and `NAPI_RS_FORCE_WASI` checks in binding.js only pick which binary to require, so I dropped them as loader plumbing. Their combined effect (no binary loads) is condition c3, which is dependency tree and out of scope. On a platform with no published binary (for example FreeBSD or riscv64), or when optional dependencies were skipped, the fallback install runs.
- c2, c3 and c5 and their early-exit guards are out of set because the extractor gave no candidate for those statements.
- The `env_recipe` cannot express the dependency-tree conditions (no native binding present, `@swc/wasm` not installed). The INIT_CWD value is left as "any value pointing at a project folder".
- The two GitHub URLs only appear in a comment and an error message. Nothing contacts them.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@swc/core",
    "version": "1.16.20",
    "archive_sha256": "c7081a10cb4bedbf936763d7bc010452cf76e5d8f6915fb26f80aeaae4b524c6",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-22",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/core-1.16.20.tgz",
    "package_root": "layer0/package",
    "cluster_key": "75a1d09ae33f7180c7634894585ae45151236373986cf05a017be79d9fec5696",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "postinstall.js",
          "binding.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "optionalDependencies (platform picks belong to the dependency tree): @swc/core-darwin-x64, @swc/core-win32-x64-msvc, @swc/core-linux-x64-gnu, @swc/core-linux-ppc64-gnu, @swc/core-linux-s390x-gnu, @swc/core-linux-x64-musl, @swc/core-win32-ia32-msvc, @swc/core-linux-arm-gnueabihf, @swc/core-darwin-arm",
      "generator truncated: some helpers walked under only 2 guard contexts in binding.js; candidates there may be missing",
      "postinstall.js (148 lines) and binding.js (369 lines, napi-rs generated loader) both read in full; nothing unread, no bundled third-party code.",
      "binding.js only picks which platform-specific native binary (.node file or @swc/core-<platform> optional dependency) to require. All its platform, arch, musl and NAPI_RS_FORCE_WASI checks are loader plumbing; dropped as candidates.",
      "binding.js musl detection reads /usr/bin/ldd and, on Linux when that and process.report give no answer, runs `ldd --version`. Plumbing to locate the binary, not recorded as a behaviour.",
      "The only real decision is in postinstall.js: when the native binding fails to load (c3), SWC_BINARY_PATH is unset and @swc/wasm is not resolvable, it runs `npm install @swc/wasm@<version>` in a temp dir and moves it into $INIT_CWD/node_modules.",
      "Errors from the fallback install are caught and only logged; the temp dir cleanup swallows errors, so silent_failure is true."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "fallback branch runs npm install @swc/wasm, which fetches from the configured npm registry (default registry assumed)"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "fallback branch shells out to the system npm via child_process.execSync"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "process.env.INIT_CWD",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_11e6c87b72",
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2980,
            "end_byte": 3039,
            "node_type": "call_expression",
            "sha256": "27ca1ed9a2a7f65b",
            "line": 69
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "file",
        "callee": "require",
        "target": "$INIT_CWD/package.json",
        "accessor": "throws"
      }
    },
    {
      "id": "c2",
      "category": "consuming_app",
      "api": "require(INIT_CWD/package.json).name",
      "operator": "not_in",
      "value": [
        "@swc/core",
        "@swc/workspace"
      ],
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 3053,
            "end_byte": 3102,
            "node_type": "binary_expression",
            "sha256": "16ade56ca50fa465",
            "line": 70
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "dependency_tree",
      "api": "require",
      "operator": "not_exists",
      "value": "./binding.js",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 3372,
            "end_byte": 3395,
            "node_type": "call_expression",
            "sha256": "5c114c3553e107ea",
            "line": 81
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.SWC_BINARY_PATH",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8b9e252689",
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4380,
            "end_byte": 4410,
            "node_type": "subscript_expression",
            "sha256": "28779745f2b5dc33",
            "line": 100
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "dependency_tree",
      "api": "require.resolve",
      "operator": "not_exists",
      "value": "@swc/wasm",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4739,
            "end_byte": 4767,
            "node_type": "call_expression",
            "sha256": "01beb40aab26e09e",
            "line": 107
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4818,
            "end_byte": 4851,
            "node_type": "call_expression",
            "sha256": "bae3b774b5fa99e1",
            "line": 110
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
      "expression": "c1 && c2 && c3 && c4 && c5",
      "guards": [
        {
          "candidate": "q_3957be6867",
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2949,
            "end_byte": 3179,
            "node_type": "try_statement",
            "sha256": "516d20a7411e5b7a",
            "line": 68
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 3049,
            "end_byte": 3135,
            "node_type": "if_statement",
            "sha256": "87dc80993e013781",
            "line": 70
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4247,
            "end_byte": 4285,
            "node_type": "if_statement",
            "sha256": "08de3dc1535adfbe",
            "line": 96
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": "q_11dfba7dae",
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4374,
            "end_byte": 4608,
            "node_type": "if_statement",
            "sha256": "0a440cb4069e3cdd",
            "line": 100
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4797,
            "end_byte": 4876,
            "node_type": "if_statement",
            "sha256": "be032966bb11d7ff",
            "line": 110
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "installs the @swc/wasm fallback only when no native binary loads for this platform and the user has not overridden or already installed it",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "spawn_process",
          "download",
          "write_file",
          "delete_file"
        ],
        "env_recipe": {
          "env_var": {
            "INIT_CWD": null
          },
          "env_var_absent": [
            "SWC_BINARY_PATH"
          ],
          "installed_tool": [
            "npm"
          ],
          "file_present": [
            "$INIT_CWD/package.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 4881,
            "end_byte": 6752,
            "node_type": "stmt_range",
            "sha256": "4e3254e95667882b",
            "line": 113
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 5759,
              "end_byte": 5930,
              "node_type": "call_expression",
              "sha256": "3004783ad085fba1",
              "line": 125
            },
            "witness": []
          },
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 5759,
              "end_byte": 5930,
              "node_type": "call_expression",
              "sha256": "3004783ad085fba1",
              "line": 125
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 5497,
              "end_byte": 5558,
              "node_type": "call_expression",
              "sha256": "be931d5770168628",
              "line": 122
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 2726,
              "end_byte": 2743,
              "node_type": "call_expression",
              "sha256": "89c2753ab7ec8599",
              "line": 61
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "postinstall.js",
                  "derived_from": null,
                  "start_byte": 6562,
                  "end_byte": 6589,
                  "node_type": "call_expression",
                  "sha256": "45b04cf5c9b679d3",
                  "line": 138
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "postinstall.js",
                  "derived_from": null,
                  "start_byte": 2263,
                  "end_byte": 2746,
                  "node_type": "function_declaration",
                  "sha256": "28d3f206aab8c855",
                  "line": 46
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
      "download",
      "write_file",
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
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall is the upstream swc script: it checks that the platform's native binding loads and, only if it does not, installs the matching @swc/wasm version with the system npm as a fallback. No credential access, exfiltration or remote code beyond a normal registry install.",
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
      "sha256": "04e020fe8d54913e"
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
        "candidate": "k_6063d6486a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1377,
          "end_byte": 1407,
          "node_type": "binary_expression",
          "sha256": "667c01ab5dfb03bd",
          "line": 60
        }
      },
      {
        "candidate": "k_7279e5af9a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1419,
          "end_byte": 1443,
          "node_type": "binary_expression",
          "sha256": "c1d8076b6140dc61",
          "line": 61
        }
      },
      {
        "candidate": "k_eba4691ef6",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2687,
          "end_byte": 2711,
          "node_type": "binary_expression",
          "sha256": "c1d8076b6140dc61",
          "line": 113
        }
      },
      {
        "candidate": "k_be4d282e19",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3630,
          "end_byte": 3654,
          "node_type": "binary_expression",
          "sha256": "c1d8076b6140dc61",
          "line": 152
        }
      },
      {
        "candidate": "k_4083d042e5",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4326,
          "end_byte": 4350,
          "node_type": "binary_expression",
          "sha256": "c1d8076b6140dc61",
          "line": 180
        }
      },
      {
        "candidate": "k_dfcf046170",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5315,
          "end_byte": 5339,
          "node_type": "binary_expression",
          "sha256": "c1d8076b6140dc61",
          "line": 222
        }
      },
      {
        "candidate": "k_51936c7c12",
        "reason_code": "other",
        "note": "binding.js loader plumbing: require of a platform binary; outcome captured by c3",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1592,
          "end_byte": 1626,
          "node_type": "call_expression",
          "sha256": "df1feb972dc2be02",
          "line": 68
        }
      },
      {
        "candidate": "k_3f9d93f161",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1698,
          "end_byte": 1720,
          "node_type": "binary_expression",
          "sha256": "48b0b560ca3ee5a1",
          "line": 73
        }
      },
      {
        "candidate": "k_d3825fda5c",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5889,
          "end_byte": 5911,
          "node_type": "binary_expression",
          "sha256": "48b0b560ca3ee5a1",
          "line": 248
        }
      },
      {
        "candidate": "k_f2e2a06f09",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1872,
          "end_byte": 1909,
          "node_type": "call_expression",
          "sha256": "9519d10ac6b8948d",
          "line": 80
        }
      },
      {
        "candidate": "k_a26f75e203",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2086,
          "end_byte": 2114,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 88
        }
      },
      {
        "candidate": "k_00c293dcba",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2126,
          "end_byte": 2148,
          "node_type": "binary_expression",
          "sha256": "705293be392fa6c8",
          "line": 89
        }
      },
      {
        "candidate": "k_ce4c309a46",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3359,
          "end_byte": 3381,
          "node_type": "binary_expression",
          "sha256": "705293be392fa6c8",
          "line": 140
        }
      },
      {
        "candidate": "k_70700f11bf",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4053,
          "end_byte": 4075,
          "node_type": "binary_expression",
          "sha256": "705293be392fa6c8",
          "line": 168
        }
      },
      {
        "candidate": "k_a0d24ca414",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4751,
          "end_byte": 4773,
          "node_type": "binary_expression",
          "sha256": "705293be392fa6c8",
          "line": 196
        }
      },
      {
        "candidate": "k_3c58ebd645",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2298,
          "end_byte": 2333,
          "node_type": "call_expression",
          "sha256": "8a9daf0ddfca4183",
          "line": 96
        }
      },
      {
        "candidate": "k_d25c30cab3",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2405,
          "end_byte": 2428,
          "node_type": "binary_expression",
          "sha256": "a4a6683e419cbd26",
          "line": 101
        }
      },
      {
        "candidate": "k_4dbff90628",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2579,
          "end_byte": 2615,
          "node_type": "call_expression",
          "sha256": "d333517f179d6631",
          "line": 108
        }
      },
      {
        "candidate": "k_928ad6504a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2863,
          "end_byte": 2900,
          "node_type": "call_expression",
          "sha256": "06794e18626e5109",
          "line": 120
        }
      },
      {
        "candidate": "k_e9a5386e0b",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3078,
          "end_byte": 3107,
          "node_type": "binary_expression",
          "sha256": "58c601c101556765",
          "line": 128
        }
      },
      {
        "candidate": "k_a8cff79eac",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3257,
          "end_byte": 3294,
          "node_type": "call_expression",
          "sha256": "1f3058fbcfeac79f",
          "line": 135
        }
      },
      {
        "candidate": "k_dc5c8ca781",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3527,
          "end_byte": 3558,
          "node_type": "call_expression",
          "sha256": "8bd3246e02d2ae96",
          "line": 147
        }
      },
      {
        "candidate": "k_dde47a0100",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3802,
          "end_byte": 3835,
          "node_type": "call_expression",
          "sha256": "3b6ca7ce3cbfa924",
          "line": 159
        }
      },
      {
        "candidate": "k_9f351fe240",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4011,
          "end_byte": 4041,
          "node_type": "binary_expression",
          "sha256": "5d093a1fb7fa186e",
          "line": 167
        }
      },
      {
        "candidate": "k_f0ef1f0f76",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4222,
          "end_byte": 4254,
          "node_type": "call_expression",
          "sha256": "c04c334b6b8ba303",
          "line": 175
        }
      },
      {
        "candidate": "k_ac6c34a66c",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4499,
          "end_byte": 4533,
          "node_type": "call_expression",
          "sha256": "0db7c56e4c67df27",
          "line": 187
        }
      },
      {
        "candidate": "k_92a8e358be",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4711,
          "end_byte": 4739,
          "node_type": "binary_expression",
          "sha256": "3bca60607dc21698",
          "line": 195
        }
      },
      {
        "candidate": "k_e62c6ffe1a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 209,
          "end_byte": 237,
          "node_type": "binary_expression",
          "sha256": "3bca60607dc21698",
          "line": 12
        }
      },
      {
        "candidate": "k_d187c8623b",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 562,
          "end_byte": 599,
          "node_type": "call_expression",
          "sha256": "b35a1e38fd8cc293",
          "line": 28
        }
      },
      {
        "candidate": "k_c668f8d674",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1101,
          "end_byte": 1125,
          "node_type": "call_expression",
          "sha256": "2fbcd86bc8bd5690",
          "line": 52
        }
      },
      {
        "candidate": "k_1a1a5b2f0a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4947,
          "end_byte": 4982,
          "node_type": "call_expression",
          "sha256": "c9975b650486de6c",
          "line": 204
        }
      },
      {
        "candidate": "k_d5aed10b83",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5201,
          "end_byte": 5235,
          "node_type": "call_expression",
          "sha256": "0c15d2fb02f444fd",
          "line": 216
        }
      },
      {
        "candidate": "k_e0d2694ea2",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5515,
          "end_byte": 5552,
          "node_type": "call_expression",
          "sha256": "56a90d51faa0114c",
          "line": 230
        }
      },
      {
        "candidate": "k_18f78e5436",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5773,
          "end_byte": 5809,
          "node_type": "call_expression",
          "sha256": "72b6167b06ff7689",
          "line": 242
        }
      },
      {
        "candidate": "k_c27658a1de",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6066,
          "end_byte": 6106,
          "node_type": "call_expression",
          "sha256": "2f74f8628591a10f",
          "line": 255
        }
      },
      {
        "candidate": "k_329a94aaa6",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6178,
          "end_byte": 6204,
          "node_type": "binary_expression",
          "sha256": "953f9f3ab2eecddb",
          "line": 260
        }
      },
      {
        "candidate": "k_f3aa456f09",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6382,
          "end_byte": 6421,
          "node_type": "call_expression",
          "sha256": "1f7a3ac6dd4321ec",
          "line": 268
        }
      },
      {
        "candidate": "k_33ec9e5fee",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6644,
          "end_byte": 6682,
          "node_type": "call_expression",
          "sha256": "ff966fc56d200559",
          "line": 280
        }
      },
      {
        "candidate": "k_6bc371d31e",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6762,
          "end_byte": 6786,
          "node_type": "binary_expression",
          "sha256": "a223bb58f43c9d80",
          "line": 286
        }
      },
      {
        "candidate": "k_4a597ccb0f",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6937,
          "end_byte": 6973,
          "node_type": "call_expression",
          "sha256": "65084025eebbadbc",
          "line": 293
        }
      },
      {
        "candidate": "k_df9bec187d",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7045,
          "end_byte": 7069,
          "node_type": "binary_expression",
          "sha256": "b44d004c111230f5",
          "line": 298
        }
      },
      {
        "candidate": "k_75faf830d4",
        "reason_code": "other",
        "note": "binding.js loader plumbing: platform/arch/libc pick of which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7220,
          "end_byte": 7256,
          "node_type": "call_expression",
          "sha256": "40498d243baa145d",
          "line": 305
        }
      },
      {
        "candidate": "k_fb762a24cf",
        "reason_code": "other",
        "note": "binding.js NAPI_RS_FORCE_WASI: loader plumbing choosing the wasi build over the native binary, or log-only",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7593,
          "end_byte": 7623,
          "node_type": "member_expression",
          "sha256": "ba6b2b3147910852",
          "line": 320
        }
      },
      {
        "candidate": "k_b8c7739a51",
        "reason_code": "log_only",
        "note": "NAPI_RS_FORCE_WASI test only decides whether a load error is printed",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7707,
          "end_byte": 7737,
          "node_type": "member_expression",
          "sha256": "ba6b2b3147910852",
          "line": 324
        }
      },
      {
        "candidate": "k_86c6e8e167",
        "reason_code": "log_only",
        "note": "NAPI_RS_FORCE_WASI test only decides whether a load error is printed",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7895,
          "end_byte": 7925,
          "node_type": "member_expression",
          "sha256": "ba6b2b3147910852",
          "line": 332
        }
      },
      {
        "candidate": "k_e12e039475",
        "reason_code": "other",
        "note": "binding.js loader plumbing: require of the wasi fallback binary; outcome captured by c3",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7832,
          "end_byte": 7864,
          "node_type": "call_expression",
          "sha256": "b06b8bd1fc8d6ea9",
          "line": 330
        }
      },
      {
        "candidate": "q_796dcb54bb",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1373,
          "end_byte": 7534,
          "node_type": "if_statement",
          "sha256": "b28c9c887ee75deb",
          "line": 60
        }
      },
      {
        "candidate": "q_8c5cd98767",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1415,
          "end_byte": 2072,
          "node_type": "if_statement",
          "sha256": "db798fd8017cbc01",
          "line": 61
        }
      },
      {
        "candidate": "q_3aa6e21091",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1571,
          "end_byte": 1681,
          "node_type": "try_statement",
          "sha256": "fc2547a0473ce48c",
          "line": 67
        }
      },
      {
        "candidate": "q_00edcad60b",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1694,
          "end_byte": 2072,
          "node_type": "if_statement",
          "sha256": "077b90a5f711e9b4",
          "line": 73
        }
      },
      {
        "candidate": "q_53649c10d5",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1851,
          "end_byte": 1964,
          "node_type": "try_statement",
          "sha256": "4787a7a95dec284b",
          "line": 79
        }
      },
      {
        "candidate": "q_1763b91786",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2082,
          "end_byte": 7534,
          "node_type": "if_statement",
          "sha256": "930b0b20c5d56a94",
          "line": 88
        }
      },
      {
        "candidate": "q_018fbad750",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2122,
          "end_byte": 3064,
          "node_type": "if_statement",
          "sha256": "2dadfc0af99b633e",
          "line": 89
        }
      },
      {
        "candidate": "q_5842bdbe87",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2277,
          "end_byte": 2388,
          "node_type": "try_statement",
          "sha256": "7fddcb326b26f0e6",
          "line": 95
        }
      },
      {
        "candidate": "q_05f8ec6836",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2401,
          "end_byte": 3064,
          "node_type": "if_statement",
          "sha256": "0918f32775992371",
          "line": 101
        }
      },
      {
        "candidate": "q_20be3afa90",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2558,
          "end_byte": 2670,
          "node_type": "try_statement",
          "sha256": "930daa80ed0b408a",
          "line": 107
        }
      },
      {
        "candidate": "q_f904047160",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2683,
          "end_byte": 3064,
          "node_type": "if_statement",
          "sha256": "4894b65b76904739",
          "line": 113
        }
      },
      {
        "candidate": "q_a645227989",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 2842,
          "end_byte": 2955,
          "node_type": "try_statement",
          "sha256": "4decbc812eaa5c65",
          "line": 119
        }
      },
      {
        "candidate": "q_94e69c86be",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3074,
          "end_byte": 7534,
          "node_type": "if_statement",
          "sha256": "988cecb5e1ce25dd",
          "line": 128
        }
      },
      {
        "candidate": "q_e3e94cf12d",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3236,
          "end_byte": 3349,
          "node_type": "try_statement",
          "sha256": "1d01655f08698406",
          "line": 134
        }
      },
      {
        "candidate": "q_e857b19977",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3355,
          "end_byte": 3997,
          "node_type": "if_statement",
          "sha256": "9c68073ea850956a",
          "line": 140
        }
      },
      {
        "candidate": "q_ed9b41416c",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3506,
          "end_byte": 3613,
          "node_type": "try_statement",
          "sha256": "70f3c5b6106beda6",
          "line": 146
        }
      },
      {
        "candidate": "q_b8c36f10aa",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3626,
          "end_byte": 3997,
          "node_type": "if_statement",
          "sha256": "24c40f530ec15290",
          "line": 152
        }
      },
      {
        "candidate": "q_973405e115",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 3781,
          "end_byte": 3890,
          "node_type": "try_statement",
          "sha256": "f042001b8a2873ef",
          "line": 158
        }
      },
      {
        "candidate": "q_1b14a0a147",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4007,
          "end_byte": 7534,
          "node_type": "if_statement",
          "sha256": "154c442ae1b25fff",
          "line": 167
        }
      },
      {
        "candidate": "q_1b60f1f487",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4049,
          "end_byte": 4697,
          "node_type": "if_statement",
          "sha256": "e3bc172a826f24bb",
          "line": 168
        }
      },
      {
        "candidate": "q_ff5510d8b0",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4201,
          "end_byte": 4309,
          "node_type": "try_statement",
          "sha256": "646d49643565c78f",
          "line": 174
        }
      },
      {
        "candidate": "q_3baabd46e7",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4322,
          "end_byte": 4697,
          "node_type": "if_statement",
          "sha256": "106b4b34757449b2",
          "line": 180
        }
      },
      {
        "candidate": "q_90c0829d96",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4478,
          "end_byte": 4588,
          "node_type": "try_statement",
          "sha256": "83a5e4b195976d6b",
          "line": 186
        }
      },
      {
        "candidate": "q_fdf7ff64fa",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4707,
          "end_byte": 7534,
          "node_type": "if_statement",
          "sha256": "2979bb66c8805739",
          "line": 195
        }
      },
      {
        "candidate": "q_53685bf219",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4747,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "6879c004ab9a83da",
          "line": 196
        }
      },
      {
        "candidate": "q_ee6b2c9738",
        "reason_code": "other",
        "note": "binding.js musl detection (isMusl helpers): libc probe used only to pick the binary",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 205,
          "end_byte": 410,
          "node_type": "if_statement",
          "sha256": "0a33be38a32b0430",
          "line": 12
        }
      },
      {
        "candidate": "q_0fbc783c52",
        "reason_code": "other",
        "note": "binding.js musl detection (isMusl helpers): libc probe used only to pick the binary",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 545,
          "end_byte": 648,
          "node_type": "try_statement",
          "sha256": "97d399726c3c3230",
          "line": 27
        }
      },
      {
        "candidate": "q_283362ff57",
        "reason_code": "other",
        "note": "binding.js musl detection (isMusl helpers): libc probe used only to pick the binary",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 1084,
          "end_byte": 1340,
          "node_type": "try_statement",
          "sha256": "43e94d46ac0b9a44",
          "line": 51
        }
      },
      {
        "candidate": "q_34eb303a8b",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 4926,
          "end_byte": 5037,
          "node_type": "try_statement",
          "sha256": "01070e81f4536194",
          "line": 203
        }
      },
      {
        "candidate": "q_2370e246fd",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5180,
          "end_byte": 5290,
          "node_type": "try_statement",
          "sha256": "32a93da154d429cc",
          "line": 215
        }
      },
      {
        "candidate": "q_fbf01e6947",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5311,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "1feea0732fab5f42",
          "line": 222
        }
      },
      {
        "candidate": "q_d97dfa2d6c",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5494,
          "end_byte": 5607,
          "node_type": "try_statement",
          "sha256": "03a095560b6db386",
          "line": 229
        }
      },
      {
        "candidate": "q_cb9e446199",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5752,
          "end_byte": 5864,
          "node_type": "try_statement",
          "sha256": "8a01a751342611e1",
          "line": 241
        }
      },
      {
        "candidate": "q_d1bbd6809a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 5885,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "6dd77123334bf048",
          "line": 248
        }
      },
      {
        "candidate": "q_c57837e99d",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6045,
          "end_byte": 6161,
          "node_type": "try_statement",
          "sha256": "00b0c4612d8043b3",
          "line": 254
        }
      },
      {
        "candidate": "q_6b1a70a6ab",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6174,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "6e01211c8f0c8810",
          "line": 260
        }
      },
      {
        "candidate": "q_b80d30c06a",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6361,
          "end_byte": 6476,
          "node_type": "try_statement",
          "sha256": "39027678df090016",
          "line": 267
        }
      },
      {
        "candidate": "q_4744ca4880",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6623,
          "end_byte": 6737,
          "node_type": "try_statement",
          "sha256": "2632df0ff180b07d",
          "line": 279
        }
      },
      {
        "candidate": "q_f59b8aad35",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6758,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "b2cc78c43429a4e4",
          "line": 286
        }
      },
      {
        "candidate": "q_67498c6271",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 6916,
          "end_byte": 7028,
          "node_type": "try_statement",
          "sha256": "e23734f7d916025b",
          "line": 292
        }
      },
      {
        "candidate": "q_17b138f320",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7041,
          "end_byte": 7418,
          "node_type": "if_statement",
          "sha256": "9643412c32740da7",
          "line": 298
        }
      },
      {
        "candidate": "q_463350089c",
        "reason_code": "other",
        "note": "binding.js loader plumbing: decision picking which native binary to require",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7199,
          "end_byte": 7311,
          "node_type": "try_statement",
          "sha256": "7bc1890ad32fb660",
          "line": 304
        }
      },
      {
        "candidate": "q_442a33545e",
        "reason_code": "other",
        "note": "binding.js loader plumbing: falls back to the wasi build when no native binary loaded or NAPI_RS_FORCE_WASI is set",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7571,
          "end_byte": 7975,
          "node_type": "if_statement",
          "sha256": "ccb560de113cee56",
          "line": 320
        }
      },
      {
        "candidate": "q_3caecf74f1",
        "reason_code": "log_only",
        "note": "NAPI_RS_FORCE_WASI test only decides whether a load error is printed",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7703,
          "end_byte": 7771,
          "node_type": "if_statement",
          "sha256": "0027269bfbf7a6e6",
          "line": 324
        }
      },
      {
        "candidate": "q_9da4935ce3",
        "reason_code": "other",
        "note": "binding.js loader plumbing: try-require of the wasi fallback binary",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7804,
          "end_byte": 7969,
          "node_type": "try_statement",
          "sha256": "c9eb4998722489b3",
          "line": 329
        }
      },
      {
        "candidate": "q_9094380b68",
        "reason_code": "log_only",
        "note": "catch side of the wasi try-require only logs the error",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7804,
          "end_byte": 7969,
          "node_type": "try_statement",
          "sha256": "c9eb4998722489b3",
          "line": 329
        }
      },
      {
        "candidate": "q_179c54488d",
        "reason_code": "log_only",
        "note": "NAPI_RS_FORCE_WASI test only decides whether a load error is printed",
        "anchor": {
          "file": "binding.js",
          "derived_from": null,
          "start_byte": 7891,
          "end_byte": 7963,
          "node_type": "if_statement",
          "sha256": "c279bfe137459872",
          "line": 332
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 49,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 93,
    "conditions_in_set": 2,
    "conditions_out_of_set": 3,
    "guard_candidates": 49,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c5",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
