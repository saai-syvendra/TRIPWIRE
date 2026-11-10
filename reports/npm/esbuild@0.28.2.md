# npm esbuild@0.28.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-08-08 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node install.js`, esbuild's standard installer. It resolves the native binary from the platform `@esbuild/*` optionalDependency and finishes by running it with `--version` (through `node bin/esbuild` when the JS shim is still in place). Three gates change what it does: g1, an ESBUILD_BINARY_PATH override that names an existing file, writes a shim pointing at that binary and prepends the path to lib/main.js; g2, when the platform package cannot be resolved and the platform is not a WASM one, runs `npm install` of that package or downloads its tarball from the npm registry, checks its sha256 against package.json and writes it; g3, outside Windows, Yarn and WASM platforms, hard-links the binary over bin/esbuild. A plain npm install on a supported platform with optional dependencies takes g3 and none of the others.

## Execution

- **postinstall** `node install.js`: 2-file chain; direct_script, download_then_exec, dropped_binary; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 (c1: process.env.ESBUILD_BINARY_PATH truthy; c2: process.env.ESBUILD_BINARY_PATH != /usr/bin/esbuild; c3: file_or_dir_exists exists) | then | 3 | write_file | env_var=ESBUILD_BINARY_PATH=/opt/esbuild/esbuild; file_present=/opt/esbuild/esbuild |
| g2 | postinstall | c4 && c5 (c4: dependency_tree not_exists; c5: os not_in android arm LE, android x64 LE, openharmony arm64 LE) | then | 2 | spawn_process, download, write_file, delete_file | os=linux; arch=x64 |
| g3 | postinstall | c6 && c7 && c5 (c6: os != win32; c7: process.env.npm_config_user_agent not_regex \byarn\/; c5: os not_in android arm LE, android x64 LE, openharmony arm64 LE) | then | 3 | write_file | os=linux; arch=x64; package_manager=npm |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/portability; g3 activate/enables/portability

Grounding: 2 of 7 conditions and 1 of 3 gates from the candidate set; out of set, pending verification: c1, c2, c4, c5, c7, g1, g2.

## Requirements

- other: process.platform/os.arch()/os.endianness() combination listed in esbuild's known package tables (pkgAndSubpathForCurrentPlatform throws Unsupported platform otherwise, before any binary is resolved)
- installed_tool: npm (g2 fallback first runs npm install of the platform package; on failure it falls back to a direct download)
- network: registry[.]npmjs[.]org:443 (g2 fallback (npm install or direct tarball fetch) needs the npm registry)

## Behaviour

- Ungated: spawn_process, benign_build
- Gated: write_file, spawn_process, download, delete_file

## Notes

- bin/esbuild was added to the file chain because the version check can run it; it only locates the binary and execs it. lib/main.js is only read and rewritten as text at install, never loaded.
- c4 (optional dependency missing) is a dependency_tree condition, out of scope for Phase 2; reaching g2 in a VM needs an install with `--no-optional` or the platform package removed.
- The macOS sw_vers branch and the removeRecursive lstat try were dropped as log-only and cleanup plumbing.
- The registry endpoint is only contacted in the g2 fallback; the other URLs the tool found are in comments and error text.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "esbuild",
    "version": "0.28.2",
    "archive_sha256": "e045f94c235c7adc50e77ba2a579c7bec41b496b6b47c3a7845f7c1e19959a88",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-08-08",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/esbuild-0.28.2.tgz",
    "package_root": "layer0/package",
    "cluster_key": "a7d8969adf555ab36318b0d86df00abdc9210d6f7c3a9f8cbd8d3fc49f95a50b",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node install.js",
        "runs_on": "always",
        "file_chain": [
          "install.js",
          "bin/esbuild"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "dropped_binary"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): esbuild",
      "optionalDependencies (platform picks belong to the dependency tree): @esbuild/aix-ppc64, @esbuild/android-arm, @esbuild/android-arm64, @esbuild/android-x64, @esbuild/darwin-arm64, @esbuild/darwin-x64, @esbuild/freebsd-arm64, @esbuild/freebsd-x64, @esbuild/linux-arm, @esbuild/linux-arm64",
      "install.js: package code (esbuild's own lib/npm/node-install.ts build output, unminified) read in full; nothing unread.",
      "bin/esbuild: read in full. install.js validateBinaryVersion runs it as `node bin/esbuild --version` when bin/esbuild is still the JS shim (Windows, Yarn, WASM platforms, or the hard link failed); it only locates the platform binary and execs it with --version.",
      "bin/esbuild locator branches (ESBUILD_BINARY_PATH, other-platform package probes, pnpapi cache copy) only pick which binary path to run or which error text to throw: plumbing, not recorded as gates.",
      "lib/main.js: not run at install. install.js only reads it as text and prepends a var line when the ESBUILD_BINARY_PATH override applies (g1); require.resolve('esbuild') resolves its path without loading it.",
      "Platform table lookup (process.platform, os.arch(), os.endianness()) throws 'Unsupported platform' for unknown combos; treated as a requirement, it only picks which @esbuild/* package holds the binary.",
      "g2 sits on the false side of g1 (override not applied, or path missing), which cannot be written positively.",
      "In g2 the downloaded binary is later run by the ungated validateBinaryVersion (exec of bin path with --version), so the fallback ends in running the fetched binary after a sha256 check against package.json hashes.",
      "validateBinaryVersion's macOS _SecTrustEvaluateWithError branch runs sw_vers only to build an error message, both sides throw: log only, dropped.",
      "isToPathJS picks whether the version check runs bin/esbuild through node or the binary directly: plumbing (how it starts)."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "process.platform/os.arch()/os.endianness() combination listed in esbuild's known package tables",
      "reason": "pkgAndSubpathForCurrentPlatform throws Unsupported platform otherwise, before any binary is resolved"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "g2 fallback first runs npm install of the platform package; on failure it falls back to a direct download"
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "g2 fallback (npm install or direct tarball fetch) needs the npm registry"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.ESBUILD_BINARY_PATH",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1394,
            "end_byte": 1397,
            "node_type": "unary_expression",
            "sha256": "c1ee241e9c6f9085",
            "line": 30
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.ESBUILD_BINARY_PATH",
      "operator": "!=",
      "value": "/usr/bin/esbuild",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1401,
            "end_byte": 1425,
            "node_type": "binary_expression",
            "sha256": "7c3bf5994abaa9cf",
            "line": 30
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_0a7775580d",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10206,
            "end_byte": 10241,
            "node_type": "call_expression",
            "sha256": "7c5b23f9fd305176",
            "line": 259
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "$ESBUILD_BINARY_PATH",
        "accessor": "exists"
      }
    },
    {
      "id": "c4",
      "category": "dependency_tree",
      "api": "require.resolve",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10551,
            "end_byte": 10587,
            "node_type": "call_expression",
            "sha256": "439885b4664aa4eb",
            "line": 269
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "require.resolve",
        "target": "*/*",
        "accessor": "throws"
      }
    },
    {
      "id": "c5",
      "category": "os",
      "api": "process.platform",
      "operator": "not_in",
      "value": "android arm LE, android x64 LE, openharmony arm64 LE",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 3119,
            "end_byte": 3166,
            "node_type": "binary_expression",
            "sha256": "cb1e0001067d6c49",
            "line": 74
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "os",
      "api": "os.platform()",
      "operator": "!=",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_001440beb3",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 8832,
            "end_byte": 8858,
            "node_type": "binary_expression",
            "sha256": "5b39e5ae1d1ff10c",
            "line": 226
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "package_manager",
      "api": "process.env.npm_config_user_agent",
      "operator": "not_regex",
      "value": "\\byarn\\/",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_4ee019cb74",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 5801,
            "end_byte": 5822,
            "node_type": "identifier",
            "sha256": "ac23fd1f0c51dbe6",
            "line": 142
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 5837,
            "end_byte": 5875,
            "node_type": "call_expression",
            "sha256": "40779ead18c7ebab",
            "line": 143
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
      "expression": "c1 && c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10151,
            "end_byte": 10443,
            "node_type": "if_statement",
            "sha256": "7123aacf30c0d67f",
            "line": 258
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2"
          ]
        },
        {
          "candidate": "q_2389a925f0",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10201,
            "end_byte": 10439,
            "node_type": "if_statement",
            "sha256": "c1de024c8e4e5d6e",
            "line": 259
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "user configuration override: when ESBUILD_BINARY_PATH names an existing binary, the install writes a shim pointing at it instead of resolving the platform package",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var": {
            "ESBUILD_BINARY_PATH": "/opt/esbuild/esbuild"
          },
          "file_present": [
            "/opt/esbuild/esbuild"
          ]
        },
        "recipe_guessed_fields": [
          "env_var",
          "file_present"
        ],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10360,
            "end_byte": 10439,
            "node_type": "statement_block",
            "sha256": "c409e0cc79d1cbd3",
            "line": 261
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 8434,
              "end_byte": 8582,
              "node_type": "call_expression",
              "sha256": "71c60fb3872aae88",
              "line": 217
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 10368,
                  "end_byte": 10418,
                  "node_type": "call_expression",
                  "sha256": "5f93c17ec8b33c0d",
                  "line": 262
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 8326,
                  "end_byte": 8776,
                  "node_type": "function_declaration",
                  "sha256": "6a128ca36a04eca6",
                  "line": 215
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
      "expression": "c4 && c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 10531,
            "end_byte": 11564,
            "node_type": "try_statement",
            "sha256": "ed3d2d2dac439bda",
            "line": 268
          },
          "kind": "try_except",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 11015,
            "end_byte": 11081,
            "node_type": "if_statement",
            "sha256": "97dc0ba597aa16fe",
            "line": 278
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
      "purpose_reason": "fallback that fetches the platform binary (npm install, then direct registry tarball) when the platform optionalDependency is missing",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "spawn_process",
          "download",
          "write_file",
          "delete_file"
        ],
        "env_recipe": {
          "os": "linux",
          "arch": "x64"
        },
        "recipe_guessed_fields": [
          "os",
          "arch"
        ],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 11086,
            "end_byte": 11560,
            "node_type": "stmt_range",
            "sha256": "e9340527dd510254",
            "line": 279
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 7499,
              "end_byte": 7687,
              "node_type": "call_expression",
              "sha256": "d6150d82fb21a8e2",
              "line": 187
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 11224,
                  "end_byte": 11262,
                  "node_type": "call_expression",
                  "sha256": "8af3d4250623e2cf",
                  "line": 282
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7148,
                  "end_byte": 7979,
                  "node_type": "function_declaration",
                  "sha256": "2a2eb06c2d56487e",
                  "line": 180
                }
              }
            ]
          },
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 9833,
              "end_byte": 9843,
              "node_type": "call_expression",
              "sha256": "02080ee9df202934",
              "line": 248
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 11415,
                  "end_byte": 11461,
                  "node_type": "call_expression",
                  "sha256": "5230e889bdea03b1",
                  "line": 286
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 9530,
                  "end_byte": 10106,
                  "node_type": "function_declaration",
                  "sha256": "fa980e8b66447b3a",
                  "line": 244
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 9906,
              "end_byte": 9939,
              "node_type": "call_expression",
              "sha256": "f2ed49826f067e00",
              "line": 250
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 11415,
                  "end_byte": 11461,
                  "node_type": "call_expression",
                  "sha256": "5230e889bdea03b1",
                  "line": 286
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 9530,
                  "end_byte": 10106,
                  "node_type": "function_declaration",
                  "sha256": "fa980e8b66447b3a",
                  "line": 244
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 8271,
              "end_byte": 8296,
              "node_type": "call_expression",
              "sha256": "9de210f1f2c9b806",
              "line": 211
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 11224,
                  "end_byte": 11262,
                  "node_type": "call_expression",
                  "sha256": "8af3d4250623e2cf",
                  "line": 282
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7148,
                  "end_byte": 7979,
                  "node_type": "function_declaration",
                  "sha256": "2a2eb06c2d56487e",
                  "line": 180
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7925,
                  "end_byte": 7952,
                  "node_type": "call_expression",
                  "sha256": "45b04cf5c9b679d3",
                  "line": 196
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7980,
                  "end_byte": 8325,
                  "node_type": "function_declaration",
                  "sha256": "9c0f902d14e9aa11",
                  "line": 201
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
      "hook": "postinstall",
      "expression": "c6 && c7 && c5",
      "guards": [
        {
          "candidate": "q_744c8cddf2",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 8828,
            "end_byte": 9115,
            "node_type": "if_statement",
            "sha256": "94edccc184ad2ea8",
            "line": 226
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6",
            "c7",
            "c5"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "outside Windows, Yarn and WASM platforms the native binary is hard-linked over the bin/esbuild JS shim to skip a node launch",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "linux",
          "arch": "x64",
          "package_manager": "npm"
        },
        "recipe_guessed_fields": [
          "os",
          "arch",
          "package_manager"
        ],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 8884,
            "end_byte": 9115,
            "node_type": "statement_block",
            "sha256": "fc4981358b212046",
            "line": 226
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 9000,
              "end_byte": 9032,
              "node_type": "call_expression",
              "sha256": "8e5978156526ed23",
              "line": 230
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
      "spawn_process",
      "benign_build"
    ],
    "gated": [
      "write_file",
      "spawn_process",
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
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/$",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall is esbuild's standard install.js: it locates the platform binary from the optionalDependency, falls back to npm install or a sha256-verified registry download only when that package is missing, optionally hard-links the binary over the JS shim, and runs it with --version. Nothing collects, sends or persists data.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "cc9c8e053a28ca42"
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
        "candidate": "k_5ac6641f52",
        "reason_code": "not_environmental",
        "note": "lstatSync in removeRecursive while deleting the temporary npm-install folder; skipping unreadable entries is cleanup plumbing",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 8143,
          "end_byte": 8167,
          "node_type": "call_expression",
          "sha256": "4f403874a4efbe6c",
          "line": 206
        }
      },
      {
        "candidate": "q_2a9ba8f897",
        "reason_code": "not_environmental",
        "note": "try around lstatSync in removeRecursive cleanup loop; plumbing",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 8123,
          "end_byte": 8204,
          "node_type": "try_statement",
          "sha256": "c6b28101a775cd1d",
          "line": 205
        }
      },
      {
        "candidate": "k_6a1ea602e7",
        "reason_code": "log_only",
        "note": "darwin check in validateBinaryVersion catch only chooses a more descriptive error; both sides throw",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4838,
          "end_byte": 4865,
          "node_type": "binary_expression",
          "sha256": "a698905dc76a7099",
          "line": 118
        }
      },
      {
        "candidate": "k_bdbbaa74e6",
        "reason_code": "log_only",
        "note": "sw_vers probe only fills the macOS version into the error message",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4994,
          "end_byte": 5052,
          "node_type": "call_expression",
          "sha256": "b5f18cb6293da171",
          "line": 121
        }
      },
      {
        "candidate": "q_d89d9e0aa2",
        "reason_code": "log_only",
        "note": "darwin/_SecTrustEvaluateWithError branch in validateBinaryVersion only changes the thrown error text",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4834,
          "end_byte": 5554,
          "node_type": "if_statement",
          "sha256": "81d841a4bd53ef92",
          "line": 118
        }
      },
      {
        "candidate": "q_0b3cb0707a",
        "reason_code": "log_only",
        "note": "same decision as q_d89d9e0aa2; only the error text differs",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4834,
          "end_byte": 5554,
          "node_type": "if_statement",
          "sha256": "81d841a4bd53ef92",
          "line": 118
        }
      },
      {
        "candidate": "q_7befdb7ee1",
        "reason_code": "log_only",
        "note": "try around sw_vers only builds the error message",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4963,
          "end_byte": 5095,
          "node_type": "try_statement",
          "sha256": "bb4b5e154cf8a8fe",
          "line": 120
        }
      },
      {
        "candidate": "q_c53c402f86",
        "reason_code": "duplicate_of",
        "note": "early return inside the isYarn helper; its result is c7 tested by the g3 guard q_744c8cddf2",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 5797,
          "end_byte": 5880,
          "node_type": "if_statement",
          "sha256": "5364df60a04740a5",
          "line": 142
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 7,
    "condition_sites_cited": 3,
    "guards_cited": 2,
    "candidates_dropped": 8,
    "conditions_in_set": 2,
    "conditions_out_of_set": 5,
    "guard_candidates": 22,
    "gates_in_set": 1,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c4",
      "c5",
      "c7",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
