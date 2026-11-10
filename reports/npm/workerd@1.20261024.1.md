# npm workerd@1.20261024.1

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-24 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node install.js`, the esbuild-style installer that workerd uses to place its native binary. The only gate is the platform lookup: the `process.platform`/`os.arch()` key must be one of the known darwin, linux or win32 on arm64 or x64 combinations, otherwise the script throws before doing anything. On a supported platform it takes the binary from the matching `@cloudflare/workerd-*` optional dependency, or, if that is missing, runs `npm install` of it or downloads its tarball from the npm registry, writes the binary, then runs it with `--version`.

## Execution

- **postinstall** `node install.js`: runs install.js; direct_script, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 (c1: os in [darwin, linux, win32]; c2: arch in [arm64, x64]; c3: arch == LE) | then | 3 | download, write_file, delete_file, spawn_process, exec_downloaded | os=linux; arch=x64 |

Gate intent: g1 activate/enables/portability

Grounding: 0 of 3 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, c2, c3, g1.

## Requirements

- network: registry[.]npmjs[.]org:443 (fallback only: npm install of the platform package or direct tarball download when the optional dependency is missing)
- installed_tool: npm (fallback only: installUsingNPM runs npm install of the platform binary package)

## Behaviour

- Ungated: none
- Gated: download, write_file, delete_file, spawn_process, exec_downloaded

## Notes

- g1 is out of set: the extractor did not offer the `platformKey in knownPackages` check as a candidate. The guard sits in a helper that throws; the regions are the code after the helper call and the `.then` callback, which only run when it returns.
- The other prefilled checks (exe extension, a linux hint in an error message, yarn detection for the hardlink optimisation) are plumbing or log text and were dropped.
- The esbuild issue, snapcraft and nodejs URLs are only in comments.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "workerd",
    "version": "1.20261024.1",
    "archive_sha256": "50d52f7bc717a111bbeacf6cf6573bc7676531e1a64e5f9eedee690542dfbe02",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-24",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/workerd-1.20261024.1.tgz",
    "package_root": "layer0/package",
    "cluster_key": "89f0419cf787bccbfdded1d30d476f5ec85eb12f1ac65ebb3c5cd0e7b3775050",
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
          "install.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): workerd",
      "optionalDependencies (platform picks belong to the dependency tree): @cloudflare/workerd-darwin-arm64, @cloudflare/workerd-darwin-64, @cloudflare/workerd-linux-arm64, @cloudflare/workerd-linux-64, @cloudflare/workerd-windows-64",
      "install.js: esbuild-style install shim (esbuild helper header plus package code), read in full; nothing unread.",
      "g1: the unsupported-platform branch throws inside pkgAndSubpathForCurrentPlatform, rejecting checkAndPreparePackage, so the rest of that function and its .then callback (binary validation) only run on a supported os/arch.",
      "require.resolve of the platform binary package is plumbing: when the optional dependency is present it is used; otherwise the script falls back to npm install of it, then a direct registry tarball download. Same end behaviour, so not a gate.",
      "maybeOptimizePackage (not win32 and not yarn) hardlinks the native binary over bin/workerd; it only changes how the binary is started, so it is plumbing. maybeExeExtension only picks a file name.",
      "Validation runs the binary with --version (execFileSync); a failure is caught and only logged, which is part of silent_failure."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "fallback only: npm install of the platform package or direct tarball download when the optional dependency is missing"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "fallback only: installUsingNPM runs npm install of the platform binary package"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "darwin",
        "linux",
        "win32"
      ],
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1781,
            "end_byte": 1797,
            "node_type": "member_expression",
            "sha256": "efe93b1e00e72877",
            "line": 39
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "arch",
      "api": "os.arch()",
      "operator": "in",
      "value": [
        "arm64",
        "x64"
      ],
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1801,
            "end_byte": 1825,
            "node_type": "call_expression",
            "sha256": "6fa7178d9b539a6a",
            "line": 39
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "arch",
      "api": "os.endianness()",
      "operator": "==",
      "value": "LE",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1829,
            "end_byte": 1859,
            "node_type": "call_expression",
            "sha256": "7f653cbea4b2aded",
            "line": 39
          }
        }
      ],
      "in_scope": true,
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
            "start_byte": 1869,
            "end_byte": 1897,
            "node_type": "binary_expression",
            "sha256": "885fe8d7fb9aa31c",
            "line": 40
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "platform key (os, arch, endianness) must map to a known prebuilt workerd binary package, else the script throws before installing or validating anything",
      "then": {
        "behaviours": [
          "download",
          "write_file",
          "delete_file",
          "spawn_process",
          "exec_downloaded"
        ],
        "env_recipe": {
          "os": "linux",
          "arch": "x64"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 8127,
            "end_byte": 9153,
            "node_type": "stmt_range",
            "sha256": "c41964b5acbdd4a5",
            "line": 218
          },
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 9196,
            "end_byte": 9316,
            "node_type": "if_statement",
            "sha256": "eab834b5706a9102",
            "line": 247
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 7801,
              "end_byte": 7811,
              "node_type": "call_expression",
              "sha256": "02080ee9df202934",
              "line": 206
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 8971,
                  "end_byte": 9017,
                  "node_type": "call_expression",
                  "sha256": "5230e889bdea03b1",
                  "line": 238
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7421,
                  "end_byte": 8020,
                  "node_type": "function_declaration",
                  "sha256": "664bca38f5990b69",
                  "line": 199
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
              "start_byte": 7718,
              "end_byte": 7827,
              "node_type": "call_expression",
              "sha256": "207078f02b004d8c",
              "line": 204
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 8971,
                  "end_byte": 9017,
                  "node_type": "call_expression",
                  "sha256": "5230e889bdea03b1",
                  "line": 238
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 7421,
                  "end_byte": 8020,
                  "node_type": "function_declaration",
                  "sha256": "664bca38f5990b69",
                  "line": 199
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 6136,
              "end_byte": 6334,
              "node_type": "call_expression",
              "sha256": "41e151543af05786",
              "line": 155
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 8764,
                  "end_byte": 8802,
                  "node_type": "call_expression",
                  "sha256": "8af3d4250623e2cf",
                  "line": 232
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 5726,
                  "end_byte": 6609,
                  "node_type": "function_declaration",
                  "sha256": "19a01117f1583a3e",
                  "line": 148
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
              "start_byte": 6944,
              "end_byte": 6983,
              "node_type": "call_expression",
              "sha256": "bd2097957feafaec",
              "line": 183
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 8764,
                  "end_byte": 8802,
                  "node_type": "call_expression",
                  "sha256": "8af3d4250623e2cf",
                  "line": 232
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 5726,
                  "end_byte": 6609,
                  "node_type": "function_declaration",
                  "sha256": "19a01117f1583a3e",
                  "line": 148
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 6555,
                  "end_byte": 6582,
                  "node_type": "call_expression",
                  "sha256": "45b04cf5c9b679d3",
                  "line": 168
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 6610,
                  "end_byte": 7026,
                  "node_type": "function_declaration",
                  "sha256": "a5f394e26b9b97af",
                  "line": 173
                }
              }
            ]
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 2862,
              "end_byte": 3690,
              "node_type": "call_expression",
              "sha256": "7c5f074e46963283",
              "line": 66
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 9218,
                  "end_byte": 9265,
                  "node_type": "call_expression",
                  "sha256": "d9c8c693112c8f35",
                  "line": 248
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 2753,
                  "end_byte": 4274,
                  "node_type": "function_declaration",
                  "sha256": "8ec78a7183cf475b",
                  "line": 62
                }
              }
            ]
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "download",
      "write_file",
      "delete_file",
      "spawn_process",
      "exec_downloaded"
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
  "assessment_reason": "The postinstall script is the standard esbuild-style binary installer for Cloudflare's workerd: it locates the platform binary from optionalDependencies, falls back to npm install or a registry tarball of the same pinned version, and runs the binary with --version. No credential access, exfiltration or unexpected endpoints.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@97d6974e53",
      "sha256": "522fadeac3c8b2e8"
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
        "candidate": "k_840d917e4b",
        "reason_code": "other",
        "note": "plumbing: process.platform == win32 only picks the .exe file extension",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 1643,
          "end_byte": 1671,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 35
        }
      },
      {
        "candidate": "q_bc5330b571",
        "reason_code": "other",
        "note": "plumbing: ternary only picks the .exe file extension",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 1643,
          "end_byte": 1685,
          "node_type": "ternary_expression",
          "sha256": "47d8092f29061d93",
          "line": 35
        }
      },
      {
        "candidate": "k_b568a7c63a",
        "reason_code": "log_only",
        "note": "linux check only appends a libc++1 hint to an error message",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 3925,
          "end_byte": 3953,
          "node_type": "binary_expression",
          "sha256": "2aef811fbf485517",
          "line": 92
        }
      },
      {
        "candidate": "q_d42c314bc5",
        "reason_code": "log_only",
        "note": "if only appends text to an error message",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 3921,
          "end_byte": 4055,
          "node_type": "if_statement",
          "sha256": "00a6e7689db1b479",
          "line": 92
        }
      },
      {
        "candidate": "k_1178b3dada",
        "reason_code": "other",
        "note": "plumbing: yarn detection only decides whether to hardlink the native binary over the JS shim (how it starts)",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4350,
          "end_byte": 4371,
          "node_type": "identifier",
          "sha256": "ac23fd1f0c51dbe6",
          "line": 108
        }
      },
      {
        "candidate": "q_1613c4bb62",
        "reason_code": "other",
        "note": "plumbing: isYarn helper early return, feeds the hardlink optimisation only",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4346,
          "end_byte": 4429,
          "node_type": "if_statement",
          "sha256": "5364df60a04740a5",
          "line": 108
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 6,
    "conditions_in_set": 0,
    "conditions_out_of_set": 3,
    "guard_candidates": 3,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
