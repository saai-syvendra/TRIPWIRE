# npm @pnpm/exe@12.15.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-21 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Both `preinstall` and `postinstall` run `node install.js`, which branches on `npm_lifecycle_event`. In preinstall, `setup()` (skipped under WebContainer, gate g1) hard-links or copies the installed platform pnpm binary over the placeholder bins. On Windows that means `.exe` plus extensionless copies with a package.json `bin` rewrite, elsewhere mode 755; this OS split is plumbing, not a gate. In postinstall, only on Windows under npm (`npm_execpath` ending in `npm-cli.js`), it spawns `node npm-cli.js rebuild --ignore-scripts` to regenerate npm shims (gate g2). No network access and no data collection.

## Execution

- **preinstall** `node install.js`: 2-file chain; direct_script; errors hidden.
- **postinstall** `node install.js`: 2-file chain; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 && c2 (c1: process.env.npm_lifecycle_event != postinstall; c2: runtime_version not_includes webcontainer) | then | 2 | write_file | env_var=npm_lifecycle_event=preinstall; runtime_version=node (not WebContainer) |
| g2 | postinstall | c4 && c5 && c7 (c4: process.env.npm_lifecycle_event == postinstall; c5: os == win32; c7: path.basename(process.env.npm_execpath) == npm-cli.js) | then | 3 | spawn_process | os=win32; env_var=npm_lifecycle_event=postinstall, npm_execpath=npm-cli.js |

Gate intent: g1 activate/enables/portability; g2 activate/enables/portability

Grounding: 4 of 5 conditions and 2 of 2 gates from the candidate set; out of set, pending verification: c7.

## Requirements

- file_present: node_modules/@pnpm/exe.<platform>-<arch>[-musl]/pnpm (pnpm.exe on win32) (setup() fails with exit 1 unless the matching platform optional dependency is installed next to the wrapper; host os/arch must be one pnpm ships a binary for)
- other: npm_config_global=true or npm_config_location=global, else npm_config_local_prefix naming the project whose node_modules holds the wrapper (postinstall shim relink returns without running npm rebuild when neither a global install nor a matching project prefix is found)

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process

## Notes

- The `npm-cli.js` basename test (c7) was added out of set; the tool only saw the platform and `npm_execpath` presence parts of that early exit. The presence check is part of c7, not a condition of its own.
- Binary lookup failures, the rebuild target choice (global vs `--prefix`), the project prefix lookup and the win32 test in `setup()` are treated as prerequisites or plumbing and dropped as candidates; see requirements.
- Legitimate pnpm release code; matches the benign source label.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@pnpm/exe",
    "version": "12.15.0",
    "archive_sha256": "2df447fb7ebbd01c974366d6b6b5617bcf4125d0f1cb27c5c7a480f5ab794a8a",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-21",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/exe-12.15.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "b28e5fa827533ccdb1a92867df9bc6771c6c4207a3fb36d58f46cc4b3ac17319",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node install.js",
        "runs_on": "always",
        "file_chain": [
          "install.js",
          "native-binary.mjs"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "postinstall",
        "command": "node install.js",
        "runs_on": "always",
        "file_chain": [
          "install.js",
          "native-binary.mjs"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): pnpm, pn, pnpx, pnx",
      "optionalDependencies (platform picks belong to the dependency tree): @pnpm/exe.win32-x64, @pnpm/exe.win32-arm64, @pnpm/exe.darwin-x64, @pnpm/exe.darwin-arm64, @pnpm/exe.linux-x64, @pnpm/exe.linux-arm64, @pnpm/exe.linux-riscv64, @pnpm/exe.linux-ppc64, @pnpm/exe.linux-s390x, @pnpm/exe.linux-x64-musl",
      "generator truncated: some helpers walked under only 2 guard contexts in install.js, native-binary.mjs; candidates there may be missing",
      "install.js and native-binary.mjs: package code, read in full; nothing unread. dist/ (bundled pnpm and node-gyp) is only used by the bins, not reached at install.",
      "Both hooks run the same install.js; npm_lifecycle_event picks setup() in preinstall and relinkNpmWindowsShims() in postinstall. The other side is dead in each hook under a real npm install.",
      "setup() returns early when the package's own package.json has no optionalDependencies (monorepo checkout); fixed by package content, not the environment, so not recorded as a gate.",
      "Binary lookup (getBinCandidates/resolveInstalledBinary) exits with an error when no platform package binary is found; treated as a prerequisite (requirements), not a gate.",
      "Postinstall: global vs --prefix only picks the npm rebuild target; findNpmProjectPrefix returning null skips the rebuild when no project holds the wrapper. Treated as plumbing/prerequisite.",
      "rewriteBin swallows read/write errors of package.json (silent_failure on preinstall); placeBinary failures exit 1 and are not silent.",
      "setup() win32 vs other OS is plumbing, not a gate: both sides run placeBinary on the same binary (line 100 sink). Windows adds .exe twins and rewrites the package.json bin map to start them; elsewhere mode 755 applies on the copy path.",
      "g2 recipe: npm_execpath gives only the file name the code tests (basename, lowercased, equals npm-cli.js). The folder is not in the code; line 149 runs that path with node, so the rebuild needs the real path npm sets."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "node_modules/@pnpm/exe.<platform>-<arch>[-musl]/pnpm (pnpm.exe on win32)",
      "reason": "setup() fails with exit 1 unless the matching platform optional dependency is installed next to the wrapper; host os/arch must be one pnpm ships a binary for"
    },
    {
      "axis": "other",
      "value": "npm_config_global=true or npm_config_location=global, else npm_config_local_prefix naming the project whose node_modules holds the wrapper",
      "reason": "postinstall shim relink returns without running npm rebuild when neither a global install nor a matching project prefix is found"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "process.env.npm_lifecycle_event",
      "operator": "!=",
      "value": "postinstall",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_9dae12ed9b",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 930,
            "end_byte": 979,
            "node_type": "binary_expression",
            "sha256": "13349cb3954dab33",
            "line": 25
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "runtime_version",
      "api": "process.versions",
      "operator": "not_includes",
      "value": "webcontainer",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_97f4cb64fb",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1444,
            "end_byte": 1478,
            "node_type": "binary_expression",
            "sha256": "c4873c9e6518c7db",
            "line": 40
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "package_manager",
      "api": "process.env.npm_lifecycle_event",
      "operator": "==",
      "value": "postinstall",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_9dae12ed9b",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 930,
            "end_byte": 979,
            "node_type": "binary_expression",
            "sha256": "13349cb3954dab33",
            "line": 25
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_fb6a2c24e2",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4241,
            "end_byte": 4269,
            "node_type": "binary_expression",
            "sha256": "05dbbdd00d49d713",
            "line": 124
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "package_manager",
      "api": "path.basename(process.env.npm_execpath)",
      "operator": "==",
      "value": "npm-cli.js",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4304,
            "end_byte": 4361,
            "node_type": "binary_expression",
            "sha256": "05850c775e792d97",
            "line": 126
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
      "hook": "preinstall",
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": "q_e482143afa",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 926,
            "end_byte": 1029,
            "node_type": "if_statement",
            "sha256": "84a7eddff6eddce9",
            "line": 25
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_9e74488a9d",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1440,
            "end_byte": 1496,
            "node_type": "if_statement",
            "sha256": "760a5ee012c3f51f",
            "line": 40
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "setup() places the native binary over the placeholder bins only in the non-postinstall run and outside WebContainer, where the placeholders stay; the win32 test inside it is plumbing",
      "then": {
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var": {
            "npm_lifecycle_event": "preinstall"
          },
          "runtime_version": "node (not WebContainer)"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 1500,
            "end_byte": 2597,
            "node_type": "stmt_range",
            "sha256": "243239e16df0f2c3",
            "line": 44
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 3507,
              "end_byte": 3540,
              "node_type": "call_expression",
              "sha256": "bfbc87ca32cb7bdb",
              "line": 100
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 2526,
                  "end_byte": 2587,
                  "node_type": "call_expression",
                  "sha256": "0da601e06d7f35e4",
                  "line": 71
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "install.js",
                  "derived_from": null,
                  "start_byte": 3121,
                  "end_byte": 3676,
                  "node_type": "function_declaration",
                  "sha256": "7b2c1fefba8d2070",
                  "line": 86
                }
              }
            ]
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c4 && c5 && c7",
      "guards": [
        {
          "candidate": "q_6f3af0b064",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 926,
            "end_byte": 1029,
            "node_type": "if_statement",
            "sha256": "84a7eddff6eddce9",
            "line": 25
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": "q_c36b7fa045",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4232,
            "end_byte": 4382,
            "node_type": "if_statement",
            "sha256": "3e4e847b5dd618bc",
            "line": 123
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "regenerates npm's Windows cmd/ps1 shims so they point at pnpm.exe after the bin rewrite; a platform-specific install fixup that only applies to Windows installs run by npm, not a victim selection",
      "then": {
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32",
          "env_var": {
            "npm_lifecycle_event": "postinstall",
            "npm_execpath": "npm-cli.js"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4386,
            "end_byte": 5209,
            "node_type": "stmt_range",
            "sha256": "7e32a8195910a422",
            "line": 131
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 4949,
              "end_byte": 5004,
              "node_type": "call_expression",
              "sha256": "25103c638698776b",
              "line": 149
            },
            "witness": []
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "in_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "write_file",
      "spawn_process"
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
  "assessment_reason": "The install hooks only hard-link or copy the already-installed platform pnpm binary over the placeholder bins (rewriting package.json bin on Windows) and, on Windows under npm, run `npm rebuild --ignore-scripts` to regenerate shims. No network access, no data collection.",
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
      "sha256": "5783d3887d036dec"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 2
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_c1db0e95ff",
        "reason_code": "other",
        "note": "win32 test in setup(): both sides place the same native binary through placeBinary; it only changes file names, the copy mode and the bin map that starts the .exe, so plumbing",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 2034,
          "end_byte": 2062,
          "node_type": "binary_expression",
          "sha256": "67d640affd7c71c5",
          "line": 59
        }
      },
      {
        "candidate": "q_533751a1fd",
        "reason_code": "other",
        "note": "win32 test in setup(): both sides place the same native binary through placeBinary; it only changes file names, the copy mode and the bin map that starts the .exe, so plumbing",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 2030,
          "end_byte": 2597,
          "node_type": "if_statement",
          "sha256": "bbefd33de1b443fd",
          "line": 59
        }
      },
      {
        "candidate": "k_9c7ac37e27",
        "reason_code": "other",
        "note": "npmExecPath == null is the presence check in front of the basename test of the same value (c7), so it is part of that test and not a separate condition",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4277,
          "end_byte": 4296,
          "node_type": "binary_expression",
          "sha256": "930a07d23fa70f39",
          "line": 125
        }
      },
      {
        "candidate": "k_651e2231d7",
        "reason_code": "other",
        "note": "npm_config_global only picks npm rebuild --global vs --prefix; both sides run the same rebuild (plumbing)",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4652,
          "end_byte": 4692,
          "node_type": "binary_expression",
          "sha256": "fef88bc47d7ed5f2",
          "line": 140
        }
      },
      {
        "candidate": "k_ca44613008",
        "reason_code": "other",
        "note": "npm_config_location only picks npm rebuild --global vs --prefix; both sides run the same rebuild (plumbing)",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4696,
          "end_byte": 4740,
          "node_type": "binary_expression",
          "sha256": "e820873c0e36c3fb",
          "line": 140
        }
      },
      {
        "candidate": "q_cbea8e73f7",
        "reason_code": "other",
        "note": "global vs local rebuild target selection; plumbing, same behaviour on both sides",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4648,
          "end_byte": 4931,
          "node_type": "if_statement",
          "sha256": "7987c79bd93944e9",
          "line": 140
        }
      },
      {
        "candidate": "q_a673f48485",
        "reason_code": "other",
        "note": "global vs local rebuild target selection; plumbing, same behaviour on both sides",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4648,
          "end_byte": 4931,
          "node_type": "if_statement",
          "sha256": "7987c79bd93944e9",
          "line": 140
        }
      },
      {
        "candidate": "k_843cd825f3",
        "reason_code": "other",
        "note": "project prefix lookup for npm rebuild; aborts only when no project is found, recorded as a requirement",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 5741,
          "end_byte": 5754,
          "node_type": "binary_expression",
          "sha256": "fe1a7b3dd7df8c9a",
          "line": 169
        }
      },
      {
        "candidate": "q_a294e6940d",
        "reason_code": "other",
        "note": "project prefix lookup for npm rebuild; aborts only when no project is found, recorded as a requirement",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 5707,
          "end_byte": 5777,
          "node_type": "if_statement",
          "sha256": "1e27e51b29c0a4cb",
          "line": 169
        }
      },
      {
        "candidate": "k_3f117a4107",
        "reason_code": "other",
        "note": "big-endian ppc64 check inside the native binary lookup; no candidate just leads to fail(), a prerequisite",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 2343,
          "end_byte": 2359,
          "node_type": "binary_expression",
          "sha256": "0c22aaf17fd15448",
          "line": 74
        }
      },
      {
        "candidate": "q_bebc39327b",
        "reason_code": "other",
        "note": "big-endian ppc64 check inside the native binary lookup; no candidate just leads to fail(), a prerequisite",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 2339,
          "end_byte": 2408,
          "node_type": "if_statement",
          "sha256": "50dde296c1a21984",
          "line": 74
        }
      },
      {
        "candidate": "k_1dbbaade7f",
        "reason_code": "other",
        "note": "libc detection only orders glibc/musl binary candidates and builds a message; plumbing",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 6173,
          "end_byte": 6193,
          "node_type": "binary_expression",
          "sha256": "7a6bc2837b29b280",
          "line": 178
        }
      },
      {
        "candidate": "q_c6fa0d8434",
        "reason_code": "other",
        "note": "libc detection only orders glibc/musl binary candidates and builds a message; plumbing",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 6169,
          "end_byte": 6216,
          "node_type": "if_statement",
          "sha256": "1bf6e36ec33de424",
          "line": 178
        }
      },
      {
        "candidate": "k_9b85748fdd",
        "reason_code": "not_environmental",
        "note": "reads the package's own package.json; throws only when the shipped manifest is corrupt",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 5823,
          "end_byte": 5860,
          "node_type": "call_expression",
          "sha256": "30e1bfa6a33f9a0e",
          "line": 167
        }
      },
      {
        "candidate": "q_029e2293b3",
        "reason_code": "not_environmental",
        "note": "reads the package's own package.json; throws only when the shipped manifest is corrupt",
        "anchor": {
          "file": "native-binary.mjs",
          "derived_from": null,
          "start_byte": 5791,
          "end_byte": 5953,
          "node_type": "try_statement",
          "sha256": "db8864700119df0f",
          "line": 166
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 28,
    "condition_sites_cited": 3,
    "guards_cited": 4,
    "candidates_dropped": 15,
    "conditions_in_set": 4,
    "conditions_out_of_set": 1,
    "guard_candidates": 11,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [
      "c7"
    ],
    "anchor_refusals": 0
  }
}
```
