# npm esoftplay@0.0.143-k

**Source:** datadog · **Source label:** malicious · **Released:** 2025-05-07 (registry) · **Assessment:** benign (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `bun ./bin/build.js install`. The script first checks that it sits inside a host project (`../../package.json` exists); without one it only logs. Inside a project it rewrites the host's config files and installs missing Expo and React Native libraries with `bun add` and `bunx expo install`. It then runs the package's own `bin/router.js` and `bin/locale.js` to generate route and locale caches. Four further gates check whether specific dependency files are present. If they are, the script patches them inside node_modules: react-native JSTimers, @react-navigation/core useNavigationBuilder, the @firebase/app RN build, and an icons type file in @expo/vector-icons. Every gate is a consuming-app or dependency-tree check, so none is in scope for Phase 2.

## Execution

- **postinstall** `bun ./bin/build.js install`: 3-file chain; direct_script, inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: consuming_app exists ../../package.json) | then | 1 | write_file, delete_file, spawn_process | file_present=../../package.json |
| g2 | postinstall | c1 && c2 (c1: consuming_app exists ../../package.json; c2: dependency_tree exists ../../node_modules/react-native/Libraries/Core/Timers/JSTimers.js) | then | 2 | modify_other_packages | file_present=../../package.json, ../../node_modules/react-native/Libraries/Core/Timers/JSTimers.js |
| g3 | postinstall | c1 && c3 (c1: consuming_app exists ../../package.json; c3: dependency_tree exists ../../node_modules/@react-navigation/core/src/useNavigationBuilder.tsx) | then | 2 | modify_other_packages | file_present=../../package.json, ../../node_modules/@react-navigation/core/src/useNavigationBuilder.tsx |
| g4 | postinstall | c1 && c4 (c1: consuming_app exists ../../package.json; c4: dependency_tree exists ../@firebase/app/dist/index.rn.cjs.js) | then | 2 | modify_other_packages | file_present=../../package.json, ../@firebase/app/dist/index.rn.cjs.js |
| g5 | postinstall | c1 && c5 (c1: consuming_app exists ../../package.json; c5: dependency_tree exists ../@expo/vector-icons) | then | 2 | modify_other_packages | file_present=../../package.json, ../@expo/vector-icons |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability

Grounding: 5 of 5 conditions and 5 of 5 gates from the candidate set.

## Requirements

- file_present: ../../app.json (Host project app.json with an `expo` object is needed; without it line 93 throws and the rest of the install script stops.)
- installed_tool: bun (The hook and every execSync command run through bun/bunx.)
- network: registry[.]npmjs[.]org:443 (`bun add ... --dev` and `bunx expo install ...` fetch missing Expo/React Native dependencies into the host project.)
- other: ../../package.json must parse as JSON and contain a `scripts` object (Line 31 sets $package.scripts.start without checking; a missing scripts object throws and stops the script.)

## Behaviour

- Ungated: none
- Gated: write_file, delete_file, spawn_process, modify_other_packages

## Notes

- I found no malicious payload in the install-reached code: no credential reads, no exfiltration, no remote stage, no obfuscation. This disagrees with the source label `malicious`, so the record is flagged for review.
- Invasive but framework-consistent actions:
  - it rewrites the host `package.json`, setting `scripts.start` and a `trustedDependencies` list of esoftplay-* packages, which lets Bun run their lifecycle scripts;
  - it overwrites `babel.config.js`, `tsconfig.json`, `.gitignore` and `eas.json`;
  - it deletes `App.js`;
  - it edits files of other installed packages.
- If the host app.json has no `expo` object, line 93 throws and everything after it is skipped.
- The CLI (`bin/cli.js`) contains `fetch` and an `eval` of a config value. It runs only when invoked, not at install, so I did not analyse it.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "esoftplay",
    "version": "0.0.143-k",
    "archive_sha256": "b8c355d1f1abf89738c700996bcc70163d283f3d21f515ddd5cc67884e3d2e6a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-05-07",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-05-07-esoftplay-v0.0.143-k.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmp68g2p4ud/esoftplay/package",
    "cluster_key": "e5adbaf25ac16fcdd71734e8ed6a5e8c8932b1fa600f13a9543561654b61cbfe",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "bun ./bin/build.js install",
        "runs_on": "always",
        "file_chain": [
          "bin/build.js",
          "bin/router.js",
          "bin/locale.js"
        ],
        "interpreter": "other",
        "launch_style": [
          "direct_script",
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): esoftplay",
      "Interpreter is bun (hook runs `bun ./bin/build.js install`). bin/build.js, bin/router.js and bin/locale.js are package code, all read in full; nothing bundled or unread.",
      "bin/router.js and bin/locale.js are started by build.js via execSync(`cd ../../ && bun ./node_modules/esoftplay/bin/<x>.js || true`), i.e. this package's own files run from the host project root.",
      "router.js and locale.js only check whether their own cache/asset/locale folders and files exist before creating them (plumbing); they generate route/type cache files under node_modules/esoftplay/cache and assets/locale/id.json.",
      "The `args[0] == \"install\"` tests (build.js lines 30, 52) read the argv the hook itself passes, so they always hold at install; not environmental.",
      "Config initialisation checks (config.json, config.live.json, app.json existence, config key presence) and the per-library node_modules presence test before `bun add`/`bunx expo install` are plumbing (create if missing, reuse installed copy) and were dropped.",
      "If ../../app.json is missing or has no `expo` object, line 93 throws a TypeError that ends the script, so the JSTimers/navigation patches, dependency installs and router/locale runs never happen; listed as a requirement.",
      "execSync calls append `|| true` and JSON.parse/readFile errors are swallowed, hence silent_failure."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "../../app.json",
      "reason": "Host project app.json with an `expo` object is needed; without it line 93 throws and the rest of the install script stops.",
      "sites": [
        {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 2666,
          "end_byte": 2700,
          "node_type": "assignment_expression",
          "sha256": "7c9820c8e303f727",
          "line": 93
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "bun",
      "reason": "The hook and every execSync command run through bun/bunx."
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "`bun add ... --dev` and `bunx expo install ...` fetch missing Expo/React Native dependencies into the host project."
    },
    {
      "axis": "other",
      "value": "../../package.json must parse as JSON and contain a `scripts` object",
      "reason": "Line 31 sets $package.scripts.start without checking; a missing scripts object throws and stops the script."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "consuming_app",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "../../package.json",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_812bb6438f",
          "anchor": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 750,
            "end_byte": 773,
            "node_type": "call_expression",
            "sha256": "072ceb4070e7fb1b",
            "line": 20
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "dependency_tree",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "../../node_modules/react-native/Libraries/Core/Timers/JSTimers.js",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_4efb4cebc9",
          "anchor": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 3670,
            "end_byte": 3696,
            "node_type": "call_expression",
            "sha256": "e168fd583c2aa37f",
            "line": 143
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "dependency_tree",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "../../node_modules/@react-navigation/core/src/useNavigationBuilder.tsx",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_3cd1f0d813",
          "anchor": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 3975,
            "end_byte": 4009,
            "node_type": "call_expression",
            "sha256": "d660b44625c77fb7",
            "line": 150
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "dependency_tree",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "../@firebase/app/dist/index.rn.cjs.js",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_1503fdafed",
          "anchor": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10353,
            "end_byte": 10407,
            "node_type": "call_expression",
            "sha256": "08ef6c1b75ecf5b3",
            "line": 395
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "dependency_tree",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "../@expo/vector-icons",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": "k_cc00cd6459",
          "anchor": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10818,
            "end_byte": 10856,
            "node_type": "call_expression",
            "sha256": "96a447b6e6154b71",
            "line": 401
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
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_e7b4b28d1e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 11681,
            "node_type": "if_statement",
            "sha256": "a7915700010ed986",
            "line": 20
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Scaffolding only runs when the package sits inside a host project (../../package.json exists); otherwise it just logs.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "delete_file",
          "spawn_process"
        ],
        "env_recipe": {
          "file_present": [
            "../../package.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 775,
            "end_byte": 11632,
            "node_type": "statement_block",
            "sha256": "febf49e72e560c28",
            "line": 20
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 1375,
              "end_byte": 1520,
              "node_type": "call_expression",
              "sha256": "ebfa4a8adac156af",
              "line": 45
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 8758,
              "end_byte": 8788,
              "node_type": "call_expression",
              "sha256": "b5c4402d1c93d0f3",
              "line": 353
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 8694,
                  "end_byte": 11626,
                  "node_type": "call_expression",
                  "sha256": "7851a4af08b30067",
                  "line": 351
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 8721,
                  "end_byte": 11625,
                  "node_type": "arrow_function",
                  "sha256": "a3d3f118d55d89ff",
                  "line": 351
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 9865,
              "end_byte": 9890,
              "node_type": "call_expression",
              "sha256": "ec6c6f19ad235222",
              "line": 387
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 8694,
                  "end_byte": 11626,
                  "node_type": "call_expression",
                  "sha256": "7851a4af08b30067",
                  "line": 351
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 8721,
                  "end_byte": 11625,
                  "node_type": "arrow_function",
                  "sha256": "a3d3f118d55d89ff",
                  "line": 351
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
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": "q_e7b4b28d1e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 11681,
            "node_type": "if_statement",
            "sha256": "a7915700010ed986",
            "line": 20
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_04fa6fa91c",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 3666,
            "end_byte": 3937,
            "node_type": "if_statement",
            "sha256": "d622e3e2276361b1",
            "line": 143
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Patches react-native's JSTimers.js (raises MAX_TIMER_DURATION_MS) only when that dependency file is installed.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "modify_other_packages"
        ],
        "env_recipe": {
          "file_present": [
            "../../package.json",
            "../../node_modules/react-native/Libraries/Core/Timers/JSTimers.js"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 3698,
            "end_byte": 3937,
            "node_type": "statement_block",
            "sha256": "efd7d95270235d74",
            "line": 143
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 3894,
              "end_byte": 3933,
              "node_type": "call_expression",
              "sha256": "82c6890e8c8fed22",
              "line": 146
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c1 && c3",
      "guards": [
        {
          "candidate": "q_e7b4b28d1e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 11681,
            "node_type": "if_statement",
            "sha256": "a7915700010ed986",
            "line": 20
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_f513adcd9a",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 3971,
            "end_byte": 4358,
            "node_type": "if_statement",
            "sha256": "c54f3c1e40f97800",
            "line": 150
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Patches @react-navigation/core useNavigationBuilder.tsx (silences the lowercase component warning) only when that file is installed; else branch only logs.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "modify_other_packages"
        ],
        "env_recipe": {
          "file_present": [
            "../../package.json",
            "../../node_modules/@react-navigation/core/src/useNavigationBuilder.tsx"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 4011,
            "end_byte": 4313,
            "node_type": "statement_block",
            "sha256": "350196096bccdc11",
            "line": 150
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 4250,
              "end_byte": 4309,
              "node_type": "call_expression",
              "sha256": "4bab78e64c297934",
              "line": 154
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c1 && c4",
      "guards": [
        {
          "candidate": "q_e7b4b28d1e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 11681,
            "node_type": "if_statement",
            "sha256": "a7915700010ed986",
            "line": 20
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_ffc4bb3964",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10349,
            "end_byte": 10763,
            "node_type": "if_statement",
            "sha256": "fdd429fab1f26423",
            "line": 395
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Rewrites @firebase/app's React Native build to use @react-native-async-storage only when that file is installed.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "modify_other_packages"
        ],
        "env_recipe": {
          "file_present": [
            "../../package.json",
            "../@firebase/app/dist/index.rn.cjs.js"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10409,
            "end_byte": 10763,
            "node_type": "statement_block",
            "sha256": "98c3a93f33dc3d44",
            "line": 395
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 10687,
              "end_byte": 10758,
              "node_type": "call_expression",
              "sha256": "9aa53a75aece49e6",
              "line": 398
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c1 && c5",
      "guards": [
        {
          "candidate": "q_e7b4b28d1e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 11681,
            "node_type": "if_statement",
            "sha256": "a7915700010ed986",
            "line": 20
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_bdaaba494e",
          "site": {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10814,
            "end_byte": 11558,
            "node_type": "if_statement",
            "sha256": "a7b2ff92d12aa457",
            "line": 401
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Generates esoftplay_icons.ts type file inside @expo/vector-icons/build only when that package is installed; else branch only logs.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "modify_other_packages"
        ],
        "env_recipe": {
          "file_present": [
            "../../package.json",
            "../@expo/vector-icons"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bin/build.js",
            "derived_from": null,
            "start_byte": 10858,
            "end_byte": 11494,
            "node_type": "statement_block",
            "sha256": "cfdf062508e87234",
            "line": 401
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bin/build.js",
              "derived_from": null,
              "start_byte": 11401,
              "end_byte": 11482,
              "node_type": "call_expression",
              "sha256": "d2f7ef521498b21e",
              "line": 412
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 10891,
                  "end_byte": 11489,
                  "node_type": "call_expression",
                  "sha256": "37b4473abd36eef3",
                  "line": 403
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bin/build.js",
                  "derived_from": null,
                  "start_byte": 10933,
                  "end_byte": 11488,
                  "node_type": "arrow_function",
                  "sha256": "fcd7d7e017b8957b",
                  "line": 403
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
      "write_file",
      "delete_file",
      "spawn_process",
      "modify_other_packages"
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
  "assessment_reason": "The postinstall is the esoftplay React Native framework's own scaffolder: it rewrites the host project's config files (package.json, app.json, eas.json, tsconfig, .gitignore, App.tsx), installs missing Expo dependencies with bun, patches a few installed dependencies, and generates route caches. No credential access, exfiltration, remote payload or evasion is present in install-reached code.",
  "label_disagreement": true,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Source label is malicious but install-time code looks like the legitimate framework scaffolder; the code is invasive (rewrites host package.json incl. trustedDependencies, patches react-native, @react-navigation/core, @firebase/app and @expo/vector-icons files) but shows no malicious payload. A reviewer should confirm whether the label rests on something outside install time.",
    "label disagreement"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "4175532f22bb3337"
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
        "candidate": "k_af98d19d96",
        "reason_code": "other",
        "note": "Plumbing: config.json existence only decides whether to read existing config before (re)writing it; same behaviour either way.",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 1603,
          "end_byte": 1626,
          "node_type": "call_expression",
          "sha256": "6328563aa1c20e3c",
          "line": 54
        }
      },
      {
        "candidate": "k_d0050db34a",
        "reason_code": "other",
        "note": "Plumbing: app.json existence only decides whether to read existing config before updating it.",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 2479,
          "end_byte": 2501,
          "node_type": "call_expression",
          "sha256": "278fd1bdb42d0ec7",
          "line": 88
        }
      },
      {
        "candidate": "k_9bedd86efc",
        "reason_code": "other",
        "note": "Plumbing: creates config.live.json only if missing (create-if-absent initialisation).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 2257,
          "end_byte": 2284,
          "node_type": "call_expression",
          "sha256": "816e550f56e70e8a",
          "line": 80
        }
      },
      {
        "candidate": "k_5df869dddc",
        "reason_code": "other",
        "note": "Plumbing: skips installing an Expo library already present in node_modules (reuse installed copy); install command runs either way.",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 8884,
          "end_byte": 8928,
          "node_type": "call_expression",
          "sha256": "603355997dfd52cf",
          "line": 357
        }
      },
      {
        "candidate": "k_8782dc6b72",
        "reason_code": "other",
        "note": "Plumbing: skips installing a dev library already present in node_modules; install command runs either way.",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 9215,
          "end_byte": 9260,
          "node_type": "call_expression",
          "sha256": "3cfc6908f978cd45",
          "line": 368
        }
      },
      {
        "candidate": "k_61b42fa257",
        "reason_code": "other",
        "note": "Plumbing: creates the host project's modules folder if it is missing.",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 9433,
          "end_byte": 9463,
          "node_type": "call_expression",
          "sha256": "10867c39fd2e8cb7",
          "line": 375
        }
      },
      {
        "candidate": "q_82839eef7e",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_af98d19d96 (config.json read).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 1599,
          "end_byte": 1726,
          "node_type": "if_statement",
          "sha256": "2359921365244b9c",
          "line": 54
        }
      },
      {
        "candidate": "q_d28601a4e2",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_d0050db34a (app.json read).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 2475,
          "end_byte": 2601,
          "node_type": "if_statement",
          "sha256": "73b708bc0c232bf6",
          "line": 88
        }
      },
      {
        "candidate": "q_4404d2d07a",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_9bedd86efc (config.live.json create).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 2252,
          "end_byte": 2451,
          "node_type": "if_statement",
          "sha256": "3f07493ac3ef2ddc",
          "line": 80
        }
      },
      {
        "candidate": "q_8fcdab1c47",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_5df869dddc (skip already installed library).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 8880,
          "end_byte": 9167,
          "node_type": "if_statement",
          "sha256": "a5afa5d666da34cd",
          "line": 357
        }
      },
      {
        "candidate": "q_d064eb7d36",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_8782dc6b72 (skip already installed dev library).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 9211,
          "end_byte": 9418,
          "node_type": "if_statement",
          "sha256": "df2d097e8f23a8a1",
          "line": 368
        }
      },
      {
        "candidate": "q_718ee59a2b",
        "reason_code": "other",
        "note": "Plumbing guard of dropped plumbing check k_61b42fa257 (mkdir modules).",
        "anchor": {
          "file": "bin/build.js",
          "derived_from": null,
          "start_byte": 9428,
          "end_byte": 9498,
          "node_type": "if_statement",
          "sha256": "d12db21f35720998",
          "line": 375
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 11,
    "condition_sites_cited": 5,
    "guards_cited": 5,
    "candidates_dropped": 12,
    "conditions_in_set": 5,
    "conditions_out_of_set": 0,
    "guard_candidates": 11,
    "gates_in_set": 5,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
