# pypi cffi@2.1.1

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-08-03 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is the upstream cffi 2.1.1 sdist. pip builds it through setuptools.build_meta, which runs setup.py; there is no cmdclass. setup.py first raises unless the interpreter is a standard GIL build or 3.14+ (g1), then picks how to find libffi (g2): MSVC on Windows builds against the bundled libffi sources, every other setup runs pkg-config (plus `brew --prefix libffi` on macOS with Homebrew) and compiler feature probes. Both sides end in the same `_cffi_backend` extension build. No network, credential or persistence behaviour.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, native_build; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c3 \|\| c1 (c3: runtime_version falsy; c1: runtime_version >= [3, 14]) | then | 1 | benign_build | runtime_version=3.14 |
| g2 | setup_py | (c3 \|\| c1) && c2 && c4 (c3: runtime_version falsy; c1: runtime_version >= [3, 14]; c2: os == win32; c4: installed_tool exists) | then | 3 | benign_build | runtime_version=3.14; os=win32; installed_tool=msvc |
| | |  | else | 3 | benign_build | runtime_version=3.14; os=linux |

Gate intent: g1 activate/enables/portability; g2 activate/selects/portability

Grounding: 2 of 4 conditions and 2 of 2 gates from the candidate set; out of set, pending verification: c3, c4.

## Requirements

- installed_tool: cc (C compiler needed to build the _cffi_backend extension (MSVC on Windows))
- installed_tool: pkg-config (used on non-MSVC builds to locate libffi; missing tool is swallowed and default include paths are used)
- other: libffi development headers and library (e.g. libffi-dev) on non-Windows (extension links against libffi; Windows uses the bundled copy)

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- c3 (Py_GIL_DISABLED falsy) and c4 (MSVC compile probe through `uses_msvc()`) are out of set: the extractor folded the free-threaded check into the version test and did not see the compiler probe as a condition.
- g2's else side requires g1 to hold; it is recorded as `requires: ["c1"]` with runtime 3.14, though any standard GIL build also passes g1.
- The remaining platform, env var and Homebrew checks only adjust include paths, link flags or compiler macros and were dropped as plumbing.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "cffi",
    "version": "2.1.1",
    "archive_sha256": "dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-08-03",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/cffi-2.1.1.tar.gz",
    "package_root": "layer0/cffi-2.1.1",
    "cluster_key": "423d648287261aa335c7b67e3fc8025c5821276ce02bd61fea10ae464b9a2aca",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "native_build"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in setup.py; candidates there may be missing",
      "setup.py: read in full (206 lines, only install-reached file; backend is setuptools.build_meta, no cmdclass). setup_base.py is not imported by setup.py. Nothing unread.",
      "silent_failure: _ask_pkg_config swallows OSError ENOENT/EACCES when pkg-config is missing, and a failed compiler probe only prints a warning and continues.",
      "Plumbing, not gates: ARM64 vs x86_64 bundled libffi pick on Windows, darwin+brew PKG_CONFIG_PATH refresh, PKG_CONFIG_SYSROOT_DIR prefixing, freebsd include dirs, macosx SDK flag (line 157), CFFI_FORCE_STATIC extra objects.",
      "Also plumbing: sys.platform checks at lines 82 and 95 only skip compiler feature probes (__thread, __sync_synchronize) on Windows non-MSVC builds; macros change, the build still runs.",
      "Line 183: on PyPy ('_cffi_backend' in builtin modules) setup() gets empty packages and ext_modules. Same setup() call with different arguments, noted rather than recorded as a gate.",
      "g1 is an early raise unless the interpreter is a standard GIL build (c3) or 3.14+ (c1). Nested gate g2 inherits c3 || c1; its recipes use runtime 3.14, which passes g1 on any build.",
      "Endpoints in setup.py are help URLs inside a printed warning message; nothing is contacted."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "C compiler needed to build the _cffi_backend extension (MSVC on Windows)"
    },
    {
      "axis": "installed_tool",
      "value": "pkg-config",
      "reason": "used on non-MSVC builds to locate libffi; missing tool is swallowed and default include paths are used"
    },
    {
      "axis": "other",
      "value": "libffi development headers and library (e.g. libffi-dev) on non-Windows",
      "reason": "extension links against libffi; Windows uses the bundled copy"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "runtime_version",
      "api": "sys.version_info",
      "operator": ">=",
      "value": [
        3,
        14
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f8a896d52a",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 646,
            "end_byte": 672,
            "node_type": "comparison_operator",
            "sha256": "8fd812ffca194176",
            "line": 21
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "os",
      "api": "sys.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_09daf98aa6",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5148,
            "end_byte": 5171,
            "node_type": "comparison_operator",
            "sha256": "81d76343f3bfcc14",
            "line": 132
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "runtime_version",
      "api": "sysconfig.get_config_var",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 573,
            "end_byte": 616,
            "node_type": "call",
            "sha256": "6e579d0df82802c9",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "installed_tool",
      "api": "config.try_compile",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "config.try_compile",
        "target": "C compiler on test source that errors unless _MSC_VER is defined",
        "accessor": "other"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 4207,
            "end_byte": 4272,
            "node_type": "call",
            "sha256": "6371aef8f98967ba",
            "line": 111
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c3 || c1",
      "guards": [
        {
          "candidate": "q_73b3f27147",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 619,
            "end_byte": 895,
            "node_type": "if_statement",
            "sha256": "86ae1c94bea1bad3",
            "line": 21
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c3"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "build refuses free-threaded CPython older than 3.14, which CFFI does not support",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "runtime_version": "3.14"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 897,
            "end_byte": 8198,
            "node_type": "stmt_range",
            "sha256": "d317cb7a1f60968a",
            "line": 26
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 7451,
              "end_byte": 8198,
              "node_type": "call",
              "sha256": "8b1e1dd2f8196c87",
              "line": 185
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "(c3 || c1) && c2 && c4",
      "guards": [
        {
          "candidate": "q_73b3f27147",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 619,
            "end_byte": 895,
            "node_type": "if_statement",
            "sha256": "86ae1c94bea1bad3",
            "line": 21
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c3"
          ]
        },
        {
          "candidate": "q_c3f53b2ac2",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5145,
            "end_byte": 6346,
            "node_type": "if_statement",
            "sha256": "170e0347cfccb39c",
            "line": 132
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2",
            "c4"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "MSVC on Windows builds against bundled libffi; everything else runs pkg-config, brew and compiler probes",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "runtime_version": "3.14",
          "os": "win32",
          "installed_tool": [
            "msvc"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5193,
            "end_byte": 6257,
            "node_type": "block",
            "sha256": "283567937b2a5cfc",
            "line": 133
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 5649,
              "end_byte": 5675,
              "node_type": "call",
              "sha256": "a83ddb26aac645fc",
              "line": 141
            },
            "witness": []
          }
        ]
      },
      "else": {
        "min_conditions": 3,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "runtime_version": "3.14",
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "requires": [
          "c1",
          "c3"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 6268,
            "end_byte": 6346,
            "node_type": "block",
            "sha256": "93fee571f3283205",
            "line": 153
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1051,
              "end_byte": 1152,
              "node_type": "call",
              "sha256": "314812a005674af4",
              "line": 29
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 6268,
                  "end_byte": 6284,
                  "node_type": "call",
                  "sha256": "f28c286bf7065e79",
                  "line": 153
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 4274,
                  "end_byte": 4748,
                  "node_type": "function_definition",
                  "sha256": "f5cab86cc3e40f37",
                  "line": 113
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 4410,
                  "end_byte": 4484,
                  "node_type": "call",
                  "sha256": "f092c718c926dadc",
                  "line": 117
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 897,
                  "end_byte": 2045,
                  "node_type": "function_definition",
                  "sha256": "947cad6f2ef6dfc5",
                  "line": 26
                }
              }
            ]
          }
        ]
      }
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "benign_build"
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
  "assessment_reason": "setup.py is the upstream cffi build script: it locates libffi (bundled on MSVC, pkg-config or Homebrew elsewhere), probes compiler features and compiles the _cffi_backend extension. No network access, credential reads or code beyond the native build.",
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
      "sha256": "00b831fa643275cd"
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
        "candidate": "k_2ca02ae20e",
        "reason_code": "other",
        "note": "plumbing: ARM64 check only picks which bundled libffi to build against on Windows; both sides compile the same extension",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 5196,
          "end_byte": 5225,
          "node_type": "comparison_operator",
          "sha256": "47271ab69ee5830a",
          "line": 133
        }
      },
      {
        "candidate": "q_cebb00cafe",
        "reason_code": "other",
        "note": "plumbing: guard of the ARM64 vs x86_64 bundled libffi pick; both sides compile the same extension",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 5193,
          "end_byte": 6257,
          "node_type": "if_statement",
          "sha256": "283567937b2a5cfc",
          "line": 133
        }
      },
      {
        "candidate": "q_98517bab29",
        "reason_code": "duplicate_of",
        "note": "else side of q_c3f53b2ac2, recorded as g2's else branch",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 5145,
          "end_byte": 6346,
          "node_type": "if_statement",
          "sha256": "170e0347cfccb39c",
          "line": 132
        }
      },
      {
        "candidate": "k_12296761eb",
        "reason_code": "other",
        "note": "plumbing: line 95 only skips the __sync_synchronize compiler probe on Windows non-MSVC builds; build still runs",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3658,
          "end_byte": 3681,
          "node_type": "comparison_operator",
          "sha256": "74866fc41f5ccf30",
          "line": 95
        }
      },
      {
        "candidate": "q_0192d69bfb",
        "reason_code": "other",
        "note": "plumbing: early return that skips one compiler feature probe; build continues either way",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3655,
          "end_byte": 3718,
          "node_type": "if_statement",
          "sha256": "b6b12fe8fea2c249",
          "line": 95
        }
      },
      {
        "candidate": "k_ebbf1e28d8",
        "reason_code": "other",
        "note": "plumbing: darwin check before refreshing PKG_CONFIG_PATH from brew --prefix libffi; locating a library, same build",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4303,
          "end_byte": 4327,
          "node_type": "comparison_operator",
          "sha256": "ae82dde18920392d",
          "line": 114
        }
      },
      {
        "candidate": "k_fc00e71976",
        "reason_code": "other",
        "note": "plumbing: brew lookup that only refreshes PKG_CONFIG_PATH when Homebrew exists",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4332,
          "end_byte": 4369,
          "node_type": "call",
          "sha256": "987cdf35bea66cc5",
          "line": 114
        }
      },
      {
        "candidate": "q_04d77445f6",
        "reason_code": "other",
        "note": "plumbing: guard of the Homebrew PKG_CONFIG_PATH refresh; same build either way",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4300,
          "end_byte": 4404,
          "node_type": "if_statement",
          "sha256": "e43559a8d7bd3443",
          "line": 114
        }
      },
      {
        "candidate": "k_06dbf40e32",
        "reason_code": "other",
        "note": "plumbing: PKG_CONFIG_SYSROOT_DIR only prefixes include and library paths for cross builds",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1654,
          "end_byte": 1698,
          "node_type": "call",
          "sha256": "f907eaf9b06f44c2",
          "line": 45
        }
      },
      {
        "candidate": "q_8c105d1eeb",
        "reason_code": "other",
        "note": "plumbing: guard of the sysroot path prefixing; same build either way",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1711,
          "end_byte": 1999,
          "node_type": "if_statement",
          "sha256": "832b6249bc50128a",
          "line": 46
        }
      },
      {
        "candidate": "k_08532a1afc",
        "reason_code": "other",
        "note": "plumbing: freebsd check only appends /usr/local include and lib dirs",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 6541,
          "end_byte": 6566,
          "node_type": "comparison_operator",
          "sha256": "ef80c4d65305a494",
          "line": 161
        }
      },
      {
        "candidate": "q_43e3d93e00",
        "reason_code": "other",
        "note": "plumbing: guard of the freebsd include dir append; same build either way",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 6538,
          "end_byte": 6655,
          "node_type": "if_statement",
          "sha256": "1d3807fdc4c4b4f1",
          "line": 161
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 9,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 12,
    "conditions_in_set": 2,
    "conditions_out_of_set": 2,
    "guard_candidates": 8,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [
      "c3",
      "c4"
    ],
    "anchor_refusals": 0
  }
}
```
