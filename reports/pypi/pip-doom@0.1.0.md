# pypi pip-doom@0.1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2026-04-03 (registry) · **Assessment:** suspicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py overrides the setuptools `install` command (`DoomInstall`), whose `run` imports `doom/game.py` and calls `run_game()` before the normal install, so it runs on any pip install of the sdist. `run_game()` chmods and launches a prebuilt binary shipped in `doom/bin/` (a terminal DOOM port, going by its strings) with the bundled `doom1.wad`. Gate g1 (`sys.platform == win32`, portability) picks the launch path: on Windows the .exe runs as a demo and then as a game with console setup and a thread that injects polled key presses into the console input; elsewhere the native build runs via `subprocess.call`. Gates g2 (win32 and `'64'` in `platform.machine()`) and g3 (`sys.platform == darwin`), both portability, pick which of the four separately unread executables is launched.

## Execution

- **cmdclass** `cmdclass[install] = DoomInstall`: 2-file chain; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == win32) | then | 1 | spawn_process | os=win32 |
| | |  | else | 1 | spawn_process | os=linux |
| g2 | cmdclass | c1 && c2 (c1: os == win32; c2: arch includes 64) | then | 2 | spawn_process | os=win32; arch=amd64 |
| | |  | else | 2 | spawn_process | os=win32; arch=x86 |
| g3 | cmdclass | c3 (c3: os == darwin) | then | 1 | spawn_process | os=darwin |
| | |  | else | 1 | spawn_process | os=linux |

Gate intent: g1 activate/selects/portability; g2 activate/selects/portability; g3 activate/selects/portability

Grounding: 3 of 3 conditions and 3 of 3 gates from the candidate set.

## Requirements

- other: interactive console (CONIN$/CONOUT$) on Windows (the Windows branch opens CONIN$ and CONOUT$ and fails without an attached console)

## Behaviour

- Ungated: none
- Gated: spawn_process

## Notes

- The four binaries in `doom/bin/` are run at install but their logic is unread. The Linux build's strings were listed (doom-ascii 0.3.1, no network strings) and the other three were searched as data for network, injection and process API names: none in the Windows builds, a `_system` symbol in the mac build with its caller unread. They stay unrecovered.
- g2 and g3 pick the file only; the launch reads it through the variable `binary`, so their payload paths are data links marked unresolved, each with a bind hop on the assignment to `binary`. The g2 arch values in the recipes are guessed: the code only tests for `'64'`.
- No network endpoints, downloads, credential reads or persistence in the Python code. The install blocks until the game exits, which is the main harm visible statically.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pip-doom",
    "version": "0.1.0",
    "archive_sha256": "a6f80674d75dfcbff92cb330845211a0e4c292dfe8325bcbd415b94a5033986d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-04-03",
    "released_at_source": "registry",
    "sample_path": "datadog/pypi/malicious_intent/2026-04-03-pip-doom-v0.1.0.zip",
    "package_root": "layer0/tmp/tmpr2y80j43/sources/pip-doom",
    "cluster_key": "d0ca9d46545397fb66c6acb83b3b9a38ad5720a4b54bd76b5cb6d91b0ce21337",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = DoomInstall",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "doom/game.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      },
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [
      {
        "site": "doom/game.py:113",
        "seconds": 0.033
      },
      {
        "site": "doom/game.py:95",
        "seconds": 0.01
      }
    ],
    "notes": [
      "setup.py top level only calls setup(); DoomInstall.run imports doom.game and calls run_game() before super().run(), so the game runs inside the install step of the sdist build.",
      "run_game() chmods and runs a prebuilt binary shipped in the sdist (doom/bin/doom-ascii, doom-ascii_mac, doom-ascii_win64.exe or doom-ascii_win32.exe) with the bundled doom1.wad. The binaries are not written by the install, so launch_style stays direct_script.",
      "doom/bin/*: compiled binaries, logic unread. Strings of doom/bin/doom-ascii listed as data match the doom-ascii 0.3.1 game (Chocolate Doom based); no network strings seen. They stay in obfuscation.unrecovered.",
      "Binary selection at game.py:12-18 decides which of four separate executables the install runs, and their logic is unread, so 'the same game' is not established. Kept as gates: g2 (win32, '64' in platform.machine()) and g3 (darwin). The win32 decision itself stays in g1.",
      "g2 and g3 only choose the file. The launches at game.py:102, :128 and :141 read it through the variable binary, a data link, so those payloads stay unresolved (computed_callee). Each has a bind hop on the assignment to binary; g2's region is a string arm inside the line-14 assignment.",
      "binary is assigned once per path (game.py:14, :16, :18) and never reassigned before the launches. Control falls from each assignment through game.py:20 to the line-22 test, which repeats the line-12 test, so the value the gate picks is what the sink runs.",
      "Text search of the win64, win32 and mac binaries as data: game strings match the Linux build (doom-ascii, Chocolate Doom URLs); no Windows network or injection API names. The mac build has a _system symbol, caller not read. A search is not a read: the logic stays unread.",
      "g3.else recipe os linux is one reachable value: any platform that is neither win32 nor darwin reaches game.py:18. The g2 arch values are guessed: the code only tests for '64' in the lowercased platform.machine().",
      "g1.else regions: the non-Windows binary choices (game.py:16, :18) on the line-12 guard's else side and the line-141 call on the line-22 guard's else side. os linux is not guessed: any non-win32, non-darwin platform reaches :18 and :141.",
      "Windows branch opens CONIN$/CONOUT$, sets console mode, runs the game once as a demo until any key is pressed, then runs it again with a daemon thread that polls GetAsyncKeyState for game keys and writes them into the console input buffer.",
      "os.chmod(binary, 0o755) at game.py:20 runs ungated on the package's own bundled file; not recorded as a behaviour."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "interactive console (CONIN$/CONOUT$) on Windows",
      "reason": "the Windows branch opens CONIN$ and CONOUT$ and fails without an attached console"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "sys.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f672c86dcf",
          "anchor": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 273,
            "end_byte": 296,
            "node_type": "comparison_operator",
            "sha256": "74866fc41f5ccf30",
            "line": 12
          }
        },
        {
          "candidate": "k_87c7ea3717",
          "anchor": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 645,
            "end_byte": 668,
            "node_type": "comparison_operator",
            "sha256": "74866fc41f5ccf30",
            "line": 22
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "arch",
      "api": "platform.machine()",
      "operator": "includes",
      "value": "64",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b56109009d",
          "anchor": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 408,
            "end_byte": 423,
            "node_type": "comparison_operator",
            "sha256": "6e0596b84d8b9e4a",
            "line": 14
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "os",
      "api": "sys.platform",
      "operator": "==",
      "value": "darwin",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_83e2e1dbc9",
          "anchor": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 462,
            "end_byte": 486,
            "node_type": "comparison_operator",
            "sha256": "ae82dde18920392d",
            "line": 15
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "cmdclass",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_a0f066b546",
          "site": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 270,
            "end_byte": 607,
            "node_type": "if_statement",
            "sha256": "2ec11cda17f39a9f",
            "line": 12
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_8ebe12a674",
          "site": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 642,
            "end_byte": 5547,
            "node_type": "if_statement",
            "sha256": "d66aa7085ed6cf22",
            "line": 22
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
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "Windows gets the .exe build launched with console handling and key injection; other OSes run the native build with a plain subprocess.call.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 306,
            "end_byte": 452,
            "node_type": "block",
            "sha256": "d25b3869f3198adf",
            "line": 13
          },
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 678,
            "end_byte": 5472,
            "node_type": "block",
            "sha256": "09e741bcfdd44df2",
            "line": 23
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 4248,
              "end_byte": 4381,
              "node_type": "call",
              "sha256": "dd1d936ff8d40942",
              "line": 102
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5148,
              "end_byte": 5343,
              "node_type": "call",
              "sha256": "55fc498b41b19cde",
              "line": 128
            },
            "witness": []
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 496,
            "end_byte": 544,
            "node_type": "block",
            "sha256": "8a07f807b4a9bd29",
            "line": 16
          },
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 563,
            "end_byte": 607,
            "node_type": "block",
            "sha256": "ae7999c3cd8d9470",
            "line": 18
          },
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 5492,
            "end_byte": 5547,
            "node_type": "block",
            "sha256": "9941b18ed4594a38",
            "line": 141
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5492,
              "end_byte": 5547,
              "node_type": "call",
              "sha256": "9941b18ed4594a38",
              "line": 141
            },
            "witness": []
          }
        ]
      }
    },
    {
      "gate_id": "g2",
      "hook": "cmdclass",
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": "q_a0f066b546",
          "site": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 270,
            "end_byte": 607,
            "node_type": "if_statement",
            "sha256": "2ec11cda17f39a9f",
            "line": 12
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_9ab299314a",
          "site": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 382,
            "end_byte": 451,
            "node_type": "conditional_expression",
            "sha256": "970089f7477409e0",
            "line": 14
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "On Windows the '64' test picks which of two separate executables the install launches, doom-ascii_win64.exe or doom-ascii_win32.exe.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32",
          "arch": "amd64"
        },
        "recipe_guessed_fields": [
          "arch"
        ],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 382,
            "end_byte": 404,
            "node_type": "string",
            "sha256": "4acb7e46d2101992",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 4248,
              "end_byte": 4381,
              "node_type": "call",
              "sha256": "dd1d936ff8d40942",
              "line": 102
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 351,
                  "end_byte": 452,
                  "node_type": "assignment",
                  "sha256": "d3c4857741f9864c",
                  "line": 14
                }
              }
            ],
            "unresolved": "computed_callee"
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5148,
              "end_byte": 5343,
              "node_type": "call",
              "sha256": "55fc498b41b19cde",
              "line": 128
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 351,
                  "end_byte": 452,
                  "node_type": "assignment",
                  "sha256": "d3c4857741f9864c",
                  "line": 14
                }
              }
            ],
            "unresolved": "computed_callee"
          }
        ]
      },
      "else": {
        "min_conditions": 2,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32",
          "arch": "x86"
        },
        "recipe_guessed_fields": [
          "arch"
        ],
        "requires": [
          "c1"
        ],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 429,
            "end_byte": 451,
            "node_type": "string",
            "sha256": "2715da7b35c494ea",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 4248,
              "end_byte": 4381,
              "node_type": "call",
              "sha256": "dd1d936ff8d40942",
              "line": 102
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 351,
                  "end_byte": 452,
                  "node_type": "assignment",
                  "sha256": "d3c4857741f9864c",
                  "line": 14
                }
              }
            ],
            "unresolved": "computed_callee"
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5148,
              "end_byte": 5343,
              "node_type": "call",
              "sha256": "55fc498b41b19cde",
              "line": 128
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 351,
                  "end_byte": 452,
                  "node_type": "assignment",
                  "sha256": "d3c4857741f9864c",
                  "line": 14
                }
              }
            ],
            "unresolved": "computed_callee"
          }
        ]
      }
    },
    {
      "gate_id": "g3",
      "hook": "cmdclass",
      "expression": "c3",
      "guards": [
        {
          "candidate": "q_a6103d6cf9",
          "site": {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 457,
            "end_byte": 544,
            "node_type": "elif_clause",
            "sha256": "2f84719e9bc6f2d7",
            "line": 15
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "Outside Windows the darwin test picks which of two separate executables the install launches, doom-ascii_mac or doom-ascii.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "darwin"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 496,
            "end_byte": 544,
            "node_type": "block",
            "sha256": "8a07f807b4a9bd29",
            "line": 16
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5492,
              "end_byte": 5547,
              "node_type": "call",
              "sha256": "9941b18ed4594a38",
              "line": 141
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 496,
                  "end_byte": 544,
                  "node_type": "assignment",
                  "sha256": "8a07f807b4a9bd29",
                  "line": 16
                }
              }
            ],
            "unresolved": "computed_callee"
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "doom/game.py",
            "derived_from": null,
            "start_byte": 563,
            "end_byte": 607,
            "node_type": "block",
            "sha256": "ae7999c3cd8d9470",
            "line": 18
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "doom/game.py",
              "derived_from": null,
              "start_byte": 5492,
              "end_byte": 5547,
              "node_type": "call",
              "sha256": "9941b18ed4594a38",
              "line": 141
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "doom/game.py",
                  "derived_from": null,
                  "start_byte": 563,
                  "end_byte": 607,
                  "node_type": "assignment",
                  "sha256": "ae7999c3cd8d9470",
                  "line": 18
                }
              }
            ],
            "unresolved": "computed_callee"
          }
        ]
      }
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": [
      {
        "file": "doom/bin/doom-ascii_mac",
        "reason": "prebuilt Mach-O binary run at install on darwin; logic not readable statically"
      },
      {
        "file": "doom/bin/doom-ascii",
        "reason": "prebuilt ELF binary run at install on linux and other non-Windows, non-macOS hosts; strings match the doom-ascii game, logic not read"
      },
      {
        "file": "doom/bin/doom-ascii_win64.exe",
        "reason": "prebuilt Windows binary run at install on 64-bit Windows; logic not readable statically"
      },
      {
        "file": "doom/bin/doom-ascii_win32.exe",
        "reason": "prebuilt Windows binary run at install on 32-bit Windows; logic not readable statically"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pip-doom install-time game",
  "claude_assessment": "suspicious",
  "assessment_reason": "The install override runs an opaque prebuilt binary (a terminal DOOM port, going by its strings) during pip install, and on Windows polls global key state and injects console input. No exfiltration, download or persistence in the Python code, but the binaries' logic is unread.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "install runs bundled prebuilt binaries whose logic was not read; behaviour of the binaries rests on strings only",
    "unrecovered code",
    "guessed recipe fields",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "534855a7f684f27a"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": []
  },
  "candidate_check": {
    "condition_candidates": 4,
    "condition_sites_cited": 4,
    "guards_cited": 4,
    "candidates_dropped": 0,
    "conditions_in_set": 3,
    "conditions_out_of_set": 0,
    "guard_candidates": 4,
    "gates_in_set": 3,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
