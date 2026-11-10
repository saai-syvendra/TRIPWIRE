# pypi urlliib3@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

All code runs from top-level `setup.py` when pip builds the sdist. Its strings are hidden as `chr` code lists, and its control flow is flattened into integer state loops; the registered decoder `py_chr_shift_fold` (derived d2) recovers it fully. Everything sits under `sys.platform == 'win32'` and then branches on the setup command in `sys.argv[1]`: `egg_info`/`build` runs `pip.main(['install', 'pypiwin32'])`, and `bdist_wheel`/`install` writes a clipboard-hijacking browser extension to `%APPDATA%\Extension`. It then rewrites every Desktop, Start Menu and pinned TaskBar `.lnk` whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe so it starts with `--load-extension`. With admin rights it also covers the all-users Start Menu.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in [egg_info, build]) | then | 2 | download | os=win32; package_manager=setup.py run with sys.argv[1] egg_info or build |
| g2 | setup_py | c1 && c5 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; env_var=APPDATA=(set); package_manager=setup.py run with sys.argv[1] bdist_wheel or install |
| g3 | setup_py | c1 && c5 && c6 && c7 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]; c6: target_artifact regex \.lnk$; c7: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; env_var=APPDATA=(set); package_manager=setup.py run with sys.argv[1] bdist_wheel or install; file_present=~\Desktop\*.lnk with target basename chrome.exe, msedge.exe, launcher.exe or brave.exe |
| g4 | setup_py | c1 && c5 && c2 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; privilege=root_or_admin; env_var=APPDATA=(set); package_manager=setup.py run with sys.argv[1] bdist_wheel or install |

Gate intent: g1 activate/selects/targeting; g2 activate/selects/targeting; g3 activate/modifies/targeting; g4 activate/modifies/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, g1, g2, g3, g4.

## Requirements

- other: python module win32com (pywin32) importable during the build (payload branch imports win32com.client.Dispatch unguarded and needs WScript.Shell COM to rewrite shortcuts)
- other: env var APPDATA set (extension folder and shortcut list are built from os.getenv('APPDATA'); None would raise a TypeError)
- network: pypi[.]org:443 (egg_info/build branch runs pip install pypiwin32, which needs the package index)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The `sys.argv[1]` checks (c4, c5) are out of set: the extractor did not offer them. I recorded them as `package_manager` because the install frontend decides which setup command runs. Modern pip runs `bdist_wheel` for the build, so a stock scanner reaches the payload branch only if `win32com` can be imported in the build environment. The import is unguarded, and without it the install aborts before anything is written.
- `pip.main` no longer exists in pip 10 and later, so the `egg_info`/`build` helper branch only works on very old pip.
- The shortcut gates (g3, g4) sit inside a flattened state loop. The guarded block only sets the next state, and `Save()` runs in a later state. Every state is a constant, so the path is fully traced, but a state value is not a binding, so no witness hop is cited; the later state blocks are regions and `Save()` sits in one. The state chain is written out in `execution.notes`. For g3 the `Save()` state runs only after c7 passes, because its value is assigned once, inside c7's block. For g4 the non-admin path reaches the same walk and `Save()`, so that region is not exclusive to c2; admin rights only add the all-users Start Menu to the folders walked.
- The background.js payload replaces wallet addresses for about eleven coins with hard-coded attacker addresses. The addresses are not reproduced here.
- The extension-folder `os.path.exists` check is plumbing (it creates the folder if it is missing), so it was dropped.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "urlliib3",
    "version": "0.1",
    "archive_sha256": "53e38266103fa7f765c6c180e877226f2544a04aea3ceead26a0ca8e2b1a3274",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/urlliib3-0.1.tar.gz",
    "package_root": "layer0/urlliib3-0.1",
    "cluster_key": "5f544f0db2594ae5204bfa60181010eea37b53f110bcdba27bc1eb5c50dcd462",
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
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: strings built as chr code lists of shift arithmetic, state machine flattening with folded int states; decoded with registered decoder py_chr_shift_fold (derived d2). Whole file read in full on the decoded copy; nothing unread.",
      "All top-level code sits under sys.platform == win32, then branches on sys.argv[1]: egg_info/build runs pip.main(['install','pypiwin32']); bdist_wheel/install drops a browser extension and rewrites browser shortcuts.",
      "The bdist_wheel/install side is an elif: c5 is tested only when c4 is false. The two argv sets are disjoint, so c5 true already implies c4 false; no negated condition is needed.",
      "egg_info/build state machine: state 286625773 (try import win32com, junk arithmetic loop) is never reached; the first state sets the state to 0 after pip.main. Dead code, not counted.",
      "pip.main was removed in pip 10, so the egg_info/build branch raises AttributeError on a modern pip; it only works with very old pip. Recorded as reachable install code since an old installer runs it.",
      "Payload branch imports win32com.client at state 12258 with no try. Without pywin32 importable in the build environment the install aborts before any file is written; PEP 517 build isolation likely hides a user's pywin32.",
      "Dropped folder: os.path.exists(APPDATA\\Extension) only decides whether to create the folder first; both sides go on to write background.js and manifest.json. Plumbing, candidate dropped.",
      "Shortcut hijack: os.walk over Desktop, user Start Menu, pinned TaskBar (plus all-users Start Menu when admin); each .lnk whose target basename is chrome.exe, msedge.exe, launcher.exe or brave.exe gets --load-extension=APPDATA\\Extension and is saved.",
      "Gates g3 and g4 sit inside flattened while/state loops: the guarded block only sets the next state and the Save sink runs in a later state. State values are integers, not bindings, so no hop is cited; the state blocks that run next are regions, and each sink sits in one.",
      "g3 path (decoded lines): line 92 sets the inner state to 60921, the only assignment of that value, and the elif at line 99 runs Save at line 100. So lines 100-101 run only for a shortcut that passed c6 and c7, though they sit outside c7's if textually.",
      "g4 path (decoded lines): line 65 sets 362814, the only assignment of that value, so line 45 appends the all-users Start Menu only under c2. Then 18005 and constant write states lead to 790593, the walk at line 78 and Save.",
      "g4 region caveat: the walk region (decoded line 78) and Save also run when c2 is false, since the non-admin path joins at 18005. Only the appended folder depends on c2, so the region is not exclusive to c2 (effect modifies).",
      "The dropped background.js is a clipboard hijacker: it replaces ETH, TRON, BNB, BTC, LTC, XRP, DOGE, ADA, XMR, XLM and ATOM addresses with attacker wallets every second. It runs later in the browser, covered here by write_file and persistence."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module win32com (pywin32) importable during the build",
      "reason": "payload branch imports win32com.client.Dispatch unguarded and needs WScript.Shell COM to rewrite shortcuts"
    },
    {
      "axis": "other",
      "value": "env var APPDATA set",
      "reason": "extension folder and shortcut list are built from os.getenv('APPDATA'); None would raise a TypeError"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "egg_info/build branch runs pip install pypiwin32, which needs the package index"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "sys.platform",
      "operator": "==",
      "value": "win32",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_03bdb6b578",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 63,
            "end_byte": 324,
            "node_type": "comparison_operator",
            "sha256": "1f749d1a844ac620",
            "line": 6
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "privilege",
      "api": "ctypes.windll.shell32.IsUserAnAdmin()",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_4fb68d086f",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 10656,
            "end_byte": 10693,
            "node_type": "call",
            "sha256": "fc942b5e5173ed6f",
            "line": 68
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "package_manager",
      "api": "sys.argv[1]",
      "operator": "in",
      "value": [
        "egg_info",
        "build"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 92,
            "end_byte": 128,
            "node_type": "comparison_operator",
            "sha256": "6cde078686fe8980",
            "line": 7
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "package_manager",
      "api": "sys.argv[1]",
      "operator": "in",
      "value": [
        "bdist_wheel",
        "install"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "str.endswith",
      "operator": "regex",
      "value": "\\.lnk$",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6878,
            "end_byte": 6943,
            "node_type": "call",
            "sha256": "8d116359f4d6412c",
            "line": 81
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "target_artifact",
      "api": "os.path.basename(shortcut.TargetPath)",
      "operator": "in",
      "value": [
        "chrome.exe",
        "msedge.exe",
        "launcher.exe",
        "brave.exe"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 7542,
            "end_byte": 7651,
            "node_type": "comparison_operator",
            "sha256": "7c422ae20ab5c615",
            "line": 90
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
      "expression": "c1 && c4",
      "guards": [
        {
          "candidate": "q_a5bff724bc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60,
            "end_byte": 66981,
            "node_type": "if_statement",
            "sha256": "11a9a105ac0e025e",
            "line": 6
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 92,
            "end_byte": 128,
            "node_type": "comparison_operator",
            "sha256": "6cde078686fe8980",
            "line": 7
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "Windows only; on the metadata/build step it installs pypiwin32 so the later install step can use win32com",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with sys.argv[1] egg_info or build"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 133,
            "end_byte": 1595,
            "node_type": "stmt_range",
            "sha256": "fd62fd7857aa64aa",
            "line": 8
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 335,
              "end_byte": 369,
              "node_type": "call",
              "sha256": "948b17ff4b80f1be",
              "line": 13
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
      "expression": "c1 && c5",
      "guards": [
        {
          "candidate": "q_a5bff724bc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60,
            "end_byte": 66981,
            "node_type": "if_statement",
            "sha256": "11a9a105ac0e025e",
            "line": 6
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "payload exists only for Windows and only on the bdist_wheel/install step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "env_var": {
            "APPDATA": null
          },
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1647,
            "end_byte": 10044,
            "node_type": "stmt_range",
            "sha256": "eb2d288176163f01",
            "line": 35
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 3819,
              "end_byte": 5880,
              "node_type": "call",
              "sha256": "45a3175521bf1aa3",
              "line": 69
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 9772,
              "end_byte": 9982,
              "node_type": "call",
              "sha256": "4c6a9e310e779ce2",
              "line": 125
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 2930,
              "end_byte": 3007,
              "node_type": "call",
              "sha256": "e9132f12380d1978",
              "line": 55
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c5 && c6 && c7",
      "guards": [
        {
          "candidate": "q_a5bff724bc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60,
            "end_byte": 66981,
            "node_type": "if_statement",
            "sha256": "11a9a105ac0e025e",
            "line": 6
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6878,
            "end_byte": 6943,
            "node_type": "call",
            "sha256": "8d116359f4d6412c",
            "line": 81
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 7542,
            "end_byte": 7651,
            "node_type": "comparison_operator",
            "sha256": "7c422ae20ab5c615",
            "line": 90
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "the .lnk and target-basename tests pick which shortcuts get rewritten: only those pointing at Chrome, Edge, Brave or Opera's launcher load the dropped extension",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "env_var": {
            "APPDATA": null
          },
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install",
          "file_present": [
            "~\\Desktop\\*.lnk with target basename chrome.exe, msedge.exe, launcher.exe or brave.exe"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 57837,
            "end_byte": 59891,
            "node_type": "stmt_range",
            "sha256": "7aac4f756c029f35",
            "line": 95
          },
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 7664,
            "end_byte": 7999,
            "node_type": "stmt_range",
            "sha256": "3b96bbe6f6d6372c",
            "line": 91
          },
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 8435,
            "end_byte": 8553,
            "node_type": "stmt_range",
            "sha256": "e2eba9988992058b",
            "line": 100
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 8435,
              "end_byte": 8490,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 100
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "setup_py",
      "expression": "c1 && c5 && c2",
      "guards": [
        {
          "candidate": "q_a5bff724bc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60,
            "end_byte": 66981,
            "node_type": "if_statement",
            "sha256": "11a9a105ac0e025e",
            "line": 6
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": "q_6301778a53",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 10653,
            "end_byte": 10829,
            "node_type": "if_statement",
            "sha256": "edea0116f0c2b970",
            "line": 68
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "with admin rights the all-users Start Menu is added to the folders whose browser shortcuts get rewritten",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "privilege": "root_or_admin",
          "env_var": {
            "APPDATA": null
          },
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 10700,
            "end_byte": 10829,
            "node_type": "block",
            "sha256": "7e271c3bc6071596",
            "line": 69
          },
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 2228,
            "end_byte": 2395,
            "node_type": "stmt_range",
            "sha256": "a2d4643aa70e2799",
            "line": 45
          },
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6430,
            "end_byte": 8553,
            "node_type": "for_statement",
            "sha256": "f397d492cf3d7e08",
            "line": 78
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 8435,
              "end_byte": 8490,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 100
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "download",
      "write_file",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "very long lines",
      "strings built from chr code lists of shift arithmetic, chr fetched via getattr(__builtins__) from builtin reprs",
      "control-flow flattening (while loop over integer states set by junk arithmetic)",
      "dead state with junk arithmetic loop",
      "confusable CJK identifiers"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "clipboard-hijack browser extension dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the install step writes a Chrome extension that swaps crypto wallet addresses in the clipboard for attacker addresses and rewrites browser shortcuts to load it on every launch. The package name typosquats urllib3.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "decoder": "py_chr_shift_fold",
          "lang": "py"
        },
        "output_sha256": "5c88ca82d9782d64"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "a5ce8c22016b00c0"
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
        "candidate": "k_648bbff21c",
        "reason_code": "other",
        "note": "plumbing: os.path.exists(APPDATA\\Extension) only decides whether to create the drop folder; both sides write the extension files",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 61548,
          "end_byte": 61951,
          "node_type": "call",
          "sha256": "08d3445425ba8ddd",
          "line": 120
        }
      },
      {
        "candidate": "q_a9279e344a",
        "reason_code": "other",
        "note": "plumbing guard for the drop folder creation; both sides write background.js and manifest.json",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 61541,
          "end_byte": 62087,
          "node_type": "if_statement",
          "sha256": "a0686cab92db5d1a",
          "line": 120
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 2,
    "conditions_in_set": 2,
    "conditions_out_of_set": 4,
    "guard_candidates": 3,
    "gates_in_set": 0,
    "gates_out_of_set": 4,
    "out_of_set_ids": [
      "c4",
      "c5",
      "c6",
      "c7",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
