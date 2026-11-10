# pypi websckets@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

`websckets` (a typosquat of `websockets`) runs its payload from top-level code in `setup.py`, which pip executes when it builds the sdist. Everything sits behind `sys.platform == 'win32'`, and then `sys.argv[1]` splits the work between pip's build steps. During `egg_info`/`build` the script runs `pip.main(['install', 'pypiwin32'])`. During `bdist_wheel`/`install` it writes a Manifest V2 browser extension into `%APPDATA%\Extension`. The extension's background script replaces crypto wallet addresses in the clipboard with attacker addresses. The script then rewrites every Start Menu, taskbar or Desktop `.lnk` that points at Chrome, Edge, Brave or `launcher.exe` so the browser starts with `--load-extension`. With admin rights it also searches the all-users Start Menu. To open every gate, the scanner needs Windows, a normal pip install of the sdist (both build steps), pywin32 available and at least one browser shortcut.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv[1] in [egg_info, build]) | then | 2 | download | os=win32; package_manager=pip |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=pip |
| g3 | setup_py | c1 && c4 && c2 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=pip; privilege=root_or_admin |
| g4 | setup_py | c1 && c4 && c5 && c6 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c5: target_artifact regex \.lnk$; c6: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=pip; file_present=%USERPROFILE%\Desktop\*.lnk (target chrome.exe) |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/modifies/targeting; g4 activate/modifies/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c3, c4, c5, c6, g1, g2, g3, g4.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (egg_info/build step installs pypiwin32 with pip.main from the default index)
- other: pywin32 (win32com.client) importable by the build interpreter (bdist_wheel/install step imports win32com.client.Dispatch unguarded before writing anything)
- other: APPDATA environment variable set (drop folder and shortcut search paths are built from os.getenv('APPDATA'))

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The tool did not recover `setup.py`: strings are built from `chr()` arithmetic and the control flow is flattened into state machines. I decoded it with the registered decoder `py_chr_shift_fold` (derivation d1) and read it in full there. Most anchors point into d1.
- Because of the flattening, the then-sides of the admin check and the browser-target check set a state value, and that state's code runs in another handler. The regions and sinks for g3 and g4 are cited where that code actually runs, so a reviewer should check those regions.
- I recorded `sys.argv[1]` as `package_manager`, because the build frontend chooses the setup.py command. Under pip, `egg_info` normally runs before `bdist_wheel`, so one ordinary install reaches both branches.
- I dropped the `os.path.exists(%APPDATA%\Extension)` check as plumbing: it only decides whether the folder gets created first.
- The attacker wallet addresses are visible in the extension body in d1. I did not copy them into this record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "websckets",
    "version": "0.1",
    "archive_sha256": "db1db47f000f9242e74ebf742da007caa20e9327b288bb05ae0d4c2b8f31f4e6",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/websckets-0.1.tar.gz",
    "package_root": "layer0/websckets-0.1",
    "cluster_key": "a179746e47a764540a740181aaf4b129c5b87c52cfeaf07bb31694ed7d583f28",
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
      "setup.py: not recovered by prepare.py (chr-from-arithmetic strings, flattened state machines). Decoded with the registered decoder py_chr_shift_fold (derivation d1); package code read in full in d1; nothing unread. websckets/__init__.py is empty.",
      "Control flow is flattened into while loops over integer states. All states were followed by hand in d1; the admin, makedirs and browser checks set the next state, so their then-side code sits in other state handlers, not in the if block itself.",
      "The egg_info/build loop's state 286625773 (try import win32com, junk arithmetic) is dead: the first state sets the state to 0 after pip.main, so the loop ends. The try/except there never runs.",
      "sys.argv[1] picks the install step: egg_info/build runs pip.main(['install','pypiwin32']); bdist_wheel/install writes the extension and patches shortcuts. A normal pip install of the sdist runs both steps, metadata first.",
      "Dropped k_648bbff21c: os.path.exists on %APPDATA%\\Extension only decides whether to create the drop folder first; both sides go on to write background.js and manifest.json (plumbing).",
      "Behaviour: writes a Manifest V2 extension (clipboardRead/Write) into %APPDATA%\\Extension whose background.js swaps crypto wallet addresses in the clipboard every second for attacker addresses (BTC, ETH, TRX, BNB, LTC, XRP, DOGE, ADA, XMR, XLM, ATOM).",
      "It then walks the Start Menu, taskbar pins and Desktop (plus the all-users Start Menu when admin) for .lnk files whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe, and adds --load-extension=<APPDATA>\\Extension to their arguments.",
      "c3/c4 (sys.argv[1]) are recorded as package_manager: the build frontend picks the setup.py command. pip.main is only a dependency install of pypiwin32 from the default index; the bdist_wheel branch needs win32com importable or it raises ImportError.",
      "g3: with admin rights state 362814 appends the all-users Start Menu to the folder list. The Save() sink is in state 790593, reached by 362814, 18005, (29059,) 37668, 382664, 12768, 162346, 4030, 145239, 186387, 790593, so that handler is g3's second region.",
      "g3: state 790593 also runs without admin rights, on the shorter folder list. c2 decides only whether the all-users Start Menu shortcuts are among those patched."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "egg_info/build step installs pypiwin32 with pip.main from the default index"
    },
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable by the build interpreter",
      "reason": "bdist_wheel/install step imports win32com.client.Dispatch unguarded before writing anything"
    },
    {
      "axis": "other",
      "value": "APPDATA environment variable set",
      "reason": "drop folder and shortcut search paths are built from os.getenv('APPDATA')"
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
      "id": "c3",
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
            "derived_from": "d1",
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
      "id": "c4",
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
            "derived_from": "d1",
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
      "id": "c5",
      "category": "target_artifact",
      "api": "str.endswith (file names from os.walk)",
      "operator": "regex",
      "value": "\\.lnk$",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
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
      "id": "c6",
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
            "derived_from": "d1",
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
      "expression": "c1 && c3",
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
            "derived_from": "d1",
            "start_byte": 89,
            "end_byte": 10044,
            "node_type": "if_statement",
            "sha256": "1a8d99e188f0f353",
            "line": 7
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the pypiwin32 install is the first stage of a Windows-only payload and has no counterpart on any other OS: it runs only on win32, in the metadata/build step, so the later bdist_wheel/install step can import win32com",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip"
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
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
              "derived_from": "d1",
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
            "derived_from": "d1",
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the extension drop and shortcut patching exist only for Windows and run only in the wheel build or install step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip"
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
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
              "derived_from": "d1",
              "start_byte": 3819,
              "end_byte": 5880,
              "node_type": "call",
              "sha256": "45a3175521bf1aa3",
              "line": 69
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
      "expression": "c1 && c4 && c2",
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
            "derived_from": "d1",
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c4"
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
      "purpose_reason": "with admin rights the all-users Start Menu is added to the folders whose browser shortcuts get patched",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip",
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 2159,
            "end_byte": 2395,
            "node_type": "elif_clause",
            "sha256": "7d2d8e1f0fd9391c",
            "line": 44
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 6430,
            "end_byte": 8615,
            "node_type": "stmt_range",
            "sha256": "056c49e46abd11b8",
            "line": 78
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
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
      "expression": "c1 && c4 && c5 && c6",
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
            "derived_from": "d1",
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 6875,
            "end_byte": 8553,
            "node_type": "if_statement",
            "sha256": "03f4280a43d774bf",
            "line": 81
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 7539,
            "end_byte": 7999,
            "node_type": "if_statement",
            "sha256": "e800ec7e59b56a28",
            "line": 90
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "the .lnk and browser-name tests pick which victim shortcuts (Chrome, Edge, Brave, launcher.exe) get the --load-extension argument",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip",
          "file_present": [
            "%USERPROFILE%\\Desktop\\*.lnk (target chrome.exe)"
          ]
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 6953,
            "end_byte": 8553,
            "node_type": "stmt_range",
            "sha256": "03f10995d4ad1a67",
            "line": 82
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
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
      "strings built as chr() of shift/add arithmetic, chr resolved via getattr(__builtins__) on builtin reprs",
      "control-flow flattening (while loops over integer states with junk arithmetic transitions)",
      "dead state branches with junk arithmetic",
      "CJK confusable identifiers",
      "very long lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "lnk-sideloaded clipboard-hijacker extension",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, setup.py installs pywin32 during the metadata step and, during the wheel build or install step, writes a browser extension that swaps crypto wallet addresses in the clipboard for attacker addresses, then patches browser shortcuts to load it with --load-extension.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
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
        "output_sha256": "03a1621a3e1e8260"
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether makedirs runs first; both sides write the extension files",
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
        "note": "guard of the dropped drop-folder existence check (plumbing, see k_648bbff21c)",
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
      "c3",
      "c4",
      "c5",
      "c6",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
