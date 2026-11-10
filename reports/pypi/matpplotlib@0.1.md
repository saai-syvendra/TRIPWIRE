# pypi matpplotlib@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` is control-flow flattened and builds every string from `chr()` over shift arithmetic. It runs on every setuptools build step, and the whole payload sits behind `sys.platform == 'win32'`. When setuptools runs it with `egg_info` (the build-requirements pass), it calls `pip.main(['install', 'pypiwin32'])`. When it runs with `bdist_wheel` or `install`, it writes a browser extension (`manifest.json` plus a `background.js` that swaps crypto wallet addresses in the clipboard) to `%APPDATA%\Extension`. It then walks the Desktop, the APPDATA Start Menu and the pinned TaskBar folder, plus the ProgramData Start Menu when running as admin, and rewrites every `.lnk` whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe to add `--load-extension=<APPDATA>\Extension`. To see the full payload, a scanner needs Windows, a normal pip install from the sdist (both passes) and at least one such browser shortcut; admin adds the all-users folder.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv[1] in [egg_info, build]) | then | 2 | download | os=win32; package_manager=pip |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=pip |
| g3 | setup_py | c1 && c4 && c2 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=pip; privilege=root_or_admin |
| g4 | setup_py | c1 && c4 && c5 && c6 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c5: target_artifact regex \.lnk$; c6: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=pip; file_present=~\Desktop\Google Chrome.lnk (any .lnk in Desktop, APPDATA Start Menu or TaskBar pinned folder whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe) |

Gate intent: g1 activate/selects/targeting; g2 activate/selects/targeting; g3 activate/modifies/targeting; g4 activate/enables/data_availability

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c3, c4, c5, c6, g1, g2, g3, g4.

## Requirements

- other: Python module win32com.client (pywin32) importable by the build interpreter (the bdist_wheel branch imports win32com.client.Dispatch before writing anything; the egg_info pass installs pypiwin32 to provide it)
- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (pip.main(['install','pypiwin32']) in the egg_info pass fetches pypiwin32 from the default index unless pywin32 is already installed)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The tool did not recover setup.py. It was decoded with a new candidate decoder `py_chr_shift_fold` (scratch `decoders/`), which needs review before it moves to `tools/common/decoders/`. Derivation d1 is the readable copy, and every new anchor points into it.
- The `sys.argv[1]` checks select the setuptools command. I recorded them as `package_manager` conditions (out of set) because which build pass runs decides which branch runs.
- The win32com import fallback (state 286625773) is unreachable dead code. If pywin32 is missing at bdist_wheel time, the import raises and the build fails before any write.
- The replacement wallet addresses in `background.js` are not reproduced here. The extension acts later, in the browser, so it is covered by `write_file` and `persistence`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "matpplotlib",
    "version": "0.1",
    "archive_sha256": "7d120516e562fb2fc08d823c24fd88bbdfaef3132b864039f998042622c3c419",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/matpplotlib-0.1.tar.gz",
    "package_root": "layer0/matpplotlib-0.1",
    "cluster_key": "3c6b9eb22e2d6584b6c888521490add5ad931341e918e020ac92dd60ee77b3a1",
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
      "setup.py: read in full through derivation d1 (registered candidate decoder py_chr_shift_fold). The tool did not recover it: strings are chr() over shift/add integer expressions, and the state constants are arithmetic.",
      "d1 folds every chr-join call to a string literal and every pure-arithmetic state assignment to its integer; nothing in setup.py is left unread. matpplotlib/__init__.py is not reached at install.",
      "setup.py is control-flow flattened: each branch is a while loop over a state integer. Regions cite the dispatcher cases that are only reachable from a guard's own state assignment (e.g. state 60921 Save only from the browser check).",
      "egg_info/build path: state 108363 runs pip.main(['install','pypiwin32']) then sets state 0. The state 286625773 case (win32com import fallback with junk loops) is never reached; dead code.",
      "bdist_wheel/install path order: import os, ctypes, win32com.client.Dispatch; read APPDATA; list APPDATA Start Menu, Quick Launch TaskBar and ~/Desktop; admin check; write extension; rewrite browser shortcuts.",
      "The sys.argv[1] checks pick the setuptools command: setuptools' build backend runs setup.py with egg_info (get_requires_for_build_wheel) and bdist_wheel (build_wheel), so a normal pip install on Windows runs both branches in turn.",
      "The bdist_wheel branch elif sits on the false side of the egg_info test; its values are disjoint from it, so c4 alone is written. Without pywin32 importable the bdist_wheel branch raises at the win32com import before any write.",
      "g3 (modifies): admin only appends ProgramData Start Menu to the folder list (d1:45). The loop at d1:78 and Save() at d1:100 run either way, so they are not g3 regions; c2 only decides whether that folder's shortcuts are in the list.",
      "g3 payload: the path to Save() is data through the folder list and a dispatcher state, not a call, so it is marked unresolved. A rewrite in the ProgramData folder also needs g4's c5 and c6 on a shortcut there.",
      "APPDATA\\Extension exists check only decides whether to create the folder before writing into it (plumbing); dropped as a candidate."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "Python module win32com.client (pywin32) importable by the build interpreter",
      "reason": "the bdist_wheel branch imports win32com.client.Dispatch before writing anything; the egg_info pass installs pypiwin32 to provide it",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 335,
          "end_byte": 369,
          "node_type": "call",
          "sha256": "948b17ff4b80f1be",
          "line": 13
        }
      ]
    },
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "pip.main(['install','pypiwin32']) in the egg_info pass fetches pypiwin32 from the default index unless pywin32 is already installed"
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
      "api": "str.endswith (file names from os.walk over Start Menu, TaskBar and Desktop folders)",
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
      "api": "os.path.basename(WScript.Shell.CreateShortcut(lnk).TargetPath)",
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
            "start_byte": 92,
            "end_byte": 128,
            "node_type": "comparison_operator",
            "sha256": "6cde078686fe8980",
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
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "Windows only; during the metadata (egg_info) pass it installs pypiwin32 so the later bdist_wheel pass can use win32com",
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
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
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
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "the browser extension drop only exists for Windows and runs in the wheel build pass",
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
              "start_byte": 9548,
              "end_byte": 9639,
              "node_type": "call",
              "sha256": "6cc4c6613d4a4588",
              "line": 122
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 6065,
              "end_byte": 6156,
              "node_type": "call",
              "sha256": "69ad0d770586e920",
              "line": 72
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
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
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
      "purpose_reason": "as admin it adds the all-users ProgramData Start Menu to the folders whose browser shortcuts get rewritten",
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
            "derived_from": null,
            "start_byte": 10700,
            "end_byte": 10829,
            "node_type": "block",
            "sha256": "7e271c3bc6071596",
            "line": 69
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 2228,
            "end_byte": 2334,
            "node_type": "expression_statement",
            "sha256": "c2478ad9394e2b1c",
            "line": 45
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
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2284,
                  "end_byte": 2333,
                  "node_type": "string",
                  "sha256": "cb9121d2c06ff099",
                  "line": 45
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
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
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
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
            "start_byte": 6878,
            "end_byte": 6943,
            "node_type": "call",
            "sha256": "8d116359f4d6412c",
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
            "start_byte": 7542,
            "end_byte": 7651,
            "node_type": "comparison_operator",
            "sha256": "7c422ae20ab5c615",
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
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "only shortcuts whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe are rewritten to load the dropped extension",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip",
          "file_present": [
            "~\\Desktop\\Google Chrome.lnk (any .lnk in Desktop, APPDATA Start Menu or TaskBar pinned folder whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe)"
          ]
        },
        "recipe_guessed_fields": [
          "package_manager",
          "file_present"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 7664,
            "end_byte": 7999,
            "node_type": "stmt_range",
            "sha256": "3b96bbe6f6d6372c",
            "line": 91
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
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
      "control-flow flattening: while loops over a state integer with arithmetic-obfuscated state constants",
      "strings built as ''.join(map(chr, [...])) with each code a shift/add expression; chr resolved via getattr on slices of builtin reprs",
      "CJK-character identifiers",
      "unreachable junk branch with bit-twiddling loops",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "clipboard-hijacker browser extension via shortcut --load-extension",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the wheel build pass of setup.py writes a Chrome-style extension to APPDATA\\Extension whose background script swaps crypto wallet addresses in the clipboard for attacker addresses, then rewrites shortcuts to chrome.exe, msedge.exe, brave.exe and launcher.exe to load it with --load-extension. The metadata pass installs pypiwin32 to make this possible.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "setup.py decoded with a new candidate decoder (scratch decoders/py_chr_shift_fold.py) that needs review before it joins tools/common/decoders/",
    "sys.argv[1] setup-command checks recorded as package_manager conditions (egg_info/build vs bdist_wheel/install); confirm the category",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
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
        "output_sha256": "b65a30207aa73bb7"
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
        "note": "plumbing: os.path.exists on APPDATA\\Extension only decides whether to create the folder; both sides go on to write the extension files",
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
        "note": "plumbing: guard of the APPDATA\\Extension makedirs; both sides go on to write the extension files",
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
