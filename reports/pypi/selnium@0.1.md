# pypi selnium@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

`setup.py` runs at top level when pip builds the sdist; it is obfuscated with chr-join strings, flattened state machines and CJK identifiers, fully decoded with `py_chr_shift_fold` (derived d1). Everything sits behind `sys.platform == 'win32'` and a check on the setuptools command in `sys.argv[1]`: during `egg_info`/`build` it runs `pip.main(['install','pypiwin32'])`, and during `bdist_wheel`/`install` it writes a Chrome MV2 extension (clipboard hijacker that swaps crypto wallet addresses) to `%APPDATA%\Extension`. It then walks the Start Menu, Taskbar pinned and Desktop folders (plus the all-users Start Menu when `IsUserAnAdmin()` is true) and adds `--load-extension` to every `.lnk` whose target is chrome.exe, msedge.exe, brave.exe or launcher.exe. A Windows VM with pip, network to PyPI, an admin install and existing browser shortcuts (including one in the all-users Start Menu) opens every gate.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv in [egg_info, build]) | then | 2 | download | os=win32 |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv in [bdist_wheel, install]) | then | 2 | write_file | os=win32 |
| g3 | setup_py | c1 && c4 && c2 && c5 && c6 (c1: os == win32; c4: sys.argv in [bdist_wheel, install]; c2: privilege truthy; c5: target_artifact regex \.lnk$; c6: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 5 | persistence | os=win32; privilege=root_or_admin; file_present=C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk with TargetPath C:\Program Files\Google\Chrome\Application\chrome.exe |
| g4 | setup_py | c1 && c4 && c5 && c6 (c1: os == win32; c4: sys.argv in [bdist_wheel, install]; c5: target_artifact regex \.lnk$; c6: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; file_present=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk with TargetPath C:\Program Files\Google\Chrome\Application\chrome.exe |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/modifies/targeting; g4 activate/enables/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c3, c4, c5, c6, g1, g2, g3, g4.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (pip.main(['install','pypiwin32']) in the egg_info step fetches pypiwin32 from the default index)
- other: python module win32com (pywin32/pypiwin32) importable in the build environment (the bdist_wheel/install branch imports win32com.client.Dispatch unguarded before any write)
- file_present: browser .lnk shortcuts (chrome.exe, msedge.exe, brave.exe, launcher.exe) under %APPDATA%\Microsoft\Windows\Start Menu, Taskbar pinned or ~\Desktop (shortcut rewrite only acts on existing browser shortcuts (gate g4); listed so a VM has something to modify)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The argv checks (c3, c4) and the shortcut checks (c5 `.lnk` suffix, c6 browser target name) are out of set: the extractor produced no candidates for them. c5 is a `str.endswith('.lnk')` call, recorded as regex `\.lnk$` since the schema has no endswith operator.
- g3 (admin) adds `C:\ProgramData\Microsoft\Windows\Start Menu` to the folder list, so the same shortcut rewrite also reaches all-users shortcuts. Its sink is the `Save()` of the shortcut rewrite. The state machine links the regions through state values rather than nesting: the admin branch reaches the `append` state, and the `.lnk` and browser-target tests lead to the `--load-extension` assignment and `Save()`. `Save()` itself also runs without admin for per-user shortcuts (g4); only the all-users shortcuts depend on c2.
- The `APPDATA\Extension` existence check is dropped as plumbing (only decides whether to create the folder).
- Embedded wallet addresses are attacker indicators in background.js; not copied here.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "selnium",
    "version": "0.1",
    "archive_sha256": "1f5b703a8a935b722767a8ba07aec248ea3bd0f7211506f62f0fbd7ef8c75edc",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/selnium-0.1.tar.gz",
    "package_root": "layer0/selnium-0.1",
    "cluster_key": "b8bc6c89cf2a07bf3d62f9f4149b5ac5f1d5ca679aaae200a252787bd9c4c46f",
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
      "setup.py: strings built as chr-joins of shift arithmetic, control flow flattened into integer state machines with CJK identifiers. Decoded with registered decoder py_chr_shift_fold (derived d1); read in full; nothing unread.",
      "Top-level code is gated on sys.argv[1]: egg_info/build runs pip.main(['install','pypiwin32']); bdist_wheel/install runs the payload. Under pip's setuptools fallback both steps happen in one install (egg_info for requirements, then bdist_wheel).",
      "dist_info (prepare_metadata) matches neither argv list, so a metadata-only step runs nothing. pip download would only reach the egg_info branch.",
      "Payload: writes a Chrome MV2 extension (background.js clipboard hijacker swapping crypto wallet addresses, manifest.json) to %APPDATA%\\Extension, then rewrites browser .lnk shortcuts to add --load-extension.",
      "Shortcut folders: AppData Start Menu, Taskbar pinned, Desktop; ProgramData Start Menu added only when IsUserAnAdmin() is true.",
      "Dropped k_648bbff21c/q_a9279e344a: os.path.exists(APPDATA\\Extension) only decides whether to makedirs the drop folder; both sides then write the extension (plumbing).",
      "State 286625773 in the egg_info loop (win32com import probe with junk arithmetic) is never assigned, so that branch is dead code. import random is unused.",
      "from win32com.client import Dispatch is not in a try: if pywin32 is missing at bdist_wheel the payload aborts with ImportError before writing anything.",
      "selnium/__init__.py is empty; nothing runs at import."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pypi[.]org:443, files[.]pythonhosted[.]org:443",
      "reason": "pip.main(['install','pypiwin32']) in the egg_info step fetches pypiwin32 from the default index"
    },
    {
      "axis": "other",
      "value": "python module win32com (pywin32/pypiwin32) importable in the build environment",
      "reason": "the bdist_wheel/install branch imports win32com.client.Dispatch unguarded before any write"
    },
    {
      "axis": "file_present",
      "value": "browser .lnk shortcuts (chrome.exe, msedge.exe, brave.exe, launcher.exe) under %APPDATA%\\Microsoft\\Windows\\Start Menu, Taskbar pinned or ~\\Desktop",
      "reason": "shortcut rewrite only acts on existing browser shortcuts (gate g4); listed so a VM has something to modify"
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
      "api": "sys.argv",
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
      "api": "sys.argv",
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
      "api": "os.path.basename(WScript.Shell.CreateShortcut(...).TargetPath)",
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
      "purpose_reason": "Windows only; in the metadata (egg_info) build step it installs pywin32 so the later bdist_wheel step can drive WScript.Shell",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
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
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "payload exists only for Windows browsers and runs only in the wheel build / install step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
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
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c4 && c2 && c5 && c6",
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
      "purpose_reason": "as admin the shortcut rewrite also covers the all-users ProgramData Start Menu; those shortcuts are saved only through the same .lnk and browser-target tests as g4",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "privilege": "root_or_admin",
          "file_present": [
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Google Chrome.lnk with TargetPath C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
          ]
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
            "derived_from": "d1",
            "start_byte": 2228,
            "end_byte": 2395,
            "node_type": "stmt_range",
            "sha256": "a2d4643aa70e2799",
            "line": 45
          },
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
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "only shortcuts whose target is a Chromium browser executable get --load-extension added and saved",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Google Chrome.lnk with TargetPath C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
          ]
        },
        "recipe_guessed_fields": [],
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
    "level": "moderate",
    "techniques": [
      "strings built as chr() joins of shift/add integer expressions, chr name assembled from builtin reprs",
      "control-flow flattening into integer state machines with junk arithmetic",
      "CJK identifier renaming",
      "dead state-machine branch with junk loop",
      "very long lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "lnk --load-extension clipboard hijacker",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, the wheel build step writes a browser extension that swaps cryptocurrency wallet addresses in the clipboard for attacker addresses and rewrites Chrome, Edge and Brave shortcuts to load it on every launch. The name typosquats selenium.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
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
        "output_sha256": "acf2332fdd20d417"
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to makedirs the drop folder; both sides then write the extension",
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
        "note": "plumbing: guard of the drop-folder existence check; both sides continue to the same extension write",
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
