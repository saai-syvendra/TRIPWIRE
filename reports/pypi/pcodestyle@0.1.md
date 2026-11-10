# pypi pcodestyle@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py runs at every sdist build step. All of it sits behind `sys.platform == 'win32'`, and it then branches on `sys.argv[1]`. On `egg_info`/`build` it calls `pip.main(['install', 'pypiwin32'])`. On `bdist_wheel`/`install` it creates `%APPDATA%\Extension`, writes `background.js` and `manifest.json` there, then walks the user Start Menu, pinned Taskbar and Desktop. If `IsUserAnAdmin()` it also walks the all-users Start Menu. Every `.lnk` whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe gets `--load-extension=%APPDATA%\Extension` added to its arguments and is saved. A normal pip install of the sdist on Windows hits both argv branches, so opening everything needs only Windows, plus a browser shortcut for the hijack itself.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv[1] in [egg_info, build]) | then | 2 | download | os=win32; package_manager=pip |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=pip |
| g3 | setup_py | c1 && c4 && c2 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=pip; privilege=root_or_admin |
| g4 | setup_py | c1 && c4 && c5 && c6 (c1: os == win32; c4: sys.argv[1] in [bdist_wheel, install]; c5: target_artifact regex \.lnk$; c6: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=pip; file_present=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Google Chrome.lnk (TargetPath ...\chrome.exe) |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/targeting; g3 activate/modifies/targeting; g4 activate/modifies/data_availability

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c3, c4, c5, c6, g1, g2, g3, g4.

## Requirements

- other: pywin32 (win32com.client) importable in the build interpreter (state 12258 does 'from win32com.client import Dispatch' before any file is written; an ImportError aborts the payload)
- other: pip importable from setup.py (pip.main) (the egg_info/build branch installs pypiwin32 through pip.main)
- network: pypi[.]org:443 (pip.main install pypiwin32 fetches from the default index unless pypiwin32 is already installed)
- other: APPDATA env var set (extension folder, file paths and shortcut folders are built from os.getenv('APPDATA'))

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The obfuscation is heavy: chr() integer arithmetic for every string, control flow flattened into state machines, CJK identifiers. Derivation d1 (registered decoder `py_chr_shift_fold`) folds the strings and state values, so the state order is read from d1 rather than worked out by hand. Condition, guard and sink anchors still sit on the raw `setup.py`.
- The dropped extension is fully decoded in d1. `background.js` checks the clipboard every second and replaces cryptocurrency addresses with attacker addresses; `manifest.json` names it "Windows" and asks for clipboard permissions. It runs in the browser, not at install, so it doesn't affect the gates.
- The argv conditions use category `package_manager`: they test which setuptools command the frontend runs.
- Whether `import pip` / `pip.main` works inside an isolated build env is uncertain. If it doesn't, pywin32 must already be installed or the payload stops at the win32com import.
- The name is one letter off pycodestyle (typosquat).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pcodestyle",
    "version": "0.1",
    "archive_sha256": "9e988bcffda9c7ef1868a5eb1cc3755be9e66c8bdc90631ea969f1c65a868658",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pcodestyle-0.1.tar.gz",
    "package_root": "layer0/pcodestyle-0.1",
    "cluster_key": "9d55462b284007312ca4b9a4fc290bbb0571b2702f673a699df441638b367b54",
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
      "setup.py: every string is chr() arithmetic (chr built from oct/hex/copyright reprs); control flow is flattened into while/elif state machines.",
      "Derivation d1 (decoder py_chr_shift_fold) folds strings and integer states, so the state order below is read from d1, not folded by hand.",
      "State order on the bdist_wheel/install branch: import os, ctypes, win32com Dispatch; APPDATA; Desktop path; shortcut folder list; admin check; mkdir APPDATA\\Extension if missing; write background.js; write manifest.json; WScript.Shell; walk folders and patch .lnk files.",
      "Shortcut folders: %APPDATA%\\Microsoft\\Windows\\Start Menu, %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar, ~\\Desktop; plus C:\\ProgramData\\Microsoft\\Windows\\Start Menu when IsUserAnAdmin().",
      "Patched shortcuts get Arguments '--load-extension=%APPDATA%\\Extension' (str.format with the APPDATA value) and are saved, so the dropped extension loads at every browser launch.",
      "egg_info/build branch: its state machine starts at 108363 (d1:13, pip.main(['install', 'pypiwin32'])) then sets state 0 and exits; the elif state 286625773 (win32com import probe and junk arithmetic) is never reached, dead code.",
      "The elif at line 35 (c4) sits on the false side of the line 7 test (c3); argv[1] cannot match both lists, so c4 alone is written for g2.",
      "g3: only IsUserAnAdmin() true (line 68) jumps to state 362814, whose line 46 appends the ProgramData Start Menu to the folder list.",
      "g3: line 82 walks that folder list, so ProgramData shortcuts reach the same Save() at line 104.",
      "g4: Save() (state 60921, line 104) is set only on the c6 then side (line 95); the c6 false side sets state 0 (>>8932), ending the loop.",
      "Dropped c3 candidate (os.path.exists APPDATA\\Extension): both sides reach the same open/write of background.js, only creating the folder first. Plumbing, not a gate.",
      "background.js (line 73, d1:69) is fully decoded: every second it replaces clipboard values matching cryptocurrency address patterns with hardcoded attacker addresses.",
      "manifest.json (line 129, d1:125) names the extension 'Windows' and asks for clipboardRead and clipboardWrite.",
      "Both files run in the browser, not at install, so they add no install-time gate or behaviour.",
      "pip.main exists in pip >= 19.3 as a wrapper; whether 'import pip' works inside an isolated build env is not certain, so the pypiwin32 install may fail and the payload branch then dies at the win32com import.",
      "g3/g4 regions: only the guard-side code. Line 69 sets state 362814, line 95 sets 60921.",
      "The line 46 append and line 104 Save() are sibling elif states, reached only via that state value; payloads unresolved.",
      "g4 path in d1: states 86892 -> 9653 -> 61499; c6 true sets 60921 and continues (d1:92-93); state 60921 calls Save() (d1:99-100). d1:92 is the only assignment of 60921.",
      "No witness hop kind expresses a state transition, and a second region around Save() would read as an alternative to c6, so g3 and g4 stay unresolved with no hops."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable in the build interpreter",
      "reason": "state 12258 does 'from win32com.client import Dispatch' before any file is written; an ImportError aborts the payload"
    },
    {
      "axis": "other",
      "value": "pip importable from setup.py (pip.main)",
      "reason": "the egg_info/build branch installs pypiwin32 through pip.main"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip.main install pypiwin32 fetches from the default index unless pypiwin32 is already installed"
    },
    {
      "axis": "other",
      "value": "APPDATA env var set",
      "reason": "extension folder, file paths and shortcut folders are built from os.getenv('APPDATA')"
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
            "derived_from": null,
            "start_byte": 330,
            "end_byte": 903,
            "node_type": "comparison_operator",
            "sha256": "f4bbc7019b252984",
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
            "derived_from": null,
            "start_byte": 3191,
            "end_byte": 3838,
            "node_type": "comparison_operator",
            "sha256": "dca3caa7dbd54f9c",
            "line": 35
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
            "derived_from": null,
            "start_byte": 55319,
            "end_byte": 55588,
            "node_type": "call",
            "sha256": "6d3b62ab42731b98",
            "line": 85
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "os.path.basename(shell.CreateShortcut(path).TargetPath)",
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
            "derived_from": null,
            "start_byte": 56310,
            "end_byte": 57824,
            "node_type": "comparison_operator",
            "sha256": "6a4385bb6cb1e613",
            "line": 94
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
            "derived_from": null,
            "start_byte": 327,
            "end_byte": 66981,
            "node_type": "if_statement",
            "sha256": "a09055fcd6f076ed",
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
      "purpose": "unclear",
      "purpose_reason": "stages the attack across setuptools commands: on Windows the egg_info/build pass installs pypiwin32, which the later bdist_wheel/install pass needs for win32com",
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
            "derived_from": null,
            "start_byte": 908,
            "end_byte": 3184,
            "node_type": "stmt_range",
            "sha256": "1405f9f6498c66c6",
            "line": 8
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1185,
              "end_byte": 1794,
              "node_type": "call",
              "sha256": "79499be5970a633f",
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
            "derived_from": null,
            "start_byte": 3186,
            "end_byte": 66981,
            "node_type": "elif_clause",
            "sha256": "af2b8af2aeae720b",
            "line": 35
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
      "purpose_reason": "the extension drop only exists for Windows and runs on the build pass that installs the package",
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
            "derived_from": null,
            "start_byte": 3842,
            "end_byte": 66981,
            "node_type": "stmt_range",
            "sha256": "62e7796e765af3be",
            "line": 36
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 11023,
              "end_byte": 53348,
              "node_type": "call",
              "sha256": "71cacfab3b59cae1",
              "line": 73
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 63414,
              "end_byte": 66862,
              "node_type": "call",
              "sha256": "acdca039472fdfac",
              "line": 129
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
            "derived_from": null,
            "start_byte": 3186,
            "end_byte": 66981,
            "node_type": "elif_clause",
            "sha256": "af2b8af2aeae720b",
            "line": 35
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
      "purpose_reason": "as admin the shortcut hijack also covers the all-users Start Menu under C:\\ProgramData",
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
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 60459,
              "end_byte": 60514,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 104
            },
            "witness": [],
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
            "derived_from": null,
            "start_byte": 3186,
            "end_byte": 66981,
            "node_type": "elif_clause",
            "sha256": "af2b8af2aeae720b",
            "line": 35
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
            "derived_from": null,
            "start_byte": 55316,
            "end_byte": 60650,
            "node_type": "if_statement",
            "sha256": "3b770fa35ca0a3fe",
            "line": 85
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
            "derived_from": null,
            "start_byte": 56307,
            "end_byte": 59891,
            "node_type": "if_statement",
            "sha256": "76b73f77a63ff981",
            "line": 94
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
      "purpose": "data_availability",
      "purpose_reason": "a shortcut is rewritten only when a .lnk in the walked folders points at chrome, msedge, Opera launcher or brave",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip",
          "file_present": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Google Chrome.lnk (TargetPath ...\\chrome.exe)"
          ]
        },
        "recipe_guessed_fields": [
          "package_manager",
          "file_present"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 57837,
            "end_byte": 59891,
            "node_type": "stmt_range",
            "sha256": "7aac4f756c029f35",
            "line": 95
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 60459,
              "end_byte": 60514,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 104
            },
            "witness": [],
            "unresolved": "dynamic_dispatch"
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
      "strings built as chr() over shift/add integer arithmetic, chr looked up via getattr(__builtins__) from builtin reprs",
      "control-flow flattening into while/elif state machines with obfuscated next-state expressions",
      "CJK-character identifiers",
      "dead states and junk arithmetic",
      "very long lines (embedded extension source)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "browser-shortcut load-extension sideload",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, setup.py installs pypiwin32 during egg_info/build, then during bdist_wheel/install drops a browser extension into %APPDATA%\\Extension and rewrites Chrome, Edge, Opera and Brave shortcuts to load it at every launch, extending to the all-users Start Menu when admin. The extension swaps cryptocurrency addresses on the clipboard for attacker addresses. All strings and control flow are heavily obfuscated.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
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
        "output_sha256": "1aa3044a141d0253"
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
        "note": "plumbing: os.path.exists(APPDATA\\Extension) only decides whether to mkdir first; both sides go on to write background.js",
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
        "note": "plumbing guard for the mkdir of APPDATA\\Extension; both sides reach the same file writes",
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
