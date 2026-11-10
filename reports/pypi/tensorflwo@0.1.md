# pypi tensorflwo@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

tensorflwo is a typosquat of tensorflow whose setup.py runs its payload at module top level when the sdist is built. Every string is hidden as chr codes built from shift arithmetic, and the code is a flattened state machine; it was decoded with the registered `py_chr_shift_fold` decoder (d1). The outer gate is `sys.platform == 'win32'`. Inside it, `sys.argv[1]` picks the step: on `egg_info`/`build` it runs `pip.main(['install', 'pypiwin32'])` (g1). On `bdist_wheel`/`install` (g2) it writes a Chrome MV2 extension (`manifest.json`, `background.js`) to `%APPDATA%\Extension` that swaps crypto wallet addresses on the clipboard. It then walks the Start Menu, Desktop and pinned TaskBar folders and rewrites each `.lnk` whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe to add `--load-extension` (g3). When the process is admin, it also adds the all-users Start Menu to that folder list (g4).

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in egg_info, build) | then | 2 | download | os=win32; package_manager=setup.py command egg_info or build |
| g2 | setup_py | c1 && c5 (c1: os == win32; c5: sys.argv[1] in bdist_wheel, install) | then | 2 | write_file | os=win32; package_manager=setup.py command bdist_wheel or install |
| g3 | setup_py | c1 && c5 && c7 && c6 (c1: os == win32; c5: sys.argv[1] in bdist_wheel, install; c7: target_artifact regex \.lnk$; c6: target_artifact in chrome.exe, msedge.exe, launcher.exe, brave.exe) | then | 4 | persistence | os=win32; package_manager=setup.py command bdist_wheel or install; file_present=%APPDATA%\Microsoft\Windows\Start Menu\...\<browser>.lnk targeting chrome.exe, msedge.exe, launcher.exe or brave.exe (or on Desktop or pinned TaskBar) |
| g4 | setup_py | c1 && c5 && c2 (c1: os == win32; c5: sys.argv[1] in bdist_wheel, install; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=setup.py command bdist_wheel or install; privilege=root_or_admin |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/enables/data_availability; g4 activate/modifies/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, g1, g2, g3, g4.

## Requirements

- other: pywin32 (win32com.client) importable in the build interpreter (install branch runs from win32com.client import Dispatch before writing any file; ModuleNotFoundError aborts the build otherwise)
- other: setup.py executed with __builtins__ as a module (python setup.py install/bdist_wheel or legacy pip setup.py shim) (every string is built with getattr(__builtins__, 'chr'); under a PEP 517 setuptools.build_meta exec __builtins__ is a dict and the line 6 test raises)
- other: pip older than 10 importable as pip with pip.main (egg_info/build branch calls pip.main(['install', 'pypiwin32']); only needed for that pre-install step)
- network: pypi[.]org:443 (pip.main install of pypiwin32 in the egg_info/build branch fetches from the default index)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- Out-of-set conditions: the two `sys.argv[1]` checks (c4, c5) and the shortcut filters (c7 `.lnk`, c6 browser executable name), all cited in d1.
- The `%APPDATA%\Extension` existence check only decides whether to create the folder first, so it is plumbing and was dropped.
- The payload probably does not run under modern pip. `getattr(__builtins__, ...)` fails when setuptools.build_meta execs setup.py with a plain dict for globals, and `pip.main` was removed in pip 10. A scanner needs `python setup.py install` (or legacy pip) with pywin32 already importable.
- The attacker's wallet addresses are inside the dropped JS; they are not reproduced here.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "tensorflwo",
    "version": "0.1",
    "archive_sha256": "b95b8fab074658aa132ae8aa5b2aaac402c81f96d179f10cb1c308ecc2e8ebc2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/tensorflwo-0.1.tar.gz",
    "package_root": "layer0/tensorflwo-0.1",
    "cluster_key": "1669c4bb4c59e78009e9db184ba2a79211126cc8cb3a9f0f56648411bc497568",
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
      "setup.py: tool did not fold the chr-from-builtins strings or opaque state values; registered decoder py_chr_shift_fold as d1. Package code read in full in d1; nothing unread. tensorflwo/__init__.py is empty.",
      "Both payload blocks are flattened state machines (while state: if state == N). State order was followed by hand in d1: install branch runs imports, APPDATA, shortcut dir list, admin check, mkdir, write background.js and manifest.json, then shortcut patching.",
      "The egg_info/build branch sets state 0 right after pip.main, so the 286625773 state (try import win32com, junk arithmetic in the except handler) is never reached. Dead code.",
      "g2 sits on the elif of the argv check (c4 false, c5 true); the two value lists are disjoint so it is written as c1 && c5.",
      "Line 6 fetches chr via getattr(__builtins__, ...). This works only when __builtins__ is the module (python setup.py, legacy pip exec shim). Under setuptools.build_meta exec(code, locals()) __builtins__ is a dict and line 6 likely raises, so nothing runs.",
      "The egg_info branch calls pip.main, which pip 10+ no longer provides; on newer pip that step raises. The install branch then needs win32com already importable or it fails at the Dispatch import before writing files.",
      "g4: constant states lead from the admin append to the walk: 362814, 18005, (29059,) 37668, 382664, 12768, 162346, 4030, 145239, 186387, 790593.",
      "g4: c2 controls only the append. State 383984 goes to 362814 when admin and straight to 18005 otherwise, and both reach the 790593 walk, so the walk is not a g4 region; non-admin runs walk the shorter list.",
      "g4: the append reaches Save() only through the folder list and the state variable, not a call chain, so the payload is marked unresolved. Save() on an all-users shortcut still needs c7 and c6 in that loop (see g3).",
      "sys.argv[1] in c4/c5 is the setup.py command the install frontend passes (pip runs setup.py egg_info, then bdist_wheel or install), so category package_manager.",
      "Dropped extension is a Chrome MV2 background script that rewrites crypto wallet addresses on the clipboard every second (clipper); browser shortcuts are patched with --load-extension so it loads at each browser launch."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable in the build interpreter",
      "reason": "install branch runs from win32com.client import Dispatch before writing any file; ModuleNotFoundError aborts the build otherwise"
    },
    {
      "axis": "other",
      "value": "setup.py executed with __builtins__ as a module (python setup.py install/bdist_wheel or legacy pip setup.py shim)",
      "reason": "every string is built with getattr(__builtins__, 'chr'); under a PEP 517 setuptools.build_meta exec __builtins__ is a dict and the line 6 test raises"
    },
    {
      "axis": "other",
      "value": "pip older than 10 importable as pip with pip.main",
      "reason": "egg_info/build branch calls pip.main(['install', 'pypiwin32']); only needed for that pre-install step"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip.main install of pypiwin32 in the egg_info/build branch fetches from the default index"
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
      "value": "egg_info, build",
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
      "id": "c5",
      "category": "package_manager",
      "api": "sys.argv[1]",
      "operator": "in",
      "value": "bdist_wheel, install",
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
      "id": "c6",
      "category": "target_artifact",
      "api": "os.path.basename(shortcut.TargetPath)",
      "operator": "in",
      "value": "chrome.exe, msedge.exe, launcher.exe, brave.exe",
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
    },
    {
      "id": "c7",
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
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Windows only; during the metadata/build step it pre-installs pypiwin32 that the later install-step payload imports",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command egg_info or build"
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
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the Chrome-extension dropper exists only for Windows and only runs in the install/bdist_wheel step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install"
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
      "expression": "c1 && c5 && c7 && c6",
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
            "c5"
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
            "c7"
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
      "purpose_reason": "only .lnk shortcuts whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe are rewritten to load the extension",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install",
          "file_present": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\...\\<browser>.lnk targeting chrome.exe, msedge.exe, launcher.exe or brave.exe (or on Desktop or pinned TaskBar)"
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
            "sink_kind": "other",
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
      "purpose_reason": "as admin it adds the all-users Start Menu (C:\\ProgramData) to the folders whose browser shortcuts get patched",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install",
          "privilege": "root_or_admin"
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
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2228,
                  "end_byte": 2334,
                  "node_type": "call",
                  "sha256": "c2478ad9394e2b1c",
                  "line": 45
                }
              }
            ],
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
    "level": "moderate",
    "techniques": [
      "very long lines",
      "strings built as ''.join(map(chr, [...])) with chr fetched through getattr(__builtins__, ...) from builtin reprs and code points written as shift/add integer expressions",
      "control-flow flattening with opaque integer state values",
      "junk arithmetic loop in an unreachable except handler",
      "CJK-character identifiers"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "chrome-extension clipboard clipper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows during the install/bdist_wheel step, setup.py writes a Chrome extension into %APPDATA%\\Extension whose background script swaps crypto wallet addresses on the clipboard, then patches browser shortcuts with --load-extension so it loads at each launch.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "payload likely only runs under direct python setup.py or legacy pip (getattr(__builtins__) and pip.main); see notes",
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
        "output_sha256": "2fa7ca177ac6c5fe"
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to makedirs it first; both sides go on to write the extension files",
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
        "note": "plumbing: the if around the Extension folder existence check; both sides continue to state 37668 which writes background.js",
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
