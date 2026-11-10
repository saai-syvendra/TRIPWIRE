# pypi beautifulsopu@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Code runs at install through top-level `setup.py`, which pip executes for each setup command it runs on the sdist. Everything sits under a Windows check (`sys.platform == 'win32'`), and then branches on the setup command in `sys.argv[1]`. During `egg_info`/`build` it runs `pip.main(['install', 'pypiwin32'])` (g4). During `bdist_wheel`/`install` (g1) it writes a Manifest V2 browser extension to `%APPDATA%\Extension` whose background script swaps crypto wallet addresses in the clipboard for attacker addresses, then rewrites `.lnk` shortcuts on the Desktop, Start Menu and pinned TaskBar whose target is chrome.exe, msedge.exe, brave.exe or launcher.exe to add `--load-extension` (g3), and when `IsUserAnAdmin()` is true it also covers the all-users ProgramData Start Menu (g2). Opening the gates takes a Windows VM doing a normal pip install of the sdist with pywin32 importable, plus a browser shortcut to rewrite; admin rights add the extra shortcuts.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c5 (c1: os == win32; c5: sys.argv in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=pip running setup.py bdist_wheel or install |
| g2 | setup_py | c1 && c5 && c2 (c1: os == win32; c5: sys.argv in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=pip running setup.py bdist_wheel or install; privilege=root_or_admin |
| g3 | setup_py | c1 && c5 && c6 && c7 (c1: os == win32; c5: sys.argv in [bdist_wheel, install]; c6: target_artifact regex \.lnk$; c7: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=pip running setup.py bdist_wheel or install; file_present=any *.lnk under %USERPROFILE%\Desktop, %APPDATA%\Microsoft\Windows\Start Menu or %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe |
| g4 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv in [egg_info, build]) | then | 2 | download | os=win32; package_manager=pip running setup.py egg_info or build |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting; g3 activate/enables/data_availability; g4 activate/enables/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, g1, g2, g3, g4.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (egg_info/build branch runs pip.main(['install', 'pypiwin32']) from the default index)
- other: Python module win32com (pywin32) importable by the setup.py interpreter (bdist_wheel/install branch does 'from win32com.client import Dispatch' unguarded; under pip build isolation it may be missing and the build aborts before the payload)
- runtime_version: pip<10 (egg_info/build branch calls pip.main unguarded; pip 10 removed pip.main, so on newer pip the AttributeError aborts the build before bdist_wheel/install runs the payload)
- other: env var APPDATA set (extension folder and shortcut folders are built from os.getenv('APPDATA'))

## Behaviour

- Ungated: none
- Gated: write_file, persistence, download

## Notes

- The tool did not recover `setup.py`: strings are chr-joins over integer expressions, and the control flow is flattened into state machines with CJK identifiers. I decoded it with the existing repo decoder `py_chr_shift_fold`, registered as derivation d2, and read it in full. An earlier, unregistered decode (`derived/d1`) is also in the folder; d2 matches it, but only d2 is cited.
- The setup-command checks (`sys.argv[1]`, c4/c5) are out-of-set conditions, recorded as category `package_manager`. Phase 2 needs pip to reach `bdist_wheel` or `install` for the payload, and `egg_info` for the pypiwin32 fetch.
- `pip.main` was removed in pip 10. In a pip install, `egg_info` runs first, so on modern pip that call raises and the install fails before the payload phase. The payload is realistically reached only with pip < 10 (recorded as a `runtime_version` requirement) or a direct `setup.py install` with pywin32 already present.
- Under pip build isolation, `import pip` and `from win32com.client import Dispatch` may not resolve inside the build environment either. Not checked statically.
- g2 reaches the shortcut `Save()` through the flattened state variable rather than a call, so it is marked `dynamic_dispatch`. In g3 the `Save()` state arm (d2 lines 100-101) is cited as a second region, because state 60921 is set only under c7 at d2 line 92.
- The attacker wallet addresses are in the `background.js` content (d2 line 69); they are not reproduced here.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "beautifulsopu",
    "version": "0.1",
    "archive_sha256": "e1b02e284e5e69f4dfa75f668d0234d51b484c5f9c354ae839199ded091dfe37",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/beautifulsopu-0.1.tar.gz",
    "package_root": "layer0/beautifulsopu-0.1",
    "cluster_key": "8cb78c63d1590f638390fb306a3c5c6ba2726c2c2591982826d3c6c46d83a252",
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
      "setup.py: strings are chr-joins over integer expressions and control flow is flattened into state machines with CJK identifiers; decoded with registered decoder py_chr_shift_fold (derivation d2) and read in full; nothing unread.",
      "beautifulsopu/__init__.py is not reached at install and was not analysed.",
      "State 286625773 in the egg_info branch (try import win32com) is never assigned, so that block is dead; the egg_info branch only runs pip.main(['install', 'pypiwin32']).",
      "The bdist_wheel/install state machine runs in order: imports, APPDATA and Desktop paths, admin check, mkdir Extension if missing, write background.js and manifest.json, then walk shortcut folders and rewrite browser .lnk files.",
      "c3 (Extension folder missing -> makedirs) is plumbing: both sides go on to write the same extension files. Dropped.",
      "g2 reaches the shortcut Save() only through the flattened state variable, not a call, so its payload is marked dynamic_dispatch.",
      "g3: state 60921 is set only at d2 line 92 under c7, and the Save() arm at d2 lines 100-101 runs only in that state, so that arm is a second region of g3.then and the sink sits in it.",
      "from distutils.core import setup needs Python < 3.12 or setuptools' distutils shim; not a gate.",
      "pip.main no longer exists from pip 10 on. A pip install runs egg_info first, where the unguarded pip.main call would raise and fail the install, so the payload is only reached with pip < 10 or a direct 'setup.py install' with pywin32 present.",
      "c6 (.lnk suffix) and c7 (shortcut target is a browser exe) are per-file filters in the os.walk over Desktop, Start Menu and TaskBar folders; kept as target_artifact checks since Phase 2 must plant a browser shortcut."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pypi[.]org:443, files[.]pythonhosted[.]org:443",
      "reason": "egg_info/build branch runs pip.main(['install', 'pypiwin32']) from the default index"
    },
    {
      "axis": "other",
      "value": "Python module win32com (pywin32) importable by the setup.py interpreter",
      "reason": "bdist_wheel/install branch does 'from win32com.client import Dispatch' unguarded; under pip build isolation it may be missing and the build aborts before the payload"
    },
    {
      "axis": "runtime_version",
      "value": "pip<10",
      "reason": "egg_info/build branch calls pip.main unguarded; pip 10 removed pip.main, so on newer pip the AttributeError aborts the build before bdist_wheel/install runs the payload"
    },
    {
      "axis": "other",
      "value": "env var APPDATA set",
      "reason": "extension folder and shortcut folders are built from os.getenv('APPDATA')"
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "privilege",
      "api": "ctypes.windll.shell32.IsUserAnAdmin()",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "in",
      "value": [
        "egg_info",
        "build"
      ],
      "value_recovered": "decoded",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "in",
      "value": [
        "bdist_wheel",
        "install"
      ],
      "value_recovered": "decoded",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "str.endswith",
      "operator": "regex",
      "value": "\\.lnk$",
      "value_recovered": "decoded",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "target_artifact",
      "api": "os.path.basename(WScript.Shell.CreateShortcut().TargetPath)",
      "operator": "in",
      "value": [
        "chrome.exe",
        "msedge.exe",
        "launcher.exe",
        "brave.exe"
      ],
      "value_recovered": "decoded",
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
      "in_scope": true,
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
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
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "The clipper extension and shortcut rewrite exist only for Windows and only run in the bdist_wheel/install setup phase.",
      "then": {
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip running setup.py bdist_wheel or install"
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
              "start_byte": 9548,
              "end_byte": 9639,
              "node_type": "call",
              "sha256": "6cc4c6613d4a4588",
              "line": 122
            },
            "witness": []
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
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
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
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
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "Admin rights add the all-users ProgramData Start Menu to the folders whose browser shortcuts get rewritten.",
      "then": {
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip running setup.py bdist_wheel or install",
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
            "witness": [],
            "unresolved": "dynamic_dispatch"
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
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
            "start_byte": 1597,
            "end_byte": 10044,
            "node_type": "elif_clause",
            "sha256": "0a20073c58f9142c",
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
            "start_byte": 6875,
            "end_byte": 8553,
            "node_type": "if_statement",
            "sha256": "03f4280a43d774bf",
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
            "start_byte": 7539,
            "end_byte": 7999,
            "node_type": "if_statement",
            "sha256": "e800ec7e59b56a28",
            "line": 90
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Only .lnk shortcuts whose target is a Chromium browser get --load-extension added; no such shortcut means no persistence.",
      "then": {
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip running setup.py bdist_wheel or install",
          "file_present": [
            "any *.lnk under %USERPROFILE%\\Desktop, %APPDATA%\\Microsoft\\Windows\\Start Menu or %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
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
        ],
        "min_conditions": 4
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g4",
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
            "start_byte": 89,
            "end_byte": 10044,
            "node_type": "if_statement",
            "sha256": "1a8d99e188f0f353",
            "line": 7
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "On Windows during the egg_info/build phase it installs pypiwin32, which the later bdist_wheel/install payload imports.",
      "then": {
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "pip running setup.py egg_info or build"
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
            "sink_kind": "other",
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
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "write_file",
      "persistence",
      "download"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "very long lines",
      "strings built as ''.join(map(chr, [int expressions])) with chr fetched via getattr(__builtins__, ...) from builtin reprs",
      "integer constant arithmetic for state values",
      "control-flow flattening into while/elif state machines",
      "CJK-character identifier names",
      "dead state block (unreachable try import win32com)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "crypto clipper browser extension via shortcut --load-extension",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, setup.py installs pypiwin32 during egg_info and, during bdist_wheel/install, drops a browser extension that replaces crypto wallet addresses in the clipboard and rewrites Chrome/Edge/Brave shortcuts to load it.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "With pip >= 10 the egg_info step's pip.main call raises before the payload phase; check whether the dataset should count the payload as reachable only on old pip.",
    "out-of-set claim pending verification",
    "payload path not fully traced"
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
        "output_sha256": "6029f169c98d65be"
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
        "note": "Plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to mkdir first; both sides write the same extension files.",
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
        "note": "Guard of the Extension-folder exists check (k_648bbff21c); plumbing, not a gate.",
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
