# pypi crpytography@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py runs at sdist build time and does everything inside `if sys.platform == 'win32'`. The setup step in `sys.argv[1]` then picks the work: during `egg_info`/`build` it installs pypiwin32 through pip's internal API if win32com is missing, and during `bdist_wheel`/`install` it writes an unpacked browser extension (background.js and manifest.json) to `%APPDATA%\Extension`. It then walks the user's Start Menu, taskbar pins and Desktop (plus the all-users Start Menu when IsUserAnAdmin is true) and rewrites every .lnk that targets chrome.exe, msedge.exe, brave.exe or launcher.exe to add `--load-extension`. The extension swaps cryptocurrency addresses in the clipboard for attacker wallets. To open the gates you need Windows, a normal pip sdist install, pywin32 available and at least one browser shortcut.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv[1] in [egg_info, build]) | then | 2 | download | os=win32; package_manager=setup.py command egg_info or build (sys.argv[1]) |
| g2 | setup_py | c1 && c5 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=setup.py command bdist_wheel or install (sys.argv[1]) |
| g3 | setup_py | c1 && c5 && c6 && c7 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]; c6: target_artifact regex \.lnk$; c7: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=setup.py command bdist_wheel or install (sys.argv[1]); file_present=%APPDATA%\Microsoft\Windows\Start Menu\**\*.lnk whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe (or the same under %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar or ~\Desktop) |
| g4 | setup_py | c1 && c5 && c2 (c1: os == win32; c5: sys.argv[1] in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=setup.py command bdist_wheel or install (sys.argv[1]); privilege=root_or_admin |

Gate intent: g1 activate/selects/targeting; g2 activate/selects/targeting; g3 activate/enables/data_availability; g4 activate/modifies/targeting

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, g1, g2, g3, g4.

## Requirements

- os: win32 (ctypes.windll, win32com and WScript.Shell are Windows-only)
- other: pywin32 (win32com) importable in the build interpreter (from win32com.client import Dispatch is unconditional in the bdist_wheel/install branch; an ImportError aborts the payload before any file is written)
- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (pip._internal.main(['install','pypiwin32']) in the egg_info/build step downloads pywin32 when it is missing (default index assumed))
- other: APPDATA environment variable set (os.getenv('APPDATA') is concatenated with strings; None raises and aborts the payload)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The argv checks (c4, c5) and shortcut checks (c6, c7) are out of set. The extractor did not offer them as candidates.
- The admin gate g4 changes only which folders get searched. Its link to `shortcut.Save()` goes through the `paths` list (data flow), not through a call.
- The extension JS is obfuscator.io style. I read it only as data to classify what it does. It does not run at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "crpytography",
    "version": "0.1",
    "archive_sha256": "28e8d2773d43945f5eb665f0d7afa759a9dae4284aab32dfbd908477240730ba",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/crpytography-0.1.tar.gz",
    "package_root": "layer0/crpytography-0.1",
    "cluster_key": "c6cf9c5e3d1556a635ba0377c90fecc9bbb07da81431c3e2d61cb34a2cff7c35",
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
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (58 lines). crpytography/__init__.py is empty and not reached at install.",
      "sys.argv[1] picks the setup step: egg_info/build installs pypiwin32 via pip._internal.main when win32com is missing; bdist_wheel/install drops the extension and rewrites browser shortcuts. A normal pip sdist install runs both steps.",
      "The try/import win32com probe in the egg_info branch is plumbing (fetch a module the payload needs only if missing), so it is not a gate; the pypiwin32 download is recorded as the g1 behaviour and as a requirement.",
      "if not os.path.exists(APPDATA\\Extension): os.makedirs(...) only creates the drop folder; both sides go on to write the extension, so k_fcbe9adaf8/q_342d74f0ef are dropped as plumbing.",
      "The extension body written to background.js is obfuscator.io-style JS: a clipboard watcher that swaps ETH, TRON, BNB, BTC and LTC addresses for attacker wallets every second. It is written at install, it runs only later in the browser.",
      "g4 (IsUserAnAdmin) only appends the all-users Start Menu folder to the list walked for shortcuts; the link to shortcut.Save() is data flow through the paths list, not a call, hence the bind hop on the appended path.",
      "g4 persistence on that extra folder also needs a browser .lnk there (c6, c7), which the g4 expression leaves out because those tests sit in the shared loop that g3 covers.",
      "setup.py imports distutils.core, absent from Python 3.12+ unless setuptools provides its shim (it does in pip build environments)."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "ctypes.windll, win32com and WScript.Shell are Windows-only"
    },
    {
      "axis": "other",
      "value": "pywin32 (win32com) importable in the build interpreter",
      "reason": "from win32com.client import Dispatch is unconditional in the bdist_wheel/install branch; an ImportError aborts the payload before any file is written"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443, files[.]pythonhosted[.]org:443",
      "reason": "pip._internal.main(['install','pypiwin32']) in the egg_info/build step downloads pywin32 when it is missing (default index assumed)"
    },
    {
      "axis": "other",
      "value": "APPDATA environment variable set",
      "reason": "os.getenv('APPDATA') is concatenated with strings; None raises and aborts the payload"
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
          "candidate": "k_4e73dbaaa8",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 49,
            "end_byte": 72,
            "node_type": "comparison_operator",
            "sha256": "74866fc41f5ccf30",
            "line": 5
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
          "candidate": "k_7b91d7e5d8",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 666,
            "end_byte": 703,
            "node_type": "call",
            "sha256": "fc942b5e5173ed6f",
            "line": 26
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
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 79,
            "end_byte": 115,
            "node_type": "comparison_operator",
            "sha256": "6cde078686fe8980",
            "line": 6
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
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 262,
            "end_byte": 303,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 13
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
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3685,
            "end_byte": 3706,
            "node_type": "call",
            "sha256": "1388f6944b986f93",
            "line": 43
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
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3861,
            "end_byte": 3898,
            "node_type": "call",
            "sha256": "e8f975fbcebcb106",
            "line": 46
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
          "candidate": "q_ef0750118d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 46,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "b69afc8fe18df79b",
            "line": 5
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
            "start_byte": 76,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "d653d7327296a31b",
            "line": 6
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
      "purpose_reason": "Windows only, and the setup step decides whether the pywin32 dependency is fetched or the payload runs",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command egg_info or build (sys.argv[1])"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 121,
            "end_byte": 253,
            "node_type": "try_statement",
            "sha256": "83769b0ce1152149",
            "line": 7
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 223,
              "end_byte": 253,
              "node_type": "call",
              "sha256": "8d2a424e86489596",
              "line": 11
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
          "candidate": "q_ef0750118d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 46,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "b69afc8fe18df79b",
            "line": 5
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
            "start_byte": 262,
            "end_byte": 303,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 13
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
      "purpose_reason": "The extension drop only exists for Windows and runs in the wheel-build/install step of setup.py",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install (sys.argv[1])"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 309,
            "end_byte": 4242,
            "node_type": "stmt_range",
            "sha256": "0128caf333ad6ee1",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 893,
              "end_byte": 947,
              "node_type": "call",
              "sha256": "9ade45dfa3552263",
              "line": 32
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 3248,
              "end_byte": 3302,
              "node_type": "call",
              "sha256": "0edb16c7b1831a3e",
              "line": 35
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
          "candidate": "q_ef0750118d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 46,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "b69afc8fe18df79b",
            "line": 5
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
            "start_byte": 262,
            "end_byte": 303,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 13
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
            "derived_from": null,
            "start_byte": 3682,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "c3e300e8b1ef0a4b",
            "line": 43
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
            "derived_from": null,
            "start_byte": 3924,
            "end_byte": 4173,
            "node_type": "if_statement",
            "sha256": "71a284145531cbb9",
            "line": 48
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
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Only shortcuts that point at Chrome, Edge, Brave or launcher.exe are rewritten to load the dropped extension",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install (sys.argv[1])",
          "file_present": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\**\\*.lnk whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe (or the same under %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar or ~\\Desktop)"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 4033,
            "end_byte": 4173,
            "node_type": "stmt_range",
            "sha256": "d6ee1f9b86ec470b",
            "line": 49
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 4158,
              "end_byte": 4173,
              "node_type": "call",
              "sha256": "8d854dbaa469edb4",
              "line": 50
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
          "candidate": "q_ef0750118d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 46,
            "end_byte": 4242,
            "node_type": "if_statement",
            "sha256": "b69afc8fe18df79b",
            "line": 5
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
            "start_byte": 262,
            "end_byte": 303,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 13
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": "q_73012633ad",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 663,
            "end_byte": 776,
            "node_type": "if_statement",
            "sha256": "a28d185030c164ff",
            "line": 26
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
      "purpose_reason": "As admin the all-users Start Menu is added to the folders whose browser shortcuts get rewritten",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py command bdist_wheel or install (sys.argv[1])",
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 713,
            "end_byte": 776,
            "node_type": "call",
            "sha256": "9b27d540b86d82ac",
            "line": 27
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 4158,
              "end_byte": 4173,
              "node_type": "call",
              "sha256": "8d854dbaa469edb4",
              "line": 50
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 713,
                  "end_byte": 776,
                  "node_type": "call",
                  "sha256": "9b27d540b86d82ac",
                  "line": 27
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 726,
                  "end_byte": 775,
                  "node_type": "string",
                  "sha256": "cb9121d2c06ff099",
                  "line": 27
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
      "download",
      "write_file",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "obfuscator.io-style JS (hex identifiers, rotated string array) embedded as a string literal and written to disk; the Python install code itself is plain"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "clipboard-hijack browser extension dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, setup.py drops an unpacked browser extension that swaps cryptocurrency addresses in the clipboard for attacker wallets, then rewrites Chrome, Edge and Brave shortcuts to load it with --load-extension. Typosquat of cryptography.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "0ea9f47c9e692e68"
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
        "candidate": "k_fcbe9adaf8",
        "reason_code": "other",
        "note": "Plumbing: creates the APPDATA\\Extension drop folder when missing; both sides go on to write the same extension files.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 789,
          "end_byte": 832,
          "node_type": "call",
          "sha256": "d8652b0c32972f0c",
          "line": 29
        }
      },
      {
        "candidate": "q_342d74f0ef",
        "reason_code": "other",
        "note": "Guard of the drop-folder makedirs check (k_fcbe9adaf8); plumbing, not a gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 782,
          "end_byte": 882,
          "node_type": "if_statement",
          "sha256": "3d8f177291037e6f",
          "line": 29
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
