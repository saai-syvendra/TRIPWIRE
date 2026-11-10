# pypi mysql-connector-pyhton@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

A typosquat of mysql-connector-python whose setup.py runs at sdist build. Everything sits behind `sys.platform == 'win32'` and a check on the setuptools command in `sys.argv[1]`: during egg_info/build it installs pypiwin32 if win32com is missing, and during bdist_wheel/install it drops a clipboard-hijacking browser extension (background.js and manifest.json) into `%APPDATA%\Extension`. It then walks the user's Start Menu, Taskbar pins and Desktop, and rewrites every .lnk whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe to add `--load-extension` pointing at the drop folder. As admin it also walks the all-users Start Menu. To see the full payload, a scanner needs Windows, a real pip install (not just a metadata build), and at least one browser shortcut in those folders.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv[1] in [bdist_wheel, install]) | then | 2 | write_file | os=win32; package_manager=setup.py run with sys.argv[1] bdist_wheel or install |
| g2 | setup_py | c1 && c3 && c6 && c4 && c5 (c1: os == win32; c3: sys.argv[1] in [bdist_wheel, install]; c6: privilege truthy; c4: target_artifact regex \.lnk$; c5: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 5 | persistence | os=win32; package_manager=setup.py run with sys.argv[1] bdist_wheel or install; privilege=root_or_admin; file_present=a *.lnk file under C:\ProgramData\Microsoft\Windows\Start Menu whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe |
| g3 | setup_py | c1 && c3 && c4 && c5 (c1: os == win32; c3: sys.argv[1] in [bdist_wheel, install]; c4: target_artifact regex \.lnk$; c5: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; package_manager=setup.py run with sys.argv[1] bdist_wheel or install; file_present=a *.lnk file anywhere under %APPDATA%\Microsoft\Windows\Start Menu, %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar or ~\Desktop whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting; g3 activate/enables/data_availability

Grounding: 2 of 5 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c3, c4, c5, g1, g2, g3.

## Requirements

- other: Python module win32com (pypiwin32) importable (the payload branch imports win32com.client.Dispatch; setup.py installs pypiwin32 via pip during the egg_info/build step if it is missing)
- network: pypi[.]org:443 (pip install pypiwin32 during the egg_info/build step when win32com is missing (host inferred from pip defaults))
- other: env var APPDATA set (the extension folder and Start Menu/Taskbar paths are built from os.getenv('APPDATA'); concatenating None raises)

## Behaviour

- Ungated: none
- Gated: write_file, persistence

## Notes

- The setup command check (c3) and the two shortcut checks (c4, c5) were missed by the extractor and were added by hand, so they are out of set.
- The extension swaps copied ETH, TRON, BNB, BTC and LTC addresses for attacker wallets (the addresses are left out here). It is written to disk and not run at install.
- The `os.path.exists` check before `makedirs` was dropped as plumbing.
- The admin check (`IsUserAnAdmin()`, c6) adds the all-users Start Menu to the folders the shortcut loop walks. The loop runs either way, but as admin it also rewrites the all-users browser shortcuts, so the check changes which shortcuts are taken. It is recorded as gate g2 with effect `modifies`.
- The egg_info-step `pip install pypiwin32` is treated as setting up a prerequisite and is listed under requirements.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "mysql-connector-pyhton",
    "version": "0.1",
    "archive_sha256": "4709764d33adc0cc3e025f1a9f9aa303b62eb77da41170ca0a1e8cd7983a403a",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/mysql-connector-pyhton-0.1.tar.gz",
    "package_root": "layer0/mysql-connector-pyhton-0.1",
    "cluster_key": "e371aa64fa9f51ca95ab1e9c801f7eba0b617b754cb06f8faebf995cfb9e538c",
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
      "setup.py: package code read in full (58 lines, no bundled code). The embedded background.js is a string written to disk, read in full as data; it is not run at install.",
      "Line 6: when sys.argv[1] is egg_info or build and win32com fails to import, setup.py calls pip's internal main to install pypiwin32. Treated as plumbing that provides the payload's prerequisite, not a gate; listed under requirements.",
      "c3 (sys.argv[1] in bdist_wheel/install) is the elif of the egg_info/build test, so reaching it also means argv[1] is not egg_info/build, which c3 already implies. A scan that only builds metadata (pip download, egg_info/dist_info) never reaches the payload.",
      "Line 26: IsUserAnAdmin() (c6) adds the all-users Start Menu to the folders the shortcut loop walks, so admins also get all-users browser shortcuts rewritten: gate g2, effect modifies.",
      "g2 reaches the sink through the paths list, not a call: its regions are the append at line 27 (under c6) and the rewrite at lines 49-50 (under c4, c5), joined with &&.",
      "Dropped g3 candidate (not os.path.exists APPDATA\\Extension, then makedirs): it only creates the drop folder when missing and the extension files are written either way, so it is plumbing.",
      "Payload: background.js is a clipboard hijacker that replaces copied ETH, TRON, BNB, BTC and LTC addresses with attacker wallets; manifest.json asks for clipboardRead/clipboardWrite. Browser shortcuts get --load-extension pointing at it.",
      "mysql-connector-pyhton/__init__.py is not reached at install."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "Python module win32com (pypiwin32) importable",
      "reason": "the payload branch imports win32com.client.Dispatch; setup.py installs pypiwin32 via pip during the egg_info/build step if it is missing"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip install pypiwin32 during the egg_info/build step when win32com is missing (host inferred from pip defaults)"
    },
    {
      "axis": "other",
      "value": "env var APPDATA set",
      "reason": "the extension folder and Start Menu/Taskbar paths are built from os.getenv('APPDATA'); concatenating None raises"
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
      "id": "c3",
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
      "id": "c4",
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
      "id": "c5",
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
      "probe": {
        "kind": "file",
        "callee": "shell.CreateShortcut",
        "target": "<Start Menu, Taskbar or Desktop folder>\\*.lnk",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3927,
            "end_byte": 4003,
            "node_type": "comparison_operator",
            "sha256": "ff3f7b2b296bb841",
            "line": 48
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "privilege",
      "api": "ctypes.windll.shell32.IsUserAnAdmin",
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
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c1 && c3",
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
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the extension drop only exists for Windows (APPDATA paths, win32com) and only runs in the wheel build/install step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install"
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
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c1 && c3 && c6 && c4 && c5",
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
            "c3"
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
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3685,
            "end_byte": 3706,
            "node_type": "call",
            "sha256": "1388f6944b986f93",
            "line": 43
          },
          "kind": "if",
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
            "start_byte": 3927,
            "end_byte": 4003,
            "node_type": "comparison_operator",
            "sha256": "ff3f7b2b296bb841",
            "line": 48
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "with admin rights the all-users Start Menu is added to the folders walked, so the same shortcut rewrite also takes the all-users browser shortcuts",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install",
          "privilege": "root_or_admin",
          "file_present": [
            "a *.lnk file under C:\\ProgramData\\Microsoft\\Windows\\Start Menu whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 713,
            "end_byte": 776,
            "node_type": "expression_statement",
            "sha256": "9b27d540b86d82ac",
            "line": 27
          },
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
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c3 && c4 && c5",
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
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3685,
            "end_byte": 3706,
            "node_type": "call",
            "sha256": "1388f6944b986f93",
            "line": 43
          },
          "kind": "if",
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
            "start_byte": 3927,
            "end_byte": 4003,
            "node_type": "comparison_operator",
            "sha256": "ff3f7b2b296bb841",
            "line": 48
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "only shortcuts whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe are rewritten to load the extension",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with sys.argv[1] bdist_wheel or install",
          "file_present": [
            "a *.lnk file anywhere under %APPDATA%\\Microsoft\\Windows\\Start Menu, %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar or ~\\Desktop whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe"
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
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "write_file",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "obfuscator.io-style string array with hex identifiers in the embedded browser extension JavaScript (dropped to disk, not run at install)",
      "very long lines (the extension source is one line)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "clipboard-hijacker browser extension via shortcut --load-extension",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, during the wheel build or install step, setup.py writes a browser extension that swaps copied cryptocurrency addresses for attacker wallets and rewrites Chrome, Edge, Brave and Opera shortcuts to load it on every launch. The name typosquats mysql-connector-python.",
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
        "note": "plumbing: only creates the APPDATA\\Extension drop folder when missing; the extension files are written either way",
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
        "note": "plumbing: guard of the makedirs for the drop folder; no behaviour differs when the folder already exists",
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
    "conditions_out_of_set": 3,
    "guard_candidates": 3,
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c3",
      "c4",
      "c5",
      "g1",
      "g2",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
