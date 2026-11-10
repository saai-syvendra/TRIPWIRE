# pypi etnsorflow@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs at build time and is heavily obfuscated: strings are built from `chr` codes, integer states are opaque expressions, and control flow is flattened into a state machine. A registered candidate decoder (`chr_shift_join`, derivation d1) recovers it. Everything sits behind `sys.platform == 'win32'` and then dispatches on `sys.argv[1]`. The `egg_info`/`build` step runs `pip.main(['install','pypiwin32'])`. The `bdist_wheel`/`install` step writes a Chrome extension (`%APPDATA%\Extension`, a clipboard crypto-address clipper) and walks the Desktop, Start Menu and Taskbar folders. Every `.lnk` there whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe gets `--load-extension` added, and an admin check adds the all-users Start Menu to that list. Opening the gates needs Windows and, for the persistence step, a Chromium browser shortcut in one of those folders.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c6 (c1: os == win32; c6: other in [egg_info, build]) | then | 2 | download | os=win32 |
| g2 | setup_py | c1 && c7 && c2 (c1: os == win32; c7: other in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; privilege=root_or_admin |
| g3 | setup_py | c1 && c7 (c1: os == win32; c7: other in [bdist_wheel, install]) | then | 2 | write_file | os=win32 |
| g4 | setup_py | c1 && c7 && c5 && c4 (c1: os == win32; c7: other in [bdist_wheel, install]; c5: target_artifact regex \.lnk$; c4: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 4 | persistence | os=win32; file_present=%USERPROFILE%\Desktop\*.lnk (any name, any subfolder) whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe; %APPDATA%\Microsoft\Windows\Start Menu and %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar are scanned the same way |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting; g3 activate/enables/targeting; g4 activate/enables/data_availability

Grounding: 2 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c4, c5, c6, c7, g1, g2, g3, g4.

## Requirements

- runtime_version: pip<10 (egg_info step calls pip.main, which newer pip lacks; the AttributeError aborts the install before the payload branch)
- network: pypi[.]org:443 (pip.main installs pypiwin32 from the default index during egg_info)
- other: pywin32 (win32com.client) importable by the build interpreter (payload branch imports win32com.client.Dispatch to edit shortcuts; it is installed by the egg_info step)

## Behaviour

- Ungated: none
- Gated: download, persistence, write_file

## Notes

- `pip.main` was removed in pip 10. On a modern pip the `egg_info` step fails and the install aborts before the payload branch, so the payload needs pip<10 or a direct `setup.py install`.
- The `argv` conditions (c6, c7) are recorded as out-of-scope `other`; a normal pip install hits both branches in sequence.
- c4/c5 and the `argv` guards are out of set because the extractor could not see through the flattened control flow. The c2 gate's payload is reached through later dispatcher states, so its witness is empty and marked `computed_callee`.
- The decoder is a candidate in `scratch/pypi__etnsorflow@0.1/decoders/chr_shift_join.py` and needs review. One wrapped `chr` join (pypiwin32) was decoded by hand.
- The wallet addresses in the extension are not recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "etnsorflow",
    "version": "0.1",
    "archive_sha256": "b87e996b2f18dedc872c84462b5190233807f84d16ac6c48af4d3a78ce7efa73",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/etnsorflow-0.1.tar.gz",
    "package_root": "layer0/etnsorflow-0.1",
    "cluster_key": "594e1236dc601587e42437b5c77112dbd9d395824e273cbdd7323409b64e4bd4",
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
      "setup.py: not recovered by prepare.py (chr built via getattr on builtins, shift arithmetic, opaque integer states). Registered candidate decoder chr_shift_join (derivation d1) folding constant ints and chr-joins; d1 read in full, nothing unread.",
      "One join in d1 line 13 stays unfolded because the getter text is line-wrapped; its codes 112,121,112,105,119,105,110,51,50 spell pypiwin32 (decoded by hand as data).",
      "Code is control-flow flattened: while loops over a state variable. State 286625773 in the egg_info branch (try import win32com plus junk arithmetic loop) is never assigned, so it is dead code.",
      "sys.argv[1] dispatch: egg_info/build branch runs pip.main(['install','pypiwin32']); bdist_wheel/install branch drops the extension and patches shortcuts. A normal pip install runs egg_info then bdist_wheel (or install), so both branches run in sequence.",
      "d1 state chain traced by hand: 83520, 8473, 12258, 183269, 28669, 1929, 383984 (admin: 362814), 18005 (29059), 37668, 382664, 12768, 162346, 4030, 145239, 186387, 790593 (walk, Save). No hop kind fits a state transition, so g2's Save path stays unresolved.",
      "pip.main was removed in pip 10, so on a modern pip the egg_info step raises AttributeError (or ImportError for pip in an isolated build env) and the install aborts before the payload branch. Payload needs pip<10 or a direct python setup.py install/bdist_wheel.",
      "c3 (os.path.exists on %APPDATA%\\Extension) only decides whether to makedirs the folder; both sides go on to write the extension, so it is plumbing and dropped.",
      "c2 (IsUserAnAdmin) adds the ProgramData Start Menu to the scanned folders; modifies gate, regions d1 lines 65-67 and 46-47. Save() (line 101) is reached via state dispatch: bind hop line 47, computed_callee.",
      "The dropped background.js replaces cryptocurrency wallet addresses in the clipboard with attacker addresses every second (clipper); manifest.json is named Windows and asks for clipboardRead/clipboardWrite. Runs later in the browser, covered by write_file and persistence."
    ]
  },
  "requirements": [
    {
      "axis": "runtime_version",
      "value": "pip<10",
      "reason": "egg_info step calls pip.main, which newer pip lacks; the AttributeError aborts the install before the payload branch"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip.main installs pypiwin32 from the default index during egg_info"
    },
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable by the build interpreter",
      "reason": "payload branch imports win32com.client.Dispatch to edit shortcuts; it is installed by the egg_info step"
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
            "start_byte": 7686,
            "end_byte": 7795,
            "node_type": "comparison_operator",
            "sha256": "7c422ae20ab5c615",
            "line": 91
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "str.endswith (os.walk file names under Desktop, Start Menu, Taskbar)",
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
            "start_byte": 7022,
            "end_byte": 7087,
            "node_type": "call",
            "sha256": "8d116359f4d6412c",
            "line": 82
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "other",
      "api": "sys.argv[1]",
      "operator": "in",
      "value": [
        "egg_info",
        "build"
      ],
      "value_recovered": "decoded",
      "in_scope": false,
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
      "id": "c7",
      "category": "other",
      "api": "sys.argv[1]",
      "operator": "in",
      "value": [
        "bdist_wheel",
        "install"
      ],
      "value_recovered": "decoded",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 1746,
            "end_byte": 1787,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 35
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
      "expression": "c1 && c6",
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
            "end_byte": 10188,
            "node_type": "if_statement",
            "sha256": "41dc6ac4d90f4987",
            "line": 7
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
      "purpose_reason": "Windows only payload; argv picks the metadata step to install pypiwin32 that the later payload step needs",
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
            "end_byte": 1739,
            "node_type": "stmt_range",
            "sha256": "a5ed0ab37921334b",
            "line": 8
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 335,
              "end_byte": 519,
              "node_type": "call",
              "sha256": "9d6fc38c406fd671",
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
      "expression": "c1 && c7 && c2",
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
            "start_byte": 1746,
            "end_byte": 1787,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 35
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c7"
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
      "purpose_reason": "as admin the all-users Start Menu is added to the folders whose browser shortcuts get patched; non-admin runs the same patching on the per-user folders only",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
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
            "start_byte": 2372,
            "end_byte": 2539,
            "node_type": "stmt_range",
            "sha256": "a2d4643aa70e2799",
            "line": 46
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8579,
              "end_byte": 8634,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 101
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2483,
                  "end_byte": 2539,
                  "node_type": "assignment",
                  "sha256": "f898a0567e0aa50e",
                  "line": 47
                }
              }
            ],
            "unresolved": "computed_callee"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c7",
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
            "start_byte": 1746,
            "end_byte": 1787,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 35
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the browser-extension clipper only exists for Windows; argv runs it in the wheel build or install step",
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
            "start_byte": 1791,
            "end_byte": 10188,
            "node_type": "stmt_range",
            "sha256": "eb2d288176163f01",
            "line": 36
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 3963,
              "end_byte": 6024,
              "node_type": "call",
              "sha256": "45a3175521bf1aa3",
              "line": 70
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 6209,
              "end_byte": 6300,
              "node_type": "call",
              "sha256": "69ad0d770586e920",
              "line": 73
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
      "expression": "c1 && c7 && c5 && c4",
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
            "start_byte": 1746,
            "end_byte": 1787,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 35
          },
          "kind": "elif",
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
            "start_byte": 7019,
            "end_byte": 8697,
            "node_type": "if_statement",
            "sha256": "03f4280a43d774bf",
            "line": 82
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
            "start_byte": 7683,
            "end_byte": 8143,
            "node_type": "if_statement",
            "sha256": "e800ec7e59b56a28",
            "line": 91
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
      "purpose": "data_availability",
      "purpose_reason": "only shortcuts whose target is a Chromium browser get --load-extension added and saved",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%\\Desktop\\*.lnk (any name, any subfolder) whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe; %APPDATA%\\Microsoft\\Windows\\Start Menu and %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar are scanned the same way"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 7808,
            "end_byte": 8143,
            "node_type": "stmt_range",
            "sha256": "3b96bbe6f6d6372c",
            "line": 92
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8579,
            "end_byte": 8697,
            "node_type": "stmt_range",
            "sha256": "e2eba9988992058b",
            "line": 101
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8579,
              "end_byte": 8634,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 101
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
      "persistence",
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "very long lines",
      "strings built from chr code points via getattr on builtins with shift arithmetic",
      "opaque constant integer expressions",
      "control-flow flattening (state-machine dispatch)",
      "CJK identifier renaming",
      "dead code (unreachable state with junk arithmetic loop)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "lnk-patching browser-extension crypto clipper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the setup.py installs pypiwin32, writes a Chrome extension that swaps cryptocurrency addresses in the clipboard, and patches Chromium browser shortcuts with --load-extension so it loads on every launch. Typosquat of tensorflow.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "payload only reachable with pip<10 (pip.main) or a direct setup.py install; check whether Phase 2 should provision an old pip",
    "decode via candidate decoder chr_shift_join needs review",
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
          "chr_getter": "getattr(__builtins__, oct.__str__()[-3 << 0] + hex.__str__()[-1 << 2] + copyright.__str__()[4 << 0])",
          "decoder": "chr_shift_join",
          "lang": "py"
        },
        "output_sha256": "6e8537c80930b3da"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44c82ac8af",
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to makedirs the folder; both sides write the extension",
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
        "note": "plumbing: guard of the folder-exists check (k_648bbff21c); both sides continue to the extension write",
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
