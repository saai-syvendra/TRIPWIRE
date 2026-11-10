# pypi sloana@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

All code runs from the top level of `setup.py`, which is obfuscated with chr-arithmetic strings and a flattened state machine (decoded as derivation d1). Everything sits behind `sys.platform == 'win32'` (g1). On the egg_info/build step it pip-installs pypiwin32. On the bdist_wheel/install step it writes a Chromium extension (`background.js` plus `manifest.json`) to `%APPDATA%\Extension`; the script polls the clipboard and swaps wallet addresses for attacker ones. It then walks the Start Menu, Taskbar and Desktop folders and adds `--load-extension` to every `.lnk` that targets chrome.exe, msedge.exe, brave.exe or launcher.exe (g3). With admin rights the all-users Start Menu is added to that list (g2).

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file | os=win32 |
| g2 | setup_py | c1 && c2 (c1: os == win32; c2: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |
| g3 | setup_py | c1 && c3 && c4 (c1: os == win32; c3: target_artifact regex \.lnk$; c4: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 3 | persistence | os=win32; file_present=a .lnk file anywhere under %APPDATA%\Microsoft\Windows\Start Menu, %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar or ~\Desktop whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting; g3 activate/enables/targeting

Grounding: 2 of 4 conditions and 2 of 3 gates from the candidate set; out of set, pending verification: c3, c4, g3.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (egg_info step pip-installs pypiwin32, which the later step needs for win32com (unless pywin32 is already present))
- other: pywin32 (win32com.client) importable in the build interpreter (the install/bdist_wheel step imports win32com.client.Dispatch to edit shortcuts; ImportError aborts the payload)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The `sys.argv[1]` checks pick which build step runs which part. A normal pip install of the sdist runs both steps, so I did not record them as gates (see execution.notes).
- The extension drop does not depend on any shortcut. Persistence (the shortcut rewrite) needs an existing browser shortcut, so a fresh VM with no Chrome, Edge or Brave shortcut gets the files written but no shortcut changed.
- g2 and g3 only set the next state number, and the `Save()` sink runs in a later state. For g3 that state (60921) is assigned only inside the c4 block, so its arm is cited as a second region. g2's payload witness stays unresolved, because the state chain after it also runs without admin rights. A reviewer should check the state order in d1 lines 36-127.
- I dropped the `%APPDATA%\Extension` exists check as plumbing (mkdir if missing).
- I left the attacker wallet addresses in the JS out of the record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "sloana",
    "version": "0.1",
    "archive_sha256": "cec9f94349348a10fd012ac2e8cc034e80fc9f31d5191a37c9f16f73ddf6a276",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/sloana-0.1.tar.gz",
    "package_root": "layer0/sloana-0.1",
    "cluster_key": "1eea634df504fced877e46f8211c5ea7281f75a8687eca27978f567cfca4aabf",
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
      "setup.py: tool did not decode it; strings are chr() joins of shift arithmetic. Decoded with the existing chr_shift_join decoder as derivation d1; package code read in full in d1; nothing unread. sloana/__init__.py is empty.",
      "Inside the win32 block the code dispatches on sys.argv[1]: egg_info/build runs pip.main(['install','pypiwin32']); bdist_wheel/install runs the extension drop. A normal pip sdist install runs both steps, so this is install-step dispatch, not an environment gate.",
      "Control flow is flattened into while/state-number loops. State order (install branch): import os, ctypes, win32com Dispatch, APPDATA, Desktop, folder list, admin check, mkdir, write background.js and manifest.json, walk .lnk files.",
      "Dead code: the egg_info loop's state 286625773 (try import win32com with a junk arithmetic loop) is never reached because state goes 108363 -> 0.",
      "The admin gate (g2) and the browser shortcut gate (g3) only set the next state number; the guarded sink (shortcut Save) runs in a later state of the same loop. g2's witness stays unresolved; g3 cites that state as a region (see below).",
      "g2 path in d1: admin block sets state 362814 (line 66), which appends the ProgramData Start Menu (46), then 18005, 37668, 382664, 12768, 162346, 4030, 145239, 186387, 790593, whose os.walk loop reaches Save (101) for shortcuts in that folder. The witness stops at the state assignment.",
      "g3 path in d1: the c4 block sets inner state 60921 (line 93), its only assignment; the elif for 60921 runs Save (101). Save needs c4, so that arm (101-102) is a second g3 region holding the sink.",
      "g3's 60921 arm is outside the c4 if but inside the c1 and c3 guards. g3's c1 guard is cited on d1 so its guards and regions share a file.",
      "g2's region is only the admin if's then block; the state that appends the ProgramData Start Menu folder is a separate elif reached via the state number, so it is not a region.",
      "If win32com is not importable in the build env (pywin32 missing), the install branch raises ImportError and the build fails before writing anything; errors are not swallowed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "egg_info step pip-installs pypiwin32, which the later step needs for win32com (unless pywin32 is already present)"
    },
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable in the build interpreter",
      "reason": "the install/bdist_wheel step imports win32com.client.Dispatch to edit shortcuts; ImportError aborts the payload"
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
      "id": "c4",
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
            "start_byte": 8351,
            "end_byte": 8428,
            "node_type": "call",
            "sha256": "60ceda81e375a2de",
            "line": 98
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
      "expression": "c1",
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
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the whole payload (win32com shortcuts, APPDATA browser extension) exists only for Windows; other OSes just run setup()",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 327,
            "end_byte": 66981,
            "node_type": "block",
            "sha256": "a09055fcd6f076ed",
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
              "start_byte": 1185,
              "end_byte": 1794,
              "node_type": "call",
              "sha256": "79499be5970a633f",
              "line": 13
            },
            "witness": []
          },
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
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c1 && c2",
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
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "as admin it adds the all-users Start Menu (ProgramData) to the folders whose browser shortcuts get rewritten",
      "then": {
        "min_conditions": 2,
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
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 60459,
              "end_byte": 60514,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 104
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 10700,
                  "end_byte": 10815,
                  "node_type": "assignment",
                  "sha256": "14ea991301de820f",
                  "line": 69
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
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c3 && c4",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 60,
            "end_byte": 10188,
            "node_type": "if_statement",
            "sha256": "262fab7a5294e118",
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
            "start_byte": 7019,
            "end_byte": 8697,
            "node_type": "if_statement",
            "sha256": "03f4280a43d774bf",
            "line": 82
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
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
      "purpose": "targeting",
      "purpose_reason": "only shortcuts (.lnk) in Start Menu, Taskbar or Desktop that launch Chrome, Edge, Brave or launcher.exe get the --load-extension argument",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "a .lnk file anywhere under %APPDATA%\\Microsoft\\Windows\\Start Menu, %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar or ~\\Desktop whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe"
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
      "write_file",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "very long lines",
      "strings built as chr() joins of bit-shift arithmetic, chr fetched via getattr on builtins reprs",
      "control-flow flattening with integer state machine and opaque arithmetic state values",
      "CJK-character identifier names",
      "dead state branch with junk arithmetic loop"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "lnk-load-extension crypto clipper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, setup.py installs pypiwin32, writes a Chromium extension to %APPDATA%\\Extension whose background script swaps crypto wallet addresses in the clipboard for attacker addresses, and rewrites browser shortcuts to load it with --load-extension.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
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
        "output_sha256": "f47064b2839f8536"
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
        "note": "plumbing: tests whether %APPDATA%\\Extension exists only to create it; both sides go on to write the extension files",
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
        "note": "plumbing: guard of the mkdir-if-missing check on %APPDATA%\\Extension; both sides write the extension",
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
    "conditions_out_of_set": 2,
    "guard_candidates": 3,
    "gates_in_set": 2,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c3",
      "c4",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
