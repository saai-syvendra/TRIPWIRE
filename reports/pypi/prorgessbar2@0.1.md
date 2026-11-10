# pypi prorgessbar2@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

All install-time code is top-level code in `setup.py`, which pip runs while building the sdist. The code is obfuscated with chr-from-arithmetic strings and flattened state machines. It was decoded with the `chr_shift_join` decoder (derivation d1). Everything sits behind `sys.platform == 'win32'` (g1). On Windows the egg_info/build step runs `pip.main(['install', 'pypiwin32'])`. The bdist_wheel/install step then writes a browser extension to `%APPDATA%\Extension`: a manifest plus a background.js that swaps crypto wallet addresses on the clipboard for attacker addresses. Next, the code walks the Desktop, user Start Menu and pinned TaskBar shortcuts, and also the all-users Start Menu when `IsUserAnAdmin()` is true (g2). Each shortcut that targets chrome.exe, msedge.exe, launcher.exe or brave.exe (g3) is rewritten to start the browser with `--load-extension`. So the environment that opens the gates is a Windows build with pywin32 importable and at least one Chromium-browser shortcut, plus admin rights to reach the all-users shortcuts.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file | os=win32 |
| g2 | setup_py | c1 && c2 (c1: os == win32; c2: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |
| g3 | setup_py | c1 && c3 (c1: os == win32; c3: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 2 | persistence | os=win32; file_present=a .lnk file anywhere under %APPDATA%\Microsoft\Windows\Start Menu, %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar or ~\Desktop whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting; g3 activate/enables/data_availability

Grounding: 2 of 3 conditions and 2 of 3 gates from the candidate set; out of set, pending verification: c3, g3.

## Requirements

- other: python module win32com (pywin32) importable by the build interpreter (unguarded from win32com.client import Dispatch before the dropper; ImportError aborts the build)
- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (egg_info/build step runs pip.main(['install', 'pypiwin32']) against the configured index (default PyPI))
- other: env var APPDATA set (Windows default) (extension folder and shortcut paths are built from os.getenv('APPDATA'); None would raise)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The tool did not recover the strings. The decoded copy d1 was read in full, so nothing is left unread. The g3 condition and guard are out of set, because the extractor never saw the decoded browser-name test.
- The g2 and g3 payloads are linked to `Save()` through state-variable values rather than calls, so they are marked `unresolved: dynamic_dispatch`. The g2 witness stops at the state assignment in its region. The g3 witness cites where the `Save()` receiver is bound (`CreateShortcut`, d1 line 87); the state hop from the region to the `Save()` arm cannot be expressed as a hop.
- `Save()` is outside both regions. For g2 it also runs without admin, on the user folders; admin only adds the all-users Start Menu to the walk. For g3 it runs only after the browser-name test passes, through state 60921.
- The `sys.argv[1]` split (egg_info/build vs bdist_wheel/install) was not recorded as a gate: a normal pip sdist install runs both steps.
- Under pip build isolation, the unguarded `from win32com.client import Dispatch` may fail even after the pypiwin32 install. Dynamic runs may need `--no-build-isolation` or pywin32 already visible. This was not verified.
- The wallet addresses in the dropped script are attacker indicators. They are not reproduced here.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "prorgessbar2",
    "version": "0.1",
    "archive_sha256": "3066e9a9816fab39e178de81e631919136675f421778ce29fd84c70ff14984ae",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/prorgessbar2-0.1.tar.gz",
    "package_root": "layer0/prorgessbar2-0.1",
    "cluster_key": "be903ca9b8e1bb6f46d200e2e7eae3a8ee64bfed615a7332693a583d9e0726f3",
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
      "setup.py: tool did not recover strings (chr code points built from shift arithmetic, chr fetched via getattr(__builtins__)); registered decoder chr_shift_join as d1. Decoded copy read in full, every state of both state machines traced; nothing unread.",
      "Top-level code under sys.platform == 'win32' picks a step by sys.argv[1]: 'egg_info'/'build' runs pip.main install pypiwin32; 'bdist_wheel'/'install' runs the dropper. A normal pip sdist install runs both steps in turn, so this is staging, not an environmental gate.",
      "Dropper: writes a Chrome-style extension (manifest.json + background.js clipboard hijacker swapping crypto wallet addresses for attacker ones) to %APPDATA%\\Extension, then walks Start Menu, TaskBar and Desktop .lnk files.",
      "For each shortcut whose target is chrome.exe, msedge.exe, launcher.exe or brave.exe it sets Arguments to --load-extension=<APPDATA>\\Extension and saves it, so the browser loads the clipper at every launch.",
      "Control flow is flattened into while loops over opaque integer states; gate regions and Save()/write sinks are linked by state values, not calls, so the g2/g3 payloads are marked unresolved dynamic_dispatch.",
      "The g2 witness stops at the state assignment in its region. The g3 witness cites the Save() receiver's binding (CreateShortcut, d1 line 87); its state hop to the Save() arm has no hop kind.",
      "g2: the admin block only sets state 362814, whose arm appends C:\\ProgramData Start Menu to the folder list. Save() is not in the block and also runs without admin, on the user folders. The gate only adds all-users shortcuts to the walk (effect modifies).",
      "g3: the region sets Arguments and state 60921. Save() sits in the separate arm for 60921 (d1 line 100), and that assignment is the only one of 60921, so Save() runs only after the browser-name test passes.",
      "State 286625773 in the egg_info loop (try import win32com, fallback arithmetic) is never assigned, so it is dead code. os.path.exists check before os.makedirs of the Extension folder is plumbing (dropped).",
      "from win32com.client import Dispatch is unguarded in the bdist_wheel/install loop; under pip build isolation the pypiwin32 installed by the egg_info step may not be importable, so the dropper likely only completes without isolation or when pywin32 is already visible (not verified)."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module win32com (pywin32) importable by the build interpreter",
      "reason": "unguarded from win32com.client import Dispatch before the dropper; ImportError aborts the build",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 8833,
          "end_byte": 8869,
          "node_type": "import_from_statement",
          "sha256": "919030ccf606d5c3",
          "line": 108
        }
      ]
    },
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "egg_info/build step runs pip.main(['install', 'pypiwin32']) against the configured index (default PyPI)"
    },
    {
      "axis": "other",
      "value": "env var APPDATA set (Windows default)",
      "reason": "extension folder and shortcut paths are built from os.getenv('APPDATA'); None would raise"
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
      "value_site": {
        "file": "setup.py",
        "derived_from": "d1",
        "start_byte": 79,
        "end_byte": 86,
        "node_type": "string",
        "sha256": "79447999dfa004d7",
        "line": 6
      },
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
      "value_site": {
        "file": "setup.py",
        "derived_from": "d1",
        "start_byte": 7738,
        "end_byte": 7795,
        "node_type": "list",
        "sha256": "531e1824f49dd447",
        "line": 91
      },
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
      "purpose_reason": "the whole payload (pywin32 install, browser extension drop, shortcut hijack) only exists for Windows",
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
      "purpose_reason": "as admin, the all-users Start Menu (C:\\ProgramData) is added to the folders whose browser shortcuts are hijacked",
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
      "expression": "c1 && c3",
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
            "start_byte": 7683,
            "end_byte": 8143,
            "node_type": "if_statement",
            "sha256": "e800ec7e59b56a28",
            "line": 91
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
      "purpose": "data_availability",
      "purpose_reason": "only .lnk shortcuts that target a Chromium browser are rewritten to load the dropped extension",
      "then": {
        "min_conditions": 2,
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
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
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
                  "start_byte": 7300,
                  "end_byte": 7522,
                  "node_type": "assignment",
                  "sha256": "b21d2bfd2f438e60",
                  "line": 87
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
    "level": "heavy",
    "techniques": [
      "very long lines",
      "strings built as ''.join(map(chr, [...])) with chr fetched by getattr(__builtins__) from builtin repr characters",
      "char codes and state constants written as shift/bitwise arithmetic",
      "control-flow flattening into while loops over opaque integer states",
      "CJK-character identifier renaming",
      "dead state branch"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "browser-shortcut clipper extension dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the sdist build installs pypiwin32, drops a browser extension whose background script swaps crypto wallet addresses on the clipboard, and rewrites Chrome/Edge/Brave shortcuts to load it with --load-extension. The name typosquats progressbar2.",
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
        "output_sha256": "1db419a8236af939"
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to makedirs; both sides go on to write the same extension files",
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
        "note": "plumbing: guard of the folder-exists check before os.makedirs; both sides continue to the same extension write",
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
    "conditions_out_of_set": 1,
    "guard_candidates": 3,
    "gates_in_set": 2,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c3",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
