# pypi propt-toolkit@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`propt-toolkit` (a likely typosquat of the popular `prompt-toolkit`) ships a single heavily obfuscated `setup.py` that runs under setuptools on any `pip install` of the sdist. Every string is built with `''.join(map(chr, [junk arithmetic]))` and the logic is control-flow-flattened into a `while`-loop state machine with CJK variable names; the adopted `py_chr_shift_fold` decoder (derived copy `d4`) recovers the plaintext and folds the state arithmetic to concrete integers. The whole payload is gated by `sys.platform == 'win32'` (g1): it calls `pip.main(['install','pypiwin32'])`, creates `%APPDATA%\Extension`, and writes a malicious browser extension (`manifest.json` + `background.js`) whose `background.js` watches the clipboard and rewrites copied BTC/ETH/TRON/BNB/LTC/XRP/DOGE/Cardano/Monero/Stellar/Cosmos wallet addresses to attacker-controlled ones. It then walks the Start Menu, Taskbar and Desktop and, for shortcuts whose target is a browser (`chrome.exe`/`msedge.exe`/`brave.exe`/`launcher.exe`, g3), rewrites them to launch with `--load-extension=%APPDATA%\Extension`, so the extension loads on next browser start (persistence). If the install runs with admin rights (g2) it also hijacks the all-users `C:\ProgramData\...\Start Menu` shortcuts.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file | os=win32 |
| g2 | setup_py | c1 && c2 (c1: os == win32; c2: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |
| g3 | setup_py | c1 && c4 (c1: os == win32; c4: target_artifact in [chrome.exe, msedge.exe, launcher.exe, brave.exe]) | then | 2 | persistence | os=win32; file_present=%APPDATA%\Microsoft\Windows\Start Menu\*.lnk (any depth, os.walk) whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe (the same holds for %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar or ~\Desktop) |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/portability; g3 activate/enables/targeting

Grounding: 2 of 3 conditions and 2 of 3 gates from the candidate set; out of set, pending verification: c4, g3.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (pip.main(['install','pypiwin32']) downloads the pypiwin32 (pywin32) package from PyPI at build time)
- installed_tool: pip (imports pip and calls pip.main to install the pypiwin32 dependency)
- other: win32com (pywin32) module importable (needs win32com.client.Dispatch to create and modify .lnk shortcuts; the package installs pypiwin32 itself via pip.main)
- other: APPDATA environment variable set (writes the browser extension under %APPDATA%\Extension and reads os.getenv('APPDATA'))

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- Gates: g1 `os == win32` (master, enables the whole dropper); g2 `win32 && admin` (modifies/broadens the hijack target set to system-wide shortcuts); g3 `win32 && browser-shortcut-present` (enables the shortcut rewrite only for browser `.lnk` files). c1's value and c4 were recovered from the decoded copy `d4`.
- The `sys.argv[1]` check (`egg_info`/`build` vs `bdist_wheel`/`install`) only selects the install phase; both phases run during a normal `pip install`, so it is not a machine-environment gate. It was left out and noted.
- Dropped the extractor's c3/old-g3 (`os.path.exists(%APPDATA%\Extension)`): it is create-dir-if-missing plumbing (the absent branch calls `os.makedirs`, then both paths write the extension), not a behaviour-selecting gate.
- Because of the control-flow flattening, each gate's guard, region and sink are separate dispatched states; all are anchored in `d4`. g3's regions are the then block of the browser test and the state 60921 arm holding `Save()`, which only that block jumps to. g2's region is the admin state that appends the all-users folder; `Save()` also runs without it, so g2's path through the folder list stays unresolved `dynamic_dispatch`. That and the out-of-set c4/g3 claims are why the record is flagged for manual review.
- No hardcoded C2: `needs_remote` is true only because `pip.main` fetches `pypiwin32` from PyPI; the attacker wallet addresses are clipboard-replacement targets, not network endpoints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "propt-toolkit",
    "version": "0.1",
    "archive_sha256": "ff2cbfec50bcb2531e29c02eb0ea9e8f74bed84abdfd4b203b32586671ae8292",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/propt-toolkit-0.1.tar.gz",
    "package_root": "layer0/propt-toolkit-0.1",
    "cluster_key": "4bb684c6ab106a1d82e828426470754679c49add8df97dd80dee604f13827a11",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
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
      "setup.py: package code read in full via decoded copy derived/d4 (adopted decoder py_chr_shift_fold replaces the ''.join(map(chr,[arithmetic])) string building and folds the junk state arithmetic to concrete integers; output_sha256 matched). Nothing unread; no third-party/bundled code.",
      "Heavy obfuscation: control flow flattened into a while-loop state machine dispatched on junk integer arithmetic, with CJK identifier names. d4 folds every state to a literal, so the dispatch order is explicit.",
      "sys.argv[1] in ['egg_info','build'] vs ['bdist_wheel','install'] selects the install phase, not a machine-environment gate; both run during a normal pip install (egg_info/build installs pypiwin32, bdist_wheel/install drops the payload).",
      "win32com import is wrapped in try/except ModuleNotFoundError (a dead junk loop; state 286625773 is never reached) and is the only swallowed error. The payload is not wrapped, so entry silent_failure is false.",
      "Dropped c3/old-g3 (os.path.exists(%APPDATA%/Extension)): create-dir-if-missing plumbing; if absent it jumps to os.makedirs then both paths converge on state 37668 which writes the extension, so not a behaviour-selecting gate.",
      "Control-flow flattening means each gate's guard, region and sink are separate dispatched states, anchored in d4. g2's region is the code its guard leads to, and Save() is reached from there by state jumps. g3's regions hold the Save() state itself.",
      "c1 value 'win32' is recovered from derived/d4; the condition anchor is kept on the original obfuscated comparison bytes.",
      "Repair: decode spot-checked against the original bytes (the chr arithmetic at line 6 gives 'win32', the first sys.argv list item gives 'egg_info', and the getattr pieces build 'chr'), matching d4.",
      "Repair: g2's admin state only appends the all-users Start Menu to the folder list; Save() in state 790593 rewrites the shortcuts, reached by state dispatch, so g2's sink is that Save() with unresolved dynamic_dispatch.",
      "Repair: g3 path traced in d4: state 790593 walks each folder, CreateShortcut (86892) -> basename(TargetPath) (9653) -> browser test (61499, c4) -> Arguments set, then Save() (60921).",
      "Repair: g3's first region is the then block of the c4 test (Arguments set, jump to 60921), not the whole while loop, which is entered before the test.",
      "Repair: g3's second region is the state 60921 arm (Save(), state reset). In d4 the only assignment of 60921 is line 92 in c4's then block, so this arm is flattened c4 then code; Save() sits in the region, the empty witness holds and g3 needs no unresolved mark.",
      "Repair: g2 keeps unresolved dynamic_dispatch. Save() also runs without c2 (user Start Menu, Taskbar, Desktop); c2 only adds a folder to the list the walk reads, a data link no witness hop expresses, so the Save() state is not added as a g2 region."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "pip.main(['install','pypiwin32']) downloads the pypiwin32 (pywin32) package from PyPI at build time"
    },
    {
      "axis": "installed_tool",
      "value": "pip",
      "reason": "imports pip and calls pip.main to install the pypiwin32 dependency"
    },
    {
      "axis": "other",
      "value": "win32com (pywin32) module importable",
      "reason": "needs win32com.client.Dispatch to create and modify .lnk shortcuts; the package installs pypiwin32 itself via pip.main"
    },
    {
      "axis": "other",
      "value": "APPDATA environment variable set",
      "reason": "writes the browser extension under %APPDATA%\\Extension and reads os.getenv('APPDATA')"
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
      "api": "os.path.basename",
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
            "derived_from": "d4",
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
      "purpose_reason": "The whole dropper sits inside `if sys.platform == 'win32'` and uses Windows-only APIs (ctypes.windll, win32com, %APPDATA%); there is no non-Windows branch, so it only runs on Windows victims.",
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
            "derived_from": "d4",
            "start_byte": 89,
            "end_byte": 10044,
            "node_type": "if_statement",
            "sha256": "1a8d99e188f0f353",
            "line": 7
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 335,
              "end_byte": 369,
              "node_type": "call",
              "sha256": "948b17ff4b80f1be",
              "line": 13
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 2930,
              "end_byte": 3007,
              "node_type": "call",
              "sha256": "e9132f12380d1978",
              "line": 55
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 3819,
              "end_byte": 5880,
              "node_type": "call",
              "sha256": "45a3175521bf1aa3",
              "line": 69
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 9772,
              "end_byte": 9982,
              "node_type": "call",
              "sha256": "4c6a9e310e779ce2",
              "line": 125
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
      "purpose": "portability",
      "purpose_reason": "When the install runs as admin it appends the system-wide 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu' to the list of folders whose .lnk shortcuts get hijacked; the check only includes the all-users folder when the process has the rights to rewrite shortcuts there (Save() is not wrapped in try), so it adapts the same hijack to the privilege level rather than selecting victims.",
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
            "derived_from": "d4",
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
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 8435,
              "end_byte": 8490,
              "node_type": "call",
              "sha256": "4121e2954f13e471",
              "line": 100
            },
            "witness": [],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
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
            "derived_from": "d4",
            "start_byte": 7539,
            "end_byte": 7999,
            "node_type": "if_statement",
            "sha256": "e800ec7e59b56a28",
            "line": 90
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
      "purpose_reason": "A shortcut is only rewritten with the malicious --load-extension argument when its target executable is a browser (chrome.exe/msedge.exe/brave.exe/launcher.exe); non-browser .lnk files are skipped, so the extension-hijack only targets browser users.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%\\Microsoft\\Windows\\Start Menu\\*.lnk (any depth, os.walk) whose TargetPath basename is chrome.exe, msedge.exe, launcher.exe or brave.exe (the same holds for %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar or ~\\Desktop)"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d4",
            "start_byte": 7664,
            "end_byte": 7999,
            "node_type": "stmt_range",
            "sha256": "3b96bbe6f6d6372c",
            "line": 91
          },
          {
            "file": "setup.py",
            "derived_from": "d4",
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
              "derived_from": "d4",
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
      "very long physical lines",
      "control-flow flattening via an integer state-machine dispatch",
      "string literals built with ''.join(map(chr, <integer arithmetic>))",
      "opaque junk arithmetic assignments",
      "non-ASCII (CJK) identifier names"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "windows clipboard-clipper browser-extension dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The heavily obfuscated setup.py is a Windows-only install-time dropper: it installs pypiwin32, writes a browser extension under %APPDATA%\\Extension whose background.js replaces copied cryptocurrency wallet addresses with attacker addresses, and rewrites Chrome/Edge/Brave shortcuts to auto-load that extension via --load-extension. Clearly malicious with no legitimate function.",
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
        "id": "d4",
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
        "output_sha256": "c1956635a8d89ad3"
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
        "note": "os.path.exists(%APPDATA%/Extension) is a create-dir-if-missing plumbing check; both branches converge on writing the extension, so not a behaviour-selecting gate.",
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
        "note": "Guards the create-dir-if-missing plumbing check dropped as c3; not a behaviour-selecting gate.",
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
      "c4",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
