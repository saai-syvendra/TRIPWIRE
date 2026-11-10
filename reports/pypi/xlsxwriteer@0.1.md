# pypi xlsxwriteer@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`xlsxwriteer` is a typosquat of the popular `XlsxWriter` package whose `setup.py` runs a heavily obfuscated payload at install (sdist build, `setup_py` hook). All real behaviour is wrapped in `if sys.platform == 'win32'`, so it only runs on Windows (gate g1, targeting). During a normal `pip install`, a `sys.argv[1]` check routes the `egg_info`/`build` phase to `pip.main(['install','pywin32'])` (so `win32com` is importable) and the `bdist_wheel`/`install` phase to the real payload: it reads `%APPDATA%`, creates `%APPDATA%\Extension` if it is missing, writes `manifest.json` and `background.js` (a Chrome/Edge extension using `chrome.*` APIs), then walks the `.lnk` files in the Start Menu folders and, for browser shortcuts, uses `win32com` `Dispatch('WScript.Shell').CreateShortcut(...)` to set a `--load-extension` argument. An `IsUserAnAdmin()` check (g2, modifies, targeting) adds the machine-wide `C:\ProgramData\Microsoft\Windows\Start Menu` folder to the shortcut folders, so with admin rights the shared shortcuts are rewritten too.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, download_then_exec.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file, persistence | os=win32 |
| g2 | setup_py | c1 && c2 (c1: os == win32; c2: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting

Grounding: 2 of 2 conditions and 2 of 2 gates from the candidate set.

## Requirements

- network: pypi[.]org:443 (pip.main(['install','pywin32']) fetches pywin32 from PyPI at install so win32com is importable for the WScript.Shell COM persistence)
- installed_tool: pip (the payload calls pip.main in-process to install pywin32)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- Obfuscation is heavy: every string is built by `map(chr, [<bit-shift integer>...])` where `chr` is fetched as `getattr(__builtins__, oct.__str__()[-3]+hex.__str__()[-4]+copyright.__str__()[4])`, and control flow is flattened into three `while` dispatch loops (lines 10, 38, 88; loop C nested in loop B) keyed on a CJK-named integer state variable with opaque computed transitions. The key literals were decoded by hand, and the transitions around the two in-loop tests were computed by hand; no code is left unread.
- `os.path.exists(%APPDATA%\Extension)` only decides whether `os.makedirs` runs; both outcomes reach the state that writes the extension files, so it is plumbing and its candidates are dropped.
- The admin branch reaches the `CreateShortcut` sink only through state transitions, which a witness cannot express, so g2's payload stays `unresolved: computed_callee`. g1 carries the full behaviour set with its sinks directly in the region.
- `sys.argv[1]` checks (`egg_info`/`build` vs `bdist_wheel`/`install`) select the pywin32 install vs the extension drop across pip's build phases; both fire during one `pip install`. Recorded as command-phase routing in `execution.notes`, not as environmental gates.
- No C2 or second stage: the extension content is embedded in the file. The only network need is `pip` fetching `pywin32` from PyPI (in `requirements`).
- `pip.main(['install','pywin32'])` is labelled `download`; pywin32 itself is a legitimate dependency the COM persistence needs.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "xlsxwriteer",
    "version": "0.1",
    "archive_sha256": "c4b346e95b8c26f69c53b9bdfe8a956267cf37ffc45862310cfe33aca0e381c9",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/xlsxwriteer-0.1.tar.gz",
    "package_root": "layer0/xlsxwriteer-0.1",
    "cluster_key": "80edfac870b2f072f395186c63cb3f880a43e7861b398963d18ea8586ae4144f",
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
          "direct_script",
          "download_then_exec"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full. All strings are built at runtime by map(chr, [<bit-shift integer>...]), chr being getattr(__builtins__, oct.__str__()[-3]+hex.__str__()[-4]+copyright.__str__()[4]); key literals decoded by hand.",
      "State transitions computed by hand: IsUserAnAdmin() true goes to 362814 (appends C:\\ProgramData\\...\\Start Menu to the shortcut folders), false to 18005; 362814 also ends in 18005. No code left unread.",
      "g2 path, state values computed by hand: line 69 sets 362814 (line 45 arm, append at line 46), line 48 sets 18005, then 37668, 382664, 12768, 162346, 4030, 145239, 186387, 790593 (line 81 walk). Line 86 starts loop C at 86892, whose arm holds the line 90 sink.",
      "os.path.exists(%APPDATA%\\Extension) at line 120 (state 18005) only guards os.makedirs: not existing goes to state 29059 (makedirs), existing goes to 37668, and 29059 ends in 37668 (open %APPDATA%\\Extension\\background.js, mode w+). The drop runs either way, so it is plumbing, not a gate.",
      "Control flow is flattened: three while-loop dispatchers (lines 10, 38, 88; loop C nested in loop B) select blocks by an integer state variable, each setting the next state via opaque arithmetic. Source order is not execution order.",
      "sys.argv[1] routing: ['egg_info','build'] runs loop A = pip.main(['install','pywin32']) then import win32com; ['bdist_wheel','install'] runs loops B/C = the extension drop. A normal pip install triggers both phases.",
      "That sys.argv routing is treated as command-phase routing inside the setup_py hook, not an environmental gate; recorded here rather than as conditions.",
      "Payload: base=os.getenv('APPDATA'); makedirs(base+'\\Extension') if absent; write base+'\\Extension\\manifest.json' (JSON) and base+'\\Extension\\background.js' (JS starting 'let page = chrome...').",
      "Persistence: loop C walks the .lnk files in the shortcut folder list and, for browser shortcuts, opens them with win32com Dispatch('WScript.Shell').CreateShortcut(...) and sets Arguments to a --load-extension argument; pywin32 is installed via pip.main so win32com imports.",
      "setup(name='xlsxwriteer', packages=['xlsxwriteer'], version='0.1') is the only code outside the win32 block and is benign metadata."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443"
      ],
      "reason": "pip.main(['install','pywin32']) fetches pywin32 from PyPI at install so win32com is importable for the WScript.Shell COM persistence"
    },
    {
      "axis": "installed_tool",
      "value": [
        "pip"
      ],
      "reason": "the payload calls pip.main in-process to install pywin32"
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
      "purpose_reason": "The entire install payload is wrapped in sys.platform=='win32'; it exists only for Windows victims and does nothing on other platforms.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "persistence"
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
            "sink_kind": "other",
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
              "start_byte": 8819,
              "end_byte": 9219,
              "node_type": "call",
              "sha256": "0ed165ea6a4596a0",
              "line": 59
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 53590,
              "end_byte": 54477,
              "node_type": "call",
              "sha256": "78505879caf3772f",
              "line": 76
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 55913,
              "end_byte": 56084,
              "node_type": "call",
              "sha256": "743a28a7ff64cd52",
              "line": 90
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
      "purpose_reason": "When IsUserAnAdmin() is true the code goes to state 362814, which adds the machine-wide C:\\ProgramData\\Microsoft\\Windows\\Start Menu folder to the list of shortcut folders, then rejoins the non-admin path at state 18005; the admin result decides which browser shortcuts get the --load-extension argument. The CreateShortcut sink at line 90 runs on both paths; c2 only widens the set of shortcuts it rewrites, reached through state dispatch that a witness cannot express.",
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
              "start_byte": 55913,
              "end_byte": 56084,
              "node_type": "call",
              "sha256": "743a28a7ff64cd52",
              "line": 90
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
            "unresolved": "computed_callee"
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
      "char-code string construction (map over getattr(__builtins__,'chr') with operands encoded as bit-shift integer arithmetic)",
      "chr built indirectly via oct/hex/copyright __str__ slicing to hide the builtin name",
      "control-flow flattening via state-machine dispatch loops with opaque computed transition values",
      "non-ASCII (CJK) identifier names",
      "opaque junk assignments between real operations",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "Heavily obfuscated Windows-only setup.py (typosquat of XlsxWriter) that, during pip install, installs pywin32 and drops a browser extension (manifest.json + background.js using chrome.* APIs) into %APPDATA%\\Extension, then rewrites browser shortcuts through WScript.Shell so the browser loads that extension. All real behaviour is hidden behind char-code string building and a flattened state machine. Clearly malicious install-time code.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Control-flow flattening: the g2 path from the admin branch to the CreateShortcut sink runs through state-machine transitions that a witness cannot express, so its payload stays marked unresolved (transition values computed by hand in execution.notes).",
    "sys.argv[1] setup-command checks (['egg_info','build'] vs ['bdist_wheel','install']) route the pywin32 install vs the extension drop across pip build phases; treated as command-phase routing rather than an environmental gate (see execution.notes) - a reviewer may wish to confirm.",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [],
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
        "note": "os.path.exists(%APPDATA%\\Extension) only decides whether os.makedirs runs; both outcomes reach state 37668 and write the extension files, so it is plumbing, not a gate.",
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
        "note": "The if around os.path.exists(%APPDATA%\\Extension) routes to makedirs (state 29059) or straight to 37668; 29059 also ends in 37668, so both sides drop the extension. Plumbing, not a gate.",
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
    "conditions_out_of_set": 0,
    "guard_candidates": 3,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
