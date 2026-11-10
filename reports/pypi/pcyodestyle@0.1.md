# pypi pcyodestyle@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`pcyodestyle` is a typosquat of `pycodestyle` whose `setup.py` runs a heavily obfuscated payload at install time (control-flow flattened into state machines, strings built from `chr` over bit-shift integer lists, non-ascii identifiers). Everything is wrapped in `if sys.platform == 'win32':` (gate g1), so it only runs on Windows. During a normal `pip install` of the sdist it first (in the `egg_info`/`build` phase) calls `pip.main(['install','pypiwin32'])` to pull in `win32com`, then (in the `bdist_wheel`/`install` phase) drops a browser extension (`manifest.json` + `background.js`) into `%APPDATA%\Extension` and walks the Start Menu / ProgramData shortcut folders. For every `.lnk` whose target is `chrome.exe`, `msedge.exe`, `launcher.exe` (Opera) or `brave.exe` (gate g2, `c1 && c4`) it rewrites the shortcut's `.Arguments` to `--load-extension=%APPDATA%\Extension` and saves it, so the attacker's extension side-loads on every browser launch. The file drop is gated only by Windows; the shortcut hijack additionally requires one of those browsers to be present.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, download_then_exec.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file | os=win32 |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: target_artifact in chrome.exe \|\| msedge.exe \|\| launcher.exe \|\| brave.exe) | then | 2 | persistence | os=win32; file_present=%USERPROFILE%\Desktop\*.lnk (any .lnk under a scanned folder whose TargetPath basename is chrome.exe/msedge.exe/launcher.exe/brave.exe; scanned folders: %APPDATA%\Microsoft\Windows\Start Menu, %APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar, ~\Desktop) |
| g3 | setup_py | c1 && c5 (c1: os == win32; c5: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/modifies/targeting

Grounding: 2 of 3 conditions and 2 of 3 gates from the candidate set; out of set, pending verification: c4, g2.

## Requirements

- network: pypi[.]org:443 (the egg_info/build branch runs pip.main(['install','pypiwin32']) which fetches pypiwin32 from PyPI to obtain win32com for the COM shortcut manipulation)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- Obfuscation is heavy. Condition values (`win32`, the browser list) and the state hops are confirmed by the candidate decoder `py_shift_charcode_join` (derivation `d1`), which still needs a person's review. Anchors stay on the original bytes until it is accepted, so the verifier holds those values open.
- The first state machine goes 108363 then 0, so its state 286625773 arm (a `win32com` import probe) is dead code and not a gate.
- Two `sys.argv[1]` checks (`['egg_info','build']` and `['bdist_wheel','install']`) select which build phase does what; they are build-phase, not environmental, and are not recorded as gates. Both phases run during an ordinary `pip install`, so `runs_on=always`.
- The `ctypes.windll.shell32.IsUserAnAdmin()` probe is gate g3 (`c1 && c5`, effect `modifies`): when elevated, the state goes to the branch that appends `C:\ProgramData\Microsoft\Windows\Start Menu` to the scanned folders, so all-users shortcuts are hijacked too; otherwise only `%APPDATA%\Microsoft\Windows\Start Menu`, the taskbar pins folder and `~\Desktop` are scanned. The state values were worked out from the integer arithmetic at lines 69 and 71.
- Dropped candidate: the `os.path.exists(%APPDATA%\Extension)` check is mkdir-if-absent plumbing (its not-exists side goes to the `os.makedirs` branch) and does not abort on an existing folder.
- The `.Save()` sink is reached from the browser-match branch by a state transition (line 96 sets 60921, the `.Save()` branch), traced on `d1`; g2 and g3 keep `unresolved: dynamic_dispatch` because a state-machine hop has no witness form. g2 cites that arm (lines 104-105) as a second region, since line 96 is the only assignment that reaches it.
- The only install-time network is the `pip` fetch of `pypiwin32` (a legitimate PyPI package) for `win32com`; there is no attacker C2 or exfil at install. `background.js` (decoded in `d1`, not pasted) swaps cryptocurrency wallet addresses in the clipboard for fixed attacker addresses. That runs later in the browser and is covered here by the write_file/persistence that installs it.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pcyodestyle",
    "version": "0.1",
    "archive_sha256": "98163d2df511c6a82e37f27bd770729965d57201c5b14203a16029aff20e9bf7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pcyodestyle-0.1.tar.gz",
    "package_root": "layer0/pcyodestyle-0.1",
    "cluster_key": "608076cc2bce5eb3bcbcd15fd22dcfbec67f0c0e44ecb3c9472c206fe9bd56b4",
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
      "setup.py read in full. Char-code strings (chr via getattr(__builtins__,...) over bit-shift int lists) and opaque arithmetic are folded by candidate decoder py_shift_charcode_join (derivation d1), not yet reviewed. No library code; nothing unread.",
      "Anchors stay on the original setup.py bytes, so line numbers in these notes are original lines and the verifier still holds decoded values open. d1 confirmed the earlier hand decode of win32, the browser list and the state hops. Re-cite into d1 once a person accepts the decoder.",
      "Dead code: the first state machine goes 108363 then 0, so the state 286625773 arm (try import win32com, except ModuleNotFoundError) never runs. It is not a gate.",
      "Control-flow flattened: while-loops dispatch on a numeric state variable whose transitions are opaque bit-shift arithmetic; identifiers are non-ascii glyph runs. Entire body is wrapped in `if sys.platform == 'win32':`.",
      "Payload sits under two non-environmental sys.argv[1] checks: ['egg_info','build'] runs pip.main(['install','pypiwin32']); ['bdist_wheel','install'] drops the extension and hijacks shortcuts. A normal pip install of the sdist runs both phases, so runs_on=always.",
      "Drops %APPDATA%\\Extension\\manifest.json and background.js (open 'w+', write, close), then os.walk of Start Menu/ProgramData for .lnk files; shortcuts targeting chrome/msedge/launcher/brave.exe get .Arguments set to '--load-extension=%APPDATA%\\Extension' and .Save()d.",
      "No subprocess, registry, exec or exfil at install; only network is the pip fetch of pypiwin32 (legitimate PyPI package) to obtain win32com for the COM shortcut object.",
      "background.js decoded in d1, not pasted: every second it swaps cryptocurrency wallet addresses in the clipboard for fixed attacker addresses. That runs later in the browser, so it is covered by the install-time write_file/persistence.",
      "Hand-traced: a browser match sets state 60921 (line 96), the .Save() branch; no match ends the loop. unresolved stays since a state hop has no witness form.",
      "IsUserAnAdmin(): admin side sets state 362814, the line 45 branch appending C:\\ProgramData\\...\\Start Menu to the scan list; non-admin skips it. Gate g3.",
      "Scanned folders decoded from lines 51-54 and 62: %APPDATA%\\Microsoft\\Windows\\Start Menu, %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar, ~\\Desktop; files must end with .lnk (line 85).",
      "g2 second region is the state 60921 arm (lines 104-105), where .Save() sits. It is not lexically inside the line 94 if, but line 96 is the only assignment of the inner state that evaluates to 60921 (the others give 86892, 9653, 61499 and 0), so it runs only after a browser match."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "the egg_info/build branch runs pip.main(['install','pypiwin32']) which fetches pypiwin32 from PyPI to obtain win32com for the COM shortcut manipulation"
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
      "id": "c4",
      "category": "target_artifact",
      "api": "os.path.basename",
      "operator": "in",
      "value": "chrome.exe || msedge.exe || launcher.exe || brave.exe",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60170,
            "end_byte": 60247,
            "node_type": "call",
            "sha256": "60ceda81e375a2de",
            "line": 101
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "privilege",
      "api": "ctypes.windll.shell32.IsUserAnAdmin",
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
      "purpose_reason": "the entire payload is wrapped in sys.platform == 'win32'; the drop and shortcut hijack only exist for Windows victims, there is no other-OS branch",
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
              "start_byte": 62334,
              "end_byte": 63221,
              "node_type": "call",
              "sha256": "69898819c8a89113",
              "line": 126
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
            "start_byte": 56307,
            "end_byte": 59891,
            "node_type": "if_statement",
            "sha256": "76b73f77a63ff981",
            "line": 94
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
      "purpose_reason": "the --load-extension hijack is only applied to shortcuts whose target is chrome.exe/msedge.exe/launcher.exe/brave.exe, so persistence only fires on machines with one of those browsers installed",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%\\Desktop\\*.lnk (any .lnk under a scanned folder whose TargetPath basename is chrome.exe/msedge.exe/launcher.exe/brave.exe; scanned folders: %APPDATA%\\Microsoft\\Windows\\Start Menu, %APPDATA%\\Microsoft\\Internet Explorer\\Quick Launch\\User Pinned\\TaskBar, ~\\Desktop)"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 57837,
            "end_byte": 59743,
            "node_type": "assignment",
            "sha256": "2cc88eec7164776b",
            "line": 95
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 60459,
            "end_byte": 60650,
            "node_type": "stmt_range",
            "sha256": "8c2519828f7be53a",
            "line": 104
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
      "gate_id": "g3",
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
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "targeting",
      "purpose_reason": "when the installer runs elevated, the state goes to the branch that appends C:\\ProgramData\\Microsoft\\Windows\\Start Menu to the shortcut scan list, so the --load-extension hijack also hits all-users shortcuts; otherwise only per-user folders are hijacked",
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
            "node_type": "stmt_range",
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
      "else": null,
      "provenance": "in_set"
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
      "control-flow flattening (state-machine dispatch on a numeric variable with opaque arithmetic transitions)",
      "char-code string construction (chr resolved via getattr(__builtins__, ...) index tricks over bit-shift integer lists)",
      "opaque arithmetic predicates",
      "non-ascii identifier names",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "pypi[.]org",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "browser-shortcut-extension-hijack",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, during a normal pip install of the sdist, setup.py drops a browser extension (manifest.json + background.js) into %APPDATA%\\Extension and rewrites Chrome/Edge/Brave/Opera shortcuts to add --load-extension pointing at it, so the attacker's extension, a clipboard wallet-address swapper, side-loads on every browser launch. The behaviour is heavily obfuscated and the package name typosquats pycodestyle.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Condition values (win32, browser list) are confirmed by candidate decoder py_shift_charcode_join (derivation d1), which needs a person's review. Their anchors stay on the encoded bytes until it is accepted, so the verifier holds them open.",
    "c4 (browser-shortcut target_artifact) and gate g2 are out of set.",
    "g2 and g3 persistence payloads have unresolved=dynamic_dispatch: the state-machine transition to .Save() was traced on the decoded copy d1 but has no witness form.",
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
          "resolver": "getattr(__builtins__, oct.__str__()[-3 << 0] + hex.__str__()[-1 << 2] + copyright.__str__()[4 << 0])",
          "decoder": "py_shift_charcode_join",
          "lang": "py"
        },
        "output_sha256": "6ce6e7fda753dedb"
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
        "note": "os.path.exists(%APPDATA%\\Extension) only decides whether os.makedirs runs (not-exists sets state 29059, the makedirs branch); both sides go on to write the extension. No abort.",
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
        "note": "guard for the dropped Extension-dir exists check; directory-preparation plumbing, not a behaviour gate (see k_648bbff21c).",
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
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
