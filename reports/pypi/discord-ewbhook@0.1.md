# pypi discord-ewbhook@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`discord-ewbhook` is a typosquat of `discord-webhook`. Its only code is a heavily obfuscated `setup.py` (chr-map string building, shift/add integer constants, and two integer while-loop state machines), which runs at install under setuptools. Everything is wrapped in `if sys.platform == 'win32'` (gate g1), so the payload only runs on Windows. On Windows it drops a browser extension into `%APPDATA%\Extension` (`background.js`, a clipboard hijacker that rewrites crypto wallet addresses to attacker-controlled ones, plus a `manifest.json`), pip-installs `pypiwin32`, and rewrites Chrome/Edge/Brave/launcher `.lnk` shortcuts via WScript.Shell to auto-load that extension (persistence). A second gate (g2) checks `ctypes.windll.shell32.IsUserAnAdmin()`; when admin, it also adds the all-users ProgramData Start Menu to the directories whose shortcuts are hijacked.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == win32) | then | 1 | download, write_file, persistence | os=win32 |
| g2 | setup_py | c1 && c2 (c1: os == win32; c2: privilege truthy) | then | 2 | persistence | os=win32; privilege=root_or_admin |

Gate intent: g1 activate/enables/targeting; g2 activate/modifies/targeting

Grounding: 2 of 2 conditions and 2 of 2 gates from the candidate set.

## Requirements

- network: pypi[.]org:443 (pip.main(['install','pypiwin32']) fetches pypiwin32 from PyPI so the later 'from win32com.client import Dispatch' (used to rewrite browser shortcuts) succeeds.)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- Decode: recovered with the repo decoder `py_chr_shift_fold` (registered as derivation d3). Conditions/guards/regions/sinks are cited on the raw `setup.py`; c1's value `win32` is recovered via the decoder, so the verifier will hold that literal open (encoded_unchecked). d1/d2 in `derived/` are leftover runs of an earlier scratch decoder; d3 is the one this record uses.
- Build-phase dispatch: `sys.argv[1] in ['egg_info','build']` runs the pip install, `['bdist_wheel','install']` runs the drop+hijack. Both fire during a normal `pip install` of the sdist, so this is not recorded as an environmental gate.
- Control-flow flattening means g2's admin check reaches its append through a state variable, not lexical nesting, so the g2 guard->region link will read as cannot_tell on verification. Noted in the record.
- Dead code: the egg_info/build state machine's `elif state == 286625773` (try/import win32com with an arithmetic loop) is never reached and is excluded.
- No attacker C2/exfil endpoint is contacted at install; `needs_remote` is true only because the payload pip-installs `pypiwin32` from PyPI. The hardcoded wallet addresses are clipboard-swap targets inside the dropped extension, not install-time network destinations.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "discord-ewbhook",
    "version": "0.1",
    "archive_sha256": "28933d04d674a1155eecd9c9b25a6494c83f755b7618e2e3f73859dcaa755dac",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/discord-ewbhook-0.1.tar.gz",
    "package_root": "layer0/discord-ewbhook-0.1",
    "cluster_key": "cb43ece3b953cb2d827c5e81a5159f67b9f9422c99997e365a0b4b0a67ed06d7",
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
      "setup.py: package code read in full after decoding chr-map getattr/join strings and shift/add integer constants with the py_chr_shift_fold decoder (derivation d3); control flow is flattened into integer while-loop state machines. Nothing unread.",
      "Behaviour splits on sys.argv[1]: ['egg_info','build'] runs pip.main(['install','pypiwin32']); ['bdist_wheel','install'] drops the extension and hijacks shortcuts. Both fire during a normal pip install of the sdist, so this dispatch is not an environmental gate.",
      "In the egg_info/build branch the state-machine elif for state 286625773 (a try/import win32com with an arithmetic loop) is dead: state 108363 runs pip.main then sets the state to 0, so the while loop exits and 286625773 is never reached.",
      "g2 (IsUserAnAdmin) reaches its effect via the flattened state machine: the admin-true arm (setup.py:69-70, the cited region) sets the state so a later elif appends the all-users ProgramData Start Menu to the hijack list.",
      "g2's append only extends the in-memory folder list; the persistence is the later shortcut Save(), reached only through state transitions, so g2's payload cites that Save() marked unresolved (dynamic_dispatch).",
      "g2 path (decoded d3): admin arm -> state 362814 (append ProgramData Start Menu) -> 18005 -> 37668 -> 382664 -> 12768 -> 162346 -> 4030 -> 145239 -> 186387 -> 790593, which walks the folder list and Save()s each .lnk (setup.py:104).",
      "The non-admin arm of g2 sets state 18005 directly, so the Save() runs either way; only the ProgramData folder being in the walked list depends on c2.",
      "The bdist_wheel/install branch imports win32com.client (Dispatch) with no try/except, so it needs the pypiwin32 the egg_info/build branch installs."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443"
      ],
      "reason": "pip.main(['install','pypiwin32']) fetches pypiwin32 from PyPI so the later 'from win32com.client import Dispatch' (used to rewrite browser shortcuts) succeeds."
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
      "purpose_reason": "The whole payload exists only for Windows: it drops a Windows browser extension and rewrites Windows browser shortcuts via WScript.Shell. On any other platform nothing runs.",
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
              "start_byte": 11023,
              "end_byte": 53348,
              "node_type": "call",
              "sha256": "71cacfab3b59cae1",
              "line": 73
            },
            "witness": []
          },
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
      "purpose_reason": "When the install runs with admin rights, the all-users 'C:\\ProgramData\\Microsoft\\Windows\\Start Menu' is appended to the list of folders whose browser .lnk shortcuts get rewritten, extending the shortcut hijack from the current user to every user on the machine.",
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
      "control-flow flattening via integer while-loop state machines",
      "strings built from chr-map getattr/join calls",
      "integer constants encoded as shift/add arithmetic",
      "non-ascii (CJK) identifier names",
      "very long lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "clipboard-wallet-clipper-browser-extension",
  "claude_assessment": "malicious",
  "assessment_reason": "A typosquat of discord-webhook whose heavily obfuscated setup.py runs at install on Windows. It drops a Chrome/Edge/Brave browser extension (background.js plus manifest.json) that hijacks the clipboard to swap crypto wallet addresses for attacker-controlled ones, then rewrites browser .lnk shortcuts to auto-load the extension (persistence). It also pip-installs pypiwin32 to drive the shortcut API.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "setup.py heavily obfuscated (chr-map strings, shift/add integer constants, integer state-machine control-flow flattening); recovered with the registered decoder py_chr_shift_fold (derivation d3).",
    "c1 value 'win32' was recovered by decoding chr-map bytes; the raw site is cited so the verifier holds the literal open (encoded_unchecked).",
    "g2 (admin privilege) connects to its append via the flattened state machine, so the guard->region control dependence is not confirmable by CFG.",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d3",
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
        "output_sha256": "152bedf5320aaa81"
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
        "note": "Only decides whether os.makedirs runs; both arms still write background.js and manifest.json, so no behaviour change (plumbing to skip makedirs when the dir exists).",
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
        "note": "Guard for the dropped os.path.exists check; it gates only the os.makedirs, not a behaviour change, so it is plumbing rather than a gate.",
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
