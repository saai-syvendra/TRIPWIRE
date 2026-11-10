# pypi ryptocompare@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Typosquat of `cryptocompare` whose `setup.py` runs at sdist build time. All code sits under `sys.platform == 'win32'` (strings and state values are arithmetic-encoded, decoded as derivation d1), and then the setup command picks the branch. On `egg_info`/`build` it calls `pip.main(['install', 'pypiwin32'])`. On `bdist_wheel`/`install` it writes a Manifest V2 browser extension to `%APPDATA%\Extension` (background script that swaps clipboard crypto addresses for attacker wallets every second) and rewrites `.lnk` shortcuts to chrome, msedge, brave or launcher on the Desktop, user Start Menu and TaskBar pins to add `--load-extension`. With admin rights (`IsUserAnAdmin`) it also rewrites shortcuts in the all-users Start Menu.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && c3 (c1: os == win32; c3: sys.argv in [egg_info, build]) | then | 2 | download | os=win32; package_manager=setup.py run with command (sys.argv[1]) egg_info or build |
| g2 | setup_py | c1 && c4 (c1: os == win32; c4: sys.argv in [bdist_wheel, install]) | then | 2 | write_file, persistence | os=win32; package_manager=setup.py run with command (sys.argv[1]) bdist_wheel or install |
| g3 | setup_py | c1 && c4 && c2 (c1: os == win32; c4: sys.argv in [bdist_wheel, install]; c2: privilege truthy) | then | 3 | persistence | os=win32; package_manager=setup.py run with command (sys.argv[1]) bdist_wheel or install; privilege=root_or_admin |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/modifies/targeting

Grounding: 2 of 4 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c3, c4, g1, g2, g3.

## Requirements

- other: pywin32 (win32com.client) importable in the build environment (from win32com.client import Dispatch is unguarded in the bdist_wheel/install branch)
- other: APPDATA env var set (extension folder path is built from os.getenv('APPDATA'))
- network: pypi[.]org:443 (egg_info/build branch runs pip.main(['install','pypiwin32']) against the package index)
- file_present: Windows .lnk shortcuts to chrome.exe, msedge.exe, brave.exe or launcher.exe under Desktop, Start Menu or TaskBar pins (shortcut hijack only rewrites shortcuts whose target is one of these browsers)

## Behaviour

- Ungated: none
- Gated: download, write_file, persistence

## Notes

- The setup-command checks (c3, c4) are out of set: the extractor did not see them as conditions. I recorded them as `package_manager` because the installer picks the command. A Windows VM with a PEP 517 `pip install` (bdist_wheel) or legacy `setup.py install` reaches the payload.
- `pip.main` does not exist in pip 10 and later, so the egg_info/build branch raises there. The payload branch also needs pywin32 importable (unguarded `from win32com.client import Dispatch`); in an isolated build env without pywin32 it fails before writing anything.
- The `%APPDATA%\Extension` exists check was dropped as plumbing (create the folder if missing). The loop state 286625773 in the egg_info branch is an unreachable decoy.
- Attacker wallet addresses for about 11 chains are hard-coded in the extension script; I left them out of the record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "ryptocompare",
    "version": "0.1",
    "archive_sha256": "6d17681b29a052aae383030b838984d1aa756a75752df68dcd62164aaf57f218",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/ryptocompare-0.1.tar.gz",
    "package_root": "layer0/ryptocompare-0.1",
    "cluster_key": "6cd0c06c28725e0f0b92a24658e773796d946d0f91313dab2d3a77e596ea8395",
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
      "setup.py: strings built as ''.join(map(chr, [shift arithmetic])) and state values as constant arithmetic; the tool did not recover it. Decoded with registered decoder py_chr_shift_fold (derivation d1); package code read in full; nothing unread.",
      "Both payload branches are control-flow flattened state machines; I followed every state transition in d1. The egg_info/build loop's state 286625773 (try import win32com, junk arithmetic) is never reached: decoy.",
      "The setup command (sys.argv[1]) picks the branch: egg_info/build runs pip.main(['install','pypiwin32']); bdist_wheel/install runs the extension dropper. Recorded as package_manager conditions since the installer picks the command.",
      "pip.main was removed in pip 10, so on modern pip the egg_info/build branch raises AttributeError and aborts that step. Under PEP 517 builds metadata uses dist_info (no branch) and the wheel build uses bdist_wheel (payload branch).",
      "Payload branch needs win32com (pywin32) importable; the import is unguarded, so without it the install branch raises before writing anything.",
      "c2 (IsUserAnAdmin) only adds the all-users Start Menu folder to the shortcut folders it rewrites: a modifies gate. The os.path.exists check on %APPDATA%\\Extension only decides whether to create the folder before writing: plumbing, dropped.",
      "g3's state 362814 appends the all-users Start Menu folder to the folder list; shortcuts there are rewritten by the same shortcut.Save() (state 60921) that g2 cites. g3's regions now include the folder walk (state 790593) holding Save, so the sink sits in a region and the witness is empty.",
      "g3 path: 383984 (admin) > 362814 > 18005 (> 29059) > 37668 > 382664 > 12768 > 162346 > 4030 > 145239 > 186387 > 790593, whose loop walks the folder list to Save. Moves are state assignments, not calls, so they need no witness hop.",
      "The folder walk region runs under c1 and c4 whether or not c2 holds; c2 only adds a folder to what it walks. That shared sink is why g3 is a modifies gate: Save on the all-users folder needs c2, Save itself does not.",
      "c3 and c4 test the same sys.argv[1] against disjoint lists, so c4 true already implies c3 false: the elif's exclusion of c3 adds no condition to g2 or g3."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "pywin32 (win32com.client) importable in the build environment",
      "reason": "from win32com.client import Dispatch is unguarded in the bdist_wheel/install branch"
    },
    {
      "axis": "other",
      "value": "APPDATA env var set",
      "reason": "extension folder path is built from os.getenv('APPDATA')"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "egg_info/build branch runs pip.main(['install','pypiwin32']) against the package index"
    },
    {
      "axis": "file_present",
      "value": "Windows .lnk shortcuts to chrome.exe, msedge.exe, brave.exe or launcher.exe under Desktop, Start Menu or TaskBar pins",
      "reason": "shortcut hijack only rewrites shortcuts whose target is one of these browsers"
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
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "in",
      "value": [
        "egg_info",
        "build"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
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
      "id": "c4",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "in",
      "value": [
        "bdist_wheel",
        "install"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
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
      "expression": "c1 && c3",
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
            "start_byte": 92,
            "end_byte": 128,
            "node_type": "comparison_operator",
            "sha256": "6cde078686fe8980",
            "line": 7
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
      "purpose": "targeting",
      "purpose_reason": "the pypiwin32 install exists only for Windows, has no other-platform counterpart, and supplies the win32com import that the Windows-only shortcut payload (g2) uses",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with command (sys.argv[1]) egg_info or build"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
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
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 335,
              "end_byte": 369,
              "node_type": "call",
              "sha256": "948b17ff4b80f1be",
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
            "derived_from": "d1",
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          },
          "kind": "elif",
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
      "purpose_reason": "the browser-extension clipper and shortcut hijack exist only for Windows and run on the wheel build or install step",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file",
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with command (sys.argv[1]) bdist_wheel or install"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
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
              "derived_from": "d1",
              "start_byte": 3819,
              "end_byte": 5880,
              "node_type": "call",
              "sha256": "45a3175521bf1aa3",
              "line": 69
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
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
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c1 && c4 && c2",
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
            "start_byte": 1602,
            "end_byte": 1643,
            "node_type": "comparison_operator",
            "sha256": "4f1224b550255378",
            "line": 34
          },
          "kind": "elif",
          "arm": "then",
          "conditions": [
            "c4"
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
      "purpose_reason": "with admin rights it also rewrites browser shortcuts in the all-users Start Menu, not just the current user's",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "os": "win32",
          "package_manager": "setup.py run with command (sys.argv[1]) bdist_wheel or install",
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
            "start_byte": 2228,
            "end_byte": 2395,
            "node_type": "stmt_range",
            "sha256": "a2d4643aa70e2799",
            "line": 45
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 6430,
            "end_byte": 8553,
            "node_type": "for_statement",
            "sha256": "f397d492cf3d7e08",
            "line": 78
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
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
      "very long lines",
      "strings built from chr() over shift/add arithmetic, chr fetched via getattr(__builtins__) with the name sliced from builtin reprs",
      "control-flow flattening with arithmetic state values",
      "CJK identifier names",
      "unreachable decoy state with junk arithmetic"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "browser-extension clipper via shortcut hijack",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, the wheel-build/install step of setup.py writes an unpacked browser extension to %APPDATA%\\Extension whose background script swaps cryptocurrency addresses on the clipboard for attacker wallets, and rewrites Chrome/Edge/Brave shortcuts with --load-extension so it loads at every browser start.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
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
          "decoder": "py_chr_shift_fold",
          "lang": "py"
        },
        "output_sha256": "dc9c428836ddbd12"
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
        "note": "plumbing: os.path.exists on %APPDATA%\\Extension only decides whether to create the folder; both sides go on to write the same extension files",
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
        "note": "plumbing: guard of the folder-exists check; both sides go on to write the same extension files",
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
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c3",
      "c4",
      "g1",
      "g2",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
