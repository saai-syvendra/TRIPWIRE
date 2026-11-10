# pypi aiohttp_socks_connector@0.1.11

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`aiohttp_socks_connector` is a typosquat that copies the real aiohttp-proxy project's metadata and bolts an info-stealer onto `setup.py`. When pip builds the sdist, top-level code runs `setup()` for the real metadata, then (guarded by a Python 3.5.3+ check copied from the impersonated project) writes `sys.argv` to an `args.txt` file and, when the setup command is `install` or a `bdist` build step, decodes a large embedded base64 blob into a Python stage, drops it and two VBS launchers into `%USERPROFILE%/appdata/local/temp/__pycache__`, and launches it hidden with `os.system('start main.cpython-39.vbs')`. The dropped stage (a stickytape single-file bundle) is a Windows stealer that collects browser passwords/cookies, crypto wallets (MetaMask, Phantom, Exodus), Telegram/WhatsApp/FileZilla data and screenshots and posts a zip to a hardcoded IP. There is no real environment gating of the stealer itself: it runs on any Windows machine where the pip command is install/bdist and the interpreter is new enough.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: runtime_version >= [3, 5, 3]) | then | 1 | write_file | runtime_version=3.5.3 |
| g3 | setup_py | c1 && (c3 \|\| c4) (c1: runtime_version >= [3, 5, 3]; c3: sys.argv == install; c4: sys.argv includes bdist) | then | 2 | write_file, spawn_process | runtime_version=3.5.3; package_manager=install |

Gate intent: g1 activate/enables/portability; g3 activate/enables/unclear

Grounding: 1 of 3 conditions and 1 of 2 gates from the candidate set; out of set, pending verification: c3, c4, g3.

## Requirements

- os: win32 (setup.py reads os.environ['USERPROFILE'] unconditionally and the stage uses Windows-only paths and APIs (DPAPI via crypt32, mss.windows); it raises on non-Windows.)
- network: 144[.]24[.]115[.]170:80 (the spawned stage posts victim details and the stolen-data zip to this host; without it the exfil cannot complete.)

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process

## Notes

- Two gates recorded: g1 (`c1`, Python >= 3.5.3 early-exit raise) guarding the `args.txt` write, and g3 (`c1 && (c3 || c4)`, the `install`/`bdist` argv early-exit) guarding the decode-drop-launch payload. g3 and its conditions c3/c4 are out of set; the extractor missed the argv early-exit, so this record forces manual review.
- The tool's c2/g2 (`if not isdir(main_dir): mkdir`) is mkdir-if-absent plumbing and was dropped.
- Windows-only: `os.environ['USERPROFILE']` is read unconditionally (KeyError aborts on other OSes); recorded as an os=win32 requirement, not a gate.
- Ordering bug worth noting for Phase 2: `args.txt` is opened with `'a+'` at line 51 inside `.../temp/__pycache__/` before that directory is created in the try block, so on a machine where the dir is absent the open raises an uncaught FileNotFoundError and the deeper payload is never reached. The directory must already exist for the stealer to fire.
- Endpoints: the github URL in `setup()` is the impersonated project's real repo and is not contacted at install, so it is dropped; the exfil C2 `hxxp://144.24.115[.]170` lives in the dropped stage and is kept as role c2.
- The stealer's log strings are in Russian and it carries a `tag='bauka'` (a handle, not recorded as a family name).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aiohttp_socks_connector",
    "version": "0.1.11",
    "archive_sha256": "183decb0bec9e159ff575058c6474063d8c55791cd471fd90872f1f6a78c2aab",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/aiohttp_socks_connector-0.1.11.tar.gz",
    "package_root": "layer0/aiohttp_socks_connector-0.1.11",
    "cluster_key": "311a470ac52b2f9d376160985432659be70a27ab33129703f69d0621a3a69075",
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
          "decoded_eval",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full; the base64 stage decoded to derived/d1 (b64_wrapper_drop) and read in full; its stickytape-bundled modules decoded to derived/d2-d7 and read; nothing unread.",
      "Payload runs only on Windows: setup.py reads os.environ['USERPROFILE'] with no guard (KeyError aborts the install on other OSes); recorded as an os=win32 requirement, not a gate.",
      "args.txt (sys.argv) is written at line 51 before the pip-command check, so it is gated by c1 only; its parent __pycache__ dir is created later in the try block, so on a machine where that dir is absent the line-51 open('a+') raises FileNotFoundError and the deeper try payload is not reached.",
      "The pip-command gate g3 (c3/c4) is out of set: the extractor did not record the 'install'/'bdist' argv early-exit; added by analyst with cited anchors.",
      "Dropped candidate c2/q_8feea40970 (if not isdir(main_dir): mkdir) is mkdir-if-absent plumbing, not a behaviour gate.",
      "The stage (derived/d1) is launched detached via os.system('start main.cpython-39.vbs'); it steals browser creds, wallets, Telegram/WhatsApp/FileZilla data and screenshots and posts a zip to hxxp://144.24.115[.]170.",
      "The stealer's actions run in the spawned child process, covered here by spawn_process at install time."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "setup.py reads os.environ['USERPROFILE'] unconditionally and the stage uses Windows-only paths and APIs (DPAPI via crypt32, mss.windows); it raises on non-Windows."
    },
    {
      "axis": "network",
      "value": [
        "144[.]24[.]115[.]170:80"
      ],
      "reason": "the spawned stage posts victim details and the stolen-data zip to this host; without it the exfil cannot complete."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "runtime_version",
      "api": "sys.version_info",
      "operator": ">=",
      "value": [
        3,
        5,
        3
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_22e2a911f1",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 525,
            "end_byte": 553,
            "node_type": "comparison_operator",
            "sha256": "1b2f7dda8e05b788",
            "line": 26
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "==",
      "value": "install",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1554,
            "end_byte": 1578,
            "node_type": "comparison_operator",
            "sha256": "5cac8381ec46e9c3",
            "line": 58
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "includes",
      "value": "bdist",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1582,
            "end_byte": 1604,
            "node_type": "comparison_operator",
            "sha256": "5e10a9d9dc16c41e",
            "line": 58
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
          "candidate": "q_e6e2fe7e15",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 522,
            "end_byte": 628,
            "node_type": "if_statement",
            "sha256": "5575171e48606abf",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "raises unless the interpreter is Python 3.5.3+, the impersonated aiohttp project's minimum, before any dropper code runs.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1396,
            "end_byte": 1498,
            "node_type": "with_statement",
            "sha256": "fd13d7728caaecaf",
            "line": 51
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1401,
              "end_byte": 1464,
              "node_type": "call",
              "sha256": "fa380a29636a7665",
              "line": 51
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
      "expression": "c1 && (c3 || c4)",
      "guards": [
        {
          "candidate": "q_e6e2fe7e15",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 522,
            "end_byte": 628,
            "node_type": "if_statement",
            "sha256": "5575171e48606abf",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1546,
            "end_byte": 1622,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 58
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3",
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "runs the dropper only when setup.py is invoked for the install or a bdist build step, the steps a real pip install of the sdist triggers.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "install"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1790,
            "end_byte": 63757,
            "node_type": "try_statement",
            "sha256": "8376aebcd8787e9c",
            "line": 69
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2091,
              "end_byte": 2155,
              "node_type": "call",
              "sha256": "890ef53a78737a92",
              "line": 81
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 63576,
              "end_byte": 63614,
              "node_type": "call",
              "sha256": "fb964946954abe9b",
              "line": 91
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
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "large base64 literal decoded to a Python stage at install",
      "stage is a stickytape single-file bundle of many modules",
      "stage dropped into %USERPROFILE%/appdata/local/temp/__pycache__ and named main.cpython-39.py to look like a cached bytecode module",
      "launched through a VBS wrapper that runs python with a hidden window",
      "very long lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://144.24.115[.]170",
        "role": "c2"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py decodes an embedded base64 Python stage, drops it and two VBS launchers into %USERPROFILE%/appdata/local/temp/__pycache__, and runs it hidden via os.system('start main.cpython-39.vbs'). The stage is a Windows info-stealer that collects browser passwords and cookies, crypto wallets, Telegram/WhatsApp/FileZilla data and screenshots and exfiltrates a zip to a hardcoded IP. The package impersonates the real aiohttp-proxy project.",
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
          "func": "b64",
          "nth": 0,
          "decoder": "b64_wrapper_drop",
          "lang": "py"
        },
        "output_sha256": "d21e3cdfba7f1809"
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/browsers/chromium.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "2f9865ff78a1606e"
      },
      {
        "id": "d3",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/wallets/exodus.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "c215f112773d965e"
      },
      {
        "id": "d4",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/telegram.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "79b16225987744ec"
      },
      {
        "id": "d5",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/whatsapp.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "911dc75292688756"
      },
      {
        "id": "d6",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/filezilla.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "7cf66eec1522a5f2"
      },
      {
        "id": "d7",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/details.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "2fb97579e4555efa"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "95f1cdf18d9cde8a"
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
        "candidate": "k_282f990700",
        "reason_code": "other",
        "note": "mkdir-if-absent plumbing; both branches leave main_dir present and the payload continues, so not a behaviour gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2037,
          "end_byte": 2052,
          "node_type": "call",
          "sha256": "0c7768f672ec7194",
          "line": 78
        }
      },
      {
        "candidate": "q_8feea40970",
        "reason_code": "other",
        "note": "guards only the mkdir-if-absent plumbing (c2), which was dropped; not a behaviour gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2030,
          "end_byte": 2078,
          "node_type": "if_statement",
          "sha256": "08258896d2d2e7e6",
          "line": 78
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 2,
    "conditions_in_set": 1,
    "conditions_out_of_set": 2,
    "guard_candidates": 2,
    "gates_in_set": 1,
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
