# pypi 2022-requests@3.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` is a copy of requests 2.28.1's, and runs on any pip install of the sdist. A Windows payload sits after the `setup()` call, pushed down by blank lines. The inherited interpreter check (Python >= 3.7) exits before anything else runs. After that, `os.name == 'nt'` (g11) guards a dropper: it changes to %temp%, fetches `connect-CANDC.txt` from 52[.]14[.]229[.]35:1122, saves it as `local.bat`, runs it and deletes it. Inside that block, a `net session` probe (g13) runs a second stage (`shoomsha.jpg` renamed to `loc.bat`) only when the stderr does not contain "Access is denied.", which means the install is running as administrator. To open both gates: Windows, Python >= 3.7, admin rights, and the C2 reachable.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: 18-file chain; direct_script, inline_shell, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g11 | setup_py | c8 && c9 (c8: runtime_version >= [3, 7] [inherited]; c9: os == nt) | then | 2 | download, write_file, exec_downloaded, delete_file | runtime_version=3.7; os=win32 |
| g13 | setup_py | c8 && c9 && c11 (c8: runtime_version >= [3, 7] [inherited]; c9: os == nt; c11: privilege not_includes Access is denied.) | then | 3 | download, write_file, exec_downloaded, delete_file | runtime_version=3.7; os=win32; privilege=root_or_admin |

Gate intent: g11 activate/enables/targeting; g13 activate/enables/targeting

Grounding: 3 of 3 conditions and 2 of 2 gates from the candidate set.

## Requirements

- network: 52[.]14[.]229[.]35:1122 (both .bat stages are fetched from this host over HTTP)
- installed_tool: cmd (stages are renamed, run and deleted through cmd /c)
- installed_tool: net ('net session' output is read for the admin check)
- other: requests importable, or pip able to install it from PyPI (the fetch uses requests.get; when import fails it runs 'python -m pip install requests')

## Behaviour

- Ungated: none
- Gated: download, write_file, exec_downloaded, delete_file

## Notes

- The prefilled `cmdclass[test]` entry was removed because `test` never runs on pip install.
- The bundled `requests/` is an unmodified-looking copy of 2.28.1 (checked by sink inventory). Its win32 checks are library code and were dropped.
- The non-admin branch only prints "Reinstall with Administrative permissions", and the package description also says to install as admin. Both are lures to get the second stage to run, so this is flagged as misleading text.
- The whole payload is wrapped in `except Exception: pass`, so a dead C2 fails silently.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "2022-requests",
    "version": "3.0.0",
    "archive_sha256": "11303701e094dd1d69ed8dad381a0bb99bf9dedee6e0224b5b5bb63f0662ddf2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/2022-requests-3.0.0.tar.gz",
    "package_root": "layer0/2022-requests-3.0.0",
    "cluster_key": "eba7fa8e310f6e53a7cc98ac0bdd03d6751f61415a4bd06ac420f5f86689c527",
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
          "setup.py",
          "requests/__init__.py",
          "requests/exceptions.py",
          "requests/packages.py",
          "requests/utils.py",
          "requests/__version__.py",
          "requests/api.py",
          "requests/models.py",
          "requests/sessions.py",
          "requests/status_codes.py",
          "requests/compat.py",
          "requests/certs.py",
          "requests/_internal_utils.py",
          "requests/cookies.py",
          "requests/structures.py",
          "requests/auth.py",
          "requests/hooks.py",
          "requests/adapters.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "inline_shell",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "setup.py:183",
        "seconds": 5
      },
      {
        "site": "setup.py:198",
        "seconds": 2
      },
      {
        "site": "setup.py:219",
        "seconds": 2
      }
    ],
    "notes": [
      "The prefilled cmdclass entry (cmdclass[test] = PyTest) was removed: the test command only runs on 'setup.py test', never on pip install. Its gates duplicated the setup_py ones.",
      "setup.py: read in full. Copy of the requests 2.28.1 setup.py with a Windows payload appended after setup(), pushed down by about 40 blank lines (lines 168-229).",
      "requests/ (bundled copy of requests 2.28.1): audited by sink inventory, no injected code found; the sys.platform checks in utils.py and sessions.py are upstream library code. Nothing unread.",
      "The payload's 'import requests' may load the bundled requests/ (setup.py's dir is on sys.path under the legacy backend); if its deps are missing the except runs 'pip install requests' and retries. Plumbing, not a gate.",
      "Whole payload sits in try/except Exception: pass, so any failure (C2 down, no requests) is silent.",
      "The printed message on non-admin ('Reinstall with Administrative permissions to solve the problem') and the setup() description urging admin install are lures to get a re-run as admin; the code has no such problem.",
      "c8 is the upstream requests interpreter check, inherited; it exits before setup() and the payload, so it is folded into g11 and g13 rather than kept as its own gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "52[.]14[.]229[.]35:1122",
      "reason": "both .bat stages are fetched from this host over HTTP"
    },
    {
      "axis": "installed_tool",
      "value": "cmd",
      "reason": "stages are renamed, run and deleted through cmd /c"
    },
    {
      "axis": "installed_tool",
      "value": "net",
      "reason": "'net session' output is read for the admin check"
    },
    {
      "axis": "other",
      "value": "requests importable, or pip able to install it from PyPI",
      "reason": "the fetch uses requests.get; when import fails it runs 'python -m pip install requests'"
    }
  ],
  "conditions": [
    {
      "id": "c8",
      "category": "runtime_version",
      "api": "sys.version_info[]",
      "operator": ">=",
      "value": [
        3,
        7
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "inherited": true,
      "sites": [
        {
          "candidate": "k_5057f0a1c5",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 221,
            "end_byte": 253,
            "node_type": "comparison_operator",
            "sha256": "a0897a2baefdb9ec",
            "line": 12
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c9",
      "category": "os",
      "api": "os.name",
      "operator": "==",
      "value": "nt",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_cae38f1e88",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3854,
            "end_byte": 3869,
            "node_type": "comparison_operator",
            "sha256": "eafa1b347f03245f",
            "line": 168
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c11",
      "category": "privilege",
      "api": "subprocess.Popen",
      "operator": "not_includes",
      "value": "Access is denied.",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_3cf073168b",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5538,
            "end_byte": 5564,
            "node_type": "comparison_operator",
            "sha256": "7b30c294c87bf6f4",
            "line": 206
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "exec",
        "callee": "subprocess.Popen",
        "target": "net session",
        "accessor": "stderr"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g11",
      "hook": "setup_py",
      "expression": "c8 && c9",
      "guards": [
        {
          "candidate": "q_3d9af4ba48",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 218,
            "end_byte": 737,
            "node_type": "if_statement",
            "sha256": "1e4e7032f281658f",
            "line": 12
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ]
        },
        {
          "candidate": "q_e1e9b318dc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3851,
            "end_byte": 6560,
            "node_type": "if_statement",
            "sha256": "0355a0eac9b2649d",
            "line": 168
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the dropper only exists for Windows (cmd, .bat, %temp%); other OSes just get the plain requests build",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download",
          "write_file",
          "exec_downloaded",
          "delete_file"
        ],
        "env_recipe": {
          "runtime_version": "3.7",
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3873,
            "end_byte": 6560,
            "node_type": "block",
            "sha256": "764cfa2df0992430",
            "line": 169
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 4562,
              "end_byte": 4586,
              "node_type": "call",
              "sha256": "eaacac25d2ae1d8e",
              "line": 187
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 4668,
              "end_byte": 4692,
              "node_type": "call",
              "sha256": "b6deeac729d83eeb",
              "line": 190
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 5054,
              "end_byte": 5172,
              "node_type": "call",
              "sha256": "eb30b1b19aa9ccb4",
              "line": 197
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 5201,
              "end_byte": 5347,
              "node_type": "call",
              "sha256": "5129fa37c4503d45",
              "line": 200
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g13",
      "hook": "setup_py",
      "expression": "c8 && c9 && c11",
      "guards": [
        {
          "candidate": "q_3d9af4ba48",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 218,
            "end_byte": 737,
            "node_type": "if_statement",
            "sha256": "1e4e7032f281658f",
            "line": 12
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ]
        },
        {
          "candidate": "q_e1e9b318dc",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 3851,
            "end_byte": 6560,
            "node_type": "if_statement",
            "sha256": "0355a0eac9b2649d",
            "line": 168
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": "q_00bc5c73a3",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5535,
            "end_byte": 6524,
            "node_type": "if_statement",
            "sha256": "ee7e0c232cd08007",
            "line": 206
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c11"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the second .bat stage only runs when 'net session' is not denied, i.e. the install runs as administrator; otherwise it just prints a lure to reinstall as admin",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "download",
          "write_file",
          "exec_downloaded",
          "delete_file"
        ],
        "env_recipe": {
          "runtime_version": "3.7",
          "os": "win32",
          "privilege": "root_or_admin"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 5689,
            "end_byte": 6524,
            "node_type": "block",
            "sha256": "894723bce56fa08f",
            "line": 209
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 5788,
              "end_byte": 5812,
              "node_type": "call",
              "sha256": "eaacac25d2ae1d8e",
              "line": 211
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 5900,
              "end_byte": 5924,
              "node_type": "call",
              "sha256": "b6deeac729d83eeb",
              "line": 214
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 6095,
              "end_byte": 6235,
              "node_type": "call",
              "sha256": "1516767ca7f849e2",
              "line": 217
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 6270,
              "end_byte": 6416,
              "node_type": "call",
              "sha256": "7313dac69a979cd6",
              "line": 221
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
      "exec_downloaded",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "payload appended after setup() behind about 40 blank lines",
      "second stages served as .txt/.jpg and renamed to .bat before running",
      "downloaded .bat files deleted after running",
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://52[.]14[.]229[.]35:1122/connect-CANDC.txt",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://52[.]14[.]229[.]35:1122/shoomsha.jpg",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "requests-copy bat dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py is a copy of requests' with a block appended that, on Windows, downloads a .bat from a raw IP C2, runs it and deletes it, then downloads and runs a second .bat when the install has admin rights.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: a printed message and the setup() description falsely say the library needs admin rights, luring a re-run as administrator that unlocks the second stage"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "dad56683c1dc2d88"
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
        "candidate": "k_553ef8d5c7",
        "reason_code": "library_code",
        "note": "sys.platform == win32 in bundled requests/utils.py (upstream proxy_bypass_registry), not package logic",
        "anchor": {
          "file": "requests/utils.py",
          "derived_from": null,
          "start_byte": 1435,
          "end_byte": 1458,
          "node_type": "comparison_operator",
          "sha256": "81d76343f3bfcc14",
          "line": 68
        }
      },
      {
        "candidate": "k_0feb889211",
        "reason_code": "library_code",
        "note": "sys.platform == win32 in bundled requests/sessions.py (upstream preferred_clock pick)",
        "anchor": {
          "file": "requests/sessions.py",
          "derived_from": null,
          "start_byte": 1308,
          "end_byte": 1331,
          "node_type": "comparison_operator",
          "sha256": "81d76343f3bfcc14",
          "line": 55
        }
      },
      {
        "candidate": "q_837d6a64a8",
        "reason_code": "library_code",
        "note": "upstream requests utils.py win32 block",
        "anchor": {
          "file": "requests/utils.py",
          "derived_from": null,
          "start_byte": 1432,
          "end_byte": 3340,
          "node_type": "if_statement",
          "sha256": "e810e523c01002bb",
          "line": 68
        }
      },
      {
        "candidate": "q_51b6b8d5aa",
        "reason_code": "library_code",
        "note": "upstream requests sessions.py clock selection",
        "anchor": {
          "file": "requests/sessions.py",
          "derived_from": null,
          "start_byte": 1305,
          "end_byte": 1410,
          "node_type": "if_statement",
          "sha256": "a6cb6f00518fb1b3",
          "line": 55
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 10,
    "condition_sites_cited": 3,
    "guards_cited": 3,
    "candidates_dropped": 4,
    "conditions_in_set": 3,
    "conditions_out_of_set": 0,
    "guard_candidates": 12,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
