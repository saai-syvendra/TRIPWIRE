# pypi aiohttp_proxies@0.8.43

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The malicious code is at the top of setup.py, so it runs when pip builds the sdist. A single gate tests `sys.argv[1]` and lets the payload through only when the setuptools command is `install` or contains `bdist`. A normal pip install meets this during the wheel build (`bdist_wheel`), but the metadata pass does not. Behind the gate, the code sends base64 `username|hostname` to 144[.]24[.]115[.]170:8080, then writes an embedded base64 Windows PE to %TEMP% under a random `.exe` name and starts it hidden. Nothing checks the OS, but the payload only works on Windows.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, dropped_binary; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 \|\| c2 (c1: sys.argv == install; c2: sys.argv includes bdist) | then | 1 | recon, exfil, write_file, spawn_process | package_manager=pip |

Gate intent: g1 activate/enables/targeting

Grounding: 0 of 2 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, c2, g1.

## Requirements

- os: win32 (backslash %TEMP% paths and Popen creationflags only work on Windows; the dropped file is a Windows PE)
- network: 144[.]24[.]115[.]170:8080 (beacon carrying base64 username|hostname; a failure is swallowed and does not stop the exe drop)

## Behaviour

- Ungated: write_file
- Gated: recon, exfil, write_file, spawn_process

## Notes

- The dropped PE (the `aagfdc` literal, about 1.1 MB of base64) was not analysed and may contain its own gates, so the record is flagged for review.
- The interpreter-version check copied from aiohttp-socks was dropped as unreachable, because the file uses f-strings.
- Both conditions are out of set: the extractor did not offer the argv test as a candidate.
- Every failure is swallowed. The beacon is skipped when `os.getlogin()` fails, which happens with no controlling terminal, but the exe drop still runs.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aiohttp_proxies",
    "version": "0.8.43",
    "archive_sha256": "b940a05937917e602453daf93e388ffa113e62b30ebab078fccef2e776cec331",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/aiohttp_proxies-0.8.43.tar.gz",
    "package_root": "layer0/aiohttp_proxies-0.8.43",
    "cluster_key": "520a7463ae3d99d9941250ef3c91b828821ec6b275d2d7392ae09c4f8aa655d0",
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
          "direct_script",
          "dropped_binary"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "setup.py:39",
        "seconds": 0.1
      }
    ],
    "notes": [
      "setup.py: read in full except the aagfdc base64 literal on line 1. Its prefix decodes to a Windows PE (MZ header, DOS stub text). The install writes it to %TEMP% and starts it. The PE logic was not analysed (dropped binary, unread).",
      "The gate tests sys.argv[1], the setuptools command. On a pip sdist install the setuptools backend runs setup.py with bdist_wheel for the wheel build, so the payload runs then. The egg_info/metadata pass skips it.",
      "len(sys.argv) > 0 in the same test is always true when setup.py runs, so it is not recorded as a condition.",
      "In practice the payload only works on Windows: paths are joined with a backslash, and Popen gets creationflags=CREATE_NO_WINDOW, which raises ValueError on POSIX (the error is swallowed). Nothing checks the OS, so this is an os requirement, not a gate.",
      "os.getlogin() raises OSError when there is no controlling terminal. The except swallows it and the beacon is skipped, but the exe drop in the second try still runs.",
      "The redefined print() appends every message (timestamp, sys.argv, server reply, exe path) to %TEMP%\\back_logs.txt, both before and after the gate.",
      "The sys.version_info < (3, 6, 0) check is copied from aiohttp-socks' setup.py and is dropped. The file uses f-strings, so on Python < 3.6 it fails to parse before that line runs. It also only guards setup()."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "backslash %TEMP% paths and Popen creationflags only work on Windows; the dropped file is a Windows PE"
    },
    {
      "axis": "network",
      "value": "144[.]24[.]115[.]170:8080",
      "reason": "beacon carrying base64 username|hostname; a failure is swallowed and does not stop the exe drop"
    }
  ],
  "conditions": [
    {
      "id": "c1",
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
            "start_byte": 1132458,
            "end_byte": 1132482,
            "node_type": "comparison_operator",
            "sha256": "5cac8381ec46e9c3",
            "line": 23
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
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
            "start_byte": 1132486,
            "end_byte": 1132508,
            "node_type": "comparison_operator",
            "sha256": "5e10a9d9dc16c41e",
            "line": 23
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
      "expression": "c1 || c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1132433,
            "end_byte": 1133336,
            "node_type": "if_statement",
            "sha256": "1bc306f85dba1144",
            "line": 23
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "payload runs only when setup.py is invoked for an install or wheel build, not for the metadata pass or other setup commands",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "exfil",
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "package_manager": "pip"
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1132514,
            "end_byte": 1133336,
            "node_type": "block",
            "sha256": "4c7e5da03fb2320c",
            "line": 24
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1132554,
              "end_byte": 1132567,
              "node_type": "call",
              "sha256": "123d614ae5db4083",
              "line": 25
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1132709,
              "end_byte": 1132721,
              "node_type": "call",
              "sha256": "c82a68b333ac3fef",
              "line": 29
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1132937,
              "end_byte": 1132953,
              "node_type": "call",
              "sha256": "83ad5d5d3f41cdd5",
              "line": 36
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1133070,
              "end_byte": 1133130,
              "node_type": "call",
              "sha256": "4e3874aa17b401f5",
              "line": 43
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [
      "write_file"
    ],
    "gated": [
      "recon",
      "exfil",
      "write_file",
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "embedded base64-encoded Windows PE in a very long single-line literal",
      "random file name for the dropped exe"
    ],
    "decoded": false,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "the aagfdc literal is a base64 Windows PE that the install drops and runs; it is compiled code and its logic was not analysed"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxp://144[.]24[.]115[.]170:8080/info?data=",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "aiohttp-socks copy with embedded exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "When setup.py runs for install or bdist, it sends the username and hostname to a hard-coded IP. It then writes an embedded base64 Windows executable to %TEMP% under a random name and starts it with no window. The rest of the file copies aiohttp-socks' setup.py.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "dropped Windows PE not analysed; it may contain its own environment checks",
    "unrecovered code",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "f98307e590094f93"
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
        "candidate": "k_f5f2ceb2d0",
        "reason_code": "dead_branch",
        "note": "sys.version_info < (3,6,0): the file uses f-strings so it cannot run on < 3.6, so the raise is unreachable; copied from aiohttp-socks and it only guards setup()",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1133853,
          "end_byte": 1133881,
          "node_type": "comparison_operator",
          "sha256": "ffe024b9fa0c2aa8",
          "line": 71
        }
      },
      {
        "candidate": "q_62c293d311",
        "reason_code": "dead_branch",
        "note": "guard of the same unreachable version check (k_f5f2ceb2d0)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1133850,
          "end_byte": 1133944,
          "node_type": "if_statement",
          "sha256": "4895a89e34989794",
          "line": 71
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 2,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "c2",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
