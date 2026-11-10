# npm ansi-universal-ui@1.4.0

**Source:** datadog · **Source label:** malicious · **Released:** 2026-01-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`, a short plain-JS stager. Its only gate is a top-level early exit: when `process.platform` is not a key of the `ASSETS` table (`win32` or `darwin`), it calls `process.exit(1)` before doing anything. On Windows or macOS it downloads an x86_64 python-build-standalone CPython from GitHub and extracts it with `tar` into `python_runtime/`. It then fetches base64-encoded Python from an Appwrite storage bucket, decodes it in memory and pipes it to that interpreter over stdin. A Linux sandbox sees nothing; setting `os` to win32 or darwin opens the gate.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script, download_then_exec, decoded_eval.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: os in [win32, darwin]) | then | 1 | download, write_file, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- network: fra[.]cloud[.]appwrite[.]io:443 (second-stage base64 Python payload fetched with https.get)
- network: github[.]com:443 (standalone CPython tarball download; the redirect target host is not named in the code)
- installed_tool: tar (spawn('tar', ...) extracts the downloaded runtime; a failure rejects and the script exits)
- arch: x64 (downloaded CPython is an x86_64 build; Apple Silicon needs Rosetta to run it)

## Behaviour

- Ungated: none
- Gated: download, write_file, exec_downloaded

## Notes

- The extractor missed the platform check at line 28; it is recorded out of set. The two prefilled `existsSync` candidates only cache the runtime or create its folder, so they were dropped as plumbing.
- The second-stage Python code is remote (Appwrite bucket) and was not fetched, so any gates inside it are unknown.
- The runtime is an x86_64 build, so it needs x64 hardware or Rosetta on Apple Silicon. It also needs `tar` on PATH.
- The package lists itself as a dependency.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "ansi-universal-ui",
    "version": "1.4.0",
    "archive_sha256": "ed13ba42adfe25d89e70f3df47faa2d39243a928985131f4bd703e819026d982",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-01-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-01-23-ansi-universal-ui-v1.4.0.zip",
    "package_root": "layer0/tmp/tmpbl7ibm2d/ansi-universal-ui/package",
    "cluster_key": "34d0305d502bb5157cc9f4801399c36ac61ddb2e04bf40785581fcfd38d850cc",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "decoded_eval"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): ansi-universal-ui",
      "generator truncated: some helpers walked under only 2 guard contexts in index.js; candidates there may be missing",
      "index.js (91 lines, plain JS): read in full; nothing unread. The extractor missed the top-level early exit at line 28 (process.platform not a key of ASSETS), added as c1 out of set.",
      "existsSync(LOCAL_PYTHON_BIN) at line 68 and existsSync(CACHE_DIR) at line 48 only reuse an already downloaded Python runtime or create its folder: plumbing, dropped.",
      "Second stage is base64 Python fetched from an Appwrite storage bucket at install, decoded in memory and piped to the downloaded CPython over stdin; its content is not in the package and was not fetched.",
      "Runtime asset is an x86_64 python-build-standalone build for win32 or darwin; spawn('tar') at line 56 extracts it into <pkg>/python_runtime and is the write_file sink. The install waits for the Python child and exits with its code.",
      "package.json lists the package itself (ansi-universal-ui ^1.4.0) as a dependency: dependency tree, not followed.",
      "https.get at line 35 runs in a synchronous Promise executor: traced.",
      "spawn('tar') at line 56 runs in the https.get response callback (line 50), an event handler no package call runs: unresolved."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "fra[.]cloud[.]appwrite[.]io:443",
      "reason": "second-stage base64 Python payload fetched with https.get"
    },
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "standalone CPython tarball download; the redirect target host is not named in the code"
    },
    {
      "axis": "installed_tool",
      "value": "tar",
      "reason": "spawn('tar', ...) extracts the downloaded runtime; a failure rejects and the script exits"
    },
    {
      "axis": "arch",
      "value": "x64",
      "reason": "downloaded CPython is an x86_64 build; Apple Silicon needs Rosetta to run it"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "win32",
        "darwin"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1011,
            "end_byte": 1027,
            "node_type": "subscript_expression",
            "sha256": "8235d9dba6b5b585",
            "line": 28
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1006,
            "end_byte": 1045,
            "node_type": "if_statement",
            "sha256": "9542aa297ccdda92",
            "line": 28
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "ASSETS only defines Windows and macOS runtimes; any other platform (e.g. a Linux sandbox) exits before any download",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "exec_downloaded"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 1049,
            "end_byte": 3043,
            "node_type": "stmt_range",
            "sha256": "dfb149c82bfd0d08",
            "line": 30
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 1263,
              "end_byte": 1622,
              "node_type": "call_expression",
              "sha256": "1958e2e2c91111b7",
              "line": 35
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2365,
                  "end_byte": 3042,
                  "node_type": "call_expression",
                  "sha256": "0a80aa8a36be3167",
                  "line": 66
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2366,
                  "end_byte": 3039,
                  "node_type": "arrow_function",
                  "sha256": "6c6393aa67c6e090",
                  "line": 66
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2541,
                  "end_byte": 2571,
                  "node_type": "call_expression",
                  "sha256": "b7a0c02b73f8c4b2",
                  "line": 72
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1176,
                  "end_byte": 1655,
                  "node_type": "function_declaration",
                  "sha256": "12752a3bd8c7c504",
                  "line": 33
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1219,
                  "end_byte": 1651,
                  "node_type": "new_expression",
                  "sha256": "fd5327edcbd56f8c",
                  "line": 34
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1231,
                  "end_byte": 1650,
                  "node_type": "arrow_function",
                  "sha256": "ba3f71a7407beac6",
                  "line": 34
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 2085,
              "end_byte": 2133,
              "node_type": "call_expression",
              "sha256": "9b2db2ac337f3fcc",
              "line": 56
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2365,
                  "end_byte": 3042,
                  "node_type": "call_expression",
                  "sha256": "0a80aa8a36be3167",
                  "line": 66
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2366,
                  "end_byte": 3039,
                  "node_type": "arrow_function",
                  "sha256": "6c6393aa67c6e090",
                  "line": 66
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2459,
                  "end_byte": 2492,
                  "node_type": "call_expression",
                  "sha256": "84e5bbbb4ee4a7bf",
                  "line": 69
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1659,
                  "end_byte": 2361,
                  "node_type": "function_declaration",
                  "sha256": "0f43354518baa6d5",
                  "line": 47
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1760,
                  "end_byte": 2357,
                  "node_type": "new_expression",
                  "sha256": "78b1a9f6b0e49ba8",
                  "line": 49
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1772,
                  "end_byte": 2356,
                  "node_type": "arrow_function",
                  "sha256": "552791220b09fb07",
                  "line": 49
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1804,
                  "end_byte": 2328,
                  "node_type": "call_expression",
                  "sha256": "ed100f58ea738d96",
                  "line": 50
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 1819,
                  "end_byte": 2327,
                  "node_type": "arrow_function",
                  "sha256": "cead7a892e22aaf8",
                  "line": 50
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 2745,
              "end_byte": 2841,
              "node_type": "call_expression",
              "sha256": "b6dbb2d0311613bb",
              "line": 78
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2365,
                  "end_byte": 3042,
                  "node_type": "call_expression",
                  "sha256": "0a80aa8a36be3167",
                  "line": 66
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 2366,
                  "end_byte": 3039,
                  "node_type": "arrow_function",
                  "sha256": "6c6393aa67c6e090",
                  "line": 66
                }
              }
            ]
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
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "second stage hosted remotely as base64, decoded in memory and piped to interpreter stdin (never written to disk)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://fra[.]cloud[.]appwrite[.]io/v1/storage/buckets/6968ea5600316c128f22/files/69736838003349357574/view?project=6968e9e9000ee4ac710c",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/indygreg/python-build-standalone/releases/download/$",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "appwrite-hosted python stager",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall of a package described as a UI component library downloads a standalone CPython, then fetches base64 Python code from an Appwrite storage bucket and runs it through that interpreter. It only does so on Windows and macOS.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "second-stage Python payload is remote and not in the package; it may hold further gates",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "892dbcccbabcba60"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_a28ccb09c3",
        "reason_code": "other",
        "note": "plumbing: skips the runtime download when a cached python_runtime binary already exists; the payload runs either way",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2405,
          "end_byte": 2436,
          "node_type": "call_expression",
          "sha256": "3026e5d3f4b7ab2b",
          "line": 68
        }
      },
      {
        "candidate": "q_67c9a2b5b4",
        "reason_code": "other",
        "note": "plumbing guard for the cached runtime check at line 68",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2400,
          "end_byte": 2504,
          "node_type": "if_statement",
          "sha256": "833275eb5374f72e",
          "line": 68
        }
      },
      {
        "candidate": "k_25c096b203",
        "reason_code": "other",
        "note": "plumbing: creates the python_runtime folder only when it is missing",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1697,
          "end_byte": 1721,
          "node_type": "call_expression",
          "sha256": "935279556c302c13",
          "line": 48
        }
      },
      {
        "candidate": "q_914e5a9395",
        "reason_code": "other",
        "note": "plumbing guard for the mkdir at line 48",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1692,
          "end_byte": 1747,
          "node_type": "if_statement",
          "sha256": "3d701f65165b554b",
          "line": 48
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 4,
    "conditions_in_set": 0,
    "conditions_out_of_set": 1,
    "guard_candidates": 2,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
