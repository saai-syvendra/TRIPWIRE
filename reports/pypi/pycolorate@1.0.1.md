# pypi pycolorate@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2023-04-25 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

pip runs the obfuscated `setup.py` of the sdist at build time. Under several layers (hex-escaped builtins aliases, a base64/zlib/rot13/base64 seed, then numbers divided by seeded `random.randint`), it holds a short stage that imports `requests`, downloads `hxxps://pyobfuscate[.]com/aes.txt` and `exec()`s it. The download runs with no gate in front. Gate g1 is whether `APPDATA` is set. When it is, the stage also deletes an existing `%APPDATA%\aes.txt` or `rsa.txt` and writes the download to `aes2.txt`. When it is not, the path concatenation throws and the bare `except` goes straight to `exec(fl)`. Gate g2 selects what is executed: with `APPDATA` set and both `aes.txt` and `rsa.txt` already present, the local `rsa.txt` runs; on any other host, including a clean one, the handler runs the download.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os.getenv exists APPDATA) | then | 1 | write_file, delete_file | env_var=APPDATA=(set) |
| g2 | setup_py | c1 && c2 && c3 (c1: os.getenv exists APPDATA; c2: file_or_dir_exists exists %APPDATA%\aes.txt; c3: file_or_dir_exists exists %APPDATA%\rsa.txt) | then | 3 | delete_file, other | env_var=APPDATA=(set); file_present=%APPDATA%\aes.txt, %APPDATA%\rsa.txt |
| | |  | else | 1 | exec_downloaded, delete_file | file_absent=%APPDATA%\rsa.txt |

Gate intent: g1 activate/enables/portability; g2 activate/selects/unclear

Grounding: 0 of 3 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c1, c2, c3, g1, g2.

## Requirements

- other: python module requests importable in the setup.py build environment (stage does 'from requests import get'; on ImportError it prompts with input() and calls sys.exit before any download)
- network: pyobfuscate[.]com:443 (second stage fetched with requests.get and exec()d; an uncaught exception there aborts the build)

## Behaviour

- Ungated: download
- Gated: write_file, delete_file, other, exec_downloaded

## Notes

- The stage was recovered with a new candidate decoder, `pyobfuscate_seeded_div` (derivation d1). It reimplements CPython's MT19937 seeding and `randint` as data and checks that every number divides exactly. It needs review before it moves into `tools/common/decoders/`.
- The gate tests presence, not truthiness: only an unset `APPDATA` (`getenv` returns `None`) makes the concatenation throw. An empty `APPDATA` still reaches the file drop and cleanup.
- `requests` must be importable in the build environment. Otherwise the stage calls `input()` and `sys.exit()` before downloading. Under pip's default build isolation `requests` is usually missing, so a scanner may need `--no-build-isolation` or a build env that has `requests`.
- `exec(open(rsa.txt).read())` runs only when both `aes.txt` and `rsa.txt` already exist in `%APPDATA%` (g2). `aes.txt` matters because the `if`/`elif` deletes `rsa.txt` when `aes.txt` is absent. This code never writes either file, and what `rsa.txt` would hold is not in the package. If it raises, the bare `except` still runs the download.
- The `obfuscate = dict(...)` literal holding the bare pyobfuscate URL is never used. The prefilled endpoint taken from it was replaced with the URL that is actually fetched.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pycolorate",
    "version": "1.0.1",
    "archive_sha256": "366bd7e6e4a3e9d0d11e2e965ab365b0776879912e0e165b7dbbf28018070c6c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-04-25",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-04-25-pycolorate-v1.0.1.zip",
    "package_root": "layer0/2023-04-25-pycolorate-v1.0.1/pycolorate-1.0.1",
    "cluster_key": "f267b07939088b3f9ab6f6e33a8b2fca5aef639374f432aa61a546afb5ad00e3",
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
          "decoded_eval",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: tool did not recover it (pyobfuscate-style layers). Decoded by hand as data: hex-escaped builtins aliases, seed from b64/zlib/rot13/b64 literal, then exec(_(__)) dividing each number by seeded random.randint(1,100000).",
      "Registered candidate decoder pyobfuscate_seeded_div (reimplements CPython MT19937 seeding and randint; self-check that every number divides exactly passed) as derivation d1. Whole file now read in full; nothing unread.",
      "Stage: imports requests (else input() prompt and sys.exit), GETs hxxps://pyobfuscate[.]com/aes.txt, then in a bare try reads APPDATA and builds paths; on any exception exec()s the downloaded text.",
      "With APPDATA unset, loc+'...' raises TypeError and the handler exec()s the download. With APPDATA set: deletes %APPDATA%\\aes.txt (or else rsa.txt) if present, writes download to aes2.txt if absent, then exec(open(rsa.txt)).",
      "rsa.txt is never written by this code, so on a clean host open() fails and the handler exec()s the download. Only when APPDATA is set and aes.txt and rsa.txt both pre-exist is the local rsa.txt run instead; this is g2 (selects), with exec_downloaded on its else side.",
      "g2 needs aes.txt because the if/elif removes rsa.txt whenever aes.txt is absent. If the local rsa.txt runs and raises, the bare except still exec()s the download.",
      "c1 is a presence test, not a truthiness test: only getenv returning None makes loc+'...' raise. An empty APPDATA string concatenates without error and still enters the g1 region, with paths relative to the root or working folder.",
      "For g1 the ex(p1)/ex(p2)/ex(p3) checks are plumbing (avoid errors on remove, reuse an existing aes2.txt) and are folded into the APPDATA gate. ex(p1) is recorded as c2 only because it decides whether rsa.txt survives to the exec in g2.",
      "Opaque predicate: eval('exec' if exec != print) is always true. The obfuscate=dict(...) literal with the pyobfuscate URL and the leading pycryptodome comment are unused decoys.",
      "requests is not in the default pip build-isolation env, so under isolation the stage likely hits input() then sys.exit and the build fails before the download; payload runs when requests is importable (e.g. --no-build-isolation)."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module requests importable in the setup.py build environment",
      "reason": "stage does 'from requests import get'; on ImportError it prompts with input() and calls sys.exit before any download",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 8199,
          "end_byte": 8326,
          "node_type": "try_statement",
          "sha256": "a1b77223a5050e1e",
          "line": 10
        }
      ]
    },
    {
      "axis": "network",
      "value": "pyobfuscate[.]com:443",
      "reason": "second stage fetched with requests.get and exec()d; an uncaught exception there aborts the build",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 8331,
          "end_byte": 8392,
          "node_type": "call",
          "sha256": "f2a59317676250ff",
          "line": 16
        }
      ]
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "os.getenv",
      "operator": "exists",
      "value": "APPDATA",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8487,
            "end_byte": 8500,
            "node_type": "call",
            "sha256": "f3a2f261f3a92f29",
            "line": 20
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "%APPDATA%\\aes.txt",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8567,
            "end_byte": 8579,
            "node_type": "comparison_operator",
            "sha256": "ac4c087bf4ed79a9",
            "line": 22
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "file_or_dir_exists",
      "api": "open",
      "operator": "exists",
      "value": "%APPDATA%\\rsa.txt",
      "value_recovered": "decoded",
      "probe": {
        "kind": "file",
        "callee": "open",
        "target": "%APPDATA%\\rsa.txt",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8726,
            "end_byte": 8734,
            "node_type": "call",
            "sha256": "a8676bab6f899d5b",
            "line": 28
          }
        }
      ],
      "in_scope": true,
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
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8398,
            "end_byte": 8768,
            "node_type": "try_statement",
            "sha256": "2fb00bcdb9155309",
            "line": 17
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "Windows-only path handling: with APPDATA unset the path concatenation throws and the file drop and cleanup are skipped, while the download is exec()d in the handler either way.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "delete_file"
        ],
        "env_recipe": {
          "env_var": {
            "APPDATA": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8564,
            "end_byte": 8716,
            "node_type": "stmt_range",
            "sha256": "408c48a89d93b9d9",
            "line": 22
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8700,
              "end_byte": 8716,
              "node_type": "call",
              "sha256": "9bb5ab5fa0838c5e",
              "line": 27
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8589,
              "end_byte": 8599,
              "node_type": "call",
              "sha256": "9148e7a9f839fcbb",
              "line": 23
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8631,
              "end_byte": 8641,
              "node_type": "call",
              "sha256": "be4268f3cb82e061",
              "line": 25
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
      "expression": "c1 && c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8398,
            "end_byte": 8768,
            "node_type": "try_statement",
            "sha256": "2fb00bcdb9155309",
            "line": 17
          },
          "kind": "try_except",
          "arm": "then",
          "conditions": [
            "c1",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8564,
            "end_byte": 8641,
            "node_type": "if_statement",
            "sha256": "4665fc25446ce56e",
            "line": 22
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "selects",
      "purpose": "unclear",
      "purpose_reason": "Picks a local rsa.txt over the download. This code never writes rsa.txt or aes.txt, so they can only come from an earlier run of something else; what rsa.txt holds is not in the package.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "delete_file",
          "other"
        ],
        "env_recipe": {
          "env_var": {
            "APPDATA": null
          },
          "file_present": [
            "%APPDATA%\\aes.txt",
            "%APPDATA%\\rsa.txt"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8589,
            "end_byte": 8599,
            "node_type": "expression_statement",
            "sha256": "9148e7a9f839fcbb",
            "line": 23
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8721,
            "end_byte": 8742,
            "node_type": "expression_statement",
            "sha256": "03ba0f60e21a6c12",
            "line": 28
          }
        ],
        "payload": [
          {
            "behaviour": "other",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8721,
              "end_byte": 8742,
              "node_type": "call",
              "sha256": "03ba0f60e21a6c12",
              "line": 28
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8589,
              "end_byte": 8599,
              "node_type": "call",
              "sha256": "9148e7a9f839fcbb",
              "line": 23
            },
            "witness": []
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "exec_downloaded",
          "delete_file"
        ],
        "env_recipe": {
          "file_absent": [
            "%APPDATA%\\rsa.txt"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8631,
            "end_byte": 8641,
            "node_type": "expression_statement",
            "sha256": "be4268f3cb82e061",
            "line": 25
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 8760,
            "end_byte": 8768,
            "node_type": "expression_statement",
            "sha256": "adc7d7244a1942ac",
            "line": 31
          }
        ],
        "payload": [
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8760,
              "end_byte": 8768,
              "node_type": "call",
              "sha256": "adc7d7244a1942ac",
              "line": 31
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 8631,
              "end_byte": 8641,
              "node_type": "call",
              "sha256": "be4268f3cb82e061",
              "line": 25
            },
            "witness": []
          }
        ]
      },
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "download"
    ],
    "gated": [
      "write_file",
      "delete_file",
      "other",
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "pyobfuscate-style multi-layer wrapper",
      "hex-escaped strings aliasing exec/eval/print onto builtins",
      "char-code built 'exec' and 'rot13' names",
      "base64 + zlib + rot13 + base64 chain",
      "PRNG-keyed number encoding (seeded random.randint divisors)",
      "opaque predicate (exec != print)",
      "unused decoy literal",
      "dynamic_eval",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://pyobfuscate[.]com/aes.txt",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pyobfuscate aes.txt loader",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py hides, under several decode layers, a stage that downloads text from a remote host and exec()s it during install, with silent exception handling. On Windows it also drops the download into %APPDATA%\\aes2.txt and deletes earlier aes.txt/rsa.txt files.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "candidate decoder pyobfuscate_seeded_div (scratch decoders/) needs review before it is added to tools/common/decoders/",
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
          "decoder": "pyobfuscate_seeded_div",
          "lang": "py"
        },
        "output_sha256": "99277efe30f3bab4"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "428960f5b8cf6c20"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": []
  },
  "candidate_check": {
    "condition_candidates": 0,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 0,
    "conditions_out_of_set": 3,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
