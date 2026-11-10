# pypi reqyest3@2.19.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

reqyest3 is a typosquat of requests that keeps requests' `setup.py` and adds an install payload. On a pip install from the sdist, the top level of `setup.py` first runs requests' own Python >= 3.7 guard, then runs `os.system("touch /tmp/license.py")`. After that, the overridden `install` cmdclass decrypts and runs one of two pyarmor-encrypted blobs. The choice is a `platform.machine() == "x86"` check: on x86 it takes the pyarmor 7 `pytransform` blob, on anything else the pyarmor 8.3.9 trial blob. Both bundled native runtimes are 32-bit Windows DLLs, so the encrypted code can only run on Windows under a 32-bit Python (probably 3.7). Everywhere else the install aborts when the runtime fails to load.

## Execution

- **cmdclass** `cmdclass[install] = PostInstallCommand`: 3-file chain; direct_script, decoded_eval.
- **setup_py** `python setup.py (pip install from sdist)`: 2-file chain; direct_script, inline_shell.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 && c2 (c1: runtime_version >= [3, 7] [inherited]; c2: arch == x86) | then | 2 | other | runtime_version=3.7; arch=ia32 |
| | |  | else | 2 | other | runtime_version=3.7; arch=x64 |
| g16 | setup_py | c8 (c8: runtime_version >= [3, 7] [inherited]) | then | 1 | write_file | runtime_version=3.7 |

Gate intent: g1 activate/selects/portability; g16 activate/enables/portability

Grounding: 3 of 3 conditions and 2 of 2 gates from the candidate set.

## Requirements

- os: win32 (both pyarmor runtimes (tests/pytransform/_pytransform.dll, tests/pyarmor_runtime_000000/pyarmor_runtime.pyd) are Windows PE DLLs; on other OSes the install aborts before the payload decrypts)
- arch: ia32 (both runtime DLLs are PE32 i386, so they only load into a 32-bit Python interpreter)
- runtime_version: 3.7 (pyarmor native runtimes are built per Python minor version; the bundled __pycache__ files are cpython-37. Inferred, not confirmed from the binaries)

## Behaviour

- Ungated: none
- Gated: other, write_file

## Notes

- I could not recover the encrypted payloads, so both branches of the architecture gate are labelled `other`. The architecture check is recorded as `portability`, but whether the two blobs do different things is unknown.
- The Python version guard (c1/c8) is marked `inherited` from requests' `setup.py`. The `publish` argv shortcut was copied from requests too and is not environmental.
- `tests/pytransform/__init__.py` is pyarmor's stock loader and was audited; its platform checks are library code. The `.dll` and `.pyd` runtimes were not read, only identified as PE32 i386.
- On a stock Linux sandbox you would only see the empty `/tmp/license.py` being created, followed by a failed install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "reqyest3",
    "version": "2.19.0",
    "archive_sha256": "d82108f00567a979619df59f6a42f98c2dd753f37111b4ef94280dd7b408eed7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/reqyest3-2.19.0.tar.gz",
    "package_root": "layer0/reqyest3-2.19.0",
    "cluster_key": "a1977a788d8fdad991b354a741c0bb77f926e15270c6d5dcbcfae273a34a059f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "tests/pytransform/__init__.py",
          "tests/pyarmor_runtime_000000/__init__.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "decoded_eval"
        ],
        "silent_failure": false
      },
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "src/reqyest3/__version__.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "cmdclass test (PyTest) and develop (PostDevelopCommand, only calls develop.run) entries removed: test never runs on pip install, develop only on legacy editable installs and adds nothing.",
      "setup.py: read in full. PostInstallCommand.run picks one of two pyarmor-encrypted blobs by platform.machine() == 'x86' (f1: pyarmor 7 pytransform, f2: pyarmor 8.3.9 trial runtime), then calls install.run.",
      "tests/pytransform/__init__.py: stock pyarmor pytransform loader, audited (ctypes load of _pytransform.dll, nothing outside the library's purpose). Its platform checks are library code, not gates.",
      "tests/pyarmor_runtime_000000/__init__.py: two-line stub read in full, imports the native pyarmor_runtime.pyd. Both native runtimes are PE32 i386 Windows DLLs, logic unread.",
      "On Linux or 64-bit Python neither runtime loads: f1's pyarmor_runtime prints the error and calls sys.exit(1), f2's import raises, so the install aborts. Top-level touch of /tmp/license.py has already run by then.",
      "src/reqyest3/__version__.py is exec'd by setup.py for metadata; read in full, only constant assignments.",
      "Version guard at line 16 and the 'publish' argv shortcut are copied from the requests setup.py; the argv check is not environmental and was not a candidate.",
      "Python's platform.machine() on Windows reports PROCESSOR_ARCHITECTURE, so 'x86' means a 32-bit Windows OS; 32-bit Python on 64-bit Windows reports AMD64 and takes the f2 branch."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "both pyarmor runtimes (tests/pytransform/_pytransform.dll, tests/pyarmor_runtime_000000/pyarmor_runtime.pyd) are Windows PE DLLs; on other OSes the install aborts before the payload decrypts"
    },
    {
      "axis": "arch",
      "value": "ia32",
      "reason": "both runtime DLLs are PE32 i386, so they only load into a 32-bit Python interpreter"
    },
    {
      "axis": "runtime_version",
      "value": "3.7",
      "reason": "pyarmor native runtimes are built per Python minor version; the bundled __pycache__ files are cpython-37. Inferred, not confirmed from the binaries"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "runtime_version",
      "api": "sys.version_info[]",
      "operator": ">=",
      "value": [
        3,
        7
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_b4c1233035",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 311,
            "end_byte": 343,
            "node_type": "comparison_operator",
            "sha256": "a0897a2baefdb9ec",
            "line": 16
          }
        }
      ],
      "provenance": "in_set",
      "inherited": true
    },
    {
      "id": "c2",
      "category": "arch",
      "api": "platform.machine()",
      "operator": "==",
      "value": "x86",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f86b184e98",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 13802,
            "end_byte": 13829,
            "node_type": "comparison_operator",
            "sha256": "cf79cb1124118a82",
            "line": 81
          }
        }
      ],
      "provenance": "in_set"
    },
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
      "sites": [
        {
          "candidate": "k_b4c1233035",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 311,
            "end_byte": 343,
            "node_type": "comparison_operator",
            "sha256": "a0897a2baefdb9ec",
            "line": 16
          }
        }
      ],
      "provenance": "in_set",
      "inherited": true
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "cmdclass",
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": "q_1b7f19c161",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 308,
            "end_byte": 827,
            "node_type": "if_statement",
            "sha256": "1e4e7032f281658f",
            "line": 16
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_d7c03906ff",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 13799,
            "end_byte": 13878,
            "node_type": "if_statement",
            "sha256": "e55225ebc5bd0454",
            "line": 81
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
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "picks the pyarmor 7 pytransform blob on 32-bit Windows (machine x86) and the pyarmor 8 blob elsewhere; both blobs are encrypted, so whether they differ in function is not recovered",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "other"
        ],
        "env_recipe": {
          "runtime_version": "3.7",
          "arch": "ia32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 13843,
            "end_byte": 13847,
            "node_type": "block",
            "sha256": "ca1fc92c04fc43a9",
            "line": 82
          }
        ],
        "payload": [
          {
            "behaviour": "other",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1762,
              "end_byte": 7937,
              "node_type": "call",
              "sha256": "972d542707f36d45",
              "line": 71
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 13843,
                  "end_byte": 13847,
                  "node_type": "call",
                  "sha256": "ca1fc92c04fc43a9",
                  "line": 82
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 1651,
                  "end_byte": 7937,
                  "node_type": "function_definition",
                  "sha256": "60c70eaa6bb2dd9d",
                  "line": 67
                }
              }
            ]
          }
        ]
      },
      "else": {
        "requires": [
          "c1"
        ],
        "behaviours": [
          "other"
        ],
        "env_recipe": {
          "runtime_version": "3.7",
          "arch": "x64"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 13874,
            "end_byte": 13878,
            "node_type": "block",
            "sha256": "cebd8f0111467d52",
            "line": 84
          }
        ],
        "payload": [
          {
            "behaviour": "other",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 8035,
              "end_byte": 13789,
              "node_type": "call",
              "sha256": "d922bfbca929a9bf",
              "line": 78
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 13874,
                  "end_byte": 13878,
                  "node_type": "call",
                  "sha256": "cebd8f0111467d52",
                  "line": 84
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 7947,
                  "end_byte": 13789,
                  "node_type": "function_definition",
                  "sha256": "43b328fadfa37f89",
                  "line": 75
                }
              }
            ]
          }
        ],
        "min_conditions": 2
      }
    },
    {
      "gate_id": "g16",
      "hook": "setup_py",
      "expression": "c8",
      "guards": [
        {
          "candidate": "q_1b7f19c161",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 308,
            "end_byte": 827,
            "node_type": "if_statement",
            "sha256": "1e4e7032f281658f",
            "line": 16
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "interpreter version guard copied from requests' setup.py; exits before the injected code on Python older than 3.7",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "runtime_version": "3.7"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 830,
            "end_byte": 16606,
            "node_type": "stmt_range",
            "sha256": "7b7afe087a291543",
            "line": 35
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 14527,
              "end_byte": 14561,
              "node_type": "call",
              "sha256": "c2d660a244ea5dab",
              "line": 112
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
      "other",
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "pyarmor-encrypted code objects passed as bytes literals to __pyarmor__ (pyarmor 7 pytransform and pyarmor 8.3.9 trial)",
      "native pyarmor runtimes bundled under tests/ (32-bit Windows DLLs)",
      "payload hidden inside nested functions of an install cmdclass in a copied requests setup.py",
      "very long lines"
    ],
    "decoded": false,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "two pyarmor-encrypted code blobs (f1 line 71, f2 line 78); no static way to decrypt them"
      },
      {
        "file": "tests/pytransform/_pytransform.dll",
        "reason": "compiled pyarmor runtime (PE32 i386), logic unread"
      },
      {
        "file": "tests/pyarmor_runtime_000000/pyarmor_runtime.pyd",
        "reason": "compiled pyarmor runtime (PE32 i386), logic unread"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "pyarmor-armored requests typosquat",
  "claude_assessment": "malicious",
  "assessment_reason": "A typosquat of requests whose install cmdclass decrypts and runs pyarmor-encrypted code, choosing between two blobs by machine architecture, with Windows-only 32-bit runtimes bundled under tests/. The encrypted payload is not recovered, but hiding armored code in an install hook of a copied popular package has no benign purpose.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Both install payloads are pyarmor-encrypted; gate behaviours are labelled 'other' because what the decrypted code does is not recovered.",
    "Top-level os.system('touch /tmp/license.py') creates an empty file; its purpose (marker for the encrypted payload?) is not recovered.",
    "unrecovered code"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "27b8653155d93539"
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
    "condition_candidates": 2,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 0,
    "conditions_in_set": 3,
    "conditions_out_of_set": 0,
    "guard_candidates": 9,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
