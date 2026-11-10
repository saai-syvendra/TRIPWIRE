# pypi charset-normalizer@3.5.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-09-30 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist builds through an in-tree PEP 517 backend (`_build_hook/backend.py`) that wraps `setuptools.build_meta`, so `setup.py` also runs during the build. One gate exists: when `CHARSET_NORMALIZER_USE_CYTHON=1`, `setup.py` cythonizes and compiles the optional `md` and `cd` extensions; otherwise a plain pure-Python wheel is built. `CHARSET_NORMALIZER_CYTHON_ABI3` and `os.name` only adjust requirement specs and compile options. Nothing beyond an ordinary setuptools build happens.

## Execution

- **build_backend** `in-tree build backend backend`: 2-file chain; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | build_backend | c1 (c1: os.getenv('CHARSET_NORMALIZER_USE_CYTHON') == 1) | then | 1 | benign_build | env_var=CHARSET_NORMALIZER_USE_CYTHON=1 |

Gate intent: g1 activate/enables/unclear

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- network: pypi[.]org:443 (pip build isolation fetches build-system.requires (setuptools) and, with the Cython switch on, Cython)
- installed_tool: cc (a C compiler is needed to build the Cython extensions when CHARSET_NORMALIZER_USE_CYTHON=1)

## Behaviour

- Ungated: benign_build
- Gated: benign_build

## Notes

- The tool note claiming the backend does not run `setup.py` is wrong: `setuptools.build_meta` runs it, so `setup.py` was added to the chain and read in full. Its guard and sink are out of set for that reason.
- Backend candidates for the ABI3 ternary, `_with_cython` and `build_wheel` were dropped as dependency-tree plumbing or prerequisite checks.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "charset-normalizer",
    "version": "3.5.2",
    "archive_sha256": "39de2a259fc954455c57274dc94c79d5842774e1247a016aff30bc0efed0f4ef",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-09-30",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/charset_normalizer-3.5.2.tar.gz",
    "package_root": "layer0/charset_normalizer-3.5.2",
    "cluster_key": "25fc4f31eff9dc6c85d9a4ee02debfed11ddaf7513a58a28a8b69cc349873124",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "build_backend",
        "command": "in-tree build backend backend",
        "runs_on": "always",
        "file_chain": [
          "_build_hook/backend.py",
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
      "The tool note says the backend does not run setup.py, but _build_hook/backend.py wraps setuptools.build_meta, whose build hooks run setup.py; setup.py is added to file_chain and read in full.",
      "_build_hook/backend.py and setup.py: package code read in full; no other package files are reached at build time; nothing unread.",
      "backend.py only re-exports setuptools PEP 517 hooks, adds a Cython requirement when CHARSET_NORMALIZER_USE_CYTHON=1, and raises if Cython cannot be imported then. No network, exec or file writes of its own.",
      "In setup.py, CHARSET_NORMALIZER_CYTHON_ABI3 only sets limited-API macros and bdist_wheel options, and os.name != 'nt' only adds -g0 to compile args: build plumbing, not gates.",
      "The try/except import of Cython.Build in setup.py falls back to a pure-Python build when Cython is missing; treated as a prerequisite of the native build, not a separate gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip build isolation fetches build-system.requires (setuptools) and, with the Cython switch on, Cython"
    },
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "a C compiler is needed to build the Cython extensions when CHARSET_NORMALIZER_USE_CYTHON=1"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "os.getenv('CHARSET_NORMALIZER_USE_CYTHON')",
      "operator": "==",
      "value": "1",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_1140a72011",
          "anchor": {
            "file": "_build_hook/backend.py",
            "derived_from": null,
            "start_byte": 159,
            "end_byte": 213,
            "node_type": "comparison_operator",
            "sha256": "f7c10af1e1ab987c",
            "line": 8
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 123,
            "end_byte": 172,
            "node_type": "comparison_operator",
            "sha256": "4633489837409dcb",
            "line": 8
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
      "hook": "build_backend",
      "expression": "c1",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 262,
            "end_byte": 1580,
            "node_type": "if_statement",
            "sha256": "f73a04444395e202",
            "line": 13
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "opt-in build switch that compiles the optional Cython speedup extensions instead of a pure-Python build; no targeting",
      "then": {
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "env_var": {
            "CHARSET_NORMALIZER_USE_CYTHON": "1"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 281,
            "end_byte": 1580,
            "node_type": "stmt_range",
            "sha256": "50f0ed427a3bbf34",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 832,
              "end_byte": 1580,
              "node_type": "call",
              "sha256": "26657550652bf872",
              "line": 32
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "benign_build"
    ],
    "gated": [
      "benign_build"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The in-tree backend is a thin wrapper around setuptools.build_meta and setup.py only configures optional Cython extensions. No network, credential, exec or file activity beyond a normal setuptools build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "fcfcfbb55aad868f"
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
        "candidate": "k_41491787d8",
        "reason_code": "other",
        "note": "CHARSET_NORMALIZER_CYTHON_ABI3 only picks the Cython version spec string added to build requirements; dependency-tree plumbing, same behaviour either way",
        "anchor": {
          "file": "_build_hook/backend.py",
          "derived_from": null,
          "start_byte": 337,
          "end_byte": 387,
          "node_type": "comparison_operator",
          "sha256": "703b251902709909",
          "line": 12
        }
      },
      {
        "candidate": "q_3e9940ddc1",
        "reason_code": "other",
        "note": "ternary selecting the Cython version spec from CHARSET_NORMALIZER_CYTHON_ABI3; dependency-tree plumbing, not a gate",
        "anchor": {
          "file": "_build_hook/backend.py",
          "derived_from": null,
          "start_byte": 311,
          "end_byte": 415,
          "node_type": "conditional_expression",
          "sha256": "2a1d3099d697dfe9",
          "line": 11
        }
      },
      {
        "candidate": "q_7a9d5d6836",
        "reason_code": "other",
        "note": "_with_cython only appends Cython to the build requirements returned to the frontend; dependency tree, the native build itself is gated in setup.py (g1)",
        "anchor": {
          "file": "_build_hook/backend.py",
          "derived_from": null,
          "start_byte": 918,
          "end_byte": 1055,
          "node_type": "if_statement",
          "sha256": "d1641933760c8c10",
          "line": 28
        }
      },
      {
        "candidate": "q_6af4dcdffe",
        "reason_code": "other",
        "note": "build_wheel only raises when Cython cannot be imported under the switch; a prerequisite check, the native build itself is gated in setup.py (g1)",
        "anchor": {
          "file": "_build_hook/backend.py",
          "derived_from": null,
          "start_byte": 1558,
          "end_byte": 1822,
          "node_type": "if_statement",
          "sha256": "6f0e55e8f068c2ea",
          "line": 47
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 0,
    "candidates_dropped": 4,
    "conditions_in_set": 0,
    "conditions_out_of_set": 1,
    "guard_candidates": 3,
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
