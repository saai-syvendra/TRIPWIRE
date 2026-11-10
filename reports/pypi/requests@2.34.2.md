# pypi requests@2.34.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-05-14 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is an sdist built with the setuptools.build_meta backend, so pip runs `setup.py` during the build. `setup.py` has one gate: when `sys.version_info` is below 3.10 it writes an error to stderr and calls `sys.exit(1)`. Otherwise it calls a bare `setup()`, and setuptools reads the declarative metadata from `pyproject.toml`. The only environment needed to get past the gate is Python 3.10 or newer, and what runs after it is an ordinary package build.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: runtime_version >= [3, 10]) | then | 1 | benign_build | runtime_version=3.10 |

Gate intent: g1 activate/enables/portability

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- The version guard is the requests project's own code, not a copy in a typosquat, so it is not marked `inherited`.
- The dynamic version comes from a plain string literal in `src/requests/__version__.py`. No package module is run to read it.
- The `setup()` call is used as the payload sink with `sink_kind: other`, because the tool found no sink hints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "requests",
    "version": "2.34.2",
    "archive_sha256": "f288924cae4e29463698d6d60bc6a4da69c89185ad1e0bcc4104f584e960b9ed",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-05-14",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/requests-2.34.2.tar.gz",
    "package_root": "layer0/requests-2.34.2",
    "cluster_key": "50583f9e0add9b5eadd2a6b16128a35472fc156e1d9b3ce0ef66380f4516346d",
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
      "setup.py read in full: a Python >= 3.10 check (stderr message and sys.exit(1) otherwise), then a bare setuptools setup() call. No other package code runs at install.",
      "pyproject.toml uses the setuptools.build_meta backend with declarative metadata; the dynamic version is the plain string literal in src/requests/__version__.py.",
      "build-system.requires setuptools>=61.0 and four registry dependencies (charset_normalizer, idna, urllib3, certifi): dependency tree only. requires-python >=3.10 matches the setup.py guard.",
      "src/requests/ and tests/ are library and test code that run only when the package is imported or tested, not at install."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "runtime_version",
      "api": "sys.version_info",
      "operator": ">=",
      "value": [
        3,
        10
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_eca6b634dc",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 15,
            "end_byte": 41,
            "node_type": "comparison_operator",
            "sha256": "83df3ebaf69ead17",
            "line": 3
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
          "candidate": "q_f0eb5e9732",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 12,
            "end_byte": 139,
            "node_type": "if_statement",
            "sha256": "7bfbbc6448c7e577",
            "line": 3
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
      "purpose_reason": "Interpreter version guard: the build stops with an error on Python older than 3.10, which the project does not support.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "runtime_version": "3.10"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 141,
            "end_byte": 178,
            "node_type": "stmt_range",
            "sha256": "5b0e146d973f8091",
            "line": 7
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 171,
              "end_byte": 178,
              "node_type": "call",
              "sha256": "e260962f3d4d4ec2",
              "line": 9
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
  "assessment_reason": "The install path is a standard setuptools build: setup.py checks the interpreter version and calls setup() with metadata from pyproject.toml. No network, process, file or credential activity happens at install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "cd8ab44543744dd9"
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
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
