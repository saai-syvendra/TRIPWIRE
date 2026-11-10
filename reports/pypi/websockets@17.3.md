# pypi websockets@17.3

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is the websockets sdist, built through setuptools.build_meta, so setup.py runs at install. It execs its own src/websockets/version.py to get the version string (released = True, so the git lookup there is dead), reads README.rst for the long description and calls setuptools.setup. The only gate is the documented build switch `BUILD_EXTENSION == "no"`: when set, no extension is declared; otherwise setuptools compiles the optional C extension websockets.speedups from speedups.c. Nothing touches the network, credentials or other processes.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: 2-file chain; direct_script, native_build.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os.environ.get == no) | then | 1 | - | env_var=BUILD_EXTENSION=no |
| | |  | else | 1 | benign_build | env_var_absent=BUILD_EXTENSION |

Gate intent: g1 activate/enables/portability

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- installed_tool: cc (C compiler and Python headers to build the optional websockets.speedups extension from speedups.c; build failure is tolerated unless BUILD_EXTENSION=yes)

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- The exec() sink flagged by the tool is the read of the package's own plain version file, not obfuscation.
- The extension's `optional=` flag depends on `BUILD_EXTENSION != "yes"`; it only decides whether a compile failure is fatal, so it is noted, not recorded as a gate.
- The else branch sink is the `setuptools.Extension(...)` declaration; the compile itself happens inside setuptools when `setup()` runs.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "websockets",
    "version": "17.3",
    "archive_sha256": "1c7dd93a1c9f89297471493674b1fc1d9467cafd45374f2172213046bdb3a329",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/websockets-17.3.tar.gz",
    "package_root": "layer0/websockets-17.3",
    "cluster_key": "92c0883ce4901b0d3172c62e03092679ff2bfe3872ebc60daf3a04a22fb845c6",
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
          "src/websockets/version.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full. Backend is setuptools.build_meta, so setup.py runs at build; no cmdclass overrides.",
      "src/websockets/version.py: read in full; setup.py exec()s it (path built with pathlib, so the extractor did not chain it). released = True, so the git describe branch is dead and it only sets version strings.",
      "The exec() sink is the read of the package's own version file, plain text, ordinary build plumbing.",
      "optional=BUILD_EXTENSION != 'yes' only decides whether a failed C compile is fatal; same behaviour either way, not a gate. With the var unset a compile failure is tolerated by setuptools.",
      "Files under src/websockets other than version.py and speedups.c are not reached at install (import-time library code)."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "C compiler and Python headers to build the optional websockets.speedups extension from speedups.c; build failure is tolerated unless BUILD_EXTENSION=yes"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "os.environ.get",
      "operator": "==",
      "value": "no",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_5017566e16",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 571,
            "end_byte": 612,
            "node_type": "comparison_operator",
            "sha256": "a7ee38ff23131654",
            "line": 22
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
          "candidate": "q_428b32aeba",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 568,
            "end_byte": 857,
            "node_type": "if_statement",
            "sha256": "5345f426612fb957",
            "line": 22
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
      "purpose": "portability",
      "purpose_reason": "Documented build switch: BUILD_EXTENSION=no skips compiling the optional C speedups extension, so the package installs where it cannot be built and falls back to the pure Python apply_mask in utils.py.",
      "then": {
        "min_conditions": 1,
        "behaviours": [],
        "env_recipe": {
          "env_var": {
            "BUILD_EXTENSION": "no"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 618,
            "end_byte": 634,
            "node_type": "block",
            "sha256": "db08d681c392cce3",
            "line": 23
          }
        ],
        "payload": []
      },
      "else": {
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "env_var_absent": [
            "BUILD_EXTENSION"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 645,
            "end_byte": 857,
            "node_type": "expression_statement",
            "sha256": "7aeae03929670f00",
            "line": 25
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 669,
              "end_byte": 851,
              "node_type": "call",
              "sha256": "4780a07b3f496795",
              "line": 26
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      }
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
  "assessment_reason": "setup.py execs the package's own plain version.py, reads README.rst for the long description and declares an optional C extension that setuptools compiles unless BUILD_EXTENSION=no. No network, no process launch beyond the normal native build, no data access.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "7eb822e7a6e47dcc"
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
