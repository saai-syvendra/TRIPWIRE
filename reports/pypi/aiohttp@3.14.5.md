# pypi aiohttp@3.14.5

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-11 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

aiohttp 3.14.5 is an sdist built with the setuptools.build_meta backend, so setup.py runs during pip install. The only gate is the project's interpreter check: on Python older than 3.10 it raises RuntimeError before anything else runs. Past it, setup() builds the package and, on CPython without AIOHTTP_NO_EXTENSIONS, compiles the bundled C extensions (llhttp, websocket mask, writer). Nothing beyond a normal build happens.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, native_build.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: runtime_version >= [3, 10]) | then | 1 | benign_build | runtime_version=3.10 |

Gate intent: g1 activate/enables/portability

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- installed_tool: C compiler (gcc/cc or MSVC) (setuptools compiles the C extensions unless AIOHTTP_NO_EXTENSIONS is set or the interpreter is not CPython)
- installed_tool: pkg-config (only when AIOHTTP_USE_SYSTEM_DEPS is set: the pkgconfig module queries libllhttp flags)

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- Env vars AIOHTTP_NO_EXTENSIONS, AIOHTTP_USE_SYSTEM_DEPS / USE_SYSTEM_DEPS and AIOHTTP_CYTHON_TRACE, plus the non-CPython check, only change build options (pure vs accelerated, compile flags). Both sides are benign_build, so I did not record them as gates.
- The git-submodule exit (needs .git and a missing vendor/llhttp/README.md) cannot be reached from the sdist.
- The setup() call is the payload sink with sink_kind other, because the tool listed no sinks.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aiohttp",
    "version": "3.14.5",
    "archive_sha256": "5558a7f5a05af9ecf744af91e5baefc436f93c9333e656c27ec253f9a6bbe178",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-11",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/aiohttp-3.14.5.tar.gz",
    "package_root": "layer0/aiohttp-3.14.5",
    "cluster_key": "82846d639d7efffbac40fa46354a0b00b015a431e24addaab8db260966bad735",
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
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full (108 lines). pyproject.toml uses the setuptools.build_meta backend, so setup.py runs at sdist build. No network, exec or file writes in package code beyond setuptools compiling C extensions.",
      "Build config env checks (AIOHTTP_NO_EXTENSIONS, AIOHTTP_USE_SYSTEM_DEPS/USE_SYSTEM_DEPS, AIOHTTP_CYTHON_TRACE, sys.implementation.name != cpython) only pick pure vs accelerated build or compile flags; both sides are benign_build, so not recorded as gates.",
      "The .git plus missing vendor/llhttp/README.md check exits with a submodule hint; it is a git-checkout prerequisite and is not reached from the sdist (no .git). Not recorded as a gate.",
      "ParallelBuildExt (cmdclass build_ext, only when extensions are enabled) just sets parallel = os.cpu_count() and calls super().build_extensions(); build plumbing.",
      "Requires-Python >= 3.10 in pyproject.toml matches the setup.py version check."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "C compiler (gcc/cc or MSVC)",
      "reason": "setuptools compiles the C extensions unless AIOHTTP_NO_EXTENSIONS is set or the interpreter is not CPython"
    },
    {
      "axis": "installed_tool",
      "value": "pkg-config",
      "reason": "only when AIOHTTP_USE_SYSTEM_DEPS is set: the pkgconfig module queries libllhttp flags"
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
        10
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_6a7d1a2d20",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 132,
            "end_byte": 158,
            "node_type": "comparison_operator",
            "sha256": "83df3ebaf69ead17",
            "line": 8
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
          "candidate": "q_3d467bd988",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 129,
            "end_byte": 219,
            "node_type": "if_statement",
            "sha256": "4f441c6ad457fddb",
            "line": 8
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
      "purpose_reason": "Project's own interpreter version check; raises RuntimeError on Python older than 3.10 before the build",
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
            "start_byte": 222,
            "end_byte": 2891,
            "node_type": "stmt_range",
            "sha256": "7553a869fd38c7c0",
            "line": 12
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "other",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2870,
              "end_byte": 2891,
              "node_type": "call",
              "sha256": "d9feb8516681beae",
              "line": 108
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
  "assessment_reason": "setup.py is the upstream aiohttp build script: a Python version check, build-option env vars, and a setuptools setup() call that compiles the bundled C extensions. No network, credential access or process launches in package code.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "f20f1a98948940ec"
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
