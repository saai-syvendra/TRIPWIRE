# pypi multidict@7.2.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-24 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

multidict 7.2.0 is an sdist built with setuptools.build_meta, so `setup.py` runs at install and registers a `build_ext` override. The script compiles the package's own C extensions (`multidict._multidict`, `multidict._testcapi`), or does a pure-Python build when `MULTIDICT_NO_EXTENSIONS` is set or the interpreter is not CPython. The only environment checks pick compiler flags (non-Windows warning flags, debug and sanitizer flags, dropping `-Wconversion` on GCC below 10 after a `cc -dM -E` probe). None of them changes the behaviour class, so no gates are recorded.

## Execution

- **cmdclass** `cmdclass[build_ext] = BuildExt`: runs setup.py; direct_script, native_build.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- installed_tool: cc (C compiler needed to build multidict._multidict on CPython unless MULTIDICT_NO_EXTENSIONS is set)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- Both prefilled candidates (the `platform.system() != "Windows"` flag block) were dropped as build plumbing.
- Building the C extension needs a C compiler; listed as a requirement.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "multidict",
    "version": "7.2.0",
    "archive_sha256": "f4110a13e264858eb00697751785cb2c58ee96707d8ded5ddb8239530d3b9ba4",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-24",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/multidict-7.2.0.tar.gz",
    "package_root": "layer0/multidict-7.2.0",
    "cluster_key": "d3d26b7ab14add40164f42f795ade44a55f7e126230aa128ed5127086496b58f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[build_ext] = BuildExt",
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
      },
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
      "setup.py: read in full (140 lines). Backend is setuptools.build_meta, no in-tree backend; setup.cfg only sets egg_info tags. Nothing unread.",
      "platform.system() != 'Windows' (line 29) only adds GCC/Clang warning and sanitizer flags; both sides compile the same C extensions, so it is build plumbing, not a gate.",
      "MULTIDICT_* env vars and sys.implementation.name pick debug flags or a pure-Python build instead of the C build; both outcomes are benign_build, so not recorded as gates.",
      "BuildExt.build_extensions runs the compiler with -dM -E on os.devnull (subprocess.run, line 79) to read the GCC major version and drop -Wconversion on GCC < 10. Compiler probe, build plumbing.",
      "Optional Cython test extension is built only when Cython is importable in the build env (try/except ImportError); same benign build either way."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "C compiler needed to build multidict._multidict on CPython unless MULTIDICT_NO_EXTENSIONS is set"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "benign_build"
    ],
    "gated": []
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
  "assessment_reason": "setup.py only configures and compiles the package's own C extensions with setuptools, with an optional pure-Python fallback. No network, credential, file or process activity beyond a compiler version probe.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "502df2477258582f"
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
        "candidate": "k_828d7521e2",
        "reason_code": "other",
        "note": "platform.system() != 'Windows' only selects compiler warning and sanitizer flags; the same C extensions are compiled on every OS, so no behaviour changes.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 953,
          "end_byte": 983,
          "node_type": "comparison_operator",
          "sha256": "66261f6d741d3a80",
          "line": 29
        }
      },
      {
        "candidate": "q_e71fe157bc",
        "reason_code": "other",
        "note": "if-block only extends CFLAGS/LDFLAGS for non-Windows compilers; build plumbing, same benign_build on both sides.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 950,
          "end_byte": 2039,
          "node_type": "if_statement",
          "sha256": "a32da111106da246",
          "line": 29
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
