# pypi MarkupSafe@3.0.4

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-02 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

MarkupSafe 3.0.4 is an sdist built with setuptools, so pip runs `setup.py` at install, and a `build_ext` cmdclass override (`ve_build_ext`) compiles the optional `_speedups` C extension. The script checks `CIBUILDWHEEL` and the Python implementation (PyPy, Jython or GraalVM have no speedups). These checks only decide whether the C extension is built and whether a failed build is retried without it. Every path ends in an ordinary package build, so no gates are recorded.

## Execution

- **cmdclass** `cmdclass[build_ext] = ve_build_ext`: runs setup.py; direct_script, native_build.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The two prefilled candidates (the `CIBUILDWHEEL` comparison and the if/elif/else at line 60) were dropped as build plumbing: every branch is `benign_build`.
- The tool flagged truncation in `setup.py`. The file is 83 lines and was read in full, and nothing was missed.
- No network access, decoding or process launches outside setuptools' normal compiler call.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "MarkupSafe",
    "version": "3.0.4",
    "archive_sha256": "2e9ad7dd851bf45fab9f75cbff4cb493fee9979e8d8c7c9c3ee119022518edd6",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-02",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/markupsafe-3.0.4.tar.gz",
    "package_root": "layer0/markupsafe-3.0.4",
    "cluster_key": "08a3a774dfad6be2631650462591e5aa36bb9b9108e531c527a97fbe9ec78a00",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[build_ext] = ve_build_ext",
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
      "generator truncated: some helpers walked under only 2 guard contexts in setup.py; candidates there may be missing",
      "setup.py: read in full (83 lines). Build backend is setuptools.build_meta; no other install-reached package code.",
      "ve_build_ext only wraps setuptools build_ext and turns compiler or platform errors into BuildFailed; it compiles src/markupsafe/_speedups.c.",
      "CIBUILDWHEEL == '1' and platform.python_implementation() not in PyPy/Jython/GraalVM only choose between building the C speedups extension and a plain-Python build; every branch is benign_build, so neither is a gate.",
      "Under CIBUILDWHEEL=1 a failed C build is not retried without the extension; otherwise BuildFailed is caught, a warning printed and the build retried. Failures are printed, not hidden."
    ]
  },
  "requirements": [],
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
  "assessment_reason": "The install runs the upstream MarkupSafe setup.py, which only builds the optional C speedups extension through setuptools and falls back to a pure-Python build. No network, credential, or process activity outside the normal build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "d95b67955e8b5287"
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
        "candidate": "k_ac939c6491",
        "reason_code": "other",
        "note": "CIBUILDWHEEL check only decides whether a failed C extension build is retried as plain Python; both sides run the same native build (benign_build), so no behaviour class changes.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1437,
          "end_byte": 1479,
          "node_type": "comparison_operator",
          "sha256": "3fa0ef1162b45a90",
          "line": 60
        }
      },
      {
        "candidate": "q_cdb829d81d",
        "reason_code": "other",
        "note": "if/elif/else only picks C-extension build vs plain-Python build vs build with fallback; every branch is benign_build via run_setup, so it is build plumbing, not a gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1434,
          "end_byte": 2237,
          "node_type": "if_statement",
          "sha256": "bf002c76c865bcb0",
          "line": 60
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
