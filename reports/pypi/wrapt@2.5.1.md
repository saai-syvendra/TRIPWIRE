# pypi wrapt@2.5.1

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-14 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

wrapt 2.5.1 is an sdist built with setuptools.build_meta, so `setup.py` runs during a pip install. It reads `WRAPT_INSTALL_EXTENSIONS` (falling back to `WRAPT_EXTENSIONS`) and `platform.python_implementation()` to decide whether to compile the optional C extension `src/wrapt/_wrappers.c`, then calls `setuptools.setup`. Those checks only choose build options, so no gates are recorded. The only install behaviour is a normal package build.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, native_build.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- No candidates from the extractor; no sinks, endpoints or obfuscation.
- The extension is `optional=True` unless the env var is `true`, so a missing compiler doesn't stop the build.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "wrapt",
    "version": "2.5.1",
    "archive_sha256": "f595bb0185aab3e9dc31950c95d914f56ea8278810c3b928f3426e12ed6d27bc",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-14",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/wrapt-2.5.1.tar.gz",
    "package_root": "layer0/wrapt-2.5.1",
    "cluster_key": "3111e1830199e5caa531a929adc6923b1b12246f4d040c4e6909b14067d53c12",
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
      "setup.py: read in full (36 lines). Backend is setuptools.build_meta, so setup.py runs at build; no cmdclass overrides, no network, no process launch of its own.",
      "WRAPT_INSTALL_EXTENSIONS / WRAPT_EXTENSIONS env vars and platform.python_implementation() only choose whether the optional C extension src/wrapt/_wrappers.c is compiled; both sides end in a setuptools build, so treated as build options, not gates.",
      "The C extension is declared optional unless WRAPT_INSTALL_EXTENSIONS=true, so a missing compiler only skips it; no compiler requirement recorded.",
      "src/wrapt/ and tests/ are library and test code loaded only at import or test time, not at install."
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
  "assessment_reason": "setup.py only reads two build-option env vars and the Python implementation to decide whether to compile wrapt's optional C extension, then calls setuptools.setup. No network, process launch, file access or decoding at install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
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
    "conditions_out_of_set": 0,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
