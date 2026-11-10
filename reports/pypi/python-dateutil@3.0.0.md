# pypi python-dateutil@3.0.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-21 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This sdist builds through setuptools.build_meta, so setup.py runs at install. setup.py reads README.rst, swaps `.. doctest` directives for code blocks in the long description, and calls setup() with setuptools_scm writing the version file. There are no gates: no environment checks, no network, no process launches. The install behaviour is an ordinary benign build.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- setup.cfg is metadata and packaging options only; no cmdclass overrides or in-tree backend.
- subprocess and requests uses exist only in tests/ helpers, which the install never reaches.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "python-dateutil",
    "version": "3.0.0",
    "archive_sha256": "7ebcb3c29a92f3ceafe79a7a48a5c45677e9e004bbeec5742ac0bbb00560b7a2",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-21",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/python_dateutil-3.0.0.tar.gz",
    "package_root": "layer0/python_dateutil-3.0.0",
    "cluster_key": "a46a996d0e2c67824367e5d2582d29d83f714f92229f20c9702611c18740dff7",
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
      "setup.py: read in full; it reads README.rst, rewrites '.. doctest' lines for long_description and calls setup() with use_scm_version writing src/dateutil/_version.py. No other code runs.",
      "pyproject.toml uses setuptools.build_meta with build requirements setuptools and setuptools_scm<8.0 (dependency tree); setup.cfg holds metadata only, no cmdclass or entry hooks.",
      "install_requires: six>=1.6, tzdata (dependency tree). Package modules under src/ and tests/ are not reached at install."
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
  "assessment_reason": "The only install-time code is a standard setuptools setup.py that reads README.rst for the long description and builds with setuptools_scm. There are no environment checks, network calls, process launches or writes beyond the normal build.",
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
