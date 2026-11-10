# pypi s3transfer@0.19.3

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

s3transfer 0.19.3 is an sdist with no build-system table in pyproject.toml, so pip builds it through setuptools and runs setup.py. setup.py reads `__version__` from `s3transfer/__init__.py`, reads README.rst, and calls `setup()` with static metadata and a botocore dependency. There are no environment checks, so there are no gates. The only install-time behaviour is the normal setuptools build.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- file_present: s3transfer/__init__.py (get_version() opens it unconditionally to read __version__; ships in the sdist)
- file_present: README.rst (read unconditionally for long_description; ships in the sdist)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

The GitHub project URL in setup.py is metadata only and is never contacted, so it was removed from reachability.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "s3transfer",
    "version": "0.19.3",
    "archive_sha256": "8326acc3d056d7f7b8a37110c7d2aea41f67e83f6ae79cd3b5fbcca34c726406",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/s3transfer-0.19.3.tar.gz",
    "package_root": "layer0/s3transfer-0.19.3",
    "cluster_key": "4d8ee6826f506785dddb57d74c104e79285e8702748d99fe635e27ee8431eacf",
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
      "setup.py: read in full (52 lines). It reads __version__ from s3transfer/__init__.py with a regex, reads README.rst for long_description and calls setuptools.setup(). No cmdclass, no process launch, no network.",
      "pyproject.toml has only pytest and ruff config, no build-system table, so pip uses the setuptools legacy backend. setup.cfg holds only metadata and egg_info options.",
      "Dependency tree: install_requires botocore>=1.37.4,<2.0a.0; extra crt pulls botocore[crt]. python_requires >= 3.10 (ordinary).",
      "The s3transfer/ library modules and tests/ are not reached at install; they only run when the package is imported or tests are run."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "s3transfer/__init__.py",
      "reason": "get_version() opens it unconditionally to read __version__; ships in the sdist"
    },
    {
      "axis": "file_present",
      "value": "README.rst",
      "reason": "read unconditionally for long_description; ships in the sdist"
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
  "assessment_reason": "The only install-time code is a standard setuptools setup.py that reads the version string and README and calls setup(). There are no environment checks, process launches, network calls or file writes beyond the normal build.",
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
