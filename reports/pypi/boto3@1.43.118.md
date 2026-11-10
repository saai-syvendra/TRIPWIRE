# pypi boto3@1.43.118

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-22 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

boto3 1.43.118 is an sdist built by setuptools, so setup.py runs at install. It reads `__version__` from `boto3/__init__.py` with a regex, reads `README.rst` for the long description and calls `setup()` with static metadata and three AWS dependencies. There are no gates, no cmdclass overrides and no install-time behaviour beyond build plumbing.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

The two URLs in setup.py (project homepage and documentation) are metadata only and are not contacted at install, so they were removed from reachability endpoints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "boto3",
    "version": "1.43.118",
    "archive_sha256": "c0620f799e0f0c222ba42c337b65cdbcd3da38a3121187f634d8926cbbb28a9c",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-22",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/boto3-1.43.118.tar.gz",
    "package_root": "layer0/boto3-1.43.118",
    "cluster_key": "ae77386f39e83e3238b4d7e253e1f134a52569debb7cbb5d1ac083b0cd530b25",
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
      "setup.py: read in full. Only build plumbing: reads __version__ from boto3/__init__.py by regex, reads README.rst for long_description, calls setuptools.setup(). No cmdclass, no subprocess, no network.",
      "pyproject.toml has no build-system table (setuptools default); setup.cfg only holds metadata and extras. install_requires botocore, jmespath, s3transfer (dependency tree, official AWS packages)."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [],
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
  "assessment_reason": "The sdist's setup.py only reads the version string and README and calls setuptools.setup() with static metadata. No environment checks, process launches, network access or file writes by package code at install.",
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
