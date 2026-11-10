# pypi certifi@2026.10.23

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-23 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

certifi 2026.10.23 is an sdist built with setuptools.build_meta, so pip runs setup.py at install. setup.py imports setup (falling back to distutils), reads `__version__` from `certifi/__init__.py` with a regex, reads README.rst for the long description and calls setup() with static metadata. There are no gates: nothing checks the environment, and there is no cmdclass override, network access, process launch or eval. The only install-time behaviour is the ordinary package build.

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

- The project URL in setup() is metadata only and is not contacted at install, so it is not listed as an endpoint.
- The setuptools/distutils try/except is a fallback for an import and not a gate. The RuntimeError raised when no version is found is a build sanity check.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "certifi",
    "version": "2026.10.23",
    "archive_sha256": "a9895e6e2758b371e0545e321a3a8fd1fcfd9829ada8824a936dfb16aaaf36cd",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-23",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/certifi-2026.10.23.tar.gz",
    "package_root": "layer0/certifi-2026.10.23",
    "cluster_key": "814b12c6eb8bdd8f60e5e11f5ce774a2bcc04675b93ca926124b217d8ecb7413",
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
      "setup.py: read in full. Imports setup from setuptools (distutils fallback on ImportError, plumbing), reads __version__ from certifi/__init__.py by regex, reads README.rst, calls setup(). No cmdclass, no process, network or eval sinks.",
      "Build backend is setuptools.build_meta (pyproject.toml); setup.cfg only sets egg_info tags. The 'raise RuntimeError' when no version is found is a build sanity check, not environmental.",
      "certifi/core.py and __init__.py run only when the package is imported (CA bundle path lookup); not reached at install."
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
  "assessment_reason": "The only install-time code is a standard setuptools setup.py that reads the version string and README and declares package metadata. No gates, no network, process or file-write behaviour of its own.",
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
