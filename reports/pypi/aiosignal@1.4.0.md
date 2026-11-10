# pypi aiosignal@1.4.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2025-07-03 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

aiosignal 1.4.0 is an sdist built with the setuptools.build_meta backend. At install, pip runs `setup.py`, which only calls `setup()`. All metadata comes from a static `setup.cfg`, and the version is read with `attr: aiosignal.__version__`, which is a plain literal. The install path has no gates, no network access, no process launches and no file operations beyond the normal build, so the only behaviour is `benign_build`.

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

- `aiosignal/__init__.py` has `sys.version_info` checks that pick typing imports. Those are import-time code, and they run at build only if setuptools falls back to importing the module to read the version. They are not install gates.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aiosignal",
    "version": "1.4.0",
    "archive_sha256": "f47eecd9468083c2029cc99945502cb7708b082c232f9aca65da147157b251c7",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2025-07-03",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/aiosignal-1.4.0.tar.gz",
    "package_root": "layer0/aiosignal-1.4.0",
    "cluster_key": "0b7ff7cdfc40d92336ea2b3f5f25a43517d17f2a0e2efde21cc5c251f024ccbc",
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
      "setup.py: read in full, a bare setup() call under a __main__ guard. setup.cfg and pyproject.toml read: setuptools.build_meta backend, static metadata, version via attr: aiosignal.__version__ (a literal).",
      "aiosignal/__init__.py read in full: typing imports chosen by sys.version_info and the Signal class. It runs at build only if setuptools falls back to importing it for the version; no gates or sinks.",
      "Dependency tree: build requires setuptools>=51.0; install_requires frozenlist>=1.1.0 and typing-extensions>=4.2 (python_version < 3.13)."
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
  "assessment_reason": "setup.py only calls setuptools.setup() with metadata from a static setup.cfg. There are no environment checks and no network, process or file operations beyond the normal setuptools build.",
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
