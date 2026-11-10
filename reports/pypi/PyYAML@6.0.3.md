# pypi PyYAML@6.0.3

**Source:** benign_sample · **Source label:** benign · **Released:** 2025-09-25 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is the PyYAML 6.0.3 sdist. Building it runs the in-tree PEP 517 backend `packaging/_pyyaml_pep517.py`, which re-exports the `setuptools.build_meta` hooks inside a context that exposes `config_settings`. setuptools then runs `setup.py`. Its `build_ext` override compiles the `yaml._yaml` libyaml/Cython extension and falls back to pure Python when that fails. No gates: the environment reads (Windows warning filters, `PYYAML_FORCE_*` variables, Python implementation) only pick build options for the same benign build.

## Execution

- **build_backend** `in-tree build backend _pyyaml_pep517`: 2-file chain; direct_script, native_build.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The prepared note said the backend does not run `setup.py`. That is wrong: the backend delegates to `setuptools.build_meta`, which runs it. `setup.py` was added to the file chain and read in full.
- All endpoints are project metadata URLs or a comment link. None is contacted at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "PyYAML",
    "version": "6.0.3",
    "archive_sha256": "d76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2025-09-25",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/pyyaml-6.0.3.tar.gz",
    "package_root": "layer0/pyyaml-6.0.3",
    "cluster_key": "9faa343b68bdd337802ac15cf3859db5dfb12eb7df6b53fa615a10496b1b08c1",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "build_backend",
        "command": "in-tree build backend _pyyaml_pep517",
        "runs_on": "always",
        "file_chain": [
          "packaging/_pyyaml_pep517.py",
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
      "The tool note that the backend does not run setup.py is wrong: _pyyaml_pep517 re-exports setuptools.build_meta hooks wrapped in a config-settings context, and build_meta runs setup.py, so setup.py is install-reached.",
      "packaging/_pyyaml_pep517.py and setup.py read in full. No network, exec of downloaded code, eval or file writes outside the normal setuptools build; lib/ and tests/ are not reached at install.",
      "setup.py build_ext override compiles the yaml._yaml libyaml/Cython extension and falls back to pure Python on CompileError/LinkError or DistutilsPlatformError when the extension is optional. These are build choices (compile vs pure Python), not gates.",
      "Environment reads in setup.py (platform.system() == 'Windows' only filters warnings; PYYAML_FORCE_CYTHON, PYYAML_FORCE_LIBYAML, platform.python_implementation()) only pick build options for the same benign build; not recorded as gates.",
      "Build requirements: setuptools and Cython (version by python_version marker); dependency tree only. The test cmdclass runs only on direct setup.py test, not at install."
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
  "assessment_reason": "The in-tree backend only wraps setuptools.build_meta, and setup.py configures and compiles the libyaml C/Cython extension with a pure-Python fallback. The install has no network access, credential reads or execution of anything outside the normal build.",
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
