# pypi barcodegeneratorqr@1.0.3

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command with a class `Updater`, which runs on a normal pip install from source. `Updater.run` assembles a Discord CDN attachment URL from short string fragments, downloads `qrcodegen.py` from it with `requests.get`, writes it to the working directory and runs it with `sys.executable`. There are no gates on the install path: any environment with network access to the Discord CDN and `requests` available runs the second stage.

## Execution

- **cmdclass** `cmdclass[install] = Updater`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: cdn[.]discordapp[.]com:443 (second-stage qrcodegen.py is downloaded from a Discord CDN attachment)
- other: Python module requests importable in the build environment (setup.py imports requests at top level; declared in setup_requires and build-system.requires)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- The second stage was not fetched, so any gates inside it are unknown. The endpoint's attachment ids are redacted.
- `barcodegeneratorqr/__init__.py` only re-exports `vidstream` classes and runs only on import.
- The `url` in `setup()` points to a GitHub repo that is only metadata and is never contacted at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "barcodegeneratorqr",
    "version": "1.0.3",
    "archive_sha256": "a0fcb7fb01b534c7b3dd984a4223413a271cce13d8e1e8308f7d96ce5f0523d0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/barcodegeneratorqr-1.0.3.tar.gz",
    "package_root": "layer0/barcodegeneratorqr-1.0.3",
    "cluster_key": "0e46ee82d8c2e04b39f746626eb4e86403cd11dca411788094a7334b2cb9125e",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = Updater",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
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
      "setup_requires (dependency tree): ['requests', 'pycryptodome']",
      "setup.py: read in full (57 lines). Top-level code only builds string fragments and calls setup(); the payload is in Updater.run (cmdclass install). No conditions anywhere on the install path; nothing unread.",
      "Updater.run builds a Discord CDN attachment URL from string fragments, downloads qrcodegen.py with requests.get, writes it to the build cwd and runs it with sys.executable via subprocess.check_call, then calls the normal install.",
      "The downloaded qrcodegen.py is not in the package and was not fetched; its behaviour and any gates inside it are unknown.",
      "barcodegeneratorqr/__init__.py only re-exports vidstream classes; it runs at import, not at install, and is out of scope."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cdn[.]discordapp[.]com:443",
      "reason": "second-stage qrcodegen.py is downloaded from a Discord CDN attachment"
    },
    {
      "axis": "other",
      "value": "Python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level; declared in setup_requires and build-system.requires"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
      "write_file",
      "exec_downloaded"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "download URL assembled from many short string fragments in an f-string",
      "requests imported under the alias 'updating'"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://cdn[.]discordapp[.]com/attachments/1121…/1121…/qrcodegen.py",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "An overridden install command unconditionally downloads a Python script from a Discord CDN attachment URL hidden in string fragments, writes it to disk and runs it with the build interpreter.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
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
