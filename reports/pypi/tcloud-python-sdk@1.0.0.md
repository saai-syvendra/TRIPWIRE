# pypi tcloud-python-sdk@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Installing the sdist runs setup.py through setuptools. Its top level imports a module named `tencentcloud`, which the sdist does not ship and does not declare as a dependency, then reads README.rst and calls setup() with literal metadata. There are no environment checks, so no gates, and no install-time behaviour beyond build metadata. On a machine without a `tencentcloud` module the import raises ImportError and the build fails before setup() is reached.

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

- The sdist contains no Python package at all (empty top_level.txt), so there is no import-time code either.
- Source label is malicious; nothing in the shipped files supports it. Either the payload was stripped from this sample or the attack relies on a separately published `tencentcloud` module that `import tencentcloud` would run. That external code is out of scope here.
- The name and README point at the Tencent Cloud SDK, which hints at impersonation, but that rests on name and text only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "tcloud-python-sdk",
    "version": "1.0.0",
    "archive_sha256": "3c8dbead892b03cb439935a04be496e0bd0c043ce1a3be9775d1517e4c174b38",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/tcloud-python-sdk-1.0.0.tar.gz",
    "package_root": "layer0/tcloud-python-sdk-1.0.0",
    "cluster_key": "60c0db34b2e05ef41e1618aae12e378a05f24ab95a35ae6a71ceb6e599e2aa3f",
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
      "setup.py: read in full. Top level does `import tencentcloud` (not shipped in the sdist, no install_requires), reads README.rst for long_description, then calls setup() with literal metadata. No gates, no sinks.",
      "`import tencentcloud` runs whatever installed module of that name exists; on a clean machine it raises ImportError and the build fails before setup(). Not a deliberate check, so not a gate. Code of an external tencentcloud module is out of scope.",
      "No package module ships: SOURCES.txt lists only setup.py, README, LICENSE and metadata, and top_level.txt is empty, so there is no import-time code either.",
      "The name and README point at the Tencent Cloud SDK (README tells users to pip install a differently named package). Impersonation rests on name and text only, so attack_type is left unknown."
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
  "attack_type": "unknown",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The only install-reached file, setup.py, imports a tencentcloud module the sdist does not ship, reads README.rst and calls setup() with static metadata. There is no process launch, network access, file write or decode at install time, and the sdist contains no package module at all.",
  "label_disagreement": true,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Source label is malicious but the sdist holds only setup.py, README, LICENSE and metadata with no payload anywhere; the malicious part may have been stripped from the sample or live in a separately published tencentcloud module.",
    "label disagreement"
  ],
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
