# pypi antchain_sdk_cat@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command (`cmdclass={'install': CustomInstall}`), which runs during a normal pip install from source. After calling the stock install, `CustomInstall.run` reads the hostname, current working directory and username and sends them as query parameters in an HTTP GET to an out-of-band interaction host (5r13v9[.]ceye[.]io). There are no environment gates: the beacon runs unconditionally on every install. It only needs outbound HTTP to that host and the `requests` module being importable when setup.py runs.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: 5r13v9[.]ceye[.]io:80 (recon data is sent by HTTP GET to an out-of-band interaction host)
- other: python module requests importable when setup.py runs (setup.py imports requests at top level without declaring it; under pip build isolation the import raises and nothing runs)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `requests` is imported at the top of setup.py but not declared as a build requirement, so in an isolated pip build the import fails and no code runs; listed as a requirement.
- The first-line comment points to a public dependency-confusion PoC repository and the code matches that template's shape. The attack type rests on the code (an unconditional host beacon) and the internal-SDK-style name, not on the comment.
- The GitHub URL in the comment is never contacted, so it is not listed as an endpoint.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "antchain_sdk_cat",
    "version": "1.0.0",
    "archive_sha256": "dff14895e9641f8a4637fd783055823227e29a3fc38247f6ea192d13b3c7ad29",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/antchain_sdk_cat-1.0.0.tar.gz",
    "package_root": "layer0/antchain_sdk_cat-1.0.0",
    "cluster_key": "4ed485e008e15cbdd3c58456944d3e4046fbf81c43f46e71d276a4f8d27c8da4",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstall",
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
      "setup.py: read in full (25 lines); the only install-reached file. No environment checks on the install path.",
      "CustomInstall.run calls install.run, then reads hostname, cwd and username and sends them as GET query params to an interaction host; no try/except around it.",
      "setup.py imports requests at module level but declares no build requirement; in an isolated pip build the import fails before setup() runs."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "5r13v9[.]ceye[.]io:80",
      "reason": "recon data is sent by HTTP GET to an out-of-band interaction host"
    },
    {
      "axis": "other",
      "value": "python module requests importable when setup.py runs",
      "reason": "setup.py imports requests at top level without declaring it; under pip build isolation the import raises and nothing runs"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil"
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
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://5r13v9[.]ceye[.]io",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dependency-confusion PoC template",
  "claude_assessment": "malicious",
  "assessment_reason": "An install command override sends the host's hostname, working directory and username to an out-of-band interaction domain on every install, with no gate. The code is a dependency-confusion proof-of-concept template under a name resembling an internal SDK.",
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
