# pypi python3-ki@610.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command, so `CustomInstall.run` executes on a normal pip install from source. After running the stock install, it reads the hostname, current working directory and username and sends them as query parameters in a `requests.get` to a pipedream collector (hxxps://eolunbv9e34gp3b[.]m[.]pipedream[.]net). There are no gates: the beacon runs in any environment, needing only outbound HTTPS and the `requests` module in the build environment.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: eolunbv9e34gp3b[.]m[.]pipedream[.]net:443 (recon data is sent by HTTPS GET to this collector)
- other: python module requests importable in the build environment (setup.py imports requests at top level and no pyproject.toml declares it; without it setup.py fails before the payload)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Version 610.0.0 with no real package code looks like a dependency-confusion probe; the attack type is inferred from that shape, not from package text.
- `requests` is imported at top level but not declared as a build requirement, so under build isolation without it the build fails before the payload runs.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "python3-ki",
    "version": "610.0.0",
    "archive_sha256": "d67b3e35502a4c3f1d5f1cc2fec5e96a6b5443e1464601c341dd59a04758ba5c",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/python3-ki-610.0.0.tar.gz",
    "package_root": "layer0/python3-ki-610.0.0",
    "cluster_key": "d5820eb84c91715c300ed0c5c3d8bece379da5a8c321f3b1755669c3a89b9a64",
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
      "setup.py: package code read in full (24 lines); no other install-reached files.",
      "CustomInstall.run calls install.run first, then collects hostname, cwd and username and sends them as query parameters to a pipedream collector. No checks or branches.",
      "The setup_py hook only runs imports and setup(); the payload is in the install cmdclass override."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "eolunbv9e34gp3b[.]m[.]pipedream[.]net:443",
      "reason": "recon data is sent by HTTPS GET to this collector"
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level and no pyproject.toml declares it; without it setup.py fails before the payload",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 76,
          "end_byte": 91,
          "node_type": "import_statement",
          "sha256": "06185522e4085460",
          "line": 3
        }
      ]
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
        "indicator": "hxxps://eolunbv9e34gp3b[.]m[.]pipedream[.]net",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pipedream recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override sends the hostname, working directory and username to a pipedream collector on every sdist install, with no gate. The very high version number and empty package fit a dependency-confusion probe.",
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
