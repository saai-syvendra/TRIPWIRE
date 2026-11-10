# pypi 0x000testqwe@5.20.4

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command with `CustomInstall`, which runs during a normal pip install of the sdist. After calling the stock install, `run` reads the hostname, current working directory and username and sends them as query parameters in a `requests.get` to a Burp Collaborator host. There are no gates: no conditions, no early exits and no error handling. Any environment that can import `requests` during the build and reach the host triggers the beacon.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- other: Python module requests importable by the setup.py build environment (setup.py imports requests at line 3 and calls requests.get; no pyproject.toml or setup_requires provides it)
- network: yourburpcolloboratorid[.]burpcollaborator[.]net:443 (recon data is sent as GET query parameters to this host)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The collaborator host (`yourburpcolloboratorid[.]burpcollaborator[.]net`) looks like an unedited template placeholder, so the beacon may never have reached a real listener. It is still recon plus exfil at install time.
- `requests` is imported at the top of setup.py but is not declared as a build requirement, so an isolated PEP 517 build without it fails on import before anything runs. This is recorded as a requirement.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "0x000testqwe",
    "version": "5.20.4",
    "archive_sha256": "3fdaa917d30f5e77d88a59461614b15dc1db98366b809440e7dd2c29b1453a17",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/0x000testqwe-5.20.4.tar.gz",
    "package_root": "layer0/0x000testqwe-5.20.4",
    "cluster_key": "53798982ee497308cf72b84daa26fb04dfbd08d0e1119cb1a727e3f3763ab72a",
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
      "setup.py: read in full (24 lines); no other package code. setup.cfg holds only egg_info tags.",
      "Top-level setup.py code only imports modules and calls setup(); the payload is in CustomInstall.run, after install.run(self). No conditions, no try/except, no delays.",
      "setup.py imports requests at top level but declares no build requirement; in an isolated PEP 517 build env without requests the import fails and nothing runs."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "Python module requests importable by the setup.py build environment",
      "reason": "setup.py imports requests at line 3 and calls requests.get; no pyproject.toml or setup_requires provides it"
    },
    {
      "axis": "network",
      "value": "yourburpcolloboratorid[.]burpcollaborator[.]net:443",
      "reason": "recon data is sent as GET query parameters to this host"
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
        "indicator": "hxxps://yourburpcolloboratorid[.]burpcollaborator[.]net",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "burp collaborator install-time beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override collects hostname, working directory and username and sends them to a Burp Collaborator host on every sdist install, with no gate. The host looks like an unfilled template placeholder, so it reads as a test or research beacon, but it still exfiltrates host identity at install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
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
