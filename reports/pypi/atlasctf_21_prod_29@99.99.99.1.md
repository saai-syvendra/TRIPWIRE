# pypi atlasctf_21_prod_29@99.99.99.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command (`CustomInstallCommand`), so the payload runs during a normal pip install from source. After calling `install.run`, it reads `/flag.txt` and POSTs the contents to a webhook.site URL inside a bare `try/except: pass`. There are no gates: the file read is unconditional, and a missing file only makes the try fail silently. A dynamic scanner sees the exfil as long as `/flag.txt` exists, webhook.site is reachable and `requests` can be imported at build time.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- file_present: /flag.txt (payload reads this file unconditionally; if absent the read raises and nothing is sent)
- network: webhook[.]site:443 (file contents are POSTed to a webhook.site URL)
- other: Python module requests importable in the build environment (setup.py imports requests at top level without declaring it as a build requirement)

## Behaviour

- Ungated: cred_read, exfil
- Gated: none

## Notes

- The name pattern and the inflated version 99[.]99[.]99[.]1 point to a CTF dependency-confusion challenge. The "flag" is the target secret, so I recorded the read as `cred_read`.
- `99[.]99[.]99[.]1` in the endpoint hints is just the version string. I removed it from the endpoints.
- The package `__init__.py` sends `/etc/passwd` to the same webhook on import. That is import time, so it is out of scope here.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "atlasctf_21_prod_29",
    "version": "99.99.99.1",
    "archive_sha256": "e6670f66c5a2b686e2c85afd27af9c7b855baa718ef16d8e5f3312483c785de8",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/atlasctf_21_prod_29-99.99.99.1.tar.gz",
    "package_root": "layer0/atlasctf_21_prod_29-99.99.99.1",
    "cluster_key": "79166269635adf41f2eae2e50c7ccfb4b9735b8058272851bb3302b221cd4c05",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
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
      "setup.py read in full (20 lines). The install override calls install.run, then reads /flag.txt and POSTs its contents to a webhook; a bare except swallows any failure.",
      "The read of /flag.txt is unconditional inside the try; a missing file just raises into the bare except. Recorded as a requirement, not a gate.",
      "setup.py top level only imports requests and calls setup(); requests is not declared in setup_requires, so the build needs it already installed.",
      "atlasctf_21_prod_29/__init__.py reads /etc/passwd and POSTs it to the same webhook, but only on import; not install time, out of scope."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "/flag.txt",
      "reason": "payload reads this file unconditionally; if absent the read raises and nothing is sent",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 220,
          "end_byte": 237,
          "node_type": "call",
          "sha256": "4887afb460d79182",
          "line": 9
        }
      ]
    },
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "file contents are POSTed to a webhook.site URL",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 288,
          "end_byte": 418,
          "node_type": "call",
          "sha256": "80275c16f6001b06",
          "line": 11
        }
      ]
    },
    {
      "axis": "other",
      "value": "Python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level without declaring it as a build requirement",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 91,
          "end_byte": 106,
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
      "cred_read",
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
        "indicator": "hxxps://webhook[.]site/0b19…/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "atlasctf flag exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "The install override reads /flag.txt and POSTs its contents to a webhook.site URL, with no gate in front. It looks like a CTF dependency-confusion exercise (version 99[.]99[.]99[.]1), but the install code does exfiltrate a local file.",
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
