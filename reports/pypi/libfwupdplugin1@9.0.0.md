# pypi libfwupdplugin1@9.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with `CustomInstall`, so its `run` method executes during a normal pip install of the sdist. After calling the stock install it reads the hostname, current working directory and username and sends them as query parameters in an HTTPS GET to an interactsh (oast) callback host. There are no gates: nothing checks the environment before the callback. The payload only needs `requests` to be importable in the build environment and outbound HTTPS to the callback host.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: chc7ss72vtc0000ra0e0gesdhhwyyyyyb[.]oast[.]fun:443 (HTTPS GET that carries the collected host data)
- other: python module requests importable in the build environment (setup.py imports requests at top level without declaring it; with build isolation it is absent and setup.py fails before the install hook)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The code is the common dependency-confusion proof-of-concept callback (hostname, cwd, username). A comment in setup.py links a public PoC repo; that link is not contacted and the classification rests on the code.
- `requests` is imported at top level but never declared as a build requirement, so under pip's isolated build the import fails and the callback never fires. A scanner needs `requests` available (non-isolated build) to see it.
- The `setup()` description and author fields carry a handle; not recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "libfwupdplugin1",
    "version": "9.0.0",
    "archive_sha256": "653972d1b614977d6f76669130a5715c000530318e146c6681fdb9cf739efbc2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/libfwupdplugin1-9.0.0.tar.gz",
    "package_root": "layer0/libfwupdplugin1-9.0.0",
    "cluster_key": "013864985502daf080106fa04dab77b3e8e2a81ce5bca0d9dd57d148a8a0c854",
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
      "setup.py: read in full (25 lines). Top level only imports modules and calls setup(); the payload is in CustomInstall.run, which calls install.run first and then sends the data.",
      "No environmental check anywhere: hostname, cwd and username are collected only to be sent, so they are recon, not gates.",
      "requests is imported at top level but not declared in setup_requires or a pyproject; under pip build isolation the import fails and nothing runs. Recorded as a requirement."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "chc7ss72vtc0000ra0e0gesdhhwyyyyyb[.]oast[.]fun:443",
      "reason": "HTTPS GET that carries the collected host data"
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level without declaring it; with build isolation it is absent and setup.py fails before the install hook",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 174,
          "end_byte": 189,
          "node_type": "import_statement",
          "sha256": "06185522e4085460",
          "line": 4
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
        "indicator": "hxxps://chc7ss72vtc0000ra0e0gesdhhwyyyyyb[.]oast[.]fun",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dependency-confusion PoC (interactsh callback)",
  "claude_assessment": "malicious",
  "assessment_reason": "The install override sends the machine's hostname, working directory and username to an interactsh (oast) callback host on every install, with no gate in front. It is the standard dependency-confusion proof-of-concept callback: limited recon, but unsolicited exfiltration at install time.",
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
