# pypi dbcounter@1.0.4

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py registers a `CustomInstall` class as the `install` cmdclass, so its `run` method executes during a normal pip install from source. After calling the stock `install.run`, it collects the hostname, current working directory and username and sends them as query parameters in a `requests.get` to an oast[.]fun out-of-band interaction host. There are no gates: nothing checks the environment, so any sdist install that can reach the host triggers the beacon.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: cck47c52vtc0000zed2gggj1d9yyyyyyn[.]oast[.]fun:443 (recon data is sent as GET query parameters to this host)
- other: python package requests importable during the sdist build (setup.py imports requests at top level and uses requests.get for the beacon)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The only requirements are outbound HTTPS to the oast[.]fun host and `requests` being importable in the build environment (imported at setup.py top level).
- The `description='Exfiltration'` metadata matches the code but is package text, not evidence; the assessment rests on the code.
- No try/except around the request, so a blocked network fails the install visibly.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "dbcounter",
    "version": "1.0.4",
    "archive_sha256": "d5452327dfcbddf918717f3c34055a9cd111bc3144352ddc6d1c33a2691e9db8",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/dbcounter-1.0.4.tar.gz",
    "package_root": "layer0/dbcounter-1.0.4",
    "cluster_key": "ea6e82e1a285a2cd900f5738bf44b09efaf7fc48d8ad02739c4bb1fef28f1760",
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
      "setup.py: read in full (24 lines). Top level only imports and calls setup(); the payload is in CustomInstall.run, after install.run(self). No conditions, gates or delays.",
      "The setup_py entry adds nothing of its own beyond the top-level imports; requests is imported at module top, so setup.py fails with ImportError if requests is not installed in the build environment.",
      "requests.get is not wrapped in try/except, so an unreachable endpoint raises and fails the install visibly."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cck47c52vtc0000zed2gggj1d9yyyyyyn[.]oast[.]fun:443",
      "reason": "recon data is sent as GET query parameters to this host"
    },
    {
      "axis": "other",
      "value": "python package requests importable during the sdist build",
      "reason": "setup.py imports requests at top level and uses requests.get for the beacon"
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
        "indicator": "hxxps://cck47c52vtc0000zed2gggj1d9yyyyyyn[.]oast[.]fun",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "oast[.]fun install-time recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "A cmdclass install override sends the hostname, current working directory and username to an oast[.]fun out-of-band interaction host on every sdist install, with no environment check. Small and unobfuscated, typical of dependency-confusion style probing.",
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
