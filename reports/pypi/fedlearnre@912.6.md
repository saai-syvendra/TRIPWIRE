# pypi fedlearnre@912.6

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command with `CrazyInstallStrat`, whose `run` calls `install.run` and then imports and calls `main()` from `main.py`. `main()` reads the hostname, username and current working directory and sends them as query parameters in an HTTP GET to each of three OAST callback hosts (two under byted-dast[.]com, one under oast[.]fun). There are no gates: nothing checks the environment, so any pip install of the sdist runs the beacon. The only need is outbound HTTP to at least one of the hosts; failures are caught and logged.

## Execution

- **cmdclass** `cmdclass[install] = CrazyInstallStrat`: 2-file chain; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: dnipqouebm-psl[.]cn[.]oast-cn[.]byted-dast[.]com:80, oqvignkp58-psl[.]i18n[.]oast-row[.]byted-dast[.]com:80, sbfwstspuutiarcjzptfenn9u0dsxhjlu[.]oast[.]fun:80 (HTTP GET beacons carrying host data; each failure is swallowed, so at least one must be reachable for the exfil to land)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The inflated version (912.6), the placeholder metadata and the OAST endpoints point to a dependency-confusion probe. The beacon sends host identity data and nothing else.
- `main.py` imports only `urllib` and then uses `urllib.parse` and `urllib.request`. This works at install because setuptools and pip have already loaded those submodules.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "fedlearnre",
    "version": "912.6",
    "archive_sha256": "c44bb37d4fd270d7332440185ad9b174e79398f4c2cf4a2736766e0bc658c650",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/fedlearnre-912.6.tar.gz",
    "package_root": "layer0/fedlearnre-912.6",
    "cluster_key": "db3446af3a805cc3af657d3ede3fdcfa2e48addb43752aba4d695fb192d9f697",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CrazyInstallStrat",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "main.py"
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
      "setup_requires (dependency tree): ['setuptools']",
      "setup.py and main.py are package code, read in full. Top-level setup.py only calls setup(); main.py is imported and main() called only from CrazyInstallStrat.run, after install.run, so the payload sits on the cmdclass hook.",
      "main.py collects platform.node(), getpass.getuser() and os.getcwd() and sends them as query params in a GET to each of three OAST callback hosts. Each urlopen is wrapped in try/except Exception that only logs, so failures are hidden.",
      "main.py does 'import urllib' only and then uses urllib.parse and urllib.request; these resolve because setuptools/pip have already imported those submodules during the build. No condition or branch on the environment exists."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "dnipqouebm-psl[.]cn[.]oast-cn[.]byted-dast[.]com:80, oqvignkp58-psl[.]i18n[.]oast-row[.]byted-dast[.]com:80, sbfwstspuutiarcjzptfenn9u0dsxhjlu[.]oast[.]fun:80",
      "reason": "HTTP GET beacons carrying host data; each failure is swallowed, so at least one must be reachable for the exfil to land"
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
        "indicator": "hxxp://dnipqouebm-psl[.]cn[.]oast-cn[.]byted-dast[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxp://oqvignkp58-psl[.]i18n[.]oast-row[.]byted-dast[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxp://sbfwstspuutiarcjzptfenn9u0dsxhjlu[.]oast[.]fun",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast-callback-beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "An install cmdclass override sends hostname, username and current directory to three out-of-band callback hosts on every sdist install, with no gate. The pattern (unknown internal-looking name, inflated version 912.6, OAST endpoints) is a dependency-confusion probe.",
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
