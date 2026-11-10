# pypi nnabla-dataset-uploader@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2022-12-07 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command with `CustomInstall`, which runs on a normal pip install. After the regular install step it collects the hostname, current working directory and username and sends them as query parameters in an HTTPS GET to an OAST host (`cdf5rwk2vtc0000c78d0ggz1hqeyyyyyb[.]oast[.]fun`). There are no gates: the callback runs in every environment, provided `requests` is importable and the host is reachable.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: cdf5rwk2vtc0000c78d0ggz1hqeyyyyyb[.]oast[.]fun:443 (recon data is sent via HTTPS GET to this OAST host)
- other: Python module requests importable in the build environment (setup.py imports requests at top level; it is not declared as a build requirement)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `requests` is imported at top level of `setup.py` but never declared as a build dependency, so in an isolated build env without it the build fails before the payload.
- Name, `description='test'` and the OAST callback point to a dependency confusion probe against the nnabla ecosystem; no second stage.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "nnabla-dataset-uploader",
    "version": "1.0.0",
    "archive_sha256": "4f8835f924359c2236b663ddd7e6ae86d74aaf5c127a4124a1e478f6ca91b3e0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2022-12-07",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2022-12-07-nnabla-dataset-uploader.zip",
    "package_root": "layer0/2022-12-07-nnabla-dataset-uploader/nnabla-dataset-uploader-1.0.0",
    "cluster_key": "16e01ac5f6217a64d76e5775db0a04f520662b7d52e0bd24a9b9fcd403b25d24",
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
      "setup.py read in full (25 lines); setup.cfg holds only egg_info tags. No other install-reached files.",
      "Top-level setup.py only imports modules and calls setup(); the payload is in CustomInstall.run, after install.run(self). No conditions anywhere.",
      "setup.py imports requests at top level with no install_requires/setup_requires, so the build fails with ImportError if requests is absent from the build environment."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cdf5rwk2vtc0000c78d0ggz1hqeyyyyyb[.]oast[.]fun:443",
      "reason": "recon data is sent via HTTPS GET to this OAST host"
    },
    {
      "axis": "other",
      "value": "Python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level; it is not declared as a build requirement"
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
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://cdf5rwk2vtc0000c78d0ggz1hqeyyyyyb[.]oast[.]fun",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast-callback-probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override sends the hostname, working directory and username to an OAST (Interactsh) host on every sdist install, with no gate. The name looks like an internal package of the nnabla project, consistent with a dependency confusion probe.",
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
