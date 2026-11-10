# pypi peptest@1.2.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-20 (dataset) · **Assessment:** suspicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` registers a `cmdclass` override for `install`, so `PostInstallCommand.run` runs on a normal pip install from source. After calling `install.run`, it POSTs a fixed JSON payload (event "installation" plus `sys.version`) to a webhook[.]site URL, inside a try/except that only prints the error. There are no environment checks, so no gates: the beacon runs on every install where the webhook is reachable and `requests` is importable at build time.

## Execution

- **cmdclass** `cmdclass[install] = PostInstallCommand`: runs setup.py; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (install override POSTs the beacon over HTTPS; failure is swallowed)
- other: Python module requests importable in the build environment (setup.py imports requests at top level; install_requires does not make it available at build time, so setup.py fails without it)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The payload has placeholder values (`package_name` "sizin-paket-adiniz", version "1.0.0") and no secrets beyond the interpreter version. It looks like a test beacon, so I assessed it as suspicious rather than malicious.
- `setup.py` imports `requests` at top level, so the build fails before the hook runs if `requests` is missing from the build environment.
- The package modules (`peptest/__init__.py`, `peptest/main.py`) are empty.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "peptest",
    "version": "1.2.0",
    "archive_sha256": "ab7d3625c0dabbbc8800895b1ff68f2f364e465a37ec1010f32bebefda4d3170",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-20",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2025-11-20-peptest-v1.2.0.zip",
    "package_root": "layer0/tmp/tmp18_4jmcn/peptest/peptest-1.2.0",
    "cluster_key": "7e7c555388bbb4bb48c1117c881fe46925387dfe4d3ffc3faf69f6916b30fd55",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstallCommand",
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
      "setup.py: read in full (56 lines). No environment checks; PostInstallCommand.run calls install.run then POSTs a fixed JSON beacon with sys.version to a webhook. The try/except only prints the error.",
      "setup_py hook: top-level code only imports modules (including requests) and calls setup(); no behaviour of its own besides registering the install override.",
      "peptest/__init__.py and peptest/main.py are empty; nothing runs at import either."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "install override POSTs the beacon over HTTPS; failure is swallowed"
    },
    {
      "axis": "other",
      "value": "Python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level; install_requires does not make it available at build time, so setup.py fails without it"
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
        "indicator": "hxxps://webhook[.]site/33a9…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "webhook[.]site install beacon",
  "claude_assessment": "suspicious",
  "assessment_reason": "The install override sends an unconditional HTTP POST to a webhook.site URL with a fixed event payload and the Python version. It is an install-time beacon with no credential theft or second stage, consistent with a test or proof of concept, but it phones home without consent.",
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
