# pypi mianprojlol@0.55

**Source:** datadog · **Source label:** malicious · **Released:** 2022-11-12 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command, which pip runs while building the package. `CustomInstallCommand.run` imports discord.py and aiohttp, reads the hostname and resolves its IP, posts both to a hardcoded Discord webhook, then calls the normal install. There are no gates: nothing is tested before the send. The only thing standing between a sandbox and the payload is whether discord.py (pre-2.0, with `RequestsWebhookAdapter`) is importable during the build, and whether discord[.]com is reachable.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: discord[.]com:443 (Hostname and IP are posted to a Discord webhook.)
- other: Python modules discord (discord.py <2.0, provides RequestsWebhookAdapter) and aiohttp importable in the build environment (run() imports them before sending; install_requires are not installed before the build, so they must already be present.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- discord.py and aiohttp are in `install_requires` only, so with pip's default build isolation the import in `run()` probably fails and the payload does not run. Recorded as a requirement, not a gate.
- The `url` field (hxxps://github[.]com) is metadata and is never contacted; removed from endpoints.
- Webhook token redacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "mianprojlol",
    "version": "0.55",
    "archive_sha256": "560fb1dbaf336af8d41c7194afff74c81b969f074353a290e62d7237198ea8f4",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2022-11-12",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2022-11-12-mianprojlol.zip",
    "package_root": "layer0/2022-11-12-mianprojlol/mianprojlol-0.55",
    "cluster_key": "545674d7110b5568b4ffe91c4c0d717ccd195813ec958c3b459cc526dd1be210",
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
      "setup.py: package code read in full (33 lines); it is the only install-reached file. Top-level code only calls setup(); the payload is in CustomInstallCommand.run.",
      "run() imports discord (Webhook, RequestsWebhookAdapter) and aiohttp at install time. Neither is a build requirement, so under pip build isolation the import likely raises ImportError and the payload never runs; it runs only where discord.py <2.0 is importable (no build isolation or preinstalled).",
      "No environment checks: hostname and IP from socket.gethostname/gethostbyname are collected and sent, not tested. install.run(self) follows the send, so a failed import or send also aborts the install (errors not swallowed)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "Hostname and IP are posted to a Discord webhook."
    },
    {
      "axis": "other",
      "value": "Python modules discord (discord.py <2.0, provides RequestsWebhookAdapter) and aiohttp importable in the build environment",
      "reason": "run() imports them before sending; install_requires are not installed before the build, so they must already be present."
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
        "indicator": "hxxps://discord[.]com/api/webhooks/1040…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord webhook recon",
  "claude_assessment": "malicious",
  "assessment_reason": "The overridden install command sends the machine's hostname and IP address to a hardcoded Discord webhook with no checks before it. The package has no other function.",
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
