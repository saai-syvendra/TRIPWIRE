# pypi miantestone@0.55

**Source:** datadog · **Source label:** malicious · **Released:** 2022-11-12 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command with `CustomInstallCommand`, which runs on a normal pip install. Its `run` method gets the hostname with `socket.gethostname()`, resolves it to an IP with `socket.gethostbyname()`, and posts both to a hardcoded Discord webhook through `discord.SyncWebhook`, then continues the normal install. There are no gates: nothing checks the environment before the recon and exfil run.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: discord[.]com:443 (webhook.send posts hostname and IP to a Discord webhook)
- other: Python modules discord (discord.py), aiohttp and requests importable in the build environment (imported at the top of CustomInstallCommand.run; declared only in install_requires, so missing in an isolated pip build)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The override imports `discord`, `aiohttp` and `requests` at build time, but they are only declared in `install_requires`. In an isolated pip build they are usually missing, so the import raises and the install fails before the webhook call. A scanner needs these modules present in the build environment (recorded as a requirement), plus outbound access to discord[.]com:443.
- Webhook path redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "miantestone",
    "version": "0.55",
    "archive_sha256": "fe0df5ee34b14d8379171fb3ef637786d9ee2e01d3c48cfcd253fbb864337e45",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2022-11-12",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2022-11-12-miantestone.zip",
    "package_root": "layer0/2022-11-12-miantestone/miantestone-0.55",
    "cluster_key": "7d39e3ba837b08a09306fadfbcb6870452ac7d5431db855bfc72f181a59dc9eb",
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
      "setup.py: read in full (35 lines); it is the only package code and no other file is reached at install.",
      "CustomInstallCommand.run imports aiohttp, requests and discord at build time. They are only in install_requires, so in an isolated pip build the import likely raises and the payload does not run. Recorded as a requirement.",
      "setup_py hook: top-level code only calls setup(); the payload sits in the cmdclass install override, which then calls install.run.",
      "hxxps://github[.]com is only the setup() url metadata and is never contacted; removed from endpoints."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "webhook.send posts hostname and IP to a Discord webhook"
    },
    {
      "axis": "other",
      "value": "Python modules discord (discord.py), aiohttp and requests importable in the build environment",
      "reason": "imported at the top of CustomInstallCommand.run; declared only in install_requires, so missing in an isolated pip build"
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
  "family_hint": "discord-webhook-hostname-exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override reads the machine hostname and its resolved IP and sends them to a hardcoded Discord webhook, with no gate in front. It needs discord.py, aiohttp and requests importable at build time to run.",
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
