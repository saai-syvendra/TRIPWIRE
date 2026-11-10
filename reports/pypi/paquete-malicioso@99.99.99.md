# pypi paquete-malicioso@99.99.99

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with `PostInstallCommand`, whose `run` calls `createfile()` before the normal install. `createfile()` reads `/proc/uptime`, platform release/system/version and `psutil.net_if_addrs()` and sends them as one string over a raw TCP socket to 134[.]209[.]85[.]64:9090. There are no gates: nothing checks the environment, and the payload runs on every install. It does need Linux (`/proc/uptime`), the `psutil` module in the build environment, and the collector to be reachable; otherwise it raises and the install fails.

## Execution

- **cmdclass** `cmdclass[install] = PostInstallCommand`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: 134[.]209[.]85[.]64:9090 (TCP connect to deliver the recon string; an unreachable host raises and aborts the install)
- file_present: /proc/uptime (read unconditionally before collection; absent on non-Linux hosts, so the payload raises there)
- os: linux (/proc/uptime only exists on Linux, and the top-level pty import fails on Windows)
- other: python module psutil importable in the build environment (top-level import psutil in setup.py; without it setup.py fails before any code runs)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `import pty` is unused; no reverse shell is present despite the import.
- The `url` field (hxxps://google[.]com) is descriptive metadata and is never contacted, so it was removed from endpoints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "paquete-malicioso",
    "version": "99.99.99",
    "archive_sha256": "a969c0bc23fb1df1026e365d1eaac5f11cc9de71da5cbea13cb580ddbf61018d",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/paquete-malicioso-99.99.99.tar.gz",
    "package_root": "layer0/paquete-malicioso-99.99.99",
    "cluster_key": "dbc15950f8957eb06a73edcaa87c409cfc781533bf80496bfdd8e6dacfaa3e6a",
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
      "setup.py read in full (45 lines); no other install-reached files. Top-level code only imports modules and calls setup(); the payload runs from the install cmdclass override, before install.run.",
      "Imports pty but never uses it. No condition, branch or error handling in the payload: it runs unconditionally on any sdist install.",
      "createfile reads /proc/uptime, platform release/system/version and psutil.net_if_addrs(), then sends them as one string over a raw TCP socket to 134[.]209[.]85[.]64:9090."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "134[.]209[.]85[.]64:9090",
      "reason": "TCP connect to deliver the recon string; an unreachable host raises and aborts the install",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 826,
          "end_byte": 870,
          "node_type": "call",
          "sha256": "2b16f9a49f2edb83",
          "line": 25
        }
      ]
    },
    {
      "axis": "file_present",
      "value": "/proc/uptime",
      "reason": "read unconditionally before collection; absent on non-Linux hosts, so the payload raises there",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 245,
          "end_byte": 270,
          "node_type": "call",
          "sha256": "c2e6bdc9398622d1",
          "line": 15
        }
      ]
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "/proc/uptime only exists on Linux, and the top-level pty import fails on Windows",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 245,
          "end_byte": 270,
          "node_type": "call",
          "sha256": "c2e6bdc9398622d1",
          "line": 15
        }
      ]
    },
    {
      "axis": "other",
      "value": "python module psutil importable in the build environment",
      "reason": "top-level import psutil in setup.py; without it setup.py fails before any code runs",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 95,
          "end_byte": 108,
          "node_type": "import_statement",
          "sha256": "f6b32ab9229eb831",
          "line": 7
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
        "indicator": "134[.]209[.]85[.]64",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override collects uptime, OS details and network interface addresses and sends them unconditionally over a raw TCP socket to a hard-coded IP on port 9090. No gates; it reads like a recon proof of concept but exfiltrates host data from whoever installs it.",
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
