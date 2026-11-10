# npm react-fatigue-dev@5.2.7

**Source:** datadog · **Source label:** malicious · **Released:** 2024-11-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script looks up the external IP, hostname and organisation from ipinfo[.]io, then gathers the username, home directory, install directory, hostname, internal IPv4 address, DNS servers and the full package.json, and POSTs it all as JSON to a hardcoded Discord webhook. There are no gates: nothing checks the OS, CI, env vars or any other part of the environment, so any VM with outbound HTTPS to discord[.]com sees the full behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: discord[.]com:443 (collected host data is POSTed to a hardcoded Discord webhook)
- network: ipinfo[.]io:443 (external IP, hostname and org lookup; optional, failure falls back to placeholder values)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Shape matches the common dependency-confusion recon template (install directory, DNS servers and `___resolved` from the manifest are collected). The package name looks like an internal package name, which is why attack_type is `dependency_confusion`; that is an inference from the name and payload shape, not something the code states.
- Webhook id and token are redacted in the record.
- ipinfo failure is handled, so it is not needed for the exfil. ipinfo is tagged `exfil_sink` only because the role enum has no lookup value.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "react-fatigue-dev",
    "version": "5.2.7",
    "archive_sha256": "9c6ffd13f377ba912a2a59dc42f2539cd57e72dab80ec6fcc6e83f465d33f8a0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-11-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-11-20-react-fatigue-dev-v5.2.7.zip",
    "package_root": "layer0/tmp/tmp9zdpipyh/react-fatigue-dev/package",
    "cluster_key": "fcf7adb694d7644b2feff863cf91aac0f42bd21cd108d3c0c621eed5369b19f8",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "index.js: package code read in full (88 lines, plain JS, no bundled or encoded code); nothing unread. No conditions or gates: the whole script runs on every install.",
      "The IPv4/non-internal test in getIPAddress only picks which interface address to report; it is data collection, not a gate.",
      "ipinfo lookup errors are caught and replaced with placeholder strings, so the webhook POST still runs when ipinfo is unreachable. Errors are logged to stderr, not hidden, so silent_failure stays false.",
      "Endpoint roles: ipinfo[.]io is a public IP/geo lookup, not attacker-controlled; the role enum has no lookup value, so exfil_sink is used as the closest fit. The real exfil sink is the Discord webhook."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "collected host data is POSTed to a hardcoded Discord webhook"
    },
    {
      "axis": "network",
      "value": "ipinfo[.]io:443",
      "reason": "external IP, hostname and org lookup; optional, failure falls back to placeholder values"
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
        "indicator": "hxxps://ipinfo[.]io/json",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://discord[.]com/api/webhooks/1306…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects username, home directory, hostname, internal and external IP, DNS servers, install directory and the package manifest and POSTs them to a hardcoded Discord webhook. No environment check gates any of it.",
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
