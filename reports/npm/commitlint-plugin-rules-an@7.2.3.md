# npm commitlint-plugin-rules-an@7.2.3

**Source:** datadog · **Source label:** malicious · **Released:** 2024-11-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script asks a public IP lookup service for the external IP, hostname and organisation. It then gathers the username, home directory, install directory, DNS servers, hostname and first non-internal IPv4 address, and POSTs all of it with the package.json contents to a hardcoded Discord webhook. There are no gates: the same recon and exfil runs in every environment and only needs outbound HTTPS to discord.com.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: discord[.]com:443 (collected host data is POSTed to a Discord webhook; without it the beacon fails (the error is only logged))

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The name looks like an internal-style commitlint plugin, and the beacon reports the install path, `___resolved` and the package name, which fits dependency-confusion probing. The attack type is inferred from that, not from any text in the package.
- The external IP lookup falls back to placeholder values on error, so it is not a requirement for the exfil.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "commitlint-plugin-rules-an",
    "version": "7.2.3",
    "archive_sha256": "fd8ebdd4472f2dac0f0577b61af53463aa95ba87d619e0ff3c695064ac53a671",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-11-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-11-06-commitlint-plugin-rules-an-v7.2.3.zip",
    "package_root": "layer0/tmp/tmpmf22ia18/commitlint-plugin-rules-an/package",
    "cluster_key": "b7ab5fb1b0da4106ace3ae37bbe7dd42417a3c96caf80cc625d96a7d6ef5372f",
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
      "index.js (88 lines): package code read in full; nothing bundled, nothing unread.",
      "No environment checks pick behaviour. alias.family/internal in getIPAddress only selects which address to report (data collection); the ipinfo error handler substitutes placeholder values and the beacon still goes out.",
      "hxxps://ipinfo[.]io/json is queried for external IP, hostname and org (recon). It is a public lookup service, not attacker infrastructure, and its failure does not stop the exfil, so it is not listed as an endpoint."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "collected host data is POSTed to a Discord webhook; without it the beacon fails (the error is only logged)"
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
        "indicator": "hxxps://discord[.]com/api/webhooks/1301…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "Discord webhook recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects username, home directory, hostname, DNS servers, internal and external IP, org and the install path and POSTs them to a hardcoded Discord webhook. There are no environment gates.",
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
