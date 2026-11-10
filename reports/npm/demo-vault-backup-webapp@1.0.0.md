# npm demo-vault-backup-webapp@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js` on every registry install. The script builds a JSON object with `os.hostname()`, `process.platform`, `process.cwd()` and the whole `process.env`, and POSTs it with `https.request` to a webhook.site URL. There are no gates: no condition is tested before the request, so any environment with outbound HTTPS to webhook[.]site:443 sees the full behaviour.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (https.request POST of the collected data; nothing else happens if it fails)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The package has one code file, `index.js`, read in full. No obfuscation.
- `attack_type: dependency_confusion` comes from the internal-looking package name and the callback-only behaviour (host and environment beacon, no second stage). The manifest keywords also say "dependency-confusion" and the description says "PoC", but those are text and the label does not rest on them alone.
- Dumping all of `process.env` sends any secrets present in the installer's environment (CI tokens, cloud keys), so this is more than a harmless ping.
- The webhook path is redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "demo-vault-backup-webapp",
    "version": "1.0.0",
    "archive_sha256": "68cd781f7c34c702a1592ab21e7476a933d32fcf7d1cc088d00b14faa280480f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-24-demo-vault-backup-webapp-v1.0.0.zip",
    "package_root": "layer0/tmp/tmpq26g0q_9/demo-vault-backup-webapp/package",
    "cluster_key": "aa7b5745062423b7a72d00afbc850d989a6c184f2929b8147dc8e5f3f7dbae66",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
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
      "index.js (31 lines): read in full; no other files in the package, nothing unread.",
      "No environment checks anywhere: hostname, platform, cwd and the whole process.env are collected and POSTed unconditionally.",
      "Request errors are caught by req.on('error') and printed to stderr; the install still succeeds, but the error is not hidden, so silent_failure stays false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "https.request POST of the collected data; nothing else happens if it fails"
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
        "indicator": "hxxps://webhook[.]site/1ce4…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook runs index.js, which sends the hostname, platform, working directory and the full process.env (which can hold tokens and cloud keys) to a webhook.site collector with no gate. Calling itself a PoC does not change that it exfiltrates installer secrets.",
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
