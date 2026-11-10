# npm @rrvis/vehicle@99.99.3

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every install. The script has no gates: it builds a JSON blob with the package name, install directory, home directory, hostname, username, DNS servers and the full package.json, and POSTs it to a pipedream webhook (hxxps://eoy7….m.pipedream[.]net/). Any environment with outbound HTTPS to that host triggers the full behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: eoy7….m.pipedream[.]net:443 (Collected host data is POSTed to this webhook endpoint; without it the exfil fails (error only logged).)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Scoped package name with version 99.99.3 is the usual dependency-confusion pattern. The description and README call it a PoC; that text does not change the label, the code exfiltrates host identity data either way.
- Webhook subdomain redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@rrvis/vehicle",
    "version": "99.99.3",
    "archive_sha256": "138a5ec729040d3858404a0308b87089b3644716da5b228f8b02eda2486840f5",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-20-@rrvis_vehicle-v99.99.3.zip",
    "package_root": "layer0/tmp/tmpgjj1onu6/@rrvis-vehicle/package",
    "cluster_key": "7bb1b509dde7518afbf5d94f459ddd86594268325a76e1d0389af332e294cbb0",
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
      "index.js (40 lines) read in full: no conditionals at all; it collects package name, install dir, home dir, hostname, username, DNS servers and the whole package.json, and POSTs them once over https.",
      "The request error handler only logs to stderr; the install is not blocked either way, so silent_failure stays false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "eoy7….m.pipedream[.]net:443",
      "reason": "Collected host data is POSTed to this webhook endpoint; without it the exfil fails (error only logged)."
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
        "indicator": "hxxps://eoy7….m.pipedream[.]net/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pipedream recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally gathers hostname, username, home directory, install path, DNS servers and package.json and POSTs them to a pipedream webhook. Scoped name with version 99.99.3 fits a dependency-confusion probe.",
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
