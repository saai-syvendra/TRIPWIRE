# npm mongodb-chatbot-verified-answers@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-05 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node vishu.js`, a short plain script. It fetches the installer's public IP from api[.]ipify[.]org, sends it as a query parameter in a GET to a webhook[.]site URL, and then does a DNS lookup of `ping-<hostname>` under a collaborator domain. There are no gates: everything runs unconditionally on any OS, with errors swallowed. The package name looks like an internal MongoDB chatbot package, which fits a dependency-confusion beacon.

## Execution

- **preinstall** `node vishu.js`: runs vishu.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (HTTPS GET carrying the public IP goes to the webhook URL)
- network: api[.]ipify[.]org:443 (public IP lookup; without it the beacon still runs but sends ip=unknown)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The DNS beacon domain is an unedited template placeholder (`your-collab-domain[.]oastify[.]com`), so only the webhook request reaches the author in practice.
- The script comment and package description present this as a white-hat PoC. The code matches that claim (IP and hostname only), so it is not flagged as misleading text, but it still sends host data off the machine without consent.
- If the ipify lookup fails, the webhook request still goes out with `ip=unknown`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "mongodb-chatbot-verified-answers",
    "version": "1.0.0",
    "archive_sha256": "00b3cc83228f7c98bf081a30790ceb9f1da3ec8a2c89faa4c8a429cb9827df5d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-05",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-11-05-mongodb-chatbot-verified-answers-v1.0.0.zip",
    "package_root": "layer0/tmp/tmp_ovdj78k/mongodb-chatbot-verified-answers/package",
    "cluster_key": "c0bbd9c2d3b898c3d915f22285139e0ce28606c5987ca96762ffaaa1075c75dd",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node vishu.js",
        "runs_on": "always",
        "file_chain": [
          "vishu.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "vishu.js: package code read in full (62 lines, plain JS); nothing bundled or unread. No environment checks: main() runs unconditionally at preinstall.",
      "Flow: https.get to api[.]ipify[.]org for the public IP (falls back to 'unknown' on error), then GET to a webhook[.]site URL with ?ip=<ip>, then dns.lookup of ping-<os.hostname()>.your-collab-domain[.]oastify[.]com.",
      "The DNS beacon domain is an unedited template placeholder (your-collab-domain[.]oastify[.]com), so the hostname leak reaches the resolver but likely no attacker-controlled collaborator.",
      "api[.]ipify[.]org is a public IP lookup service, not an attacker endpoint, so it is left out of reachability.endpoints; its failure does not stop the webhook request.",
      "Errors are swallowed throughout (request error handlers are no-ops, try/catch around the DNS ping), so silent_failure is true.",
      "Comment and description claim a safe white-hat PoC; the code matches that description (IP and hostname beacon only), so this is not recorded as misleading text."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "HTTPS GET carrying the public IP goes to the webhook URL"
    },
    {
      "axis": "network",
      "value": "api[.]ipify[.]org:443",
      "reason": "public IP lookup; without it the beacon still runs but sends ip=unknown"
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
        "indicator": "hxxps://webhook[.]site/ffcc…",
        "role": "exfil_sink"
      },
      {
        "indicator": "ping-<hostname>.your-collab-domain[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dependency-confusion IP/hostname beacon PoC",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall script unconditionally looks up the installer's public IP and sends it to a webhook[.]site URL, and leaks the hostname through a DNS lookup. It is a dependency-confusion style beacon with no gates and no further payload.",
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
