# npm nodejs-paypal-checkout-demo@100.2.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-01-30 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script builds a JSON blob with the package name, install directory, home directory, hostname, username, DNS servers and the whole package.json, and POSTs it over HTTPS to a Burp Collaborator (oastify) host. There are no gates: nothing checks the environment, so any machine with outbound access to that host on 443 triggers it.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: sfbegruan1arccffaaiim5kmrdx4l19q[.]oastify[.]com:443 (HTTPS POST of collected host info; failure is only logged.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Shape and version (100.2.0, self-dependency, OAST callback) fit a dependency-confusion probe. The package description claims a takeover, but the code only beacons host info.
- `dns.getServers()` is flagged as a network sink by the tool; it is a local read used for recon.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "nodejs-paypal-checkout-demo",
    "version": "100.2.0",
    "archive_sha256": "570ef12807143daa9ed51cef23979b75dc03511b29a2d49146fd60882312f24e",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-01-30",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-01-30-nodejs-paypal-checkout-demo-v100.2.0.zip",
    "package_root": "layer0/tmp/tmp5amyf6nr/nodejs-paypal-checkout-demo/package",
    "cluster_key": "3a7c9a92eb4be074beb07d41d27b841340dd76a7d48506a99217d81786111510",
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
      "index.js: package code, 46 lines, read in full; nothing bundled, nothing unread.",
      "No environment checks at all: the script collects package name, install dir, home dir, hostname, username, DNS servers and the full package.json, then POSTs them over HTTPS on every install.",
      "Request errors are only logged with console.error; the response body is echoed to stdout. Neither changes behaviour, so not silent_failure and not a gate.",
      "package.json lists the package itself as a dependency (^100.2.0); dependency tree only. The description claims a computer takeover, but the code only beacons host info."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "sfbegruan1arccffaaiim5kmrdx4l19q[.]oastify[.]com:443",
      "reason": "HTTPS POST of collected host info; failure is only logged."
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
        "indicator": "sfbegruan1arccffaaiim5kmrdx4l19q[.]oastify[.]com:443",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST host-info beacon (oastify)",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally sends the hostname, username, home dir, install path, DNS servers and package.json to an oastify collaborator host. It is a dependency-confusion style recon beacon with no gating.",
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
