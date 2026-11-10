# npm collabs-influencer-ui@1.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-11 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script has no conditionals, so there are no gates: it always gathers the package name, install directory, home directory, hostname, username, DNS servers and the full package.json, and POSTs them as form data over HTTPS to an Interactsh host (oast[.]fun). Any environment with outbound access to that host on 443 sees the full behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: d31dsedsvpasadl53r10fxpea1jjjy9rn[.]oast[.]fun:443 (recon data is POSTed over HTTPS to this host; the beacon is lost without it)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Only network reachability to the OAST host matters; the request error handler is empty, so a blocked beacon fails silently.
- Unnamed, description-less package with an OAST callback fits the dependency-confusion probe pattern; attack type is inferred from that, not from any text claim.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "collabs-influencer-ui",
    "version": "1.0.2",
    "archive_sha256": "9fd451f650b48773e3a7a34853ffc0180e50fb5651d5b70821314b2715766628",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-11",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-09-11-collabs-influencer-ui-v1.0.2.zip",
    "package_root": "layer0/tmp/tmp0dtpn_v8/collabs-influencer-ui/package",
    "cluster_key": "67872df0e6aa7ed1c37bb642e863b72757d698b0501fc4852dcadc4a6ef415d8",
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
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js (47 lines, plain JS): read in full; nothing unread. No conditionals at all, so no gates.",
      "Collects package name, install dir, home dir, hostname, username, DNS servers and the whole package.json, then POSTs it as form data to an Interactsh (oast[.]fun) host on 443.",
      "The request error handler is empty (console.error commented out), so a failed beacon is silent; set silent_failure."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "d31dsedsvpasadl53r10fxpea1jjjy9rn[.]oast[.]fun:443",
      "reason": "recon data is POSTed over HTTPS to this host; the beacon is lost without it",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 896,
          "end_byte": 1001,
          "node_type": "call_expression",
          "sha256": "1b785117c08990a0",
          "line": 35
        }
      ]
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
        "indicator": "hxxps://d31dsedsvpasadl53r10fxpea1jjjy9rn[.]oast[.]fun:443/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST dependency-confusion recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects the hostname, username, home dir, install path and DNS servers and POSTs them to an Interactsh OAST host. There is no gate and no further payload; it is a dependency-confusion style recon beacon.",
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
