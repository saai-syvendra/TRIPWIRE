# npm test-object-model@0.7.6

**Source:** datadog · **Source label:** malicious · **Released:** 2024-09-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. index.js builds a JSON blob with the package name, install directory, home directory, hostname, username, DNS servers, `__resolved`, version and the whole package.json, prints it, and POSTs it over HTTPS to a Pipedream endpoint (eo2a…[.]m[.]pipedream[.]net). There are no gates: no condition is tested anywhere, so any environment with outbound HTTPS to that host runs the full payload.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: eo2a…[.]m[.]pipedream[.]net:443 (Collected host data is POSTed over HTTPS to this endpoint; the request must connect for the exfil to complete.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Generic name, recon-only payload and the `__resolved` field are the usual dependency-confusion probe pattern; attack type is inferred from that, not from any text claim.
- The `os` dependency (^0.1.2) is a registry dependency, not install code of this package; index.js uses the Node built-in `os` anyway.
- Endpoint id redacted to the first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "test-object-model",
    "version": "0.7.6",
    "archive_sha256": "3e52d16c8c02b9e1ff5edf0db4267557910c28df1a80c4f8992ab4ac2c50094c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-09-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-09-22-test-object-model-v0.7.6.zip",
    "package_root": "layer0/tmp/tmpxka6rtzv/test-object-model/package",
    "cluster_key": "28055327bad03167b1d73393f2c4fb3b01f472b3a87731a6e46eaa549bc7fcb3",
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
      "index.js (48 lines): package code read in full; no conditionals, every statement runs unconditionally at preinstall; nothing unread.",
      "The https request error handler only logs the error with console.error, so a failed POST does not abort the install but is not hidden either.",
      "The exfil host is a Pipedream request-bin style endpoint; its per-endpoint id is redacted to the first 4 characters."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "eo2a…[.]m[.]pipedream[.]net:443",
      "reason": "Collected host data is POSTed over HTTPS to this endpoint; the request must connect for the exfil to complete."
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
        "indicator": "hxxps://eo2a…[.]m[.]pipedream[.]net:443/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pipedream host-info beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects the package directory, home directory, hostname, username, DNS servers and package.json and POSTs them to a Pipedream endpoint. No gates; this is the common dependency-confusion recon beacon pattern.",
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
