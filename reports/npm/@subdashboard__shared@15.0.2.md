# npm @subdashboard/shared@15.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package's `preinstall` hook runs `node index.js` on every install. index.js gathers the package name, install directory, home directory, hostname, username, DNS servers, version and the whole package.json, and POSTs them as a form-encoded body over HTTPS to hxxps://eor68vh25euiq4.m.pipedream[.]net/. There are no gates: nothing checks the OS, env vars, CI markers or anything else before the beacon goes out. The only thing it needs is outbound access to that host on port 443.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: eor68vh25euiq4[.]m[.]pipedream[.]net:443 (preinstall POSTs the collected host data over HTTPS to this host; no retry or fallback.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- A scoped name with a high version (15.0.2) and a stub README is the usual dependency-confusion probe shape. The attack type comes from that shape, not from the manifest description, which claims to be a PoC and names an author handle (redacted here).
- The code reads `packageJSON.___resolved`, which is not in the shipped package.json, so it sends undefined. This has no effect on behaviour.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@subdashboard/shared",
    "version": "15.0.2",
    "archive_sha256": "3a5d28efa5a7190e6265734c0a72af7893cd84a8afd3756ed3a02009aecfb9a3",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-06-@subdashboard_shared-v15.0.2.zip",
    "package_root": "layer0/tmp/tmp_a9qaqgg/@subdashboard-shared/package",
    "cluster_key": "38e8d82f486c62366e05a2386e64eccb19b7f3173ef5da98f27cf785be4e7001",
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
      "index.js: package code read in full (40 lines, no bundled or third-party code); nothing unread. README.md is not executed.",
      "The request error handler only logs the error with console.error; it is printed, not hidden, so silent_failure is left false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "eor68vh25euiq4[.]m[.]pipedream[.]net:443",
      "reason": "preinstall POSTs the collected host data over HTTPS to this host; no retry or fallback."
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
        "indicator": "hxxps://eor68vh25euiq4.m.pipedream[.]net/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pipedream recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js unconditionally, which collects the install directory, home directory, hostname, username, DNS servers and the full package.json and POSTs them to a pipedream.net collector. There are no environment checks; the beacon runs on every install.",
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
