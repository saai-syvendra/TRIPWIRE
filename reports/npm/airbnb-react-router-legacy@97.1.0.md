# npm airbnb-react-router-legacy@97.1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-22 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node src/math/zusage-analytics/monitoring.js || true` on every registry install. The script is obfuscator.io output (string table recovered as d1). It reads the username and hostname, sends an HTTPS HEAD request to a subdomain of an oastify (Burp Collaborator) host that carries them hex-encoded, then POSTs host, user and the full `process.env` as JSON to the same host. There are no gates: any environment with node 18+ (global fetch) and outbound HTTPS sends the data.

## Execution

- **preinstall** `node src/math/zusage-analytics/monitoring.js || true`: runs src/math/zusage-analytics/monitoring.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: pkd1parpzdu9efe7cujefrdl1c73vujj[.]oastify[.]com:443 (HTTPS HEAD to a subdomain of this host (hex username and hostname as labels) and HTTPS POST of host, user and full env to it.)
- runtime_version: node>=18 (Uses the global fetch API; older node throws inside the swallowed try/catch and nothing is sent.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The name, the high version 97.1.0 and an out-of-band collaborator sink point to a dependency confusion probe. The env dump can leak CI secrets, so this goes beyond a plain callback.
- Both fetch calls are wrapped in empty try/catch blocks, and the hook ends with `|| true`, so failures are silent.
- The rest of `src/` is a decoy utility library that only runs when loaded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "airbnb-react-router-legacy",
    "version": "97.1.0",
    "archive_sha256": "4f977100264000941406578031a9c0fe03e67ac5ae178446e8b5968ca0dd21e2",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-22",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-11-22-airbnb-react-router-legacy-v97.1.0.zip",
    "package_root": "layer0/tmp/tmpd4x9jgne/airbnb-react-router-legacy/package",
    "cluster_key": "31ce2feaadfaf1d8f746c6855c1c3f130645b8b63c12a5426e5787794e8237f3",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node src/math/zusage-analytics/monitoring.js || true",
        "runs_on": "always",
        "file_chain": [
          "src/math/zusage-analytics/monitoring.js"
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
      "src/math/zusage-analytics/monitoring.js: package code read in full after obfuscator.io string-table decode (derived d1, 12 of 12 calls substituted); no bundled library code; nothing unread.",
      "No environment checks: the script reads os.userInfo().username, os.hostname() and process.env unconditionally and sends them; both fetch calls sit in empty try/catch blocks and the hook ends with || true.",
      "Requires node with a global fetch (Node 18+); on older node the fetch calls throw ReferenceError, which the empty catch swallows, so nothing is sent.",
      "src/index.js and the other src/ helpers are the package main (math, string, date utilities), only run when loaded; not install-time."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pkd1parpzdu9efe7cujefrdl1c73vujj[.]oastify[.]com:443",
      "reason": "HTTPS HEAD to a subdomain of this host (hex username and hostname as labels) and HTTPS POST of host, user and full env to it."
    },
    {
      "axis": "runtime_version",
      "value": "node>=18",
      "reason": "Uses the global fetch API; older node throws inside the swallowed try/catch and nothing is sent."
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
    "level": "light",
    "techniques": [
      "obfuscator.io hex identifiers",
      "rotated string array with index decoder (recovered)",
      "single-line minified file",
      "hex-encoded username and hostname in DNS labels"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://pkd1parpzdu9efe7cujefrdl1c73vujj[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify OOB recon (dependency confusion probe)",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs an obfuscated script that unconditionally sends the username, hostname and the whole process environment (which can hold tokens and secrets) to a Burp Collaborator (oastify) host. No gate is in front of it.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "obfuscatorio_strings",
        "recipe_version": 1,
        "input": {
          "file": "src/math/zusage-analytics/monitoring.js",
          "derived_from": null
        },
        "params": {
          "provider": "_0x2db3",
          "decoder": "_0xa1e4",
          "offset": 291,
          "variant": "none",
          "form": "v2",
          "table_size": 22,
          "rotations": 3,
          "checksum_target": 114748,
          "callables": 6
        },
        "output_sha256": "7f07839bf429e2a7",
        "stats": {
          "calls_total": 12,
          "substituted": 12,
          "unresolved": 0
        }
      }
    ],
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
