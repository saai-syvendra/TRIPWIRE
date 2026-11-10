# npm hilton_cms@1.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-08 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script has no environment gates: it collects the hostname, home directory, working directory, first non-internal IPv4 address and the public IP (looked up via ipinfo[.]io), then POSTs them as JSON to `hxxp://23[.]22[.]251[.]177:8080/collect_info.php`. Any environment with network access to that host and a resolvable `axios` module triggers the full behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: 23[.]22[.]251[.]177:8080 (collected data is POSTed to this host; a failure is caught and logged)
- other: axios module resolvable from the package root (index.js requires axios unconditionally at the top of the preinstall script)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The only conditional picks which local interface address to report. That is data collection, not a gate.
- Both network calls are wrapped in try/catch handlers that only log, so failures are silent to the install.
- `kk.js` is a copy of the script with a different collector (35.170.187[.]220) and `server.js` is an express receiver. No hook runs either one.
- The attack type (dependency confusion) is inferred from the name and the pingback-only payload, so it is flagged for review.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "hilton_cms",
    "version": "1.0.2",
    "archive_sha256": "51d04552695be7620a9811361480ec1093e349b188e6d4e2e2389bb8cf4662be",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-08",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-02-08-hilton_cms-v1.0.2.zip",
    "package_root": "layer0/tmp/tmplfwckqmc/hilton_cms/package",
    "cluster_key": "4ec341786624472e4487ce6dd69964c7fe75988570ba6bb2d719d20b91a3697f",
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
      "index.js: package code read in full (69 lines, no obfuscation). No gates: the only conditional (details.family === 'IPv4' && !details.internal) picks which local IP to report, which is data collection.",
      "Collects hostname, home directory, cwd, first non-internal IPv4 and the public IP (GET to ipinfo[.]io, failure tolerated), then POSTs them as JSON to the hardcoded collector. Both requests sit in try/catch blocks that only log.",
      "require('axios') is unguarded at the top of the preinstall script; if axios is not resolvable when preinstall runs, the script throws and nothing is sent.",
      "kk.js (same script, different collector 35.170.187[.]220) and server.js (an express receiver) are not run by any hook, so they are not install-reached."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "23[.]22[.]251[.]177:8080",
      "reason": "collected data is POSTed to this host; a failure is caught and logged"
    },
    {
      "axis": "other",
      "value": "axios module resolvable from the package root",
      "reason": "index.js requires axios unconditionally at the top of the preinstall script"
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
        "indicator": "hxxp://23[.]22[.]251[.]177:8080/collect_info.php",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which with no gate collects hostname, home directory, working directory, local and public IP and POSTs them to a hardcoded IP. This is a recon pingback typical of dependency-confusion probes.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "attack_type dependency_confusion inferred from the unscoped company-style name and pingback-only payload; no matching internal package was confirmed"
  ],
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
