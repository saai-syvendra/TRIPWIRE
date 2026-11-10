# npm cmp-ocr-liveness-acquisition@0.0.24

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-12 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script collects hostname, OS type, platform and release, the first non-internal IPv4 address, the public IP (via ipinfo[.]io), the output of `whoami` and `npm whoami`, the working directory, and whether an internal-looking host answers a ping request, then POSTs it all as JSON to a hard-coded IP on port 8080. There are no environment gates: the try/catch blocks around the user lookups and the internal API check only change the collected values, and the beacon is sent unconditionally. Any environment with outbound access to the collector shows the whole behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: 23[.]22[.]251[.]177:8080 (collector the beacon is POSTed to; failure is caught and logged)
- other: axios dependency installed before preinstall runs (index.js requires axios at top level; if it is missing the script throws before collecting anything)

## Behaviour

- Ungated: recon, spawn_process, exfil
- Gated: none

## Notes

- The two prefilled `whoami`/`npm whoami` try/catch candidates were dropped as data collection; both arms lead to the same POST.
- The internal API probe targets a placeholder-style host (internal-api[.]company[.]com) and only feeds a field in the beacon. This fits a dependency confusion recon package.
- `kk.js` (an older variant beaconing to a different IP) and `server.js` (an express listener) ship in the package but no hook runs them.
- Errors in the POST are caught and logged, so the install never fails visibly.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "cmp-ocr-liveness-acquisition",
    "version": "0.0.24",
    "archive_sha256": "cae2e2bf394e0e0d856384476205986e2ae6c8d1058bd9f29e3470d586117224",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-12",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-02-12-cmp-ocr-liveness-acquisition-v0.0.24.zip",
    "package_root": "layer0/tmp/tmp13p4569x/cmp-ocr-liveness-acquisition/package",
    "cluster_key": "74b50dd27f1d99306979b08b91489d7c484ebe5953a3ec774e1d31c889a72c16",
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
      "index.js: package code, 106 lines, read in full; nothing unread.",
      "The try/catch around execSync('whoami') and execSync('npm whoami') only swaps the value collected for 'Unknown'; both sides send the same POST, so these are data collection, not gates.",
      "checkInternalAPI() compares the status of a GET to an internal-looking host to 200, but only to put 'Accessible' or 'No Access' into the beacon; recon, not a gate.",
      "kk.js (older beacon variant with a different collector IP) and server.js (express listener) are not run by any hook; not install-time.",
      "ipinfo[.]io and internal-api[.]company[.]com are contacted at install for recon only; no endpoint role fits, so only the collector is listed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "23[.]22[.]251[.]177:8080",
      "reason": "collector the beacon is POSTed to; failure is caught and logged"
    },
    {
      "axis": "other",
      "value": "axios dependency installed before preinstall runs",
      "reason": "index.js requires axios at top level; if it is missing the script throws before collecting anything"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "spawn_process",
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
      },
      {
        "indicator": "23[.]22[.]251[.]177:8080",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which collects hostname, OS details, local and public IP, the OS user, the npm user, the working directory and whether an internal-looking host answers, and POSTs it to a hard-coded IP. No gate decides whether this runs.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "2e6376847758efbc"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_d1ce47b8d9",
        "reason_code": "not_environmental",
        "note": "execSync('whoami') in try; failure only replaces the collected value with 'Unknown', beacon is sent either way (data collection).",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1025,
          "end_byte": 1065,
          "node_type": "call_expression",
          "sha256": "47b2a3b1c369f163",
          "line": 40
        }
      },
      {
        "candidate": "k_6c914314b2",
        "reason_code": "not_environmental",
        "note": "execSync('npm whoami') in try; failure only replaces the collected value with 'Unknown', beacon is sent either way (data collection).",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 846,
          "end_byte": 890,
          "node_type": "call_expression",
          "sha256": "ec250ac6a4d2ae91",
          "line": 31
        }
      },
      {
        "candidate": "q_e92c5d9c28",
        "reason_code": "not_environmental",
        "note": "try/catch in getWhoamiUser(); both arms return a string that is sent, no behaviour change.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1008,
          "end_byte": 1119,
          "node_type": "try_statement",
          "sha256": "19805fb515cd4fad",
          "line": 39
        }
      },
      {
        "candidate": "q_f63b45765a",
        "reason_code": "not_environmental",
        "note": "try/catch in getNpmUser(); both arms return a string that is sent, no behaviour change.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 829,
          "end_byte": 944,
          "node_type": "try_statement",
          "sha256": "0fa6a5d52a809ab6",
          "line": 30
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 4,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 2,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
