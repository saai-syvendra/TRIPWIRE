# npm airbnb-location-suggester@3.9.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-06-11 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script collects hostname, OS type, platform, release and arch, the first non-internal IPv4 address, the username and the working directory. It then looks up the public IP and sends everything by GET and POST to a hardcoded IP on port 8080. If the HTTP send fails, it falls back to a WebSocket send to a placeholder host. There are no environment gates. The only check, `npm_lifecycle_event === "preinstall"`, controls console logging and does not change what runs.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: 54[.]173[.]15[.]59:8080 (GET and POST exfil target)
- other: node-fetch dependency installed and importable (sendData imports node-fetch dynamically; on failure only the WebSocket fallback to a placeholder host remains)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Six tool candidates (the `isPreinstall` site and five `if (!isPreinstall)` guards) were dropped as `log_only`.
- The nested `npm/` folder holds a variant named service-config-provider that checks CI env vars, waits a random delay and posts to a different IP. Nothing in this package's install runs it, so it is out of scope here. It may show up as its own sample.
- `silent_failure` is true: send errors are caught and only logged outside preinstall.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "airbnb-location-suggester",
    "version": "3.9.0",
    "archive_sha256": "943f402acd284c05da479fc731affa17e9bb504bf6a00a37ce0a96f4c257291a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-06-11",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-06-11-airbnb-location-suggester-v3.9.0.zip",
    "package_root": "layer0/tmp/tmpkhdydvqc/airbnb-location-suggester/package",
    "cluster_key": "ade8fc347e09e0b8522725016254ca69155b4d23406448cc4b05b29d3cfcb3b5",
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
      "index.js read in full (116 lines). The isPreinstall (npm_lifecycle_event == preinstall) checks only suppress console logging; both sides send the same data, so they are not gates.",
      "Exfil runs ungated: hostname, OS type/platform/release/arch, local IP, username and cwd, plus the public IP from an IP lookup, are sent by GET query string and POST JSON to a hardcoded IP on port 8080.",
      "If the HTTP send throws (for example node-fetch not importable), the catch falls back to a WebSocket send through the ws module to a placeholder host (yourserver[.]com). Fallback chain, not a gate.",
      "The public IP lookup (api64[.]ipify[.]org) is recon; on error the data is sent anyway with publicIP empty. Not listed under endpoints since no endpoint role fits a lookup service.",
      "npm/index.js and npm/package.json are a nested copy named service-config-provider (CI env var evasion, random delay, different IP). This package's preinstall never runs them; not install-reached."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "54[.]173[.]15[.]59:8080",
      "reason": "GET and POST exfil target"
    },
    {
      "axis": "other",
      "value": "node-fetch dependency installed and importable",
      "reason": "sendData imports node-fetch dynamically; on failure only the WebSocket fallback to a placeholder host remains"
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
        "indicator": "hxxp://54[.]173[.]15[.]59:8080/jpd.php",
        "role": "exfil_sink"
      },
      {
        "indicator": "wss://yourserver[.]com/socket",
        "role": "exfil_sink"
      },
      {
        "indicator": "54[.]173[.]15[.]59:8080",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects hostname, username, OS details, local and public IP and working directory and sends them to a hardcoded IP. There is no environment gate; the npm_lifecycle_event check only silences logging.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "e33ade2ed0a8131c"
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
        "candidate": "k_bb9a54b9bd",
        "reason_code": "log_only",
        "note": "isPreinstall only decides whether responses and errors are printed; the exfil runs either way.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 121,
          "end_byte": 169,
          "node_type": "binary_expression",
          "sha256": "21dd896d26b5513c",
          "line": 5
        }
      },
      {
        "candidate": "q_c0dc4a9d4f",
        "reason_code": "log_only",
        "note": "if (!isPreinstall) guards console.log of the HTTP responses only.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2344,
          "end_byte": 2512,
          "node_type": "if_statement",
          "sha256": "f554bdaf267a9ad8",
          "line": 80
        }
      },
      {
        "candidate": "q_fa0a7e97ce",
        "reason_code": "log_only",
        "note": "if (!isPreinstall) guards console.error only; the WebSocket fallback call sits after it.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2543,
          "end_byte": 2639,
          "node_type": "if_statement",
          "sha256": "d6db485a6ec44155",
          "line": 85
        }
      },
      {
        "candidate": "q_f7a50dc258",
        "reason_code": "log_only",
        "note": "if (!isPreinstall) guards console.log only; ws.send runs after it either way.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 2958,
          "end_byte": 3058,
          "node_type": "if_statement",
          "sha256": "601a8e18f3edd5ae",
          "line": 99
        }
      },
      {
        "candidate": "q_6136c0e2bb",
        "reason_code": "log_only",
        "note": "if (!isPreinstall) guards console.error only.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 3185,
          "end_byte": 3275,
          "node_type": "if_statement",
          "sha256": "6413709120b17da5",
          "line": 107
        }
      },
      {
        "candidate": "q_1005e3f207",
        "reason_code": "log_only",
        "note": "if (!isPreinstall) guards console.error only.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 3318,
          "end_byte": 3417,
          "node_type": "if_statement",
          "sha256": "ffbed7d503de2d28",
          "line": 112
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 6,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
