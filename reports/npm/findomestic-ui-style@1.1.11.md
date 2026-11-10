# npm findomestic-ui-style@1.1.11

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`. The script collects hostname, username, OS type, platform, release and arch, the first external IPv4 address and the working directory, looks up the public IP via ipify, and sends everything to one of two PHP endpoints on 23[.]22[.]251[.]177:8080 as a GET query string and a POST JSON body. If the HTTP path fails it tries a WebSocket send to a placeholder host. There are no gates: every install that can reach the network sends the beacon.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: 23[.]22[.]251[.]177:8080 (exfil endpoints jpd.php and jpd1.php receive the GET query string and the POST JSON body)
- other: dependency node-fetch installed and importable via dynamic import (sendData imports node-fetch; if that fails it falls through to the WebSocket path, which needs the ws dependency)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The name matches a real financial company's brand and the package has no real content, which points to dependency confusion (a recon-only callback). The author field is a handle and is left out.
- `Exploit/` contains a near-identical copy of the script for a different package name; it is not run at install.
- Requirements: network access to the exfil IP, and the `node-fetch` dependency (otherwise the `ws` fallback runs).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "findomestic-ui-style",
    "version": "1.1.11",
    "archive_sha256": "492fff2b7a8f361cf66b59754ff386fd44eedf3c782bef67f8ab51939378a9da",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-02-20-findomestic-ui-style-v1.1.11.zip",
    "package_root": "layer0/tmp/tmpyaglwuvd/findomestic-ui-style/package",
    "cluster_key": "7e27bb99fb66c48c7dfa38d55b49a61d8a1a1a90747993130f83f471d744020c",
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
      "index.js: package code, read in full (103 lines); no bundled code, nothing unread.",
      "No environment check decides what runs: system info is collected and sent unconditionally. An ipify failure still calls sendData; an HTTP failure falls back to a WebSocket send. Both are fallback chains, not gates.",
      "Exploit/ holds a near-identical copy of the script and a manifest for another package name; nothing at install references it, so it is not install-reached.",
      "Failures are hidden: sendData and sendViaWebSocket catch errors and only log them, and the https error handler swallows the ipify failure.",
      "api64[.]ipify[.]org is queried at install only to learn the public IP (recon); left out of endpoints since it has no exfil or c2 role. wss://yourserver[.]com is a placeholder host used only by the WebSocket fallback."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "23[.]22[.]251[.]177:8080",
      "reason": "exfil endpoints jpd.php and jpd1.php receive the GET query string and the POST JSON body"
    },
    {
      "axis": "other",
      "value": "dependency node-fetch installed and importable via dynamic import",
      "reason": "sendData imports node-fetch; if that fails it falls through to the WebSocket path, which needs the ws dependency"
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
        "indicator": "hxxp://23[.]22[.]251[.]177:8080/jpd.php",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxp://23[.]22[.]251[.]177:8080/jpd1.php",
        "role": "exfil_sink"
      },
      {
        "indicator": "wss://yourserver[.]com/socket",
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
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects hostname, username, OS details, local and public IP and the working directory and sends them by GET and POST to a hard-coded IP on port 8080, with a WebSocket fallback. The install does nothing else.",
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
