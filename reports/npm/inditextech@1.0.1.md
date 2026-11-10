# npm inditextech@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-29 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js` on every registry install. index.js has no conditions: it requests the public IP from api[.]ipify[.]org and, when the response ends, sends the IP and a timestamp to a hardcoded Telegram bot (token redacted to 7699…) with an "RCE Triggered" message. There are no gates, so any environment with outbound HTTPS to both hosts triggers the beacon.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: api[.]ipify[.]org:443, api[.]telegram[.]org:443 (public IP lookup must answer before the Telegram exfil request is sent from its 'end' callback)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Behaviours are recon (public IP lookup) and exfil (Telegram sendMessage); nothing is written, run or persisted.
- Attack type dependency_confusion is an inference from the name and the beacon-only payload. The manifest description and author field contain an attacker handle, not recorded here.
- The Telegram endpoint is recorded with the bot token truncated; the tool's prefilled `bot$` indicator was replaced.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "inditextech",
    "version": "1.0.1",
    "archive_sha256": "67cc84870a3391dde3088116c9c0d33c6258a1f68fda3da38541f4fc92fd959a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-29",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-29-inditextech-v1.0.1.zip",
    "package_root": "layer0/tmp/tmp_siq7ael/inditextech/package",
    "cluster_key": "b03be06d14bd48ca72466dd2d350887f78450243211a5c9d4421e9df597b637c",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
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
      "index.js (19 lines) read in full: no conditions anywhere. It fetches the public IP from api[.]ipify[.]org, then in the response 'end' callback sends IP and timestamp to a Telegram bot via sendMessage (token 7699…, chat id 6567…).",
      "api[.]ipify[.]org is a public IP lookup used for recon, not a C2 or exfil sink, so it is listed as a network requirement rather than an endpoint role.",
      "No 'error' handlers on either https.get; a network failure surfaces as an unhandled error, so silent_failure stays false.",
      "attack_type dependency_confusion is inferred from the unscoped name matching a company org name and the code only beaconing host IP; no registry metadata confirms an internal package of that name."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]ipify[.]org:443",
        "api[.]telegram[.]org:443"
      ],
      "reason": "public IP lookup must answer before the Telegram exfil request is sent from its 'end' callback",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 33,
          "end_byte": 569,
          "node_type": "call_expression",
          "sha256": "998a23282a2880f2",
          "line": 3
        },
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 526,
          "end_byte": 540,
          "node_type": "call_expression",
          "sha256": "d0e1a39ae2f8af98",
          "line": 18
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
        "indicator": "hxxps://api[.]telegram[.]org/bot7699…/sendMessage",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook runs index.js unconditionally, which looks up the installing host's public IP and sends it with a timestamp to an attacker-controlled Telegram bot. There are no environment gates; it is an install-time beacon typical of dependency-confusion probing.",
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
