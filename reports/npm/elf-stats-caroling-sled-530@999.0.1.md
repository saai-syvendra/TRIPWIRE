# npm elf-stats-caroling-sled-530@999.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-12-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js || true`. index.js recursively lists and reads every file under `/opt/`, wraps the text in a JSON object under a `flag` key, and POSTs it over HTTPS to a webhook.site URL. There are no environment gates: the only decision is a try/catch around reading `/opt/`, and the POST runs on both sides of it. Any Linux or macOS host with outbound HTTPS to webhook.site triggers the full behaviour.

## Execution

- **preinstall** `node index.js || true`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (recursive dump of /opt is POSTed as JSON to a webhook.site URL; the install does not depend on the reply)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Webhook path redacted to its first 4 characters (`hxxps://webhook[.]site/e78d…`).
- Version 999.0.1 and the `flag` key suggest a dependency-confusion probe or a CTF-style grab of files under `/opt`; the name does not match any known internal package, so attack_type is `malicious_new_package`.
- Both prefilled candidates (the readdirSync probe and its try statement) were dropped: they swallow errors, they do not pick behaviour.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "elf-stats-caroling-sled-530",
    "version": "999.0.1",
    "archive_sha256": "ebdce1979cbc1c0b792d6cb4d400b568260ac134a3aada914bdd10e402c2e9c4",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-12-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-12-04-elf-stats-caroling-sled-530-v999.0.1.zip",
    "package_root": "layer0/tmp/tmp53tqgga9/elf-stats-caroling-sled-530/package",
    "cluster_key": "7382c0cfa57dbd656dfb379407122cc8217eefcabec49d38be8082aac75e821e",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js || true",
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
      "generator truncated: some helpers walked under only 2 guard contexts in index.js; candidates there may be missing",
      "index.js (53 lines): package code read in full; nothing bundled, nothing unread. The recursive readDir helper is the only function and its only callers are the top-level call and itself.",
      "The try around fs.readdirSync('/opt/') is not a gate: when /opt is missing the handler returns an error string and the POST to the webhook still runs, so both sides end in the same exfil.",
      "Per-file try/catch and the req 'error' handler only add error text or log; together with '|| true' in the hook they hide failures (silent_failure)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "recursive dump of /opt is POSTed as JSON to a webhook.site URL; the install does not depend on the reply",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1062,
          "end_byte": 1140,
          "node_type": "call_expression",
          "sha256": "9b356d7c522f8174",
          "line": 44
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
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://webhook[.]site/e78d…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which recursively reads every file under /opt/ and POSTs the contents as a JSON 'flag' field to a webhook.site URL. Nothing gates it; failures are swallowed.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "2966a29559cf3f43"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_bdca1b3460",
        "reason_code": "other",
        "note": "readdirSync('/opt/') failing only changes the dumped text to an error string; the webhook POST runs either way, so no behaviour depends on it.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 139,
          "end_byte": 158,
          "node_type": "call_expression",
          "sha256": "8939d906f9795932",
          "line": 7
        }
      },
      {
        "candidate": "q_ae5fefc3c1",
        "reason_code": "other",
        "note": "try/catch in readDir: both outcomes return a string that is exfiltrated unconditionally; error swallowing, not a gate.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 115,
          "end_byte": 727,
          "node_type": "try_statement",
          "sha256": "d1ada9f637cb78eb",
          "line": 6
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
