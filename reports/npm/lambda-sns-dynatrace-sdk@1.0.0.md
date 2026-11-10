# npm lambda-sns-dynatrace-sdk@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-07-29 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node ./dist/index.js` on every registry install. The script loads `dotenv/config`, collects OS info, hostname, FQDN, runtime versions, shell, system details, the working directory, the package name and version, and the whole `process.env`, then POSTs it to a pipedream endpoint (hxxps://eoegnvha3l4b0yp[.]m[.]pipedream[.]net). There are no gates: the only candidate, `process.env.JBOSS ? process.env : process.env`, has identical arms, so the environment is sent either way. Any environment with outbound HTTPS to that host triggers the exfil.

## Execution

- **postinstall** `node ./dist/index.js`: runs dist/index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: eoegnvha3l4b0yp[.]m[.]pipedream[.]net:443 (axios POST of the collected data; failure is swallowed)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Errors are swallowed by an empty try/catch around `log()`.
- The header comment says only limited non-PII data is collected, but the code sends the full environment. It is recorded as misleading text.
- `analytics/index.js` is the unbuilt source of `dist/index.js` and does not run at install. The inlined regenerator runtime on line 13 was audited and is clean.
- The dependency confusion attack type comes from the internal-sounding name and the recon-style payload.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lambda-sns-dynatrace-sdk",
    "version": "1.0.0",
    "archive_sha256": "1788aa971a40b9f1f935a7b7125e952dacb861dfd2b6619c961dc83d08e341fd",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-07-29",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-07-29-lambda-sns-dynatrace-sdk-v1.0.0.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpibugf28z/package",
    "cluster_key": "8fd9cd137b2cd8f3df0cf77ac491f5c3ebf73386c016d3c501cf79f0022ce399",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node ./dist/index.js",
        "runs_on": "always",
        "file_chain": [
          "dist/index.js"
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
      "dist/index.js: package code (lines 1-12, 14-119) read in full; the inlined Babel regenerator runtime on line 13 audited by sink inventory (only licence URL and generator state strings hit); nothing unread.",
      "Postinstall loads dotenv/config (pulls a .env from the cwd into process.env if present), gathers systeminformation osInfo/versions/time/shell/system, cwd and the package name/version, and POSTs it all with axios.",
      "data.is_jboss = process.env.JBOSS ? process.env : process.env sends the whole environment on both arms, so the JBOSS test is not a gate. JFROG_ARTIFACTORY_URL is read only to be sent (recon).",
      "log() wraps everything in try/catch with an empty handler, so failures are silent. A rejected systeminformation call leaves getInfos unresolved and nothing is sent.",
      "Line 3 comment claims only limited non-PII data is collected; the code sends hostname, FQDN and the full process.env (any secrets in it). analytics/index.js is the unbuilt source and is not run at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "eoegnvha3l4b0yp[.]m[.]pipedream[.]net:443",
      "reason": "axios POST of the collected data; failure is swallowed"
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
    "techniques": [
      "Babel regenerator runtime inlined on one long line (build output, not obfuscation)",
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://eoegnvha3l4b0yp[.]m[.]pipedream[.]net",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pipedream install-time env exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall unconditionally collects host details, the working directory and the entire process environment (including anything loaded from a local .env) and posts them to a pipedream collection endpoint. The internal-sounding name and no real functionality fit a dependency confusion probe.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: comment says only limited non-PII data is collected while the code exfiltrates the full process.env",
    "attack_type dependency_confusion inferred from the internal-style name and recon payload; not confirmed against a real internal package"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "a56e6939cb561b85"
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
        "candidate": "k_6760860858",
        "reason_code": "other",
        "note": "process.env.JBOSS ternary yields process.env on both arms; flipping it changes nothing, so it is not a gate",
        "anchor": {
          "file": "dist/index.js",
          "derived_from": null,
          "start_byte": 12919,
          "end_byte": 12936,
          "node_type": "member_expression",
          "sha256": "02428323e2350a4d",
          "line": 51
        }
      },
      {
        "candidate": "q_0514914dad",
        "reason_code": "other",
        "note": "ternary with identical arms (process.env : process.env); no behaviour depends on it",
        "anchor": {
          "file": "dist/index.js",
          "derived_from": null,
          "start_byte": 12919,
          "end_byte": 12964,
          "node_type": "ternary_expression",
          "sha256": "3a8445f61794c014",
          "line": 51
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
