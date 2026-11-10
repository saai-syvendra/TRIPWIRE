# npm lambda-sns-dynatrace-sdk@3.2.1

**Source:** datadog · **Source label:** malicious · **Released:** 2024-08-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node ./dist/index.js`, a Babel-transpiled script. On every install it collects OS info, hostname, fqdn, shell, software versions, system info, the `JFROG_ARTIFACTORY_URL` value, the cwd and the whole `process.env`. It then POSTs all of it with axios to an `oast[.]live` out-of-band interaction host. Nothing gates it: the only candidate check (`process.env.JBOSS ? process.env : process.env`) has the same value on both arms. Any install environment with outbound HTTPS to the OAST host triggers the exfil.

## Execution

- **postinstall** `node ./dist/index.js`: runs dist/index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: cqp63mhucph76c0aogvgcsnj8emjj448b[.]oast[.]live:443 (axios POST of the collected data; the exfil only completes if the OAST host accepts the connection)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The package name copies a Lambda/Dynatrace internal-SDK style naming and the endpoint is an OAST collector, which fits dependency-confusion probing.
- The header comment says it collects "limited non-pii" data. The code contradicts that because it sends the full environment, which can include secrets. Recorded as misleading text.
- Errors are swallowed by the async try/catch in `log()`. If a `systeminformation` call fails, `getInfos` never resolves and nothing is sent.
- The regenerator licence URL in the inlined helper is not contacted and was removed from the endpoints.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lambda-sns-dynatrace-sdk",
    "version": "3.2.1",
    "archive_sha256": "92033cb8ebd8328caac9816200513d80c9d7021780cb2ecab1c5a2c1cc4cec1a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-08-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-08-06-lambda-sns-dynatrace-sdk-v3.2.1.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmp_0f9n1lq/package",
    "cluster_key": "458cea0ebbad4fead2526d094f2370670b223637059d673fe236a9a8e3d9a9a1",
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
      "dist/index.js: package code (lines 21-119) read in full; Babel helpers and the inlined regenerator-runtime helper (line 13) audited as third-party transpiler output, no sinks; nothing unread.",
      "process.env.JBOSS ternary on line 51 yields process.env on both arms, so the full environment is always sent; not a gate. JFROG_ARTIFACTORY_URL is read only as data.",
      "The async log() wraps collection and the axios POST in try/catch with an empty handler (tryLocs [0,13]), so failures are hidden: silent_failure.",
      "If any systeminformation call rejects, getInfos never resolves (catch has no handler), so the POST never happens; that is a failure mode, not a gate.",
      "Header comment claims it collects only limited non-pii npm/node/package info, but the code sends hostname, fqdn, OS, shell, system info and the whole process.env.",
      "Other files (analytics/index.js source of dist, storeNote.js, queueNote.js, serverless.yml) are not reached by the install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cqp63mhucph76c0aogvgcsnj8emjj448b[.]oast[.]live:443",
      "reason": "axios POST of the collected data; the exfil only completes if the OAST host accepts the connection"
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
      "Babel-transpiled output with an inlined regenerator-runtime helper on one very long line",
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://cqp63mhucph76c0aogvgcsnj8emjj448b[.]oast[.]live",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast[.]live dependency-confusion recon",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script unconditionally collects host details (hostname, fqdn, OS, shell, system info) plus the whole process.env and POSTs them to an out-of-band interaction host on oast[.]live. There is no environment gate.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: header comment claims only limited non-pii info is collected, while the code sends the full process.env and host identifiers"
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
        "note": "process.env.JBOSS ? process.env : process.env has identical arms; flipping it changes nothing, so it is not a gate.",
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
        "note": "Ternary on JBOSS with identical arms (process.env both ways); no behaviour difference.",
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
