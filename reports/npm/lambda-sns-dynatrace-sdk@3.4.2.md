# npm lambda-sns-dynatrace-sdk@3.4.2

**Source:** datadog · **Source label:** malicious · **Released:** 2024-08-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Both `preinstall` and `postinstall` run `node ./dist/index.js`, a Babel build of `analytics/index.js`. The script loads `dotenv/config`, collects OS info, hostname, FQDN, runtime versions, time, shell, system info, `JFROG_ARTIFACTORY_URL` and the entire `process.env`, adds the cwd and package name and version, and POSTs it with axios to an oast[.]fun out-of-band callback host. There are no gates: the only candidate, `process.env.JBOSS ? process.env : process.env`, has identical arms. Any environment where the dependencies resolve and the host is reachable triggers the exfiltration.

## Execution

- **preinstall** `node ./dist/index.js`: runs dist/index.js; direct_script; errors hidden.
- **postinstall** `node ./dist/index.js`: runs dist/index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: poc[.]cqp6e79ucphfnmne8lugjymjc13rk1kk3[.]oast[.]fun:443 (axios.post of collected host data and process.env to the OAST endpoint)
- other: dependencies axios, systeminformation, read-package-json, dotenv resolvable from the package (top-level require of these modules; without them the script throws before collecting data)

## Behaviour

- Ungated: recon, cred_read, exfil
- Gated: none

## Notes

- Dependency confusion style recon: the package name looks like an internal Lambda/Dynatrace helper and the endpoint is an interactsh (oast) callback.
- The header comment says it collects "limited non-pii information", which the code contradicts by sending all env vars (recorded as misleading text).
- Errors during collection and the POST are swallowed by an empty catch in `log()`. The top-level requires sit outside it, so missing dependencies would fail the hook visibly.
- The payload runs twice per install (pre and post).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lambda-sns-dynatrace-sdk",
    "version": "3.4.2",
    "archive_sha256": "6e1d7cac695c39bca0b76b9a4499d3ed3931c7184e99bce33a6d2859568915e3",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-08-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-08-06-lambda-sns-dynatrace-sdk-v3.4.2.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpgvyfy8us/package",
    "cluster_key": "a27e50914bf38d0ba8a125ed81b61c019c49c01a1da5bc4111d0befab165c97f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
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
      },
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
      "dist/index.js: package code (Babel output of analytics/index.js) read in full; inlined Babel helpers and regenerator-runtime on line 13 audited as library, no sinks; nothing unread.",
      "process.env.JBOSS ? process.env : process.env (line 51) returns the full environment on both arms, so it is not a gate; the whole env is sent regardless.",
      "require('dotenv/config') loads a .env file from the install cwd into process.env before it is dumped, so any secrets there are exfiltrated too.",
      "log() wraps everything in try/catch with an empty handler, so failures (missing deps, unreachable host) are swallowed: silent_failure.",
      "Both runs need axios, systeminformation, read-package-json and dotenv to resolve; the requires are top level, outside the try, so a missing dep fails the hook loudly. npm 7+ installs deps before running the package's preinstall.",
      "analytics/index.js, storeNote.js, queueNote.js, serverless.yml are not run at install (build source and Lambda handlers)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "poc[.]cqp6e79ucphfnmne8lugjymjc13rk1kk3[.]oast[.]fun:443",
      "reason": "axios.post of collected host data and process.env to the OAST endpoint",
      "sites": [
        {
          "file": "dist/index.js",
          "derived_from": null,
          "start_byte": 13651,
          "end_byte": 13693,
          "node_type": "call_expression",
          "sha256": "de170ea4476d68f3",
          "line": 71
        }
      ]
    },
    {
      "axis": "other",
      "value": "dependencies axios, systeminformation, read-package-json, dotenv resolvable from the package",
      "reason": "top-level require of these modules; without them the script throws before collecting data"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read",
      "exfil"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://poc[.]cqp6e79ucphfnmne8lugjymjc13rk1kk3[.]oast[.]fun",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "Pre- and postinstall run dist/index.js, which gathers OS, hostname, versions, shell and system info plus the entire process.env (after loading a local .env via dotenv) and POSTs it to an oast.fun out-of-band callback host. No gate; it runs on every install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@497d11fbce",
      "sha256": "610fa8ec3f974e89"
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
        "note": "process.env.JBOSS is tested in a ternary whose two arms are both process.env; flipping it changes nothing, so not a gate.",
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
        "note": "Ternary process.env.JBOSS ? process.env : process.env has identical arms; no behaviour depends on it.",
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
    "condition_candidates": 2,
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
