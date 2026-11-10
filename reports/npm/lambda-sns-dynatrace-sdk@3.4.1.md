# npm lambda-sns-dynatrace-sdk@3.4.1

**Source:** datadog · **Source label:** malicious · **Released:** 2024-08-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

On install, npm runs `postinstall: node ./dist/index.js`, a Babel-compiled script. It gathers OS info, hostname, fqdn, versions, shell, system details, `JFROG_ARTIFACTORY_URL` and the entire `process.env`, adds the working directory and package name and version, and POSTs everything to an oast[.]site collector with axios. There are no gates: the only candidate, a `process.env.JBOSS` ternary, has identical arms. Any environment with outbound HTTPS to the collector sees the exfiltration.

## Execution

- **postinstall** `node ./dist/index.js`: runs dist/index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: poc[.]cqp6at1ucphcmo94k0s0eaiywdzx8ygcn[.]oast[.]site:443 (The collected data is POSTed over HTTPS to this host.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The header comment says only limited non-pii data is collected. That does not match the code, which sends the full environment, so it is recorded as misleading text.
- Errors are swallowed by the regenerator try/catch around the whole flow.
- The `.catch()` in `getInfos` has no handler, so a systeminformation failure leaves the promise pending and nothing is sent. That is an incidental requirement, not a gate.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lambda-sns-dynatrace-sdk",
    "version": "3.4.1",
    "archive_sha256": "607cdcd77e94c74da947f4a14947b7f2901bb82de513db77b4aae94f03426093",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-08-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-08-06-lambda-sns-dynatrace-sdk-v3.4.1.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpdq_77h5g/package",
    "cluster_key": "deb58d379c43d8efffa81f1680dfbcf9162aeb11d81ddd79965e1aba13d122a6",
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
      "dist/index.js: package code (lines 21-119) read in full; lines 6-20 are Babel helpers and the regenerator runtime, audited, no sinks; nothing unread.",
      "Postinstall collects systeminformation osInfo (hostname, fqdn, platform), versions, time, shell and system, plus JFROG_ARTIFACTORY_URL and the whole process.env, and POSTs it with cwd and package name/version to an oast[.]site collector.",
      "The JBOSS ternary on line 51 has identical arms (process.env either way), so it is not a gate; process.env is always sent.",
      "Errors are swallowed: the log() generator wraps the whole flow in try/catch (tryLocs [0,13]) with an empty handler, so silent_failure is true.",
      "The header comment claims only limited non-pii information is collected, but the code sends the full process.env and the hostname; recorded as misleading text.",
      "require('dotenv/config') loads a .env from the working directory into process.env before it is sent; no test on the file, so it is not a gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "poc[.]cqp6at1ucphcmo94k0s0eaiywdzx8ygcn[.]oast[.]site:443",
      "reason": "The collected data is POSTed over HTTPS to this host.",
      "sites": [
        {
          "file": "dist/index.js",
          "derived_from": null,
          "start_byte": 13652,
          "end_byte": 13694,
          "node_type": "call_expression",
          "sha256": "de170ea4476d68f3",
          "line": 71
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
    "techniques": [
      "Babel-transpiled output with long helper lines (not obfuscation)",
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://poc[.]cqp6at1ucphcmo94k0s0eaiywdzx8ygcn[.]oast[.]site",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script unconditionally collects host details and the entire process.env (which commonly holds secrets) and POSTs them to an out-of-band interaction (oast) collector. The name mimics an internal-looking Dynatrace/Lambda SDK, consistent with dependency confusion probing.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Header comment claims only limited non-pii data is collected while the code exfiltrates the whole process.env and hostname (misleading text)."
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
        "note": "process.env.JBOSS test in a ternary whose two arms are both process.env; flipping it changes nothing.",
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
        "note": "Ternary with identical arms (process.env : process.env); no behaviour depends on it.",
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
