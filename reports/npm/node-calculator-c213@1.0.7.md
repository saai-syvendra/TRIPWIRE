# npm node-calculator-c213@1.0.7

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-17 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script's only top-level statement is a `fetch` that puts `JSON.stringify(process.env)` in the query string of an HTTP GET to an ngrok TCP tunnel (`7[.]tcp[.]eu[.]ngrok[.]io:19974`). There are no gates: the env dump is sent on every OS and every environment. It needs Node 18 or later for the global `fetch`, and the tunnel has to be reachable.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: 7[.]tcp[.]eu[.]ngrok[.]io:19974 (Env dump is sent by HTTP GET to this ngrok tunnel.)
- runtime_version: node>=18 (Uses the global fetch, which Node only provides from v18; on older Node the call throws a ReferenceError and nothing is sent.)

## Behaviour

- Ungated: recon, cred_read, exfil
- Gated: none

## Notes

- The `calculate()` export only returns `process.env` and is never called at install.
- The rejected fetch promise is not caught, so a network failure makes the preinstall exit non-zero rather than failing silently.
- The registry metadata shows earlier versions (1.0.0) with no install hook. This looks like a small throwaway env-exfil test package.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "node-calculator-c213",
    "version": "1.0.7",
    "archive_sha256": "839a798def3baa3bd1e6c0b66ade5bd542aa2790809abb79fee65a1916ba00f1",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-17",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-11-17-node-calculator-c213-v1.0.7.zip",
    "package_root": "layer0/tmp/tmpwqemj9kw/node-calculator-c213/package",
    "cluster_key": "895d807e6e6eee8f4266fd1237e7d784517bfe91d7130fc0057b248bf53713e4",
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
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "index.js (6 lines) read in full: top-level fetch sends JSON.stringify(process.env) in the query string to an ngrok TCP tunnel. No checks, no branches, no other files.",
      "The fetch promise is not awaited or caught, so a network failure surfaces as an unhandled rejection that makes node exit non-zero; failures are not silenced.",
      "calculate() just returns process.env and is only exported (main), never called at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "7[.]tcp[.]eu[.]ngrok[.]io:19974",
      "reason": "Env dump is sent by HTTP GET to this ngrok tunnel.",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 60,
          "end_byte": 132,
          "node_type": "call_expression",
          "sha256": "1df997189c2268c8",
          "line": 5
        }
      ]
    },
    {
      "axis": "runtime_version",
      "value": "node>=18",
      "reason": "Uses the global fetch, which Node only provides from v18; on older Node the call throws a ReferenceError and nothing is sent.",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 60,
          "end_byte": 132,
          "node_type": "call_expression",
          "sha256": "1df997189c2268c8",
          "line": 5
        }
      ]
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
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://7[.]tcp[.]eu[.]ngrok[.]io:19974?c=$",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally sends the full process environment (including any tokens or secrets in env vars) to an ngrok tunnel. There is no other functionality at install.",
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
