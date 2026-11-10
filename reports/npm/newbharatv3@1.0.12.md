# npm newbharatv3@1.0.12

**Source:** datadog · **Source label:** malicious · **Released:** 2024-11-16 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`, which executes `ifconfig` through `child_process.exec` and POSTs the trimmed output with axios to an oastify.com (Burp Collaborator style) host. There are no environment gates. The callback returns early if `ifconfig` errors or writes to stderr; those are prerequisites, not gates. Any machine where `ifconfig` is installed, the host is reachable and `axios` resolves will run the recon and exfil.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- other: node module axios resolvable from the package root (parent node_modules or NODE_PATH) (top-level require('axios') is undeclared; without it the script throws before running anything)
- installed_tool: ifconfig (exec('ifconfig') must succeed with empty stderr or the callback returns before the exfil)
- network: j5pr27jwyd78l5etpestecz990fr3jr8[.]oastify[.]com:80 (ifconfig output is POSTed here over plain HTTP)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `axios` is required but not declared as a dependency, and preinstall runs before dependencies are installed, so on a clean install the `require` likely throws and nothing is sent. Recorded as a requirement; a dynamic scanner needs axios on a parent `node_modules` path to see the behaviour.
- Comments are in Hinglish and describe the code accurately; no misleading text.
- Endpoint: hxxp://j5pr27jwyd78l5etpestecz990fr3jr8[.]oastify[.]com (exfil sink).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "newbharatv3",
    "version": "1.0.12",
    "archive_sha256": "93de1e93f90d924b9839bdc4445cc3609a6f17204f62b8f79586a0dd6a6af66e",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-11-16",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-11-16-newbharatv3-v1.0.12.zip",
    "package_root": "layer0/tmp/tmpq605wb6c/newbharatv3/package",
    "cluster_key": "6a22c6cfec8078e6b04f5d293b4100e53988c5b75555e6d5c1eb8c12be43f463",
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
      "index.js (31 lines, package code) read in full; nothing unread.",
      "index.js requires axios but package.json declares no dependencies, and preinstall runs before dependencies anyway; unless axios resolves from a parent node_modules or NODE_PATH, the require throws and nothing runs.",
      "The exec callback returns early when ifconfig fails or writes to stderr. These are prerequisite aborts (the tool must exist and run cleanly), not environment gates; recorded as requirements.",
      "The axios.post error is caught and only logged, so a failed exfil does not fail the install (silent_failure)."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "node module axios resolvable from the package root (parent node_modules or NODE_PATH)",
      "reason": "top-level require('axios') is undeclared; without it the script throws before running anything",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 58,
          "end_byte": 74,
          "node_type": "call_expression",
          "sha256": "dded6390477fe484",
          "line": 2
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "ifconfig",
      "reason": "exec('ifconfig') must succeed with empty stderr or the callback returns before the exfil",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 213,
          "end_byte": 945,
          "node_type": "call_expression",
          "sha256": "2313176f1a75ff6f",
          "line": 7
        },
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 265,
          "end_byte": 342,
          "node_type": "if_statement",
          "sha256": "9528c8455636e153",
          "line": 8
        }
      ]
    },
    {
      "axis": "network",
      "value": "j5pr27jwyd78l5etpestecz990fr3jr8[.]oastify[.]com:80",
      "reason": "ifconfig output is POSTed here over plain HTTP"
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
        "indicator": "hxxp://j5pr27jwyd78l5etpestecz990fr3jr8[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "oastify-recon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs ifconfig and POSTs its output to an oastify.com (Burp Collaborator style) host, sending the installing machine's network interface details to an outside listener. There are no environment gates; it runs wherever axios resolves and ifconfig exists.",
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
