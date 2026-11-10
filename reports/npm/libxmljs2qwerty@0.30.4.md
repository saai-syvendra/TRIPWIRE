# npm libxmljs2qwerty@0.30.4

**Source:** datadog · **Source label:** malicious · **Released:** 2025-12-09 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The only install code is a `postinstall` hook that runs `node index.js`. That script reads `/etc/passwd` with `fs.readFileSync` and prints the whole file and its last line to the install output, inside a try/catch that only logs the error. There are no gates: no environment check decides whether the read happens, and nothing is sent over the network at install. The only thing the environment needs is an existing `/etc/passwd` (any Linux or macOS host).

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- file_present: /etc/passwd (the read throws and the error is caught when the file is missing (e.g. on Windows), so nothing is dumped)

## Behaviour

- Ungated: recon
- Gated: none

## Notes

- The name looks borrowed from `libxmljs2`; `main` exports a stub `parseXml`.
- The archive accidentally includes what looks like the publisher's home directory (npm logs and cache, `otp.py`, `script.js`, an XSS scanner). `script.js` is an HTTP listener that saves received "flags" to a file and logs a listener address of 91.229.11[.]62:8080, but nothing at install contacts it. I only checked these files far enough to confirm that no hook reaches them.
- I recorded the behaviour as `recon` (a local system file dumped to stdout). Whether it counts as exfil depends on who reads the install log, for example a CI or sandbox service that shows install output.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "libxmljs2qwerty",
    "version": "0.30.4",
    "archive_sha256": "c236b7ba9f6654e52c258a13ecec5e0408b3e758e3c523f0ed05dcc6a87a79e4",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-12-09",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-12-09-libxmljs2qwerty-v0.30.4.zip",
    "package_root": "layer0/tmp/tmph9xa_bb8/libxmljs2qwerty/package",
    "cluster_key": "cb44fea1f2903a9432b3abf6df1ab1363d0a3f37a34c9069a188a8d6244919e5",
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
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js: package code read in full (17 lines). It reads /etc/passwd and prints it and its last line to install output inside a try/catch that only logs the error. No network, no process launch, no gate.",
      "The archive also holds what looks like the publisher's home directory (npm logs and cache, otp.py, script.js, XsSCan, payment-order-service). No hook reaches any of it; nested package.json files are not installed.",
      "script.js (not run at install) is a small HTTP listener on port 8080 that appends POST bodies to stolen_flags.txt, consistent with a CTF-style flag-leak setup. It is outside the install path."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "/etc/passwd",
      "reason": "the read throws and the error is caught when the file is missing (e.g. on Windows), so nothing is dumped",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 98,
          "end_byte": 136,
          "node_type": "call_expression",
          "sha256": "aca73865419aad3c",
          "line": 5
        }
      ]
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon"
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
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook always reads /etc/passwd and prints the whole file and its last line to the install output, under a name borrowed from libxmljs2. Nothing is sent over the network at install; the data leaks only to whoever can read the install log.",
  "label_disagreement": false,
  "confidence": "medium",
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
