# npm meditek@1.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2024-09-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script collects the package name, install directory, OS type and arch, home directory, hostname, username, DNS servers and the package's own package.json (including `___resolved`). It then POSTs that data as form data to an Interactsh collector at `jclvggshiuspsqrvxwbd15fntqglrjrea.oast[.]fun:443`. There are no gates: any environment that can reach the collector triggers the full payload.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: jclvggshiuspsqrvxwbd15fntqglrjrea[.]oast[.]fun:443 (The HTTPS POST of collected host data must reach the Interactsh collector for the exfil to complete)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The request error handler is empty, so install does not fail when the collector is unreachable (silent_failure).
- The unscoped generic name, the `___resolved` field and the out-of-band callback host match the common dependency-confusion probe template. `attack_type` is based on the code pattern, not the "JOD POC" description.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "meditek",
    "version": "1.0.2",
    "archive_sha256": "ffc09fdf8ffd45f95f10472e367b1ff6b603170b8f1b5ea0d154f85171b66a3b",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-09-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-09-25-meditek-v1.0.2.zip",
    "package_root": "layer0/tmp/tmpm_1ii9_f/meditek/package",
    "cluster_key": "18316905c26aa8255c5379fc7f45f40c2a9b69044694d811ec44acb78779350c",
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
      "index.js: package code read in full (48 lines, no bundled or obfuscated code); nothing unread.",
      "No environment checks: the script collects host data and POSTs it unconditionally at preinstall.",
      "The req.on('error') handler is empty (its console.error is commented out), so a failed request is hidden: silent_failure.",
      "Collected fields: package name, __dirname, os.type(), os.arch(), homedir, hostname, username, dns.getServers(), and package.json including ___resolved and version.",
      "The server response is only echoed to stdout; it does not pick any behaviour."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "jclvggshiuspsqrvxwbd15fntqglrjrea[.]oast[.]fun:443",
      "reason": "The HTTPS POST of collected host data must reach the Interactsh collector for the exfil to complete",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 926,
          "end_byte": 1031,
          "node_type": "call_expression",
          "sha256": "1b785117c08990a0",
          "line": 37
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
        "indicator": "hxxps://jclvggshiuspsqrvxwbd15fntqglrjrea.oast[.]fun:443/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "Interactsh (oast[.]fun) dependency-confusion recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which unconditionally collects hostname, username, home directory, DNS servers, install path and package.json and POSTs them to an Interactsh out-of-band collector. There are no gates; it is a dependency-confusion style recon beacon.",
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
