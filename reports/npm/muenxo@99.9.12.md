# npm muenxo@99.9.12

**Source:** datadog · **Source label:** malicious · **Released:** 2026-04-30 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script has no gates: it runs a `find ../.. -maxdepth 4 -name package.json` shell line that greps for `dependencies`, then POSTs the first five matching lines together with the hostname, working directory and `CIRCLE_PROJECT_REPONAME` to a webhook.site URL. Nothing about the environment needs to be set to reach the payload; only outbound HTTP to that host is needed for the data to arrive.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: webhook[.]site:80 (hostname, cwd and find output are POSTed there; failure is swallowed)
- installed_tool: sh, find, grep, head (exec runs a find | head shell line to collect dependency lines; without them only the fallback text is sent)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Version 99.9.12 and the CircleCI project-name field point to dependency-confusion recon. The description says it is a bug bounty PoC, but that rests only on text, so it is not used as a label.
- The description's "Harmless" claim is recorded as misleading text, since the code sends host data to a third party.
- Errors from both the `find` command and the HTTP request are discarded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "muenxo",
    "version": "99.9.12",
    "archive_sha256": "6d0e0d7cd93d4c4f159c291e686eb5e8f2b6384a42dfecf5b1a9466870487daf",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-04-30",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-04-30-muenxo-v99.9.12.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmp4xeehkkd/muenxo/package",
    "cluster_key": "089132d4888223801c8235481465c7f62744190e3d03de193bb454c5fc0735f0",
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
      "index.js: 32 lines of package code, read in full; nothing bundled, nothing unread.",
      "The exec callback ignores the find error and the request has an empty error handler, so failures are hidden (silent_failure).",
      "The `stdout || ...` and `process.env.CIRCLE_PROJECT_REPONAME || ...` fallbacks only pick the text that is sent, so they are data collection, not gates.",
      "The URL is https but the request goes through http.request with only hostname and path, so it is a plain HTTP POST to port 80 of that host.",
      "package.json description calls the package harmless, but the install code sends hostname, cwd and dependency lines of parent package.json files to a third-party webhook."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:80",
      "reason": "hostname, cwd and find output are POSTed there; failure is swallowed"
    },
    {
      "axis": "installed_tool",
      "value": "sh, find, grep, head",
      "reason": "exec runs a find | head shell line to collect dependency lines; without them only the fallback text is sent"
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
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://webhook[.]site/dec9…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs unconditionally, searches parent folders for package.json dependency lines and POSTs them with the hostname, working directory and a CircleCI project name to a webhook. This is dependency-confusion recon and exfiltration on whoever installs it.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: package.json description claims the package is harmless while install code exfiltrates host data"
  ],
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
