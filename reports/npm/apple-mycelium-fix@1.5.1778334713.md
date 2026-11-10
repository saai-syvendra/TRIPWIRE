# npm apple-mycelium-fix@1.5.1778334713

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-09 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js` on every registry install. The script runs one shell command, with no checks first. That command appends a signature line to `node_modules/@apple/mycelium/README.md` and then runs `npm publish` on that folder with a dummy OTP, so it tries to push a tampered copy of another package using the installer's npm credentials. Whatever the outcome, a second `exec` POSTs the command's stdout and stderr, the `USERNAME`/`USER` value and a timestamp to a webhook[.]site URL with curl. There are no gates. The only branch is a ternary that sets the status string in the exfil body.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script, inline_shell; errors hidden.

## Gates

None.

## Requirements

- file_present: node_modules/@apple/mycelium/README.md (README append is chained with && before npm publish; without the target package in node_modules the publish step never runs)
- installed_tool: npm (npm publish of the tampered target package)
- installed_tool: curl (exfil POST to the webhook)
- network: registry[.]npmjs[.]org:443, webhook[.]site:443 (npm publish talks to the registry; the webhook is the exfil sink)
- other: npm credentials with write access to @apple/mycelium in the installer's npm config (publish only succeeds with an authenticated token for the target package; otherwise it fails and the failure is still exfiltrated)

## Behaviour

- Ungated: modify_other_packages, recon, exfil
- Gated: none

## Notes

- The publish only works when `@apple/mycelium` is present in `node_modules` and the host's npm config holds a token with write access to it. Both are listed as requirements, not gates, because the code never tests for them.
- The package text frames it as a write-access "security audit" or "challenge" PoC. The code matches that framing: it really does try the write. That is why this is not recorded as misleading text, but it still acts on victim credentials.
- The webhook id is redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "apple-mycelium-fix",
    "version": "1.5.1778334713",
    "archive_sha256": "0c2ecbde1b6a35621ded3612d9eb98615dbe25f8295399ea048b0af508b474de",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-09",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-05-09-apple-mycelium-fix-v1.5.1778334713.zip",
    "package_root": "layer0/tmp/tmpd2_2zumr/apple-mycelium-fix/package",
    "cluster_key": "a684c1758fcb00b5c53f5407206dc70cf2ae325009fcabbfbd643aaa42449bfb",
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
          "direct_script",
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js: package code read in full (23 lines); no other file is reached at install.",
      "The shell command appends a line to node_modules/@apple/mycelium/README.md, then runs npm publish on that folder with a dummy OTP, using whatever npm credentials the installing host has.",
      "The exec callback always runs a second exec that POSTs the command's stdout, stderr and the USERNAME/USER value to a webhook with curl. Errors only go there and never fail the install (silent_failure).",
      "The ternary error ? ATTEMPTED : SUCCESS only changes a status string in the exfil body, so it is not a gate."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "node_modules/@apple/mycelium/README.md",
      "reason": "README append is chained with && before npm publish; without the target package in node_modules the publish step never runs"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "npm publish of the tampered target package"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "exfil POST to the webhook"
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443, webhook[.]site:443",
      "reason": "npm publish talks to the registry; the webhook is the exfil sink"
    },
    {
      "axis": "other",
      "value": "npm credentials with write access to @apple/mycelium in the installer's npm config",
      "reason": "publish only succeeds with an authenticated token for the target package; otherwise it fails and the failure is still exfiltrated"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "modify_other_packages",
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
        "indicator": "hxxps://webhook[.]site/acc4…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "On every install, postinstall tampers with the README of @apple/mycelium in node_modules and tries to npm publish it with the installer's credentials, then POSTs the result and the local username to a webhook. It is framed as a write-access proof of concept, but it uses the victim's credentials and exfiltrates data without consent.",
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
