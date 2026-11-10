# npm rsflows-pexml@99.9.20

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-10 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`, which passes one shell script to `child_process.exec` with no callback. The script prints hostname, user and network interfaces, asks the GCP metadata server for the default service-account access token, lists files named like tokens, secrets or `.npmrc` under /home and /root, and pipes all of it to a webhook.site URL with curl. There are no gates: nothing in the JS or the shell checks the environment before running. The only branches are shell fallbacks (`|| echo 'Not GCP'`, `ip a || ifconfig`) that keep the same behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- os: linux (POSIX shell script using hostname, whoami, ip/ifconfig and find over /home and /root)
- installed_tool: sh (child_process.exec runs the command through /bin/sh)
- installed_tool: curl (used for the GCP metadata request and to POST the collected output)
- network: webhook[.]site:443 (collected output is POSTed to a webhook.site URL)
- network: metadata[.]google[.]internal:80 (GCP service-account token request; only returns a token on a GCP instance, else prints 'Not GCP' and the script continues)

## Behaviour

- Ungated: recon, cred_read, exfil
- Gated: none

## Notes

- Version 99.9.20 and an internal-looking name point to dependency confusion. The manifest description calls it a research PoC, but the code still exfiltrates a live cloud token, so it is assessed malicious. The description is not used for any label.
- The comments in the script name a target ("gcpjenkins"). That is comment text only and is not used for any label.
- The webhook id is redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "rsflows-pexml",
    "version": "99.9.20",
    "archive_sha256": "edcda7068da3c6bfc12aaf4160895419b593e3dd21229dc6a6afed1c1e4b7a92",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-10",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-05-10-rsflows-pexml-v99.9.20.zip",
    "package_root": "layer0/tmp/tmp0mzz1x4y/rsflows-pexml/package",
    "cluster_key": "16849183dc90fd6738de3a6694fc52e01b09b52c1bbe5d8246d2d285160be0b9",
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
      "index.js: read in full (20 lines, package code). No JS conditionals; one child_process.exec of a shell script held in a template literal, called with no callback, so exit status and errors are discarded.",
      "Shell fallbacks `curl ... || echo 'Not GCP'` and `ip a || ifconfig` only print a placeholder or try another tool; the behaviour is the same either way, so they are plumbing and requirements, not gates.",
      "find over /home and /root (maxdepth 4) lists paths of files named *token*, *secret* or .npmrc (names only, not contents); stderr goes to /dev/null. The output is piped with the rest to the webhook.",
      "GCP metadata URL (hxxp://metadata[.]google[.]internal/computeMetadata/v1/instance/service-accounts/default/token) is a credential source read at install, not an exfil sink or C2, so it is listed under requirements instead of endpoints."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX shell script using hostname, whoami, ip/ifconfig and find over /home and /root"
    },
    {
      "axis": "installed_tool",
      "value": "sh",
      "reason": "child_process.exec runs the command through /bin/sh"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "used for the GCP metadata request and to POST the collected output"
    },
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "collected output is POSTed to a webhook.site URL"
    },
    {
      "axis": "network",
      "value": "metadata[.]google[.]internal:80",
      "reason": "GCP service-account token request; only returns a token on a GCP instance, else prints 'Not GCP' and the script continues"
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
        "indicator": "hxxps://webhook[.]site/53b0…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs, with no environment checks, a shell script that collects hostname, user, network interfaces, a GCP service-account access token from the metadata server and paths of token/secret/.npmrc files, then POSTs it all to a webhook.site URL.",
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
