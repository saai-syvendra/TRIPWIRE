# npm sap-answer@0.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-07-11 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` with all output sent to /dev/null. index.js makes a single `child_process.exec` call that runs curl against `<whoami>.sap-answer.<id>.oast[.]fun/<hostname>_<pwd>_<base64 env>`. The username leaks in the DNS name, and the hostname, working directory and full environment leak in the URL path. There are no gates: the beacon runs on every install and needs only network access, curl and a POSIX shell.

## Execution

- **preinstall** `node index.js > /dev/null 2>&1`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: sap-answer[.]pqpncipjsoqjksyifeluqbb6pcfrlh7qz[.]oast[.]fun:80 (curl sends recon over HTTP to <whoami>.sap-answer.<id> under oast.fun; the DNS lookup of the subdomain alone already leaks the username)
- installed_tool: curl (the beacon is sent with curl)
- installed_tool: base64 (the env dump is encoded with GNU base64 -w 0; if it is missing only that URL segment is empty)
- os: linux (the command relies on sh backtick substitution and GNU base64 -w; works on Linux, partly on macOS, not under cmd.exe)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The name (SAP-flavoured, version 0.0.0) and the OAST collector fit a dependency-confusion probe. The full env dump goes beyond a minimal proof of concept, though, and can carry tokens and keys.
- The callback branches only log, so they are not gates. `main.js` (the manifest's `main`) is absent and is not run at install.
- The tool did not extract the endpoint because it is built from shell substitutions inside the command string. I added it by hand.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "sap-answer",
    "version": "0.0.0",
    "archive_sha256": "42c118665b892594f11af14fa35aeece2a16d8a1c3b657a3122355bd324387e0",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-07-11",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-07-11-sap-answer-v0.0.0.zip",
    "package_root": "layer0/2024-07-11-sap-answer-v0.0.0/package",
    "cluster_key": "ecf1404a6ee0944c0f2de2fe2669631a1f506390502ba5090bc533e8f7bb3975",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js > /dev/null 2>&1",
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
      "index.js: package code read in full (14 lines); no other file is reached at install. main.js named in package.json main does not exist and is not run at install.",
      "The exec callback only logs the error or output (hidden by the hook's redirect); its if(error) and if(getter) branches are log-only, not gates.",
      "Backtick substitution needs a POSIX /bin/sh; under cmd.exe on Windows the backticks pass through literally and the beacon URL is malformed.",
      "If base64 -w 0 fails (non-GNU base64), only the env segment is empty; the whoami, hostname and pwd beacon still goes out."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "sap-answer[.]pqpncipjsoqjksyifeluqbb6pcfrlh7qz[.]oast[.]fun:80",
      "reason": "curl sends recon over HTTP to <whoami>.sap-answer.<id> under oast.fun; the DNS lookup of the subdomain alone already leaks the username",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 44,
          "end_byte": 319,
          "node_type": "call_expression",
          "sha256": "1f3511cb5feb5e25",
          "line": 3
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the beacon is sent with curl",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 44,
          "end_byte": 319,
          "node_type": "call_expression",
          "sha256": "1f3511cb5feb5e25",
          "line": 3
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "base64",
      "reason": "the env dump is encoded with GNU base64 -w 0; if it is missing only that URL segment is empty",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 44,
          "end_byte": 319,
          "node_type": "call_expression",
          "sha256": "1f3511cb5feb5e25",
          "line": 3
        }
      ]
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "the command relies on sh backtick substitution and GNU base64 -w; works on Linux, partly on macOS, not under cmd.exe",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 44,
          "end_byte": 319,
          "node_type": "call_expression",
          "sha256": "1f3511cb5feb5e25",
          "line": 3
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
      "base64 encoding of the exfiltrated env dump (data encoding, not code obfuscation)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://<whoami>.sap-answer.pqpncipjsoqjksyifeluqbb6pcfrlh7qz.oast[.]fun/<hostname>_<pwd>_<env base64>",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST callback recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook silently runs curl to an oast[.]fun out-of-band collector, sending the username, hostname, working directory and the full base64-encoded environment (which can hold secrets). There is no gate; it runs on every install.",
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
