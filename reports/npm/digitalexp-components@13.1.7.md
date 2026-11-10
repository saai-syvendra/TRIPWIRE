# npm digitalexp-components@13.1.7

**Source:** datadog · **Source label:** malicious · **Released:** 2025-01-29 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The preinstall hook runs `node index.js`. The script opens a raw TCP socket to an ngrok tunnel (`0.tcp.in[.]ngrok[.]io:14410`). Once connected, it spawns `bash -i` and pipes the shell's stdin, stdout and stderr through the socket, which is a plain reverse shell. There are no environment gates: any install that can reach the tunnel and has `bash` gives the remote side a shell.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: 0[.]tcp[.]in[.]ngrok[.]io:14410 (reverse shell connects to this ngrok TCP tunnel; the shell is only spawned in the connect callback)
- installed_tool: bash (spawn('bash', ['-i']) is the shell piped to the remote side)

## Behaviour

- Ungated: reverse_shell
- Gated: none

## Notes

- Attack type `dependency_confusion` is inferred from the package's shape (unscoped corporate-style name, high version 13.1.7, no real library code), not from code. The description field reads like a researcher's RCE probe, which fits that.
- The `node-fetch` dependency is unused.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "digitalexp-components",
    "version": "13.1.7",
    "archive_sha256": "2eb0cbd236acd867d42381212110e9cac1df239578c30dc0553f5f372c0b9563",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-01-29",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-01-29-digitalexp-components-v13.1.7.zip",
    "package_root": "layer0/tmp/tmpygcn9m8t/digitalexp-components/package",
    "cluster_key": "002f90fe0b731c15f83cd4c8904437abd4ff90ba8ba64250bcfbb036f0b67242",
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
      "index.js: package code read in full (41 lines); no bundled or third-party code, nothing unread.",
      "No environment checks: the socket connect and the bash spawn in its connect callback run unconditionally on preinstall. Connection errors are logged by an error handler, so the hook exits normally either way.",
      "The node process stays alive while the shell session is open, so the install blocks until the remote side closes it.",
      "Dependency node-fetch ^2.7.0 is a normal registry package and is not used by index.js."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "0[.]tcp[.]in[.]ngrok[.]io:14410",
      "reason": "reverse shell connects to this ngrok TCP tunnel; the shell is only spawned in the connect callback"
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "spawn('bash', ['-i']) is the shell piped to the remote side"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "reverse_shell"
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
        "indicator": "0[.]tcp[.]in[.]ngrok[.]io:14410",
        "role": "reverse_shell"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which opens a TCP connection to an ngrok tunnel and pipes an interactive bash shell over it, giving the remote side command execution on the installing machine. There are no gates.",
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
