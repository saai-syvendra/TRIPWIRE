# npm fiddlesticks@9.9.9

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-25 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`. On the first run the script respawns itself as a detached `node` child with a `--background` argument and stdio ignored, then returns so the install carries on. The child opens a TCP connection to 134.209.149[.]207:4444 and pipes `/bin/sh` stdin, stdout and stderr over it, giving a reverse shell. There are no environment gates: the only branch is the script's own `--background` re-entry check, so the shell opens on any install with outbound access to that host and a `/bin/sh` (Linux or macOS).

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script, detached_child; errors hidden.

## Gates

None.

## Requirements

- network: 134[.]209[.]149[.]207:4444 (reverse shell connects out to this host and port; without it the child exits)
- file_present: /bin/sh (shell spawned and piped over the socket)
- installed_tool: node (the detached child is started as spawn('node', ...) and needs node on PATH)

## Behaviour

- Ungated: spawn_process, reverse_shell
- Gated: none

## Notes

- The `--background` argv check is a re-entry guard set by the payload for its own child, not a gate.
- The child does not reconnect: on socket error or close it exits.
- `dependency_confusion` is inferred only from the 9.9.9 version and empty metadata.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "fiddlesticks",
    "version": "9.9.9",
    "archive_sha256": "9e425f7a2b50a91ab7ed733442a85010c97e2c7d119f3c517d2d5a04fff98805",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-25",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-25-fiddlesticks-v9.9.9.zip",
    "package_root": "layer0/tmp/tmpsiwac2ry/fiddlesticks/package",
    "cluster_key": "33cb4b63343ccaff3f79e865e6caee8977396f9eed611d02d6c09c6b14080bff",
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
          "direct_script",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js: package code read in full (56 lines, plain JS); nothing bundled, nothing unread.",
      "The process.argv check for --background is a re-entry guard: the preinstall run respawns itself as a detached node child with that argument, and only the child opens the shell. Not a gate.",
      "The child runs with stdio ignored and its socket error handler only destroys the socket, so connection failures are invisible to the install (silent_failure).",
      "attack_type dependency_confusion rests only on the 9.9.9 version with empty metadata; no recon or callback beacon supports it further."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "134[.]209[.]149[.]207:4444",
      "reason": "reverse shell connects out to this host and port; without it the child exits"
    },
    {
      "axis": "file_present",
      "value": "/bin/sh",
      "reason": "shell spawned and piped over the socket"
    },
    {
      "axis": "installed_tool",
      "value": "node",
      "reason": "the detached child is started as spawn('node', ...) and needs node on PATH"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "spawn_process",
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
        "indicator": "134[.]209[.]149[.]207",
        "role": "reverse_shell"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which respawns itself as a detached node process that connects to a hardcoded IP on port 4444 and pipes /bin/sh over the socket. There are no environment gates: it runs on every install where /bin/sh exists and the host is reachable.",
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
