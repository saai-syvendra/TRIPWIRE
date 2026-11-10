# npm google-cloud-secret-manager-config-poc@99.9.9

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-03 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. index.js runs one shell command line that prints hostname, username and internal IPs and queries the GCP metadata server for the default service-account email and project id. The exec callback POSTs stdout and stderr as JSON to a webhook[.]site URL. There are no gates: the only branch is a shell `|| echo` that changes the collected text when the metadata request fails, and the POST runs either way.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (collected output is POSTed to the webhook; without it the data is not exfiltrated)
- network: metadata[.]google[.]internal:80 (service-account email and project id are only collected when the GCP metadata server answers; the POST runs either way)
- installed_tool: sh, curl, hostname, whoami (the exec command line uses these; the chain stops early when one is missing, but the POST still runs)
- os: linux (hostname -I and the POSIX shell syntax assume Linux; on Windows the commands mostly fail but the POST still sends stderr)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Name, version 99.9.9 and manifest description point to a dependency confusion probe aimed at an internal Google Cloud package name. The behaviour is unconditional recon plus exfil, so any VM with outbound HTTPS triggers it; GCP metadata reachability only adds data.
- The prefilled `dynamic_eval` signal was removed: there is no eval, only `child_process.exec` of a literal string.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "google-cloud-secret-manager-config-poc",
    "version": "99.9.9",
    "archive_sha256": "c2bee4419860713efc680b80b47a79f69c3cfd0eea1f9ce641b68e49c3b13603",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-03",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-05-03-google-cloud-secret-manager-config-poc-v99.9.9.zip",
    "package_root": "layer0/tmp/tmp1lx5zpcz/google-cloud-secret-manager-config-poc/package",
    "cluster_key": "8c07ecefb7ec01a7da4963e3a6c0e477533de31093e0150f0ec44e1957353ada",
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
      "index.js (22 lines) read in full. It runs one shell command line via child_process.exec (hostname, whoami, two GCP metadata curls, hostname -I) and POSTs stdout and stderr to a webhook in the exec callback.",
      "The '|| echo \"Not inside Google Cloud\"' after the metadata curl only changes the collected text; the POST runs on both sides, so it is not a gate. The exec callback ignores err, so command failures are hidden (silent_failure).",
      "The metadata.google.internal requests are recon sources, not C2 or exfil sinks, so they are listed as requirements rather than endpoints. The tool's dynamic_eval signal does not match any eval in the code: it is a plain exec of a literal command."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "collected output is POSTed to the webhook; without it the data is not exfiltrated"
    },
    {
      "axis": "network",
      "value": "metadata[.]google[.]internal:80",
      "reason": "service-account email and project id are only collected when the GCP metadata server answers; the POST runs either way"
    },
    {
      "axis": "installed_tool",
      "value": "sh, curl, hostname, whoami",
      "reason": "the exec command line uses these; the chain stops early when one is missing, but the POST still runs"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "hostname -I and the POSIX shell syntax assume Linux; on Windows the commands mostly fail but the POST still sends stderr"
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
        "indicator": "hxxps://webhook[.]site/11b6…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dependency confusion recon PoC",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs unconditionally, collects hostname, username, internal IPs and GCP metadata (service-account email, project id) and POSTs them to a third-party webhook. Even if meant as a bug-bounty probe, it exfiltrates host data from whoever installs it.",
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
