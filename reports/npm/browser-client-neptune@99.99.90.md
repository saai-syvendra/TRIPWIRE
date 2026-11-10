# npm browser-client-neptune@99.99.90

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-28 (registry) · **Assessment:** suspicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node preinstall.js` on every registry install. The script builds a JSON body with the machine hostname, the package name and a timestamp and POSTs it over HTTPS to an OAST (interactsh-style) host. There are no gates: no platform, env, CI or file checks, so any environment with outbound HTTPS to that host triggers it. The 99.99.90 version and internal-looking name point to a dependency confusion probe.

## Execution

- **preinstall** `node preinstall.js`: runs preinstall.js; direct_script.

## Gates

None.

## Requirements

- network: kybfvljgcdgoehzjagwy1vu5s1oq92qae[.]oast[.]fun:443 (hostname beacon is POSTed over HTTPS to this OAST host)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Strings and the package description call it a bug bounty dependency confusion PoC and print "No malicious action performed". That attribution comes from text only. The code does what it looks like: ungated recon plus exfil of the hostname, nothing more.
- There is no request error handler, so the hook throws if the host can't be reached.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "browser-client-neptune",
    "version": "99.99.90",
    "archive_sha256": "c08a7026c483af42dd938cb3ab729c71200d53e5f587185d54edaed6f6caf25f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-28",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-11-28-browser-client-neptune-v99.99.90.zip",
    "package_root": "layer0/tmp/tmprlmqrqz9/browser-client-neptune/package",
    "cluster_key": "9866fb42b03175fa7b0399f93bf7011f55161f21d60939e6c2749c6b58b45c17",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node preinstall.js",
        "runs_on": "always",
        "file_chain": [
          "preinstall.js"
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
      "preinstall.js: read in full (25 lines, plain JS). No conditions, branches, try/catch or delays; the POST runs on every install.",
      "Request errors are not handled (no 'error' listener), so a failed connection raises in the hook rather than being swallowed; silent_failure stays false.",
      "Console output claims a bug bounty security test with no malicious action; the code still sends the host's hostname to an external OAST host. The researcher attribution comes only from these strings and package.json description/author; no gate, behaviour or assessment field depends on it."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "kybfvljgcdgoehzjagwy1vu5s1oq92qae[.]oast[.]fun:443",
      "reason": "hostname beacon is POSTed over HTTPS to this OAST host",
      "sites": [
        {
          "file": "preinstall.js",
          "derived_from": null,
          "start_byte": 457,
          "end_byte": 479,
          "node_type": "call_expression",
          "sha256": "341317865cbcd4f8",
          "line": 20
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
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://kybfvljgcdgoehzjagwy1vu5s1oq92qae[.]oast[.]fun/orange-dependency-confusion",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dependency confusion OAST hostname beacon",
  "claude_assessment": "suspicious",
  "assessment_reason": "The preinstall hook unconditionally POSTs the machine hostname and a timestamp to an interactsh-style OAST host from a 99.99.90 version, a classic dependency confusion beacon. It collects only the hostname and runs nothing else, consistent with a researcher PoC per its strings, but it is still unsolicited data exfiltration from installers.",
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
