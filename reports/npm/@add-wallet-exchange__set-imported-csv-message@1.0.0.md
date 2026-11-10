# npm @add-wallet-exchange/set-imported-csv-message@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-02 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`, a 58-line script with no gates. It first sends an HTTP GET to an internal-looking host, hxxp://4a-admin[.]crypto[.]com/. Whether that request succeeds or fails, it then sends OS type and release, the install directory and the hostname to an OAST callback host (fycgdvjhjghrglljahci6bvckhfffk19x[.]oast[.]fun) in an HTTPS GET query string, along with the probe's status code or `error`. Any install environment with outbound HTTPS triggers it.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: fycgdvjhjghrglljahci6bvckhfffk19x[.]oast[.]fun:443 (OAST callback host that receives OS, cwd and hostname over HTTPS GET)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The scoped name and the internal host probe point to a dependency-confusion recon beacon aimed at one organisation's internal namespace. The probe result only changes what the beacon reports, not whether it is sent.
- The internal probe host is left out of `reachability.endpoints` because no endpoint role fits a recon probe target. It is listed in the execution notes.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@add-wallet-exchange/set-imported-csv-message",
    "version": "1.0.0",
    "archive_sha256": "d988b68a9020a1ee66cbbd1aac3671edb006e7638e3ca58a4feb6d32528a012d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-02",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-03-@add-wallet-exchange_set-imported-csv-message-v1.0.0.zip",
    "package_root": "layer0/tmp/tmp9cn5v8e6/@add-wallet-exchange-set-imported-csv-message/package",
    "cluster_key": "c60d093203d6790bb9da0622f2c136f866956fabe0e7ff2e13d4a9f120c66ba6",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
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
      "index.js: package code read in full (58 lines), no bundled or third-party code; nothing unread.",
      "makeSecondRequest probes an internal-looking host (hxxp://4a-admin[.]crypto[.]com/) and passes its HTTP status, or 'error' on failure, to makeFirstRequest. Both paths call makeFirstRequest, so the beacon runs either way; not a gate.",
      "The ternary on status in makeFirstRequest only adds the &4= parameter to the URL; same behaviour and same host on both sides, so it is data collection, not a gate.",
      "The internal probe host is left out of reachability.endpoints because none of the endpoint roles fits a recon probe target; it is not required for the exfil to run.",
      "Request errors are caught and logged with console.error, not hidden, so silent_failure stays false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "fycgdvjhjghrglljahci6bvckhfffk19x[.]oast[.]fun:443",
      "reason": "OAST callback host that receives OS, cwd and hostname over HTTPS GET"
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
        "indicator": "hxxps://fycgdvjhjghrglljahci6bvckhfffk19x[.]oast[.]fun/?1=$",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script runs unconditionally, probes an internal-looking corporate host, then sends OS type and release, the install directory and the hostname to an OAST callback domain. This is a dependency-confusion recon beacon with no gate.",
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
