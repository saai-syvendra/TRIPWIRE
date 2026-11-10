# npm com.meta.utilities@99.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-05-31 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script runs `uname -a` and collects the package name and version, hostname, username, home directory, arch, platform, DNS servers and a timestamp. It sends them in the query string of an HTTPS GET to an oastify[.]com OAST host, and also leaks the hostname by resolving `npm-<hostname>.<OAST host>`. There are no gates: everything runs unconditionally. The only branch is a try/catch that sets uname to "N/A" if the command fails.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: slhw1ueu9vvpwm9epauijp7thknbb6zv[.]oastify[.]com:443 (HTTPS GET carrying the collected host data in the query string)
- other: DNS resolution of subdomains under the OAST domain (dns.lookup of npm-<hostname>.<OAST domain> leaks the hostname through DNS)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Version 99.0.0 on an internal-looking name points to a dependency-confusion probe. A comment and the package description claim this is white-hat research. That is a claim about intent, not about what the code does, so it is not recorded as misleading text.
- All network errors are swallowed, so the install always succeeds.
- The family hint describes the technique, not the claimed author. The researcher domain in the comment is left out.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "com.meta.utilities",
    "version": "99.0.0",
    "archive_sha256": "58911b5d5646b17538de8bd1875c3b38761b8eb9736131bd1587d83b58cb723a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-05-31",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-05-31-com.meta.utilities-v99.0.0.zip",
    "package_root": "layer0/tmp/tmpuho16e1u/com.meta.utilities/package",
    "cluster_key": "f7e8894032042bc9ec26eac4e5ea8249ea03b5344e1830f2539bec5964ad7b6f",
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
      "index.js (60 lines, package code) read in full; nothing bundled or unread.",
      "The try/catch around execSync('uname -a') only sets the uname field to 'N/A' on failure; the beacon runs either way, so it is data collection, not a gate.",
      "HTTPS GET and DNS lookup errors are swallowed with empty handlers and empty catch blocks, so the install never fails."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "slhw1ueu9vvpwm9epauijp7thknbb6zv[.]oastify[.]com:443",
      "reason": "HTTPS GET carrying the collected host data in the query string"
    },
    {
      "axis": "other",
      "value": "DNS resolution of subdomains under the OAST domain",
      "reason": "dns.lookup of npm-<hostname>.<OAST domain> leaks the hostname through DNS"
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
        "indicator": "hxxps://slhw1ueu9vvpwm9epauijp7thknbb6zv[.]oastify[.]com/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify dependency-confusion beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs uname -a and collects hostname, username, home directory, platform, arch and DNS servers, then sends them unconditionally to an OAST (oastify) domain via HTTPS GET and a DNS lookup. Version 99.0.0 on an internal-looking name fits a dependency-confusion probe; the research claim in a comment and description does not change what the code does.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "c09bd988acb6a8cd"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_c8c37a7229",
        "reason_code": "not_environmental",
        "note": "execSync('uname -a') only collects data; on failure the field becomes 'N/A' and the same exfil runs.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 367,
          "end_byte": 387,
          "node_type": "call_expression",
          "sha256": "3e853a8a4e2ded28",
          "line": 15
        }
      },
      {
        "candidate": "q_65eaba9809",
        "reason_code": "not_environmental",
        "note": "try/catch around the uname collection; both sides lead to the same unconditional beacon.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 351,
          "end_byte": 439,
          "node_type": "try_statement",
          "sha256": "9f54f622c9e92b38",
          "line": 14
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
