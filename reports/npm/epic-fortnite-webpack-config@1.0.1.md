# npm epic-fortnite-webpack-config@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-31 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package's postinstall hook runs `node index.js`. The script is meant to gather host details (hostname, username, platform, network interfaces, the full process.env, /etc/hosts and /etc/resolv.conf) and POST them as JSON to a webhook[.]site collector. Line 34, however, has a template literal with no backticks, so the file is a SyntaxError: node aborts before running anything and the install fails. There are no gates. Even if the file parsed, the only check (existsSync before reading the /etc files) just decides whether a data field is filled, and the beacon would run in any environment.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- The tool's candidate gate g1 (existsSync and try in readFullFile) is dropped: it is unreachable because of the parse error, and it is data-collection plumbing anyway.
- The endpoint is left out of reachability because nothing is contacted at install. The intended target is hxxps://webhook[.]site/3630… (path id redacted).
- The name looks like an internal company package and the code is a typical dependency-confusion recon beacon, so attack_type is dependency_confusion. The manifest keywords say the same, but the label rests on the name and the code, not on that text.
- Assessment is malicious by intent, confidence medium, because the install code does nothing as shipped. Flagged for review.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "epic-fortnite-webpack-config",
    "version": "1.0.1",
    "archive_sha256": "cc2561be826500fab782a4795b3c01a1bab8899009a89ffae05d29d68bf2dfbe",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-31",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-31-epic-fortnite-webpack-config-v1.0.1.zip",
    "package_root": "layer0/tmp/tmpfc88vdhn/epic-fortnite-webpack-config/package",
    "cluster_key": "31df18bfa30ad87c1176e00fbb0fb024c2cad88c786894f21c633f6d7c7c8264",
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
      "index.js: read in full (64 lines, package code). Line 34 is a template literal written without backticks (return Error reading ${filePath}: ...), so the file is a JavaScript SyntaxError and node aborts before running any statement.",
      "Because of the parse error the postinstall exits non-zero and the install fails; none of the recon collection (hostname, user, env, /etc/hosts, /etc/resolv.conf) or the HTTPS POST to webhook[.]site runs.",
      "Intended behaviour if it parsed: collect host info and the full process.env, then POST it as JSON to hxxps://webhook[.]site/3630… (path id redacted), request errors swallowed. No environment check decides whether it runs.",
      "The existsSync test in readFullFile only decides whether a field of the collected object is filled; the POST runs either way, so it would be data-collection plumbing, not a gate."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script is written to send host details and the full environment (including any secrets) to a webhook[.]site collector, a dependency-confusion style beacon on an internal-looking name. As shipped it contains a syntax error, so at install it fails to parse and nothing executes.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "index.js does not parse (template literal without backticks on line 34), so the record lists no install-time behaviour; reviewer should confirm that malicious intent with an inert install outcome is labelled as wanted."
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "124664842fe0ab75"
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
        "candidate": "k_ed9672957f",
        "reason_code": "other",
        "note": "index.js is a SyntaxError (line 34), so readFullFile never runs; even if it did, the exists check only fills a field of the exfil object and the POST runs on both sides.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 656,
          "end_byte": 689,
          "node_type": "call_expression",
          "sha256": "81bf546f160052e2",
          "line": 31
        }
      },
      {
        "candidate": "k_f7fbe729cb",
        "reason_code": "other",
        "note": "Same existsSync check as k_ed9672957f; the file does not parse, and the check only fills a data field, not a behaviour choice.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 616,
          "end_byte": 639,
          "node_type": "call_expression",
          "sha256": "8aebf40d46a4dd4e",
          "line": 30
        }
      },
      {
        "candidate": "q_9d81308a83",
        "reason_code": "other",
        "note": "try around existsSync/readFileSync in readFullFile; never runs (SyntaxError) and only changes a collected field value, not which behaviour runs.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 602,
          "end_byte": 751,
          "node_type": "try_statement",
          "sha256": "51a21916bdeaf79d",
          "line": 29
        }
      },
      {
        "candidate": "q_28fb90300b",
        "reason_code": "other",
        "note": "if (fs.existsSync(filePath)) in readFullFile; never runs (SyntaxError) and only changes a collected field value, not which behaviour runs.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 612,
          "end_byte": 696,
          "node_type": "if_statement",
          "sha256": "3bb47653748c967d",
          "line": 30
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 4,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 2,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
