# npm moodle-core_filepicker@1.2.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-03 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package runs `node index.js` as a preinstall hook. index.js is meant to gather host recon (package path, home directory, hostname, username, DNS servers, package.json) and POST it to an oastify[.]com interaction host, a typical dependency-confusion probe on a Moodle module name. There are no gates: the code has no environment checks. In practice nothing runs, because line 6 (`packageJSON.moodle-core_filepicker`) is parsed as a subtraction and the undeclared identifier `core_filepicker` throws a ReferenceError, killing the script before the recon and the request.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- Behaviours are left empty because the exfil is unreachable in every environment. A fixed re-upload of the same script would be ungated recon plus exfil to an oastify[.]com host on port 443.
- The package declares itself as a dependency.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "moodle-core_filepicker",
    "version": "1.2.0",
    "archive_sha256": "9108aab7c81430a7f2bae2be7ede4a5ee8892d9a129201d810d846bc3d7dc1ec",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-03",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-09-03-moodle-core_filepicker-v1.2.0.zip",
    "package_root": "layer0/tmp/tmp7vsg_xze/moodle-core_filepicker/package",
    "cluster_key": "a28388931306d8387dea6209a411feb1ad3b5d8ccf81761461aaf29b23964cb2",
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
      "index.js: package code read in full (46 lines); no bundled code, nothing unread.",
      "index.js line 6 `packageJSON.moodle-core_filepicker` parses as a subtraction; resolving the undeclared identifier core_filepicker throws ReferenceError, so the preinstall script dies there and the install fails.",
      "Everything after line 6 (recon of homedir, hostname, username, DNS servers, package path and package.json, then an HTTPS POST to an oastify[.]com interaction host) never runs at install, so behaviours are empty.",
      "No environment checks exist in the code; the ReferenceError is not a gate since it fails in every environment.",
      "package.json lists the package itself (moodle-core_filepicker ^1.2.0) as a dependency."
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
  "family_hint": "oastify dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall script is written to collect host recon (home dir, hostname, username, DNS servers, package path) and POST it to an oastify[.]com interaction host, a dependency-confusion probe on a Moodle module name. A coding error on line 6 throws a ReferenceError before any of it runs, so in practice the install only fails.",
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
