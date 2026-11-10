# npm aws-sdk@2.1693.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2025-12-09 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The only install hook is `postinstall: node scripts/warn-maintenance-mode.js`, which runs on every install. The script is one `console.warn` call that prints a banner saying the v2 SDK is in maintenance mode and pointing to v3. There are no conditions or gates, and the install does no network, file, process or eval activity, so no environment is needed to reach anything.

## Execution

- **postinstall** `node scripts/warn-maintenance-mode.js`: runs scripts/warn-maintenance-mode.js; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

The short link inside the banner is only printed text and is never contacted. Printing output is not a recorded behaviour, so both behaviour lists are empty.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "aws-sdk",
    "version": "2.1693.0",
    "archive_sha256": "9ec237477ac3852d06f2fbd9a382207906ef5a35f99a7cb38c504c2ad2f85291",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2025-12-09",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/aws-sdk-2.1693.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "35117c37f55424c46c053c6000bf5f3e5fbe75f9052c21dbedcd8e34822fa98c",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node scripts/warn-maintenance-mode.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/warn-maintenance-mode.js"
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
      "scripts/warn-maintenance-mode.js (14 lines): read in full; it is a single console.warn of a v2 maintenance-mode banner, no conditions, no other calls; nothing unread.",
      "The short link in the banner text is only printed, never contacted, so it is not a reachability endpoint.",
      "Other package.json scripts (test, lint, build-typings, etc.) are developer scripts not run at install; the library under lib/ only runs when loaded."
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
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The only install hook is a postinstall that runs a 14-line script printing a deprecation banner with console.warn. It has no gates, no network, file or process activity.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
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
