# npm es5-ext@0.10.64

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-02-27 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node -e` to require `_postinstall.js` inside a try/catch, and ends with `|| exit 0`, so failures are hidden. The script checks whether `Intl.DateTimeFormat().resolvedOptions().timeZone` is one of a list of Russian timezones and returns early if it is not. When it is, the script only prints a Russian-language anti-war message (with a link to a torproject forum page) through `process._rawDebug`. There are no gates, because the timezone check only decides whether text is printed, and there are no install-time behaviours.

## Execution

- **postinstall** ` node -e "try{require('./_postinstall')}catch(e){}" || exit 0`: runs _postinstall.js; inline_eval; errors hidden.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- I treated the timezone check as log-only rather than a gate. Phase 2 may still want to know that a Russian timezone (for example `Europe/Moscow`) is the only way to see the message.
- `attack_type` is `protestware` because the check targets Russian locales, but the assessment is benign: nothing is fetched, written or run.
- The comment at the top of the file ("Call for peace" message, otherwise no-op) matches what the code does.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "es5-ext",
    "version": "0.10.64",
    "archive_sha256": "e8e64fee8cd0ccc432438b38dd8bfdb18b794fe811badcb045f3da633299349f",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-02-27",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/es5-ext-0.10.64.tgz",
    "package_root": "layer0/package",
    "cluster_key": "168a0e8d522c0693171509906982b3d50c736295d618ccb1fd84b0bac5682ea3",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": " node -e \"try{require('./_postinstall')}catch(e){}\" || exit 0",
        "runs_on": "always",
        "file_chain": [
          "_postinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "inline_eval"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "_postinstall.js (54 lines) read in full. The hook requires it inside try/catch with || exit 0; the file itself wraps everything in try/catch with an empty handler.",
      "_postinstall.js line 17 compares Intl.DateTimeFormat().resolvedOptions().timeZone against a list of Russian zones and returns early otherwise. The only guarded code prints a Russian-language anti-war message via process._rawDebug, so this is log-only and not a gate.",
      "The torproject forum URL is only part of the printed text; nothing is fetched, written, spawned or sent. Library code under main is not reached at install."
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
  "attack_type": "protestware",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall script only prints an anti-war message to stderr when the system timezone is a Russian zone, and does nothing otherwise. It has no network, file, process or credential activity, so it is protestware in the message-only sense and harmless to the host.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "inline_script",
        "recipe_version": 1,
        "input": {
          "file": "package.json",
          "derived_from": null
        },
        "params": {
          "hook": "postinstall",
          "flag": "-e"
        },
        "output_sha256": "84065703095dd849"
      }
    ],
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
