# npm vant@2.13.4

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-19 (registry) · **Assessment:** suspicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

This copy of vant 2.13.4 declares a `postinstall` hook `node lib/utils/support.js`, but that file is not in the archive. On install node would fail with module not found, so no package code runs and no gates or behaviours can be recorded. The rest of the package is a compiled Vant UI component build that only runs when loaded, and a sink search over it found nothing install-related.

## Execution

- **postinstall** `node lib/utils/support.js`: no package files; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- The postinstall hook is not part of the upstream project's scripts (the other scripts are the normal dev and release ones), which fits a compromised publish. The payload in `lib/utils/support.js` was not captured in this sample, so a reviewer should look for another archive of this version that includes it.
- The manifest lists `es` in `files` and `module: es/index.mjs`, but there is no `es/` folder, and the dependencies keep unresolved `workspace:` specs. That points to a publish outside the project's normal release flow.
- Attack type `compromised_maintainer` rests on the manifest (real project name and repository, an added hook), not on recovered payload code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "vant",
    "version": "2.13.4",
    "archive_sha256": "6b4c5bd1abbb6f889c26cfe7b2baae2b322946a2cdbbf5a71bdf9d77a14f4b2f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2024-12-20-vant-v2.13.4.zip",
    "package_root": "layer0/tmp/tmpq33p7tqn/vant/package",
    "cluster_key": "f4d03491757c4d682c2493005a6c30e2196cc263c31c5828981fb981bfd7297a",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node lib/utils/support.js",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "postinstall: 'lib/utils/support.js' is not a file in the package",
      "The hook target is absent from the archive, so node fails with module not found and the install errors out; no package code runs at install.",
      "lib/: compiled Vant UI component build (cjs, es, umd, per-component files), loaded only on require; audited by sink grep (no child_process, fs, net, eval); not install-reached.",
      "package.json declares 'es' in files and module es/index.mjs, but no es/ folder is in the archive; dependencies use unresolved workspace: specs."
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
    "unrecovered": [
      {
        "file": "lib/utils/support.js",
        "reason": "postinstall target not present in the archive; the install-time payload, if any, was not captured"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "compromised_maintainer",
  "family_hint": null,
  "claude_assessment": "suspicious",
  "assessment_reason": "A postinstall hook added to a legitimate UI library runs lib/utils/support.js, which is missing from the archive, so no install code can be read and the install would fail. The shipped library code is a normal Vant build with no install-time behaviour.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "postinstall target lib/utils/support.js missing from the sample; payload not captured, so gates and behaviours could not be analysed",
    "unrecovered code"
  ],
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
