# npm @automagik/genie@4.260421.37

**Source:** datadog · **Source label:** malicious · **Released:** 2026-04-21 (registry) · **Assessment:** suspicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package declares a postinstall hook `node src/env-compat.cjs || true`, added by a self-propagating npm worm to this compromised release. The file it names is not in the tarball (the `files` list only ships `src/db/migrations/` under `src/`), so node exits with a module-not-found error, `|| true` swallows it, and no package code runs at install. There are no gates and no install-time behaviours. The worm payload itself ships at `dist/env-compat.cjs` but nothing install-time references it.

## Execution

- **postinstall** `node src/env-compat.cjs || true`: no package files; direct_script; errors hidden.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- `dist/env-compat.cjs` is a credential stealer and worm (Chrome password decryption, npm token use, downloading other packages' tarballs and republishing them with an injected `env-compat.cjs` postinstall). It was not analysed for gates because the install never reaches it; it has a `_PKG_INIT` re-entry guard and env-var driven settings at the top.
- The worm's injection picks the first of `lib`, `src`, `dist` present in `files` as the payload folder. For this package it chose `src` because of `src/db/migrations/`, which is why the hook and the shipped file disagree.
- A dynamic scanner installing this version will see no install-time activity; a sibling release with a working hook would need its own record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@automagik/genie",
    "version": "4.260421.37",
    "archive_sha256": "d6a07ad61c128a608422c30a2f818c18ffff850ef60e477f0f62f468253b7979",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-04-21",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-04-21-@automagik_genie-v4.260421.37.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpt7qzfnqe/@automagik-genie/package",
    "cluster_key": "69e9b39a5c67ed88cf46ad533361b5f3b9ad15ca71af7d08a7452deb746cfefa",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node src/env-compat.cjs || true",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "postinstall: 'src/env-compat.cjs' is not a file in the package",
      "bin commands not analysed (run only when invoked): genie",
      "The hook target is absent from the tarball (package.json files only ships src/db/migrations/ under src/), so node fails with module not found, || true hides it, and no package code runs at install.",
      "dist/env-compat.cjs holds a credential stealer and npm worm (browser password decryption, token theft, republishing packages with an env-compat.cjs postinstall). No hook, bin or other file references it, so it is not install-reached.",
      "The worm's own injection logic picks the first of lib, src, dist present in files and writes <dir>/env-compat.cjs; here it chose src, which the files list does not ship, which explains the broken hook."
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
  "attack_type": "compromised_maintainer",
  "family_hint": "env-compat npm worm",
  "claude_assessment": "suspicious",
  "assessment_reason": "The postinstall hook was injected to run a credential-stealing npm worm, but it points at src/env-compat.cjs, which is not in the published tarball, so nothing runs at install. The worm file is shipped at dist/env-compat.cjs but nothing install-time reaches it.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Malicious hook is broken in this version: the payload ships at dist/env-compat.cjs but the postinstall runs the missing src/env-compat.cjs, so a dynamic scanner sees no install-time behaviour."
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
