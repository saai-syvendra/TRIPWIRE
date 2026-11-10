# npm thangved-react-grid@1.0.3

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-14 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is a worm-compromised copy of a small React grid library. The only lifecycle hook npm runs is `prepare` (`run-s build`), which runs only for git or local-folder installs and calls microbundle-crl to build the library. The worm payload `bundle.js` sits behind a `postInstall` script with a capital I. npm only runs the lowercase `postinstall`, so the payload does not run at install. There are no gates and no conditions; the install-time behaviour is a benign build.

## Execution

- **prepare** `run-s build`: runs on git or local install only; no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: run-s (prepare hook calls run-s (npm-run-all devDependency) to run the microbundle-crl build)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- `bundle.js` was not analysed (never reached at install). A grep shows its repack routine setting `scripts.postInstall="node bundle.js"` and re-tarring `package.json`. That matches the Shai-Hulud worm, and the miscased key it writes is why the hook here is dead.
- The source label is malicious and the install-time assessment is benign. The package is still malicious as shipped: running `npm run postInstall` or `node bundle.js` by hand would start the worm.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "thangved-react-grid",
    "version": "1.0.3",
    "archive_sha256": "a3d0dc937545b7b236a7a27f59642d194ebad733bc4b51f35f22762d4d84d892",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-14",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-14-thangved-react-grid-v1.0.3.zip",
    "package_root": "layer0/tmp/tmpb9x7qmm7/thangved-react-grid/package",
    "cluster_key": "07ff45c9dcf6e00182e9e39c6b76210fa7ed6abcfe093271f359560703a6be36",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "prepare",
        "command": "run-s build",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "prepare: runs 'run-s' from a dependency or the system; its code is out of scope",
      "package.json declares 'postInstall' (capital I): node bundle.js. npm only runs the lowercase 'postinstall' lifecycle script, so bundle.js is not run at install.",
      "bundle.js (worm bundle with embedded AWS/GCP SDKs) is never reached at install and was not analysed; grep shows its repack code writing scripts.postInstall='node bundle.js', the source of the dead hook.",
      "main/module (dist/index.js, dist/index.modern.js) only run when the package is loaded; not install-time code."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "run-s",
      "reason": "prepare hook calls run-s (npm-run-all devDependency) to run the microbundle-crl build"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "benign_build"
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
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "Shai-Hulud",
  "claude_assessment": "benign",
  "assessment_reason": "The only install hook that npm runs is prepare (run-s build, git/local installs only), a normal microbundle build. The worm payload bundle.js is wired to a 'postInstall' script that npm never runs because lifecycle names are case-sensitive, so no malicious code executes at install.",
  "label_disagreement": true,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Compromised package with worm payload bundle.js shipped but unreachable at install: hook is 'postInstall' (camel case), which npm does not run. Confirm case-sensitivity assumption for the installer versions Phase 2 uses.",
    "label disagreement"
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
