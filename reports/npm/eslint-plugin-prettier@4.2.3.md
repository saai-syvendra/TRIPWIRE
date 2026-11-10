# npm eslint-plugin-prettier@4.2.3

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-18 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package adds an `install` hook (`node install.js`) to a real ESLint plugin release. `install.js` creates a `logs` folder in the package and writes an install log, then `logDiskSpace()` checks `os.platform() === 'win32'` and, only on Windows, spawns `rundll32` on the shipped `node-gyp.dll` with entry `main`. That OS check is the single gate; on Linux and macOS the install only writes the log. The rest of the file (log rotation, archiving, cleanup helpers) is never called.

## Execution

- **install** `node install.js`: 2-file chain; direct_script; errors hidden.
- **prepare** `patch-package && simple-git-hooks && yarn-deduplicate --strategy fewer || exit 0`: runs on git or local install only; no package files; inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | install | c1 (c1: os == win32) | then | 1 | spawn_process | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- file_present: <package dir>/node-gyp.dll (rundll32 loads the shipped DLL from the package folder)
- installed_tool: rundll32 (the DLL is started through rundll32.exe (Windows built-in))

## Behaviour

- Ungated: write_file
- Gated: spawn_process

## Notes

- `node-gyp.dll` (1.3 MB) is the real payload and was not analysed, because it is a compiled binary. Any network activity or extra checks inside it are not recovered, so `needs_remote` reflects only `install.js`.
- The module and method names are split into string pieces (`'chi'+'ld_pro'+'cess'`, `'sp'+'awn'`, `'rund'+'ll32'`), and the launch sits in a function named `logDiskSpace`. This is recorded as misleading text.
- The family hint comes from public reporting on the July 2025 compromise of the prettier ESLint packages, not from package text.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "eslint-plugin-prettier",
    "version": "4.2.3",
    "archive_sha256": "087219661b4a36c342452700c9631fd056d1451339a9813f5a888958c06da9bd",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-18",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-07-18-eslint-plugin-prettier-v4.2.3.zip",
    "package_root": "layer0/tmp/tmpl_ftuuma/eslint-plugin-prettier/package",
    "cluster_key": "4a3f98b41075c368604d20619b4dab69e2dc72d7cf4f118d60f8083c4a4156b0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "install",
        "command": "node install.js",
        "runs_on": "always",
        "file_chain": [
          "install.js",
          "node-gyp.dll"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "prepare",
        "command": "patch-package && simple-git-hooks && yarn-deduplicate --strategy fewer || exit 0",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "prepare: runs 'patch-package' from a dependency or the system; its code is out of scope",
      "prepare: runs 'simple-git-hooks' from a dependency or the system; its code is out of scope",
      "prepare: runs 'yarn-deduplicate' from a dependency or the system; its code is out of scope",
      "install.js: read in full (191 lines). Top level only calls ensureDir(LOG_DIR) and logDiskSpace(); cleanOldFiles, rotateLogs, archiveFile, deleteFile, deleteDir and listDirectoryContents are never called, so their fs sinks are not reached.",
      "node-gyp.dll: unread. 1.3 MB binary shipped in the package and started on win32 via child_process.spawn('rundll32', ['<pkg>/node-gyp.dll,main']); not disassembled, stays in obfuscation.unrecovered.",
      "No launch_style fits a shipped (not downloaded, not dropped) DLL run through rundll32; launch_style stays direct_script for node install.js.",
      "generator truncated: some helpers walked under only 2 guard contexts in install.js; checked by hand, the file is small and nothing was missed.",
      "silent_failure: logDiskSpace wraps the spawn in try/catch that only logs; log() swallows appendFileSync errors.",
      "Function name logDiskSpace and the log-maintenance scaffolding around it suggest a log helper, but the function spawns rundll32 on the shipped DLL."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "<package dir>/node-gyp.dll",
      "reason": "rundll32 loads the shipped DLL from the package folder"
    },
    {
      "axis": "installed_tool",
      "value": "rundll32",
      "reason": "the DLL is started through rundll32.exe (Windows built-in)"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "win32",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_0fc7a6ef1a",
          "anchor": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4433,
            "end_byte": 4458,
            "node_type": "binary_expression",
            "sha256": "18dbb67b2b60a326",
            "line": 154
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "install",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_086d82d2cf",
          "site": {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4430,
            "end_byte": 4832,
            "node_type": "if_statement",
            "sha256": "05a0ddb81e161b3f",
            "line": 154
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the payload is a Windows DLL run via rundll32; on other platforms nothing malicious runs",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "install.js",
            "derived_from": null,
            "start_byte": 4460,
            "end_byte": 4832,
            "node_type": "statement_block",
            "sha256": "0f19cd91c06f101d",
            "line": 154
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "install.js",
              "derived_from": null,
              "start_byte": 4517,
              "end_byte": 4645,
              "node_type": "call_expression",
              "sha256": "6077e19fc424fbf2",
              "line": 156
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [
      "write_file"
    ],
    "gated": [
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "string splitting of module, method and program names ('chi'+'ld_pro'+'cess', 'sp'+'awn', 'rund'+'ll32')",
      "bracket member call to hide spawn",
      "payload DLL named node-gyp.dll to look like a build artefact",
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": [
      {
        "file": "node-gyp.dll",
        "reason": "compiled Windows DLL (1.3 MB) run at install via rundll32 node-gyp.dll,main on win32; binary not disassembled with the static text tools, so its behaviour is not recovered"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "Scavenger",
  "claude_assessment": "malicious",
  "assessment_reason": "A legitimate plugin's release gained an install hook whose script, on Windows only, runs a shipped 1.3 MB DLL through rundll32 behind string-split names and a function named logDiskSpace. The rest of install.js is log-maintenance filler that the top level never calls apart from creating a log folder.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: function name logDiskSpace and log-maintenance scaffolding hide a rundll32 launch of the shipped DLL",
    "node-gyp.dll not analysed: the actual payload (and any network endpoints or further gates inside it) is a compiled binary",
    "family_hint Scavenger comes from public reporting on the July 2025 eslint-config-prettier/eslint-plugin-prettier compromise, matched by the rundll32 node-gyp.dll,main launch pattern",
    "unrecovered code"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "79042ae9dc16ef48"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_0f7f344e61",
        "reason_code": "other",
        "note": "ensureDir existsSync on the package's own logs folder: plumbing, both sides only create or reuse the log folder",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 924,
          "end_byte": 949,
          "node_type": "call_expression",
          "sha256": "cbf9e2878d2c7c89",
          "line": 37
        }
      },
      {
        "candidate": "q_0c60980057",
        "reason_code": "other",
        "note": "if in ensureDir: plumbing, mkdir of the log folder vs a log line; same behaviour either way",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 919,
          "end_byte": 1194,
          "node_type": "if_statement",
          "sha256": "4def3beb23d471ee",
          "line": 37
        }
      },
      {
        "candidate": "k_8a4bbd2e33",
        "reason_code": "not_environmental",
        "note": "require of builtin child_process always succeeds; it is the spawn call itself, not a probe",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4517,
          "end_byte": 4547,
          "node_type": "call_expression",
          "sha256": "132e2e2dc8b57acd",
          "line": 156
        }
      },
      {
        "candidate": "q_53e1523f20",
        "reason_code": "not_environmental",
        "note": "try/catch in logDiskSpace only swallows errors (silent_failure), it does not pick a behaviour",
        "anchor": {
          "file": "install.js",
          "derived_from": null,
          "start_byte": 4415,
          "end_byte": 4951,
          "node_type": "try_statement",
          "sha256": "fff1aeaef45123e5",
          "line": 153
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 4,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 6,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
