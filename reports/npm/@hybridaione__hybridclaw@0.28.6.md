# npm @hybridaione/hybridclaw@0.28.6

**Source:** datadog · **Source label:** malicious · **Released:** 2026-08-14 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

On a registry install, npm runs `postinstall`, which starts `scripts/postinstall-container.mjs`. The script checks whether the package root has a `src/` folder (a source checkout). If it does not, and the dependencies listed in `container/package.json` are missing from `container/node_modules`, it runs a nested `npm install --ignore-scripts --omit=dev` for the container folder. In a published tarball there is no `src/` and no `container/node_modules`, so the bootstrap always runs. The `prepare` hook only runs for git or local installs, and only runs `husky` when `git` exists and `.git/config` is writable.

## Execution

- **postinstall** `node ./scripts/postinstall-container.mjs`: runs scripts/postinstall-container.mjs; direct_script.
- **prepare** `command -v git >/dev/null 2>&1 && test -w .git/config && husky || true`: runs on git or local install only; no package files; inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: file_or_dir_exists not_exists <package root>/src) | then | 1 | benign_build | file_absent=<package root>/src |
| g2 | prepare | c2 (c2: file_or_dir_exists other .git/config) | then | 1 | benign_build | file_present=.git/config |

Gate intent: g1 activate/enables/portability; g2 activate/enables/portability

Grounding: 1 of 2 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c2, g1, g2.

## Requirements

- network: registry[.]npmjs[.]org:443 (nested npm install of the container dependencies fetches them from the registry)
- installed_tool: npm (used when npm_execpath is not npm-cli.js (installs by pnpm, yarn or bun))
- installed_tool: git (prepare hook only runs husky when git is on PATH)

## Behaviour

- Ungated: none
- Gated: benign_build

## Notes

- The postinstall script was read in full. It is plain code, nothing is obfuscated, and it contacts no endpoint other than the npm registry through the nested install.
- The checks that `container/package.json` exists, that dependencies are missing, and which `npm_execpath` to use were dropped as plumbing (see candidate_review).
- The source label is malicious, but the install-time code is benign. Runtime code under `dist/` (the `hybridclaw` bin) runs only when invoked and was not reviewed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@hybridaione/hybridclaw",
    "version": "0.28.6",
    "archive_sha256": "e901c69a9dfafbb927ecb60b998dedfca36cb94a66433ba023a8001f9f755307",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-08-14",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-08-14-@hybridaione_hybridclaw-v0.28.6.zip",
    "package_root": "layer0/tmp/tmplmo11ivm/@hybridaione-hybridclaw/package",
    "cluster_key": "62c0a550e49ec123e220d14389d5551c22116bdbfd5739b36af2c08d5bb60e6e",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node ./scripts/postinstall-container.mjs",
        "runs_on": "always",
        "file_chain": [
          "scripts/postinstall-container.mjs"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      },
      {
        "hook": "prepare",
        "command": "command -v git >/dev/null 2>&1 && test -w .git/config && husky || true",
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
      "scripts/postinstall-container.mjs: read in full (201 lines, plain ESM, no bundled code); nothing unread.",
      "postinstall: if the container deps are missing and this is not a source checkout, spawns 'npm --prefix container install --ignore-scripts --omit=dev' (via node + npm_execpath when it is npm-cli.js, else plain npm).",
      "The invokedAsScript check (argv[1] equals the script path) only stops the module body running when imported; under the hook it is always true. Not a gate.",
      "Dropped as plumbing: container/package.json exists (shipped in the tarball), missing-dependency check (skips reinstall when container/node_modules is already populated), npm_execpath test (only picks how npm is launched).",
      "prepare: 'command -v git' is a tool lookup that only aborts the step, recorded as a requirement; 'test -w .git/config' gates husky (git hook setup), a delegated dependency command.",
      "c2: 'test -w' is true only when .git/config exists and the installing user can write it. No operator names writability, so the operator is 'other'; the recipe plants the file.",
      "Runtime code (dist/, bin hybridclaw) runs only when invoked and was not reviewed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "nested npm install of the container dependencies fetches them from the registry"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "used when npm_execpath is not npm-cli.js (installs by pnpm, yarn or bun)"
    },
    {
      "axis": "installed_tool",
      "value": "git",
      "reason": "prepare hook only runs husky when git is on PATH"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "<package root>/src",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_de4053d282",
          "anchor": {
            "file": "scripts/postinstall-container.mjs",
            "derived_from": null,
            "start_byte": 573,
            "end_byte": 617,
            "node_type": "call_expression",
            "sha256": "92adb26bfde128eb",
            "line": 23
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "test -w",
      "operator": "other",
      "value": ".git/config",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "package.json",
            "derived_from": null,
            "start_byte": 5824,
            "end_byte": 5843,
            "node_type": "text",
            "sha256": "0ab9f49614289c51",
            "line": 113
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_9f3e0cd08c",
          "site": {
            "file": "scripts/postinstall-container.mjs",
            "derived_from": null,
            "start_byte": 2192,
            "end_byte": 2357,
            "node_type": "if_statement",
            "sha256": "5683c7a0d204b1ca",
            "line": 73
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "scripts/postinstall-container.mjs",
            "derived_from": null,
            "start_byte": 4732,
            "end_byte": 4765,
            "node_type": "if_statement",
            "sha256": "725e472924f997b0",
            "line": 173
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "adapts to the install layout: skips the container dependency bootstrap in a source checkout (developer setup), runs it in a packaged install",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "file_absent": [
            "<package root>/src"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall-container.mjs",
            "derived_from": null,
            "start_byte": 2361,
            "end_byte": 2726,
            "node_type": "stmt_range",
            "sha256": "c5b72a848339fd57",
            "line": 82
          },
          {
            "file": "scripts/postinstall-container.mjs",
            "derived_from": null,
            "start_byte": 4769,
            "end_byte": 5075,
            "node_type": "stmt_range",
            "sha256": "e7ee2cb768c08672",
            "line": 175
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "exec",
            "sink": {
              "file": "scripts/postinstall-container.mjs",
              "derived_from": null,
              "start_byte": 4500,
              "end_byte": 4595,
              "node_type": "call_expression",
              "sha256": "3259233f030cf9b5",
              "line": 164
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/postinstall-container.mjs",
                  "derived_from": null,
                  "start_byte": 4950,
                  "end_byte": 5005,
                  "node_type": "call_expression",
                  "sha256": "8047e3398b99cf50",
                  "line": 180
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/postinstall-container.mjs",
                  "derived_from": null,
                  "start_byte": 4300,
                  "end_byte": 4598,
                  "node_type": "function_declaration",
                  "sha256": "05e184f15c8b7ff9",
                  "line": 158
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "prepare",
      "expression": "c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "package.json",
            "derived_from": null,
            "start_byte": 5824,
            "end_byte": 5852,
            "node_type": "text",
            "sha256": "41e0fdbf83b431b3",
            "line": 113
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "adapts to the install layout: sets up husky git hooks only inside a writable git checkout, and skips them elsewhere",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "benign_build"
        ],
        "env_recipe": {
          "file_present": [
            ".git/config"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "package.json",
            "derived_from": null,
            "start_byte": 5847,
            "end_byte": 5852,
            "node_type": "text",
            "sha256": "09e28e9c5875ef3b",
            "line": 113
          }
        ],
        "payload": [
          {
            "behaviour": "benign_build",
            "sink_kind": "exec",
            "sink": {
              "file": "package.json",
              "derived_from": null,
              "start_byte": 5847,
              "end_byte": 5852,
              "node_type": "text",
              "sha256": "09e28e9c5875ef3b",
              "line": 113
            },
            "witness": []
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "benign_build"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "unknown",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The only install-time code is a postinstall that runs a nested 'npm install --ignore-scripts --omit=dev' for the package's own container/ dependencies, plus a prepare hook that runs husky in git checkouts. No recon, credential access, exfiltration or remote payload at install.",
  "label_disagreement": true,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Source label is malicious but install-time code is a plain dependency bootstrap; any malicious code would be in runtime files (dist/), which were not reviewed.",
    "label disagreement",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "af48d856650755e2"
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
        "candidate": "k_0216a9a545",
        "reason_code": "not_environmental",
        "note": "container/package.json is shipped in the tarball, so the check always passes on a real install",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 2007,
          "end_byte": 2046,
          "node_type": "call_expression",
          "sha256": "4f360f50fc6702e3",
          "line": 64
        }
      },
      {
        "candidate": "q_a9ebd1fa2c",
        "reason_code": "not_environmental",
        "note": "guard of the container/package.json existence check, file shipped in the tarball",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 2002,
          "end_byte": 2188,
          "node_type": "if_statement",
          "sha256": "47a8f1c2b0845b6a",
          "line": 64
        }
      },
      {
        "candidate": "k_d6c5f47944",
        "reason_code": "not_environmental",
        "note": "same shipped container/package.json, tested again before reading its dependency list",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 757,
          "end_byte": 787,
          "node_type": "call_expression",
          "sha256": "8d6b5b49d010f2ac",
          "line": 28
        }
      },
      {
        "candidate": "q_21315b5903",
        "reason_code": "not_environmental",
        "note": "guard of the repeated container/package.json existence check",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 752,
          "end_byte": 799,
          "node_type": "if_statement",
          "sha256": "272a8358eb18f017",
          "line": 28
        }
      },
      {
        "candidate": "k_44aa320d56",
        "reason_code": "other",
        "note": "plumbing: skips the nested npm install when container/node_modules already holds each dependency (reuse of an existing copy)",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 1708,
          "end_byte": 1738,
          "node_type": "call_expression",
          "sha256": "8d6b5b49d010f2ac",
          "line": 52
        }
      },
      {
        "candidate": "q_f21dafdab3",
        "reason_code": "other",
        "note": "plumbing: collects missing container dependencies; only avoids reinstalling what is present",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 1703,
          "end_byte": 1779,
          "node_type": "if_statement",
          "sha256": "968c0a5b1c5bc240",
          "line": 52
        }
      },
      {
        "candidate": "k_376abbfe30",
        "reason_code": "other",
        "note": "plumbing: npm_execpath existence only picks whether npm is launched via node + npm-cli.js or plain npm; same install either way",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 3545,
          "end_byte": 3571,
          "node_type": "call_expression",
          "sha256": "baf634466a7d3576",
          "line": 123
        }
      },
      {
        "candidate": "q_c46978f0c9",
        "reason_code": "other",
        "note": "plumbing: chooses the npm launch command, both sides run the same install",
        "anchor": {
          "file": "scripts/postinstall-container.mjs",
          "derived_from": null,
          "start_byte": 3461,
          "end_byte": 3677,
          "node_type": "if_statement",
          "sha256": "d01fea5daff71e49",
          "line": 119
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 5,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 8,
    "conditions_in_set": 1,
    "conditions_out_of_set": 1,
    "guard_candidates": 5,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c2",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
