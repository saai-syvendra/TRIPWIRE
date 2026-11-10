# npm core-js@3.51.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node -e` with an inline `require('./postinstall')` wrapped in an empty try/catch. `postinstall.js` is core-js's own funding banner script. One gate (g1) decides whether the banner is shown. It returns early under any of these: a quiet npm log level, `ADBLOCK`, `DISABLE_OPENCOLLECTIVE` or `OPEN_SOURCE_CONTRIBUTOR` set, a CI marker (`CI`, `BUILD_NUMBER`, `CONTINUOUS_INTEGRATION`, `DRONE`, `RUN_ID`), or the same banner already recorded in the temp file during the last 3 minutes. When the gate is open, the script writes `core-js-banners` to the OS temp folder and prints the banner. No network, process or credential activity.

## Execution

- **postinstall** `node -e "try{require('./postinstall')}catch(e){}"`: runs postinstall.js; inline_eval; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 && c4 && c5 && c6 (c1: process.env.npm_config_loglevel not_in [silent, error, warn]; c2: process.env.ADBLOCK falsy; c3: process.env falsy [BUILD_NUMBER, CI, CONTINUOUS_INTEGRATION, DRONE, RUN_ID]; c4: process.env.DISABLE_OPENCOLLECTIVE falsy; c5: process.env.OPEN_SOURCE_CONTRIBUTOR falsy; c6: file_content not_includes <core-js funding banner text>) | then | 6 | write_file | env_var_absent=npm_config_loglevel, ADBLOCK, BUILD_NUMBER, CI, CONTINUOUS_INTEGRATION, DRONE, RUN_ID, DISABLE_OPENCOLLECTIVE, OPEN_SOURCE_CONTRIBUTOR; file_absent=/tmp/core-js-banners |

Gate intent: g1 evade/enables/unclear

Grounding: 1 of 6 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, c6, g1.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: write_file

## Notes

- The printed banner contains donation URLs and a bitcoin address. They are output text only and are never contacted, so no endpoints are recorded.
- Conditions c2 to c6 are out of set. The extractor did not see the env checks routed through the `is()` helper or the dedup check on the temp file.
- The URLs in the banner name the maintainer's handle. That was not copied into the record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "core-js",
    "version": "3.51.0",
    "archive_sha256": "2a7abc3121a44b75acdf02b9bdd7408e22633f70f422fc0bd5b9e00abb17bb31",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/core-js-3.51.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "023b2b51703fc0cf9c5b4704d30715ed5787ed1b833fb63d1555d9fe1872e520",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node -e \"try{require('./postinstall')}catch(e){}\"",
        "runs_on": "always",
        "file_chain": [
          "postinstall.js"
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
      "postinstall.js (63 lines) read in full. It is the upstream core-js funding banner script: it decides whether to print a banner and records the banner in a temp file so repeat installs within 3 minutes stay quiet.",
      "The banner print itself is output only. The only behaviour is writing os.tmpdir()/core-js-banners (JSON list of banners); it also reads that file back if it was modified less than 3 minutes ago.",
      "c6 is a dedup check on the package's own temp marker from an earlier install in the last 3 minutes (statSync mtime then content). If the file is absent, stale or unreadable the write still happens, so file_absent is enough to open it.",
      "The file_absent path assumes os.tmpdir() is /tmp (Linux, TMPDIR unset), so it stays guessed.",
      "c1 is open when npm_config_loglevel is unset: ['silent','error','warn'].indexOf(undefined) is -1, so the recipe lists it as absent; any value outside the three also opens it.",
      "c3 tests any of BUILD_NUMBER, CI, CONTINUOUS_INTEGRATION, DRONE, RUN_ID being set to a value other than empty, 0 or false; is() treats '0' and 'false' as unset for c2 to c5 too.",
      "No network, process launch or credential access at install. The URLs and a bitcoin address are only in the printed banner text."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "process.env.npm_config_loglevel",
      "operator": "not_in",
      "value": [
        "silent",
        "error",
        "warn"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_17f3df2e0f",
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 394,
            "end_byte": 461,
            "node_type": "binary_expression",
            "sha256": "d6c5c36b74637468",
            "line": 12
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.ADBLOCK",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 265,
            "end_byte": 280,
            "node_type": "call_expression",
            "sha256": "ab2597381992d6ef",
            "line": 9
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "ci_marker",
      "api": "process.env",
      "operator": "falsy",
      "value": [
        "BUILD_NUMBER",
        "CI",
        "CONTINUOUS_INTEGRATION",
        "DRONE",
        "RUN_ID"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 733,
            "end_byte": 744,
            "node_type": "call_expression",
            "sha256": "d6429b2b63bbad1a",
            "line": 23
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.DISABLE_OPENCOLLECTIVE",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 349,
            "end_byte": 379,
            "node_type": "call_expression",
            "sha256": "d4acf36da7d792fc",
            "line": 11
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.OPEN_SOURCE_CONTRIBUTOR",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 493,
            "end_byte": 524,
            "node_type": "call_expression",
            "sha256": "a130f2e987c31a4b",
            "line": 13
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "file_content",
      "api": "fs.readFileSync",
      "operator": "not_includes",
      "value": "<core-js funding banner text>",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "%TMP%/core-js-banners",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 1988,
            "end_byte": 2018,
            "node_type": "binary_expression",
            "sha256": "703c639e1902f2b9",
            "line": 45
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
      "expression": "c1 && c2 && c3 && c4 && c5 && c6",
      "guards": [
        {
          "candidate": "q_1b288ba1e9",
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 1649,
            "end_byte": 1744,
            "node_type": "if_statement",
            "sha256": "a25876060a466ea4",
            "line": 38
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4",
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 1984,
            "end_byte": 2033,
            "node_type": "if_statement",
            "sha256": "234f229d1894164e",
            "line": 45
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Upstream banner suppression: skips the banner and its temp-file dedup write in CI, quiet log levels, opt-out env vars, or when shown in the last 3 minutes. Not anti-analysis.",
      "then": {
        "min_conditions": 6,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "npm_config_loglevel",
            "ADBLOCK",
            "BUILD_NUMBER",
            "CI",
            "CONTINUOUS_INTEGRATION",
            "DRONE",
            "RUN_ID",
            "DISABLE_OPENCOLLECTIVE",
            "OPEN_SOURCE_CONTRIBUTOR"
          ],
          "file_absent": [
            "/tmp/core-js-banners"
          ]
        },
        "recipe_guessed_fields": [
          "file_absent"
        ],
        "regions": [
          {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2084,
            "end_byte": 2210,
            "node_type": "try_statement",
            "sha256": "e8de62d7a3db43cc",
            "line": 50
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "postinstall.js",
              "derived_from": null,
              "start_byte": 2120,
              "end_byte": 2175,
              "node_type": "call_expression",
              "sha256": "c85942598744fd19",
              "line": 52
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
      "write_file"
    ]
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
  "assessment_reason": "The postinstall is core-js's well-known funding banner script. At install it only prints a message and writes a small JSON dedup file to the temp folder; no network, process launch or credential access.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
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
        "output_sha256": "c0263f9979d538c9"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@97d6974e53",
      "sha256": "d48adb3313875cef"
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
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 5,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
