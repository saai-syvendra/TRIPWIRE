# npm core-js-pure@3.51.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-19 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node -e` with a try/catch that requires `postinstall.js`, the standard core-js funding banner script. One gate (g1) decides whether the banner is printed and a JSON marker is written to `%TMP%/core-js-banners`: it backs off in CI (`CI`, `BUILD_NUMBER`, `CONTINUOUS_INTEGRATION`, `DRONE`, `RUN_ID`), at npm log levels silent/error/warn, when `ADBLOCK`, `DISABLE_OPENCOLLECTIVE` or `OPEN_SOURCE_CONTRIBUTOR` is set. A plain non-CI install opens it. The early return on line 45 also skips the write when the marker shows the banner was already printed in the last 3 minutes, but an absent, stale or unparsable marker reaches the write, so that check is not a gate condition. Nothing is downloaded, executed or sent.

## Execution

- **postinstall** `node -e "try{require('./postinstall')}catch(e){}"`: runs postinstall.js; inline_eval; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c2 && c3 && c4 && c5 (c1: process.env.npm_config_loglevel not_in [silent, error, warn]; c2: process.env.ADBLOCK falsy; c3: process.env falsy [BUILD_NUMBER, CI, CONTINUOUS_INTEGRATION, DRONE, RUN_ID]; c4: process.env.DISABLE_OPENCOLLECTIVE falsy; c5: process.env.OPEN_SOURCE_CONTRIBUTOR falsy) | then | 5 | write_file | env_var_absent=ADBLOCK, BUILD_NUMBER, CI, CONTINUOUS_INTEGRATION, DRONE, RUN_ID, DISABLE_OPENCOLLECTIVE, OPEN_SOURCE_CONTRIBUTOR; env_var=npm_config_loglevel=notice; file_absent=%TMP%/core-js-banners |

Gate intent: g1 evade/enables/unclear

Grounding: 1 of 5 conditions and 1 of 1 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: write_file

## Notes

- The extractor only found the log level check (c1); the opt-out env vars and the CI list (c2 to c5) were added out of set from the same `if` on line 38.
- The URLs in the banner are printed text only and are not contacted, so no endpoints are recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "core-js-pure",
    "version": "3.51.0",
    "archive_sha256": "58e146de212fdaacdb1551fd1e0e0bdfda767cdefeff2cec91deadb79754ff04",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-19",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/core-js-pure-3.51.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "04edcd8308a29c3b4f730c851a0b0956cd7f9e269d479c9f8365f617c65cb750",
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
      "postinstall.js (63 lines): read in full. It is the standard core-js funding banner script: it prints a banner and records it in a temp marker file so the banner is not repeated within 3 minutes. No network, no process launch.",
      "The inline -e wrapper swallows any error from require('./postinstall'); the marker write on line 52 is also inside an empty catch.",
      "is() treats unset, empty, '0' and 'false' as false, so c2 to c5 'falsy' means the variable is unset or set to one of those values.",
      "The line 45 dedup check is not a gate condition: an absent, stale or unparsable temp marker also reaches the write, so the marker is not needed for it.",
      "c1 holds for any npm_config_loglevel outside silent/error/warn, including unset (indexOf returns -1); the recipe value 'notice' is one such value.",
      "The banner print (console.log) is output only and not recorded as a behaviour. The fs.readFileSync on line 44 only reads the package's own marker file."
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
      "in_scope": true,
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
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 625,
            "end_byte": 748,
            "node_type": "call_expression",
            "sha256": "9c03ae238657f84c",
            "line": 17
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.DISABLE_OPENCOLLECTIVE",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.OPEN_SOURCE_CONTRIBUTOR",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1 && c2 && c3 && c4 && c5",
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
        }
      ],
      "provenance": "in_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Benign opt-out: the funding banner and its temp marker are skipped in CI, with quiet npm log levels, when opt-out variables are set, or when the banner was shown in the last 3 minutes.",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "ADBLOCK",
            "BUILD_NUMBER",
            "CI",
            "CONTINUOUS_INTEGRATION",
            "DRONE",
            "RUN_ID",
            "DISABLE_OPENCOLLECTIVE",
            "OPEN_SOURCE_CONTRIBUTOR"
          ],
          "env_var": {
            "npm_config_loglevel": "notice"
          },
          "file_absent": [
            "%TMP%/core-js-banners"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "postinstall.js",
            "derived_from": null,
            "start_byte": 2084,
            "end_byte": 2225,
            "node_type": "stmt_range",
            "sha256": "6c8d84d7066481cf",
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
  "assessment_reason": "The only install code is the upstream core-js postinstall banner: it prints a funding message and writes a small JSON dedup marker to the temp folder. The URLs are only printed text and nothing is contacted or executed.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
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
    "conditions_out_of_set": 4,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5"
    ],
    "anchor_refusals": 0
  }
}
```
