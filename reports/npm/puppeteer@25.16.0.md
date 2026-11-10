# npm puppeteer@25.16.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-22 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node install.mjs`, which dynamic-imports the package's own `lib/puppeteer/node/install.js` and calls `downloadBrowsers()`, all inside a try/catch that only warns on failure. One gate (g1) decides whether anything happens: `getConfiguration()` turns `PUPPETEER_SKIP_DOWNLOAD`, `PUPPETEER_EXECUTABLE_PATH` and any puppeteer config file found by lilconfig into `skipDownload`, and when that is true the installer returns early. The sources merge by precedence: a false value of `PUPPETEER_SKIP_DOWNLOAD` (c4) overrides the executable path and the config, so the gate is `c4 || (c1 && c2 && c3)`. In a stock environment (none of these set) the gate is open and Chrome plus chrome-headless-shell are downloaded and unpacked into `~/.cache/puppeteer` through the `@puppeteer/browsers` dependency. This is the normal behaviour of the real Puppeteer package.

## Execution

- **postinstall** `node install.mjs`: 3-file chain; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c4 \|\| (c1 && c2 && c3) (c4: process.env.PUPPETEER_SKIP_DOWNLOAD in [, 0, false, off]; c1: process.env.PUPPETEER_SKIP_DOWNLOAD not_exists; c2: process.env.PUPPETEER_EXECUTABLE_PATH not_exists; c3: consuming_app other no puppeteer config found by lilconfig has a truthy skipDownload or executablePath) | then | 1 | download, write_file | env_var_absent=PUPPETEER_SKIP_DOWNLOAD, PUPPETEER_EXECUTABLE_PATH |

Gate intent: g1 activate/enables/unclear

Grounding: 0 of 4 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, g1.

## Requirements

- network: browser download host set in @puppeteer/browsers (not in this package):443 (the browser archives are fetched at install; the default host lives in the dependency, which is not part of this archive, so it is not recorded here)
- os: linux, darwin or win32 (detectBrowserPlatform() must return a supported platform or downloadBrowsers throws before any download)
- other: dependencies @puppeteer/browsers and puppeteer-core installed (install.js imports them; without them the import fails and install.mjs exits 0)

## Behaviour

- Ungated: none
- Gated: download, write_file

## Notes

- The extractor did not follow the self-referencing import `puppeteer/internal/node/install.js` (resolved through the `exports` map), so g1 and its conditions are out of set. That is why this record is flagged for review.
- The prefilled RUNNER_DEBUG candidate only chooses whether an import error gets printed, so I dropped it as log-only.
- The download sink is the `install()` call from `@puppeteer/browsers`. That dependency isn't in this archive, so the download host and the extraction code were not read.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "puppeteer",
    "version": "25.16.0",
    "archive_sha256": "08568210e4f2c972d25499d06f215f39fcc2112b7bf167437cfc4f8d5f70676d",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-22",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/puppeteer-25.16.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "3c6e4455b3e44f5648ba273bfd1a1ee4020ea21684135c30d163b526f243e732",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node install.mjs",
        "runs_on": "always",
        "file_chain": [
          "install.mjs",
          "lib/puppeteer/node/install.js",
          "lib/puppeteer/getConfiguration.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): puppeteer",
      "install.mjs dynamic-imports puppeteer/internal/node/install.js, a self-reference that the exports map resolves to lib/puppeteer/node/install.js; the extractor did not follow it. Added to file_chain with getConfiguration.js.",
      "Coverage: install.mjs, lib/puppeteer/node/install.js and lib/puppeteer/getConfiguration.js read in full. The actual download and unpack happen in dependency @puppeteer/browsers (install, detectBrowserPlatform), not shipped here, so out of scope.",
      "install.mjs: if the import of the built installer fails, it logs and exits 0; that probes the package's own lib file, present in every registry tarball, so not an environment gate.",
      "skipDownload merges by precedence: a false PUPPETEER_SKIP_DOWNLOAD (c4, compared after toLowerCase) overrides c2 and c3, hence c4 || (c1 && c2 && c3).",
      "c1 && c2 && c3 is the stock-environment path; the env_recipe describes that path.",
      "c2 is written as not_exists for the stock path; the code tests the merged executablePath for truthiness, so PUPPETEER_EXECUTABLE_PATH='' also passes and, through ??, hides a config executablePath.",
      "Per-browser switches (PUPPETEER_CHROME_SKIP_DOWNLOAD, PUPPETEER_SKIP_CHROME_HEADLESS_SHELL_DOWNLOAD, etc.) only drop single browsers; the behaviour class stays download, so they are not separate gates. Firefox is skipped by default.",
      "npm_config_*proxy vars are copied into HTTPS_PROXY/HTTP_PROXY/NO_PROXY (plumbing) and npm_config_loglevel only changes logging; neither is a gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "browser download host set in @puppeteer/browsers (not in this package):443",
      "reason": "the browser archives are fetched at install; the default host lives in the dependency, which is not part of this archive, so it is not recorded here"
    },
    {
      "axis": "os",
      "value": "linux, darwin or win32",
      "reason": "detectBrowserPlatform() must return a supported platform or downloadBrowsers throws before any download"
    },
    {
      "axis": "other",
      "value": "dependencies @puppeteer/browsers and puppeteer-core installed",
      "reason": "install.js imports them; without them the import fails and install.mjs exits 0"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.PUPPETEER_SKIP_DOWNLOAD",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "lib/puppeteer/getConfiguration.js",
            "derived_from": null,
            "start_byte": 3416,
            "end_byte": 3459,
            "node_type": "call_expression",
            "sha256": "4718474c20706339",
            "line": 116
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.PUPPETEER_EXECUTABLE_PATH",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "lib/puppeteer/getConfiguration.js",
            "derived_from": null,
            "start_byte": 3105,
            "end_byte": 3145,
            "node_type": "subscript_expression",
            "sha256": "62a18a8187964ce3",
            "line": 109
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "consuming_app",
      "api": "lilconfig.search",
      "operator": "other",
      "value": "no puppeteer config found by lilconfig has a truthy skipDownload or executablePath",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "lilconfig.search",
        "target": "package.json#puppeteer, .puppeteerrc*, puppeteer.config.* (searched upward from cwd)",
        "accessor": "content"
      },
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "lib/puppeteer/getConfiguration.js",
            "derived_from": null,
            "start_byte": 2200,
            "end_byte": 2728,
            "node_type": "call_expression",
            "sha256": "b1a4c77d513d7c6c",
            "line": 87
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.PUPPETEER_SKIP_DOWNLOAD",
      "operator": "in",
      "value": [
        "",
        "0",
        "false",
        "off"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "lib/puppeteer/getConfiguration.js",
            "derived_from": null,
            "start_byte": 3416,
            "end_byte": 3459,
            "node_type": "call_expression",
            "sha256": "4718474c20706339",
            "line": 116
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
      "expression": "c4 || (c1 && c2 && c3)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "lib/puppeteer/node/install.js",
            "derived_from": null,
            "start_byte": 1367,
            "end_byte": 1500,
            "node_type": "if_statement",
            "sha256": "1782b0aa1a2d5c7e",
            "line": 37
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "user opt-out of the browser download (skipDownload from env or config); not targeting or evasion, and not portability because the other side does nothing rather than run a platform-specific version of the download",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "PUPPETEER_SKIP_DOWNLOAD",
            "PUPPETEER_EXECUTABLE_PATH"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "lib/puppeteer/node/install.js",
            "derived_from": null,
            "start_byte": 1505,
            "end_byte": 2917,
            "node_type": "stmt_range",
            "sha256": "b8d971ffb37f0da2",
            "line": 41
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "lib/puppeteer/node/install.js",
              "derived_from": null,
              "start_byte": 671,
              "end_byte": 936,
              "node_type": "call_expression",
              "sha256": "ca3a00b2d26f164d",
              "line": 14
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "lib/puppeteer/node/install.js",
                  "derived_from": null,
                  "start_byte": 1931,
                  "end_byte": 2081,
                  "node_type": "call_expression",
                  "sha256": "46ced69a76a7e379",
                  "line": 52
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "lib/puppeteer/node/install.js",
                  "derived_from": null,
                  "start_byte": 320,
                  "end_byte": 1225,
                  "node_type": "function_declaration",
                  "sha256": "f88538c306756085",
                  "line": 9
                }
              }
            ]
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "download",
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
    "needs_remote": true,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall runs Puppeteer's own installer, which downloads Chrome and chrome-headless-shell into ~/.cache/puppeteer through @puppeteer/browsers unless the user opts out via PUPPETEER_SKIP_DOWNLOAD, PUPPETEER_EXECUTABLE_PATH or a puppeteer config. Nothing reads credentials or sends data.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "f1248e71f756155e"
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
        "candidate": "k_cc186e4e13",
        "reason_code": "log_only",
        "note": "RUNNER_DEBUG only decides whether the import error is printed with console.error",
        "anchor": {
          "file": "install.mjs",
          "derived_from": null,
          "start_byte": 828,
          "end_byte": 855,
          "node_type": "subscript_expression",
          "sha256": "9d8efc8981c239b5",
          "line": 28
        }
      },
      {
        "candidate": "q_70cfc6a92d",
        "reason_code": "log_only",
        "note": "the if around console.error(error) for RUNNER_DEBUG; both sides then warn and exit 0",
        "anchor": {
          "file": "install.mjs",
          "derived_from": null,
          "start_byte": 824,
          "end_byte": 892,
          "node_type": "if_statement",
          "sha256": "7e03d2ceb49b95fc",
          "line": 28
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 4,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c4",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
