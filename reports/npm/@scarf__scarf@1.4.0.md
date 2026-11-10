# npm @scarf/scarf@1.4.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-11-06 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node ./report.js`, the Scarf install-analytics library. It runs `npm ls @scarf/scarf --json --long` in `$INIT_CWD` to find the package that depends on it, then POSTs platform, arch, node version and hashed package names to scarf[.]sh. The report is gated by opt-out env vars (`SCARF_ANALYTICS=false`, `SCARF_NO_ANALYTICS=true`, `DO_NOT_TRACK=1`), by a yarn check on `npm_execpath` (skipped under yarn unless `SCARF_ANALYTICS=true`), and by consuming-project settings in `package.json` `scarfSettings` (defaultOptIn, allowTopLevel, skipTraversal, enabled). `SCARF_LOCAL_PORT` sends the report to localhost over http, and `SCARF_API_TOKEN` adds a Basic auth header. A default npm install of a package that depends on Scarf, with none of these variables set, sends the report.

## Execution

- **postinstall** `node ./report.js`: runs report.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: process.env.SCARF_LOCAL_PORT truthy) | then | 1 | exfil | env_var=SCARF_LOCAL_PORT=(set) |
| g2 | postinstall | c13 (c13: consuming_app falsy) | then | 1 | recon | (none) |
| g3 | postinstall | (c10 \|\| c2 \|\| c17) && (c16 \|\| c8 \|\| c12) (c10: consuming_app falsy; c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c16: consuming_app falsy; c8: process.env.npm_config_global truthy; c12: consuming_app truthy) | then | 2 | exfil | (none) |
| g4 | postinstall | c11 && c12 (c11: consuming_app truthy; c12: consuming_app truthy) | then | 2 | recon | (none) |
| g5 | postinstall | c2 \|\| c17 \|\| c7 (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$) | then | 1 | exfil | package_manager=npm |
| g6 | postinstall | (c2 \|\| c17 \|\| c7) && c9 && c19 && c3 && c4 && c5 (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$; c9: consuming_app truthy; c19: consuming_app != false; c3: process.env.SCARF_ANALYTICS != false; c4: process.env.SCARF_NO_ANALYTICS != true; c5: process.env.DO_NOT_TRACK != 1) | then | 6 | exfil | package_manager=npm; env_var_absent=SCARF_ANALYTICS, SCARF_NO_ANALYTICS, DO_NOT_TRACK |
| g7 | postinstall | (c2 \|\| c17 \|\| c7) && c9 && c19 && c3 && c4 && c5 && c14 && c18 (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$; c9: consuming_app truthy; c19: consuming_app != false; c3: process.env.SCARF_ANALYTICS != false; c4: process.env.SCARF_NO_ANALYTICS != true; c5: process.env.DO_NOT_TRACK != 1; c14: process.env.SCARF_ANALYTICS != true; c18: consuming_app falsy) | then | 8 | write_file | package_manager=npm; env_var_absent=SCARF_ANALYTICS, SCARF_NO_ANALYTICS, DO_NOT_TRACK |
| g8 | postinstall | (c2 \|\| c17 \|\| c7) && c15 && (c2 \|\| c17) (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$; c15: consuming_app falsy) | then | 2 | exfil | env_var=SCARF_ANALYTICS=true |
| g9 | postinstall | (c2 \|\| c17 \|\| c7) && c15 && c14 && c18 && c19 && c3 && c4 && c5 (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$; c15: consuming_app falsy; c14: process.env.SCARF_ANALYTICS != true; c18: consuming_app falsy; c19: consuming_app != false; c3: process.env.SCARF_ANALYTICS != false; c4: process.env.SCARF_NO_ANALYTICS != true; c5: process.env.DO_NOT_TRACK != 1) | then | 8 | write_file | package_manager=npm; env_var_absent=SCARF_ANALYTICS, SCARF_NO_ANALYTICS, DO_NOT_TRACK |
| g10 | postinstall | (c2 \|\| c17 \|\| c7) && c6 (c2: process.env.SCARF_ANALYTICS == true; c17: consuming_app truthy; c7: process.env.npm_execpath not_regex (yarn\|yarn\.js\|yarnpkg\|yarn\.cmd\|yarnpkg\.cmd)$; c6: process.env.SCARF_API_TOKEN truthy) | then | 2 | exfil | package_manager=npm; env_var=SCARF_API_TOKEN=(set) |

Gate intent: g1 activate/modifies/unclear; g2 activate/enables/unclear; g3 activate/enables/targeting; g4 activate/enables/targeting; g5 activate/enables/targeting; g6 activate/enables/targeting; g7 activate/enables/unclear; g8 activate/enables/targeting; g9 activate/enables/unclear; g10 activate/modifies/data_availability

Grounding: 8 of 19 conditions and 4 of 10 gates from the candidate set; out of set, pending verification: c7, c9, c10, c11, c12, c13, c15, c16, c17, c18, c19, g2, g4, g6, g7, g8, g9.

## Requirements

- network: scarf[.]sh:443 (telemetry POST to /package-event/install over https)
- installed_tool: npm (npm ls @scarf/scarf --json --long builds the dependency info unless skipTraversal is set)
- installed_tool: git (git rev-parse HEAD only on the g4 branch; failure is tolerated)
- other: INIT_CWD set to a project directory whose npm ls tree has @scarf/scarf under a parent package (otherwise npm ls fails or finds no parent and the report is rejected)

## Behaviour

- Ungated: none
- Gated: exfil, recon, write_file

## Notes

- Benign and matches the source label. Every error is swallowed and the script exits 0.
- Many conditions are `consuming_app` (the root or parent package.json `scarfSettings`) and were added out of set, so the record is flagged for review. Root `scarfSettings.enabled` also counts as opt-in or opt-out and is recorded as c17, c18 and c19; recipes only express the env var forms.
- Several payload witnesses start at a promise `resolve(...)` call. The POST runs later in the same `reportPostInstall` body, after the `await` on that promise. The `https` binding at line 5 is a ternary over the core `http` and `https` modules, so the sink is a network call either way. The g1, g3 and g10 witnesses stop early and are marked unresolved: those gates reach the POST by data or a promise continuation, not by a call path.
- The defaultOptIn false path prompts on stdin with 7 s and 15 s timeouts. Under a non-interactive install it times out and nothing is sent.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@scarf/scarf",
    "version": "1.4.0",
    "archive_sha256": "d5b13758ca8f84c0e050bbe4b4b36247cba55871d0b7ef9c8bc8c42c6b52ae14",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-11-06",
    "released_at_source": "registry",
    "sample_path": "benign_sample/npm/benign/scarf-1.4.0.tgz",
    "package_root": "layer0/package",
    "cluster_key": "0b4b22d1df2764efb4a5eb9f6414958c449b3ffc77e9863b810b7fbb2a9f4a27",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node ./report.js",
        "runs_on": "always",
        "file_chain": [
          "report.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "report.js:321",
        "seconds": 7.0
      },
      {
        "site": "report.js:349",
        "seconds": 15.0
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in report.js; candidates there may be missing",
      "report.js (575 lines, plain package code): read in full; nothing bundled, nothing unread. README.md and LICENSE are not code.",
      "All failures are swallowed: reportPostInstall().catch logs only when SCARF_VERBOSE=true, then process.exit(0). Every reject below just ends the script quietly.",
      "The checks are sequential: getDependencyInfo (g2, g3) must resolve, then g5 (yarn), then the defaultOptIn split (g6 or g8/g9), before the POST at line 406. Rejects inside promise executors end reportPostInstall through the await.",
      "Opt-in (userHasOptedIn) is c2 or c17 (root scarfSettings.enabled truthy); not opted in is c14 and c18. Not opted out (userHasOptedOut) is c19 (enabled not false) and c3, c4, c5. c17-c19 are consuming_app, so recipes only express the env var forms.",
      "g1 payload path: the ternary arms only pick the module and host held in https and scarfHost; reportPostInstall reads those bindings at line 406 and no call leads there from the arms, so the witness stops at the binding (unresolved).",
      "os.platform(), os.arch() and the node version at lines 379-381 are read only to fill the POST body, so they count under exfil. No separate recon sink sits behind g3, g5, g6 or g8; the npm ls walk (g2) runs before those checks.",
      "c9/c15 parent scarfSettings.defaultOptIn defaults to true (makeDefaultSettings) unless the depending package sets it, so the g6 path is the normal one; g8/g9 apply to packages that set defaultOptIn false.",
      "g9 prompts on stdin (y/N) with 7 s and 15 s timeouts; only a typed y leads to the POST and optionally rewriting the root package.json scarfSettings. Under a non-interactive install it times out and rejects.",
      "Rate limit: rateLimitedUserLog and line 303 skip the notice if the tmp file scarf-js-history-<user>.log holds a timestamp from the last minute. This is a throttle on the package's own file, recorded as no gate.",
      "Not gates: SCARF_VERBOSE (logging only), require('crypto') try (only picks a hash or a placeholder string in the payload), npm_config_global in rootPackageDepInfo line 485 (picks where root info is read from npm ls JSON).",
      "The require of $INIT_CWD/package.json in a try (line 217) is not a separate gate: on failure the code falls through to the same npm ls path a falsy skipTraversal takes.",
      "g3 payload path: resolve at line 190 settles the getDependencyInfo promise awaited at line 262 before the POST at line 406; a promise continuation has no call/def hop, so the witness stops there (unresolved).",
      "g10 payload path: the token block (line 400) only sets the Authorization header; https.request at line 406 runs after it either way and reads reqOptions as data, so the witness stops at the assignment (unresolved).",
      "Sent data: os.platform(), os.arch(), node version, sha256 hashes of root/grandparent package names and versions, parent package name/version and optional git sha of the root project."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "scarf[.]sh:443",
      "reason": "telemetry POST to /package-event/install over https"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "npm ls @scarf/scarf --json --long builds the dependency info unless skipTraversal is set"
    },
    {
      "axis": "installed_tool",
      "value": "git",
      "reason": "git rev-parse HEAD only on the g4 branch; failure is tolerated"
    },
    {
      "axis": "other",
      "value": "INIT_CWD set to a project directory whose npm ls tree has @scarf/scarf under a parent package",
      "reason": "otherwise npm ls fails or finds no parent and the report is rejected"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.SCARF_LOCAL_PORT",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_f8b6b33237",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 161,
            "end_byte": 173,
            "node_type": "identifier",
            "sha256": "e9f60f191ca13aed",
            "line": 5
          }
        },
        {
          "candidate": "k_a5cd7536a9",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 312,
            "end_byte": 324,
            "node_type": "identifier",
            "sha256": "e9f60f191ca13aed",
            "line": 10
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.SCARF_ANALYTICS",
      "operator": "==",
      "value": "true",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_b8fa6873d7",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1947,
            "end_byte": 1985,
            "node_type": "binary_expression",
            "sha256": "16aa31d4671ce400",
            "line": 62
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.SCARF_ANALYTICS",
      "operator": "!=",
      "value": "false",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_5ea7026ed3",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1688,
            "end_byte": 1727,
            "node_type": "binary_expression",
            "sha256": "4dc3f72721b4b115",
            "line": 58
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env.SCARF_NO_ANALYTICS",
      "operator": "!=",
      "value": "true",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_c25f50f07e",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1731,
            "end_byte": 1772,
            "node_type": "binary_expression",
            "sha256": "cad070a201281813",
            "line": 58
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.DO_NOT_TRACK",
      "operator": "!=",
      "value": "1",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_bad257af97",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1776,
            "end_byte": 1808,
            "node_type": "binary_expression",
            "sha256": "73399a6d0443b4ea",
            "line": 58
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "process.env.SCARF_API_TOKEN",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_302c351097",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 14696,
            "end_byte": 14709,
            "node_type": "identifier",
            "sha256": "d34ee90f0daf1ec5",
            "line": 400
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "package_manager",
      "api": "process.env.npm_execpath",
      "operator": "not_regex",
      "value": "(yarn|yarn\\.js|yarnpkg|yarn\\.cmd|yarnpkg\\.cmd)$",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 4815,
            "end_byte": 4851,
            "node_type": "call_expression",
            "sha256": "30da0e5f8ba4108b",
            "line": 140
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "package_manager",
      "api": "process.env.npm_config_global",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_0c7108ecd2",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2781,
            "end_byte": 2810,
            "node_type": "member_expression",
            "sha256": "a205e71ab43f4d30",
            "line": 84
          }
        },
        {
          "candidate": "k_c08760e3a9",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2902,
            "end_byte": 2931,
            "node_type": "member_expression",
            "sha256": "a205e71ab43f4d30",
            "line": 88
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c9",
      "category": "consuming_app",
      "api": "dependencyInfo.parent.scarfSettings.defaultOptIn",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10159,
            "end_byte": 10207,
            "node_type": "member_expression",
            "sha256": "bd3af9012c723b30",
            "line": 281
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "consuming_app",
      "api": "dependencyToReport.anyInChainDisabled",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 6527,
            "end_byte": 6564,
            "node_type": "member_expression",
            "sha256": "54ddcc80fdbf85a1",
            "line": 182
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "consuming_app",
      "api": "parentIsRoot",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2589,
            "end_byte": 2688,
            "node_type": "binary_expression",
            "sha256": "74b23378acf046d1",
            "line": 80
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "consuming_app",
      "api": "rootPackage.scarfSettings.allowTopLevel",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2216,
            "end_byte": 2299,
            "node_type": "binary_expression",
            "sha256": "ea17547e9e188300",
            "line": 69
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "consuming_app",
      "api": "rootPackage.scarfSettings.skipTraversal",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2351,
            "end_byte": 2434,
            "node_type": "binary_expression",
            "sha256": "a0d9fdadcc8d91a2",
            "line": 73
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "env_var",
      "api": "process.env.SCARF_ANALYTICS",
      "operator": "!=",
      "value": "true",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_b8fa6873d7",
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1947,
            "end_byte": 1985,
            "node_type": "binary_expression",
            "sha256": "16aa31d4671ce400",
            "line": 62
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c15",
      "category": "consuming_app",
      "api": "dependencyInfo.parent.scarfSettings.defaultOptIn",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10159,
            "end_byte": 10207,
            "node_type": "member_expression",
            "sha256": "bd3af9012c723b30",
            "line": 281
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c16",
      "category": "consuming_app",
      "api": "parentIsRoot",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 2589,
            "end_byte": 2688,
            "node_type": "binary_expression",
            "sha256": "74b23378acf046d1",
            "line": 80
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c17",
      "category": "consuming_app",
      "api": "rootPackage.scarfSettings.enabled",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1865,
            "end_byte": 1942,
            "node_type": "binary_expression",
            "sha256": "3331b96a6104e779",
            "line": 62
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c18",
      "category": "consuming_app",
      "api": "rootPackage.scarfSettings.enabled",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1865,
            "end_byte": 1942,
            "node_type": "binary_expression",
            "sha256": "3331b96a6104e779",
            "line": 62
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c19",
      "category": "consuming_app",
      "api": "rootPackage.scarfSettings.enabled",
      "operator": "!=",
      "value": "false",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 1591,
            "end_byte": 1678,
            "node_type": "binary_expression",
            "sha256": "907c81b6010625e1",
            "line": 57
          }
        }
      ],
      "in_scope": false,
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
          "candidate": "q_81a8a02f8c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 161,
            "end_byte": 210,
            "node_type": "ternary_expression",
            "sha256": "1da9b2de543d8ffb",
            "line": 5
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_87217f67fa",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 312,
            "end_byte": 351,
            "node_type": "ternary_expression",
            "sha256": "64441f03d617adc2",
            "line": 10
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "unclear",
      "purpose_reason": "local development switch: report goes over plain http to localhost:<port> instead of https to scarf.sh",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var": {
            "SCARF_LOCAL_PORT": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 176,
            "end_byte": 191,
            "node_type": "call_expression",
            "sha256": "bdebe6742736c36f",
            "line": 5
          },
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 327,
            "end_byte": 338,
            "node_type": "string",
            "sha256": "6d6bda3bbb069bc4",
            "line": 10
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "import",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 176,
                  "end_byte": 191,
                  "node_type": "call_expression",
                  "sha256": "bdebe6742736c36f",
                  "line": 5
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 153,
                  "end_byte": 210,
                  "node_type": "variable_declarator",
                  "sha256": "1e9dd2e1a1de7826",
                  "line": 5
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c13",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 8039,
            "end_byte": 8689,
            "node_type": "if_statement",
            "sha256": "9b9af751e9a6b0e4",
            "line": 221
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c13"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "the consuming project's scarfSettings.skipTraversal turns off the npm ls dependency walk",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 8752,
            "end_byte": 8965,
            "node_type": "return_statement",
            "sha256": "4876cb45a5ddc573",
            "line": 242
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "exec",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 8798,
              "end_byte": 8960,
              "node_type": "call_expression",
              "sha256": "fe78f492a9455c42",
              "line": 243
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 8771,
                  "end_byte": 8964,
                  "node_type": "arrow_function",
                  "sha256": "8b64c11aac880293",
                  "line": 242
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "(c10 || c2 || c17) && (c16 || c8 || c12)",
      "guards": [
        {
          "candidate": "q_618385a61f",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 6523,
            "end_byte": 6730,
            "node_type": "if_statement",
            "sha256": "2592ba0d3b851e17",
            "line": 182
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c10",
            "c2",
            "c17"
          ]
        },
        {
          "candidate": "q_4e43adb566",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 6738,
            "end_byte": 7083,
            "node_type": "if_statement",
            "sha256": "ee7adab386756d5a",
            "line": 186
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c16",
            "c8",
            "c12"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "reports only when no package in the chain disabled Scarf and the install is as a dependency, global, or allowTopLevel is set",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 7091,
            "end_byte": 7125,
            "node_type": "return_statement",
            "sha256": "1b8f0fd98a177b84",
            "line": 190
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 7098,
                  "end_byte": 7125,
                  "node_type": "call_expression",
                  "sha256": "26e4e782baed34f8",
                  "line": 190
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c11 && c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9648,
            "end_byte": 9878,
            "node_type": "if_statement",
            "sha256": "34a4e59a92d792cc",
            "line": 268
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11",
            "c12"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "adds the root project's git commit sha only when the scarfed package is itself the root and allowTopLevel is set",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9733,
            "end_byte": 9874,
            "node_type": "stmt_range",
            "sha256": "45e9dc1877a5cfed",
            "line": 269
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "exec",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 9068,
              "end_byte": 9212,
              "node_type": "call_expression",
              "sha256": "9007b1d0de711334",
              "line": 249
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 9754,
                  "end_byte": 9777,
                  "node_type": "call_expression",
                  "sha256": "7d6e20cfebae6d74",
                  "line": 269
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 8969,
                  "end_byte": 9313,
                  "node_type": "function_declaration",
                  "sha256": "e85736358dc31158",
                  "line": 247
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 9041,
                  "end_byte": 9216,
                  "node_type": "arrow_function",
                  "sha256": "d556406c5bf47008",
                  "line": 248
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c2 || c17 || c7",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "skips yarn installs (cannot show the analytics notice there) unless SCARF_ANALYTICS=true opts in",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "package_manager": "npm"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10110,
            "end_byte": 15272,
            "node_type": "stmt_range",
            "sha256": "49dd23ca36e505a8",
            "line": 280
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 14863,
                  "end_byte": 15272,
                  "node_type": "new_expression",
                  "sha256": "f83bf8c0db9db5e0",
                  "line": 405
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 14875,
                  "end_byte": 15271,
                  "node_type": "arrow_function",
                  "sha256": "7929101d9e2595a0",
                  "line": 405
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g6",
      "hook": "postinstall",
      "expression": "(c2 || c17 || c7) && c9 && c19 && c3 && c4 && c5",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10155,
            "end_byte": 14114,
            "node_type": "if_statement",
            "sha256": "fc34c2dcb2e51362",
            "line": 281
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": "q_a56b9e2e4d",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10217,
            "end_byte": 10315,
            "node_type": "if_statement",
            "sha256": "57dd624740ffca6e",
            "line": 282
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c19",
            "c3",
            "c4",
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "default opt-out model: reports unless SCARF_ANALYTICS=false, SCARF_NO_ANALYTICS=true or DO_NOT_TRACK=1",
      "then": {
        "min_conditions": 6,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "package_manager": "npm",
          "env_var_absent": [
            "SCARF_ANALYTICS",
            "SCARF_NO_ANALYTICS",
            "DO_NOT_TRACK"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10323,
            "end_byte": 11005,
            "node_type": "stmt_range",
            "sha256": "46e632cfae8457aa",
            "line": 286
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 10982,
                  "end_byte": 11005,
                  "node_type": "call_expression",
                  "sha256": "3c20ec4999376d4b",
                  "line": 297
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 153,
                  "end_byte": 210,
                  "node_type": "variable_declarator",
                  "sha256": "1e9dd2e1a1de7826",
                  "line": 5
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g7",
      "hook": "postinstall",
      "expression": "(c2 || c17 || c7) && c9 && c19 && c3 && c4 && c5 && c14 && c18",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10155,
            "end_byte": 14114,
            "node_type": "if_statement",
            "sha256": "fc34c2dcb2e51362",
            "line": 281
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": "q_a56b9e2e4d",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10217,
            "end_byte": 10315,
            "node_type": "if_statement",
            "sha256": "57dd624740ffca6e",
            "line": 282
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c19",
            "c3",
            "c4",
            "c5"
          ]
        },
        {
          "candidate": "q_c68a0512ed",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10323,
            "end_byte": 10975,
            "node_type": "if_statement",
            "sha256": "3481a5a1f528954f",
            "line": 286
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c14",
            "c18"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "shows the analytics notice and records its time in a tmp throttle file when the user has not explicitly opted in",
      "then": {
        "min_conditions": 8,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "package_manager": "npm",
          "env_var_absent": [
            "SCARF_ANALYTICS",
            "SCARF_NO_ANALYTICS",
            "DO_NOT_TRACK"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10357,
            "end_byte": 10975,
            "node_type": "statement_block",
            "sha256": "34521b348c15424d",
            "line": 286
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 18739,
              "end_byte": 18810,
              "node_type": "call_expression",
              "sha256": "b8c7cd2f97439658",
              "line": 541
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 10367,
                  "end_byte": 10967,
                  "node_type": "call_expression",
                  "sha256": "a9567ed2a269160f",
                  "line": 287
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 17852,
                  "end_byte": 18164,
                  "node_type": "function_declaration",
                  "sha256": "4abe35ec362cce86",
                  "line": 509
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 18002,
                  "end_byte": 18053,
                  "node_type": "call_expression",
                  "sha256": "b57cd3965cdc1133",
                  "line": 512
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 18626,
                  "end_byte": 18812,
                  "node_type": "function_declaration",
                  "sha256": "d91f0a078ee07117",
                  "line": 539
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g8",
      "hook": "postinstall",
      "expression": "(c2 || c17 || c7) && c15 && (c2 || c17)",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10155,
            "end_byte": 14114,
            "node_type": "if_statement",
            "sha256": "fc34c2dcb2e51362",
            "line": 281
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c15"
          ]
        },
        {
          "candidate": "q_bca7d5b734",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 11025,
            "end_byte": 14108,
            "node_type": "if_statement",
            "sha256": "9380cdb03f9bfaa7",
            "line": 299
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c2",
            "c17"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "for packages with defaultOptIn false, reports only when the user opted in with SCARF_ANALYTICS=true",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var": {
            "SCARF_ANALYTICS": "true"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 14077,
            "end_byte": 14100,
            "node_type": "expression_statement",
            "sha256": "3c20ec4999376d4b",
            "line": 370
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 14077,
                  "end_byte": 14100,
                  "node_type": "call_expression",
                  "sha256": "3c20ec4999376d4b",
                  "line": 370
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 153,
                  "end_byte": 210,
                  "node_type": "variable_declarator",
                  "sha256": "1e9dd2e1a1de7826",
                  "line": 5
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g9",
      "hook": "postinstall",
      "expression": "(c2 || c17 || c7) && c15 && c14 && c18 && c19 && c3 && c4 && c5",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 10155,
            "end_byte": 14114,
            "node_type": "if_statement",
            "sha256": "fc34c2dcb2e51362",
            "line": 281
          },
          "kind": "if",
          "arm": "else",
          "conditions": [
            "c15"
          ]
        },
        {
          "candidate": "q_bca7d5b734",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 11025,
            "end_byte": 14108,
            "node_type": "if_statement",
            "sha256": "9380cdb03f9bfaa7",
            "line": 299
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c14",
            "c18"
          ]
        },
        {
          "candidate": "q_55c36e8ebd",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 11069,
            "end_byte": 14053,
            "node_type": "if_statement",
            "sha256": "167ec4038b359120",
            "line": 300
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c19",
            "c3",
            "c4",
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "opt-in prompt path for defaultOptIn false packages: notice, throttle file write, and a stdin y/N question",
      "then": {
        "min_conditions": 8,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "package_manager": "npm",
          "env_var_absent": [
            "SCARF_ANALYTICS",
            "SCARF_NO_ANALYTICS",
            "DO_NOT_TRACK"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 11104,
            "end_byte": 14053,
            "node_type": "statement_block",
            "sha256": "23283c7f099948db",
            "line": 300
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 18739,
              "end_byte": 18810,
              "node_type": "call_expression",
              "sha256": "b8c7cd2f97439658",
              "line": 541
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 11490,
                  "end_byte": 12096,
                  "node_type": "call_expression",
                  "sha256": "963df3c3df8da798",
                  "line": 306
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 17852,
                  "end_byte": 18164,
                  "node_type": "function_declaration",
                  "sha256": "4abe35ec362cce86",
                  "line": 509
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 18002,
                  "end_byte": 18053,
                  "node_type": "call_expression",
                  "sha256": "b57cd3965cdc1133",
                  "line": 512
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 18626,
                  "end_byte": 18812,
                  "node_type": "function_declaration",
                  "sha256": "d91f0a078ee07117",
                  "line": 539
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g10",
      "hook": "postinstall",
      "expression": "(c2 || c17 || c7) && c6",
      "guards": [
        {
          "candidate": "q_ae55f6890c",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 9932,
            "end_byte": 10106,
            "node_type": "if_statement",
            "sha256": "20a39432a4f9395a",
            "line": 276
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c17",
            "c7"
          ]
        },
        {
          "candidate": "q_aafab5adcf",
          "site": {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 14692,
            "end_byte": 14853,
            "node_type": "if_statement",
            "sha256": "d73c2f556261ccd4",
            "line": 400
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "modifies",
      "purpose": "data_availability",
      "purpose_reason": "when SCARF_API_TOKEN is set the report is sent with a Basic auth header carrying that token",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "package_manager": "npm",
          "env_var": {
            "SCARF_API_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "report.js",
            "derived_from": null,
            "start_byte": 14711,
            "end_byte": 14853,
            "node_type": "statement_block",
            "sha256": "5ab2da593c226a76",
            "line": 400
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "report.js",
              "derived_from": null,
              "start_byte": 14914,
              "end_byte": 15030,
              "node_type": "call_expression",
              "sha256": "5da754474fb60589",
              "line": 406
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "report.js",
                  "derived_from": null,
                  "start_byte": 14794,
                  "end_byte": 14849,
                  "node_type": "assignment_expression",
                  "sha256": "d69125cd08f84156",
                  "line": 402
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "exfil",
      "recon",
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
    "endpoints": [
      {
        "indicator": "hxxps://scarf[.]sh",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "The postinstall script is the published Scarf install-analytics library: it runs npm ls to find which package depends on it and POSTs platform, arch, node version and hashed package names to scarf.sh. It honours documented opt-out variables, prints a notice, and swallows all errors.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "f520fd64684379b3"
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
        "candidate": "k_463793af5c",
        "reason_code": "log_only",
        "note": "SCARF_VERBOSE only enables console logging",
        "anchor": {
          "file": "report.js",
          "derived_from": null,
          "start_byte": 1376,
          "end_byte": 1412,
          "node_type": "binary_expression",
          "sha256": "fca6846cad1fbc15",
          "line": 50
        }
      },
      {
        "candidate": "q_fa892312ac",
        "reason_code": "log_only",
        "note": "logIfVerbose guard; only prints",
        "anchor": {
          "file": "report.js",
          "derived_from": null,
          "start_byte": 1372,
          "end_byte": 1454,
          "node_type": "if_statement",
          "sha256": "53f29666419ee2f9",
          "line": 50
        }
      },
      {
        "candidate": "k_61dc9b65f9",
        "reason_code": "other",
        "note": "require('crypto') try only decides hash vs placeholder string inside the same telemetry payload",
        "anchor": {
          "file": "report.js",
          "derived_from": null,
          "start_byte": 3020,
          "end_byte": 3037,
          "node_type": "call_expression",
          "sha256": "717a0f0505588c86",
          "line": 94
        }
      },
      {
        "candidate": "q_bdf1484c2b",
        "reason_code": "other",
        "note": "crypto load probe; same behaviour either way, only a field value changes",
        "anchor": {
          "file": "report.js",
          "derived_from": null,
          "start_byte": 3001,
          "end_byte": 3110,
          "node_type": "try_statement",
          "sha256": "4310d42f9699aaac",
          "line": 93
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 10,
    "condition_sites_cited": 9,
    "guards_cited": 10,
    "candidates_dropped": 4,
    "conditions_in_set": 8,
    "conditions_out_of_set": 11,
    "guard_candidates": 14,
    "gates_in_set": 4,
    "gates_out_of_set": 6,
    "out_of_set_ids": [
      "c7",
      "c9",
      "c10",
      "c11",
      "c12",
      "c13",
      "c15",
      "c16",
      "c17",
      "c18",
      "c19",
      "g2",
      "g4",
      "g6",
      "g7",
      "g8",
      "g9"
    ],
    "anchor_refusals": 0
  }
}
```
