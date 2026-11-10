# npm ember-url-hash-polyfill@1.0.13

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-16 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This compromised version of `ember-url-hash-polyfill` ships a `postinstall: node bundle.js` hook whose webpack bundle (~1847 modules) hides the Shai-Hulud npm worm among bundled AWS/GCP/Octokit/grpc SDKs. At install the worm reads GitHub, npm, AWS and GCP credentials, downloads trufflehog to scan the filesystem for secrets, and exfiltrates everything by creating a public GitHub repo literally named "Shai-Hulud" (triple-base64 data) and by injecting a `.github/workflows/shai-hulud-workflow.yml` into the victim's repos that posts Actions secrets to `webhook[.]site`. It also self-propagates: on Linux or Mac with a valid npm token it downloads the maintainer's own packages, injects the same postinstall and bundle, and `npm publish`es trojanized versions. The main install gates are OS == linux/darwin (targeting GitHub extraction and npm propagation), presence of a GitHub token starting with `ghp_`/`gho_`, npm and AWS credential validity, resolvable GCP credentials and project id, and the `SKIP_TRUFFLE` env kill switch; opening them requires a developer-like host with real cloud and VCS credentials.

## Execution

- **postinstall** `node bundle.js`: runs bundle.js; direct_script, detached_child, download_then_exec, dropped_binary; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c3 \|\| c4) && (c1 \|\| c2) && (c5 \|\| c6) && c7 (c3: process.env.GITHUB_TOKEN truthy; c4: target_artifact exists; c1: os == linux; c2: os == darwin; c5: target_artifact startswith ghp_; c6: target_artifact startswith gho_; c7: server_response exists) | then | 4 | spawn_process, persistence, exfil, write_file | os=linux; env_var=GITHUB_TOKEN=(set) |
| g2 | postinstall | c8 && (c1 \|\| c2) (c8: server_response exists; c1: os == linux; c2: os == darwin) | then | 2 | self_propagation, modify_other_packages, download, spawn_process | os=linux; env_var=NPM_TOKEN=(set) |
| g3 | postinstall | c9 (c9: server_response exists) | then | 1 | cred_read | file_present=~/.aws/credentials |
| g4 | postinstall | c10 && c12 (c10: target_artifact exists; c12: target_artifact exists) | then | 2 | cred_read | env_var=GOOGLE_APPLICATION_CREDENTIALS=(set), GOOGLE_CLOUD_PROJECT=(set) |
| g5 | postinstall | c11 (c11: process.env.SKIP_TRUFFLE falsy) | then | 1 | download, write_file, exec_downloaded, cred_read | env_var_absent=SKIP_TRUFFLE |
| g6 | postinstall | c3 \|\| c4 (c3: process.env.GITHUB_TOKEN truthy; c4: target_artifact exists) | then | 1 | exfil | env_var=GITHUB_TOKEN=(set) |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/unclear; g6 activate/enables/data_availability

Grounding: 1 of 12 conditions and 1 of 6 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c12, g1, g2, g3, g4, g6.

## Requirements

- installed_tool: tar, gzip, npm (NpmModule.updatePackage self-propagation shells out to tar and gzip to repack the victim tarball and to npm to publish the trojanized version; it aborts the step if `which tar` fails)
- installed_tool: bash, curl, jq (the dropped /tmp/processor.sh and /tmp/migrate-repos.sh are bash scripts that use curl and jq against the GitHub API)
- network: api[.]github[.]com:443, registry[.]npmjs[.]org:443, github[.]com:443 (install-time payload contacts the GitHub API (repo creation, extraction, migration), the npm registry (token validation and self-propagation publish) and GitHub releases (trufflehog download); AWS and GCP cloud APIs are also contacted when their credential gates open)

## Behaviour

- Ungated: recon, cred_read, spawn_process
- Gated: spawn_process, persistence, exfil, write_file, self_propagation, modify_other_packages, download, cred_read, exec_downloaded

## Notes

- Coverage: worm package code read in full (entry `main()` plus modules `_utils_os`, `_lib_utils`, `_modules_github/aws/gcp/truffle/npm`, and embedded scripts `/tmp/processor.sh`, `/tmp/migrate-repos.sh`). The ~1800 bundled SDK modules were audited by sink inventory; every sink hint (Function() eval, fetch, spawn@92323 = AWS credential_process, writeFile@75274 = AWS SSO token, atob, grpc readFileSync) is library behaviour. Nothing left unread.
- Dropped the prefilled GOOGLE_APPLICATION_CREDENTIALS gate (g7 in the candidate set): it is google-auth-library's `_tryGetApplicationCredentialsFromEnvironmentVariable`, not a worm gate. Kept the prefilled SKIP_TRUFFLE early-return as g5.
- Only g5 (SKIP_TRUFFLE) is in set; the other gates are out of set because the extractor did not walk `main()`'s orchestration as package code. Payload sinks are anchored on the worm's own class-method wrappers, so witnesses are empty and the verifier should confirm each wrapper reaches its underlying spawn/fetch/publish.
- `attack_type` is compromised_maintainer (the sample sits in the dataset's `compromised_lib` set); `family_hint` shai-hulud is code-supported (repo name, branch `shai-hulud`, workflow filename).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "ember-url-hash-polyfill",
    "version": "1.0.13",
    "archive_sha256": "29373a2d9a179265c87d3894c24be84ac592f8d04e8aea7deb49bd454b74d828",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-16",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-16-ember-url-hash-polyfill-v1.0.13.zip",
    "package_root": "layer0/tmp/tmpo0f0mf2g/ember-url-hash-polyfill/package",
    "cluster_key": "c4c6d044edb6ac92a5dc40b256723f367d8e249d0d9522f3deb88beca9929f0e",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node bundle.js",
        "runs_on": "always",
        "file_chain": [
          "bundle.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "detached_child",
          "download_then_exec",
          "dropped_binary"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 3.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 3.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 2.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 2.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 2.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 0.25
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in bundle.js; candidates there may be missing",
      "bundle.js: webpack bundle (~1847 modules). Worm package code read in full: entry main() block, modules _utils_os(71197), _lib_utils(54704), github(82036), aws(56686), gcp(9897), truffle(94913), npm(40766), and embedded scripts /tmp/processor.sh(941) and /tmp/migrate-repos.sh(26935).",
      "bundle.js: bundled AWS/GCP/Octokit/grpc SDK modules audited by sink inventory; all sink hits (Function() eval, fetch, spawn@92323 = AWS credential_process, writeFile@75274 = AWS SSO token, atob, grpc readFileSync) are library behaviour. Nothing left unread.",
      "Dropped prefilled gate g7 (GOOGLE_APPLICATION_CREDENTIALS || google_application_credentials): it is google-auth-library's _tryGetApplicationCredentialsFromEnvironmentVariable, library code, not a worm gate. Candidates k_8518fb5657, k_ccc1cce0b7, q_18dd9a4edc dropped as library_code.",
      "All worm gates except the SKIP_TRUFFLE early-return (g5, in set) are out of set (candidate null): they sit in main()'s orchestration which the bundle extractor did not walk as package code. They force manual review.",
      "Re-entry/self-propagation: updatePackage injects postinstall 'node bundle.js' and copies the running bundle.js into the victim's package before npm publish (worm). getToken() runs execSync('gh auth token') in the GitHubModule constructor, unconditional.",
      "Repair: wrappers traced. extraction/migration write /tmp/*.sh and spawn detached; makeRepo creates the repo via octokit; updatePackage fetches, patches and npm-publishes the tarball; isAvailable downloads trufflehog, scanFilesystem spawns it.",
      "Repair: getAllSecretValues (AWS, GCP) call the Secrets Manager list/get APIs. main() reads process.env.NPM_TOKEN before parseNpmToken (.npmrc), so c8's NPM_TOKEN recipe holds.",
      "Repair: GCPModule.initialize needs both getProjectId and getClient truthy (if(t&&r)), read through isValid(), so g4 is c10 && c12. Off GCE both resolve from local env vars, credential files or gcloud config with no server check, so both are target_artifact.",
      "Repair: g4's recipe variable GOOGLE_APPLICATION_CREDENTIALS must name a readable credential file; ~/.config/gcloud/application_default_credentials.json or GCE metadata also satisfy c10, and key-file project_id, gcloud config or metadata also satisfy c12."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": [
        "tar",
        "gzip",
        "npm"
      ],
      "reason": "NpmModule.updatePackage self-propagation shells out to tar and gzip to repack the victim tarball and to npm to publish the trojanized version; it aborts the step if `which tar` fails"
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash",
        "curl",
        "jq"
      ],
      "reason": "the dropped /tmp/processor.sh and /tmp/migrate-repos.sh are bash scripts that use curl and jq against the GitHub API"
    },
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "github[.]com:443"
      ],
      "reason": "install-time payload contacts the GitHub API (repo creation, extraction, migration), the npm registry (token validation and self-propagation publish) and GitHub releases (trufflehog download); AWS and GCP cloud APIs are also contacted when their credential gates open"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3096423,
            "end_byte": 3096445,
            "node_type": "binary_expression",
            "sha256": "e5df35ecfd8652b8",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "darwin",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3096469,
            "end_byte": 3096492,
            "node_type": "binary_expression",
            "sha256": "db343c99a634b5e9",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3334440,
            "end_byte": 3334473,
            "node_type": "lexical_declaration",
            "sha256": "a532a80dba3663a3",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3334499,
            "end_byte": 3334562,
            "node_type": "call_expression",
            "sha256": "068a699c2ec7b939",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "gh auth token",
        "accessor": "stdout"
      }
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "String.startsWith",
      "operator": "startswith",
      "value": "ghp_",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732718,
            "end_byte": 3732738,
            "node_type": "call_expression",
            "sha256": "4543339d6327e436",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "String.startsWith",
      "operator": "startswith",
      "value": "gho_",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732740,
            "end_byte": 3732760,
            "node_type": "call_expression",
            "sha256": "d6596d920f76693c",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "octokit.rest.users.getAuthenticated",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732687,
            "end_byte": 3732704,
            "node_type": "await_expression",
            "sha256": "9f5f505771c5df5f",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "server_response",
      "api": "fetch",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732934,
            "end_byte": 3732958,
            "node_type": "await_expression",
            "sha256": "3042db409eddc70b",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "fetch",
        "target": "hxxps://registry[.]npmjs[.]org/-/whoami",
        "accessor": "other"
      }
    },
    {
      "id": "c9",
      "category": "server_response",
      "api": "STSClient.GetCallerIdentityCommand",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733639,
            "end_byte": 3733656,
            "node_type": "await_expression",
            "sha256": "ec0596a72c556404",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "GoogleAuth.getClient",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 235744,
            "end_byte": 235771,
            "node_type": "await_expression",
            "sha256": "06cb2fd3534b9633",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "target_artifact",
      "api": "GoogleAuth.getProjectId",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 235711,
            "end_byte": 235741,
            "node_type": "await_expression",
            "sha256": "e409f9820ec21421",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "env_var",
      "api": "process.env.SKIP_TRUFFLE",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1391595ecc",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733274,
            "end_byte": 3733298,
            "node_type": "member_expression",
            "sha256": "60c63f19f1d2a95a",
            "line": 2
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "(c3 || c4) && (c1 || c2) && (c5 || c6) && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732528,
            "end_byte": 3732655,
            "node_type": "binary_expression",
            "sha256": "43b18ab23523e424",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3",
            "c4",
            "c1",
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732708,
            "end_byte": 3732764,
            "node_type": "binary_expression",
            "sha256": "f27de419caf3c9c6",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5",
            "c6",
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "GitHub repo exfiltration and org migration run only on Linux or Mac, and only when a real GitHub PAT/OAuth token (ghp_/gho_) belongs to an authenticated user",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "spawn_process",
          "persistence",
          "exfil",
          "write_file"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732765,
            "end_byte": 3732880,
            "node_type": "statement_block",
            "sha256": "c57919320836b7b7",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3732772,
              "end_byte": 3732787,
              "node_type": "call_expression",
              "sha256": "5933766791cbd291",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3732772,
              "end_byte": 3732787,
              "node_type": "call_expression",
              "sha256": "5933766791cbd291",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3732772,
              "end_byte": 3732787,
              "node_type": "call_expression",
              "sha256": "5933766791cbd291",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3732837,
              "end_byte": 3732879,
              "node_type": "call_expression",
              "sha256": "9b600fd574b32151",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c8 && (c1 || c2)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732931,
            "end_byte": 3733077,
            "node_type": "sequence_expression",
            "sha256": "1370957abbfc1def",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c1",
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "self-propagation (republishing trojanized versions of the maintainer's own packages) runs only with a valid npm token and only on Linux or Mac",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "self_propagation",
          "modify_other_packages",
          "download",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "NPM_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733078,
            "end_byte": 3733205,
            "node_type": "statement_block",
            "sha256": "970ffb02d4c65121",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733171,
              "end_byte": 3733190,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733171,
              "end_byte": 3733190,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733171,
              "end_byte": 3733190,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733171,
              "end_byte": 3733190,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733639,
            "end_byte": 3733691,
            "node_type": "binary_expression",
            "sha256": "e52087fff0a3f713",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c9"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "AWS Secrets Manager values are collected only when AWS credentials present on the host validate via STS GetCallerIdentity",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "file_present": [
            "~/.aws/credentials"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733659,
            "end_byte": 3733690,
            "node_type": "assignment_expression",
            "sha256": "17ff0661f0b8a520",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733668,
              "end_byte": 3733690,
              "node_type": "call_expression",
              "sha256": "e9dee37943f7b7c9",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c10 && c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733702,
            "end_byte": 3733754,
            "node_type": "binary_expression",
            "sha256": "13cb321700c05d76",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c10",
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "GCP Secret Manager values are collected only when Google application-default credentials on the host resolve a project and client",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "GOOGLE_APPLICATION_CREDENTIALS": null,
            "GOOGLE_CLOUD_PROJECT": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733722,
            "end_byte": 3733753,
            "node_type": "assignment_expression",
            "sha256": "7abaf1b9aa5d02ea",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733731,
              "end_byte": 3733753,
              "node_type": "call_expression",
              "sha256": "4c76d3bf8f164fa3",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c11",
      "guards": [
        {
          "candidate": "q_f7cde5e9da",
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733271,
            "end_byte": 3733373,
            "node_type": "if_statement",
            "sha256": "6792b9c8d70dfe9c",
            "line": 2
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c11"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "the SKIP_TRUFFLE env var is a kill switch: when it is set the trufflehog download-and-scan is skipped, otherwise it runs",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "exec_downloaded",
          "cred_read"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SKIP_TRUFFLE"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733373,
            "end_byte": 3733584,
            "node_type": "stmt_range",
            "sha256": "9e0dd827e15179f8",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733403,
              "end_byte": 3733419,
              "node_type": "call_expression",
              "sha256": "503401ceef52dfd5",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733403,
              "end_byte": 3733419,
              "node_type": "call_expression",
              "sha256": "503401ceef52dfd5",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733468,
              "end_byte": 3733487,
              "node_type": "call_expression",
              "sha256": "1533827532af681e",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733468,
              "end_byte": 3733487,
              "node_type": "call_expression",
              "sha256": "1533827532af681e",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g6",
      "hook": "postinstall",
      "expression": "c3 || c4",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734101,
            "end_byte": 3734178,
            "node_type": "binary_expression",
            "sha256": "0756bcfac23f657e",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c3",
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the collected GitHub/AWS/GCP/npm/trufflehog data is exfiltrated by creating a public GitHub repo named Shai-Hulud, which needs a usable GitHub token",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_TOKEN": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734122,
            "end_byte": 3734178,
            "node_type": "await_expression",
            "sha256": "bf9fd3315e85d377",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3734128,
              "end_byte": 3734178,
              "node_type": "call_expression",
              "sha256": "521d943a5598542e",
              "line": 2
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
      "recon",
      "cred_read",
      "spawn_process"
    ],
    "gated": [
      "spawn_process",
      "persistence",
      "exfil",
      "write_file",
      "self_propagation",
      "modify_other_packages",
      "download",
      "cred_read",
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "webpack_bundling",
      "minification",
      "very_long_lines",
      "small payload hidden among bundled AWS/GCP/Octokit/grpc SDKs"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api[.]github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7;",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/repos/trufflesecurity/trufflehog/releases/latest",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/trufflesecurity/trufflehog/releases/download/$",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall runs a webpack-bundled worm (Shai-Hulud) that steals GitHub, npm, AWS and GCP credentials, downloads trufflehog to scan the filesystem for secrets, exfiltrates everything to an attacker-created GitHub repo and to webhook.site via an injected Actions workflow, and self-propagates by republishing trojanized versions of the maintainer's own npm packages. Install-time behaviour is unambiguously malicious.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Most gates and conditions are out of set (candidate null): the worm payload sits in main()'s orchestration, which the bundle extractor did not walk as package code.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "e9caa29fdbdf9e76"
    },
    "units_summary": [
      {
        "file": "bundle.js",
        "derived_from": null,
        "bundler": "webpack",
        "count": 1847,
        "entry": "71197",
        "by_role": {
          "unknown": 1802,
          "library": 38,
          "package": 7
        }
      }
    ],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_8518fb5657",
        "reason_code": "library_code",
        "note": "google-auth-library ADC env lookup (GOOGLE_APPLICATION_CREDENTIALS)",
        "anchor": {
          "file": "bundle.js",
          "derived_from": null,
          "start_byte": 985105,
          "end_byte": 985147,
          "node_type": "member_expression",
          "sha256": "c2e788090a847026",
          "line": 2
        }
      },
      {
        "candidate": "k_ccc1cce0b7",
        "reason_code": "library_code",
        "note": "google-auth-library ADC env lookup (google_application_credentials)",
        "anchor": {
          "file": "bundle.js",
          "derived_from": null,
          "start_byte": 985149,
          "end_byte": 985191,
          "node_type": "member_expression",
          "sha256": "b73615be56a5eba8",
          "line": 2
        }
      },
      {
        "candidate": "q_18dd9a4edc",
        "reason_code": "library_code",
        "note": "guard of google-auth-library _tryGetApplicationCredentialsFromEnvironmentVariable",
        "anchor": {
          "file": "bundle.js",
          "derived_from": null,
          "start_byte": 985192,
          "end_byte": 985224,
          "node_type": "if_statement",
          "sha256": "48e600711ac14ed7",
          "line": 2
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 3,
    "conditions_in_set": 1,
    "conditions_out_of_set": 11,
    "guard_candidates": 103,
    "gates_in_set": 1,
    "gates_out_of_set": 5,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "c9",
      "c10",
      "c12",
      "g1",
      "g2",
      "g3",
      "g4",
      "g6"
    ],
    "anchor_refusals": 0
  }
}
```
