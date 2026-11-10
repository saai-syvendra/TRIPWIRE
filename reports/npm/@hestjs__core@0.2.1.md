# npm @hestjs/core@0.2.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-14 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`@hestjs/core` 0.2.1 is a compromised release whose `package.json` adds `postinstall: node bundle.js`. `bundle.js` is a minified webpack bundle; its entry `main()` is the Shai-Hulud worm. On every install it collects system/runtime info, reads GitHub (env `GITHUB_TOKEN` or `gh auth token`) and npm (`NPM_TOKEN` or `.npmrc`) credentials, and downloads TruffleHog if needed and runs a filesystem scan, all with no gate in front; then it runs several gated behaviours. The main gate runs the GitHub repo-worm and GitHub Actions persistence only on Linux/macOS when a GitHub PAT starting `ghp_`/`gho_` is present; a second gate republishes the maintainer's other npm packages (with the same postinstall) on Linux/macOS when the npm token validates; two further gates harvest AWS secrets when STS accepts the host's credentials and GCP secrets when GoogleAuth finds a project and client on the host. The final upload to a new GitHub repo named "Shai-Hulud" is dead code, because `repoExists` is not awaited and `!Promise` is always false.

## Execution

- **postinstall** `node bundle.js`: runs bundle.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c1 \|\| c2) && (c3 \|\| c4) && (c5 \|\| c6) && c7 (c1: process.env.GITHUB_TOKEN truthy; c2: target_artifact exists; c3: os == linux; c4: os == darwin; c5: process.env.GITHUB_TOKEN startswith ghp_; c6: process.env.GITHUB_TOKEN startswith gho_; c7: server_response truthy) | then | 4 | write_file, spawn_process, self_propagation, persistence, exfil | os=linux; env_var=GITHUB_TOKEN=ghp_<valid classic PAT>; network=api[.]github[.]com:443=reachable |
| g2 | postinstall | c8 && (c3 \|\| c4) (c8: server_response truthy; c3: os == linux; c4: os == darwin) | then | 2 | self_propagation, modify_other_packages, spawn_process | os=linux; env_var=NPM_TOKEN=(set); network=registry[.]npmjs[.]org:443=reachable |
| g4 | postinstall | c10 (c10: server_response truthy) | then | 1 | cred_read | file_present=~/.aws/credentials; network=sts[.]amazonaws[.]com:443=reachable |
| g5 | postinstall | c11 (c11: target_artifact truthy) | then | 1 | cred_read | env_var=GOOGLE_APPLICATION_CREDENTIALS=(set); network=oauth2[.]googleapis[.]com:443=reachable |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability

Grounding: 0 of 10 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c10, c11, g1, g2, g4, g5.

## Requirements

- network: api[.]github[.]com:443 (octokit API calls for user/orgs and the GitHub worm; latest TruffleHog release lookup)
- network: github[.]com:443 (TruffleHog release archive download, which the scan needs when no binary is present)
- network: registry[.]npmjs[.]org:443 (npm token validation (whoami) and package republish)
- network: webhook[.]site:443 (exfiltration sink used by the injected GitHub Actions workflow)
- network: sts[.]amazonaws[.]com:443 (AWS STS GetCallerIdentity to validate stolen AWS credentials)
- network: secretsmanager[.]us-east-1[.]amazonaws[.]com:443 (AWS Secrets Manager list/get across regions)
- network: oauth2[.]googleapis[.]com:443 (GCP auth for Secret Manager access)
- installed_tool: git (migrate-repos.sh mirror-clones and pushes repositories)
- installed_tool: curl (embedded bash scripts call the GitHub API via curl)
- installed_tool: jq (embedded bash scripts parse GitHub API JSON)
- installed_tool: tar (npm updatePackage repacks tarballs; trufflehog archive extraction)
- installed_tool: npm (republishing trojanised packages)

## Behaviour

- Ungated: recon, cred_read, download, exec_downloaded
- Gated: write_file, spawn_process, self_propagation, persistence, exfil, modify_other_packages, cred_read

## Notes

- Install-time entry is `postinstall` -> `node bundle.js` (`runs_on: always`); `main().catch(()=>process.exit(0))` swallows all errors (`silent_failure`).
- Coverage: all package-written webpack modules read in full (entry `main`, `utils_os`, `lib_utils`, `GitHubModule`, `AWSModule`, `GCPModule`, `NpmModule`, `TruffleHogModule`, `Application`, and the two embedded bash scripts `processor.sh`/`migrate-repos.sh`); bundled SDKs (octokit, aws-sdk-js-v3, google-auth/secret-manager, node-fetch, grpc) audited by sink inventory, all hits library behaviour; nothing unread.
- Dropped the only prefilled gate (g7) and its conditions: they are `GOOGLE_APPLICATION_CREDENTIALS` reads inside google-auth-library, not package code.
- All recorded conditions/gates are out-of-set (candidate null) because they sit in the bundle; several gate conditions are `server_response` (API/STS success) and are out of scope. The in-scope machine gates are the OS check (linux/darwin) that fences the repo-worm and the npm republish, and the GCP credential check.
- Repair round 1 removed two gates. The old g3 (repo upload) is a dead branch: `F.repoExists` is async and not awaited. The old g6 (TruffleHog) is not a gate: `isAvailable()` downloads a missing binary, so only the network is needed, which is a requirement. Ids c9, c12, g3 and g6 are left unused so other claim ids stay stable.
- `formatOutput(pe)` only reaches the dead `makeRepo` call, so main() does not upload the collected AWS, GCP, npm and TruffleHog data in this version.
- `extraction()`/`migration()` write bash scripts to `/tmp` and spawn them detached; `processor.sh` plants a GitHub Actions workflow that posts `${{ toJSON(secrets) }}` to a webhook, and `migrate-repos.sh` mirror-clones private repos to new public attacker repos. `updatePackage()` repacks and republishes other packages via `npm publish`.
- family_hint "Shai-Hulud" is grounded in code: repo name "Shai-Hulud", branch "shai-hulud", workflow filename, and "Shai-Hulud Repository/Migration" descriptions.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@hestjs/core",
    "version": "0.2.1",
    "archive_sha256": "df945a5b0777fb9c5bfde20c2cf959b005109c45b4d08aca81357b86ef3ab02a",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-14",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-14-@hestjs_core-v0.2.1.zip",
    "package_root": "layer0/tmp/tmpx3u96_cj/@hestjs-core/package",
    "cluster_key": "664952742849f3daa6a5c1786f55878e602c105af169a52fc674a024c0a2f803",
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
          "direct_script"
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
      "bundle.js: minified webpack bundle. All package-written modules read in full (entry main, utils_os, lib_utils, GitHubModule, AWSModule, GCPModule, NpmModule, TruffleHogModule, Application, two embedded bash scripts).",
      "bundle.js: bundled SDKs (octokit, aws-sdk-js-v3, google-auth/secretmanager, node-fetch, grpc) audited by sink inventory; all hits library behaviour; nothing left unread.",
      "Prefilled gate g7 / conditions on GOOGLE_APPLICATION_CREDENTIALS are inside google-auth-library (GoogleAuth reads the credential file), not package code; dropped as library_code.",
      "Delays (2-3s) are octokit/retry library backoffs in bundled SDK code, not payload timers.",
      "extraction() writes /tmp/processor.sh and migration() writes /tmp/migrate-repos.sh then spawns each detached (detached_child); the spawned bash scripts add a GitHub Actions workflow that exfils repo secrets to a webhook and mirror-clone private repos to new public attacker repos.",
      "updatePackage() rewrites a maintainer's other packages to add postinstall 'node bundle.js' and republishes them (self-propagation / modify_other_packages).",
      "Dead branch, not a gate: main() ends with F.isAuthenticated()&&!F.repoExists(\"Shai-Hulud\")&&await F.makeRepo(...). repoExists is async and not awaited, so !Promise is always false and makeRepo never runs. No gate or exfil is recorded for it; the old g3 and c9 are removed.",
      "formatOutput(pe), the collected report, is only passed to that dead makeRepo call, so the harvested AWS, GCP, npm and TruffleHog data is not uploaded by main() in this version. Exfil here is the workflow and migration scripts behind g1.",
      "TruffleHog is not a gate: isAvailable() is !!installedStatus||await install(), so a missing binary is downloaded and the scan still runs. existsSync(binaryPath) only reuses an existing copy (plumbing) and the download is a requirement. The old g6 and c12 are removed; the scan is ungated.",
      "validateToken() returns null when no npm token is set (NPM_TOKEN or .npmrc), so c8 can only hold with a token; a 401 or non-ok response throws into the surrounding catch, which skips g2.",
      "c11 is target_artifact: getProjectId and getClient read env vars, a credential file or gcloud config without validating anything against a server for a key file. On a GCE host both can instead come from the metadata server."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]github[.]com:443",
      "reason": "octokit API calls for user/orgs and the GitHub worm; latest TruffleHog release lookup"
    },
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "TruffleHog release archive download, which the scan needs when no binary is present"
    },
    {
      "axis": "network",
      "value": "registry[.]npmjs[.]org:443",
      "reason": "npm token validation (whoami) and package republish"
    },
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "exfiltration sink used by the injected GitHub Actions workflow"
    },
    {
      "axis": "network",
      "value": "sts[.]amazonaws[.]com:443",
      "reason": "AWS STS GetCallerIdentity to validate stolen AWS credentials"
    },
    {
      "axis": "network",
      "value": "secretsmanager[.]us-east-1[.]amazonaws[.]com:443",
      "reason": "AWS Secrets Manager list/get across regions"
    },
    {
      "axis": "network",
      "value": "oauth2[.]googleapis[.]com:443",
      "reason": "GCP auth for Secret Manager access"
    },
    {
      "axis": "installed_tool",
      "value": "git",
      "reason": "migrate-repos.sh mirror-clones and pushes repositories"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "embedded bash scripts call the GitHub API via curl"
    },
    {
      "axis": "installed_tool",
      "value": "jq",
      "reason": "embedded bash scripts parse GitHub API JSON"
    },
    {
      "axis": "installed_tool",
      "value": "tar",
      "reason": "npm updatePackage repacks tarballs; trufflehog archive extraction"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "republishing trojanised packages"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3335001,
            "end_byte": 3335025,
            "node_type": "member_expression",
            "sha256": "d84c66c7d4334fd6",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "gh auth token",
        "accessor": "stdout"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3335052,
            "end_byte": 3335122,
            "node_type": "call_expression",
            "sha256": "1094b1400341772c",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "linux",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3096976,
            "end_byte": 3096998,
            "node_type": "binary_expression",
            "sha256": "e5df35ecfd8652b8",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "os",
      "api": "os.platform()",
      "operator": "==",
      "value": "darwin",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3097022,
            "end_byte": 3097045,
            "node_type": "binary_expression",
            "sha256": "db343c99a634b5e9",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "startswith",
      "value": "ghp_",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733756,
            "end_byte": 3733776,
            "node_type": "call_expression",
            "sha256": "4543339d6327e436",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "startswith",
      "value": "gho_",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733778,
            "end_byte": 3733798,
            "node_type": "call_expression",
            "sha256": "d6596d920f76693c",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "octokit.rest.users.getAuthenticated",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733731,
            "end_byte": 3733742,
            "node_type": "call_expression",
            "sha256": "4412f44e790a0b1e",
            "line": 2
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "server_response",
      "api": "fetch",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 1437861,
            "end_byte": 1438104,
            "node_type": "call_expression",
            "sha256": "b23b2adaad9e617a",
            "line": 2
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "server_response",
      "api": "STSClient.send(GetCallerIdentityCommand)",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 2629102,
            "end_byte": 2629131,
            "node_type": "binary_expression",
            "sha256": "f1c19da09178c2fc",
            "line": 2
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "target_artifact",
      "api": "GoogleAuth.getProjectId / GoogleAuth.getClient",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 235775,
            "end_byte": 235779,
            "node_type": "binary_expression",
            "sha256": "e47fbcae4fe44d54",
            "line": 2
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
      "expression": "(c1 || c2) && (c3 || c4) && (c5 || c6) && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733566,
            "end_byte": 3733693,
            "node_type": "binary_expression",
            "sha256": "619c58c7c29ceb28",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733746,
            "end_byte": 3733802,
            "node_type": "binary_expression",
            "sha256": "792983cf985aca12",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2",
            "c5",
            "c6",
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "The bash repo-worm and GitHub Actions persistence only run on Linux/macOS when a GitHub PAT (ghp_/gho_) is present and the authenticated user resolves.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file",
          "spawn_process",
          "self_propagation",
          "persistence",
          "exfil"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_TOKEN": "ghp_<valid classic PAT>"
          },
          "network": {
            "api[.]github[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [
          "env_var"
        ],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733803,
            "end_byte": 3733918,
            "node_type": "statement_block",
            "sha256": "9dc9ba7133cdfbfc",
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
              "start_byte": 3335690,
              "end_byte": 3335734,
              "node_type": "call_expression",
              "sha256": "cb0fecb3b7f3271f",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733810,
                  "end_byte": 3733825,
                  "node_type": "call_expression",
                  "sha256": "a92cbb502673a786",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335462,
                  "end_byte": 3335754,
                  "node_type": "method_definition",
                  "sha256": "0765a50a5a2f9e0f",
                  "line": 2
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
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c8 && (c3 || c4)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733966,
            "end_byte": 3734243,
            "node_type": "if_statement",
            "sha256": "74c8098162cb0fba",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c3",
            "c4"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "npm republish self-propagation only runs when an npm token (NPM_TOKEN or ~/.npmrc) validates via whoami, and only on Linux/macOS where the repack step works; nothing selects a victim by identity.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "self_propagation",
          "modify_other_packages",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "NPM_TOKEN": null
          },
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734116,
            "end_byte": 3734243,
            "node_type": "statement_block",
            "sha256": "f7e3fa4fa71d7319",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3734209,
              "end_byte": 3734228,
              "node_type": "call_expression",
              "sha256": "dca5d53ddf87a291",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734575,
            "end_byte": 3734629,
            "node_type": "binary_expression",
            "sha256": "232359b8991f5c3e",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c10"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Harvests AWS Secrets Manager values across regions only when AWS credentials on the host validate via STS GetCallerIdentity.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "file_present": [
            "~/.aws/credentials"
          ],
          "network": {
            "sts[.]amazonaws[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734605,
            "end_byte": 3734628,
            "node_type": "call_expression",
            "sha256": "f9fb71f93dd1eff7",
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
              "start_byte": 3734605,
              "end_byte": 3734628,
              "node_type": "call_expression",
              "sha256": "f9fb71f93dd1eff7",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734640,
            "end_byte": 3734694,
            "node_type": "binary_expression",
            "sha256": "946f936e70f5e961",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c11"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Harvests GCP Secret Manager values only when GoogleAuth finds a project id and a client from credentials on the host; both are read from one credential source and tested together in `t&&r`.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "GOOGLE_APPLICATION_CREDENTIALS": null
          },
          "network": {
            "oauth2[.]googleapis[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734670,
            "end_byte": 3734693,
            "node_type": "call_expression",
            "sha256": "51636d49b07b208e",
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
              "start_byte": 3734670,
              "end_byte": 3734693,
              "node_type": "call_expression",
              "sha256": "51636d49b07b208e",
              "line": 2
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read",
      "download",
      "exec_downloaded"
    ],
    "gated": [
      "write_file",
      "spawn_process",
      "self_propagation",
      "persistence",
      "exfil",
      "modify_other_packages",
      "cred_read"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "minified code",
      "webpack bundle"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api[.]github[.]com",
        "role": "c2"
      },
      {
        "indicator": "hxxps://webhook[.]site/bb8c…",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://sts[.]amazonaws[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://secretsmanager[.]",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://oauth2[.]googleapis[.]com/token",
        "role": "exfil_sink"
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
  "family_hint": "Shai-Hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall runs node bundle.js, a webpack-bundled worm that harvests GitHub, npm, AWS and GCP credentials, runs TruffleHog over the filesystem, plants a GitHub Actions workflow that posts repo secrets to a webhook, mirror-clones private repos to new public repos, and republishes the maintainer's other packages with the same postinstall. Its upload to a new GitHub repo is dead code (unawaited repoExists). This is the Shai-Hulud campaign; @hestjs/core 0.2.1 is a compromised release.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and gates are out-of-set (candidate null): added from package code inside a large minified webpack bundle.",
    "The GitHub worm, npm republish and AWS harvest gates partly rest on server_response conditions (API/STS success); g1's GITHUB_TOKEN value (a server-valid ghp_ token) is inferred, not literal.",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "c3666bf1e299b167"
    },
    "units_summary": [
      {
        "file": "bundle.js",
        "derived_from": null,
        "bundler": "webpack",
        "count": 1848,
        "entry": "71197",
        "by_role": {
          "unknown": 1802,
          "library": 38,
          "package": 8
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
        "note": "google-auth-library GoogleAuth reading GOOGLE_APPLICATION_CREDENTIALS, not package code",
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
        "note": "google-auth-library GoogleAuth credential-file read, not package code",
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
        "note": "guard inside google-auth-library credential loading, not package code",
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
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 3,
    "conditions_in_set": 0,
    "conditions_out_of_set": 10,
    "guard_candidates": 102,
    "gates_in_set": 0,
    "gates_out_of_set": 4,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "c10",
      "c11",
      "g1",
      "g2",
      "g4",
      "g5"
    ],
    "anchor_refusals": 0
  }
}
```
