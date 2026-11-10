# npm @ctrl/shared-torrent@6.3.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-15 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

The `postinstall` hook runs `node bundle.js`, a ~3.7MB webpack bundle that is the Shai-Hulud worm. Its `main()` collects system info, reads GitHub (env or `gh auth token`), npm (`NPM_TOKEN` or `.npmrc`), AWS and GCP credentials, downloads and runs TruffleHog to scan the home directory for verified secrets, and publishes the whole harvest to a new public GitHub repo named "Shai-Hulud" (triple base64). On Linux/macOS with a `ghp_`/`gho_` GitHub token it writes and spawns two detached bash scripts that inject a `.github/workflows/shai-hulud-workflow.yml` (which posts CI secrets to webhook[.]site) and republish private org repos as public. With a valid npm token on Linux/macOS it self-propagates by republishing the maintainer's packages with the same malicious `postinstall`. Six install-time gates decide what runs: an OS check (linux||darwin) in front of both the GitHub scripts and the npm republish, GitHub-token presence (exfil repo + extraction/migration), the token prefix and user lookup, a valid-npm-token check, an STS identity check for AWS, GCP credentials plus a project id, and an operator `SKIP_TRUFFLE` switch over the TruffleHog scan.

## Execution

- **postinstall** `node bundle.js`: runs bundle.js; direct_script, detached_child, download_then_exec, dropped_binary; errors hidden.
- **prepare** `npm run build`: runs on git or local install only; no package files; inline_shell.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g12 | postinstall | c13 (c13: process.env.SKIP_TRUFFLE falsy) | then | 1 | download, exec_downloaded, cred_read | env_var_absent=SKIP_TRUFFLE |
| g20 | postinstall | (c85 \|\| c86) && (c87 \|\| c88) && (c89 \|\| c90) && c91 (c85: process.env.GITHUB_TOKEN truthy; c86: target_artifact truthy; c87: os == linux; c88: os == darwin; c89: process.env.GITHUB_TOKEN startswith ghp_; c90: process.env.GITHUB_TOKEN startswith gho_; c91: server_response truthy) | then | 4 | write_file, spawn_process, persistence, exfil | os=linux; env_var=GITHUB_TOKEN=ghp_ |
| g21 | postinstall | c85 \|\| c86 (c85: process.env.GITHUB_TOKEN truthy; c86: target_artifact truthy) | then | 1 | exfil | env_var=GITHUB_TOKEN=(set) |
| g22 | postinstall | c92 && (c87 \|\| c88) (c92: server_response truthy; c87: os == linux; c88: os == darwin) | then | 2 | modify_other_packages, self_propagation | os=linux; env_var=NPM_TOKEN=(set) |
| g23 | postinstall | c93 (c93: server_response truthy) | then | 1 | cred_read | file_present=~/.aws/credentials |
| g24 | postinstall | c94 && c95 (c94: target_artifact truthy; c95: target_artifact truthy) | then | 2 | cred_read | env_var=GOOGLE_CLOUD_PROJECT=(set); file_present=~/.config/gcloud/application_default_credentials.json |

Gate intent: g12 activate/enables/unclear; g20 activate/enables/targeting; g21 activate/enables/data_availability; g22 activate/enables/targeting; g23 activate/enables/data_availability; g24 activate/enables/data_availability

Grounding: 1 of 12 conditions and 1 of 6 gates from the candidate set; out of set, pending verification: c85, c86, c87, c88, c89, c90, c91, c92, c93, c94, c95, g20, g21, g22, g23, g24.

## Requirements

- network: api[.]github[.]com:443, registry[.]npmjs[.]org:443, github[.]com:443, sts[.]amazonaws[.]com:443, secretsmanager[.]us-east-1[.]amazonaws[.]com:443, secretmanager[.]googleapis[.]com:443, oauth2[.]googleapis[.]com:443, webhook[.]site:443 (GitHub and npm registry APIs, victim cloud secret stores, the TruffleHog GitHub release download, and the webhook[.]site sink the injected CI workflow posts to)
- installed_tool: tar (updatePackage() runs `which tar` and aborts the republish if tar is absent; it also shells out to gzip and tar)
- installed_tool: curl (the embedded processor.sh and migrate-repos.sh call curl against the GitHub API)
- installed_tool: jq (processor.sh and migrate-repos.sh parse GitHub API JSON with jq)
- installed_tool: git (migrate-repos.sh clones and pushes repositories over git)

## Behaviour

- Ungated: recon, cred_read
- Gated: download, exec_downloaded, cred_read, write_file, spawn_process, persistence, exfil, modify_other_packages, self_propagation

## Notes

- Only `c13` (SKIP_TRUFFLE) survived from the prefilled candidates. The prefilled `c8`/`c9`/`g7` (GOOGLE_APPLICATION_CREDENTIALS) are google-auth-library's ADC env lookup and were dropped as `library_code`; GCP credential availability is captured at package level by `g24` (`GCPModule.isValid`).
- Every gate except `g12` is out of set (`candidate: null`): the worm's decisions sit in `main()` and the package modules, which the extractor reached only through unresolved method calls, so it prefilled no guards there. The record is flagged for manual review for this reason.
- `c91` (getUser), `c92` (validateToken) and `c93` (AWS STS GetCallerIdentity) are server_response checks (GitHub, npm or AWS must accept the credential); they are kept as conditions but `in_scope: false`. `g23`'s recipe still names `~/.aws/credentials`, where `fromIni` reads the credentials, but a planted file alone will not pass STS. `c94`/`c95` (GCP client and project id) are target_artifact availability tests; `isValid` needs both.
- `g20`'s scripts are recorded as `persistence` (the injected workflow) and `exfil` (private repos mirrored to public ones), not `self_propagation`: neither copies this package. `self_propagation` is on `g22` only.
- AWS/GCP secret theft contacts the victim's own cloud APIs and metadata servers; those are the data source, not attacker infrastructure, and were summarised rather than listed per region in `reachability`.
- `prepare` (`npm run build` -> `tsc`) only runs on git/local installs and is benign build plumbing.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@ctrl/shared-torrent",
    "version": "6.3.1",
    "archive_sha256": "d2b1d42ae11f34b5e2e985c41429453c3e12e79e74c93e06ef62176a0d9b1935",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-15",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-15-@ctrl_shared-torrent-v6.3.1.zip",
    "package_root": "layer0/tmp/tmpq7b0gr_l/@ctrl-shared-torrent/package",
    "cluster_key": "3a2ee93228f8847c01675946011124c104e4b4626ea23ea18b41a5bb7f975ffb",
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
      },
      {
        "hook": "prepare",
        "command": "npm run build",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
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
      "prepare: runs 'tsc' from a dependency or the system; its code is out of scope",
      "generator truncated: some helpers walked under only 2 guard contexts in bundle.js; candidates there may be missing",
      "bundle.js: ~3.7MB webpack bundle, one line. Package modules (os 71197, utils 54704, github 82036, aws 56686, gcp 9897, truffle 94913, npm 40766), the main() entry and the two embedded bash scripts (941, 26935) read in full.",
      "bundle.js: ~1800 vendored units (aws-sdk-v3, google-auth, grpc-js, octokit, bottleneck) audited by sink inventory, every hit library behaviour. Not diffed against the real @ctrl/shared-torrent release.",
      "Only c13 (SKIP_TRUFFLE) survived the prefilled candidates. c8/c9 (GOOGLE_APPLICATION_CREDENTIALS, lowercase too) and guard g7 are google-auth-library's ADC env lookup, dropped as library_code; GCP availability is g24.",
      "GitHub token comes from process.env.GITHUB_TOKEN or `gh auth token` (c85/c86). The ghp_/gho_ prefix (c89/c90), getUser() (c91) and validateToken() (c92) need GitHub/npm to accept the token; c91/c92 are server_response, out of scope.",
      "extraction() writes /tmp/processor.sh and spawns it detached with the token as argv; it injects .github/workflows/shai-hulud-workflow.yml that posts CI toJSON(secrets) to webhook[.]site.",
      "migration() writes /tmp/migrate-repos.sh and spawns it detached; it republishes private/internal org repos as public repos under the victim account.",
      "AWS/GCP theft contacts victim cloud APIs (sts.amazonaws[.]com, secretsmanager, secretmanager.googleapis[.]com) and metadata servers (169[.]254[.]169[.]254, metadata.google[.]internal); those are the data source, not attacker infra.",
      "makeRepo() creates a public GitHub repo 'Shai-Hulud' and commits the full harvest (env, GitHub/npm/AWS/GCP secrets, TruffleHog results) triple-base64 encoded; primary exfil channel (g21).",
      "Recipes: g20/g22 follow isLinux() and startsWith(\"ghp_\"); NPM_TOKEN is read in main() and validateToken() returns null without it.",
      "g24 file is the ADC path bundled google-auth checks (_tryGetApplicationCredentialsFromWellKnownFile). initialize() also needs a project id (c95); google-auth takes it from GCLOUD_PROJECT/GOOGLE_CLOUD_PROJECT, the credential, gcloud config or metadata.",
      "g23: AWS isValid() is true only when an STS GetCallerIdentity reply has UserId, Account and Arn (c93, server_response). existsSync in parseAwsProfiles only adds profile names; the default profile is tried anyway. The recipe file is where fromIni reads credentials.",
      "g20: processor.sh plants a push-triggered workflow in each repo the token reaches (persistence). migrate-repos.sh mirrors private org repos, strips workflows and makes the copies public (exfil). Neither copies this package, so self_propagation stays on g22 only."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "github[.]com:443",
        "sts[.]amazonaws[.]com:443",
        "secretsmanager[.]us-east-1[.]amazonaws[.]com:443",
        "secretmanager[.]googleapis[.]com:443",
        "oauth2[.]googleapis[.]com:443",
        "webhook[.]site:443"
      ],
      "reason": "GitHub and npm registry APIs, victim cloud secret stores, the TruffleHog GitHub release download, and the webhook[.]site sink the injected CI workflow posts to"
    },
    {
      "axis": "installed_tool",
      "value": "tar",
      "reason": "updatePackage() runs `which tar` and aborts the republish if tar is absent; it also shells out to gzip and tar"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the embedded processor.sh and migrate-repos.sh call curl against the GitHub API"
    },
    {
      "axis": "installed_tool",
      "value": "jq",
      "reason": "processor.sh and migrate-repos.sh parse GitHub API JSON with jq"
    },
    {
      "axis": "installed_tool",
      "value": "git",
      "reason": "migrate-repos.sh clones and pushes repositories over git"
    }
  ],
  "conditions": [
    {
      "id": "c13",
      "category": "env_var",
      "api": "process.env.SKIP_TRUFFLE",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_77bdb136e1",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733719,
            "end_byte": 3733743,
            "node_type": "member_expression",
            "sha256": "60c63f19f1d2a95a",
            "line": 2
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c85",
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
            "start_byte": 3334893,
            "end_byte": 3334917,
            "node_type": "member_expression",
            "sha256": "d84c66c7d4334fd6",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c86",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
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
            "start_byte": 3334944,
            "end_byte": 3335007,
            "node_type": "call_expression",
            "sha256": "068a699c2ec7b939",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c87",
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
            "start_byte": 3096868,
            "end_byte": 3096890,
            "node_type": "binary_expression",
            "sha256": "e5df35ecfd8652b8",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c88",
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
            "start_byte": 3096914,
            "end_byte": 3096937,
            "node_type": "binary_expression",
            "sha256": "db343c99a634b5e9",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c89",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
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
            "start_byte": 3733163,
            "end_byte": 3733183,
            "node_type": "call_expression",
            "sha256": "4543339d6327e436",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c90",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
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
            "start_byte": 3733185,
            "end_byte": 3733205,
            "node_type": "call_expression",
            "sha256": "d6596d920f76693c",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c91",
      "category": "server_response",
      "api": "octokit.rest.users.getAuthenticated",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733138,
            "end_byte": 3733149,
            "node_type": "call_expression",
            "sha256": "73fc124f98546d99",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c92",
      "category": "server_response",
      "api": "fetch()",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733385,
            "end_byte": 3733403,
            "node_type": "call_expression",
            "sha256": "187c8ad4db4c3443",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c93",
      "category": "server_response",
      "api": "STSClient.send",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 2628994,
            "end_byte": 2629023,
            "node_type": "binary_expression",
            "sha256": "f1c19da09178c2fc",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c94",
      "category": "target_artifact",
      "api": "google.auth.GoogleAuth.getClient",
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
            "start_byte": 235750,
            "end_byte": 235771,
            "node_type": "call_expression",
            "sha256": "e626233baaf9b198",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c95",
      "category": "target_artifact",
      "api": "google.auth.GoogleAuth.getProjectId",
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
            "start_byte": 235717,
            "end_byte": 235741,
            "node_type": "call_expression",
            "sha256": "d085a7486d0533bb",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g12",
      "hook": "postinstall",
      "expression": "c13",
      "guards": [
        {
          "candidate": "q_f7f275916e",
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733716,
            "end_byte": 3733818,
            "node_type": "if_statement",
            "sha256": "6792b9c8d70dfe9c",
            "line": 2
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
      "purpose_reason": "operator-controlled switch: the TruffleHog filesystem secret scan runs unless SKIP_TRUFFLE is set",
      "then": {
        "behaviours": [
          "download",
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
            "start_byte": 3733818,
            "end_byte": 3734029,
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
              "start_byte": 3733848,
              "end_byte": 3733864,
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
              "start_byte": 3733913,
              "end_byte": 3733932,
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
              "start_byte": 3733913,
              "end_byte": 3733932,
              "node_type": "call_expression",
              "sha256": "1533827532af681e",
              "line": 2
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g20",
      "hook": "postinstall",
      "expression": "(c85 || c86) && (c87 || c88) && (c89 || c90) && c91",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732970,
            "end_byte": 3733326,
            "node_type": "if_statement",
            "sha256": "0da67802c087bd27",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c85",
            "c86",
            "c87",
            "c88"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733150,
            "end_byte": 3733325,
            "node_type": "if_statement",
            "sha256": "d6b6675bee45cd97",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c89",
            "c90",
            "c91"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "the workflow injection and the private org repo mirroring are bash scripts run only on Linux or macOS, and only when a ghp_/gho_ GitHub token is present and the user resolves",
      "then": {
        "behaviours": [
          "write_file",
          "spawn_process",
          "persistence",
          "exfil"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_TOKEN": "ghp_"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733210,
            "end_byte": 3733325,
            "node_type": "statement_block",
            "sha256": "c57919320836b7b7",
            "line": 2
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3335548,
              "end_byte": 3335581,
              "node_type": "call_expression",
              "sha256": "06707c2d39e30c99",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733217,
                  "end_byte": 3733232,
                  "node_type": "call_expression",
                  "sha256": "5933766791cbd291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335354,
                  "end_byte": 3335646,
                  "node_type": "method_definition",
                  "sha256": "0765a50a5a2f9e0f",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3335582,
              "end_byte": 3335626,
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
                  "start_byte": 3733217,
                  "end_byte": 3733232,
                  "node_type": "call_expression",
                  "sha256": "5933766791cbd291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335354,
                  "end_byte": 3335646,
                  "node_type": "method_definition",
                  "sha256": "0765a50a5a2f9e0f",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3335582,
              "end_byte": 3335626,
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
                  "start_byte": 3733217,
                  "end_byte": 3733232,
                  "node_type": "call_expression",
                  "sha256": "5933766791cbd291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335354,
                  "end_byte": 3335646,
                  "node_type": "method_definition",
                  "sha256": "0765a50a5a2f9e0f",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3335940,
              "end_byte": 3335989,
              "node_type": "call_expression",
              "sha256": "dd15174c29f16e70",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733282,
                  "end_byte": 3733324,
                  "node_type": "call_expression",
                  "sha256": "9b600fd574b32151",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335646,
                  "end_byte": 3336223,
                  "node_type": "method_definition",
                  "sha256": "8e91f0b39402abfc",
                  "line": 2
                }
              }
            ]
          }
        ],
        "min_conditions": 4
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g21",
      "hook": "postinstall",
      "expression": "c85 || c86",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734546,
            "end_byte": 3734623,
            "node_type": "binary_expression",
            "sha256": "0756bcfac23f657e",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c85",
            "c86"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "a GitHub token is needed to create the public 'Shai-Hulud' repo that receives the harvested secrets",
      "then": {
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
            "start_byte": 3734573,
            "end_byte": 3734623,
            "node_type": "call_expression",
            "sha256": "521d943a5598542e",
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
              "start_byte": 3734573,
              "end_byte": 3734623,
              "node_type": "call_expression",
              "sha256": "521d943a5598542e",
              "line": 2
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g22",
      "hook": "postinstall",
      "expression": "c92 && (c87 || c88)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733373,
            "end_byte": 3733650,
            "node_type": "if_statement",
            "sha256": "963a40ba6fbea8f8",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c92",
            "c87",
            "c88"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "npm self-propagation republishes the maintainer's packages only on Linux or macOS with a valid npm token",
      "then": {
        "behaviours": [
          "modify_other_packages",
          "self_propagation"
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
            "start_byte": 3733523,
            "end_byte": 3733650,
            "node_type": "statement_block",
            "sha256": "970ffb02d4c65121",
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
              "start_byte": 3733616,
              "end_byte": 3733635,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 1439674,
                  "end_byte": 1441548,
                  "node_type": "method_definition",
                  "sha256": "9a6c9efbb43db953",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733616,
              "end_byte": 3733635,
              "node_type": "call_expression",
              "sha256": "cb1192bef7486f31",
              "line": 2
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 1439674,
                  "end_byte": 1441548,
                  "node_type": "method_definition",
                  "sha256": "9a6c9efbb43db953",
                  "line": 2
                }
              }
            ]
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g23",
      "hook": "postinstall",
      "expression": "c93",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734084,
            "end_byte": 3734136,
            "node_type": "binary_expression",
            "sha256": "e52087fff0a3f713",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c93"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "AWS Secrets Manager is harvested only when AWS credentials resolve and STS accepts them",
      "then": {
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
            "start_byte": 3734104,
            "end_byte": 3734135,
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
              "start_byte": 3734113,
              "end_byte": 3734135,
              "node_type": "call_expression",
              "sha256": "e9dee37943f7b7c9",
              "line": 2
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g24",
      "hook": "postinstall",
      "expression": "c94 && c95",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734147,
            "end_byte": 3734199,
            "node_type": "binary_expression",
            "sha256": "13cb321700c05d76",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c94",
            "c95"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "GCP Secret Manager is harvested only when application default credentials resolve to a project and client",
      "then": {
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "GOOGLE_CLOUD_PROJECT": null
          },
          "file_present": [
            "~/.config/gcloud/application_default_credentials.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734167,
            "end_byte": 3734198,
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
              "start_byte": 3734176,
              "end_byte": 3734198,
              "node_type": "call_expression",
              "sha256": "4c76d3bf8f164fa3",
              "line": 2
            },
            "witness": []
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read"
    ],
    "gated": [
      "download",
      "exec_downloaded",
      "cred_read",
      "write_file",
      "spawn_process",
      "persistence",
      "exfil",
      "modify_other_packages",
      "self_propagation"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "webpack bundle (single ~3.7MB line)",
      "minified identifiers",
      "embedded bash payloads as escaped string literals",
      "triple base64 encoding of the exfiltrated secret blob"
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
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "c2"
      },
      {
        "indicator": "hxxps://webhook[.]site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7;",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/repos/trufflesecurity/trufflehog/releases/latest",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://github[.]com/trufflesecurity/trufflehog/releases/download/$",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://$GITHUB_TOKEN@github[.]com/$TARGET_USER/$migration_name.git",
        "role": "c2"
      },
      {
        "indicator": "hxxps://sts[.]amazonaws[.]com",
        "role": "c2"
      },
      {
        "indicator": "hxxps://secretmanager[.]googleapis[.]com",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall runs a bundled worm (the Shai-Hulud campaign) that harvests GitHub, npm, AWS and GCP credentials, downloads and runs TruffleHog to scan the filesystem for more secrets, and exfiltrates everything to a public GitHub repo named 'Shai-Hulud'. It self-propagates by republishing the maintainer's npm packages with the same postinstall, injects a secret-stealing GitHub Actions workflow into the victim's repositories, and mirrors private org repositories into public ones. The legitimate @ctrl/shared-torrent has no install code, so this version is a maintainer compromise.",
  "confidence": "high",
  "label_disagreement": false,
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "9338c2663e07559f"
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
        "note": "google-auth-library _tryGetApplicationCredentialsFromEnvironmentVariable ADC lookup (process.env.GOOGLE_APPLICATION_CREDENTIALS); not a package decision",
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
        "note": "google-auth-library ADC lookup, lowercase process.env.google_application_credentials fallback; library code",
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
        "note": "early-return guard inside google-auth-library's ADC env lookup; library code, not an install gate",
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
      "c85",
      "c86",
      "c87",
      "c88",
      "c89",
      "c90",
      "c91",
      "c92",
      "c93",
      "c94",
      "c95",
      "g20",
      "g21",
      "g22",
      "g23",
      "g24"
    ],
    "anchor_refusals": 0
  }
}
```
