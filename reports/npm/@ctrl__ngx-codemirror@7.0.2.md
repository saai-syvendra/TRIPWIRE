# npm @ctrl/ngx-codemirror@7.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-15 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The compromised 7.0.2 release adds `"postinstall": "node bundle.js"`, a 3.7 MB webpack bundle that holds the Shai-Hulud worm next to bundled Octokit, AWS SDK and google-auth libraries. With no gate in front it collects system info and looks for a GitHub token (`GITHUB_TOKEN` or `gh auth token`) and an npm token (`NPM_TOKEN` or `.npmrc`). On Linux or macOS, a classic `ghp_`/`gho_` GitHub token that resolves to a user opens the GitHub stage. That stage drops and detaches `/tmp/processor.sh`, which pushes a workflow that sends repo secrets to webhook[.]site, and `/tmp/migrate-repos.sh`, which mirrors private org repos into public copies. A valid npm token on Linux or macOS opens self-propagation: the worm republishes the maintainer's packages with this bundle as their postinstall. Unless `SKIP_TRUFFLE` is set, it downloads TruffleHog and scans the home directory. Working AWS profiles or GCP ADC lead to Secret Manager dumps. When any GitHub token exists, everything collected (including all of `process.env`) is pushed to a public `Shai-Hulud` repo.

## Execution

- **postinstall** `node bundle.js`: runs bundle.js; direct_script, detached_child, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c1 \|\| c2) && (c3 \|\| c4) && (c5 \|\| c6) && c7 (c1: process.env.GITHUB_TOKEN truthy; c2: target_artifact exists; c3: os == linux; c4: os == darwin; c5: target_artifact startswith ghp_; c6: target_artifact startswith gho_; c7: server_response exists) | then | 4 | write_file, spawn_process, exfil, persistence | os=linux; env_var=GITHUB_TOKEN=ghp_<valid classic PAT with repo and workflow scopes>; network=api[.]github[.]com:443=reachable; installed_tool=bash, curl, jq, git |
| g2 | postinstall | (c8 \|\| c9) && c10 && (c3 \|\| c4) (c8: process.env.NPM_TOKEN truthy; c9: target_artifact regex (?:_authToken\|:_authToken)=([a-zA-Z0-9\-._~+/]+=*); c10: server_response exists; c3: os == linux; c4: os == darwin) | then | 3 | self_propagation, modify_other_packages, download, write_file | os=linux; env_var=NPM_TOKEN=<valid npm publish token>; network=registry[.]npmjs[.]org:443=reachable; installed_tool=tar, gzip, npm |
| g3 | postinstall | c11 (c11: process.env.SKIP_TRUFFLE falsy) | then | 1 | download, exec_downloaded, cred_read, write_file, delete_file | env_var_absent=SKIP_TRUFFLE; network=api[.]github[.]com:443=reachable, github[.]com:443=reachable; installed_tool=tar |
| g4 | postinstall | c12 (c12: server_response exists) | then | 1 | cred_read | file_present=~/.aws/credentials; network=sts[.]us-east-1[.]amazonaws[.]com:443=reachable |
| g5 | postinstall | c13 && c14 (c13: target_artifact exists; c14: target_artifact exists) | then | 2 | cred_read | env_var=GCLOUD_PROJECT=(set); file_present=~/.config/gcloud/application_default_credentials.json; network=oauth2[.]googleapis[.]com:443=reachable, secretmanager[.]googleapis[.]com:443=reachable |
| g6 | postinstall | c1 \|\| c2 (c1: process.env.GITHUB_TOKEN truthy; c2: target_artifact exists) | then | 1 | exfil | env_var=GITHUB_TOKEN=(set); network=api[.]github[.]com:443=reachable |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability; g3 activate/enables/unclear; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/enables/data_availability

Grounding: 5 of 14 conditions and 1 of 6 gates from the candidate set; out of set, pending verification: c5, c6, c7, c8, c9, c10, c12, c13, c14, g1, g2, g4, g5, g6.

## Requirements

- network: api[.]github[.]com:443, github[.]com:443, registry[.]npmjs[.]org:443, sts[.]us-east-1[.]amazonaws[.]com:443, secretsmanager.<region>.amazonaws.com:443, oauth2[.]googleapis[.]com:443, secretmanager[.]googleapis[.]com:443 (GitHub API (exfil repo, TruffleHog release lookup), TruffleHog download and git mirror pushes, npm whoami/search/publish, AWS and GCP secret managers)
- installed_tool: tar (TruffleHog archive extraction and npm tarball repack (`which tar` aborts propagation when missing))
- installed_tool: gzip (npm tarball repack in updatePackage)
- installed_tool: npm (npm publish of the trojanised tarballs)
- installed_tool: bash (dropped /tmp/processor.sh and /tmp/migrate-repos.sh are bash scripts)
- installed_tool: curl (both dropped scripts call the GitHub API with curl)
- installed_tool: jq (both dropped scripts parse API responses with jq)
- installed_tool: git (migrate-repos.sh mirrors org repos with git clone/push)
- other: /tmp/github-migration absent (migration() calls mkdirSync on it before spawning migrate-repos.sh; if it exists the spawn is skipped)

## Behaviour

- Ungated: recon, cred_read
- Gated: write_file, spawn_process, exfil, persistence, self_propagation, modify_other_packages, download, exec_downloaded, cred_read, delete_file

## Notes

- Payload modules were read in full, including both embedded bash scripts. The library units were audited by sink inventory, not diffed against upstream.
- The tool's string_array/dynamic_eval signals come from library code. The payload is only minified.
- The GitHub-token prefix check excludes Actions `ghs_` tokens, so in CI only the exfil repo step runs, not the workflow injection or migration.
- AWS (`c12`) and npm whoami (`c10`) are server-response conditions, so they are out of scope. GCP validity needs both a project ID (`c13`) and a credential client (`c14`): `GCLOUD_PROJECT` alone gives a project ID, but `getClient` still throws with no credentials, and the well-known ADC file alone gives a client but no project ID, so the `g5` recipe sets both. The ADC path comes from google-auth's well-known file lookup and the AWS path from `parseAwsProfiles`, so neither recipe file is guessed.
- Prefilled delays are mostly library timers. Endpoints were pruned to the attacker-relevant ones; SDK and documentation URLs were removed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@ctrl/ngx-codemirror",
    "version": "7.0.2",
    "archive_sha256": "6c0ae59058abfbe99a58a57435bd801c69576372b2d7a70a18debe7d51476c50",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-15",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-15-@ctrl_ngx-codemirror-v7.0.2.zip",
    "package_root": "layer0/tmp/tmpfzzi8gl2/@ctrl-ngx-codemirror/package",
    "cluster_key": "e4541aa36f463bfc18466292f4f276ed6277ec814cc5bf336ae1575106c0c396",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
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
          "download_then_exec"
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
      },
      {
        "site": "bundle.js:2",
        "seconds": 90.0
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in bundle.js; candidates there may be missing",
      "bundle.js (3.7 MB webpack): package modules 71197 (os), 54704 (npmrc), 82036 (GitHub), 56686 (AWS), 9897 (GCP), 94913 (TruffleHog), 40766 (npm), 941 and 26935 (embedded bash) and the entry read in full.",
      "bundle.js: remaining units (Octokit, AWS SDK v3, google-auth-library, gax/grpc, node-fetch, bottleneck) audited by sink inventory; only library process launch is google-auth pluggable executable auth, opt-in. Nothing unread.",
      "Not a string-array obfuscator: the tool's string_array/dynamic_eval signals come from library code (Function() in a polyfill). Payload modules are plain minified JS.",
      "Prefilled delays are mostly library timers; package ones are makeRepo 3 s wait, TruffleHog kill grace 2 s and the 90 s TruffleHog scan timeout (added).",
      "GitHub gate: the ghp_/gho_ prefix test excludes GitHub Actions ghs_ tokens and fine-grained PATs, so in CI the workflow injection and org migration do not run; the Shai-Hulud exfil repo is still attempted.",
      "/tmp/processor.sh (module 941) needs repo and workflow scopes, then pushes .github/workflows/shai-hulud-workflow.yml to every repo; scope checks are server responses inside the child, not recorded as conditions.",
      "migration(): mkdirSync('/tmp/github-migration') throws after the first org (or if the folder exists), so only the first org's migrate-repos.sh is started. Not a deliberate check; listed as a requirement.",
      "npm updatePackage: `which tar` failure only aborts that step (requirement). It bumps patch version, sets postinstall to node bundle.js, copies process.argv[1] in and runs npm publish.",
      "TruffleHog: platform/arch switches only pick the release asset name and rm vs del (plumbing). existsSync on ./trufflehog reuses an existing binary (plumbing). AWS profile enumeration from ~/.aws files is plumbing; the default profile is always tried.",
      "main().catch and the final process.exit(0) hide every failure; each module wraps its work in empty catches.",
      "g5 recipe: c14 reads HOME/.config/gcloud/application_default_credentials.json (existsSync in the well-known file lookup), but c13 runs first and never reads that file, so GCLOUD_PROJECT supplies the project.",
      "g5 alternatives in google-auth: project from GOOGLE_CLOUD_PROJECT, a GOOGLE_APPLICATION_CREDENTIALS file, gcloud config or GCE metadata; client from that env file or GCE. The recipe gives one sufficient set. The ADC file must parse as a credential."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]github[.]com:443, github[.]com:443, registry[.]npmjs[.]org:443, sts[.]us-east-1[.]amazonaws[.]com:443, secretsmanager.<region>.amazonaws.com:443, oauth2[.]googleapis[.]com:443, secretmanager[.]googleapis[.]com:443",
      "reason": "GitHub API (exfil repo, TruffleHog release lookup), TruffleHog download and git mirror pushes, npm whoami/search/publish, AWS and GCP secret managers"
    },
    {
      "axis": "installed_tool",
      "value": "tar",
      "reason": "TruffleHog archive extraction and npm tarball repack (`which tar` aborts propagation when missing)"
    },
    {
      "axis": "installed_tool",
      "value": "gzip",
      "reason": "npm tarball repack in updatePackage"
    },
    {
      "axis": "installed_tool",
      "value": "npm",
      "reason": "npm publish of the trojanised tarballs"
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "dropped /tmp/processor.sh and /tmp/migrate-repos.sh are bash scripts"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "both dropped scripts call the GitHub API with curl"
    },
    {
      "axis": "installed_tool",
      "value": "jq",
      "reason": "both dropped scripts parse API responses with jq"
    },
    {
      "axis": "installed_tool",
      "value": "git",
      "reason": "migrate-repos.sh mirrors org repos with git clone/push"
    },
    {
      "axis": "other",
      "value": "/tmp/github-migration absent",
      "reason": "migration() calls mkdirSync on it before spawning migrate-repos.sh; if it exists the spawn is skipped"
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
          "candidate": "k_294d7bd9e6",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3334921,
            "end_byte": 3334922,
            "node_type": "identifier",
            "sha256": "e3b98a4da31a127d",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
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
          "candidate": "k_33c0df6b33",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3335018,
            "end_byte": 3335019,
            "node_type": "identifier",
            "sha256": "e3b98a4da31a127d",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
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
          "candidate": "k_4c8345d30d",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3097160,
            "end_byte": 3097171,
            "node_type": "binary_expression",
            "sha256": "a91ccdbffbda4fe6",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
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
          "candidate": "k_f4a912faef",
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3097180,
            "end_byte": 3097192,
            "node_type": "binary_expression",
            "sha256": "47484a3590838b81",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "String.prototype.startsWith",
      "operator": "startswith",
      "value": "ghp_",
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "String.prototype.startsWith",
      "operator": "startswith",
      "value": "gho_",
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "server_response",
      "api": "octokit.rest.users.getAuthenticated",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3732784,
            "end_byte": 3732805,
            "node_type": "member_expression",
            "sha256": "94b3a999b234706b",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "fs.readFileSync",
      "operator": "regex",
      "value": "(?:_authToken|:_authToken)=([a-zA-Z0-9\\-._~+/]+=*)",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "~/.npmrc",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 2601668,
            "end_byte": 2601675,
            "node_type": "binary_expression",
            "sha256": "b567adeba58f219c",
            "line": 2
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "server_response",
      "api": "fetch (registry /-/whoami)",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "env_var",
      "api": "process.env.SKIP_TRUFFLE",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c12",
      "category": "server_response",
      "api": "STSClient.send(GetCallerIdentityCommand)",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "target_artifact",
      "api": "GoogleAuth.getProjectId",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
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
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "target_artifact",
      "api": "GoogleAuth.getClient",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
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
            "start_byte": 3732970,
            "end_byte": 3733326,
            "node_type": "if_statement",
            "sha256": "0da67802c087bd27",
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
            "start_byte": 3733150,
            "end_byte": 3733325,
            "node_type": "if_statement",
            "sha256": "d6b6675bee45cd97",
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
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "GitHub worm stage runs only on Linux/macOS (bash scripts) with a classic PAT or OAuth token that resolves to a user",
      "then": {
        "behaviours": [
          "write_file",
          "spawn_process",
          "exfil",
          "persistence"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_TOKEN": "ghp_<valid classic PAT with repo and workflow scopes>"
          },
          "network": {
            "api[.]github[.]com:443": "reachable"
          },
          "installed_tool": [
            "bash",
            "curl",
            "jq",
            "git"
          ]
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
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733217,
              "end_byte": 3733232,
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
              "start_byte": 3733217,
              "end_byte": 3733232,
              "node_type": "call_expression",
              "sha256": "5933766791cbd291",
              "line": 2
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3733217,
              "end_byte": 3733232,
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
              "start_byte": 3733282,
              "end_byte": 3733324,
              "node_type": "call_expression",
              "sha256": "9b600fd574b32151",
              "line": 2
            },
            "witness": []
          }
        ],
        "min_conditions": 4
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "(c8 || c9) && c10 && (c3 || c4)",
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
            "c8",
            "c9",
            "c10",
            "c3",
            "c4"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "npm self-propagation needs an npm token (NPM_TOKEN or .npmrc) that whoami accepts; limited to Linux/macOS",
      "then": {
        "behaviours": [
          "self_propagation",
          "modify_other_packages",
          "download",
          "write_file"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "NPM_TOKEN": "<valid npm publish token>"
          },
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          },
          "installed_tool": [
            "tar",
            "gzip",
            "npm"
          ]
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
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 1441337,
              "end_byte": 1441360,
              "node_type": "call_expression",
              "sha256": "d79cc6baab02f56c",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733590,
                  "end_byte": 3733648,
                  "node_type": "call_expression",
                  "sha256": "aa8dbc6a951ab152",
                  "line": 2
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733596,
                  "end_byte": 3733647,
                  "node_type": "arrow_function",
                  "sha256": "4de55ca345418096",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733616,
                  "end_byte": 3733635,
                  "node_type": "call_expression",
                  "sha256": "cb1192bef7486f31",
                  "line": 2
                }
              },
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
            "behaviour": "modify_other_packages",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 1441337,
              "end_byte": 1441360,
              "node_type": "call_expression",
              "sha256": "d79cc6baab02f56c",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733590,
                  "end_byte": 3733648,
                  "node_type": "call_expression",
                  "sha256": "aa8dbc6a951ab152",
                  "line": 2
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733596,
                  "end_byte": 3733647,
                  "node_type": "arrow_function",
                  "sha256": "4de55ca345418096",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733616,
                  "end_byte": 3733635,
                  "node_type": "call_expression",
                  "sha256": "cb1192bef7486f31",
                  "line": 2
                }
              },
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
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c11",
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
            "c11"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "author-set opt-out variable that skips the TruffleHog download and filesystem secret scan",
      "then": {
        "behaviours": [
          "download",
          "exec_downloaded",
          "cred_read",
          "write_file",
          "delete_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "SKIP_TRUFFLE"
          ],
          "network": {
            "api[.]github[.]com:443": "reachable",
            "github[.]com:443": "reachable"
          },
          "installed_tool": [
            "tar"
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
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3600533,
              "end_byte": 3600560,
              "node_type": "call_expression",
              "sha256": "6af08ce7a8d741e9",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733848,
                  "end_byte": 3733864,
                  "node_type": "call_expression",
                  "sha256": "503401ceef52dfd5",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601574,
                  "end_byte": 3601645,
                  "node_type": "method_definition",
                  "sha256": "007d98f8d081fc01",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601630,
                  "end_byte": 3601644,
                  "node_type": "call_expression",
                  "sha256": "e755cec05d024171",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601124,
                  "end_byte": 3601401,
                  "node_type": "method_definition",
                  "sha256": "17c26a6cbff99833",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601264,
                  "end_byte": 3601298,
                  "node_type": "call_expression",
                  "sha256": "78ff2c38e819287b",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3600366,
                  "end_byte": 3600651,
                  "node_type": "method_definition",
                  "sha256": "f22ab74ce44f5dec",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 3601006,
              "end_byte": 3601039,
              "node_type": "call_expression",
              "sha256": "8c4a830e9d1d07cf",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3733848,
                  "end_byte": 3733864,
                  "node_type": "call_expression",
                  "sha256": "503401ceef52dfd5",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601574,
                  "end_byte": 3601645,
                  "node_type": "method_definition",
                  "sha256": "007d98f8d081fc01",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601630,
                  "end_byte": 3601644,
                  "node_type": "call_expression",
                  "sha256": "e755cec05d024171",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601124,
                  "end_byte": 3601401,
                  "node_type": "method_definition",
                  "sha256": "17c26a6cbff99833",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3601305,
                  "end_byte": 3601326,
                  "node_type": "call_expression",
                  "sha256": "a74f90a2399ef544",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3600651,
                  "end_byte": 3601124,
                  "node_type": "method_definition",
                  "sha256": "df48e545be819daf",
                  "line": 2
                }
              }
            ]
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c12",
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
            "c12"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "AWS Secrets Manager dump runs only when some ~/.aws profile yields a valid STS caller identity",
      "then": {
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "file_present": [
            "~/.aws/credentials"
          ],
          "network": {
            "sts[.]us-east-1[.]amazonaws[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734103,
            "end_byte": 3734136,
            "node_type": "parenthesized_expression",
            "sha256": "df5b7afa31043f62",
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
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c13 && c14",
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
            "c13",
            "c14"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "GCP Secret Manager dump runs only when Application Default Credentials resolve to a project and client",
      "then": {
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "GCLOUD_PROJECT": null
          },
          "file_present": [
            "~/.config/gcloud/application_default_credentials.json"
          ],
          "network": {
            "oauth2[.]googleapis[.]com:443": "reachable",
            "secretmanager[.]googleapis[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734166,
            "end_byte": 3734199,
            "node_type": "parenthesized_expression",
            "sha256": "856b3a8ee53dee61",
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
    },
    {
      "gate_id": "g6",
      "hook": "postinstall",
      "expression": "c1 || c2",
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
            "c1",
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "collected env, tokens and secrets are pushed to a public Shai-Hulud repo only when a GitHub token was found",
      "then": {
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_TOKEN": null
          },
          "network": {
            "api[.]github[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734567,
            "end_byte": 3734623,
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
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read"
    ],
    "gated": [
      "write_file",
      "spawn_process",
      "exfil",
      "persistence",
      "self_propagation",
      "modify_other_packages",
      "download",
      "exec_downloaded",
      "cred_read",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "webpack bundle with minified identifiers",
      "payload modules hidden among bundled AWS, GCP and Octokit SDKs",
      "bash scripts embedded as string modules and dropped to /tmp",
      "exfiltrated data triple base64 encoded"
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
        "indicator": "hxxps://$GITHUB_TOKEN@github[.]com/$TARGET_USER/$migration_name.git",
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
  "assessment_reason": "postinstall runs a webpack bundle that steals GitHub, npm, AWS and GCP credentials, runs TruffleHog over the home directory, pushes the results to a public GitHub repo, injects a secret-exfiltrating workflow into the victim's repos, mirrors private org repos public and republishes the maintainer's npm packages with itself.",
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
        "note": "google-auth-library reading GOOGLE_APPLICATION_CREDENTIALS for ADC; folded into GCP condition c13",
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
        "note": "google-auth-library lowercase google_application_credentials fallback",
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
        "note": "google-auth-library ADC env var branch",
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
    "condition_sites_cited": 5,
    "guards_cited": 1,
    "candidates_dropped": 3,
    "conditions_in_set": 5,
    "conditions_out_of_set": 9,
    "guard_candidates": 103,
    "gates_in_set": 1,
    "gates_out_of_set": 5,
    "out_of_set_ids": [
      "c5",
      "c6",
      "c7",
      "c8",
      "c9",
      "c10",
      "c12",
      "c13",
      "c14",
      "g1",
      "g2",
      "g4",
      "g5",
      "g6"
    ],
    "anchor_refusals": 0
  }
}
```
