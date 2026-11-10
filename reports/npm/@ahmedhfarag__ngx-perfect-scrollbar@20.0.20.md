# npm @ahmedhfarag/ngx-perfect-scrollbar@20.0.20

**Source:** datadog · **Source label:** malicious · **Released:** 2025-09-15 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

A `postinstall` hook runs `node bundle.js`, a 3.7 MB webpack bundle of the Shai-Hulud worm. Without any gate, it collects system info and the full process environment, reads a GitHub token from `GITHUB_TOKEN` or `gh auth token`, downloads TruffleHog from GitHub releases and runs it over the home directory. Five gates follow. g1: a GitHub `ghp_`/`gho_` token, Linux or macOS and a working token lead to two detached `/tmp` bash scripts. One pushes a secrets-exfiltrating workflow to every repo, the other mirrors private org repos as public. g2: an npm token (from `NPM_TOKEN` or `.npmrc` `_authToken`) that `npm whoami` accepts, on Linux or macOS, leads to republishing up to 20 of the maintainer's packages with this bundle as `postinstall`. g3 and g4 pull AWS Secrets Manager and GCP Secret Manager values when local cloud credentials validate. g5 uploads everything, triple base64 encoded, to a public `Shai-Hulud` GitHub repo when a GitHub token exists.

## Execution

- **postinstall** `node bundle.js`: runs bundle.js; direct_script, detached_child, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | (c1 \|\| c2) && (c3 \|\| c4) && (c5 \|\| c6) && c7 (c1: process.env.GITHUB_TOKEN truthy; c2: target_artifact exists; c3: os == linux; c4: os == darwin; c5: target_artifact startswith ghp_; c6: target_artifact startswith gho_; c7: server_response truthy) | then | 4 | write_file, spawn_process | os=linux; env_var=GITHUB_TOKEN=ghp_; network=api[.]github[.]com:443=reachable |
| g2 | postinstall | (c8 \|\| (c9 && c10)) && c11 && (c3 \|\| c4) (c8: process.env.NPM_TOKEN truthy; c9: target_artifact exists; c10: target_artifact regex (?:_authToken\|:_authToken)=([a-zA-Z0-9\-._~+/]+=*); c11: server_response truthy; c3: os == linux; c4: os == darwin) | then | 3 | download, modify_other_packages, self_propagation | os=linux; env_var=NPM_TOKEN=(set); network=registry[.]npmjs[.]org:443=reachable |
| g3 | postinstall | c12 (c12: server_response truthy) | then | 1 | cred_read | file_present=~/.aws/credentials; network=sts[.]us-east-1[.]amazonaws[.]com:443=reachable |
| g4 | postinstall | c13 && c14 (c13: other truthy; c14: other truthy) | then | 2 | cred_read | env_var=GOOGLE_APPLICATION_CREDENTIALS=(set); network=oauth2[.]googleapis[.]com:443=reachable |
| g5 | postinstall | c1 \|\| c2 (c1: process.env.GITHUB_TOKEN truthy; c2: target_artifact exists) | then | 1 | exfil | env_var=GITHUB_TOKEN=(set); network=api[.]github[.]com:443=reachable |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability

Grounding: 0 of 14 conditions and 0 of 5 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, g1, g2, g3, g4, g5.

## Requirements

- network: api[.]github[.]com:443, github[.]com:443 (GitHub API for repo creation, exfil upload, workflow injection and repo mirroring; TruffleHog release lookup and download)
- network: registry[.]npmjs[.]org:443 (npm whoami token validation, maintainer package search, tarball download and npm publish)
- network: sts[.]us-east-1[.]amazonaws[.]com:443, secretsmanager[.]us-east-1[.]amazonaws[.]com:443 (AWS STS GetCallerIdentity and Secrets Manager calls across 14 regions)
- network: oauth2[.]googleapis[.]com:443, secretmanager[.]googleapis[.]com:443 (GCP credential exchange and Secret Manager access)
- installed_tool: tar, gzip, npm (TruffleHog extraction and repacking and republishing of the victim's npm packages)
- installed_tool: bash, curl, jq, git (embedded processor.sh and migrate-repos.sh scripts)
- file_present: ~/.aws/credentials (AWS credentials are loaded only through fromIni profiles (default, AWS_PROFILE and profiles in ~/.aws files))

## Behaviour

- Ungated: recon, cred_read, spawn_process, download, write_file, exec_downloaded, delete_file
- Gated: write_file, spawn_process, download, modify_other_packages, self_propagation, cred_read, exfil

## Notes

- Every gate condition is out of set: the extractor did not reach the package modules (they load `fs`/`child_process` through `n.t.bind` dynamic imports), and its only prefilled gate was google-auth-library code, which I dropped.
- The witnesses go through class methods on instances built in `main()` (`new GitHubModule`, etc.), so the verifier may return `name_only_link` for some call/def hops.
- The scope checks inside processor.sh (`x-oauth-scopes` must include `repo` and `workflow`) sit inside a bash string. They are not cited as conditions; they are noted in execution.notes.
- The webhook endpoint in the injected workflow is only contacted later from GitHub Actions, not at install.
- Library units were audited by sink inventory rather than read line by line. They were not diffed against upstream SDK releases.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@ahmedhfarag/ngx-perfect-scrollbar",
    "version": "20.0.20",
    "archive_sha256": "e03af02027dca7b872b16f326bf5f9d3d2a3957686966bf7470da358b059ca16",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-09-15",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2025-09-15-@ahmedhfarag_ngx-perfect-scrollbar-v20.0.20.zip",
    "package_root": "layer0/tmp/tmpodpgumq0/@ahmedhfarag-ngx-perfect-scrollbar/package",
    "cluster_key": "a0972f036ae62e7e10c96bb8e2d541ce6c97d27a73eca0c3b79c9f9deb1efc4e",
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
        "seconds": 3.0
      },
      {
        "site": "bundle.js:2",
        "seconds": 2.0
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in bundle.js; candidates there may be missing",
      "bundle.js: webpack bundle, 1848 modules. Package code read in full: trailing main(), modules 71197 (os utils), 54704 (utils), 32304, 82036 (GitHub), 40766 (npm), 56686 (AWS), 9897 (GCP), 94913 (TruffleHog), 941 and 26935 (embedded bash scripts).",
      "bundle.js: remaining units (Octokit, AWS SDK v3, google-auth-library, google-gax/grpc-js, protobufjs, lodash, node-fetch, bottleneck) audited by sink inventory; child_process, Function/eval and homedir hits all library behaviour; nothing unread.",
      "Delays: 3 s setTimeout in makeRepo before uploading data.json; 2 s SIGKILL grace in TruffleHog scan. Library zero-length timers removed. TruffleHog scan also has a 90 s kill timeout.",
      "Embedded /tmp/processor.sh (module 941) exits unless the token's x-oauth-scopes include repo and workflow (server_response checks inside a bash string, not citable as decision nodes), then pushes a shai-hulud workflow to every repo.",
      "The injected workflow posts toJSON(secrets) to hxxps://webhook[.]site/bb8c… when it runs on GitHub Actions later; that endpoint is not contacted at install, so it is left out of reachability.",
      "Embedded /tmp/migrate-repos.sh (module 26935) mirrors every private/internal repo of each org into a new repo under the victim's account and makes it public; exits early if curl, jq or git is missing (requirements).",
      "Windows checks in TruffleHogModule (trufflehog.exe vs trufflehog, del vs rm, skip chmod) only change file names and commands for the same behaviour; not gates.",
      "TruffleHog download is skipped when a binary already sits in cwd (existsSync reuse, plumbing). isAvailable() is true when the download and tar extract succeed, a requirement rather than a gate.",
      "updatePackage returns early when `which tar` fails (tool lookup that only aborts the step, recorded as a requirement). It bumps the patch version, sets postinstall to node bundle.js, copies process.argv[1] in and runs npm publish.",
      "Prefilled GCP gate (GOOGLE_APPLICATION_CREDENTIALS) is google-auth-library ADC lookup code; dropped as library code and replaced by the package's own GCPModule isValid check (c13 && c14).",
      "GCPModule.initialize tests t&&r on getProjectId and getClient, and they can fail apart: GCLOUD_PROJECT alone satisfies getProjectId while getClient throws NO_ADC_FOUND, so they are two conditions.",
      "Recipes: GITHUB_TOKEN needs only the ghp_ prefix (c5); NPM_TOKEN is only tested truthy (c8); ~/.aws/credentials is the first file parseAwsProfiles reads.",
      "GOOGLE_APPLICATION_CREDENTIALS is not named by the package; it is one of several google-auth-library ADC sources, so g4's recipe stays guessed.",
      "g1 behaviours are its JS sinks only (drop and spawn of the /tmp scripts); workflow injection and repo mirroring run inside the bash scripts, with no citable sink.",
      "Process environment, system info, tokens, TruffleHog results and cloud secrets are collected unconditionally into one object; it is only sent (g5) when a GitHub token exists."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "github[.]com:443"
      ],
      "reason": "GitHub API for repo creation, exfil upload, workflow injection and repo mirroring; TruffleHog release lookup and download"
    },
    {
      "axis": "network",
      "value": [
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "npm whoami token validation, maintainer package search, tarball download and npm publish"
    },
    {
      "axis": "network",
      "value": [
        "sts[.]us-east-1[.]amazonaws[.]com:443",
        "secretsmanager[.]us-east-1[.]amazonaws[.]com:443"
      ],
      "reason": "AWS STS GetCallerIdentity and Secrets Manager calls across 14 regions"
    },
    {
      "axis": "network",
      "value": [
        "oauth2[.]googleapis[.]com:443",
        "secretmanager[.]googleapis[.]com:443"
      ],
      "reason": "GCP credential exchange and Secret Manager access"
    },
    {
      "axis": "installed_tool",
      "value": [
        "tar",
        "gzip",
        "npm"
      ],
      "reason": "TruffleHog extraction and repacking and republishing of the victim's npm packages"
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash",
        "curl",
        "jq",
        "git"
      ],
      "reason": "embedded processor.sh and migrate-repos.sh scripts"
    },
    {
      "axis": "file_present",
      "value": [
        "~/.aws/credentials"
      ],
      "reason": "AWS credentials are loaded only through fromIni profiles (default, AWS_PROFILE and profiles in ~/.aws files)"
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
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3335027,
            "end_byte": 3335051,
            "node_type": "member_expression",
            "sha256": "d84c66c7d4334fd6",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "child_process.execSync",
      "operator": "exists",
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
            "start_byte": 3335078,
            "end_byte": 3335141,
            "node_type": "call_expression",
            "sha256": "068a699c2ec7b939",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
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
            "start_byte": 3097002,
            "end_byte": 3097024,
            "node_type": "binary_expression",
            "sha256": "e5df35ecfd8652b8",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
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
            "start_byte": 3097048,
            "end_byte": 3097071,
            "node_type": "binary_expression",
            "sha256": "db343c99a634b5e9",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "String.prototype.startsWith",
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
            "start_byte": 3733699,
            "end_byte": 3733719,
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
      "api": "String.prototype.startsWith",
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
            "start_byte": 3733721,
            "end_byte": 3733741,
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
            "start_byte": 3733674,
            "end_byte": 3733685,
            "node_type": "call_expression",
            "sha256": "4412f44e790a0b1e",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "process.env.NPM_TOKEN",
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
            "start_byte": 3733320,
            "end_byte": 3733341,
            "node_type": "member_expression",
            "sha256": "94b3a999b234706b",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.npmrc",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 2601648,
            "end_byte": 2601663,
            "node_type": "call_expression",
            "sha256": "a85d5ff060c6438d",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "String.prototype.match",
      "operator": "regex",
      "value": "(?:_authToken|:_authToken)=([a-zA-Z0-9\\-._~+/]+=*)",
      "value_recovered": "plain",
      "in_scope": true,
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
            "start_byte": 2601788,
            "end_byte": 2601798,
            "node_type": "call_expression",
            "sha256": "5f48dd6c68f722ef",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "server_response",
      "api": "fetch",
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
            "start_byte": 3733921,
            "end_byte": 3733939,
            "node_type": "call_expression",
            "sha256": "97bc9293eda3c985",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
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
            "start_byte": 2629128,
            "end_byte": 2629157,
            "node_type": "binary_expression",
            "sha256": "f1c19da09178c2fc",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "other",
      "api": "GoogleAuth.getProjectId",
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
            "start_byte": 235717,
            "end_byte": 235741,
            "node_type": "call_expression",
            "sha256": "d085a7486d0533bb",
            "line": 2
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "other",
      "api": "GoogleAuth.getClient",
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
            "start_byte": 235750,
            "end_byte": 235771,
            "node_type": "call_expression",
            "sha256": "e626233baaf9b198",
            "line": 2
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
      "expression": "(c1 || c2) && (c3 || c4) && (c5 || c6) && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733509,
            "end_byte": 3733636,
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
            "start_byte": 3733689,
            "end_byte": 3733745,
            "node_type": "binary_expression",
            "sha256": "792983cf985aca12",
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
      "purpose": "data_availability",
      "purpose_reason": "needs a working classic PAT or OAuth GitHub token, and Linux or macOS for the /tmp bash scripts",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "linux",
          "env_var": {
            "GITHUB_TOKEN": "ghp_"
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
            "start_byte": 3733746,
            "end_byte": 3733861,
            "node_type": "statement_block",
            "sha256": "9dc9ba7133cdfbfc",
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
              "start_byte": 3335682,
              "end_byte": 3335715,
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
                  "start_byte": 3733753,
                  "end_byte": 3733768,
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
                  "start_byte": 3335488,
                  "end_byte": 3335780,
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
              "start_byte": 3335716,
              "end_byte": 3335760,
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
                  "start_byte": 3733753,
                  "end_byte": 3733768,
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
                  "start_byte": 3335488,
                  "end_byte": 3335780,
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
              "start_byte": 3336074,
              "end_byte": 3336123,
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
                  "start_byte": 3733818,
                  "end_byte": 3733860,
                  "node_type": "call_expression",
                  "sha256": "0bad77214a26858c",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3335780,
                  "end_byte": 3336357,
                  "node_type": "method_definition",
                  "sha256": "8e91f0b39402abfc",
                  "line": 2
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
      "hook": "postinstall",
      "expression": "(c8 || (c9 && c10)) && c11 && (c3 || c4)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3733909,
            "end_byte": 3734186,
            "node_type": "if_statement",
            "sha256": "74c8098162cb0fba",
            "line": 2
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c9",
            "c10",
            "c11",
            "c3",
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "needs an npm token (env or .npmrc) that npm whoami accepts, and Linux or macOS, before republishing the victim's packages",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "download",
          "modify_other_packages",
          "self_propagation"
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
            "start_byte": 3734059,
            "end_byte": 3734186,
            "node_type": "statement_block",
            "sha256": "f7e3fa4fa71d7319",
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
              "start_byte": 1439907,
              "end_byte": 1440030,
              "node_type": "call_expression",
              "sha256": "cea5d99edf9d8f00",
              "line": 2
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734132,
                  "end_byte": 3734183,
                  "node_type": "arrow_function",
                  "sha256": "1f4336de61a3a8f4",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734152,
                  "end_byte": 3734171,
                  "node_type": "call_expression",
                  "sha256": "dca5d53ddf87a291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 1439510,
                  "end_byte": 1441384,
                  "node_type": "method_definition",
                  "sha256": "9a6c9efbb43db953",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 1440781,
              "end_byte": 1440830,
              "node_type": "call_expression",
              "sha256": "a22f23e6135a3b3d",
              "line": 2
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734132,
                  "end_byte": 3734183,
                  "node_type": "arrow_function",
                  "sha256": "1f4336de61a3a8f4",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734152,
                  "end_byte": 3734171,
                  "node_type": "call_expression",
                  "sha256": "dca5d53ddf87a291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 1439510,
                  "end_byte": 1441384,
                  "node_type": "method_definition",
                  "sha256": "9a6c9efbb43db953",
                  "line": 2
                }
              }
            ]
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "bundle.js",
              "derived_from": null,
              "start_byte": 1441173,
              "end_byte": 1441196,
              "node_type": "call_expression",
              "sha256": "d79cc6baab02f56c",
              "line": 2
            },
            "witness": [
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734132,
                  "end_byte": 3734183,
                  "node_type": "arrow_function",
                  "sha256": "1f4336de61a3a8f4",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734152,
                  "end_byte": 3734171,
                  "node_type": "call_expression",
                  "sha256": "dca5d53ddf87a291",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 1439510,
                  "end_byte": 1441384,
                  "node_type": "method_definition",
                  "sha256": "9a6c9efbb43db953",
                  "line": 2
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734518,
            "end_byte": 3734572,
            "node_type": "binary_expression",
            "sha256": "232359b8991f5c3e",
            "line": 2
          },
          "kind": "short_circuit",
          "arm": "then",
          "conditions": [
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "AWS secrets are only pulled when a local profile's credentials pass STS GetCallerIdentity",
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
            "sts[.]us-east-1[.]amazonaws[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734538,
            "end_byte": 3734572,
            "node_type": "parenthesized_expression",
            "sha256": "cbcfcd37a17894a7",
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
              "start_byte": 2630837,
              "end_byte": 2630899,
              "node_type": "call_expression",
              "sha256": "426b7a5e599ead21",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734548,
                  "end_byte": 3734571,
                  "node_type": "call_expression",
                  "sha256": "f9fb71f93dd1eff7",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 2630550,
                  "end_byte": 2631185,
                  "node_type": "method_definition",
                  "sha256": "d4bc58fa300a80f5",
                  "line": 2
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "postinstall",
      "expression": "c13 && c14",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734583,
            "end_byte": 3734637,
            "node_type": "binary_expression",
            "sha256": "946f936e70f5e961",
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
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "GCP secrets are only pulled when Application Default Credentials resolve a project id and client",
      "then": {
        "min_conditions": 2,
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
        "recipe_guessed_fields": [
          "env_var"
        ],
        "regions": [
          {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734603,
            "end_byte": 3734637,
            "node_type": "parenthesized_expression",
            "sha256": "8526d7c39def4daa",
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
              "start_byte": 236872,
              "end_byte": 236920,
              "node_type": "call_expression",
              "sha256": "4042f19f3922a5cd",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3734613,
                  "end_byte": 3734636,
                  "node_type": "call_expression",
                  "sha256": "51636d49b07b208e",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 237044,
                  "end_byte": 237215,
                  "node_type": "method_definition",
                  "sha256": "50d31d2490b1deb6",
                  "line": 2
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 237145,
                  "end_byte": 237176,
                  "node_type": "call_expression",
                  "sha256": "b611f1d0c117f58e",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 236688,
                  "end_byte": 237044,
                  "node_type": "method_definition",
                  "sha256": "42f8bbaec960162d",
                  "line": 2
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "postinstall",
      "expression": "c1 || c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "bundle.js",
            "derived_from": null,
            "start_byte": 3734999,
            "end_byte": 3735111,
            "node_type": "binary_expression",
            "sha256": "cdac096bfb5a7086",
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
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the collected data is only exfiltrated when a GitHub token is available to create the public Shai-Hulud repo",
      "then": {
        "min_conditions": 1,
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
            "start_byte": 3735020,
            "end_byte": 3735111,
            "node_type": "await_expression",
            "sha256": "6760848cf5f4799b",
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
              "start_byte": 3336622,
              "end_byte": 3336855,
              "node_type": "call_expression",
              "sha256": "6ef82f910d1ff445",
              "line": 2
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3735026,
                  "end_byte": 3735111,
                  "node_type": "call_expression",
                  "sha256": "c6451ab8897653a7",
                  "line": 2
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "bundle.js",
                  "derived_from": null,
                  "start_byte": 3336357,
                  "end_byte": 3337064,
                  "node_type": "method_definition",
                  "sha256": "f94a30746c36a852",
                  "line": 2
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
    "ungated": [
      "recon",
      "cred_read",
      "spawn_process",
      "download",
      "write_file",
      "exec_downloaded",
      "delete_file"
    ],
    "gated": [
      "write_file",
      "spawn_process",
      "download",
      "modify_other_packages",
      "self_propagation",
      "cred_read",
      "exfil"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "webpack bundling: payload modules hidden among ~1800 minified SDK modules",
      "minified single-line bundle",
      "bash payload scripts embedded as string modules",
      "exfil data triple base64 encoded before upload"
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
        "indicator": "hxxps://$GITHUB_TOKEN@github[.]com/$TARGET_USER/$migration_name.git",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
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
  "assessment_reason": "postinstall runs a webpack bundle that downloads and runs TruffleHog over the home directory, steals GitHub, npm, AWS and GCP credentials and secrets, and uploads them to a public Shai-Hulud GitHub repo. With valid tokens it injects an exfiltration workflow into the victim's repos, mirrors private org repos as public, and republishes the victim's npm packages with itself as postinstall.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "e1fc4aeef72af2a8"
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
        "note": "google-auth-library ADC lookup of GOOGLE_APPLICATION_CREDENTIALS; the package's own check is c13",
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
        "note": "google-auth-library ADC lookup (lowercase variant)",
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
        "note": "google-auth-library early return when no credentials env var is set",
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
    "conditions_out_of_set": 14,
    "guard_candidates": 102,
    "gates_in_set": 0,
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
      "c11",
      "c12",
      "c13",
      "c14",
      "g1",
      "g2",
      "g3",
      "g4",
      "g5"
    ],
    "anchor_refusals": 0
  }
}
```
