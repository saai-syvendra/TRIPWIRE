# npm @redhat-cloud-services/entitlements-client@4.0.11

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-01 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised copy of the real `@redhat-cloud-services/entitlements-client` with an injected `preinstall: node index.js` hook, so the payload runs on every registry install. `index.js` is a 4.2 MB one-liner whose outer `eval` decodes a char-code array joined to a string and Caesar-shifted by -2; the decoded wrapper then decrypts two AES-128-GCM blobs (`_b`, a Bun downloader, and `_p`, the main payload), writes `_p` to `/tmp/p<rand>.js`, and runs it with `bun run` (downloading Bun v1.3.13 from github.com if absent). `_p` is the Shai-Hulud npm worm: obfuscator.io string array plus a second feistel string cipher, recovered in full. At install it harvests npm/GitHub/cloud (AWS/Azure/GCP/Vault) credentials, dumps GitHub Actions runner memory for CI secrets, republishes npm packages with stolen tokens, and installs a Python backdoor service that polls GitHub commit search for signed download URLs. The worm gates on: decoy honeytokens in env vars (evade), Russian locale (three tests, geo-exclusion), a single-instance lock held by a live process, >=4 CPUs with no EDR path or process and not CI (the backdoor dropper), and a Linux GitHub Actions runner (the memory dumper).

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script, decoded_eval, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: process.env not_startswith decoy token prefixes: GITHUB_TOKEN!=ghp_decoyGitHubToken, NPM_TOKEN!=npm_F4k3NPMToken, ANTHROPIC_API_KEY!=sk-ant-api03-fake, CIRCLE_TOKEN!=fake_circle) | then | 1 | recon, cred_read, exfil, self_propagation | (none) |
| g2 | preinstall | c2 && c3 && c10 (c2: locale_language not_startswith ru; c3: locale_language not_startswith ru; c10: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, self_propagation | locale=en-US |
| g3 | preinstall | c4 \|\| c11 (c4: file_or_dir_exists not_exists; c11: process_list falsy) | then | 1 | recon, cred_read, exfil, self_propagation | file_absent=/tmp/tmp.0987654321.lock |
| g4 | preinstall | c5 && c6 && c12 && c7 (c5: hardware >= 4; c6: installed_tool not_exists [/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack]; c12: process_list not_includes [falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys]; c7: process.env not_exists CI!=true && GITHUB_ACTIONS!=true && JENKINS_HOME unset) | then | 4 | write_file, spawn_process, persistence | cpu_count=4; file_absent=/opt/CrowdStrike, /opt/sentinelone, /opt/carbonblack |
| g5 | preinstall | c8 && c9 (c8: process.env.GITHUB_ACTIONS == true; c9: process.env.RUNNER_OS == Linux) | then | 2 | cred_read | ci=github_actions; env_var=GITHUB_ACTIONS=true, RUNNER_OS=Linux |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/enables/targeting; g3 activate/enables/unclear; g4 evade/enables/anti_analysis; g5 activate/enables/targeting

Grounding: 0 of 12 conditions and 0 of 5 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, g1, g2, g3, g4, g5.

## Requirements

- network: api[.]github[.]com:443, registry[.]npmjs[.]org:443, github[.]com:443 (GitHub API and npm registry for credential validation, exfil and self-propagation; github.com releases to download the Bun runtime when Bun is absent.)
- installed_tool: curl, unzip (Used by the _b downloader to fetch and extract the Bun runtime zip when Bun is not already present.)
- installed_tool: bash (The t4 module pipes the RZ installer script into `bash -s`, which installs the dropped cat.py as a service.)
- installed_tool: python3 (The RZ installer exits unless python3 is present, and the Y6 runner dump runs `sudo python3`.)
- other: Bun runtime (The main payload _p is executed with `bun run`; Bun is downloaded on demand if not installed, so a Bun binary (or curl+unzip to fetch it) must be reachable.)

## Behaviour

- Ungated: write_file, download, exec_downloaded
- Gated: recon, cred_read, exfil, self_propagation, write_file, spawn_process, persistence

## Notes

- Decode chain (all registered, verifier-replayable): d7 charcode_caesar_eval -> d8/d9 aesgcm_hex_stage (`_p`/`_b`) -> d10 obfio_scoped -> d11 scramble_feistel (key P9 / salt N9, fn f4abccab2) -> d12 aesgcm_gunzip (dropped cat.py backdoor and its installer). Gate anchors cite into d11; plumbing into d7/d9.
- The `typeof Bun` branch and the `!KZ()&&q9()` daemonization are runtime plumbing / a re-entry guard (`__IS_DAEMON`), not gates: both paths run `_p`. Recorded in execution.notes.
- Gates g4 (dropper) and g5 (runner dump) sit downstream of the kq evade guards g1-g3; their enclosing conditions were left out of the expressions for readability.
- The kq guards gate the entire worm. Their cred_read, recon and self_propagation payloads are traced to concrete sinks (`readFile` in W6, `hostname` in O6, the registry PUT in `e1`). The exfil path stops at `sender.send` with unresolved dynamic_dispatch, since the sender is chosen at run time.
- `hq()` and the platform test in `R8.execute` look like possible missed gates. They were outside this repair's open items and are flagged for review, not recorded as gates.
- Bundled libraries (tar, sigstore ecosystem, node crypto) were audited by sink inventory, not read line by line; all hits are library behaviour. Not diffed against an upstream release.
- A decoy config in `bq` references api.anthropic[.]com / v1/api with noop:true; the real exfil and propagation use GitHub and the npm registry.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@redhat-cloud-services/entitlements-client",
    "version": "4.0.11",
    "archive_sha256": "2d687501e01b03709e0a5b206cca7cbd30651378d5c272aebcb8c6985024043f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-01",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-01-@redhat-cloud-services_entitlements-client-v4.0.11.zip",
    "package_root": "layer0/tmp/tmpb9u5ji2o/@redhat-cloud-services-entitlements-client/package",
    "cluster_key": "793574cf015048211733252a8d13c5e9b0a6bcb6a609a6998e65538f1bf45eb3",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "decoded_eval",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js preinstall runs `node index.js`. The outer eval decodes a char-code array joined to a string then Caesar(-2) [decoder charcode_caesar_eval -> d7]; the whole payload is one eval with the error swallowed (console.log).",
      "d7 decrypts two AES-128-GCM blobs via helper _d(key,iv,tag,ct): _b (a Bun downloader script, d9) and _p (the main payload, d8). _p is written to /tmp/p<rand>.js and run with `bun run`.",
      "typeof Bun branch: if Bun present, run _p directly; else eval(_b) which downloads Bun v1.3.13 from github[.]com/oven-sh/bun releases via curl+unzip (d9) and runs _p with it. This runtime selection is plumbing, not a gate (both paths run _p).",
      "_p (d8) is obfuscator.io-obfuscated; string array recovered [obfio_scoped -> d10]. A second string layer is the shai-hulud feistel cipher f4abccab2 with literal key P9 / salt N9, recovered [scramble_feistel -> d11]. Inline blobs via n() are AES-256-GCM+gzip, recovered [aesgcm_gunzip -> d12].",
      "Coverage: d11 worm code read in full (kq guards, fq harvesters W6/O6/Y6, exfil senders, npm republisher R8, Actions secret extractor n8, droppers s4/t4, Docker runner priv-esc).",
      "Bundled libraries in d11 (tar, sigstore: fulcio/rekor/SLSA/in-toto, node crypto) audited by sink inventory, all hits library behaviour; nothing unread. Not diffed against an upstream release.",
      "x1() EDR check has two parts: c6 loops existsSync over the hQ paths, c12 searches lowercased process-list output for the fQ names. c12's probe records `ps aux`; on win32 the same code runs `tasklist`.",
      "t4 is a persistence backdoor, not a scanner: RZ installs cat.py as a systemd user service or LaunchAgent, and cat.py polls GitHub commit search for signed URLs, then downloads and runs them. That later execution is covered by persistence.",
      "Y6 secrets are not sent inside g5: fq() returns them, and they leave through the same j8/x8 sender path as every other harvest result, so exfil is recorded on g1-g3 only.",
      "self_propagation is cited on the npm path (j8.ingest, handleNpmTokens, R8, e1 PUT to the registry). n8 extracts Actions secrets, it does not propagate. Other spread code (P8, $8, v8, a4, u8) was not re-traced in this repair.",
      "kq() also daemonizes: `if(!KZ()&&q9())process.exit(0)`. On non-CI hosts q9() spawns a detached child of node with __IS_DAEMON=1 and the parent exits (re-entry guard + detached_child); not recorded as a gate since both paths run _p.",
      "Gates g4 (t4 dropper) and g5 (Y6 runner dump) run only after the kq guards g1-g3 pass; their enclosing conditions (c1-c4) are omitted from their expressions for readability.",
      "W9 writes process.pid to tmp.0987654321.lock under os.tmpdir() and exits only if a still-live pid holds it; stale locks are deleted and overwritten. Modeled as c4 (lock absent) || c11 (recorded pid dead).",
      "The main config object in bq uses domain api.anthropic[.]com path v1/api with noop:true and a decoy token string; the real exfil and propagation go to GitHub (api.github[.]com) and the npm registry. Primary exfil is credential collection returned to GitHub-based senders."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "github[.]com:443"
      ],
      "reason": "GitHub API and npm registry for credential validation, exfil and self-propagation; github.com releases to download the Bun runtime when Bun is absent."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip"
      ],
      "reason": "Used by the _b downloader to fetch and extract the Bun runtime zip when Bun is not already present.",
      "sites": [
        {
          "file": "index.js",
          "derived_from": "d9",
          "start_byte": 718,
          "end_byte": 777,
          "node_type": "call_expression",
          "sha256": "cc1bd763ec84588b",
          "line": 17
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash"
      ],
      "reason": "The t4 module pipes the RZ installer script into `bash -s`, which installs the dropped cat.py as a service."
    },
    {
      "axis": "installed_tool",
      "value": [
        "python3"
      ],
      "reason": "The RZ installer exits unless python3 is present, and the Y6 runner dump runs `sudo python3`."
    },
    {
      "axis": "other",
      "value": "Bun runtime",
      "reason": "The main payload _p is executed with `bun run`; Bun is downloaded on demand if not installed, so a Bun binary (or curl+unzip to fetch it) must be reachable."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "decoy token prefixes: GITHUB_TOKEN!=ghp_decoyGitHubToken, NPM_TOKEN!=npm_F4k3NPMToken, ANTHROPIC_API_KEY!=sk-ant-api03-fake, CIRCLE_TOKEN!=fake_circle",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 506074,
            "end_byte": 506108,
            "node_type": "call_expression",
            "sha256": "2b00d2602a5160c0",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat().resolvedOptions().locale",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 174709,
            "end_byte": 174807,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "locale_language",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 174830,
            "end_byte": 174968,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "decoded",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "/tmp/tmp.0987654321.lock",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 550501,
            "end_byte": 550514,
            "node_type": "call_expression",
            "sha256": "0605ce420896bd18",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 382749,
            "end_byte": 382774,
            "node_type": "binary_expression",
            "sha256": "d1747f5508864861",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "installed_tool",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": [
        "/opt/CrowdStrike",
        "/Library/CS/falcon",
        "/opt/carbonblack",
        "/opt/sentinelone",
        "C:\\Program Files\\CrowdStrike",
        "C:\\Program Files\\SentinelOne",
        "C:\\Program Files\\CarbonBlack"
      ],
      "value_recovered": "decoded",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "*",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 177581,
            "end_byte": 177601,
            "node_type": "call_expression",
            "sha256": "9d64ffc24914c8bc",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env",
      "operator": "not_exists",
      "value": "CI!=true && GITHUB_ACTIONS!=true && JENKINS_HOME unset",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 382808,
            "end_byte": 382914,
            "node_type": "binary_expression",
            "sha256": "d4174e48adfd0362",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "==",
      "value": "true",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 507596,
            "end_byte": 507658,
            "node_type": "assignment_expression",
            "sha256": "52accd8ccfd307b4",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "ci_marker",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 507659,
            "end_byte": 507715,
            "node_type": "assignment_expression",
            "sha256": "7141cb4174362eef",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "locale_language",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 174983,
            "end_byte": 175122,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "process_list",
      "api": "process.kill",
      "operator": "falsy",
      "value": null,
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 550374,
            "end_byte": 550404,
            "node_type": "call_expression",
            "sha256": "644562847b016702",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "process_list",
      "api": "child_process.execSync",
      "operator": "not_includes",
      "value": [
        "falcon-sensor",
        "falcond",
        "csfalcon",
        "sentinelone",
        "sentinelagent",
        "mdatp",
        "wdavdaemon",
        "cbagent",
        "cbdaemon",
        "cylance",
        "crowdstrike",
        "trendmicro",
        "ds_agent",
        "xagt",
        "osquery",
        "tanium",
        "qualys"
      ],
      "value_recovered": "decoded",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "ps aux 2>/dev/null",
        "accessor": "stdout"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 177832,
            "end_byte": 177864,
            "node_type": "call_expression",
            "sha256": "6c70363fc09e6831",
            "line": 1
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
      "hook": "preinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 551710,
            "end_byte": 551739,
            "node_type": "if_statement",
            "sha256": "ef1fc6b9acf56c9d",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 553306,
              "end_byte": 553310,
              "node_type": "call_expression",
              "sha256": "11530eb12216ab4d",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "i7() exits the whole process when GITHUB_TOKEN/NPM_TOKEN/ANTHROPIC_API_KEY/CIRCLE_TOKEN hold known decoy prefixes planted by analysts and sandboxes; the worm only runs when no decoy token is present.",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 553311,
            "end_byte": 553466,
            "node_type": "lexical_declaration",
            "sha256": "b49e430ded9255d7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554174,
            "end_byte": 554318,
            "node_type": "lexical_declaration",
            "sha256": "ba30b24192df3b4a",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554318,
            "end_byte": 554380,
            "node_type": "for_in_statement",
            "sha256": "6d5d77aff1b8908d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554792,
            "end_byte": 554967,
            "node_type": "expression_statement",
            "sha256": "22bad2e63f361f92",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 482417,
              "end_byte": 482449,
              "node_type": "call_expression",
              "sha256": "e5f7161b65c77b3f",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550906,
                  "end_byte": 550928,
                  "node_type": "call_expression",
                  "sha256": "58f5f798bf9c700e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483237,
                  "end_byte": 483651,
                  "node_type": "method_definition",
                  "sha256": "84c105d206ebac21",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483473,
                  "end_byte": 483517,
                  "node_type": "call_expression",
                  "sha256": "d9a7da66d3a82e99",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 480676,
                  "end_byte": 483237,
                  "node_type": "method_definition",
                  "sha256": "20b31fdf4da714a0",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483164,
                  "end_byte": 483183,
                  "node_type": "call_expression",
                  "sha256": "4203c3c08ae7dfb1",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 482076,
                  "end_byte": 482738,
                  "node_type": "arrow_function",
                  "sha256": "c04ff42922bd4801",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 475216,
              "end_byte": 475227,
              "node_type": "call_expression",
              "sha256": "4745ed05d852aa1e",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550954,
                  "end_byte": 550976,
                  "node_type": "call_expression",
                  "sha256": "a10eecd9038c3389",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 474790,
                  "end_byte": 475511,
                  "node_type": "method_definition",
                  "sha256": "fb1af2de239406d1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 198464,
              "end_byte": 198492,
              "node_type": "call_expression",
              "sha256": "c465366d9c0001cb",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554283,
                  "end_byte": 554315,
                  "node_type": "pair",
                  "sha256": "93323b55221ba500",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554798,
                  "end_byte": 554896,
                  "node_type": "call_expression",
                  "sha256": "1563b1ae743fa2b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197056,
                  "end_byte": 197265,
                  "node_type": "method_definition",
                  "sha256": "bd8e9b48742134ed",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197244,
                  "end_byte": 197262,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196926,
                  "end_byte": 197056,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197000,
                  "end_byte": 197015,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196580,
                  "end_byte": 196926,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196822,
                  "end_byte": 196849,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197833,
                  "end_byte": 198594,
                  "node_type": "arrow_function",
                  "sha256": "3318e9ae26529ddf",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 186298,
              "end_byte": 186402,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554349,
                  "end_byte": 554379,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 193882,
                  "end_byte": 195132,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 194795,
                  "end_byte": 194852,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196385,
                  "end_byte": 196580,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196547,
                  "end_byte": 196577,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 186630,
                  "end_byte": 187252,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 187093,
                  "end_byte": 187126,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190231,
                  "end_byte": 190446,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190370,
                  "end_byte": 190414,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 184100,
                  "end_byte": 186482,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c2 && c3 && c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 551739,
            "end_byte": 551779,
            "node_type": "if_statement",
            "sha256": "db9ae3271cc6fdfa",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c10"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 553306,
              "end_byte": 553310,
              "node_type": "call_expression",
              "sha256": "11530eb12216ab4d",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "ZZ() exits when the Intl locale, the LC_ALL/LC_MESSAGES/LANGUAGE/LANG chain, or (with SystemRoot set) the LANG/LANGUAGE/LC_ALL chain starts with 'ru', excluding Russian-locale hosts.",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation"
        ],
        "env_recipe": {
          "locale": "en-US"
        },
        "recipe_guessed_fields": [
          "locale"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 553311,
            "end_byte": 553466,
            "node_type": "lexical_declaration",
            "sha256": "b49e430ded9255d7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554174,
            "end_byte": 554318,
            "node_type": "lexical_declaration",
            "sha256": "ba30b24192df3b4a",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554318,
            "end_byte": 554380,
            "node_type": "for_in_statement",
            "sha256": "6d5d77aff1b8908d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554792,
            "end_byte": 554967,
            "node_type": "expression_statement",
            "sha256": "22bad2e63f361f92",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 482417,
              "end_byte": 482449,
              "node_type": "call_expression",
              "sha256": "e5f7161b65c77b3f",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550906,
                  "end_byte": 550928,
                  "node_type": "call_expression",
                  "sha256": "58f5f798bf9c700e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483237,
                  "end_byte": 483651,
                  "node_type": "method_definition",
                  "sha256": "84c105d206ebac21",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483473,
                  "end_byte": 483517,
                  "node_type": "call_expression",
                  "sha256": "d9a7da66d3a82e99",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 480676,
                  "end_byte": 483237,
                  "node_type": "method_definition",
                  "sha256": "20b31fdf4da714a0",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483164,
                  "end_byte": 483183,
                  "node_type": "call_expression",
                  "sha256": "4203c3c08ae7dfb1",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 482076,
                  "end_byte": 482738,
                  "node_type": "arrow_function",
                  "sha256": "c04ff42922bd4801",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 475216,
              "end_byte": 475227,
              "node_type": "call_expression",
              "sha256": "4745ed05d852aa1e",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550954,
                  "end_byte": 550976,
                  "node_type": "call_expression",
                  "sha256": "a10eecd9038c3389",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 474790,
                  "end_byte": 475511,
                  "node_type": "method_definition",
                  "sha256": "fb1af2de239406d1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 198464,
              "end_byte": 198492,
              "node_type": "call_expression",
              "sha256": "c465366d9c0001cb",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554283,
                  "end_byte": 554315,
                  "node_type": "pair",
                  "sha256": "93323b55221ba500",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554798,
                  "end_byte": 554896,
                  "node_type": "call_expression",
                  "sha256": "1563b1ae743fa2b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197056,
                  "end_byte": 197265,
                  "node_type": "method_definition",
                  "sha256": "bd8e9b48742134ed",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197244,
                  "end_byte": 197262,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196926,
                  "end_byte": 197056,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197000,
                  "end_byte": 197015,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196580,
                  "end_byte": 196926,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196822,
                  "end_byte": 196849,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197833,
                  "end_byte": 198594,
                  "node_type": "arrow_function",
                  "sha256": "3318e9ae26529ddf",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 186298,
              "end_byte": 186402,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554349,
                  "end_byte": 554379,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 193882,
                  "end_byte": 195132,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 194795,
                  "end_byte": 194852,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196385,
                  "end_byte": 196580,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196547,
                  "end_byte": 196577,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 186630,
                  "end_byte": 187252,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 187093,
                  "end_byte": 187126,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190231,
                  "end_byte": 190446,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190370,
                  "end_byte": 190414,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 184100,
                  "end_byte": 186482,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
                  "line": 1
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
      "hook": "preinstall",
      "expression": "c4 || c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 551836,
            "end_byte": 551935,
            "node_type": "if_statement",
            "sha256": "9fc1e814d1a9ac10",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c11"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 553306,
              "end_byte": 553310,
              "node_type": "call_expression",
              "sha256": "11530eb12216ab4d",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "W9 single-instance lock: continues when the lock under os.tmpdir() is absent (c4) or its recorded PID is dead (c11, stale lock replaced); exits only if a live process holds it. Phase 2 keeps it absent.",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation"
        ],
        "env_recipe": {
          "file_absent": [
            "/tmp/tmp.0987654321.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 553311,
            "end_byte": 553466,
            "node_type": "lexical_declaration",
            "sha256": "b49e430ded9255d7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554174,
            "end_byte": 554318,
            "node_type": "lexical_declaration",
            "sha256": "ba30b24192df3b4a",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554318,
            "end_byte": 554380,
            "node_type": "for_in_statement",
            "sha256": "6d5d77aff1b8908d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 554792,
            "end_byte": 554967,
            "node_type": "expression_statement",
            "sha256": "22bad2e63f361f92",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 482417,
              "end_byte": 482449,
              "node_type": "call_expression",
              "sha256": "e5f7161b65c77b3f",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550906,
                  "end_byte": 550928,
                  "node_type": "call_expression",
                  "sha256": "58f5f798bf9c700e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483237,
                  "end_byte": 483651,
                  "node_type": "method_definition",
                  "sha256": "84c105d206ebac21",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483473,
                  "end_byte": 483517,
                  "node_type": "call_expression",
                  "sha256": "d9a7da66d3a82e99",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 480676,
                  "end_byte": 483237,
                  "node_type": "method_definition",
                  "sha256": "20b31fdf4da714a0",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 483164,
                  "end_byte": 483183,
                  "node_type": "call_expression",
                  "sha256": "4203c3c08ae7dfb1",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 482076,
                  "end_byte": 482738,
                  "node_type": "arrow_function",
                  "sha256": "c04ff42922bd4801",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 475216,
              "end_byte": 475227,
              "node_type": "call_expression",
              "sha256": "4745ed05d852aa1e",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 553451,
                  "end_byte": 553455,
                  "node_type": "call_expression",
                  "sha256": "f1db30fa13faaa02",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550711,
                  "end_byte": 551037,
                  "node_type": "function_declaration",
                  "sha256": "2102e6506cd55fce",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 550954,
                  "end_byte": 550976,
                  "node_type": "call_expression",
                  "sha256": "a10eecd9038c3389",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 474790,
                  "end_byte": 475511,
                  "node_type": "method_definition",
                  "sha256": "fb1af2de239406d1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 198464,
              "end_byte": 198492,
              "node_type": "call_expression",
              "sha256": "c465366d9c0001cb",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554283,
                  "end_byte": 554315,
                  "node_type": "pair",
                  "sha256": "93323b55221ba500",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554798,
                  "end_byte": 554896,
                  "node_type": "call_expression",
                  "sha256": "1563b1ae743fa2b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197056,
                  "end_byte": 197265,
                  "node_type": "method_definition",
                  "sha256": "bd8e9b48742134ed",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197244,
                  "end_byte": 197262,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196926,
                  "end_byte": 197056,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197000,
                  "end_byte": 197015,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196580,
                  "end_byte": 196926,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196822,
                  "end_byte": 196849,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 197833,
                  "end_byte": 198594,
                  "node_type": "arrow_function",
                  "sha256": "3318e9ae26529ddf",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 186298,
              "end_byte": 186402,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 554349,
                  "end_byte": 554379,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 193882,
                  "end_byte": 195132,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 194795,
                  "end_byte": 194852,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196385,
                  "end_byte": 196580,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 196547,
                  "end_byte": 196577,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 186630,
                  "end_byte": 187252,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 187093,
                  "end_byte": 187126,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190231,
                  "end_byte": 190446,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 190370,
                  "end_byte": 190414,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 184100,
                  "end_byte": 186482,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c5 && c6 && c12 && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 383059,
            "end_byte": 383104,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c12",
            "c7"
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "t4.shouldExecute installs the cat.py backdoor service only on real multi-core developer machines: requires >=4 CPUs, no EDR/AV path or process present, and not a CI environment.",
      "then": {
        "behaviours": [
          "write_file",
          "spawn_process",
          "persistence"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "file_absent": [
            "/opt/CrowdStrike",
            "/opt/sentinelone",
            "/opt/carbonblack"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 383104,
            "end_byte": 383183,
            "node_type": "lexical_declaration",
            "sha256": "d449b5c85a8d3874",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 383183,
            "end_byte": 383562,
            "node_type": "try_statement",
            "sha256": "108dd35d2b1583d4",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 383187,
              "end_byte": 383225,
              "node_type": "call_expression",
              "sha256": "150d96e650eed1a9",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 383240,
              "end_byte": 383331,
              "node_type": "call_expression",
              "sha256": "bbf5ecf8bacbd0fb",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 383240,
              "end_byte": 383331,
              "node_type": "call_expression",
              "sha256": "bbf5ecf8bacbd0fb",
              "line": 1
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
      "gate_id": "g5",
      "hook": "preinstall",
      "expression": "c8 && c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 509017,
            "end_byte": 509116,
            "node_type": "if_statement",
            "sha256": "b1e511154a875204",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8",
            "c9"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Y6 dumps the GitHub Actions runner worker process memory and extracts CI secrets; it only runs on a Linux GitHub Actions runner (GITHUB_ACTIONS=true and RUNNER_OS=Linux).",
      "then": {
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "ci": "github_actions",
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 509116,
            "end_byte": 509249,
            "node_type": "lexical_declaration",
            "sha256": "649a5b3ba6aa55a4",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 508421,
              "end_byte": 508492,
              "node_type": "call_expression",
              "sha256": "aab0784d4bd42c41",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 509228,
                  "end_byte": 509248,
                  "node_type": "call_expression",
                  "sha256": "57b51004d0c39d8c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 508494,
                  "end_byte": 508796,
                  "node_type": "method_definition",
                  "sha256": "85ac5ae97ee0de97",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 508688,
                  "end_byte": 508763,
                  "node_type": "call_expression",
                  "sha256": "6105c1de12bf2a71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 508316,
                  "end_byte": 508494,
                  "node_type": "method_definition",
                  "sha256": "4bd1ef01fee025ad",
                  "line": 1
                }
              }
            ]
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
      "write_file",
      "download",
      "exec_downloaded"
    ],
    "gated": [
      "recon",
      "cred_read",
      "exfil",
      "self_propagation",
      "write_file",
      "spawn_process",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "dynamic_eval",
      "very_long_lines",
      "char-code array to string",
      "Caesar cipher (shift -2)",
      "AES-128-GCM encrypted stages",
      "AES-256-GCM+gzip embedded blobs",
      "obfuscator.io string array with checksum rotation",
      "shai-hulud feistel string cipher (f4abccab2)",
      "bundled third-party libraries"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "api.github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "registry.npmjs[.]org",
        "role": "exfil_sink"
      },
      {
        "indicator": "github[.]com/oven-sh/bun/releases/download/bun-v1.3.13",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook of this compromised copy of a real Red Hat client decodes a multi-stage, Bun-executed worm. After evade checks (decoy honeytokens, Russian locale, EDR, CI, single-instance lock) it harvests npm/GitHub/cloud credentials, dumps GitHub Actions runner memory, republishes npm packages with stolen tokens, and installs a persistent GitHub-polling backdoor. This is unambiguous install-time malware.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and gates are out-of-set (added by analyst) after a six-stage manual decode chain (charcode+Caesar, two AES-128-GCM stages, obfuscator.io string array, shai-hulud feistel, AES-256-GCM+gzip).",
    "The g1/g2/g3 exfil path is traced to x8.dispatch, then stops at sender.send with unresolved dynamic_dispatch: the sender (q5 domain or A5 GitHub) is chosen at run time.",
    "Possible missed gates, not added in this repair: hq() (WORKFLOW_ID/REPO_ID_SUFFIX with GITHUB_ACTIONS and workflow ref or repository matches runs u8, then exits) and the darwin/linux platform test in R8.execute.",
    "Gates g4 and g5 run downstream of the kq guards g1-g3; enclosing conditions were omitted from their expressions for readability (see execution.notes).",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d7",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": null
        },
        "params": {
          "decoder": "charcode_caesar_eval",
          "lang": "js"
        },
        "output_sha256": "ffc3d08054ce64a5"
      },
      {
        "id": "d8",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d7"
        },
        "params": {
          "fn": "_d",
          "var": "_p",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "0dc06ecdaa63fe24"
      },
      {
        "id": "d9",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d7"
        },
        "params": {
          "fn": "_d",
          "var": "_b",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "ac2a2208e1726e00"
      },
      {
        "id": "d10",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d8"
        },
        "params": {
          "decoder": "obfio_scoped",
          "lang": "js"
        },
        "output_sha256": "cef1e4b5db297203"
      },
      {
        "id": "d11",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d10"
        },
        "params": {
          "fn": "f4abccab2",
          "key": "ba2c6ddb3672bdd6a611e6850b4f700b52aed3dab2f1b3d5f8c839d4a157a709",
          "salt": "5b26508dc0f1075a7c0b4d8aa464487e",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "b92d0bbd7c2fd575"
      },
      {
        "id": "d12",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d11"
        },
        "params": {
          "fn": "n",
          "decoder": "aesgcm_gunzip",
          "lang": "js"
        },
        "output_sha256": "069b93e722e56ea9"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "428960f5b8cf6c20"
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
    "condition_candidates": 0,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 0,
    "conditions_out_of_set": 12,
    "guard_candidates": 0,
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
