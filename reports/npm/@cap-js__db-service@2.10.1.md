# npm @cap-js/db-service@2.10.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-04-29 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised release of the legitimate SAP `@cap-js/db-service` package: a malicious `preinstall` hook (`node setup.mjs`) was added. On install, setup.mjs checks whether `bun` is already on PATH and, if not (gate g1), downloads the Bun runtime from github.com, extracts it, and runs the bundled 11.7 MB payload `execution.js` under Bun (download_then_exec + dropped_binary). The payload is an obfuscator.io string-array bundle wrapped in a bespoke pbkdf2-keyed per-byte substitution cipher; it harvests credentials (the `gh` auth token, OS-selected credential/secret files, cloud and npm secrets, and GitHub Actions runner process memory), gzip+AES-GCM+RSA-encrypts them, and exfiltrates via GitHub/npm/cloud senders. It also self-propagates: inside GitHub Actions for the real `cds-dbs` repo it commits attacker files to the repo's branches. Execution is gated by bun-absence (g1), non-Russian locale (g2), a pid lock / single-instance guard (g3), GitHub-Actions-plus-`/cds-dbs` repo targeting for the self-republish (g4), a Linux-runner check for the memory scrape (g5), and per-OS credential-file hotspot existence (g6).

## Execution

- **preinstall** `node setup.mjs`: 2-file chain; direct_script, download_then_exec, dropped_binary, detached_child, decoded_eval; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: installed_tool not_exists bun) | then | 1 | download, write_file, spawn_process, exec_downloaded | (none) |
| g2 | preinstall | c2 (c2: locale_language not_startswith ru) | then | 1 | recon, cred_read, exfil | locale=en-US |
| g3 | preinstall | c3 (c3: file_or_dir_exists other no live lock holder: <os.tmpdir()>/tmp.987654321.lock is absent, or the pid stored in it is not a live process (process.kill(pid, 0) throws, lZh); a stale lock is unlinked and overwritten) | then | 1 | recon, cred_read, exfil | file_absent=<os.tmpdir()>/tmp.987654321.lock |
| g4 | preinstall | c4 && c5 && c6 (c4: process.env.GITHUB_ACTIONS truthy; c5: process.env.GITHUB_REPOSITORY includes /cds-dbs; c6: process.env.GITHUB_WORKFLOW_REF includes release-please.yml) | then | 3 | self_propagation | ci=true; env_var=GITHUB_ACTIONS=(set), GITHUB_REPOSITORY=cap-js/cds-dbs, GITHUB_WORKFLOW_REF=release-please.yml |
| g5 | preinstall | c7 && c8 (c7: process.env.GITHUB_ACTIONS == true; c8: process.env.RUNNER_OS == Linux) | then | 2 | cred_read, recon | ci=true; os=linux; env_var=GITHUB_ACTIONS=true, RUNNER_OS=Linux |
| g6 | preinstall | c9 (c9: target_artifact other regular file of at most 5 MiB (stat succeeds, isFile() true, size <= Ya1 = 0x500000) at an OS-selected developer credential/secret path (~/.aws, ~/.ssh, ~/.npmrc, wallet and token files, kube serviceaccount token)) | then | 1 | cred_read | file_present=~/.aws/credentials, ~/.ssh/id_ed25519, ~/.npmrc |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/targeting; g3 activate/enables/unclear; g4 activate/enables/targeting; g5 activate/enables/targeting; g6 activate/enables/data_availability

Grounding: 0 of 9 conditions and 0 of 6 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, g1, g2, g3, g4, g5, g6.

## Requirements

- network: github[.]com:443, api[.]github[.]com:443, registry[.]npmjs[.]org:443 (Downloads the Bun runtime from github.com, pulls an attacker token from api.github.com commit search, and exfiltrates / self-republishes via GitHub and npm.)
- installed_tool: unzip (extractBun uses `unzip` to unpack the downloaded Bun archive on non-Windows hosts (PowerShell Expand-Archive on win32); without an extractor the install throws.)
- installed_tool: python3 (The GitHub Actions runner-memory secret scrape pipes its script into `sudo python3` (only on the Linux-runner branch, gate g5).)

## Behaviour

- Ungated: none
- Gated: download, write_file, spawn_process, exec_downloaded, recon, cred_read, exfil, self_propagation

## Notes

- execution.js was `not_chained` (launched via the downloaded Bun binary, not a followed import). It was read in full through two stacked derivations: d1 = prepare.py's obfuscator.io string-table recovery, d2 = registered decoder `scramble_v2` (reused, not newly written) replacing the direct `__decodeScrambled("literal")` calls. Bundled AWS/Azure/GCP/grpc/octokit/npm SDK modules were audited by sink inventory; their endpoints/env reads match those libraries. Nothing left unread.
- All gates are out-of-set (candidate null) because every real check is in execution.js, which the extractor never walked. The only prefilled candidates (setup.mjs win32 filename/extractor branches) are plumbing and were dropped.
- `if(!Z30() && mA0()) process.exit(0)` is NOT a gate: Z30 is CI detection and mA0 re-spawns the process detached (env `__DAEMONIZED=1`) with the parent exiting. This only picks foreground (CI) vs backgrounded execution of the same payload.
- g2 (Russian-locale exit) and g3 (pid lock) are sequential early-exit guards over the same downstream collection, so in practice that collection needs c2 && c3. Reported separately per the extractor's structure; flagged for review.
- Cipher needles passed by member access (not string literals) stay ciphertext in d2. Replaying `scramble_v2` over those strings gives `release-please.yml` for c6 (GITHUB_WORKFLOW_REF) and `ru` for J30's Intl and SystemRoot-branch tests, the same prefix as the plain test. No registered derivation rebuilds these values, so a reviewer has to replay the ciphertext to check them.
- g2's recipe `locale: en-US` stays marked guessed: the code only excludes locales starting with `ru`, so any other locale passes.
- Dune-themed identifier arrays (sardaukar/sandworm/...) plus the GitHub-Actions self-republish worm logic match the public "Shai-Hulud" npm worm campaign (family_hint).
- Endpoint list trimmed to the install-time-relevant hosts (Bun release download, api.github.com commit-search C2 and GraphQL/REST exfil+commit, npm OIDC token exchange); the bundle's many AWS/Azure/GCP/octokit SDK default/doc URLs were removed as not contacted unless those credential sources exist.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@cap-js/db-service",
    "version": "2.10.1",
    "archive_sha256": "893729fbd285d0278850bd48f818d83a86be215bceb0c7f62922772e98c4b834",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-04-29",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-04-29-@cap-js_db-service-v2.10.1.zip",
    "package_root": "layer0/tmp/tmp4fvbypgu/@cap-js-db-service/package",
    "cluster_key": "95d6849076c3ead79dcf3664ff49d9e69cdd0603c5c6c008405cc589c00adaac",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node setup.mjs",
        "runs_on": "always",
        "file_chain": [
          "setup.mjs",
          "execution.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "dropped_binary",
          "detached_child",
          "decoded_eval"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "preinstall runs `node setup.mjs`: if `bun` is not on PATH (gate g1) it downloads the Bun runtime from github.com/oven-sh/bun releases, writes it to a temp dir, extracts (unzip, or PowerShell on win32), chmods and runs the bundled payload execution.js under Bun.",
      "execution.js (11.7 MB) was not_chained (run via the downloaded Bun binary, not a followed import). Resolved: read in full, added to the entry file_chain, unrecovered entry removed.",
      "execution.js is an obfuscator.io string-array bundle; prepare.py recovered the table into d1. On top, a bespoke pbkdf2-keyed per-byte substitution cipher (salt 'ctf-scramble-v2') sits behind globalThis.__decodeScrambled/K5; I reused decoder scramble_v2 to derive d2 from d1.",
      "Coverage: package code read in full via d2 (kZh/jZh/bZh, collectors uhf/whf/w6f, senders, self-republish el/CW, cipher Jc); bundled AWS/Azure/GCP/grpc/octokit/npm SDK modules audited by sink inventory, hits all library behaviour; nothing left unread.",
      "Repair: d2 leaves cipher needles passed by member access as ciphertext. Replaying scramble_v2 over those strings gives c6 = release-please.yml and 'ru' for both other J30 tests (Intl locale, SystemRoot branch). No registered derivation rebuilds this; d2 shows only the ciphertext.",
      "Repair: c2 cites only the LC_ALL/LC_MESSAGES/LANGUAGE/LANG test. J30 also exits on an Intl locale starting with ru, and on win32-style hosts (SystemRoot set) on LANG/LANGUAGE/LC_ALL starting with ru. All three use the same needle, so Phase 2 must keep every locale source non-ru.",
      "Repair g6: ~/.aws/credentials, ~/.ssh/id_ed25519 and ~/.npmrc are literal entries in the Na1 LINUX hotspot list, so the recipe is read, not guessed. Any one listed file opens the gate.",
      "Entry flow: kZh -> jZh. jZh runs bZh first (g4), then if(J30()) exit (g2, Russian-locale), then the daemonize line (not a gate), then if(!aA0()) exit (g3, pid lock). kZh then runs dZh collectors and exfiltrates.",
      "c3 (repair): aA0 returns false only when the lock file exists AND lZh(pid) finds that pid alive (process.kill(pid, 0)); a missing or stale lock passes (stale lock unlinked, own pid written). Operator is `other` because the positive form is 'lock absent or holder dead'.",
      "All execution.js gates are downstream of g1 (bun absent). g2 (locale) and g3 (lock) are sequential early-exit guards over the same collection, so that collection effectively needs c2 && c3 together.",
      "Not a gate: `if(!Z30() && mA0()) process.exit(0)` in jZh. Z30 is CI detection; mA0 re-spawns the process detached (env __DAEMONIZED=1) and the parent exits. It only picks foreground (CI) vs backgrounded execution of the same payload = plumbing.",
      "Exfil (not a separate gate): collector results are gzip + AES-256-GCM encrypted, the key RSA-OAEP encrypted to a bundled public key (u6f.createEnvelope), and pushed via GitHub/npm/cloud senders. kA0 pulls an attacker GitHub token from api.github.com commit-search results keyed by constant VI.",
      "Dune-themed id arrays (sardaukar/sandworm/...) plus GitHub-Actions self-republish worm logic match the public 'Shai-Hulud' npm worm campaign.",
      "The g4 self-republish (el/CW) commits blobs to repo branches: .vscode/tasks.json (folderOpen task -> node .claude/setup.mjs), .claude/settings.json (Claude Code SessionStart hook -> node .vscode/setup.mjs), setup.mjs copies and execution.js; re-infects anyone opening the repo.",
      "Repair g2/g3: exfil path is kZh al.run -> finalize -> flush -> sl.dispatch -> sender.send -> Fc.commitToRepo -> octokit createOrUpdateFileContents, writing results/*.json. Only Fc defines send; its receiver comes from an array of E6f.tryCreate results, so that hop stays dynamic_dispatch.",
      "Repair g2/g3: recon is whf.execute copying all of process.env into its result, cited at the this.success call that returns it. If both tryCreate calls give null, sl throws and nothing is sent: exfil also needs a GitHub token, from kA0 or from the harvest.",
      "Repair g6: c9 covers the three tests on one stat result (stat throws, isFile, size <= 5 MiB). It stays one condition because the size cap is a test of the same value, not a second environmental check.",
      "Embedded base64+gzip blob decoded as data via decode.py: a Python script read by the g5 `sudo python3` pipe that walks /proc/<Runner.Worker>/maps and /proc/<pid>/mem to dump the GitHub Actions runner process memory."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "github[.]com:443, api[.]github[.]com:443, registry[.]npmjs[.]org:443",
      "reason": "Downloads the Bun runtime from github.com, pulls an attacker token from api.github.com commit search, and exfiltrates / self-republishes via GitHub and npm."
    },
    {
      "axis": "installed_tool",
      "value": "unzip",
      "reason": "extractBun uses `unzip` to unpack the downloaded Bun archive on non-Windows hosts (PowerShell Expand-Archive on win32); without an extractor the install throws."
    },
    {
      "axis": "installed_tool",
      "value": "python3",
      "reason": "The GitHub Actions runner-memory secret scrape pipes its script into `sudo python3` (only on the Linux-runner branch, gate g5)."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "installed_tool",
      "api": "child_process.execFileSync",
      "operator": "not_exists",
      "value": "bun",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "exec",
        "callee": "child_process.execFileSync",
        "target": "bun --version",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 3635,
            "end_byte": 3652,
            "node_type": "call_expression",
            "sha256": "77dfb37a5c4ccca4",
            "line": 123
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "locale_language",
      "api": "process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10817475,
            "end_byte": 10817601,
            "node_type": "call_expression",
            "sha256": "4769d840f50795ae",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "other",
      "value": "no live lock holder: <os.tmpdir()>/tmp.987654321.lock is absent, or the pid stored in it is not a live process (process.kill(pid, 0) throws, lZh); a stale lock is unlinked and overwritten",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "<os.tmpdir()>/tmp.987654321.lock",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10847015,
            "end_byte": 10847047,
            "node_type": "call_expression",
            "sha256": "33afefdb69203e86",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848331,
            "end_byte": 10848357,
            "node_type": "member_expression",
            "sha256": "5cc8b904f47b1e02",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "includes",
      "value": "/cds-dbs",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848625,
            "end_byte": 10848668,
            "node_type": "call_expression",
            "sha256": "1e97f83ef06a00ef",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "env_var",
      "api": "process.env.GITHUB_WORKFLOW_REF",
      "operator": "includes",
      "value": "release-please.yml",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848557,
            "end_byte": 10848623,
            "node_type": "call_expression",
            "sha256": "5df7f4413f9a0054",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "==",
      "value": "true",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10832467,
            "end_byte": 10832535,
            "node_type": "call_expression",
            "sha256": "698549f04411e05b",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10833118,
            "end_byte": 10833178,
            "node_type": "call_expression",
            "sha256": "2a0cd0347cedb525",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "fs.promises.stat",
      "operator": "other",
      "value": "regular file of at most 5 MiB (stat succeeds, isFile() true, size <= Ya1 = 0x500000) at an OS-selected developer credential/secret path (~/.aws, ~/.ssh, ~/.npmrc, wallet and token files, kube serviceaccount token)",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "fs.promises.stat",
        "target": "<hotspot path>",
        "accessor": "other"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10827282,
            "end_byte": 10827310,
            "node_type": "call_expression",
            "sha256": "a39097816a0aa07c",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10827347,
            "end_byte": 10827388,
            "node_type": "call_expression",
            "sha256": "a11f338ec4d09e68",
            "line": 1
          }
        }
      ],
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
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 3631,
            "end_byte": 3661,
            "node_type": "if_statement",
            "sha256": "6f19edfbc473bc93",
            "line": 123
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "The payload is delivered only when bun is absent: if `bun --version` succeeds main() returns before downloading and running execution.js, so a host with Bun pre-installed sees no payload.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "spawn_process",
          "exec_downloaded"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 4135,
            "end_byte": 4163,
            "node_type": "call_expression",
            "sha256": "4e2cca90c46dc04c",
            "line": 136
          },
          {
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 4300,
            "end_byte": 4396,
            "node_type": "call_expression",
            "sha256": "32503977750a4b2f",
            "line": 141
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 1380,
              "end_byte": 2227,
              "node_type": "call_expression",
              "sha256": "a2edf51fbed3e0bf",
              "line": 47
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 4135,
                  "end_byte": 4163,
                  "node_type": "call_expression",
                  "sha256": "4e2cca90c46dc04c",
                  "line": 136
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 1264,
                  "end_byte": 2339,
                  "node_type": "function_declaration",
                  "sha256": "b56bcad2c12b5afb",
                  "line": 45
                }
              }
            ]
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 4300,
              "end_byte": 4396,
              "node_type": "call_expression",
              "sha256": "32503977750a4b2f",
              "line": 141
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10849183,
            "end_byte": 10849291,
            "node_type": "if_statement",
            "sha256": "63b36e3a4c5c7208",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ],
          "via": [
            {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10849918,
              "end_byte": 10849941,
              "node_type": "call_expression",
              "sha256": "652bb09050a38e4b",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "jZh calls process.exit(0) when the host locale (Intl / LANG / LC_* / LANGUAGE) indicates Russian, limiting the credential-harvest and exfil payload to non-Russian-locale victims.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "locale": "en-US"
        },
        "recipe_guessed_fields": [
          "locale"
        ],
        "regions": [
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10849962,
            "end_byte": 10849985,
            "node_type": "call_expression",
            "sha256": "fe24473966c030e0",
            "line": 1
          },
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10850177,
            "end_byte": 10850321,
            "node_type": "lexical_declaration",
            "sha256": "50db31ede5627fd2",
            "line": 1
          },
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10850874,
            "end_byte": 10850972,
            "node_type": "call_expression",
            "sha256": "e19dae545c90af57",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10816640,
              "end_byte": 10816772,
              "node_type": "call_expression",
              "sha256": "e577241dff5b7368",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849962,
                  "end_byte": 10849985,
                  "node_type": "call_expression",
                  "sha256": "fe24473966c030e0",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849981,
                  "end_byte": 10849984,
                  "node_type": "identifier",
                  "sha256": "ccb14387c3175e53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847534,
                  "end_byte": 10848064,
                  "node_type": "function_declaration",
                  "sha256": "86295bd0fdefd2d1",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847764,
                  "end_byte": 10847783,
                  "node_type": "variable_declarator",
                  "sha256": "3cfef6d3fd408c5f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847953,
                  "end_byte": 10847975,
                  "node_type": "call_expression",
                  "sha256": "ad218acc82c2b9ec",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10816339,
                  "end_byte": 10817027,
                  "node_type": "method_definition",
                  "sha256": "1c76cb49b4f812b1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10816951,
              "end_byte": 10816977,
              "node_type": "call_expression",
              "sha256": "28ae2e23241a6218",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849962,
                  "end_byte": 10849985,
                  "node_type": "call_expression",
                  "sha256": "fe24473966c030e0",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849981,
                  "end_byte": 10849984,
                  "node_type": "identifier",
                  "sha256": "ccb14387c3175e53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847534,
                  "end_byte": 10848064,
                  "node_type": "function_declaration",
                  "sha256": "86295bd0fdefd2d1",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847764,
                  "end_byte": 10847783,
                  "node_type": "variable_declarator",
                  "sha256": "3cfef6d3fd408c5f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847953,
                  "end_byte": 10847975,
                  "node_type": "call_expression",
                  "sha256": "ad218acc82c2b9ec",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10816339,
                  "end_byte": 10817027,
                  "node_type": "method_definition",
                  "sha256": "1c76cb49b4f812b1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10842297,
              "end_byte": 10842501,
              "node_type": "call_expression",
              "sha256": "ce6069d8dcdb3dc8",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10850286,
                  "end_byte": 10850318,
                  "node_type": "pair",
                  "sha256": "9766ee8f3b4424a3",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10850874,
                  "end_byte": 10850972,
                  "node_type": "call_expression",
                  "sha256": "e19dae545c90af57",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543228,
                  "end_byte": 9543526,
                  "node_type": "method_definition",
                  "sha256": "62405c24b7183605",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543505,
                  "end_byte": 9543523,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543126,
                  "end_byte": 9543228,
                  "node_type": "method_definition",
                  "sha256": "ab9a1103ac54732c",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543172,
                  "end_byte": 9543187,
                  "node_type": "call_expression",
                  "sha256": "78973defb551976c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9542525,
                  "end_byte": 9543126,
                  "node_type": "method_definition",
                  "sha256": "5ebe02280ac6c937",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9542790,
                  "end_byte": 9542817,
                  "node_type": "call_expression",
                  "sha256": "79469854aa5e7508",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9544119,
                  "end_byte": 9545433,
                  "node_type": "arrow_function",
                  "sha256": "ac67ac60b185425e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9544996,
                  "end_byte": 9545024,
                  "node_type": "call_expression",
                  "sha256": "36f2ae1a257e75ba",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10840485,
                  "end_byte": 10840888,
                  "node_type": "method_definition",
                  "sha256": "49f1353973474494",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10840855,
                  "end_byte": 10840886,
                  "node_type": "call_expression",
                  "sha256": "42e35a2853e01a69",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10841285,
                  "end_byte": 10843188,
                  "node_type": "method_definition",
                  "sha256": "48984564959518cc",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10849386,
            "end_byte": 10849613,
            "node_type": "if_statement",
            "sha256": "57e2144fbbd6f6ed",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ],
          "via": [
            {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10849918,
              "end_byte": 10849941,
              "node_type": "call_expression",
              "sha256": "652bb09050a38e4b",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Single-instance / reinfection guard: aA0 reads a pid lock file in os.tmpdir(); if it exists and that pid is alive jZh exits, otherwise it (re)writes its own pid and proceeds to kZh's collection and exfil. Phase 2 must ensure the lock is absent or stale.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_absent": [
            "<os.tmpdir()>/tmp.987654321.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10849962,
            "end_byte": 10849985,
            "node_type": "call_expression",
            "sha256": "fe24473966c030e0",
            "line": 1
          },
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10850177,
            "end_byte": 10850321,
            "node_type": "lexical_declaration",
            "sha256": "50db31ede5627fd2",
            "line": 1
          },
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10850874,
            "end_byte": 10850972,
            "node_type": "call_expression",
            "sha256": "e19dae545c90af57",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10816640,
              "end_byte": 10816772,
              "node_type": "call_expression",
              "sha256": "e577241dff5b7368",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849962,
                  "end_byte": 10849985,
                  "node_type": "call_expression",
                  "sha256": "fe24473966c030e0",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849981,
                  "end_byte": 10849984,
                  "node_type": "identifier",
                  "sha256": "ccb14387c3175e53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847534,
                  "end_byte": 10848064,
                  "node_type": "function_declaration",
                  "sha256": "86295bd0fdefd2d1",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847764,
                  "end_byte": 10847783,
                  "node_type": "variable_declarator",
                  "sha256": "3cfef6d3fd408c5f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847953,
                  "end_byte": 10847975,
                  "node_type": "call_expression",
                  "sha256": "ad218acc82c2b9ec",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10816339,
                  "end_byte": 10817027,
                  "node_type": "method_definition",
                  "sha256": "1c76cb49b4f812b1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10816951,
              "end_byte": 10816977,
              "node_type": "call_expression",
              "sha256": "28ae2e23241a6218",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849962,
                  "end_byte": 10849985,
                  "node_type": "call_expression",
                  "sha256": "fe24473966c030e0",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10849981,
                  "end_byte": 10849984,
                  "node_type": "identifier",
                  "sha256": "ccb14387c3175e53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847534,
                  "end_byte": 10848064,
                  "node_type": "function_declaration",
                  "sha256": "86295bd0fdefd2d1",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847764,
                  "end_byte": 10847783,
                  "node_type": "variable_declarator",
                  "sha256": "3cfef6d3fd408c5f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10847953,
                  "end_byte": 10847975,
                  "node_type": "call_expression",
                  "sha256": "ad218acc82c2b9ec",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10816339,
                  "end_byte": 10817027,
                  "node_type": "method_definition",
                  "sha256": "1c76cb49b4f812b1",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10842297,
              "end_byte": 10842501,
              "node_type": "call_expression",
              "sha256": "ce6069d8dcdb3dc8",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10850286,
                  "end_byte": 10850318,
                  "node_type": "pair",
                  "sha256": "9766ee8f3b4424a3",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10850874,
                  "end_byte": 10850972,
                  "node_type": "call_expression",
                  "sha256": "e19dae545c90af57",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543228,
                  "end_byte": 9543526,
                  "node_type": "method_definition",
                  "sha256": "62405c24b7183605",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543505,
                  "end_byte": 9543523,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543126,
                  "end_byte": 9543228,
                  "node_type": "method_definition",
                  "sha256": "ab9a1103ac54732c",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9543172,
                  "end_byte": 9543187,
                  "node_type": "call_expression",
                  "sha256": "78973defb551976c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9542525,
                  "end_byte": 9543126,
                  "node_type": "method_definition",
                  "sha256": "5ebe02280ac6c937",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9542790,
                  "end_byte": 9542817,
                  "node_type": "call_expression",
                  "sha256": "79469854aa5e7508",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9544119,
                  "end_byte": 9545433,
                  "node_type": "arrow_function",
                  "sha256": "ac67ac60b185425e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 9544996,
                  "end_byte": 9545024,
                  "node_type": "call_expression",
                  "sha256": "36f2ae1a257e75ba",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10840485,
                  "end_byte": 10840888,
                  "node_type": "method_definition",
                  "sha256": "49f1353973474494",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10840855,
                  "end_byte": 10840886,
                  "node_type": "call_expression",
                  "sha256": "42e35a2853e01a69",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "execution.js",
                  "derived_from": "d2",
                  "start_byte": 10841285,
                  "end_byte": 10843188,
                  "node_type": "method_definition",
                  "sha256": "48984564959518cc",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g4",
      "hook": "preinstall",
      "expression": "c4 && c5 && c6",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848328,
            "end_byte": 10848734,
            "node_type": "if_statement",
            "sha256": "8a00567c49d8b9b0",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c4"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848435,
            "end_byte": 10848733,
            "node_type": "if_statement",
            "sha256": "bf4ec9bf2cca2a61",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5",
            "c6"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Only inside GitHub Actions for the real cds-dbs repository (GITHUB_REPOSITORY includes '/cds-dbs' and GITHUB_WORKFLOW_REF includes 'release-please.yml') does bZh run el().execute(), which pushes attacker-controlled files to the repo's branches via the GitHub GraphQL commit API.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "ci": "true",
          "env_var": {
            "GITHUB_ACTIONS": null,
            "GITHUB_REPOSITORY": "cap-js/cds-dbs",
            "GITHUB_WORKFLOW_REF": "release-please.yml"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10848435,
            "end_byte": 10848733,
            "node_type": "if_statement",
            "sha256": "bf4ec9bf2cca2a61",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10848675,
              "end_byte": 10848696,
              "node_type": "call_expression",
              "sha256": "ba018d9fef5243a5",
              "line": 1
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
      "hook": "preinstall",
      "expression": "c7 && c8",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10833044,
            "end_byte": 10833115,
            "node_type": "if_statement",
            "sha256": "b2fa71e2454cb263",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10833115,
            "end_byte": 10833257,
            "node_type": "if_statement",
            "sha256": "db7c82e30b5ac4cc",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "w6f.execute only acts on a Linux GitHub Actions runner (GITHUB_ACTIONS === 'true' and RUNNER_OS === 'Linux'); there it pipes a bundled Python script into `sudo python3` to scrape the Actions runner process memory for isSecret values.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read",
          "recon"
        ],
        "env_recipe": {
          "ci": "true",
          "os": "linux",
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10833363,
            "end_byte": 10833526,
            "node_type": "call_expression",
            "sha256": "38ec694571ea41b3",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10833363,
              "end_byte": 10833526,
              "node_type": "call_expression",
              "sha256": "38ec694571ea41b3",
              "line": 1
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g6",
      "hook": "preinstall",
      "expression": "c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10827311,
            "end_byte": 10827344,
            "node_type": "if_statement",
            "sha256": "34ba8acd8d1d9d0c",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10827344,
            "end_byte": 10827559,
            "node_type": "if_statement",
            "sha256": "b77d78bfd9901cb0",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c9"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "uhf reads an OS-selected list of developer credential/secret hotspot files, stat-ing each and reading only regular files of at most 5 MiB (larger ones get an error string instead of their content); it harvests whatever credential material is present on the host.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "file_present": [
            "~/.aws/credentials",
            "~/.ssh/id_ed25519",
            "~/.npmrc"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "execution.js",
            "derived_from": "d2",
            "start_byte": 10827559,
            "end_byte": 10827635,
            "node_type": "lexical_declaration",
            "sha256": "f923238d1f9f5b19",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "execution.js",
              "derived_from": "d2",
              "start_byte": 10827580,
              "end_byte": 10827612,
              "node_type": "call_expression",
              "sha256": "ce0d10a294708b01",
              "line": 1
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
    "ungated": [],
    "gated": [
      "download",
      "write_file",
      "spawn_process",
      "exec_downloaded",
      "recon",
      "cred_read",
      "exfil",
      "self_propagation"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "obfuscator.io string array",
      "array rotation checksum",
      "hex identifiers",
      "escaped strings",
      "very long lines",
      "bespoke pbkdf2-keyed per-byte substitution cipher (ctf-scramble-v2) behind __decodeScrambled/K5",
      "base64+gzip embedded payloads (VS Code tasks, Claude Code hook, runner-memory python)",
      "bundling (Bun single-file build with AWS/Azure/GCP/octokit/npm SDKs)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/oven-sh/bun/releases/download/bun-v$",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/search/commits?q=",
        "role": "c2"
      },
      {
        "indicator": "hxxps://api[.]github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://api[.]github[.]com/graphql",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org/-/npm/v1/oidc/token/exchange/package/",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://github[.]com/",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook downloads a Bun runtime and runs a heavily obfuscated bundled payload that harvests credentials (gh auth token, OS-selected credential files, cloud/npm secrets, and GitHub Actions runner process memory), encrypts and exfiltrates them, and self-propagates by committing attacker files to the cds-dbs repository's branches. Execution is gated by bun-absence, non-Russian locale, a pid lock, GitHub-Actions/repo targeting and a Linux-runner check.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All gates are out-of-set (candidate null): the real checks live in execution.js, which was not_chained and only reached via a downloaded Bun binary.",
    "execution.js payload read through two stacked derivations (obfuscator.io string table d1 + bespoke scramble_v2 cipher d2). c6's needle and J30's two member-access prefixes stay ciphertext in d2; they were decoded by replaying scramble_v2 over the copied strings, which no registered derivation rebuilds.",
    "g2/g3 cred_read and recon witnesses are traced through dZh to whf.execute. Their exfil witness runs to Fc.commitToRepo, but the send receiver comes from an array of tryCreate results, so that entry stays unresolved dynamic_dispatch.",
    "g1 env_recipe cannot express 'bun absent' with the allowed keys; recipe left empty and described in purpose_reason.",
    "Registered a candidate decoder reuse (scramble_v2) and a new derivation d2.",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "obfuscatorio_strings",
        "recipe_version": 1,
        "input": {
          "file": "execution.js",
          "derived_from": null
        },
        "params": {
          "provider": "_0x5a58",
          "decoder": "_0x44a0",
          "offset": 250,
          "variant": "base64",
          "form": "v2",
          "table_size": 48787,
          "rotations": 451,
          "checksum_target": 334346,
          "callables": 18760
        },
        "output_sha256": "20d327f2bb56fa5f",
        "stats": {
          "calls_total": 166100,
          "substituted": 166100,
          "unresolved": 0
        }
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "execution.js",
          "derived_from": "d1"
        },
        "params": {
          "key": "0255fcabd10ca14282d22e4d06bb53d19dd351c56ebe99f5775280f9c8e59145",
          "salt": "ctf-scramble-v2",
          "fn": "__decodeScrambled",
          "decoder": "scramble_v2",
          "lang": "js"
        },
        "output_sha256": "b8b8007a61924499"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "ef7e6cfbbf50e6e3"
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
        "candidate": "k_0e3be12221",
        "reason_code": "other",
        "note": "setup.mjs process.platform==='win32' only selects the bun binary filename (bun.exe vs bun); both branches run the same downloaded execution.js, so it gates no behaviour (plumbing).",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 3711,
          "end_byte": 3739,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 126
        }
      },
      {
        "candidate": "k_5fcf090a4e",
        "reason_code": "other",
        "note": "setup.mjs process.platform!=='win32' in extractBun only chooses the archive extractor (unzip vs PowerShell Expand-Archive); both extract the same Bun binary (plumbing).",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 2790,
          "end_byte": 2818,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 96
        }
      },
      {
        "candidate": "q_813f1d7772",
        "reason_code": "other",
        "note": "guard for the bun.exe/bun filename ternary; plumbing, see k_0e3be12221.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 3759,
          "end_byte": 3784,
          "node_type": "ternary_expression",
          "sha256": "29fd41494f70db45",
          "line": 127
        }
      },
      {
        "candidate": "q_30fe1bc14f",
        "reason_code": "other",
        "note": "guard for the win32 extractor branch in extractBun; plumbing, both branches extract the Bun binary.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 2786,
          "end_byte": 3476,
          "node_type": "if_statement",
          "sha256": "4573eda8440f859f",
          "line": 96
        }
      },
      {
        "candidate": "q_7f9b1af689",
        "reason_code": "other",
        "note": "guard for the non-win chmod of the extracted Bun binary; plumbing, prepares the same binary for exec.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 4254,
          "end_byte": 4295,
          "node_type": "if_statement",
          "sha256": "9ec3b0c3808b625e",
          "line": 140
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 5,
    "conditions_in_set": 0,
    "conditions_out_of_set": 9,
    "guard_candidates": 59,
    "gates_in_set": 0,
    "gates_out_of_set": 6,
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
      "g1",
      "g2",
      "g3",
      "g4",
      "g5",
      "g6"
    ],
    "anchor_refusals": 0
  }
}
```
