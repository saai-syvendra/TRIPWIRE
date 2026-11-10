# npm executable-stories-jest@6.1.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised copy of the real `executable-stories-jest` package with a malicious `binding.gyp` and `index.js` injected. On install, npm runs the implicit `node-gyp rebuild`, and `binding.gyp`'s `sources` field uses a gyp command expansion `<!(node index.js > /dev/null 2>&1 && echo stub.c)`, so `node index.js` executes at install time. `index.js` is a 4.5 MB self-decoding dropper: a decimal char-code array is Caesar-shifted (ROT3) and `eval`ed, which decrypts two AES-128-GCM stages (an installer `_b` and the main payload `_p`), writes `_p` to `/tmp/p<rand>.js`, downloads the official Bun v1.3.13 runtime from GitHub, and runs the payload with `bun run`. The payload is the Shai-Hulud "Second Coming" npm worm (obfuscator.io + a scramble_feistel per-string cipher): it harvests npm/GitHub/RubyGems/Anthropic and cloud credentials, republishes packages and pushes to GitHub to self-propagate, and drops a second-stage updater. A universal guard `uX()` gates all theft behind anti-analysis checks (non-Russian locale, no honeypot cwd/AWS decoy, a PID lock), and individual modules add CPU/EDR/CI and OS gates.

## Execution

- **node_gyp_implicit** `node-gyp rebuild (binding.gyp sources: <!(node index.js > /dev/null 2>&1 && echo stub.c))`: 2-file chain; native_build, direct_script, decoded_eval, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | node_gyp_implicit | c1 && c2 && c3 (c1: locale_language not_startswith ru; c2: vm_sandbox_artifact not_startswith /tmp/npm-safe/; c3: file_content not_includes FAKE) | then | 3 | recon, cred_read, exfil | locale=en_US |
| g2 | node_gyp_implicit | c4 \|\| c12 (c4: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock; c12: process_list falsy) | then | 1 | cred_read, exfil | file_absent=<tmpdir>/tmp.0144018410.lock |
| g3 | node_gyp_implicit | c5 && c6 && c7 (c5: hardware >= 4; c6: process_list not_includes [falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys]; c7: process.env.CI falsy) | then | 3 | write_file, spawn_process | cpu_count=4; ci=false |
| g4 | node_gyp_implicit | c8 (c8: os in [darwin, linux]) | then | 1 | self_propagation | os=linux |
| g5 | node_gyp_implicit | (c9 \|\| c10) && c11 (c9: process.env.WORKFLOW_ID truthy; c10: process.env.REPO_ID_SUFFIX truthy; c11: process.env.GITHUB_ACTIONS truthy) | then | 2 | self_propagation | ci=true; env_var=WORKFLOW_ID=(set), GITHUB_ACTIONS=true |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/enables/unclear; g3 evade/enables/anti_analysis; g4 activate/enables/portability; g5 activate/enables/targeting

Grounding: 0 of 12 conditions and 0 of 5 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, g1, g2, g3, g4, g5.

## Requirements

- network: github[.]com:443, registry[.]npmjs[.]org:443, api[.]github[.]com:443, rubygems[.]org:443, api[.]anthropic[.]com:443 (_b downloads the Bun runtime from github; _p validates/exfiltrates npm, GitHub, RubyGems and Anthropic credentials and republishes packages to these registries.)
- installed_tool: curl, unzip, bash (_b uses curl+unzip to fetch and extract Bun; the i1 updater module runs the dropped script via bash.)

## Behaviour

- Ungated: write_file, download, exec_downloaded, spawn_process
- Gated: recon, cred_read, exfil, write_file, spawn_process, self_propagation

## Notes

- Decode chain, all via registered decoders (derivations in the record): d8 `charcode_caesar_eval` (whole file) -> d10 `aesgcm_hex_stage` for `_b`, d9 for `_p` -> d11 `obfio_scoped` (string array) -> d12 `scramble_feistel` (fn `f489094fb`, key `77afe07f...`, salt `74eb1241...`). I wrote a redundant custom caesar decoder first and replaced it with the existing built-in; the stub left in `decoders/charcode_caesar.py` is marked superseded and should not be registered.
- Gates recorded: g1 locale/honeypot evade and g2 PID-lock, both inside `uX()` (process.exit, so guards carry `via=[await uX()]`); g3 the i1 updater-drop module (cpu>=4 && no-EDR && not-CI); g4 OS darwin/linux for the npm republish; g5 the GitHub Actions self-replication (WORKFLOW_ID/REPO_ID_SUFFIX + GITHUB_ACTIONS).
- Not individually modelled (flagged for review): w6 filesystem secret scan gated by EDR; a harden-runner/Runner.Worker detection (`wX`) that exits; sudo tampering of `/etc/hosts` and `/etc/resolv.conf` (defense_evasion) behind that detection. `__IS_DAEMON` (detached self-respawn when not CI) and `GX` (i1 run-once) are re-entry guards, noted not gated.
- g1/g2 payloads reach their sinks through a streaming module dispatch (`_3`/`PX` run modules dynamically), so those witnesses are `unresolved=dynamic_dispatch`.
- Worm identity: `X6` tags republished tarballs `[npmoidc]` and injects a `Setup` gyp target (the same mechanism used here), reads `OIDC_PACKAGES`; embedded string `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner` and probes to `api.anthropic.com`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "executable-stories-jest",
    "version": "6.1.1",
    "archive_sha256": "c14564535e12a4d790bc6dd864af05d2661d57f7b67f7a0b57f4d020759135f5",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-04-executable-stories-jest-v6.1.1.zip",
    "package_root": "layer0/tmp/tmpr5s_tu_1/executable-stories-jest/package",
    "cluster_key": "b32eb5d149c6cb4c46befdc9272a68678ee7f29303c9aa6d1124e01a89c6caba",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "node_gyp_implicit",
        "command": "node-gyp rebuild (binding.gyp sources: <!(node index.js > /dev/null 2>&1 && echo stub.c))",
        "runs_on": "always",
        "file_chain": [
          "binding.gyp",
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "native_build",
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
      "node_gyp_implicit: delegates to node-gyp; code inside that dependency is out of scope.",
      "binding.gyp runs the payload: its sources use a gyp command expansion `<!(node index.js > /dev/null 2>&1 && echo stub.c)`, so node-gyp rebuild executes index.js at install. The extractor did not detect this launch; index.js added to file_chain.",
      "index.js: package code read in full via decode chain (d8 caesar char-code eval, d10 AES-128-GCM _b bun installer, d9 AES-128-GCM _p payload, d11 obfuscator.io string array, d12 scramble_feistel per-string cipher). Only the i1 updater's d7/n7 blobs stay encrypted (see the g3 note).",
      "index.js wrapper (ungated): decrypts _b/_p, writes _p to /tmp/p<rand>.js, downloads official Bun v1.3.13 from github (eval of _b installs/locates bun when runtime is not already Bun), then runs `bun run` on the dropped _p.",
      "All _p malicious behaviour sits behind the uX() guard (g1/g2); module gates g3/g4/g5 run only after uX passes. uX uses process.exit so its guards carry via=[await uX()].",
      "Re-entry guards (noted, not gates): __IS_DAEMON env var set on the detached self-respawn ($X, only when not CI); GX run-once flag in i1 after a successful updater run.",
      "i1 updater (g3): the dropped updater.py (d7) and the script piped to bash on stdin (n7) are further encrypted with the a() helper and were not decoded, so what the updater does is not known; the temp dir holding updater.py is removed in the finally block, so no persistence is claimed.",
      "Payload witnesses for g1/g2 cross the streaming module dispatch (_3 collectors and PX senders run modules dynamically via executeStreaming); marked unresolved=dynamic_dispatch.",
      "g1/g2 exfil path: finalize -> u1.flush -> this.dispatch (f1's arrow, bound by the 'dispatch' key of new u1) -> sender.send. The sender comes from i3's array, so the x9.send hop stays unresolved=dynamic_dispatch.",
      "i3 builds the x9 DomainSender (b6.tryCreate) unless SKIP_DOMAIN==\"true\", which uses p6 senders instead; p6 is also the fallback. This sender choice is not modelled as a gate.",
      "g2 (c4 || c12): yX continues when the lock file is absent (c4) or when it exists but process.kill(pid, 0) on its recorded pid throws, so mK is false (c12); the stale lock is then deleted and rewritten.",
      "c6 probe: execSync runs `tasklist 2>/dev/null` on win32 and `ps aux 2>/dev/null` elsewhere, so the target is written with * for the command. The value is the full DQ list; the output is lowercased and any entry makes w4 true.",
      "Additional _p module gates not individually modelled (flagged for review): w6 filesystem secret scan gated by EDR check w4; a harden-runner / Runner.Worker detection (wX) that process.exit(0)s; sudo writes to /etc/hosts and /etc/resolv.conf (defense_evasion) behind that detection.",
      "z7 also checks LANG/LC_ALL/LC_MESSAGES/LANGUAGE; H9 checks ~30 CI env vars; w4 checks 17 EDR process names + 7 EDR install paths; IX also tests decoy env prefixes (RK) and GITHUB_REPOSITORY==actions-security-demo/compromised-packages.",
      "Impersonates the real package executable-stories-jest (jagreehal/executable-stories); malicious binding.gyp+index.js injected. Shai-Hulud 'Second Coming' npm worm: X6 republishes tarballs tagged '[npmoidc]' and injects a 'Setup' gyp target; reads OIDC_PACKAGES."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "api[.]github[.]com:443",
        "rubygems[.]org:443",
        "api[.]anthropic[.]com:443"
      ],
      "reason": "_b downloads the Bun runtime from github; _p validates/exfiltrates npm, GitHub, RubyGems and Anthropic credentials and republishes packages to these registries."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip",
        "bash"
      ],
      "reason": "_b uses curl+unzip to fetch and extract Bun; the i1 updater module runs the dropped script via bash."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat().resolvedOptions().locale",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 178169,
            "end_byte": 178267,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c2",
      "category": "vm_sandbox_artifact",
      "api": "process.cwd",
      "operator": "not_startswith",
      "value": "/tmp/npm-safe/",
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 336807,
            "end_byte": 336855,
            "node_type": "call_expression",
            "sha256": "42883fa19751ffed",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c3",
      "category": "file_content",
      "api": "fs.readFileSync",
      "operator": "not_includes",
      "value": "FAKE",
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.readFileSync",
        "target": "~/.aws/credentials",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 336957,
            "end_byte": 337005,
            "node_type": "call_expression",
            "sha256": "2f7ba27e1b8b6d40",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c4",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "<tmpdir>/tmp.0144018410.lock",
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "<tmpdir>/tmp.0144018410.lock",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338074,
            "end_byte": 338087,
            "node_type": "call_expression",
            "sha256": "7b9d8fe4d3732eb5",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c5",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 288588,
            "end_byte": 288612,
            "node_type": "binary_expression",
            "sha256": "86f8bbfb8a68b73e",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c6",
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
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "* 2>/dev/null",
        "accessor": "stdout"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 181244,
            "end_byte": 181276,
            "node_type": "call_expression",
            "sha256": "6143271771feeb6b",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "falsy",
      "value": null,
      "value_recovered": "partial",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 179050,
            "end_byte": 179076,
            "node_type": "binary_expression",
            "sha256": "a1e133353ca470cc",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c8",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "darwin",
        "linux"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 189058,
            "end_byte": 189109,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c9",
      "category": "env_var",
      "api": "process.env.WORKFLOW_ID",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338404,
            "end_byte": 338427,
            "node_type": "member_expression",
            "sha256": "5a75660b7ff8bf6a",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c10",
      "category": "env_var",
      "api": "process.env.REPO_ID_SUFFIX",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338438,
            "end_byte": 338464,
            "node_type": "member_expression",
            "sha256": "0b7c6279e28e1af5",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c11",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338505,
            "end_byte": 338534,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c12",
      "category": "process_list",
      "api": "process.kill",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 337947,
            "end_byte": 337977,
            "node_type": "call_expression",
            "sha256": "e2c54388022987bb",
            "line": 1
          }
        }
      ]
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "node_gyp_implicit",
      "expression": "c1 && c2 && c3",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "uX() aborts before any theft when it detects an analysis/honeypot environment: a Russian locale, a /tmp/npm-safe/ working directory, or a decoy ~/.aws/credentials containing FAKE (plus decoy env prefixes).",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338962,
            "end_byte": 338991,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 581310,
              "end_byte": 581320,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338991,
            "end_byte": 339031,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
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
              "derived_from": "d12",
              "start_byte": 581310,
              "end_byte": 581320,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        }
      ],
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "locale": "en_US"
        },
        "recipe_guessed_fields": [
          "locale"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581321,
            "end_byte": 581578,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581335,
            "end_byte": 581345,
            "node_type": "await_expression",
            "sha256": "86cd92310201217b",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581744,
            "end_byte": 581773,
            "node_type": "await_expression",
            "sha256": "2887b595805175b0",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581842,
            "end_byte": 581861,
            "node_type": "await_expression",
            "sha256": "de5235e3cc8f7587",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 415439,
              "end_byte": 415517,
              "node_type": "call_expression",
              "sha256": "aac82ccc28f49c23",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581335,
                  "end_byte": 581345,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565545,
                  "end_byte": 565776,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565716,
                  "end_byte": 565744,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 415173,
                  "end_byte": 415972,
                  "node_type": "method_definition",
                  "sha256": "f4eb24f7548056a0",
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
              "derived_from": "d12",
              "start_byte": 415677,
              "end_byte": 415688,
              "node_type": "call_expression",
              "sha256": "65010ab91de87884",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581335,
                  "end_byte": 581345,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565545,
                  "end_byte": 565776,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565716,
                  "end_byte": 565744,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 415173,
                  "end_byte": 415972,
                  "node_type": "method_definition",
                  "sha256": "f4eb24f7548056a0",
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
              "derived_from": "d12",
              "start_byte": 572121,
              "end_byte": 572239,
              "node_type": "call_expression",
              "sha256": "5bd821d91242913e",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581543,
                  "end_byte": 581575,
                  "node_type": "pair",
                  "sha256": "0a0b2de5da960cb8",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581744,
                  "end_byte": 581773,
                  "node_type": "await_expression",
                  "sha256": "2887b595805175b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212597,
                  "end_byte": 212727,
                  "node_type": "method_definition",
                  "sha256": "3e1067e8c5280b20",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212671,
                  "end_byte": 212686,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212219,
                  "end_byte": 212597,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212493,
                  "end_byte": 212520,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 213417,
                  "end_byte": 214210,
                  "node_type": "arrow_function",
                  "sha256": "35cc8988a4450abf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 214080,
                  "end_byte": 214108,
                  "node_type": "call_expression",
                  "sha256": "a312c41be6301514",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 571917,
                  "end_byte": 572353,
                  "node_type": "method_definition",
                  "sha256": "621f471498dbac7c",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "node_gyp_implicit",
      "expression": "c4 || c12",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Single-instance lock: yX() aborts if a prior copy's PID (recorded in a tmpdir lock file) is still alive, otherwise writes its own PID; W6() removes the file at exit. It does not look for analysis, so it is a re-entry guard rather than evasion. Phase 2 must ensure the lock is absent so the payload runs.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 339160,
            "end_byte": 339165,
            "node_type": "unary_expression",
            "sha256": "49edb06643d91f6b",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c12"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 581310,
              "end_byte": 581320,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        }
      ],
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_absent": [
            "<tmpdir>/tmp.0144018410.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581321,
            "end_byte": 581578,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581335,
            "end_byte": 581345,
            "node_type": "await_expression",
            "sha256": "86cd92310201217b",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581744,
            "end_byte": 581773,
            "node_type": "await_expression",
            "sha256": "2887b595805175b0",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 581842,
            "end_byte": 581861,
            "node_type": "await_expression",
            "sha256": "de5235e3cc8f7587",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 415439,
              "end_byte": 415517,
              "node_type": "call_expression",
              "sha256": "aac82ccc28f49c23",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581335,
                  "end_byte": 581345,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565545,
                  "end_byte": 565776,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 565716,
                  "end_byte": 565744,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 415173,
                  "end_byte": 415972,
                  "node_type": "method_definition",
                  "sha256": "f4eb24f7548056a0",
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
              "derived_from": "d12",
              "start_byte": 572121,
              "end_byte": 572239,
              "node_type": "call_expression",
              "sha256": "5bd821d91242913e",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581543,
                  "end_byte": 581575,
                  "node_type": "pair",
                  "sha256": "0a0b2de5da960cb8",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 581744,
                  "end_byte": 581773,
                  "node_type": "await_expression",
                  "sha256": "2887b595805175b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212597,
                  "end_byte": 212727,
                  "node_type": "method_definition",
                  "sha256": "3e1067e8c5280b20",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212671,
                  "end_byte": 212686,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212219,
                  "end_byte": 212597,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 212493,
                  "end_byte": 212520,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 213417,
                  "end_byte": 214210,
                  "node_type": "arrow_function",
                  "sha256": "35cc8988a4450abf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 214080,
                  "end_byte": 214108,
                  "node_type": "call_expression",
                  "sha256": "a312c41be6301514",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 571917,
                  "end_byte": 572353,
                  "node_type": "method_definition",
                  "sha256": "621f471498dbac7c",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "node_gyp_implicit",
      "expression": "c5 && c6 && c7",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "The i1 module drops and runs a second-stage updater script only on a real host: requires at least 4 CPUs, no EDR agent present (w4), and not a CI environment (H9).",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 288827,
            "end_byte": 288872,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c7"
          ]
        }
      ],
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "ci": "false"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 288956,
            "end_byte": 289335,
            "node_type": "try_statement",
            "sha256": "8c055ed981f2c3cd",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 288960,
              "end_byte": 288998,
              "node_type": "call_expression",
              "sha256": "88de24f39016e60e",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 289013,
              "end_byte": 289104,
              "node_type": "call_expression",
              "sha256": "acc3af4cc0f3c98b",
              "line": 1
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "node_gyp_implicit",
      "expression": "c8",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "The npm package self-republish worm step runs only on darwin/linux; on other platforms it returns without downloading or republishing packages. The list only limits the step to Unix-like hosts and selects no victim.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 189055,
            "end_byte": 189429,
            "node_type": "if_statement",
            "sha256": "13ec33d6521da251",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8"
          ]
        }
      ],
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 189055,
            "end_byte": 189429,
            "node_type": "if_statement",
            "sha256": "13ec33d6521da251",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 189186,
              "end_byte": 189241,
              "node_type": "call_expression",
              "sha256": "c4ec66f5c6a0a259",
              "line": 1
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "node_gyp_implicit",
      "expression": "(c9 || c10) && c11",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Inside GitHub Actions (GITHUB_ACTIONS) with the worm's own WORKFLOW_ID/REPO_ID_SUFFIX markers matching the workflow ref/repository, bK() runs the CI self-replication (X6.execute) then exits.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338465,
            "end_byte": 338498,
            "node_type": "if_statement",
            "sha256": "58bc816e54e469cc",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c9",
            "c10"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338502,
            "end_byte": 338840,
            "node_type": "if_statement",
            "sha256": "0abdb84a676e8222",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11"
          ]
        }
      ],
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "ci": "true",
          "env_var": {
            "WORKFLOW_ID": null,
            "GITHUB_ACTIONS": "true"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 338714,
            "end_byte": 338741,
            "node_type": "await_expression",
            "sha256": "87346f0d08da50a9",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 338720,
              "end_byte": 338741,
              "node_type": "call_expression",
              "sha256": "f13363fbd43f5829",
              "line": 1
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
      "write_file",
      "download",
      "exec_downloaded",
      "spawn_process"
    ],
    "gated": [
      "recon",
      "cred_read",
      "exfil",
      "write_file",
      "spawn_process",
      "self_propagation"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "self-decoding eval: a decimal char-code array joined to a string then Caesar-shifted (ROT3) and passed to eval",
      "AES-128-GCM encrypted stages (_b bun installer, _p main payload) with keys/iv/authtag embedded as hex at the call site",
      "obfuscator.io string array with checksum-gated rotation",
      "scramble_feistel per-string substitution-permutation cipher (shai-hulud family)",
      "renamed identifiers and control flow routed through helper functions",
      "multiple third-party libraries inlined (tar, AWS SigV4, sigstore, HashiCorp Vault)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/",
        "role": "second_stage"
      },
      {
        "indicator": "registry[.]npmjs[.]org",
        "role": "exfil_sink"
      },
      {
        "indicator": "api[.]github[.]com",
        "role": "c2"
      },
      {
        "indicator": "rubygems[.]org",
        "role": "exfil_sink"
      },
      {
        "indicator": "api[.]anthropic[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "At install, binding.gyp runs `node index.js` via a gyp command expansion; index.js self-decodes (Caesar) and decrypts two AES-128-GCM stages, dropping the obfuscated Shai-Hulud worm payload to /tmp and running it under a downloaded Bun runtime. The payload harvests npm/GitHub/RubyGems/Anthropic/cloud credentials, republishes packages and pushes to GitHub to self-propagate, and drops a second-stage updater, gated by locale, CI, EDR, CPU and OS checks.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All gates are out-of-set (the extractor saw none; the install launch and the whole payload are hidden behind binding.gyp's gyp command expansion and five decode layers).",
    "g1/g2 payload witnesses cross a dynamic module dispatch (_3 collectors / PX senders run modules via executeStreaming) and are marked unresolved=dynamic_dispatch.",
    "Additional _p module gates are noted but not individually modelled: w6 filesystem secret scan gated by EDR (w4); a harden-runner/Runner.Worker detection (wX) that calls process.exit(0); sudo /etc/hosts and /etc/resolv.conf tampering (defense_evasion) behind that detection.",
    "c6 records w4's 17 EDR process names but not its 7 install paths (RQ); c7 (CI) records one representative value while H9 checks ~30 CI env vars (see notes).",
    "Payload decoded through registered decoders d8/d9/d10/d11/d12; derivations must be replayed by the verifier.",
    "The i1 updater's d7 (updater.py) and n7 (bash stdin script) are encrypted with the a() helper and not decoded; what g3's second stage does is unknown.",
    "condition value not fully recovered",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d8",
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
        "output_sha256": "c9fb35427f3cf404"
      },
      {
        "id": "d9",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d8"
        },
        "params": {
          "fn": "_d",
          "var": "_p",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "da39146ef451d1b1"
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
          "fn": "_d",
          "var": "_b",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "ceff7c51d70832c3"
      },
      {
        "id": "d11",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d9"
        },
        "params": {
          "decoder": "obfio_scoped",
          "lang": "js"
        },
        "output_sha256": "8434df42d4e26f68"
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
          "fn": "f489094fb",
          "key": "77afe07fa1eca63ce025ef790b33cdcde73da475c5a700acb14a5578b35d2813",
          "salt": "74eb124111aadb515960c4618132c1b4",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "31469ac8c0469a41"
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
