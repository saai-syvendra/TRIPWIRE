# npm @antv/data-set@0.12.8

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised release of the legitimate `@antv/data-set` package: version 0.12.8 adds a `preinstall` hook (`bun run index.js`) whose `index.js` has been replaced with the heavily obfuscated Shai-Hulud npm worm. At install the top-level `J2()` runs `x2()`, which performs the environment checks and then (unless in CI) daemonizes a detached copy of itself before scanning the filesystem and shell history for GitHub (`gh[op]_...`) and npm (`npm_...`) tokens and other secrets, validating stolen GitHub tokens against the GitHub API, and exfiltrating everything to an OpenTelemetry-disguised C2 at `t.m-kosche[.]com:443` (path `api/public/otel/v1/traces`). Gate g1 is the evade check at the top of `x2()`: it exits early if `GITHUB_TOKEN` begins with the decoy/canary value `ghp_decoyGitHubToken` or if the host locale/`LANG` begins with `ru`, so the theft only runs on a non-canary, non-Russian host (`min_conditions` = 3). Behind it, `J2`'s finally installs persistence: g2 (at least 4 CPUs and no CI marker) installs a monitor as a systemd user service or LaunchAgent, g3 (not darwin arm64) copies the payload to `~/.claude` and `~/.codex`, and g4 (a claude or codex `settings.json` exists) adds a SessionStart hook. g5 republishes packages through GitHub Actions OIDC on a matching workflow and repository. No behaviour is ungated.

## Execution

- **preinstall** `bun run index.js`: runs index.js; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 && c2 && c3 (c1: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken; c2: locale_language not_startswith ru; c3: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, spawn_process | env_var_absent=GITHUB_TOKEN |
| g2 | preinstall | c1 && c2 && c3 && c4 && c5 && c6 && c7 (c1: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken; c2: locale_language not_startswith ru; c3: locale_language not_startswith ru; c4: hardware >= 4; c5: process.env.CI != true; c6: process.env.GITHUB_ACTIONS != true; c7: process.env.JENKINS_HOME not_exists) | then | 7 | write_file, persistence | env_var_absent=GITHUB_TOKEN, CI, GITHUB_ACTIONS, JENKINS_HOME; cpu_count=4 |
| g3 | preinstall | c1 && c2 && c3 && (c8 \|\| c9) (c1: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken; c2: locale_language not_startswith ru; c3: locale_language not_startswith ru; c8: os != darwin; c9: arch != arm64) | then | 4 | write_file | env_var_absent=GITHUB_TOKEN |
| g4 | preinstall | c1 && c2 && c3 && (c8 \|\| c9) && c10 (c1: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken; c2: locale_language not_startswith ru; c3: locale_language not_startswith ru; c8: os != darwin; c9: arch != arm64; c10: target_artifact includes [claude, codex]) | then | 5 | persistence | env_var_absent=GITHUB_TOKEN; file_present=~/.claude/settings.json |
| g5 | preinstall | c1 && c11 && c12 && c13 (c1: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken; c11: process.env.GITHUB_ACTIONS truthy; c12: process.env.GITHUB_WORKFLOW_REF includes release.yml; c13: process.env.GITHUB_REPOSITORY includes /somerepository) | then | 4 | self_propagation | env_var=GITHUB_ACTIONS=(set), GITHUB_WORKFLOW_REF=release.yml, GITHUB_REPOSITORY=/somerepository, ACTIONS_ID_TOKEN_REQUEST_TOKEN=(set), ACTIONS_ID_TOKEN_REQUEST_URL=(set); env_var_absent=GITHUB_TOKEN |

Gate intent: g1 evade/enables/anti_analysis; g2 evade/enables/anti_analysis; g3 activate/enables/unclear; g4 activate/enables/data_availability; g5 activate/enables/targeting

Grounding: 0 of 13 conditions and 0 of 5 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, g1, g2, g3, g4, g5.

## Requirements

- network: t[.]m-kosche[.]com:443, api[.]github[.]com:443 (C2 exfil endpoint (OTLP-disguised) and the GitHub API used to validate/operate stolen tokens; without egress the stolen data cannot leave.)
- installed_tool: bun (The preinstall hook runs `bun run index.js`; bun must be on PATH for the payload to execute (the worm also tries to bootstrap bun via curl if missing).)
- installed_tool: python3 (The x7 script f7 pipes to bash exits unless python3 is present, so g2's monitor is only installed with it.)

## Behaviour

- Ungated: none
- Gated: recon, cred_read, exfil, spawn_process, write_file, persistence, self_propagation

## Notes

- `index.js` was recovered with three registered decode derivations: d4 (obfuscator.io base64 string array, rotation checksum matched), d5 (per-string feistel cipher behind the global `fc2edea72` function, key/salt/rounds static in the file) and d6 (AES-GCM and gzip blobs behind `a()`, used to read `Z7` and `x7`). All conditions and anchors are cited into d5. The repair read `x7` in full and only the start of `Z7` (`cat.py`), which runs later under the persistence it sets up. Other d6 blobs were not reviewed.
- Dropped the generator's prefilled candidates (`__DAEMONIZED` guard and the tmpdir PID lockfile) as `re_entry_guard`: the first stops the detached child re-daemonizing, the second is a self-managed single-instance lock that a fresh VM always passes.
- `q2()` is recorded as g5 (GitHub Actions + `GITHUB_WORKFLOW_REF` includes `release.yml` + `GITHUB_REPOSITORY` includes `/somerepository` -> `Lo.execute` republishes the packages in `uP`). Its strings and `uP=["aaaaa"]` look like unfilled attacker placeholders, so it likely does not fire on real victims; a reviewer should confirm it stays. Its else side exits with no theft on a matching repository, which is not folded into g1 to g4.
- `SKIP_DOMAIN === "true"` in `J2` picks the GitHub sender over the domain sender. It is a possible missed gate with effect `modifies` and is flagged, not recorded.
- The Harden-Runner defense-evasion code (`detectHardenRunner` -> `S1` -> `K2` writing `127[.]0[.]0[.]1` StepSecurity mappings to `/etc/hosts` via sudo) is present but `detectHardenRunner()` has no call site, so it is dead code and not counted.
- Gate g1 folds a canary-token (anti-analysis) and a Russian-locale (targeting) check into one evade gate; `purpose` set to `anti_analysis`. A reviewer may prefer to split them.
- A dead-drop fallback resolver (`x1("thebeautifulmarchoftime", ..)`) can supply a backup C2 domain if the primary is unhealthy.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@antv/data-set",
    "version": "0.12.8",
    "archive_sha256": "c25a05b1466b698cd38b42eae952aa828c30d4839af54968dcb91c20d128b80c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-05-19-@antv_data-set-v0.12.8.zip",
    "package_root": "layer0/tmp/tmp0xc8m6js/@antv-data-set/package",
    "cluster_key": "8725617c0ecc21e1d69876b6e8766a87334ed3cfbdd549e0ea93352486e61ec4",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "bun run index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "other",
        "launch_style": [
          "direct_script",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "preinstall `bun run index.js` runs the whole payload; interpreter is bun (not in enum, so `other`).",
      "index.js: worm payload read after three registered decodes (d4 obfuscator.io base64 string array, rotation checksum matched; d5 per-string feistel cipher behind fc2edea72; d6 AES-GCM blobs). Repair read x7 in full, Z7 only in part.",
      "The payload is injected into the legitimate @antv/data-set release; the surrounding library code was not separately diffed against upstream, but the worm is self-contained at module top level.",
      "Entry is top-level `J2().catch(..)`; J2 awaits x2() (environment checks) then scans for secrets and exfiltrates. All sinks sit behind x2()'s j1 check, and all but g5's behind its U7 check too, so there are no ungated behaviours.",
      "z1() daemonizes: spawns a detached copy of the install (process.execPath+argv, detached+unref, env __DAEMONIZED=1) when not in CI; __DAEMONIZED is a re-entry guard so the child does not re-daemonize. Dropped candidate c1/g1.",
      "a1() is a single-instance PID lockfile in tmpdir(): skips if the stored pid is still alive (process.kill(pid,0)), else removes the stale lock and writes its own pid. Self-managed concurrency lock, not a gate; a fresh VM always passes. Dropped c2/g2.",
      "q2(\"release.yml\",\"/somerepository\") is recorded as g5: under GITHUB_ACTIONS with GITHUB_WORKFLOW_REF including \"release.yml\" and GITHUB_REPOSITORY including \"/somerepository\", Lo.execute() gets an OIDC token and republishes the packages in uP.",
      "g5's strings and uP=[\"aaaaa\"] look like unfilled attacker placeholders, but the code tests them literally and a VM can set them, so the gate is recorded. It runs after j1() and before U7(), so only c1 of g1 applies to it.",
      "q2's else side exits with no theft when GITHUB_ACTIONS is set and GITHUB_REPOSITORY includes \"/somerepository\". That exit is not folded into g1 to g4; see review_reasons.",
      "U7() returns true (x2 exits) when any of three tests starts with 'ru': the Intl locale (c2), LC_ALL||LC_MESSAGES||LANGUAGE||LANG (c3), and on Windows (SystemRoot set) LANG||LANGUAGE||LC_ALL (second site of c3).",
      "Dead code: detectHardenRunner -> S1 -> K2 would append 127[.]0[.]0[.]1 mappings for StepSecurity domains to /etc/hosts via `sudo sh -c` (guarded by a `sudo -n true` probe), but detectHardenRunner() has no call site, so it is not reached.",
      "Secret scanners zo (filesystem) and vo (shell) match /gh[op]_[A-Za-z0-9]{36}/ and /npm_[A-Za-z0-9]{36,}/ across ~/.ssh, ~/.zsh_history, ~/.yarnrc, ~/.zcash/wallet.dat, docker container configs, wp-config.php; ko is a third scanner. Results are exfiltrated.",
      "Exfil config {domain:\"t.m-kosche[.]com\",port:443,path:\"api/public/otel/v1/traces\",dry_run:false} disguises C2 as an OpenTelemetry OTLP endpoint. lr.send POSTs the envelope with fetch.",
      "Exfil path: J2 -> Po.finalize -> flush -> Co.dispatch -> sender.send -> lr.send -> fetch. On the primary path po.tryCreate() returns an lr, stored in the senders list; _r (GitHub sender) is the fallback when lr is unhealthy or SKIP_DOMAIN is \"true\".",
      "The b() -> X() -> fetch path to api.github.com/user is recorded as recon: it reads the token owner and scopes for a stolen token. It sends nothing to the attacker, so it is no longer the exfil sink.",
      "A dead-drop fallback resolver x1(\"thebeautifulmarchoftime\", ..) can supply a backup C2 domain if the primary is unhealthy.",
      "J2's finally runs Vo.execute(), skipped on darwin arm64: it copies the payload to ~/.claude/package and ~/.codex/package (g3), and addHook writes a SessionStart hook with the ZR bun bootstrap into writable claude/codex settings.json files (g4).",
      "J2's finally also runs f7() behind CP() (g2). a7 in CP is an in-memory flag that is false on the first call, so it is not a condition.",
      "d6 (aesgcm_gunzip over d5) decrypts the a(key, blob) strings. Z7 is cat.py, a monitor that polls GitHub commit search for commands matching a pattern, with an RSA public key in the script. x7 is the bash script f7 pipes in.",
      "x7 copies cat.py to ~/.local/share/kitty and installs it as a systemd user service (Linux) or a LaunchAgent (macOS), so f7 is persistence. It exits on any other OS or without python3.",
      "g2 to g4 sit in J2's finally, not after x2() in the try block. The finally still only runs past x2's exits because process.exit ends the process, so c1 to c3 are in their expressions even though the x2 guards do not syntactically enclose those regions.",
      "g1 recipe: the code only shows the locale must not start with ru, so no locale value is given; any other locale passes c2 and c3. g3 likewise has no os or arch value: anything but darwin arm64 passes.",
      "g4 recipe: ~/.claude/settings.json is one path that passes the test; any writable settings.json under the home folder with claude or codex in its path does."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "t[.]m-kosche[.]com:443",
        "api[.]github[.]com:443"
      ],
      "reason": "C2 exfil endpoint (OTLP-disguised) and the GitHub API used to validate/operate stolen tokens; without egress the stolen data cannot leave."
    },
    {
      "axis": "installed_tool",
      "value": "bun",
      "reason": "The preinstall hook runs `bun run index.js`; bun must be on PATH for the payload to execute (the worm also tries to bootstrap bun via curl if missing)."
    },
    {
      "axis": "installed_tool",
      "value": "python3",
      "reason": "The x7 script f7 pipes to bash exits unless python3 is present, so g2's monitor is only installed with it."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.GITHUB_TOKEN",
      "operator": "not_startswith",
      "value": "ghp_decoyGitHubToken",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 386832,
            "end_byte": 386866,
            "node_type": "call_expression",
            "sha256": "11e14f119932db70",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat().resolvedOptions().locale",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 173302,
            "end_byte": 173400,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "locale_language",
      "api": "process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANGUAGE || process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 173423,
            "end_byte": 173561,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 173576,
            "end_byte": 173715,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 318707,
            "end_byte": 318732,
            "node_type": "binary_expression",
            "sha256": "92ddb30347168549",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 318747,
            "end_byte": 318773,
            "node_type": "binary_expression",
            "sha256": "a1e133353ca470cc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 318775,
            "end_byte": 318813,
            "node_type": "binary_expression",
            "sha256": "40e7bb5a102680cb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "ci_marker",
      "api": "process.env.JENKINS_HOME",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 318815,
            "end_byte": 318853,
            "node_type": "binary_expression",
            "sha256": "60afb22bc3c52114",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "os",
      "api": "os.platform",
      "operator": "!=",
      "value": "darwin",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 300907,
            "end_byte": 300941,
            "node_type": "binary_expression",
            "sha256": "6ab86b3c770564fc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "arch",
      "api": "os.arch",
      "operator": "!=",
      "value": "arm64",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 300943,
            "end_byte": 300972,
            "node_type": "binary_expression",
            "sha256": "ff925478aa85e4b1",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "Bun.Glob.scan",
      "operator": "includes",
      "value": [
        "claude",
        "codex"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 303297,
            "end_byte": 303352,
            "node_type": "call_expression",
            "sha256": "f64f0be28f6208fa",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433170,
            "end_byte": 433199,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "env_var",
      "api": "process.env.GITHUB_WORKFLOW_REF",
      "operator": "includes",
      "value": "release.yml",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433280,
            "end_byte": 433314,
            "node_type": "call_expression",
            "sha256": "6159e26b2d0d4a2c",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "includes",
      "value": "/somerepository",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433316,
            "end_byte": 433350,
            "node_type": "call_expression",
            "sha256": "775facb90dad99fc",
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
      "expression": "c1 && c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433631,
            "end_byte": 433660,
            "node_type": "if_statement",
            "sha256": "3ff72905d61ca84f",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433660,
            "end_byte": 433731,
            "node_type": "if_statement",
            "sha256": "6c330eea088a8fda",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "Two sequential early exits in x2() back off before any theft: it quits if GITHUB_TOKEN is the planted decoy 'ghp_decoyGitHubToken' (canary/honeypot token used by analysis environments) or if U7() finds a locale beginning with 'ru' in Intl.DateTimeFormat or in LC_ALL/LC_MESSAGES/LANGUAGE/LANG (Russian-host exclusion). The credential-theft payload runs only when neither holds.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "spawn_process"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 435497,
            "end_byte": 435783,
            "node_type": "for_in_statement",
            "sha256": "fbbc391c714aa835",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433731,
            "end_byte": 433767,
            "node_type": "if_statement",
            "sha256": "fcd6fa13af9cbe08",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 434401,
            "end_byte": 434421,
            "node_type": "variable_declarator",
            "sha256": "9dd5446e0799d381",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 435186,
            "end_byte": 435330,
            "node_type": "lexical_declaration",
            "sha256": "848ee75d979d33d8",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 435897,
            "end_byte": 435920,
            "node_type": "call_expression",
            "sha256": "a97addb3114d066e",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 379828,
              "end_byte": 379860,
              "node_type": "call_expression",
              "sha256": "c4784b4fa5c2c6b5",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 434417,
                  "end_byte": 434421,
                  "node_type": "call_expression",
                  "sha256": "406a1c11639ede1f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432680,
                  "end_byte": 433022,
                  "node_type": "function_declaration",
                  "sha256": "59fd39cbb7429a2d",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432790,
                  "end_byte": 432808,
                  "node_type": "variable_declarator",
                  "sha256": "389efbc8ac0509a7",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432891,
                  "end_byte": 432913,
                  "node_type": "call_expression",
                  "sha256": "d6518d9ca7c53c10",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 380643,
                  "end_byte": 381088,
                  "node_type": "method_definition",
                  "sha256": "3667f8eb43347fdf",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 380910,
                  "end_byte": 380954,
                  "node_type": "call_expression",
                  "sha256": "f57587879eb05542",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 378001,
                  "end_byte": 380643,
                  "node_type": "method_definition",
                  "sha256": "33fa340f6f289691",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 380569,
                  "end_byte": 380589,
                  "node_type": "call_expression",
                  "sha256": "51539da6eec81901",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 379485,
                  "end_byte": 380141,
                  "node_type": "variable_declarator",
                  "sha256": "a6fa69826138969a",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 372532,
              "end_byte": 372610,
              "node_type": "call_expression",
              "sha256": "2ba0542a4f853676",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 434417,
                  "end_byte": 434421,
                  "node_type": "call_expression",
                  "sha256": "406a1c11639ede1f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432680,
                  "end_byte": 433022,
                  "node_type": "function_declaration",
                  "sha256": "59fd39cbb7429a2d",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432809,
                  "end_byte": 432827,
                  "node_type": "variable_declarator",
                  "sha256": "b9174f98071e750e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 432939,
                  "end_byte": 432961,
                  "node_type": "call_expression",
                  "sha256": "ffb700ce79b02c1b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 372296,
                  "end_byte": 372904,
                  "node_type": "method_definition",
                  "sha256": "6b43c37e2f38ff3a",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 430625,
              "end_byte": 430785,
              "node_type": "call_expression",
              "sha256": "c5846db338d42728",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 433741,
                  "end_byte": 433745,
                  "node_type": "call_expression",
                  "sha256": "1c8faef66bf374e3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 430440,
                  "end_byte": 430879,
                  "node_type": "function_declaration",
                  "sha256": "a61144083ced48d5",
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
              "derived_from": "d5",
              "start_byte": 422080,
              "end_byte": 422198,
              "node_type": "call_expression",
              "sha256": "80e76c67a642e5c8",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 435208,
                  "end_byte": 435227,
                  "node_type": "pair",
                  "sha256": "f662d607365d392e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 435295,
                  "end_byte": 435327,
                  "node_type": "pair",
                  "sha256": "4c2ebf0111f3ade6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 435897,
                  "end_byte": 435920,
                  "node_type": "call_expression",
                  "sha256": "a97addb3114d066e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 188236,
                  "end_byte": 188366,
                  "node_type": "method_definition",
                  "sha256": "ccffda587164c3b0",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 188310,
                  "end_byte": 188325,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 187858,
                  "end_byte": 188236,
                  "node_type": "method_definition",
                  "sha256": "4c9436210504f345",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 188132,
                  "end_byte": 188159,
                  "node_type": "call_expression",
                  "sha256": "29fb986f1d48dd5d",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 189166,
                  "end_byte": 189894,
                  "node_type": "arrow_function",
                  "sha256": "211c379869a550b6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 189764,
                  "end_byte": 189792,
                  "node_type": "call_expression",
                  "sha256": "b4a40d5db42bb085",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 421924,
                  "end_byte": 422312,
                  "node_type": "method_definition",
                  "sha256": "f48fb40cd177bd5f",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 6228,
              "end_byte": 6318,
              "node_type": "call_expression",
              "sha256": "b163a30ccfdbc63c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 435698,
                  "end_byte": 435710,
                  "node_type": "call_expression",
                  "sha256": "77616ead4a78d473",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 6638,
                  "end_byte": 7342,
                  "node_type": "function_declaration",
                  "sha256": "4032e8dd4e88726c",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 6856,
                  "end_byte": 6876,
                  "node_type": "call_expression",
                  "sha256": "facac282ab037ad6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 6116,
                  "end_byte": 6320,
                  "node_type": "function_declaration",
                  "sha256": "a1b1f1cce0a3c5b7",
                  "line": 1
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
      "hook": "preinstall",
      "expression": "c1 && c2 && c3 && c4 && c5 && c6 && c7",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433631,
            "end_byte": 433660,
            "node_type": "if_statement",
            "sha256": "3ff72905d61ca84f",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433660,
            "end_byte": 433731,
            "node_type": "if_statement",
            "sha256": "6c330eea088a8fda",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 319031,
            "end_byte": 319047,
            "node_type": "if_statement",
            "sha256": "c5005dfd9245d028",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c5",
            "c6",
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "f7() returns before installing the monitor when CP() is false: fewer than 4 CPUs, or CI, GITHUB_ACTIONS or JENKINS_HOME marks a build machine. The persistent monitor is kept off small or CI hosts.",
      "then": {
        "min_conditions": 7,
        "behaviours": [
          "write_file",
          "persistence"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN",
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_HOME"
          ],
          "cpu_count": 4
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 436278,
            "end_byte": 436301,
            "node_type": "try_statement",
            "sha256": "5d5a36c8dead839a",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 319126,
            "end_byte": 319471,
            "node_type": "try_statement",
            "sha256": "4f97ebeca7b8e3a2",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 319130,
              "end_byte": 319168,
              "node_type": "call_expression",
              "sha256": "31c71464471eeb32",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 436288,
                  "end_byte": 436292,
                  "node_type": "call_expression",
                  "sha256": "692cbc4291df6cad",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 318877,
                  "end_byte": 319472,
                  "node_type": "function_declaration",
                  "sha256": "ed9e1c84cf56d6b2",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 319183,
              "end_byte": 319274,
              "node_type": "call_expression",
              "sha256": "c7aae45d3586a42c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 436288,
                  "end_byte": 436292,
                  "node_type": "call_expression",
                  "sha256": "692cbc4291df6cad",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 318877,
                  "end_byte": 319472,
                  "node_type": "function_declaration",
                  "sha256": "ed9e1c84cf56d6b2",
                  "line": 1
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
      "hook": "preinstall",
      "expression": "c1 && c2 && c3 && (c8 || c9)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433631,
            "end_byte": 433660,
            "node_type": "if_statement",
            "sha256": "3ff72905d61ca84f",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433660,
            "end_byte": 433731,
            "node_type": "if_statement",
            "sha256": "6c330eea088a8fda",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 301131,
            "end_byte": 301173,
            "node_type": "if_statement",
            "sha256": "33f7048622ba3966",
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
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Vo.execute() returns before doing anything when checkAppleSilicon() finds darwin on arm64. The code gives no reason for skipping those hosts.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "write_file"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 436250,
            "end_byte": 436278,
            "node_type": "expression_statement",
            "sha256": "0333c611f7ebdd41",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 301287,
            "end_byte": 301528,
            "node_type": "for_in_statement",
            "sha256": "3141b443ff8e6f01",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 301443,
              "end_byte": 301526,
              "node_type": "call_expression",
              "sha256": "396d6209da4fa1b3",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 436256,
                  "end_byte": 436277,
                  "node_type": "call_expression",
                  "sha256": "656c91798b71e254",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 300974,
                  "end_byte": 301559,
                  "node_type": "method_definition",
                  "sha256": "f54728af98b474d0",
                  "line": 1
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
      "hook": "preinstall",
      "expression": "c1 && c2 && c3 && (c8 || c9) && c10",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433631,
            "end_byte": 433660,
            "node_type": "if_statement",
            "sha256": "3ff72905d61ca84f",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433660,
            "end_byte": 433731,
            "node_type": "if_statement",
            "sha256": "6c330eea088a8fda",
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
              "derived_from": "d5",
              "start_byte": 434291,
              "end_byte": 434295,
              "node_type": "call_expression",
              "sha256": "152fb3722edf7597",
              "line": 1
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 301131,
            "end_byte": 301173,
            "node_type": "if_statement",
            "sha256": "33f7048622ba3966",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8",
            "c9"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 301889,
            "end_byte": 302937,
            "node_type": "for_in_statement",
            "sha256": "e9e5ab90f809c53d",
            "line": 1
          },
          "kind": "loop",
          "arm": "then",
          "conditions": [
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "settingsSearch() globs **/settings.json under the home folder and keeps only writable files whose path includes claude or codex; addHook() loops over those, so the SessionStart hook is only written where such a settings file exists.",
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN"
          ],
          "file_present": [
            "~/.claude/settings.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 436250,
            "end_byte": 436278,
            "node_type": "expression_statement",
            "sha256": "0333c611f7ebdd41",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 301232,
            "end_byte": 301249,
            "node_type": "call_expression",
            "sha256": "b621edcaa85da57c",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 302136,
            "end_byte": 302936,
            "node_type": "try_statement",
            "sha256": "ae353909fd0a094e",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 302866,
              "end_byte": 302927,
              "node_type": "call_expression",
              "sha256": "3f44a25a0f4e346b",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 436256,
                  "end_byte": 436277,
                  "node_type": "call_expression",
                  "sha256": "656c91798b71e254",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 300974,
                  "end_byte": 301559,
                  "node_type": "method_definition",
                  "sha256": "f54728af98b474d0",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 301232,
                  "end_byte": 301249,
                  "node_type": "call_expression",
                  "sha256": "b621edcaa85da57c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 301581,
                  "end_byte": 302938,
                  "node_type": "method_definition",
                  "sha256": "a1655b6953cc5e17",
                  "line": 1
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
      "hook": "preinstall",
      "expression": "c1 && c11 && c12 && c13",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433631,
            "end_byte": 433660,
            "node_type": "if_statement",
            "sha256": "3ff72905d61ca84f",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433167,
            "end_byte": 433466,
            "node_type": "if_statement",
            "sha256": "e77376783be615d2",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433277,
            "end_byte": 433465,
            "node_type": "if_statement",
            "sha256": "ba2646adb0b40f0f",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c12",
            "c13"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "q2() runs Lo.execute(), the OIDC republish path, only in GitHub Actions on a workflow ref including release.yml in a repository including /somerepository, so the worm spreads only from one chosen release workflow.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": null,
            "GITHUB_WORKFLOW_REF": "release.yml",
            "GITHUB_REPOSITORY": "/somerepository",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": null,
            "ACTIONS_ID_TOKEN_REQUEST_URL": null
          },
          "env_var_absent": [
            "GITHUB_TOKEN"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433660,
            "end_byte": 433731,
            "node_type": "if_statement",
            "sha256": "6c330eea088a8fda",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d5",
            "start_byte": 433357,
            "end_byte": 433378,
            "node_type": "call_expression",
            "sha256": "d028ed012ac9db4c",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d5",
              "start_byte": 318387,
              "end_byte": 318425,
              "node_type": "call_expression",
              "sha256": "58ffaf1b81cbdf75",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 433669,
                  "end_byte": 433704,
                  "node_type": "call_expression",
                  "sha256": "c3d3814bf46528b0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 433022,
                  "end_byte": 433493,
                  "node_type": "function_declaration",
                  "sha256": "0b8fe0bbb222e9df",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 433357,
                  "end_byte": 433378,
                  "node_type": "call_expression",
                  "sha256": "d028ed012ac9db4c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d5",
                  "start_byte": 317996,
                  "end_byte": 318448,
                  "node_type": "method_definition",
                  "sha256": "90d6f6bf401b6dde",
                  "line": 1
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
      "recon",
      "cred_read",
      "exfil",
      "spawn_process",
      "write_file",
      "persistence",
      "self_propagation"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "obfuscator.io base64 string array with rotation checksum",
      "per-string feistel/substitution-permutation cipher behind global decode function (shai-hulud)",
      "hex identifiers",
      "escaped_strings",
      "very_long_lines",
      "dead/unreferenced code (harden-runner evasion never called)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "t[.]m-kosche[.]com:443",
        "role": "exfil_sink"
      },
      {
        "indicator": "api[.]github[.]com",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The compromised version of @antv/data-set ships a preinstall hook (`bun run index.js`) whose injected, doubly-obfuscated payload is the Shai-Hulud npm worm: it daemonizes, scans the filesystem and shell history for GitHub/npm tokens and other secrets, validates stolen GitHub tokens and exfiltrates to an OTLP-disguised C2 (t.m-kosche[.]com:443), and can self-propagate through GitHub Actions. It first quits on a decoy/canary GitHub token or a Russian locale.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "g5 (q2) is recorded because the code tests its strings literally, but '/somerepository', 'release.yml' and uP=[\"aaaaa\"] look like unfilled placeholders. A reviewer should confirm it stays in the dataset.",
    "q2's else side exits with no theft when GITHUB_ACTIONS is set and GITHUB_REPOSITORY includes '/somerepository'. This exit is not in the expressions of g1 to g4, so their min_conditions may be one too low.",
    "J2 tests SKIP_DOMAIN === 'true' to use the GitHub sender instead of the domain sender, a possible missed gate with effect modifies. It was outside this repair's review reasons and is not recorded.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d4",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": null
        },
        "params": {
          "decoder": "obfio_objprop",
          "lang": "js"
        },
        "output_sha256": "d6febb6dbea64e2e"
      },
      {
        "id": "d5",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d4"
        },
        "params": {
          "key": "cb6c29e35a82a21409de352d9cd6e02285098d49dcb89baed52d8af24fc0258a",
          "salt": "e0c5f3c4a4ec43c177d7eb06b4b4c28f",
          "fn": "fc2edea72",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "406972a0ffb664a5"
      },
      {
        "id": "d6",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d5"
        },
        "params": {
          "fn": "a",
          "decoder": "aesgcm_gunzip",
          "lang": "js"
        },
        "output_sha256": "d648996146d030cc"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "e1e1a3a4d8e5d84f"
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
        "candidate": "k_1cf3c7b7c4",
        "reason_code": "re_entry_guard",
        "note": "process.env.__DAEMONIZED guard in z1(): the payload sets it on the detached child so the child does not re-daemonize.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 491235,
          "end_byte": 491259,
          "node_type": "member_expression",
          "sha256": "08e4ec2c1b30613e",
          "line": 1
        }
      },
      {
        "candidate": "q_9ccf9f0f20",
        "reason_code": "re_entry_guard",
        "note": "if(process.env.__DAEMONIZED)return false in z1(); re-daemonize guard, not an environment gate.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 491232,
          "end_byte": 491271,
          "node_type": "if_statement",
          "sha256": "5c2fbc3955369d6c",
          "line": 1
        }
      },
      {
        "candidate": "k_b6b5ce918f",
        "reason_code": "re_entry_guard",
        "note": "a1() single-instance PID lockfile existsSync; self-managed concurrency lock, stale locks removed, fresh VM always passes.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493289,
          "end_byte": 493302,
          "node_type": "call_expression",
          "sha256": "c82b65f15ccc0b08",
          "line": 1
        }
      },
      {
        "candidate": "k_0873e77c0c",
        "reason_code": "re_entry_guard",
        "note": "second existsSync of the same tmpdir lockfile in _o()/a1(); concurrency lock, not an environment gate.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493538,
          "end_byte": 493551,
          "node_type": "call_expression",
          "sha256": "c82b65f15ccc0b08",
          "line": 1
        }
      },
      {
        "candidate": "q_baa2dc756e",
        "reason_code": "re_entry_guard",
        "note": "guard over the lockfile existsSync branch in a1(); single-instance lock.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493286,
          "end_byte": 493420,
          "node_type": "if_statement",
          "sha256": "49623a2c51fbb4ee",
          "line": 1
        }
      },
      {
        "candidate": "q_d568cfc6cc",
        "reason_code": "re_entry_guard",
        "note": "guard over the lockfile cleanup existsSync in _o(); single-instance lock.",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493535,
          "end_byte": 493566,
          "node_type": "if_statement",
          "sha256": "ca33c50de08b9335",
          "line": 1
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 6,
    "conditions_in_set": 0,
    "conditions_out_of_set": 13,
    "guard_candidates": 8,
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
