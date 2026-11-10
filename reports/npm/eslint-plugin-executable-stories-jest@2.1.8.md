# npm eslint-plugin-executable-stories-jest@2.1.8

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised copy of a real ESLint plugin carrying the Shai-Hulud ("Second Coming") npm worm. It has no install script, but a `binding.gyp` makes npm run `node-gyp rebuild`, and the gyp `sources` field abuses the `<!(...)` command expansion to run `node index.js > /dev/null 2>&1` at configure time, so the payload executes on every install. `index.js` is a four-layer obfuscated dropper (char-code+Caesar eval, then two AES-128-GCM stages, then obfuscator.io, then a bespoke per-string cipher) that decrypts the worm, writes it to `/tmp/p<rand>.js`, downloads the Bun runtime from GitHub releases, and runs it with `bun run`. The worm's `uX()` preflight exits early on a Russian locale (g1) or when it detects an analysis/honeypot environment (g2: decoy token env vars, the author's demo repo in `GITHUB_REPOSITORY`, a `/tmp/npm-safe/` cwd, or a `FAKE` AWS credentials file); past those it harvests AWS/Azure/GCP/Vault/npm/GitHub secrets and OIDC tokens, exfiltrates them, and self-propagates via GitHub. Further gates limit a macOS/Linux package-download step (g3) and an aggressive updater drop (g4: >=4 CPUs, no EDR, not CI).

## Execution

- **node_gyp_implicit** `node-gyp rebuild (binding.gyp sources = ["<!(node index.js > /dev/null 2>&1 && echo stub.c)"])`: 2-file chain; native_build, inline_shell, direct_script, decoded_eval, download_then_exec, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | node_gyp_implicit | c1 && c12 (c1: locale_language not_startswith ru; c12: locale_language not_startswith ru) | then | 2 | recon, cred_read, exfil, self_propagation | locale=en_US.UTF-8 |
| g2 | node_gyp_implicit | c2 && c3 && c4 && c5 (c2: process.env not_startswith ghp_decoyGitHubToken / npm_F4k3NPMToken / sk-ant-api03-fake / ... (per-env-var decoy-token prefixes in RK: GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, CIRCLE_TOKEN ...); c3: process.env.GITHUB_REPOSITORY not_in [actions-security-demo/compromised-packages]; c4: home_or_path not_startswith /tmp/npm-safe/; c5: target_artifact not_includes FAKE) | then | 4 | recon, cred_read, exfil, self_propagation | (none) |
| g3 | node_gyp_implicit | c6 (c6: os in [darwin, linux]) | then | 1 | download, self_propagation | os=linux |
| g4 | node_gyp_implicit | c7 && c8 && c9 && c10 && c11 (c7: hardware >= 4; c8: process_list not_includes [falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys]; c9: process.env.CI not_in [true, 1, woodpecker]; c10: file_or_dir_exists not_exists [/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack]; c11: process.env falsy [GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL, BUILD_BUILDURI, CODEBUILD_BUILD_ID, BUILDKITE, APPVEYOR, BITBUCKET_BUILD_NUMBER, DRONE, SEMAPHORE, TEAMCITY_VERSION, bamboo_agentId, BITRISE_IO, CIRRUS_CI, CF_BUILD_ID, CI_NAME=codeship, NETLIFY=true, VERCEL, NOW_GITHUB_DEPLOYMENT, WERCKER_MAIN_PIPELINE_STARTED, BUDDY_WORKSPACE_ID, SHIPPABLE, JB_SPACE_EXECUTION_NUMBER, SAILCI, VELA, SCREWDRIVER, CF_PAGES=1, DISTELLI_APPNAME]) | then | 5 | write_file, spawn_process | cpu_count=4; env_var_absent=CI, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL, BUILD_BUILDURI, CODEBUILD_BUILD_ID, BUILDKITE, APPVEYOR, BITBUCKET_BUILD_NUMBER, DRONE, SEMAPHORE, TEAMCITY_VERSION, bamboo_agentId, BITRISE_IO, CIRRUS_CI, CF_BUILD_ID, CI_NAME, NETLIFY, VERCEL, NOW_GITHUB_DEPLOYMENT, WERCKER_MAIN_PIPELINE_STARTED, BUDDY_WORKSPACE_ID, SHIPPABLE, JB_SPACE_EXECUTION_NUMBER, SAILCI, VELA, SCREWDRIVER, CF_PAGES, DISTELLI_APPNAME |

Gate intent: g1 activate/enables/targeting; g2 evade/enables/anti_analysis; g3 activate/enables/targeting; g4 evade/enables/anti_analysis

Grounding: 0 of 12 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, g1, g2, g3, g4.

## Requirements

- network: github[.]com:443, api[.]github[.]com:443, registry[.]npmjs[.]org:443, api[.]anthropic[.]com:443 (downloads the Bun runtime from GitHub releases, validates and pushes stolen GitHub tokens/repos via the GitHub API, queries the npm registry, and POSTs collected secrets to the domain sender (api[.]anthropic[.]com))
- installed_tool: curl (getBunPath fetches the Bun release zip with curl)
- installed_tool: unzip (getBunPath unzips the downloaded Bun release)
- installed_tool: node (binding.gyp runs `node index.js` during node-gyp configure)
- installed_tool: bash (the aggressive updater is executed via `bash -s`)
- other: Bun runtime (the decrypted payload _p is executed with Bun, downloaded at install if not already present)

## Behaviour

- Ungated: download, exec_downloaded, write_file, spawn_process
- Gated: recon, cred_read, exfil, self_propagation, download, write_file, spawn_process

## Notes

- The whole payload was recovered through a replayable 5-step decode chain registered as derivations d20-d24 (`charcode_caesar_eval`, `aesgcm_hex_stage` for `_b` and `_p`, `obfio_objprop`, `scramble_feistel`); all conditions/gates cite into the final plaintext d24. Nothing was left unread.
- The extractor only saw `node-gyp rebuild` (the payload was fully encrypted), so every condition and gate here is out of set and analyst-added; needs_manual_review is set.
- Only four representative gates are encoded. The payload repeats EDR (`w4()`) and CI (`H9()`) checks across several providers, has a `sudo -n true` privilege probe gating `/etc/hosts` and `/etc/resolv.conf` DNS tampering, and a GitHub Actions self-propagation path keyed on `WORKFLOW_ID`/`REPO_ID_SUFFIX`/OIDC. These are described in execution.notes but not each encoded as a gate.
- Runtime selection (`typeof Bun`), the detached-child daemonize (`$X`, `__IS_DAEMON`) and the `/tmp` lockfile mutex (`yX`) are plumbing / re-entry guards, not gates. The Bun download is recorded as a network + curl/unzip requirement.
- `cred_read` stops at the `_3()` collection wrapper and `exfil` at the sender's `send` call, because senders are chosen at run time. `recon` is witnessed to `os.hostname` in the shell collector and `self_propagation` to the registry `PUT` in `C4`.
- The domain-sender exfil endpoint decodes to `api[.]anthropic[.]com` `/v1/api`; GitHub API is used for token validation and repo creation.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "eslint-plugin-executable-stories-jest",
    "version": "2.1.8",
    "archive_sha256": "881505cc4a1e40b8d8c1e9534e3a2aec4b7ecd06f4bfffdf86f18f716cd7a593",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-04-eslint-plugin-executable-stories-jest-v2.1.8.zip",
    "package_root": "layer0/tmp/tmp2qesroph/eslint-plugin-executable-stories-jest/package",
    "cluster_key": "46a50837805d767ed9cb0544b06b63b772a4262c26a55aabf828cf86eb11ddd4",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "node_gyp_implicit",
        "command": "node-gyp rebuild (binding.gyp sources = [\"<!(node index.js > /dev/null 2>&1 && echo stub.c)\"])",
        "runs_on": "always",
        "file_chain": [
          "binding.gyp",
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "native_build",
          "inline_shell",
          "direct_script",
          "decoded_eval",
          "download_then_exec",
          "dropped_binary",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "No install script in package.json; binding.gyp makes npm run node-gyp rebuild. Its sources field uses gyp's <!(...) command expansion to run `node index.js` at configure time; `> /dev/null 2>&1` hides output and `&& echo stub.c` returns a filename so gyp does not error.",
      "index.js (4.4MB): package code read in full via a replayable 5-step decode chain (derivations d20-d24). Nothing left unread.",
      "Decode chain: d20 charcode_caesar_eval (eval(caesar(fromCharCode(arr),18))); d21/d22 aesgcm_hex_stage decrypt aes-128-gcm stages _b and _p; d23 obfio_objprop recovers the obfuscator.io string array; d24 scramble_feistel decodes the per-string cipher f489094fb hiding endpoints and env-var names.",
      "d20 wrapper (ungated): decrypts _p to /tmp/p<rand>.js, and when Bun is absent (npm-install case) eval(_b) defines getBunPath which downloads Bun v1.3.13 from github releases via curl+unzip, then runs the payload with `bun run`. Runtime selection is plumbing; the Bun download is a requirement.",
      "Bundled node-tar and crypto/fs library modules in d24 (process.env.TESTING_TAR_FAKE_PLATFORM / __FAKE_PLATFORM__ win32 path handling) were audited by sink inventory and attributed to the library; the attacker-written provider/sender/guard code was read in full.",
      "Plumbing/re-entry not recorded as gates: $X() daemonizes via a detached child carrying __IS_DAEMON=1 then the parent exits when not CI; yX() is a /tmp lockfile mutex removed at the end; bK() re-enters for GitHub Actions self-propagation when WORKFLOW_ID/REPO_ID_SUFFIX are set.",
      "Additional sudo-gated behaviour not separately encoded: wX()/gK() probe `sudo -n true`; on success vK() overwrites /etc/resolv.conf and another path appends to /etc/hosts (defense_evasion / DNS redirection), reachable in the GitHub Actions harden-runner provider path; flagged for manual review.",
      "c8 probe: w4 picks the command by platform (`tasklist 2>/dev/null` on win32, `ps aux 2>/dev/null` elsewhere), so the target is written with * for the command name.",
      "g4 also tests GX in shouldExecute: a module flag the payload sets after its own successful run, so a re-entry guard, not a condition. c11 covers H9's provider markers; its one site is the first of the chain and the value lists every variable tested.",
      "z7 site 2 of c1 is the Windows fallback, read only when process.env.SystemRoot is set. g1 and g2 self_propagation runs through handleNpmTokens to class g1's execute, so it also sits behind g3's c6 and needs a valid npm token.",
      "The payload harvests AWS/Azure/GCP/Vault/Kubernetes/npm/GitHub secrets and GitHub Actions OIDC tokens, validates stolen ghp_/gho_/github_pat_ tokens against the GitHub API, and self-propagates by creating repositories and (TARGET_REPOS) injecting GitHub Actions workflows."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "github[.]com:443",
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "api[.]anthropic[.]com:443"
      ],
      "reason": "downloads the Bun runtime from GitHub releases, validates and pushes stolen GitHub tokens/repos via the GitHub API, queries the npm registry, and POSTs collected secrets to the domain sender (api[.]anthropic[.]com)"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "getBunPath fetches the Bun release zip with curl"
    },
    {
      "axis": "installed_tool",
      "value": "unzip",
      "reason": "getBunPath unzips the downloaded Bun release"
    },
    {
      "axis": "installed_tool",
      "value": "node",
      "reason": "binding.gyp runs `node index.js` during node-gyp configure"
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "the aggressive updater is executed via `bash -s`"
    },
    {
      "axis": "other",
      "value": "Bun runtime",
      "reason": "the decrypted payload _p is executed with Bun, downloaded at install if not already present"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "locale_language",
      "api": "process.env.LC_ALL / process.env.LC_MESSAGES / process.env.LANGUAGE / process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 178206,
            "end_byte": 178344,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 178359,
            "end_byte": 178498,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ghp_decoyGitHubToken / npm_F4k3NPMToken / sk-ant-api03-fake / ... (per-env-var decoy-token prefixes in RK: GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, CIRCLE_TOKEN ...)",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 336411,
            "end_byte": 336591,
            "node_type": "call_expression",
            "sha256": "c4103d19f2b8994c",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "not_in",
      "value": [
        "actions-security-demo/compromised-packages"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 336653,
            "end_byte": 336708,
            "node_type": "binary_expression",
            "sha256": "d73faab5cce7e8c8",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c4",
      "category": "home_or_path",
      "api": "process.cwd",
      "operator": "not_startswith",
      "value": "/tmp/npm-safe/",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 336723,
            "end_byte": 336771,
            "node_type": "call_expression",
            "sha256": "42883fa19751ffed",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "fs.readFileSync",
      "operator": "not_includes",
      "value": "FAKE",
      "value_recovered": "decoded",
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
            "derived_from": "d24",
            "start_byte": 336873,
            "end_byte": 336921,
            "node_type": "call_expression",
            "sha256": "2f7ba27e1b8b6d40",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c6",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "darwin",
        "linux"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 188974,
            "end_byte": 189025,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c7",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288504,
            "end_byte": 288528,
            "node_type": "binary_expression",
            "sha256": "86f8bbfb8a68b73e",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c8",
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
            "derived_from": "d24",
            "start_byte": 181160,
            "end_byte": 181192,
            "node_type": "call_expression",
            "sha256": "6143271771feeb6b",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c9",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "not_in",
      "value": [
        "true",
        "1",
        "woodpecker"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 178966,
            "end_byte": 179017,
            "node_type": "binary_expression",
            "sha256": "fd2a75bb878ed922",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 180051,
            "end_byte": 180083,
            "node_type": "binary_expression",
            "sha256": "5133893206ad349b",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c10",
      "category": "file_or_dir_exists",
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
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 180909,
            "end_byte": 180929,
            "node_type": "call_expression",
            "sha256": "03002d9a5c838262",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c11",
      "category": "ci_marker",
      "api": "process.env",
      "operator": "falsy",
      "value": [
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "TRAVIS",
        "CIRCLECI",
        "JENKINS_URL",
        "BUILD_BUILDURI",
        "CODEBUILD_BUILD_ID",
        "BUILDKITE",
        "APPVEYOR",
        "BITBUCKET_BUILD_NUMBER",
        "DRONE",
        "SEMAPHORE",
        "TEAMCITY_VERSION",
        "bamboo_agentId",
        "BITRISE_IO",
        "CIRRUS_CI",
        "CF_BUILD_ID",
        "CI_NAME=codeship",
        "NETLIFY=true",
        "VERCEL",
        "NOW_GITHUB_DEPLOYMENT",
        "WERCKER_MAIN_PIPELINE_STARTED",
        "BUDDY_WORKSPACE_ID",
        "SHIPPABLE",
        "JB_SPACE_EXECUTION_NUMBER",
        "SAILCI",
        "VELA",
        "SCREWDRIVER",
        "CF_PAGES=1",
        "DISTELLI_APPNAME"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 179032,
            "end_byte": 179061,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c12",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 178085,
            "end_byte": 178183,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
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
      "expression": "c1 && c12",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "uX() calls process.exit(0) when z7() reports a Russian locale (Intl locale, LC_ALL/LC_MESSAGES/LANGUAGE/LANG, or on Windows LANG/LANGUAGE/LC_ALL, starting 'ru'); a region-exclusion victim filter that stops the whole payload, not an analysis or sandbox check.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c12"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581232,
              "end_byte": 581236,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
              "line": 1
            }
          ]
        }
      ],
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation"
        ],
        "env_recipe": {
          "locale": "en_US.UTF-8"
        },
        "recipe_guessed_fields": [
          "locale"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581237,
            "end_byte": 581494,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581556,
            "end_byte": 581723,
            "node_type": "sequence_expression",
            "sha256": "36365b96c7614f9a",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 415593,
              "end_byte": 415604,
              "node_type": "call_expression",
              "sha256": "65010ab91de87884",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581257,
                  "end_byte": 581261,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 565638,
                  "end_byte": 565660,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 415089,
                  "end_byte": 415888,
                  "node_type": "method_definition",
                  "sha256": "f4eb24f7548056a0",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581257,
              "end_byte": 581261,
              "node_type": "call_expression",
              "sha256": "3275c28a77a252e7",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 213996,
              "end_byte": 214024,
              "node_type": "call_expression",
              "sha256": "a312c41be6301514",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581459,
                  "end_byte": 581491,
                  "node_type": "pair",
                  "sha256": "0a0b2de5da960cb8",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581562,
                  "end_byte": 581659,
                  "node_type": "call_expression",
                  "sha256": "5b104c9cc44fc26f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212643,
                  "end_byte": 212852,
                  "node_type": "method_definition",
                  "sha256": "45344a4079804812",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212831,
                  "end_byte": 212849,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212513,
                  "end_byte": 212643,
                  "node_type": "method_definition",
                  "sha256": "3e1067e8c5280b20",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212587,
                  "end_byte": 212602,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212135,
                  "end_byte": 212513,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212409,
                  "end_byte": 212436,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 213333,
                  "end_byte": 214126,
                  "node_type": "arrow_function",
                  "sha256": "35cc8988a4450abf",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 12730,
              "end_byte": 12834,
              "node_type": "call_expression",
              "sha256": "7bc3a060a4b3c1e8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581525,
                  "end_byte": 581555,
                  "node_type": "call_expression",
                  "sha256": "33fdfc63df1ac08a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 208121,
                  "end_byte": 209405,
                  "node_type": "method_definition",
                  "sha256": "2e6049fa858be9ba",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 208812,
                  "end_byte": 208846,
                  "node_type": "call_expression",
                  "sha256": "59172fddafdd9c53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 210626,
                  "end_byte": 211373,
                  "node_type": "method_definition",
                  "sha256": "7416d11431a7a6dd",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 211228,
                  "end_byte": 211258,
                  "node_type": "call_expression",
                  "sha256": "a0654db4d5c27114",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 188846,
                  "end_byte": 189387,
                  "node_type": "method_definition",
                  "sha256": "f27054003b323908",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189228,
                  "end_byte": 189261,
                  "node_type": "call_expression",
                  "sha256": "70fcd796a9cf7bcf",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190829,
                  "end_byte": 190873,
                  "node_type": "call_expression",
                  "sha256": "6f8a3fe42d91b397",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 10615,
                  "end_byte": 12914,
                  "node_type": "function_declaration",
                  "sha256": "3aacdd971dd1afb8",
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
      "hook": "node_gyp_implicit",
      "expression": "c2 && c3 && c4 && c5",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "uX() calls process.exit(0) when IX() detects an analysis/honeypot environment: a decoy token in GITHUB_TOKEN/NPM_TOKEN/ANTHROPIC_API_KEY/etc., the author's own demo repo in GITHUB_REPOSITORY, a cwd under /tmp/npm-safe/, or ~/.aws/credentials containing 'FAKE'.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c4",
            "c5"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581232,
              "end_byte": 581236,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
              "line": 1
            }
          ]
        }
      ],
      "then": {
        "min_conditions": 4,
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
            "derived_from": "d24",
            "start_byte": 581237,
            "end_byte": 581494,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581556,
            "end_byte": 581723,
            "node_type": "sequence_expression",
            "sha256": "36365b96c7614f9a",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 415593,
              "end_byte": 415604,
              "node_type": "call_expression",
              "sha256": "65010ab91de87884",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581257,
                  "end_byte": 581261,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 565638,
                  "end_byte": 565660,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 415089,
                  "end_byte": 415888,
                  "node_type": "method_definition",
                  "sha256": "f4eb24f7548056a0",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581257,
              "end_byte": 581261,
              "node_type": "call_expression",
              "sha256": "3275c28a77a252e7",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 213996,
              "end_byte": 214024,
              "node_type": "call_expression",
              "sha256": "a312c41be6301514",
              "line": 1
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581459,
                  "end_byte": 581491,
                  "node_type": "pair",
                  "sha256": "0a0b2de5da960cb8",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581562,
                  "end_byte": 581659,
                  "node_type": "call_expression",
                  "sha256": "5b104c9cc44fc26f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212643,
                  "end_byte": 212852,
                  "node_type": "method_definition",
                  "sha256": "45344a4079804812",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212831,
                  "end_byte": 212849,
                  "node_type": "call_expression",
                  "sha256": "e6bc6ab360b9648e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212513,
                  "end_byte": 212643,
                  "node_type": "method_definition",
                  "sha256": "3e1067e8c5280b20",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212587,
                  "end_byte": 212602,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212135,
                  "end_byte": 212513,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 212409,
                  "end_byte": 212436,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 213333,
                  "end_byte": 214126,
                  "node_type": "arrow_function",
                  "sha256": "35cc8988a4450abf",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 12730,
              "end_byte": 12834,
              "node_type": "call_expression",
              "sha256": "7bc3a060a4b3c1e8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581525,
                  "end_byte": 581555,
                  "node_type": "call_expression",
                  "sha256": "33fdfc63df1ac08a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 208121,
                  "end_byte": 209405,
                  "node_type": "method_definition",
                  "sha256": "2e6049fa858be9ba",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 208812,
                  "end_byte": 208846,
                  "node_type": "call_expression",
                  "sha256": "59172fddafdd9c53",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 210626,
                  "end_byte": 211373,
                  "node_type": "method_definition",
                  "sha256": "7416d11431a7a6dd",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 211228,
                  "end_byte": 211258,
                  "node_type": "call_expression",
                  "sha256": "a0654db4d5c27114",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 188846,
                  "end_byte": 189387,
                  "node_type": "method_definition",
                  "sha256": "f27054003b323908",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189228,
                  "end_byte": 189261,
                  "node_type": "call_expression",
                  "sha256": "70fcd796a9cf7bcf",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190829,
                  "end_byte": 190873,
                  "node_type": "call_expression",
                  "sha256": "6f8a3fe42d91b397",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 10615,
                  "end_byte": 12914,
                  "node_type": "function_declaration",
                  "sha256": "3aacdd971dd1afb8",
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
      "hook": "node_gyp_implicit",
      "expression": "c6",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "one collection provider downloads the victim's packages only on macOS or Linux (process.platform in darwin/linux); the Windows branch skips it.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 188971,
            "end_byte": 189345,
            "node_type": "if_statement",
            "sha256": "13ec33d6521da251",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        }
      ],
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
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
            "derived_from": "d24",
            "start_byte": 189026,
            "end_byte": 189345,
            "node_type": "statement_block",
            "sha256": "ea179d68c8031d4b",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 189102,
              "end_byte": 189157,
              "node_type": "call_expression",
              "sha256": "c4ec66f5c6a0a259",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 12730,
              "end_byte": 12834,
              "node_type": "call_expression",
              "sha256": "7bc3a060a4b3c1e8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189228,
                  "end_byte": 189261,
                  "node_type": "call_expression",
                  "sha256": "70fcd796a9cf7bcf",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190829,
                  "end_byte": 190873,
                  "node_type": "call_expression",
                  "sha256": "6f8a3fe42d91b397",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 10615,
                  "end_byte": 12914,
                  "node_type": "function_declaration",
                  "sha256": "3aacdd971dd1afb8",
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
      "hook": "node_gyp_implicit",
      "expression": "c7 && c8 && c9 && c10 && c11",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "the aggressive provider (i1) drops /tmp/update-*/updater.py and runs it via bash only when shouldExecute() passes: >=4 CPUs, no EDR/AV (w4: RQ install paths, then DQ agent names in ps aux or tasklist output), and not CI (H9: CI values and provider marker variables).",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288743,
            "end_byte": 288788,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7",
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        }
      ],
      "then": {
        "min_conditions": 5,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "env_var_absent": [
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "TRAVIS",
            "CIRCLECI",
            "JENKINS_URL",
            "BUILD_BUILDURI",
            "CODEBUILD_BUILD_ID",
            "BUILDKITE",
            "APPVEYOR",
            "BITBUCKET_BUILD_NUMBER",
            "DRONE",
            "SEMAPHORE",
            "TEAMCITY_VERSION",
            "bamboo_agentId",
            "BITRISE_IO",
            "CIRRUS_CI",
            "CF_BUILD_ID",
            "CI_NAME",
            "NETLIFY",
            "VERCEL",
            "NOW_GITHUB_DEPLOYMENT",
            "WERCKER_MAIN_PIPELINE_STARTED",
            "BUDDY_WORKSPACE_ID",
            "SHIPPABLE",
            "JB_SPACE_EXECUTION_NUMBER",
            "SAILCI",
            "VELA",
            "SCREWDRIVER",
            "CF_PAGES",
            "DISTELLI_APPNAME"
          ]
        },
        "recipe_guessed_fields": [
          "cpu_count"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288875,
            "end_byte": 289148,
            "node_type": "statement_block",
            "sha256": "2ab966e0c5a6fbc5",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 288876,
              "end_byte": 288914,
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
              "derived_from": "d24",
              "start_byte": 288929,
              "end_byte": 289020,
              "node_type": "call_expression",
              "sha256": "acc3af4cc0f3c98b",
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
      "download",
      "exec_downloaded",
      "write_file",
      "spawn_process"
    ],
    "gated": [
      "recon",
      "cred_read",
      "exfil",
      "self_propagation",
      "download",
      "write_file",
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "char-code array mapped to a string and Caesar-shifted (n=18), fed to eval (outer index.js wrapper)",
      "two aes-128-gcm encrypted stages (_b getBunPath bootstrap, _p main payload) decrypted at runtime from hex key/iv/tag/ciphertext",
      "obfuscator.io string-array with const-object-property index indirection",
      "bespoke pbkdf2 + substitution-permutation per-string cipher (global f489094fb) hiding endpoints and env-var names",
      "staged execution via a Bun runtime downloaded at install"
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
        "indicator": "hxxps://api[.]github[.]com",
        "role": "c2"
      },
      {
        "indicator": "hxxps://github[.]com",
        "role": "c2"
      },
      {
        "indicator": "hxxps://api[.]anthropic[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://registry[.]npmjs[.]org",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud (second coming)",
  "claude_assessment": "malicious",
  "assessment_reason": "A compromised copy of a real eslint plugin ships a binding.gyp that abuses node-gyp's <!(...) command expansion to run index.js at install, a four-layer obfuscated dropper that decrypts and runs (under a downloaded Bun) the Shai-Hulud worm. It harvests cloud/git/npm credentials and OIDC tokens, exfiltrates them, and self-propagates, behind locale, honeypot/sandbox, EDR, CPU-count and CI evasion gates. Clearly malicious.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Entire payload recovered through a hand-built 5-step decode chain (derivations d20-d24 using charcode_caesar_eval, aesgcm_hex_stage x2, obfio_objprop, scramble_feistel); verify the replay.",
    "All conditions, gates and guards are out of set (the extractor saw only node-gyp; candidate set empty), so every gate is analyst-added and needs review.",
    "Payload has many more per-provider environment gates (repeated w4() EDR and H9() CI checks, sudo privilege probe gating /etc/hosts and /etc/resolv.conf tampering, GitHub-Actions WORKFLOW_ID/REPO_ID_SUFFIX/OIDC self-propagation) beyond the four representative gates encoded; see execution.notes.",
    "cred_read stops at the _3 collection wrapper and exfil at the sender's send call (senders are chosen at run time) rather than at leaf sinks, given the heavily indirected bundle.",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d20",
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
        "output_sha256": "b28c81109f513006"
      },
      {
        "id": "d21",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d20"
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
        "id": "d22",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d20"
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
        "id": "d23",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d22"
        },
        "params": {
          "decoder": "obfio_objprop",
          "lang": "js"
        },
        "output_sha256": "9159022e77fb3e00"
      },
      {
        "id": "d24",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d23"
        },
        "params": {
          "fn": "f489094fb",
          "key": "77afe07fa1eca63ce025ef790b33cdcde73da475c5a700acb14a5578b35d2813",
          "salt": "74eb124111aadb515960c4618132c1b4",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "dbc6aa701d69aa44"
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
      "c9",
      "c10",
      "c11",
      "c12",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
