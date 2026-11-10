# npm executable-stories-playwright@7.0.3

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised release of the real `executable-stories-playwright` package carrying the Shai-Hulud npm worm. There is no install script; instead `binding.gyp` (type `none`) puts `<!(node index.js > /dev/null 2>&1 && echo stub.c)` in its `sources`, so `node-gyp rebuild` runs `node index.js` at install with all output discarded. `index.js` is a 4.3 MB char-code array that is ROT13-decoded and `eval`'d; it AES-128-GCM-decrypts a bootstrap and a main payload, writes the payload to `/tmp/p<rand>.js`, and runs it with Bun, downloading the Bun runtime from GitHub (curl + unzip) when Bun is absent. The payload (further hidden by an obfuscator.io string array and a pbkdf2-keyed scramble cipher) harvests GitHub/npm/cloud/Kubernetes credentials, exfiltrates them to attacker GitHub repos and `api[.]anthropic[.]com`, and self-propagates by injecting malicious GitHub Actions workflows and AI-assistant config files. The harvest/exfil/propagation runs only on non-Russian-locale hosts and after a honeypot/decoy check passes. A separate dropper installs a persistent GitHub-commit command monitor only off CI, with >= 4 CPUs and no EDR agent; the Kubernetes credential theft is Linux-only.

## Execution

- **node_gyp_implicit** `node-gyp rebuild; binding.gyp sources uses <!(node index.js > /dev/null 2>&1 && echo stub.c)`: 2-file chain; native_build, decoded_eval, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | node_gyp_implicit | c1 && c11 && c12 (c1: locale_language not_startswith ru; c11: locale_language not_startswith ru; c12: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, self_propagation | locale=en-US |
| g2 | node_gyp_implicit | c2 && c3 && c4 && c5 (c2: home_or_path not_startswith /tmp/npm-safe/; c3: file_content not_includes FAKE; c4: process.env not_startswith ghp_decoyGitHubToken / npm_F4k3NPMToken / sk-ant-api03-fake (planted decoy token prefixes in GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, ...); c5: process.env.GITHUB_REPOSITORY not_in actions-security-demo/compromised-packages) | then | 4 | recon, cred_read, exfil, self_propagation | file_absent=~/.aws/credentials; env_var_absent=GITHUB_REPOSITORY |
| g3 | node_gyp_implicit | c6 && c7 && c9 && c13 && c14 && c10 (c6: file_or_dir_exists not_exists /opt/CrowdStrike, /opt/sentinelone, /opt/carbonblack, /Library/CS/falcon, C:\Program Files\CrowdStrike (EDR install dirs); c7: process_list not_includes falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys (EDR process names); c9: process.env.CI not_in true, 1, woodpecker; c13: process.env.GITHUB_ACTIONS / process.env.GITLAB_CI / process.env.TRAVIS / process.env.CIRCLECI / process.env.JENKINS_URL / process.env.BUILD_BUILDURI / process.env.CODEBUILD_BUILD_ID / process.env.BUILDKITE / process.env.APPVEYOR / process.env.BITBUCKET_BUILD_NUMBER / process.env.DRONE / process.env.SEMAPHORE / process.env.TEAMCITY_VERSION / process.env.bamboo_agentId / process.env.BITRISE_IO / process.env.CIRRUS_CI / process.env.CF_BUILD_ID / process.env.VERCEL / process.env.NOW_GITHUB_DEPLOYMENT / process.env.WERCKER_MAIN_PIPELINE_STARTED / process.env.BUDDY_WORKSPACE_ID / process.env.SHIPPABLE / process.env.JB_SPACE_EXECUTION_NUMBER / process.env.SAILCI / process.env.VELA / process.env.SCREWDRIVER / process.env.DISTELLI_APPNAME falsy; c14: process.env.CI_NAME / process.env.NETLIFY / process.env.CF_PAGES not_in codeship (CI_NAME), true (NETLIFY), 1 (CF_PAGES); c10: hardware >= 4) | then | 6 | persistence, write_file | cpu_count=4; file_absent=/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack; env_var_absent=CI, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL, BUILD_BUILDURI, CODEBUILD_BUILD_ID, BUILDKITE, APPVEYOR, BITBUCKET_BUILD_NUMBER, DRONE, SEMAPHORE, TEAMCITY_VERSION, bamboo_agentId, BITRISE_IO, CIRRUS_CI, CF_BUILD_ID, CI_NAME, NETLIFY, VERCEL, NOW_GITHUB_DEPLOYMENT, WERCKER_MAIN_PIPELINE_STARTED, BUDDY_WORKSPACE_ID, SHIPPABLE, JB_SPACE_EXECUTION_NUMBER, SAILCI, VELA, SCREWDRIVER, CF_PAGES, DISTELLI_APPNAME |
| g4 | node_gyp_implicit | c8 (c8: os == linux) | then | 1 | cred_read | os=linux |

Gate intent: g1 activate/enables/targeting; g2 evade/enables/anti_analysis; g3 evade/enables/anti_analysis; g4 activate/enables/targeting

Grounding: 0 of 14 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c1, c11, c2, c3, c4, c5, c6, c7, c8, c9, c10, c12, c13, c14, g1, g2, g3, g4.

## Requirements

- network: api[.]github[.]com:443, api[.]anthropic[.]com:443, github[.]com:443 (GitHub API for repo-based exfiltration and worm propagation; api.anthropic.com as a secondary exfil sink; github.com to download the Bun runtime.)
- installed_tool: curl, unzip, bash, python3 (The bootstrap downloads and unzips the Bun runtime with curl and unzip when Bun is absent; the i1 persistence dropper runs its staged script with bash, and that script stops unless python3 is present to run the monitor.)

## Behaviour

- Ungated: download, write_file, exec_downloaded, spawn_process
- Gated: recon, cred_read, exfil, self_propagation, persistence, write_file

## Notes

- Decode chain registered as derivations d7 (charcode_caesar_eval on index.js) -> d8 (_p, aesgcm_hex_stage) and d9 (_b, aesgcm_hex_stage) -> d10 (obfio_scoped) -> d11 (scramble_feistel, fn f489094fb, key/salt at the T9 constructor) -> d12 (aesgcm_gunzip, fn a, the embedded scripts). All anchors cite into d11; d12 is the readable copy of the embedded stages.
- Everything is out of set: the generator only saw the encoded single-line index.js, so no candidates were prefilled and every condition/gate is analyst-added (candidate null). All need manual confirmation.
- Gates recorded: g1 Russian-locale victim exclusion, activate/targeting (z7: Intl locale as c1, LC_ALL/LC_MESSAGES/LANGUAGE/LANG as c11, the SystemRoot-only LANG/LANGUAGE/LC_ALL test as c12; exits in uX); g2 honeypot/decoy evade (IX: cwd /tmp/npm-safe, FAKE ~/.aws/credentials, decoy token env prefixes, research repo actions-security-demo/compromised-packages); g3 EDR+CI+CPU evade on the i1 persistence dropper (H9 split into c9 CI values, c13 presence markers, c14 other value markers); g4 Linux-only Kubernetes credential theft. The uX daemonization ($X detached respawn with __IS_DAEMON) and PID lock (yX) are launch/concurrency plumbing, noted not gated.
- EDR list (DQ/RQ): CrowdStrike, SentinelOne, Carbon Black, Defender (mdatp/wdavdaemon), Cylance, osquery, tanium, qualys, etc. Decoy env list (RK): ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, ...
- The i1 dropper writes an embedded Python monitor to /tmp/update-*/updater.py and pipes an embedded script to `bash -s -- updater.py`. Decoded as d12, the script installs the monitor as a systemd user service or LaunchAgent; the monitor polls GitHub commit search for signed `firedalazer` messages, then downloads and runs the Python file they name. This is persistence, not self-propagation.
- Static analysis only; no package code was run and no endpoint contacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "executable-stories-playwright",
    "version": "7.0.3",
    "archive_sha256": "f8382242e31c7b2174d65924fb316abd74b09986a8941b1b87d594e97ca989cc",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-04-executable-stories-playwright-v7.0.3.zip",
    "package_root": "layer0/tmp/tmp7xhm0pt0/executable-stories-playwright/package",
    "cluster_key": "993922ed4864e6934aa1a10fd50b622e2d4e2a02f3df4a5bea274906d66baf15",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "node_gyp_implicit",
        "command": "node-gyp rebuild; binding.gyp sources uses <!(node index.js > /dev/null 2>&1 && echo stub.c)",
        "runs_on": "always",
        "file_chain": [
          "binding.gyp",
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "native_build",
          "decoded_eval",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "binding.gyp is type:none with sources ['<!(node index.js > /dev/null 2>&1 && echo stub.c)']; the <!() command expansion runs `node index.js` during `node-gyp rebuild` at install, with stdout/stderr discarded.",
      "index.js: char-code array ROT13-decoded (d7) to a wrapper that AES-128-GCM-decrypts a bootstrap (_b/d9) and the main payload (_p/d8); _p is written to /tmp/p<rand>.js and run with Bun; _b downloads the Bun runtime from github (defanged) via curl+unzip when Bun is absent.",
      "_p decoded further: obfuscator.io string array (d10) then a pbkdf2-keyed scramble cipher over strings (d11).",
      "Coverage of d11: install entry, uX() evasion chain and the principal credential/propagation modules read in full; per-provider collectors characterised by behaviour, not line by line.",
      "d12 (aesgcm_gunzip, fn a) decodes the embedded stages: i1 writes Python stage d7 to /tmp/update-*/updater.py and pipes bash stage n7 to bash, which installs it as a systemd user service or LaunchAgent.",
      "The installed monitor polls GitHub commit search for signed 'firedalazer' messages, then downloads and runs the Python file named there: persistence, not self-propagation.",
      "c7's probe command is chosen by a ternary: 'tasklist 2>/dev/null' on win32, otherwise 'ps aux 2>/dev/null'; the probe target writes the choice as *. A failed probe is caught and w4 returns false, so the guarded code still runs.",
      "c12 is z7's third test: only when SystemRoot is set does it read LANG, then LANGUAGE, then LC_ALL, an order that differs from c11, so it can exit when c11 passes. With SystemRoot unset it compares an empty string and holds.",
      "GX in i1.shouldExecute is a module flag set after a successful run, a re-entry guard and not an environment test, so it is not a condition.",
      "PX calls execute on each element of the xX array, so the self_propagation payload stops at dynamic_dispatch; o1.execute reaches processRepo, which commits an injected workflow and _index.js to victim repos.",
      "PX sits after fL's try statement, so it also runs on the catch path, where t1() supplies l1, i1 and a1.",
      "uX() also daemonizes off CI via a detached self-respawn ($X, __IS_DAEMON re-entry guard) and takes a PID lock /tmp/tmp.0144018410.lock (yX); both are launch/concurrency plumbing, not gates.",
      "bK() re-runs a propagation stage (X6) when WORKFLOW_ID/REPO_ID_SUFFIX and GITHUB_ACTIONS match the worm's own injected workflow; recorded under self_propagation.",
      "bin command 'intent' (./bin/intent.js) and dist/ run only when invoked or loaded, not at install.",
      "All conditions and gates are out of set: the deterministic generator saw only the encoded single-line index.js."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "api[.]anthropic[.]com:443",
        "github[.]com:443"
      ],
      "reason": "GitHub API for repo-based exfiltration and worm propagation; api.anthropic.com as a secondary exfil sink; github.com to download the Bun runtime."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip",
        "bash",
        "python3"
      ],
      "reason": "The bootstrap downloads and unzips the Bun runtime with curl and unzip when Bun is absent; the i1 persistence dropper runs its staged script with bash, and that script stops unless python3 is present to run the monitor."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat().resolvedOptions().locale",
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
            "derived_from": "d11",
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
      "id": "c11",
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
            "derived_from": "d11",
            "start_byte": 178290,
            "end_byte": 178428,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c2",
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
            "derived_from": "d11",
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
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336957,
            "end_byte": 337005,
            "node_type": "call_expression",
            "sha256": "2f7ba27e1b8b6d40",
            "line": 1
          }
        }
      ],
      "probe": {
        "kind": "file",
        "callee": "readFileSync",
        "target": "~/.aws/credentials",
        "accessor": "content"
      }
    },
    {
      "id": "c4",
      "category": "env_var",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ghp_decoyGitHubToken / npm_F4k3NPMToken / sk-ant-api03-fake (planted decoy token prefixes in GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, ...)",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336616,
            "end_byte": 336672,
            "node_type": "binary_expression",
            "sha256": "8b7a9c969330273d",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c5",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "not_in",
      "value": "actions-security-demo/compromised-packages",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336748,
            "end_byte": 336792,
            "node_type": "call_expression",
            "sha256": "f38d816bd53db039",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c6",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "/opt/CrowdStrike, /opt/sentinelone, /opt/carbonblack, /Library/CS/falcon, C:\\Program Files\\CrowdStrike (EDR install dirs)",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180993,
            "end_byte": 181013,
            "node_type": "call_expression",
            "sha256": "03002d9a5c838262",
            "line": 1
          }
        }
      ],
      "probe": {
        "kind": "file",
        "callee": "existsSync",
        "target": "/opt/CrowdStrike (and other EDR install dirs)",
        "accessor": "exists"
      }
    },
    {
      "id": "c7",
      "category": "process_list",
      "api": "child_process.execSync",
      "operator": "not_includes",
      "value": "falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys (EDR process names)",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 181244,
            "end_byte": 181276,
            "node_type": "call_expression",
            "sha256": "6143271771feeb6b",
            "line": 1
          }
        }
      ],
      "probe": {
        "kind": "exec",
        "callee": "execSync",
        "target": "* 2>/dev/null",
        "accessor": "stdout"
      }
    },
    {
      "id": "c8",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "linux",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 545694,
            "end_byte": 545708,
            "node_type": "binary_expression",
            "sha256": "f3c3b10e4eee955a",
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
      "value": "true, 1, woodpecker",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179050,
            "end_byte": 179101,
            "node_type": "binary_expression",
            "sha256": "fd2a75bb878ed922",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180135,
            "end_byte": 180167,
            "node_type": "binary_expression",
            "sha256": "5133893206ad349b",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c10",
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
            "derived_from": "d11",
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
      "id": "c12",
      "category": "locale_language",
      "api": "process.env.LANG / process.env.LANGUAGE / process.env.LC_ALL",
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
            "derived_from": "d11",
            "start_byte": 178443,
            "end_byte": 178582,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c13",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS / process.env.GITLAB_CI / process.env.TRAVIS / process.env.CIRCLECI / process.env.JENKINS_URL / process.env.BUILD_BUILDURI / process.env.CODEBUILD_BUILD_ID / process.env.BUILDKITE / process.env.APPVEYOR / process.env.BITBUCKET_BUILD_NUMBER / process.env.DRONE / process.env.SEMAPHORE / process.env.TEAMCITY_VERSION / process.env.bamboo_agentId / process.env.BITRISE_IO / process.env.CIRRUS_CI / process.env.CF_BUILD_ID / process.env.VERCEL / process.env.NOW_GITHUB_DEPLOYMENT / process.env.WERCKER_MAIN_PIPELINE_STARTED / process.env.BUDDY_WORKSPACE_ID / process.env.SHIPPABLE / process.env.JB_SPACE_EXECUTION_NUMBER / process.env.SAILCI / process.env.VELA / process.env.SCREWDRIVER / process.env.DISTELLI_APPNAME",
      "operator": "falsy",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179116,
            "end_byte": 179145,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179160,
            "end_byte": 179184,
            "node_type": "subscript_expression",
            "sha256": "bf3c6fd310ce9ec5",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179199,
            "end_byte": 179220,
            "node_type": "subscript_expression",
            "sha256": "33677f17d7ed21b8",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179235,
            "end_byte": 179258,
            "node_type": "subscript_expression",
            "sha256": "808a8836ff790cd7",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179273,
            "end_byte": 179299,
            "node_type": "subscript_expression",
            "sha256": "4a0f22c33dd10eb9",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179314,
            "end_byte": 179343,
            "node_type": "subscript_expression",
            "sha256": "801b4a145c031dde",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179358,
            "end_byte": 179391,
            "node_type": "subscript_expression",
            "sha256": "1b6343d8e62eb900",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179406,
            "end_byte": 179430,
            "node_type": "subscript_expression",
            "sha256": "248d2f7c64c6e1d7",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179445,
            "end_byte": 179468,
            "node_type": "subscript_expression",
            "sha256": "bd8854c5bff9aa63",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179483,
            "end_byte": 179520,
            "node_type": "subscript_expression",
            "sha256": "05576fa2f24786a7",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179535,
            "end_byte": 179555,
            "node_type": "subscript_expression",
            "sha256": "37a49d71ca091431",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179570,
            "end_byte": 179594,
            "node_type": "subscript_expression",
            "sha256": "991b2de324519359",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179609,
            "end_byte": 179640,
            "node_type": "subscript_expression",
            "sha256": "359d02189a03f457",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179655,
            "end_byte": 179684,
            "node_type": "subscript_expression",
            "sha256": "e541ca98d6207b30",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179699,
            "end_byte": 179724,
            "node_type": "subscript_expression",
            "sha256": "b17b7b1ea9b01dba",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179739,
            "end_byte": 179763,
            "node_type": "subscript_expression",
            "sha256": "25a30ed5725bf2d5",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179778,
            "end_byte": 179804,
            "node_type": "subscript_expression",
            "sha256": "215c3b7db22f537a",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179915,
            "end_byte": 179974,
            "node_type": "binary_expression",
            "sha256": "f33613d195fd2f88",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179989,
            "end_byte": 180033,
            "node_type": "subscript_expression",
            "sha256": "3b2e1bea7f503989",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180048,
            "end_byte": 180081,
            "node_type": "subscript_expression",
            "sha256": "a4237663451d7cbb",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180096,
            "end_byte": 180120,
            "node_type": "subscript_expression",
            "sha256": "bb44a6383889493d",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180182,
            "end_byte": 180222,
            "node_type": "subscript_expression",
            "sha256": "44a7b3cae50fc6b6",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180237,
            "end_byte": 180258,
            "node_type": "subscript_expression",
            "sha256": "bbe092b18f94ce8d",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180273,
            "end_byte": 180292,
            "node_type": "subscript_expression",
            "sha256": "fcfc2d842423e60e",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180307,
            "end_byte": 180333,
            "node_type": "subscript_expression",
            "sha256": "f3111456ae4c98dc",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180392,
            "end_byte": 180423,
            "node_type": "subscript_expression",
            "sha256": "244a91a747b8172b",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c14",
      "category": "ci_marker",
      "api": "process.env.CI_NAME / process.env.NETLIFY / process.env.CF_PAGES",
      "operator": "not_in",
      "value": "codeship (CI_NAME), true (NETLIFY), 1 (CF_PAGES)",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179819,
            "end_byte": 179854,
            "node_type": "binary_expression",
            "sha256": "1ba613966eb22dc5",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 179869,
            "end_byte": 179900,
            "node_type": "binary_expression",
            "sha256": "9f58479b50762a0a",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180348,
            "end_byte": 180377,
            "node_type": "binary_expression",
            "sha256": "4d5972c30ba37cc9",
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
      "expression": "c1 && c11 && c12",
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Exits before any harvest when the Intl locale, LC_ALL/LC_MESSAGES/LANGUAGE/LANG or, on hosts with SystemRoot set, LANG/LANGUAGE/LC_ALL in that order indicates Russian, excluding Russian-locale victims; it does not detect analysis.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338991,
            "end_byte": 339031,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c11",
            "c12"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581316,
              "end_byte": 581320,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
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
            "start_byte": 581321,
            "end_byte": 581578,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581842,
            "end_byte": 581888,
            "node_type": "expression_statement",
            "sha256": "8f81c60cf7880881",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 1740,
              "end_byte": 1830,
              "node_type": "call_expression",
              "sha256": "f7c9a7f8e492caf9",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581362,
                  "end_byte": 581375,
                  "node_type": "call_expression",
                  "sha256": "506442d2686cb018",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581341,
                  "end_byte": 581345,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 565722,
                  "end_byte": 565744,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581341,
                  "end_byte": 581345,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 565722,
                  "end_byte": 565744,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 280910,
              "end_byte": 280960,
              "node_type": "call_expression",
              "sha256": "90f7e6e55d4ccdc2",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581848,
                  "end_byte": 581861,
                  "node_type": "call_expression",
                  "sha256": "39cf76f94c76a89c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 314817,
                  "end_byte": 315169,
                  "node_type": "function_declaration",
                  "sha256": "21b03d77b79d360a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 315133,
                  "end_byte": 315155,
                  "node_type": "call_expression",
                  "sha256": "0d8296c611757ebc",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 280271,
                  "end_byte": 281044,
                  "node_type": "method_definition",
                  "sha256": "b58b44fb4eaada03",
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
      "expression": "c2 && c3 && c4 && c5",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "Exits when honeypot/sandbox markers are present: cwd under /tmp/npm-safe, a FAKE ~/.aws/credentials decoy, planted decoy token env prefixes, or the known research repo.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
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
            "c3",
            "c4",
            "c5"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581316,
              "end_byte": 581320,
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
        "env_recipe": {
          "file_absent": [
            "~/.aws/credentials"
          ],
          "env_var_absent": [
            "GITHUB_REPOSITORY"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581321,
            "end_byte": 581578,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581842,
            "end_byte": 581888,
            "node_type": "expression_statement",
            "sha256": "8f81c60cf7880881",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 1740,
              "end_byte": 1830,
              "node_type": "call_expression",
              "sha256": "f7c9a7f8e492caf9",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581362,
                  "end_byte": 581375,
                  "node_type": "call_expression",
                  "sha256": "506442d2686cb018",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581341,
                  "end_byte": 581345,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 565722,
                  "end_byte": 565744,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581341,
                  "end_byte": 581345,
                  "node_type": "call_expression",
                  "sha256": "3275c28a77a252e7",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 565722,
                  "end_byte": 565744,
                  "node_type": "call_expression",
                  "sha256": "dbe2c935a910a3e2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 280910,
              "end_byte": 280960,
              "node_type": "call_expression",
              "sha256": "90f7e6e55d4ccdc2",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581848,
                  "end_byte": 581861,
                  "node_type": "call_expression",
                  "sha256": "39cf76f94c76a89c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 314817,
                  "end_byte": 315169,
                  "node_type": "function_declaration",
                  "sha256": "21b03d77b79d360a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 315133,
                  "end_byte": 315155,
                  "node_type": "call_expression",
                  "sha256": "0d8296c611757ebc",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 280271,
                  "end_byte": 281044,
                  "node_type": "method_definition",
                  "sha256": "b58b44fb4eaada03",
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
      "expression": "c6 && c7 && c9 && c13 && c14 && c10",
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "The persistent GitHub-commit command monitor is installed only off CI (every H9 marker clear), with at least 4 CPUs and no EDR/security agent present (sandbox and monitored-host evasion).",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 288827,
            "end_byte": 288872,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c6",
            "c7",
            "c9",
            "c13",
            "c14",
            "c10"
          ]
        }
      ],
      "then": {
        "min_conditions": 6,
        "behaviours": [
          "persistence",
          "write_file"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "file_absent": [
            "/opt/CrowdStrike",
            "/Library/CS/falcon",
            "/opt/carbonblack",
            "/opt/sentinelone",
            "C:\\Program Files\\CrowdStrike",
            "C:\\Program Files\\SentinelOne",
            "C:\\Program Files\\CarbonBlack"
          ],
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
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 288959,
            "end_byte": 289232,
            "node_type": "statement_block",
            "sha256": "2ab966e0c5a6fbc5",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 289013,
              "end_byte": 289104,
              "node_type": "call_expression",
              "sha256": "acc3af4cc0f3c98b",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 288960,
              "end_byte": 288998,
              "node_type": "call_expression",
              "sha256": "88de24f39016e60e",
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
      "purpose": "targeting",
      "purpose_reason": "Kubernetes service-account/kubeconfig credential theft runs only on Linux hosts.",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 545691,
            "end_byte": 545746,
            "node_type": "if_statement",
            "sha256": "f7cec2bb9232c8df",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ]
        }
      ],
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 545760,
            "end_byte": 545850,
            "node_type": "ternary_expression",
            "sha256": "2df50c0c46f2c82a",
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
              "start_byte": 542519,
              "end_byte": 542563,
              "node_type": "call_expression",
              "sha256": "0287d06c334d9421",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 545822,
                  "end_byte": 545850,
                  "node_type": "call_expression",
                  "sha256": "536aecb4dcfeb1f0",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 542133,
                  "end_byte": 542873,
                  "node_type": "method_definition",
                  "sha256": "44290bd8e289dc4a",
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
    "ungated": [
      "download",
      "write_file",
      "exec_downloaded",
      "spawn_process"
    ],
    "gated": [
      "recon",
      "cred_read",
      "exfil",
      "self_propagation",
      "persistence",
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "index.js is a char-code array run through a ROT13 Caesar shift and passed to eval",
      "two AES-128-GCM-encrypted stages (bootstrap _b and main payload _p) decrypted at runtime from hex literals",
      "main payload is obfuscator.io output: a rotated base64 string array plus a pbkdf2-keyed scramble substitution-permutation cipher encrypting individual strings",
      "embedded main payload written to a temp file and executed with a separately downloaded Bun runtime",
      "identifier mangling and control-flow obfuscation",
      "embedded scripts held as AES-256-GCM plus gzip base64 blobs behind the helper a(), decoded as d12"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "api[.]github[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "api[.]anthropic[.]com",
        "role": "exfil_sink"
      },
      {
        "indicator": "github[.]com",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "At install time binding.gyp runs `node index.js`, which eval-decodes a Bun-run second stage that harvests GitHub, npm, cloud and Kubernetes credentials, exfiltrates them to attacker-controlled GitHub repos and api.anthropic.com, and self-propagates by injecting malicious GitHub Actions workflows and AI-assistant config files. Execution skips Russian-locale hosts and is gated behind anti-analysis checks (honeypot/decoy markers, EDR detection, CI, CPU count). This matches the Shai-Hulud npm worm.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and gates are out of set: the deterministic generator saw only the encoded single-line index.js, so every gate needs manual confirmation.",
    "Payload recovered through a 6-stage derivation chain (ROT13 charcode eval, two AES-128-GCM stages, obfuscator.io string array, scramble SP cipher, AES-256-GCM plus gzip embedded scripts); verify the derivations rebuild to the cited bytes.",
    "A Russian-locale exclusion gate and honeypot, EDR, CI and CPU-count evasion gates guard the whole payload; the locale recipe value is inferred.",
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
        "output_sha256": "81fadd687395dadb"
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
        "output_sha256": "da39146ef451d1b1"
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
        "output_sha256": "ceff7c51d70832c3"
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
        "output_sha256": "8434df42d4e26f68"
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
          "fn": "f489094fb",
          "key": "77afe07fa1eca63ce025ef790b33cdcde73da475c5a700acb14a5578b35d2813",
          "salt": "74eb124111aadb515960c4618132c1b4",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "31469ac8c0469a41"
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
          "fn": "a",
          "decoder": "aesgcm_gunzip",
          "lang": "js"
        },
        "output_sha256": "2fb68089f76e33e3"
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
    "conditions_out_of_set": 14,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 4,
    "out_of_set_ids": [
      "c1",
      "c11",
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
      "c13",
      "c14",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
