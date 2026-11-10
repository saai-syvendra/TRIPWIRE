# npm autotel-eventcatalog@3.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

The package has no install script, but a `binding.gyp` makes npm run `node-gyp rebuild`, and the gyp file expands `node index.js` while loading. `index.js` is a layered loader (char-code Caesar eval, AES-GCM stages, string-table and Feistel string ciphers) that writes a decrypted worm payload to /tmp and runs it with bun, downloading bun first if needed. The payload exits early on honeypot signs (decoy tokens, a demo repo, /tmp/npm-safe, FAKE in ~/.aws/credentials), on a Russian locale, and when a live lock file exists. It only installs its persistence updater on hosts with 4 or more CPUs, no EDR and none of the CI markers H9() tests, and it only republishes npm and rubygems packages on darwin or linux. Past those checks it collects cloud, CI and registry credentials, sends them to a public GitHub repo, installs a token monitor whose handler deletes the home folder if the token is later revoked, and rewrites and republishes other packages.

## Execution

- **node_gyp_implicit** `node-gyp rebuild (implicit); binding.gyp expands <!(node index.js > /dev/null 2>&1 && echo stub.c) while loading`: 2-file chain; native_build, inline_shell, decoded_eval, download_then_exec, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | node_gyp_implicit | c1 && c2 && c3 && c4 (c1: process.env[envVar].startsWith not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: file_content not_includes FAKE) | then | 4 | cred_read, exfil, self_propagation, persistence, modify_other_packages | env_var_absent=GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, CIRCLE_TOKEN, AWS_ACCESS_KEY_ID, GITHUB_REPOSITORY; file_absent=~/.aws/credentials |
| g2 | node_gyp_implicit | c5 && c6 && c7 (c5: locale_language not_startswith ru; c6: locale_language not_startswith ru; c7: locale_language not_startswith ru) | then | 3 | cred_read, exfil, self_propagation, persistence, modify_other_packages | locale=en_US.UTF-8 |
| g3 | node_gyp_implicit | c8 (c8: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock holding the pid of a live process) | then | 1 | cred_read, exfil, self_propagation, persistence, modify_other_packages | file_absent=/tmp/tmp.0144018410.lock |
| g4 | node_gyp_implicit | c9 && c10 && c11 && c12 && c13 && c14 && c15 && c16 (c9: hardware >= 4; c10: vm_sandbox_artifact not_exists EDR install paths: /opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone and Windows equivalents; c11: process_list not_includes EDR process names: falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys; c12: process.env.CI not_in [true, 1, woodpecker]; c13: process.env.GITHUB_ACTIONS / process.env.GITLAB_CI / process.env.TRAVIS / process.env.CIRCLECI / process.env.JENKINS_URL / process.env.BUILD_BUILDURI / process.env.CODEBUILD_BUILD_ID / process.env.BUILDKITE / process.env.APPVEYOR / process.env.BITBUCKET_BUILD_NUMBER / process.env.DRONE / process.env.SEMAPHORE / process.env.TEAMCITY_VERSION / process.env.bamboo_agentId / process.env.BITRISE_IO / process.env.CIRRUS_CI / process.env.CF_BUILD_ID / process.env.VERCEL / process.env.NOW_GITHUB_DEPLOYMENT / process.env.WERCKER_MAIN_PIPELINE_STARTED / process.env.BUDDY_WORKSPACE_ID / process.env.SHIPPABLE / process.env.JB_SPACE_EXECUTION_NUMBER / process.env.SAILCI / process.env.VELA / process.env.SCREWDRIVER / process.env.DISTELLI_APPNAME falsy; c14: process.env.CI_NAME != codeship; c15: process.env.NETLIFY != true; c16: process.env.CF_PAGES != 1) | then | 8 | write_file, persistence | cpu_count=4; env_var_absent=CI, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL, BUILD_BUILDURI, CODEBUILD_BUILD_ID, BUILDKITE, APPVEYOR, BITBUCKET_BUILD_NUMBER, DRONE, SEMAPHORE, TEAMCITY_VERSION, bamboo_agentId, BITRISE_IO, CIRRUS_CI, CF_BUILD_ID, CI_NAME, NETLIFY, VERCEL, NOW_GITHUB_DEPLOYMENT, WERCKER_MAIN_PIPELINE_STARTED, BUDDY_WORKSPACE_ID, SHIPPABLE, JB_SPACE_EXECUTION_NUMBER, SAILCI, VELA, SCREWDRIVER, CF_PAGES, DISTELLI_APPNAME; file_absent=/opt/CrowdStrike, /opt/sentinelone |
| g5 | node_gyp_implicit | c17 (c17: os in [darwin, linux]) | then | 1 | self_propagation, modify_other_packages | os=linux |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/enables/targeting; g3 activate/enables/unclear; g4 evade/enables/anti_analysis; g5 activate/enables/targeting

Grounding: 0 of 17 conditions and 0 of 5 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, g1, g2, g3, g4, g5.

## Requirements

- installed_tool: curl, unzip (the bun fetcher downloads and unpacks a bun release when bun is not already present)
- installed_tool: bash, python3 (embedded updater installer (bash) installs a python3 monitor; it exits if python3 is missing)
- network: github[.]com:443, api[.]github[.]com:443, registry[.]npmjs[.]org:443 (bun download, GitHub API results repo and token validation, npm registry used by the propagation code)
- os: linux, darwin (the persistence installers and the token monitor refuse other operating systems)

## Behaviour

- Ungated: write_file, download, exec_downloaded, spawn_process
- Gated: cred_read, exfil, self_propagation, persistence, modify_other_packages, write_file

## Notes

- All gates are out of set because the extractor never parsed `index.js`.
- Decode chain d20 to d25 is registered and replayable.
- The 580 KB decoded payload was read for the entry flow, gates, installer scripts and token monitor; bundled libraries were only sink-inventoried. Checks not recorded as conditions (bK() workflow targeting, TARGET_REPOS, SKIP_DOMAIN) are listed in `execution.notes`.
- The rest of the package (dist, src, docs) looks like the legitimate library and does not run at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "autotel-eventcatalog",
    "version": "3.0.1",
    "archive_sha256": "0fe7bd6a948af689541c48d0b7b9a1ffa09b3f327877164af0311ac2609705fa",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-04-autotel-eventcatalog-v3.0.1.zip",
    "package_root": "layer0/tmp/tmpaq7kj763/autotel-eventcatalog/package",
    "cluster_key": "a6cbb690cdce86ab0ca8900fee564fd2152ca90fd5a0ea53725cdcb0eb075f3f",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "node_gyp_implicit",
        "command": "node-gyp rebuild (implicit); binding.gyp expands <!(node index.js > /dev/null 2>&1 && echo stub.c) while loading",
        "runs_on": "always",
        "file_chain": [
          "binding.gyp",
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "native_build",
          "inline_shell",
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
      "binding.gyp (no install script, so npm runs node-gyp rebuild) runs `node index.js` through a command expansion with output discarded. index.js is the only install-reached package code; dist/, src/ and the other files are the legitimate library and never run at install.",
      "index.js: char-code array plus Caesar shift 24 handed to eval (d20) -> AES-128-GCM stages with key, iv and tag in the code (d21 payload, d22 bun fetcher) -> obfuscator.io string table (d23) -> Feistel-style string cipher behind f489094fb (d24) -> AES-GCM+gzip embedded scripts (d25).",
      "Loader: writes the decrypted payload to /tmp/p<random>.js and runs it with bun (typeof Bun check is plumbing). Without Bun it evals the d22 helper, which downloads a pinned bun release with curl and unzip into a temp dir, then runs the payload with that binary.",
      "Payload entry fL(): preflight uX() then credential collectors, sender setup, streaming run, finalize, then propagation classes via PX(). Non-CI runs relaunch themselves as a detached child (__IS_DAEMON re-entry guard, plumbing) and the parent exits.",
      "index.js coverage: decode chain fully recovered and replayable. Package code read: loader, entry flow fL/uX, decoy/locale/lock/EDR/CI helpers, updater class i1, embedded bash installers, token monitor class c6, GitHub repo sender.",
      "index.js: bundled tar, AWS, Azure and sigstore library code was only sink-inventoried by grep, not read in full.",
      "g5 is the darwin/linux check in the npm (g1 class) and rubygems (y1 class) execute methods. It sits behind g1 to g3 and a collected token, but like g4 its expression holds only its own test.",
      "Not a gate: the w4 test in the shouldRun methods of the filesystem scanner w6 and k6. shouldRun appears in d24 only as three definitions with no caller, so those tests never run; w4 only decides through i1.shouldExecute (g4).",
      "Not recorded as a gate: bK() (WORKFLOW_ID/REPO_ID_SUFFIX with GITHUB_ACTIONS) compares env vars with each other and only opens in the workflow the worm writes (bun run _index.js), not at npm install. Left for a reviewer.",
      "Also not recorded as gates: TARGET_REPOS and SKIP_DOMAIN env choices. Only the code reads them; nothing in the payload sets them, and they were not traced further.",
      "Hardened-runner handling is dead code: k6.detectHardenRunner has no caller, so wX and its sudo writes to /etc/hosts and resolv.conf never run. No other evasion sink was found, so defense_evasion is not claimed for g1, g2 or g3.",
      "destructive is not claimed: rm -rf is only the handler string passed to c6; the installed monitor runs it later, after token revocation. That later effect is covered by persistence.",
      "g1-g3 persistence: finalize, flush, then this.dispatch (f1.dispatch, bound through the u1 constructor), sender send, P9.augmentEnvelope, c6.execute, installTokenMonitor. The dispatch hop is unresolved, and it only runs when P9 includeToken is set (token with no orgs).",
      "g1-g3 self_propagation and modify_other_packages run through u1.ingest for each collected npm token: handleNpmTokens, g1.execute, downloadPackages and updateTarball (A9 rewrites the tarball), then publishPackage (C4 PUTs it to the npm registry).",
      "PX (classes from xX or t1: l1, i1, a1, m1, o1, r1) runs after the try block in fL, so it sits outside the block that via uX() covers. Its repo pushes are not cited as sinks; the catch path also reaches PX through t1().",
      "Embedded n7 (bash): requires Darwin or Linux and python3, installs a monitor as a systemd user service (Linux) or LaunchAgent (macOS).",
      "Embedded o7 (bash): gh-token-monitor polls the GitHub API with a stolen token and eval()s a handler on HTTP 40x (token revoked); the handler seen in code is `rm -rf ~/`.",
      "Spreading behaviour in code: creates a public GitHub repo described 'Miasma - The Spreading Blight' for results, rewrites other packages' tarballs and republishes via npm/OIDC, pushes .claude/settings.json SessionStart hooks and VS Code tasks into repos, deletes branch protection.",
      "g1 evade checks look for decoy/honeypot values (fake token prefixes, a named demo repo, /tmp/npm-safe/, FAKE in ~/.aws/credentials). Positive form requires none of them. RK holds five env var/prefix pairs; c1 lists all five prefixes.",
      "H9() is split by test shape: c12 is the three compared CI values, c13 the 27 variables tested for presence (one condition, one site each), c14 to c16 the other compared variables. All must fail for g4, so its min_conditions counts these groups, not each variable.",
      "c11: w4 picks the command by platform: ps aux 2>/dev/null, or tasklist 2>/dev/null on win32. The probe target records the linux and darwin form. shouldExecute's GX test is an in-process re-entry flag set after a successful run, so it is not a condition of g4.",
      "g4 persistence: Bun.spawn runs bash -s with n7 on stdin; n7 copies updater.py to ~/.local/share/updater/ and enables a systemd user service or LaunchAgent."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip"
      ],
      "reason": "the bun fetcher downloads and unpacks a bun release when bun is not already present"
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash",
        "python3"
      ],
      "reason": "embedded updater installer (bash) installs a python3 monitor; it exits if python3 is missing"
    },
    {
      "axis": "network",
      "value": [
        "github[.]com:443",
        "api[.]github[.]com:443",
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "bun download, GitHub API results repo and token validation, npm registry used by the propagation code"
    },
    {
      "axis": "os",
      "value": [
        "linux",
        "darwin"
      ],
      "reason": "the persistence installers and the token monitor refuse other operating systems"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env[envVar].startsWith",
      "operator": "not_startswith",
      "value": [
        "ghp_decoyGitHubToken",
        "npm_F4k3NPMToken",
        "sk-ant-api03-fake",
        "fake_circle",
        "AKIAFAKE"
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
      "id": "c2",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "!=",
      "value": "actions-security-demo/compromised-packages",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 336770,
            "end_byte": 336791,
            "node_type": "binary_expression",
            "sha256": "e2f0f0a7f11a3b9a",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c3",
      "category": "home_or_path",
      "api": "process.cwd().startsWith",
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
      "id": "c4",
      "category": "file_content",
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
      "id": "c5",
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
            "derived_from": "d24",
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
      "id": "c6",
      "category": "locale_language",
      "api": "process.env.LC_ALL || LC_MESSAGES || LANGUAGE || LANG",
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
      "id": "c7",
      "category": "locale_language",
      "api": "process.env.LANG || LANGUAGE || LC_ALL (when SystemRoot is set)",
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
      "id": "c8",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "<tmpdir>/tmp.0144018410.lock holding the pid of a live process",
      "value_recovered": "decoded",
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
            "derived_from": "d24",
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
      "id": "c9",
      "category": "hardware",
      "api": "os.cpus().length",
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
            "derived_from": "d24",
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
      "id": "c10",
      "category": "vm_sandbox_artifact",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "EDR install paths: /opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone and Windows equivalents",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 180993,
            "end_byte": 181013,
            "node_type": "call_expression",
            "sha256": "03002d9a5c838262",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c11",
      "category": "process_list",
      "api": "child_process.execSync",
      "operator": "not_includes",
      "value": "EDR process names: falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
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
            "derived_from": "d24",
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
      "id": "c12",
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
            "start_byte": 179050,
            "end_byte": 179076,
            "node_type": "binary_expression",
            "sha256": "a1e133353ca470cc",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 179078,
            "end_byte": 179101,
            "node_type": "binary_expression",
            "sha256": "10b85e1bd2ac21a1",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
            "start_byte": 179915,
            "end_byte": 179936,
            "node_type": "subscript_expression",
            "sha256": "b617318eaa522c1d",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 179938,
            "end_byte": 179974,
            "node_type": "subscript_expression",
            "sha256": "7909a5d7c700b59a",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
            "derived_from": "d24",
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
      "api": "process.env.CI_NAME",
      "operator": "!=",
      "value": "codeship",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 179819,
            "end_byte": 179854,
            "node_type": "binary_expression",
            "sha256": "1ba613966eb22dc5",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c15",
      "category": "ci_marker",
      "api": "process.env.NETLIFY",
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 179869,
            "end_byte": 179900,
            "node_type": "binary_expression",
            "sha256": "9f58479b50762a0a",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c16",
      "category": "ci_marker",
      "api": "process.env.CF_PAGES",
      "operator": "!=",
      "value": "1",
      "value_recovered": "decoded",
      "in_scope": true,
      "provenance": "out_of_set",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 180348,
            "end_byte": 180377,
            "node_type": "binary_expression",
            "sha256": "4d5972c30ba37cc9",
            "line": 1
          }
        }
      ]
    },
    {
      "id": "c17",
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
            "start_byte": 189058,
            "end_byte": 189109,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 205691,
            "end_byte": 205742,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
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
      "expression": "c1 && c2 && c3 && c4",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 338962,
            "end_byte": 338991,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "via": [
            {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581316,
              "end_byte": 581320,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "exits when the host looks like a honeypot or token-canary environment (decoy tokens, a demo repo, /tmp/npm-safe, FAKE AWS credentials)",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence",
          "modify_other_packages"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "ANTHROPIC_API_KEY",
            "CIRCLE_TOKEN",
            "AWS_ACCESS_KEY_ID",
            "GITHUB_REPOSITORY"
          ],
          "file_absent": [
            "~/.aws/credentials"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581578,
            "end_byte": 581640,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581640,
            "end_byte": 581808,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581646,
              "end_byte": 581743,
              "node_type": "call_expression",
              "sha256": "5b104c9cc44fc26f",
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
              "start_byte": 581750,
              "end_byte": 581773,
              "node_type": "call_expression",
              "sha256": "7dde769c115cc13e",
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
              "start_byte": 190913,
              "end_byte": 190957,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189312,
                  "end_byte": 189345,
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
                  "start_byte": 190775,
                  "end_byte": 190989,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 189566,
              "end_byte": 189612,
              "node_type": "call_expression",
              "sha256": "605f2a97bc811878",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189186,
                  "end_byte": 189241,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189614,
                  "end_byte": 190775,
                  "node_type": "method_definition",
                  "sha256": "b83fde384b1222b6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190590,
                  "end_byte": 190622,
                  "node_type": "call_expression",
                  "sha256": "9aaee48a9b895050",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189471,
                  "end_byte": 189614,
                  "node_type": "method_definition",
                  "sha256": "13cf83dacffc2ff7",
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
              "derived_from": "d24",
              "start_byte": 573353,
              "end_byte": 573454,
              "node_type": "call_expression",
              "sha256": "3d5514587d4f2e56",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581750,
                  "end_byte": 581773,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
                  "start_byte": 212493,
                  "end_byte": 212520,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
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
      "expression": "c5 && c6 && c7",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c7"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 338991,
            "end_byte": 339031,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "via": [
            {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581316,
              "end_byte": 581320,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "exits when the system locale (Intl, LC_ALL/LANG, or LANG on Windows) starts with ru, so Russian-locale machines are never hit",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence",
          "modify_other_packages"
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
            "start_byte": 581578,
            "end_byte": 581640,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581640,
            "end_byte": 581808,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581646,
              "end_byte": 581743,
              "node_type": "call_expression",
              "sha256": "5b104c9cc44fc26f",
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
              "start_byte": 581750,
              "end_byte": 581773,
              "node_type": "call_expression",
              "sha256": "7dde769c115cc13e",
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
              "start_byte": 190913,
              "end_byte": 190957,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189312,
                  "end_byte": 189345,
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
                  "start_byte": 190775,
                  "end_byte": 190989,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 189566,
              "end_byte": 189612,
              "node_type": "call_expression",
              "sha256": "605f2a97bc811878",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189186,
                  "end_byte": 189241,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189614,
                  "end_byte": 190775,
                  "node_type": "method_definition",
                  "sha256": "b83fde384b1222b6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190590,
                  "end_byte": 190622,
                  "node_type": "call_expression",
                  "sha256": "9aaee48a9b895050",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189471,
                  "end_byte": 189614,
                  "node_type": "method_definition",
                  "sha256": "13cf83dacffc2ff7",
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
              "derived_from": "d24",
              "start_byte": 573353,
              "end_byte": 573454,
              "node_type": "call_expression",
              "sha256": "3d5514587d4f2e56",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581750,
                  "end_byte": 581773,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
                  "start_byte": 212493,
                  "end_byte": 212520,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
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
      "expression": "c8",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 339088,
            "end_byte": 339187,
            "node_type": "if_statement",
            "sha256": "0d2f9c75b2642bb9",
            "line": 1
          },
          "via": [
            {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581316,
              "end_byte": 581320,
              "node_type": "call_expression",
              "sha256": "de210fe47e0cac6c",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "reinfection guard: a lock file in the temp dir naming a live pid makes the payload exit; stale locks are removed and the run continues",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence",
          "modify_other_packages"
        ],
        "env_recipe": {
          "file_absent": [
            "/tmp/tmp.0144018410.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581578,
            "end_byte": 581640,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 581640,
            "end_byte": 581808,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 581646,
              "end_byte": 581743,
              "node_type": "call_expression",
              "sha256": "5b104c9cc44fc26f",
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
              "start_byte": 581750,
              "end_byte": 581773,
              "node_type": "call_expression",
              "sha256": "7dde769c115cc13e",
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
              "start_byte": 190913,
              "end_byte": 190957,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189312,
                  "end_byte": 189345,
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
                  "start_byte": 190775,
                  "end_byte": 190989,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 189566,
              "end_byte": 189612,
              "node_type": "call_expression",
              "sha256": "605f2a97bc811878",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581609,
                  "end_byte": 581639,
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
                  "start_byte": 208205,
                  "end_byte": 209489,
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
                  "start_byte": 208896,
                  "end_byte": 208930,
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
                  "start_byte": 210710,
                  "end_byte": 211457,
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
                  "start_byte": 211312,
                  "end_byte": 211342,
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
                  "start_byte": 188930,
                  "end_byte": 189471,
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
                  "start_byte": 189186,
                  "end_byte": 189241,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189614,
                  "end_byte": 190775,
                  "node_type": "method_definition",
                  "sha256": "b83fde384b1222b6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190590,
                  "end_byte": 190622,
                  "node_type": "call_expression",
                  "sha256": "9aaee48a9b895050",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189471,
                  "end_byte": 189614,
                  "node_type": "method_definition",
                  "sha256": "13cf83dacffc2ff7",
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
              "derived_from": "d24",
              "start_byte": 573353,
              "end_byte": 573454,
              "node_type": "call_expression",
              "sha256": "3d5514587d4f2e56",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 581750,
                  "end_byte": 581773,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
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
                  "derived_from": "d24",
                  "start_byte": 212493,
                  "end_byte": 212520,
                  "node_type": "call_expression",
                  "sha256": "93bdf93b776a5a14",
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
      "gate_id": "g4",
      "hook": "node_gyp_implicit",
      "expression": "c9 && c10 && c11 && c12 && c13 && c14 && c15 && c16",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c9",
            "c10",
            "c11",
            "c12",
            "c13",
            "c14",
            "c15",
            "c16"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288827,
            "end_byte": 288872,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "the persistence updater only installs on hosts with at least 4 CPUs, no EDR products and no CI environment, i.e. not on small analysis VMs or CI runners",
      "then": {
        "min_conditions": 8,
        "behaviours": [
          "write_file",
          "persistence"
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
          ],
          "file_absent": [
            "/opt/CrowdStrike",
            "/opt/sentinelone"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288960,
            "end_byte": 288999,
            "node_type": "expression_statement",
            "sha256": "b9c034eb3abe8028",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 288999,
            "end_byte": 289105,
            "node_type": "lexical_declaration",
            "sha256": "769078ebf4252247",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 289105,
            "end_byte": 289220,
            "node_type": "if_statement",
            "sha256": "ab11340f4e04baa9",
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
              "start_byte": 288960,
              "end_byte": 288998,
              "node_type": "call_expression",
              "sha256": "88de24f39016e60e",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
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
      "gate_id": "g5",
      "hook": "node_gyp_implicit",
      "expression": "c17",
      "guards": [
        {
          "candidate": null,
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c17"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 189058,
            "end_byte": 189109,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        },
        {
          "candidate": null,
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c17"
          ],
          "site": {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 205690,
            "end_byte": 205742,
            "node_type": "unary_expression",
            "sha256": "f87c07ff2b1dcdae",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "npm and rubygems republishing only run on darwin or linux; on any other platform the propagation classes do nothing and there is no other version of the behaviour",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "self_propagation",
          "modify_other_packages"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 189166,
            "end_byte": 189242,
            "node_type": "lexical_declaration",
            "sha256": "96a3301008ca8aca",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 189242,
            "end_byte": 189428,
            "node_type": "return_statement",
            "sha256": "197e26f7f9bd4ca6",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d24",
            "start_byte": 205903,
            "end_byte": 206016,
            "node_type": "for_in_statement",
            "sha256": "ff06da894bba9955",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 190913,
              "end_byte": 190957,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189312,
                  "end_byte": 189345,
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
                  "start_byte": 190775,
                  "end_byte": 190989,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 189566,
              "end_byte": 189612,
              "node_type": "call_expression",
              "sha256": "605f2a97bc811878",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189186,
                  "end_byte": 189241,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189614,
                  "end_byte": 190775,
                  "node_type": "method_definition",
                  "sha256": "b83fde384b1222b6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 190590,
                  "end_byte": 190622,
                  "node_type": "call_expression",
                  "sha256": "9aaee48a9b895050",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 189471,
                  "end_byte": 189614,
                  "node_type": "method_definition",
                  "sha256": "13cf83dacffc2ff7",
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
              "start_byte": 206363,
              "end_byte": 206452,
              "node_type": "call_expression",
              "sha256": "d075c873b09b8992",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 205946,
                  "end_byte": 205984,
                  "node_type": "call_expression",
                  "sha256": "297adf840275d68a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 206068,
                  "end_byte": 206454,
                  "node_type": "method_definition",
                  "sha256": "8696bc492c98a089",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "modify_other_packages",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d24",
              "start_byte": 206332,
              "end_byte": 206355,
              "node_type": "call_expression",
              "sha256": "f1519441b8a3e223",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 205946,
                  "end_byte": 205984,
                  "node_type": "call_expression",
                  "sha256": "297adf840275d68a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d24",
                  "start_byte": 206068,
                  "end_byte": 206454,
                  "node_type": "method_definition",
                  "sha256": "8696bc492c98a089",
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
      "write_file",
      "download",
      "exec_downloaded",
      "spawn_process"
    ],
    "gated": [
      "cred_read",
      "exfil",
      "self_propagation",
      "persistence",
      "modify_other_packages",
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "char-code array with Caesar shift passed to eval",
      "AES-128-GCM encrypted stages with key material in the same file",
      "obfuscator.io string table with rotation",
      "per-string Feistel-style cipher behind a global decode function",
      "AES-GCM plus gzip embedded scripts",
      "bundled library code (tar, AWS, Azure, sigstore) padding the payload"
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
        "indicator": "hxxps://api[.]github[.]com/user/repos",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud style worm (Miasma repo marker)",
  "claude_assessment": "malicious",
  "assessment_reason": "binding.gyp runs index.js at install; it decrypts and runs a worm payload that steals cloud, CI and registry credentials, exfiltrates through a public GitHub repo, installs persistence with a token-revocation dead-man switch and republishes other packages. The rest of the package is a legitimate library, which fits an injected release of a real project.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All gates are out of set: the extractor did not parse the install path because binding.gyp launches index.js through a gyp command expansion.",
    "The 580 KB decoded payload was read for entry flow, gates, installers and the token monitor, not line by line; bundled libraries were only sink-inventoried. bK() workflow targeting and the TARGET_REPOS and SKIP_DOMAIN choices are in execution.notes, not conditions; a reviewer should decide whether they count as gates.",
    "attack_type compromised_maintainer rests on the package otherwise being a real project's code and the dataset folder name; no registry history was checked.",
    "guessed recipe fields",
    "out-of-set claim pending verification",
    "payload path not fully traced"
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
        "output_sha256": "0f03a986adc5c528"
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
          "var": "_p",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "da39146ef451d1b1"
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
          "var": "_b",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "ceff7c51d70832c3"
      },
      {
        "id": "d23",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d21"
        },
        "params": {
          "decoder": "obfio_scoped",
          "lang": "js"
        },
        "output_sha256": "8434df42d4e26f68"
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
        "output_sha256": "31469ac8c0469a41"
      },
      {
        "id": "d25",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d24"
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
    "conditions_out_of_set": 17,
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
      "c13",
      "c14",
      "c15",
      "c16",
      "c17",
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
