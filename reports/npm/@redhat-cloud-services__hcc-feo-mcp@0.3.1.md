# npm @redhat-cloud-services/hcc-feo-mcp@0.3.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-01 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised version of the legitimate `@redhat-cloud-services/hcc-feo-mcp` package: an attacker added an `index.js` and a `preinstall: node index.js` hook. `index.js` is a four-layer self-decrypting dropper. The outer layer is a char-code array shifted by a Caesar(9) function and handed to `eval` (recovered as derived `d7`); it AES-128-GCM-decrypts two embedded stages with hard-coded keys: `_p`, the ~634 KB worm (`d8`), and `_b`, a `getBunPath` helper (`d9`). The worm is itself obfuscator.io-obfuscated (deobfuscated as `d10`). The dropper writes the worm to `/tmp/p<rand>.js` and runs it with Bun, downloading Bun v1.3.13 from github.com (via `curl`+`unzip`) when Bun is not present. The worm's entry (`bq`->`kq`) runs its install-time gates before stealing credentials, exfiltrating them, republishing npm packages, and worming GitHub repositories. This is the Shai-Hulud npm worm.

Three gates are early exits in `kq()` that guard the whole worm (reached via the `await kq()` call in `bq`): `i7()` exits when GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY or CIRCLE_TOKEN starts with a listed decoy prefix (anti-analysis, g1); `ZZ()` exits on a locale starting with `ru`, read from Intl and from LC_ALL/LC_MESSAGES/LANGUAGE/LANG, with a second env test on Windows (self-exclusion, g2); and a PID lock at `<tmpdir>/tmp.0987654321.lock` aborts if a live instance already runs (reinfection guard, g3). Four more gates decide parts of the payload: `t4` installs the `kitty-monitor` backdoor service only with 4 or more CPUs, no EDR paths or processes and no CI markers (g4); `R8.execute` republishes npm packages only on darwin or linux (g5); `Y6` dumps runner memory only on a Linux GitHub Actions runner (g6); and `hq()` runs an npm OIDC republish in a GitHub Actions job matching WORKFLOW_ID or REPO_ID_SUFFIX (g7). `KZ()`/`q9()` daemonization when not in CI is plumbing, since the payload runs either way.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script, decoded_eval, download_then_exec, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: process.env not_startswith [ghp_decoyGitHubToken, npm_F4k3NPMToken, sk-ant-api03-fake, fake_circle]) | then | 1 | recon, cred_read, exfil, self_propagation, modify_other_packages, persistence | env_var_absent=GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY, CIRCLE_TOKEN |
| g2 | preinstall | c2 && c3 && c4 (c2: locale_language not_startswith ru; c3: locale_language not_startswith ru; c4: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, self_propagation, modify_other_packages, persistence | locale=en-US |
| g3 | preinstall | c5 \|\| c6 (c5: file_or_dir_exists not_exists; c6: process_list not_exists) | then | 1 | recon, cred_read, exfil, self_propagation, modify_other_packages, persistence | file_absent=<os.tmpdir()>/tmp.0987654321.lock |
| g4 | preinstall | c7 && c8 && c9 && c10 && c11 && c12 (c7: hardware >= 4; c8: vm_sandbox_artifact not_exists [/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack]; c9: process_list not_includes [falcon-sensor, falcond, csfalcon, sentinelone, sentinelagent, mdatp, wdavdaemon, cbagent, cbdaemon, cylance, crowdstrike, trendmicro, ds_agent, xagt, osquery, tanium, qualys]; c10: process.env.CI != true; c11: process.env.GITHUB_ACTIONS != true; c12: process.env.JENKINS_HOME not_exists) | then | 6 | persistence | cpu_count=4; env_var_absent=CI, GITHUB_ACTIONS, JENKINS_HOME; file_absent=/opt/CrowdStrike, /Library/CS/falcon, /opt/carbonblack, /opt/sentinelone, C:\Program Files\CrowdStrike, C:\Program Files\SentinelOne, C:\Program Files\CarbonBlack |
| g5 | preinstall | c13 (c13: os in [darwin, linux]) | then | 1 | self_propagation, modify_other_packages | os=linux |
| g6 | preinstall | c14 && c15 (c14: process.env.GITHUB_ACTIONS == true; c15: process.env.RUNNER_OS == Linux) | then | 2 | cred_read | env_var=GITHUB_ACTIONS=true, RUNNER_OS=Linux |
| g7 | preinstall | c18 && ((c16 && c19) \|\| (c17 && c20)) (c18: process.env.GITHUB_ACTIONS truthy; c16: process.env.WORKFLOW_ID truthy; c19: process.env.GITHUB_WORKFLOW_REF includes <value of WORKFLOW_ID>; c17: process.env.REPO_ID_SUFFIX truthy; c20: process.env.GITHUB_REPOSITORY includes <value of REPO_ID_SUFFIX>) | then | 3 | self_propagation | env_var=GITHUB_ACTIONS=true, WORKFLOW_ID=x, GITHUB_WORKFLOW_REF=x |

Gate intent: g1 evade/enables/anti_analysis; g2 activate/enables/targeting; g3 activate/enables/unclear; g4 evade/enables/anti_analysis; g5 activate/enables/targeting; g6 activate/enables/targeting; g7 activate/enables/targeting

Grounding: 0 of 20 conditions and 0 of 7 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, g1, g2, g3, g4, g5, g6, g7.

## Requirements

- network: github[.]com:443, registry[.]npmjs[.]org:443, api[.]github[.]com:443 (downloads the Bun runtime from GitHub, validates and republishes npm packages, and worms GitHub repositories)
- installed_tool: curl (getBunPath fetches the Bun release zip with curl when Bun is not already present)
- installed_tool: unzip (getBunPath extracts the downloaded Bun zip with unzip)
- installed_tool: bash, python3 (t4 pipes its installer into bash and installs a python3 service; Y6 runs its memory dump with python3)
- privilege: root_or_admin (Y6 runs its runner memory dump through sudo, so g6's payload needs working sudo on the runner)
- other: ACTIONS_ID_TOKEN_REQUEST_TOKEN, ACTIONS_ID_TOKEN_REQUEST_URL, OIDC_PACKAGES (u8.execute needs these env vars to get an OIDC token and a package list; without OIDC_PACKAGES it publishes nothing)

## Behaviour

- Ungated: write_file, download, spawn_process, exec_downloaded
- Gated: recon, cred_read, exfil, self_propagation, modify_other_packages, persistence

## Notes

- Decode chain is fully replayable from the package bytes with registered decoders: `charcode_caesar_eval` (index.js -> d7), `aesgcm_hex_stage` with `var:_p` (d7 -> d8) and `var:_b` (d7 -> d9), `obfio_scoped` (d8 -> d10), `scramble_feistel` with the key and salt literals from the file (d10 -> d11), and `aesgcm_gunzip` with `fn:n` (d11 -> d12).
- All conditions/gates are out-of-set: the extractor produced no candidates (the only prefilled sink was the top-level `eval`), so every gate is anchored by hand and flagged for review. Conditions and g4, g6, g7 cite d12; the g1 to g3 and g5 guards and payloads stay on d10.
- Repair corrected c4: it was labelled a timezone check, but the decoded code is a second locale test on LANG/LANGUAGE/LC_ALL when SystemRoot is set. The package has no timezone check.
- g1 to g3 and g4 to g7 are recorded as separate gates. g4 to g7 only run after g1 to g3 pass, and their expressions do not repeat those conditions.
- Bundled libraries (tar, sigstore, an AWS SigV4 signer, a GitHub GraphQL client) appear in d10; their `TESTING_TAR_FAKE_PLATFORM`/`__FAKE_PLATFORM__` reads are the libraries' test hooks, not package gates.
- The lock gate g3 has two ways through: `W9()` continues when the lock file is absent (c5) or when the PID in it is not alive (c6, `process.kill(pid,0)` throws), deleting the stale lock first.
- Payload witnesses: exfil stops at `this.dispatch` and persistence stops at the `_q` queue, because the sender and the queued `s4` are called through run-time lists (`cq` runs the queue after the try block). The npm republish path is traced in full through `ingest`.
- The `D6` monitor (`gh-token-monitor`) installed from `A5.augmentEnvelope` later evals `rm -rf ~/; rm -rf ~/Documents` when the stolen token stops working. That runs after the install, so it counts as persistence, not destructive. Its `/user/orgs` trigger and `SKIP_DOMAIN` in `bq` are not modelled; both are in `review_reasons`.
- Reachability: github[.]com (Bun download), registry[.]npmjs[.]org (npm token validation and republish), api[.]github[.]com (repo worming, the commit-search dead drop and the fallback exfil sender). The configured host api[.]anthropic[.]com is a decoy that is never contacted (`noop`); the real exfil host comes from the dead drop at run time and is not in the package.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@redhat-cloud-services/hcc-feo-mcp",
    "version": "0.3.1",
    "archive_sha256": "73dfde3dc5ac8f3d69e1847499f7b214ec8464f323d207d5f51355be61cde0d6",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-01",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-01-@redhat-cloud-services_hcc-feo-mcp-v0.3.1.zip",
    "package_root": "layer0/tmp/tmp_vlt9hyt/@redhat-cloud-services-hcc-feo-mcp/package",
    "cluster_key": "42e77c4cd11e7d6814910ca0688bfbbd533804b2c37eec12a0df07b80d3a7657",
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
          "dropped_binary",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): hcc-feo-mcp",
      "index.js preinstall is a 4-layer dropper: charcode+Caesar(shift 9) eval (d7) -> AES-128-GCM stages _p (d8, the worm) and _b (d9, getBunPath) -> obfuscator.io strings (d10). Repair added f4abccab2 (d11) and helper n scripts (d12).",
      "Anchors: conditions and g4, g6, g7 cite d12, where the strings are plain. g1 to g3 and g5 guards and payloads stay on d10, whose bytes are unchanged; their code holds no encoded value that the claims depend on.",
      "Wrapper (d7) writes the decrypted worm to /tmp/p<rand>.js and runs it with Bun; if Bun is absent it eval(_b) to define getBunPath, which curl-downloads Bun v1.3.13 from github.com and unzips it, then runs the worm with the dropped bun binary.",
      "Worm entry bq()->kq() runs the gates, then secret-scans, exfiltrates, validates and republishes npm packages (registry[.]npmjs[.]org) and worms GitHub repos (api[.]github[.]com, GitHub Actions workflow injection).",
      "C2: the configured host api[.]anthropic[.]com (path v1/api) is a decoy. Its config sets noop, so q5.healthy returns false before any lookup and nothing is sent there. x6.tryCreate then takes the real host from a GitHub commit search (X9, keyword thebeautifulmarchoftime).",
      "The real C2 host is only known at run time, so it is not in the package. When that dead drop fails, the E6 GitHub sender is used.",
      "KZ() CI detection + q9() daemonize: when not in CI the worm respawns itself detached (env __IS_DAEMON=1, a re-entry guard it sets for its own child) and the parent exits; the payload runs either way, so recorded as plumbing not a gate.",
      "g7 is hq(): the !unset||match tests are written as c16 with c19 and c17 with c20. On a match it runs u8.execute (npm OIDC republish, needs ACTIONS_ID_TOKEN_REQUEST_* and OIDC_PACKAGES) then exits. A repository-only match with a failed workflow match exits with no payload.",
      "Bundled third-party libraries (tar, sigstore, AWS SigV4 signer, GitHub GraphQL client) are present; their process.env.TESTING_TAR_FAKE_PLATFORM / __FAKE_PLATFORM__ platform reads are the libraries' own test hooks, not gates.",
      "f4abccab2 (class B5) is reversed with the registered scramble_feistel decoder using the key and salt literals P9 and N9 (d11). The earlier timezone label on c4 was wrong: that test is a second locale check on LANG/LANGUAGE/LC_ALL when SystemRoot is set, needle ru.",
      "c1 pairs: GITHUB_TOKEN with ghp_decoyGitHubToken, NPM_TOKEN with npm_F4k3NPMToken, ANTHROPIC_API_KEY with sk-ant-api03-fake, CIRCLE_TOKEN with fake_circle. Decoy tokens planted by Phase 2 must avoid these prefixes.",
      "g3: W9() lets the worm continue when the lock file is absent (c5) or when the PID stored in it is not alive (c6: process.kill(pid,0) throws inside mq). A stale lock is deleted and rewritten, so the two are alternatives.",
      "Exfil path: finalize -> flush -> dispatch (x8) -> sender.send. The witness stops at dispatch because the sender comes from a list built at run time. The cited POST is q5.send; when no healthy domain is found the E6 GitHub sender is used instead.",
      "npm republish: ingest -> handleNpmTokens -> R8.execute, only for harvested npm tokens that AZ accepts. updateTarball injects the worm and a preinstall hook; e1 publishes with PUT. A new x8 with no sender throws before ingest, and the catch then queues only s4 and t4.",
      "Persistence: _q queues s4 and cq runs it after the try block, so the witness stops at the queue. s4 writes the worm to ~/.config/index.js and adds a SessionStart hook to writable settings.json files whose path matches its tool-name list.",
      "g4 is t4: it writes cat.py and runs script RZ, which installs it as a kitty-monitor systemd or LaunchAgent service. cat.py polls GitHub commit search for RSA-signed commands (keyword firedalazer), so the later commands are covered by persistence.",
      "D6 (script jZ) installs gh-token-monitor as a service. It later evals the handler rm -rf ~/; rm -rf ~/Documents on an HTTP 40x from api[.]github[.]com/user, on empty registry metadata, or on a deprecated @cap-js/openapi. That runs after the install, so it is persistence, not destructive.",
      "D6 starts from A5.augmentEnvelope only when includeToken is set, which configureGit does when /user/orgs returns no orgs for the stolen token. No separate gate or payload records that path (see review_reasons).",
      "g6 is Y6: sudo python3 runs dump script CZ against Runner.Worker. Dead code: shouldRun has no callers, so x1 gates only t4 and not W6 or Y6; detectHardenRunner has no callers, so a7 and the StepSecurity bypass helpers never run."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "github[.]com:443",
        "registry[.]npmjs[.]org:443",
        "api[.]github[.]com:443"
      ],
      "reason": "downloads the Bun runtime from GitHub, validates and republishes npm packages, and worms GitHub repositories"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "getBunPath fetches the Bun release zip with curl when Bun is not already present"
    },
    {
      "axis": "installed_tool",
      "value": "unzip",
      "reason": "getBunPath extracts the downloaded Bun zip with unzip"
    },
    {
      "axis": "installed_tool",
      "value": [
        "bash",
        "python3"
      ],
      "reason": "t4 pipes its installer into bash and installs a python3 service; Y6 runs its memory dump with python3"
    },
    {
      "axis": "privilege",
      "value": "root_or_admin",
      "reason": "Y6 runs its runner memory dump through sudo, so g6's payload needs working sudo on the runner"
    },
    {
      "axis": "other",
      "value": [
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "OIDC_PACKAGES"
      ],
      "reason": "u8.execute needs these env vars to get an OIDC token and a package list; without OIDC_PACKAGES it publishes nothing"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env",
      "operator": "not_startswith",
      "value": [
        "ghp_decoyGitHubToken",
        "npm_F4k3NPMToken",
        "sk-ant-api03-fake",
        "fake_circle"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 522721,
            "end_byte": 522755,
            "node_type": "call_expression",
            "sha256": "2b00d2602a5160c0",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "locale_language",
      "api": "Intl.DateTimeFormat",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 174709,
            "end_byte": 174807,
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
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 174830,
            "end_byte": 174968,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "locale_language",
      "api": "process.env",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 174983,
            "end_byte": 175122,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567148,
            "end_byte": 567161,
            "node_type": "call_expression",
            "sha256": "0605ce420896bd18",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "<os.tmpdir()>/tmp.0987654321.lock",
        "accessor": "exists"
      }
    },
    {
      "id": "c6",
      "category": "process_list",
      "api": "process.kill",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567021,
            "end_byte": 567051,
            "node_type": "call_expression",
            "sha256": "644562847b016702",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "hardware",
      "api": "os.cpus",
      "operator": ">=",
      "value": 4,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 399396,
            "end_byte": 399421,
            "node_type": "binary_expression",
            "sha256": "d1747f5508864861",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
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
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 177581,
            "end_byte": 177601,
            "node_type": "call_expression",
            "sha256": "9d64ffc24914c8bc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
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
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 177832,
            "end_byte": 177864,
            "node_type": "call_expression",
            "sha256": "6c70363fc09e6831",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execSync",
        "target": "ps aux 2>/dev/null",
        "accessor": "stdout"
      }
    },
    {
      "id": "c10",
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
            "derived_from": "d12",
            "start_byte": 399455,
            "end_byte": 399561,
            "node_type": "binary_expression",
            "sha256": "d4174e48adfd0362",
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
      "operator": "!=",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 399483,
            "end_byte": 399521,
            "node_type": "binary_expression",
            "sha256": "40e7bb5a102680cb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
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
            "derived_from": "d12",
            "start_byte": 399455,
            "end_byte": 399561,
            "node_type": "binary_expression",
            "sha256": "d4174e48adfd0362",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "os",
      "api": "process.platform",
      "operator": "in",
      "value": [
        "darwin",
        "linux"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 186838,
            "end_byte": 186889,
            "node_type": "call_expression",
            "sha256": "fdc7b1cea49ae691",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "==",
      "value": "true",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 524267,
            "end_byte": 524305,
            "node_type": "binary_expression",
            "sha256": "40e7bb5a102680cb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c15",
      "category": "ci_marker",
      "api": "process.env.RUNNER_OS",
      "operator": "==",
      "value": "Linux",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 524328,
            "end_byte": 524362,
            "node_type": "binary_expression",
            "sha256": "66b157594c354677",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c16",
      "category": "env_var",
      "api": "process.env.WORKFLOW_ID",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567788,
            "end_byte": 567811,
            "node_type": "member_expression",
            "sha256": "5a75660b7ff8bf6a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c17",
      "category": "env_var",
      "api": "process.env.REPO_ID_SUFFIX",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567822,
            "end_byte": 567848,
            "node_type": "member_expression",
            "sha256": "0b7c6279e28e1af5",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c18",
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
            "derived_from": "d12",
            "start_byte": 567889,
            "end_byte": 567918,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c19",
      "category": "ci_marker",
      "api": "process.env.GITHUB_WORKFLOW_REF",
      "operator": "includes",
      "value": "<value of WORKFLOW_ID>",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 568012,
            "end_byte": 568046,
            "node_type": "call_expression",
            "sha256": "3d0a00844624f17a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c20",
      "category": "ci_marker",
      "api": "process.env.GITHUB_REPOSITORY",
      "operator": "includes",
      "value": "<value of REPO_ID_SUFFIX>",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 568062,
            "end_byte": 568096,
            "node_type": "call_expression",
            "sha256": "8292e0af1795984c",
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
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 573817,
            "end_byte": 573846,
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
              "derived_from": "d10",
              "start_byte": 575480,
              "end_byte": 575490,
              "node_type": "await_expression",
              "sha256": "87b65783e1ba6f0a",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "exits when GITHUB_TOKEN, NPM_TOKEN, ANTHROPIC_API_KEY or CIRCLE_TOKEN starts with its listed decoy prefix, so planted honeypot tokens never trigger the worm",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "modify_other_packages",
          "persistence"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_TOKEN",
            "NPM_TOKEN",
            "ANTHROPIC_API_KEY",
            "CIRCLE_TOKEN"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 575667,
            "end_byte": 575671,
            "node_type": "call_expression",
            "sha256": "f1db30fa13faaa02",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576923,
            "end_byte": 576935,
            "node_type": "call_expression",
            "sha256": "4b79a0b9d7b554f3",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576565,
            "end_byte": 576595,
            "node_type": "call_expression",
            "sha256": "666bcec40ddb1c8e",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577119,
            "end_byte": 577142,
            "node_type": "call_expression",
            "sha256": "8dd4f37313ea7560",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577149,
            "end_byte": 577182,
            "node_type": "call_expression",
            "sha256": "b446b386617aa5eb",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 575667,
              "end_byte": 575671,
              "node_type": "call_expression",
              "sha256": "f1db30fa13faaa02",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 576923,
              "end_byte": 576935,
              "node_type": "call_expression",
              "sha256": "4b79a0b9d7b554f3",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 561896,
              "end_byte": 562014,
              "node_type": "call_expression",
              "sha256": "2a510791b5e84f27",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577119,
                  "end_byte": 577142,
                  "node_type": "call_expression",
                  "sha256": "8dd4f37313ea7560",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200969,
                  "end_byte": 201099,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 201043,
                  "end_byte": 201058,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200623,
                  "end_byte": 200969,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200865,
                  "end_byte": 200892,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
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
              "derived_from": "d10",
              "start_byte": 190341,
              "end_byte": 190445,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191094,
                  "end_byte": 191170,
                  "node_type": "call_expression",
                  "sha256": "62248c9c69d3622a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191125,
                  "end_byte": 191169,
                  "node_type": "arrow_function",
                  "sha256": "c05330e830e0e613",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191136,
                  "end_byte": 191169,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194274,
                  "end_byte": 194489,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194413,
                  "end_byte": 194457,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 188143,
                  "end_byte": 190525,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
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
              "derived_from": "d10",
              "start_byte": 192559,
              "end_byte": 192620,
              "node_type": "call_expression",
              "sha256": "1fd6cb7e631bd0c8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191010,
                  "end_byte": 191065,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193112,
                  "end_byte": 194274,
                  "node_type": "method_definition",
                  "sha256": "2c31f5dacbd4e23b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194200,
                  "end_byte": 194227,
                  "node_type": "call_expression",
                  "sha256": "b66a7f6b71bc4ed3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193450,
                  "end_byte": 194171,
                  "node_type": "arrow_function",
                  "sha256": "96ad6a7d807646cc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194089,
                  "end_byte": 194121,
                  "node_type": "call_expression",
                  "sha256": "7f609423302a55c4",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191295,
                  "end_byte": 193112,
                  "node_type": "method_definition",
                  "sha256": "2f37adaf0d7d5939",
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
              "derived_from": "d10",
              "start_byte": 254666,
              "end_byte": 254727,
              "node_type": "call_expression",
              "sha256": "2dc2eac50ed17f62",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577149,
                  "end_byte": 577182,
                  "node_type": "call_expression",
                  "sha256": "b446b386617aa5eb",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574116,
                  "end_byte": 574842,
                  "node_type": "function_declaration",
                  "sha256": "d338e1d80694cdfb",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574803,
                  "end_byte": 574811,
                  "node_type": "new_expression",
                  "sha256": "074aa4b29c89328b",
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
      "hook": "preinstall",
      "expression": "c2 && c3 && c4",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 573846,
            "end_byte": 573886,
            "node_type": "if_statement",
            "sha256": "db9ae3271cc6fdfa",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3",
            "c4"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 575480,
              "end_byte": 575490,
              "node_type": "await_expression",
              "sha256": "87b65783e1ba6f0a",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "exits when the Intl locale or LC_ALL/LC_MESSAGES/LANGUAGE/LANG starts with ru, including a second env test on Windows (SystemRoot set); a self-exclusion that limits victims to non-Russian-locale hosts",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "modify_other_packages",
          "persistence"
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
            "derived_from": "d10",
            "start_byte": 575667,
            "end_byte": 575671,
            "node_type": "call_expression",
            "sha256": "f1db30fa13faaa02",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576923,
            "end_byte": 576935,
            "node_type": "call_expression",
            "sha256": "4b79a0b9d7b554f3",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576565,
            "end_byte": 576595,
            "node_type": "call_expression",
            "sha256": "666bcec40ddb1c8e",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577119,
            "end_byte": 577142,
            "node_type": "call_expression",
            "sha256": "8dd4f37313ea7560",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577149,
            "end_byte": 577182,
            "node_type": "call_expression",
            "sha256": "b446b386617aa5eb",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 575667,
              "end_byte": 575671,
              "node_type": "call_expression",
              "sha256": "f1db30fa13faaa02",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 576923,
              "end_byte": 576935,
              "node_type": "call_expression",
              "sha256": "4b79a0b9d7b554f3",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 561896,
              "end_byte": 562014,
              "node_type": "call_expression",
              "sha256": "2a510791b5e84f27",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577119,
                  "end_byte": 577142,
                  "node_type": "call_expression",
                  "sha256": "8dd4f37313ea7560",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200969,
                  "end_byte": 201099,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 201043,
                  "end_byte": 201058,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200623,
                  "end_byte": 200969,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200865,
                  "end_byte": 200892,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
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
              "derived_from": "d10",
              "start_byte": 190341,
              "end_byte": 190445,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191094,
                  "end_byte": 191170,
                  "node_type": "call_expression",
                  "sha256": "62248c9c69d3622a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191125,
                  "end_byte": 191169,
                  "node_type": "arrow_function",
                  "sha256": "c05330e830e0e613",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191136,
                  "end_byte": 191169,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194274,
                  "end_byte": 194489,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194413,
                  "end_byte": 194457,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 188143,
                  "end_byte": 190525,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
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
              "derived_from": "d10",
              "start_byte": 192559,
              "end_byte": 192620,
              "node_type": "call_expression",
              "sha256": "1fd6cb7e631bd0c8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191010,
                  "end_byte": 191065,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193112,
                  "end_byte": 194274,
                  "node_type": "method_definition",
                  "sha256": "2c31f5dacbd4e23b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194200,
                  "end_byte": 194227,
                  "node_type": "call_expression",
                  "sha256": "b66a7f6b71bc4ed3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193450,
                  "end_byte": 194171,
                  "node_type": "arrow_function",
                  "sha256": "96ad6a7d807646cc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194089,
                  "end_byte": 194121,
                  "node_type": "call_expression",
                  "sha256": "7f609423302a55c4",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191295,
                  "end_byte": 193112,
                  "node_type": "method_definition",
                  "sha256": "2f37adaf0d7d5939",
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
              "derived_from": "d10",
              "start_byte": 254666,
              "end_byte": 254727,
              "node_type": "call_expression",
              "sha256": "2dc2eac50ed17f62",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577149,
                  "end_byte": 577182,
                  "node_type": "call_expression",
                  "sha256": "b446b386617aa5eb",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574116,
                  "end_byte": 574842,
                  "node_type": "function_declaration",
                  "sha256": "d338e1d80694cdfb",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574803,
                  "end_byte": 574811,
                  "node_type": "new_expression",
                  "sha256": "074aa4b29c89328b",
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
      "hook": "preinstall",
      "expression": "c5 || c6",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 573943,
            "end_byte": 574115,
            "node_type": "if_statement",
            "sha256": "009bb1e7a576a48d",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 575480,
              "end_byte": 575490,
              "node_type": "await_expression",
              "sha256": "87b65783e1ba6f0a",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "single-instance lock: a PID file in the OS temp dir; the worm exits if a live instance already holds it (reinfection/concurrency guard, so Phase 2 must ensure the lock is absent)",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "modify_other_packages",
          "persistence"
        ],
        "env_recipe": {
          "file_absent": [
            "<os.tmpdir()>/tmp.0987654321.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 575667,
            "end_byte": 575671,
            "node_type": "call_expression",
            "sha256": "f1db30fa13faaa02",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576923,
            "end_byte": 576935,
            "node_type": "call_expression",
            "sha256": "4b79a0b9d7b554f3",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 576565,
            "end_byte": 576595,
            "node_type": "call_expression",
            "sha256": "666bcec40ddb1c8e",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577119,
            "end_byte": 577142,
            "node_type": "call_expression",
            "sha256": "8dd4f37313ea7560",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 577149,
            "end_byte": 577182,
            "node_type": "call_expression",
            "sha256": "b446b386617aa5eb",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 575667,
              "end_byte": 575671,
              "node_type": "call_expression",
              "sha256": "f1db30fa13faaa02",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 576923,
              "end_byte": 576935,
              "node_type": "call_expression",
              "sha256": "4b79a0b9d7b554f3",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 561896,
              "end_byte": 562014,
              "node_type": "call_expression",
              "sha256": "2a510791b5e84f27",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577119,
                  "end_byte": 577142,
                  "node_type": "call_expression",
                  "sha256": "8dd4f37313ea7560",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200969,
                  "end_byte": 201099,
                  "node_type": "method_definition",
                  "sha256": "d358723ca578c80f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 201043,
                  "end_byte": 201058,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200623,
                  "end_byte": 200969,
                  "node_type": "method_definition",
                  "sha256": "2cc4c2b4e30bc03f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200865,
                  "end_byte": 200892,
                  "node_type": "call_expression",
                  "sha256": "c3a6c641cf9331e2",
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
              "derived_from": "d10",
              "start_byte": 190341,
              "end_byte": 190445,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191094,
                  "end_byte": 191170,
                  "node_type": "call_expression",
                  "sha256": "62248c9c69d3622a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191125,
                  "end_byte": 191169,
                  "node_type": "arrow_function",
                  "sha256": "c05330e830e0e613",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191136,
                  "end_byte": 191169,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194274,
                  "end_byte": 194489,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194413,
                  "end_byte": 194457,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 188143,
                  "end_byte": 190525,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
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
              "derived_from": "d10",
              "start_byte": 192559,
              "end_byte": 192620,
              "node_type": "call_expression",
              "sha256": "1fd6cb7e631bd0c8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 576565,
                  "end_byte": 576595,
                  "node_type": "call_expression",
                  "sha256": "666bcec40ddb1c8e",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 197925,
                  "end_byte": 199175,
                  "node_type": "method_definition",
                  "sha256": "a24f775b61eedb9a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 198838,
                  "end_byte": 198895,
                  "node_type": "call_expression",
                  "sha256": "dc2fe1a817b8f5ee",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200428,
                  "end_byte": 200623,
                  "node_type": "method_definition",
                  "sha256": "69adfb970a5b012b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 200590,
                  "end_byte": 200620,
                  "node_type": "call_expression",
                  "sha256": "1ee3b0872c5e0808",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 190673,
                  "end_byte": 191295,
                  "node_type": "method_definition",
                  "sha256": "b340ec6a9c27a522",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191010,
                  "end_byte": 191065,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193112,
                  "end_byte": 194274,
                  "node_type": "method_definition",
                  "sha256": "2c31f5dacbd4e23b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194200,
                  "end_byte": 194227,
                  "node_type": "call_expression",
                  "sha256": "b66a7f6b71bc4ed3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193450,
                  "end_byte": 194171,
                  "node_type": "arrow_function",
                  "sha256": "96ad6a7d807646cc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194089,
                  "end_byte": 194121,
                  "node_type": "call_expression",
                  "sha256": "7f609423302a55c4",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191295,
                  "end_byte": 193112,
                  "node_type": "method_definition",
                  "sha256": "2f37adaf0d7d5939",
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
              "derived_from": "d10",
              "start_byte": 254666,
              "end_byte": 254727,
              "node_type": "call_expression",
              "sha256": "2dc2eac50ed17f62",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 577149,
                  "end_byte": 577182,
                  "node_type": "call_expression",
                  "sha256": "b446b386617aa5eb",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574116,
                  "end_byte": 574842,
                  "node_type": "function_declaration",
                  "sha256": "d338e1d80694cdfb",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 574803,
                  "end_byte": 574811,
                  "node_type": "new_expression",
                  "sha256": "074aa4b29c89328b",
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
      "hook": "preinstall",
      "expression": "c7 && c8 && c9 && c10 && c11 && c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 399706,
            "end_byte": 399751,
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
            "c11",
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "t4.shouldExecute backs off on fewer than 4 CPUs, on EDR paths or processes (x1) and on CI markers, so the kitty-monitor backdoor is only installed on a real developer machine",
      "then": {
        "min_conditions": 6,
        "behaviours": [
          "persistence"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "env_var_absent": [
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_HOME"
          ],
          "file_absent": [
            "/opt/CrowdStrike",
            "/Library/CS/falcon",
            "/opt/carbonblack",
            "/opt/sentinelone",
            "C:\\Program Files\\CrowdStrike",
            "C:\\Program Files\\SentinelOne",
            "C:\\Program Files\\CarbonBlack"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 399834,
            "end_byte": 399872,
            "node_type": "call_expression",
            "sha256": "150d96e650eed1a9",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 399887,
            "end_byte": 399978,
            "node_type": "call_expression",
            "sha256": "bbf5ecf8bacbd0fb",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d12",
              "start_byte": 399887,
              "end_byte": 399978,
              "node_type": "call_expression",
              "sha256": "bbf5ecf8bacbd0fb",
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
      "hook": "preinstall",
      "expression": "c13",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 190878,
            "end_byte": 191253,
            "node_type": "if_statement",
            "sha256": "301f05239d9f02c7",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c13"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "R8.execute republishes packages with a stolen npm token only on darwin or linux; on any other platform it returns without downloading or publishing",
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
            "derived_from": "d10",
            "start_byte": 191010,
            "end_byte": 191065,
            "node_type": "call_expression",
            "sha256": "c4ec66f5c6a0a259",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d10",
            "start_byte": 191094,
            "end_byte": 191170,
            "node_type": "call_expression",
            "sha256": "62248c9c69d3622a",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "self_propagation",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d10",
              "start_byte": 190341,
              "end_byte": 190445,
              "node_type": "call_expression",
              "sha256": "81265dff90bacdb4",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191094,
                  "end_byte": 191170,
                  "node_type": "call_expression",
                  "sha256": "62248c9c69d3622a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191125,
                  "end_byte": 191169,
                  "node_type": "arrow_function",
                  "sha256": "c05330e830e0e613",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191136,
                  "end_byte": 191169,
                  "node_type": "call_expression",
                  "sha256": "50b96fb1f9ac88fd",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194274,
                  "end_byte": 194489,
                  "node_type": "method_definition",
                  "sha256": "b0650cb3795c1e6f",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194413,
                  "end_byte": 194457,
                  "node_type": "call_expression",
                  "sha256": "8455820df89d6c3a",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 188143,
                  "end_byte": 190525,
                  "node_type": "function_declaration",
                  "sha256": "115ab990ff8f416e",
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
              "derived_from": "d10",
              "start_byte": 192559,
              "end_byte": 192620,
              "node_type": "call_expression",
              "sha256": "1fd6cb7e631bd0c8",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191010,
                  "end_byte": 191065,
                  "node_type": "call_expression",
                  "sha256": "c4ec66f5c6a0a259",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193112,
                  "end_byte": 194274,
                  "node_type": "method_definition",
                  "sha256": "2c31f5dacbd4e23b",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194200,
                  "end_byte": 194227,
                  "node_type": "call_expression",
                  "sha256": "b66a7f6b71bc4ed3",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 193450,
                  "end_byte": 194171,
                  "node_type": "arrow_function",
                  "sha256": "96ad6a7d807646cc",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 194089,
                  "end_byte": 194121,
                  "node_type": "call_expression",
                  "sha256": "7f609423302a55c4",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d10",
                  "start_byte": 191295,
                  "end_byte": 193112,
                  "node_type": "method_definition",
                  "sha256": "2f37adaf0d7d5939",
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
      "gate_id": "g6",
      "hook": "preinstall",
      "expression": "c14 && c15",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 525664,
            "end_byte": 525763,
            "node_type": "if_statement",
            "sha256": "b1e511154a875204",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c14",
            "c15"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Y6.execute dumps the Runner.Worker process memory for secrets only on a Linux GitHub Actions runner; anywhere else it returns a failure result",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "RUNNER_OS": "Linux"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 525875,
            "end_byte": 525895,
            "node_type": "call_expression",
            "sha256": "57b51004d0c39d8c",
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
              "start_byte": 525068,
              "end_byte": 525139,
              "node_type": "call_expression",
              "sha256": "aab0784d4bd42c41",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 525875,
                  "end_byte": 525895,
                  "node_type": "call_expression",
                  "sha256": "57b51004d0c39d8c",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 525141,
                  "end_byte": 525443,
                  "node_type": "method_definition",
                  "sha256": "85ac5ae97ee0de97",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 525335,
                  "end_byte": 525410,
                  "node_type": "call_expression",
                  "sha256": "6105c1de12bf2a71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 524963,
                  "end_byte": 525141,
                  "node_type": "method_definition",
                  "sha256": "4bd1ef01fee025ad",
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
      "gate_id": "g7",
      "hook": "preinstall",
      "expression": "c18 && ((c16 && c19) || (c17 && c20))",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567849,
            "end_byte": 567882,
            "node_type": "if_statement",
            "sha256": "ee301c8598ca0630",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c16",
            "c17"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567886,
            "end_byte": 568224,
            "node_type": "if_statement",
            "sha256": "533a97002698cfc4",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c18"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 567996,
            "end_byte": 568223,
            "node_type": "if_statement",
            "sha256": "4f9fa5b337c52d79",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c19",
            "c20"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "hq runs the u8 npm OIDC republish, then exits, only in a GitHub Actions run whose workflow ref and repository match WORKFLOW_ID and REPO_ID_SUFFIX, the variables that pick the targeted CI job",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "self_propagation"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "WORKFLOW_ID": "x",
            "GITHUB_WORKFLOW_REF": "x"
          }
        },
        "recipe_guessed_fields": [
          "env_var"
        ],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d12",
            "start_byte": 568104,
            "end_byte": 568125,
            "node_type": "call_expression",
            "sha256": "64127e3eb1b940e5",
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
              "start_byte": 397755,
              "end_byte": 397818,
              "node_type": "call_expression",
              "sha256": "af666b2eaf3ff9d9",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 568104,
                  "end_byte": 568125,
                  "node_type": "call_expression",
                  "sha256": "64127e3eb1b940e5",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 398631,
                  "end_byte": 399135,
                  "node_type": "method_definition",
                  "sha256": "4f5d80b5e7211d43",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 399066,
                  "end_byte": 399111,
                  "node_type": "call_expression",
                  "sha256": "076616191dc57314",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d12",
                  "start_byte": 396549,
                  "end_byte": 397971,
                  "node_type": "method_definition",
                  "sha256": "742d5a70c25da83b",
                  "line": 1
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
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
      "spawn_process",
      "exec_downloaded"
    ],
    "gated": [
      "recon",
      "cred_read",
      "exfil",
      "self_propagation",
      "modify_other_packages",
      "persistence"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "caesar-shifted char-code array handed to eval (outer wrapper)",
      "AES-128-GCM encrypted stages decrypted at runtime and run via Bun",
      "obfuscator.io string-array with checksum-gated rotation",
      "per-string substitution cipher f4abccab2 (class B5, key and salt in the file) over env var names and needles, reversed as d11",
      "AES-GCM and gzip embedded scripts behind helper n, reversed as d12",
      "bundled third-party libraries (tar, sigstore, AWS SigV4, GitHub GraphQL client)",
      "dynamic_eval"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "github[.]com",
        "role": "second_stage"
      },
      {
        "indicator": "registry[.]npmjs[.]org",
        "role": "c2"
      },
      {
        "indicator": "api[.]github[.]com",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "shai-hulud",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook of this compromised Red Hat npm package is a 4-layer self-decrypting dropper that writes a 634 KB worm to /tmp, downloads the Bun runtime from GitHub if needed, and runs it. The worm scans for and steals GitHub/npm/cloud credentials, exfiltrates them, republishes npm packages the stolen token can write to, and worms GitHub repos via injected Actions workflows, after locale/decoy-token/CI evasion checks. This is the Shai-Hulud npm worm.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and gates are out-of-set (no deterministic candidates were generated for this fully-obfuscated single-line file); verify them against derived files d10 and d12.",
    "g4 to g7 run only after g1 to g3 pass in kq, but their expressions do not repeat those conditions, matching how g1 to g3 are recorded separately. A reviewer should decide whether min_conditions should count the sequence.",
    "g7 over-approximates when WORKFLOW_ID and REPO_ID_SUFFIX are both set: the code needs both matches, the expression accepts either. Its smallest case (one variable set) is exact.",
    "Not modelled, for a reviewer: SKIP_DOMAIN in bq (picks the GitHub sender over the domain sender, possibly a modifies gate), and the /user/orgs result that arms the D6 monitor (server_response).",
    "After d11, the per-OS file lists read through i4 in W6 and the other collectors were not re-audited for gates; only the flagged checks and Y6 were re-read.",
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
        "output_sha256": "572052a4b93cf3d3"
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
    "conditions_out_of_set": 20,
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
