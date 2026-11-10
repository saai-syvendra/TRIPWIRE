# npm @antv/data-samples@1.2.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

This is a compromised release of the legitimate `@antv/data-samples` package. Its `preinstall` hook runs `bun run index.js` on every install (bun is pulled in as a declared dependency), and the top-level entry `IP().catch(() => process.exit(0))` launches a heavily obfuscated (obfuscator.io) payload. `IP()` first runs `YP()`, which re-spawns the process as a detached background child (`z6()`, re-entry-guarded by the `__DAEMONIZED` env var) and then applies a series of install gates before the real work runs in that child: collecting host/CI data, scanning for secrets and credentials, exfiltrating them by HTTPS POST to `t[.]m-kosche[.]com:443/api/public/otel/v1/traces` (with a GitHub-based fallback sender), and using GitHub repository access to self-propagate. The gates are a decoy-token check that exits when `GITHUB_TOKEN` starts with `ghp_decoyGitHubToken` (`N6`, anti-analysis), a locale exclusion that exits when the Intl locale, `LC_ALL`/`LC_MESSAGES`/`LANGUAGE`/`LANG`, or (when `SystemRoot` is set) `LANG`/`LANGUAGE`/`LC_ALL` starts with `ru` (`jg`, targeting), a repository exclusion that exits under GitHub Actions when `GITHUB_REPOSITORY` includes `/somerepository` (`DP`, targeting), and a pid-file single-instance lock at `%TMP%/tmp.0987654321.lock` (`f6`/`_9`). All checks must pass (and no live prior instance may hold the lock) for the payload to proceed.

## Execution

- **preinstall** `bun run index.js`: runs index.js; direct_script, detached_child; errors hidden.
- **prepare** `husky install`: runs on git or local install only; no package files; inline_shell.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g2 | preinstall | c2 (c2: file_or_dir_exists exists %TMP%/tmp.0987654321.lock) | then | 1 | delete_file | file_present=%TMP%/tmp.0987654321.lock |
| g3 | preinstall | c3 (c3: process.env.GITHUB_TOKEN not_startswith ghp_decoyGitHubToken) | then | 1 | recon, cred_read, exfil, self_propagation, spawn_process | (none) |
| g4 | preinstall | c4 && c6 && c14 (c4: locale_language not_startswith ru; c6: locale_language not_startswith ru; c14: locale_language not_startswith ru) | then | 3 | recon, cred_read, exfil, self_propagation, spawn_process | locale=en-US |
| g5 | preinstall | c15 \|\| c5 (c15: process.env.GITHUB_ACTIONS falsy; c5: process.env.GITHUB_REPOSITORY not_includes /somerepository) | then | 1 | recon, cred_read, exfil, self_propagation, spawn_process | env_var_absent=GITHUB_ACTIONS |
| g6 | preinstall | c7 && c8 && c9 (c7: process.env.GITHUB_ACTIONS truthy; c8: process.env.GITHUB_WORKFLOW_REF includes release.yml; c9: process.env.GITHUB_REPOSITORY includes /somerepository) | then | 3 | cred_read, self_propagation | env_var=GITHUB_ACTIONS=true, GITHUB_WORKFLOW_REF=release.yml, GITHUB_REPOSITORY=/somerepository |
| g7 | preinstall | c10 && c11 && c12 && c13 (c10: hardware >= 4; c11: process.env.CI != true; c12: process.env.GITHUB_ACTIONS != true; c13: process.env.JENKINS_HOME not_exists) | then | 4 | write_file, spawn_process | cpu_count=4; env_var_absent=CI, GITHUB_ACTIONS, JENKINS_HOME |

Gate intent: g2 activate/enables/unclear; g3 evade/enables/anti_analysis; g4 evade/enables/targeting; g5 evade/enables/targeting; g6 activate/enables/targeting; g7 evade/enables/anti_analysis

Grounding: 1 of 14 conditions and 1 of 6 gates from the candidate set; out of set, pending verification: c3, c4, c6, c5, c7, c8, c9, c10, c11, c12, c13, c14, c15, g3, g4, g5, g6, g7.

## Requirements

- installed_tool: bun (preinstall command is `bun run index.js`; bun is declared as a runtime dependency so the hook can execute index.js)
- network: t[.]m-kosche[.]com:443 (IP() builds a DomainSender for t[.]m-kosche[.]com port 443 path api/public/otel/v1/traces and POSTs the collected data there; with SKIP_DOMAIN=true or an unhealthy domain it falls back to a GitHub-based sender)
- other: ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN set (GitHub Actions job with id-token: write) (g6's M9.execute() fetches an OIDC id token from ACTIONS_ID_TOKEN_REQUEST_URL with ACTIONS_ID_TOKEN_REQUEST_TOKEN without checking them; without them the fetch throws and DP's catch returns)

## Behaviour

- Ungated: none
- Gated: delete_file, recon, cred_read, exfil, self_propagation, spawn_process, write_file

## Notes

- Static only; nothing was installed or run. In repair the string table was decoded with two registered derivations: d1 (`obfio_objprop`, rotation checksum matched) and d2 (`scramble_feistel` over d1, using the key and salt embedded in the file) for the `f2959c600` strings. The gate conditions, guards and the exfil path are cited in d2.
- Gate g6: inside `DP`, when `GITHUB_WORKFLOW_REF` also includes `release.yml`, `new M9().execute()` (a tarball republish class with sigstore provenance) runs before the exit. `/somerepository` looks like an unfilled template value.
- `__DAEMONIZED` (candidate c1/g1) was dropped as a `re_entry_guard`: it only prevents the detached child from re-spawning. The spawn itself is recorded as `spawn_process` + `detached_child`.
- g2 is the pid-file lock kept from the candidate set. Gates g3 (N6), g4 (jg) and g5 (DP) are added out of set: their condition functions are `reached:false` in the candidate set, but they run via `IP() -> YP()`. Their regions are the statements after `await YP()` in `IP`, and g5 reads `c15 || c5` because `DP` tests the repository only under GitHub Actions. These, the out-of-set g6 and g7, and the exfil witness (which ends in a senders array filled at run time, so it stays `unresolved: dynamic_dispatch`) are why the record stays flagged for manual review.
- The payload uses the bun runtime and GitHub Actions variables (`GITHUB_REPOSITORY`, `GITHUB_WORKFLOW_REF`); behaviour resembles a GitHub secret-stealing / self-propagating worm, but no campaign name is asserted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@antv/data-samples",
    "version": "1.2.1",
    "archive_sha256": "a9eec26852057d910e8a407b941be4be4450b76a6ae2ce85efc49a4c38b7f8cd",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-05-19-@antv_data-samples-v1.2.1.zip",
    "package_root": "layer0/tmp/tmp5z3xuj67/@antv-data-samples/package",
    "cluster_key": "ff436c411f97f5da5fe21bf281dad18cb5aa4904155d68f68748df9477867ff0",
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
      },
      {
        "hook": "prepare",
        "command": "husky install",
        "runs_on": "git_or_local_install_only",
        "file_chain": [],
        "interpreter": "other",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "prepare: runs 'husky' from a dependency or the system; its code is out of scope",
      "non-registry optionalDependencies (dependency tree): @antv/setup (github:antvis/G2#1916faa365f2788b6e193514872d51a242876569)",
      "optionalDependencies (platform picks belong to the dependency tree): @antv/setup",
      "preinstall runs index.js under the bun runtime (bun is declared as a runtime dependency); top-level entry is IP().catch(()=>process.exit(0)), which swallows every error so the install always exits 0 (silent_failure).",
      "index.js (499 KB, single line, obfuscator.io): the install payload functions (z6, GP, f6, _9, BP, DP, YP, IP, N6, jg, Sg and HTTP/collector helpers) were read in full.",
      "index.js: the surrounding obfuscated @antv library code is executed at load only as definitions and was audited via the tool sink inventory (hints.sinks) with no unexplained hits; nothing left unread.",
      "index.js: prepare.py did not recover the string table (call sites index the decoder through const-object properties); repair registered d1 (decoder obfio_objprop, rotation checksum matched).",
      "index.js: d2 (decoder scramble_feistel over d1; key e6 and salt t6 from the file, 200000 pbkdf2 iterations, 3 rounds) decodes the f2959c600 strings; gate conditions, guards and payload are cited in d2.",
      "Recovered values: decoy GITHUB_TOKEN prefix 'ghp_decoyGitHubToken'; locale exclusion 'ru' (no timezone check); DP arguments 'release.yml' and '/somerepository'; pid lock %TMP%/tmp.0987654321.lock; exfil endpoint t[.]m-kosche[.]com:443/api/public/otel/v1/traces.",
      "__DAEMONIZED (candidate c1/g1) is a re-entry guard inside z6(): z6 re-spawns the process detached with __DAEMONIZED=1 and the parent exits; dropped as re_entry_guard, captured instead as spawn_process + detached_child.",
      "YP() runs the install gates in order (N6 decoy-token, DP repo exclusion, jg locale, Sg/z6 daemonize, f6 pid-file lock) and installs no-op SIGINT/SIGTERM handlers (defense_evasion); the collect+exfil+GitHub self-propagation payload runs in the detached child once all checks pass.",
      "gates g3 (N6), g4 (jg), g5 (DP) are out of set: their condition functions are reached:false in the candidate set but run via IP()->YP().",
      "exfil witness: IP -> A9.finalize -> flush -> this.dispatch (bound to w9.dispatch) -> sender.send -> DomainSender.send fetch POST; the senders array is filled at run time (DomainSender or GitHub fallback), so it stays unresolved: dynamic_dispatch.",
      "g6 (repair): in DP, with GITHUB_ACTIONS set, GITHUB_WORKFLOW_REF including 'release.yml' and GITHUB_REPOSITORY including '/somerepository', new M9().execute() runs before the exit.",
      "M9.execute fetches an OIDC id token; downloadPackages fetches each package in uw (only 'aaaaa'), adds optionalDependencies '@sap/setup', bumps the minor version and publishes via the npm OIDC token exchange (_n).",
      "g5 (repair): DP exits only when GITHUB_ACTIONS is set and GITHUB_REPOSITORY includes '/somerepository', so continuing needs c15 || c5. The guard is the whole outer if, which holds both exit paths.",
      "If M9.execute() throws in DP, the catch returns and YP continues even with c7, c8 and c9 true; this failure path is not in g5's expression.",
      "g3/g4/g5 regions (repair) are the statements after 'await YP()' in IP's try block, the code the via calls put on the guard's side. IP's finally block is not in them.",
      "p9.tryCreate returns class au (the DomainSender holding send) when healthy, so senders[0] is au on the domain path; the GitHub senders replace or follow it at run time, so the exfil witness stays dynamic_dispatch.",
      "jg's third test (c14, repair) only reads anything when SystemRoot is set; it can differ from c6 because LANG comes first there and LC_ALL first in c6.",
      "g7 (repair): IP()'s finally block calls $g(); $g returns unless Pw() holds (>=4 CPUs, CI!='true', GITHUB_ACTIONS!='true', JENKINS_HOME unset). The module flag fg is a run-once guard, not an environment check.",
      "$g writes Bg to /tmp/kitty-*/cat.py (mode 0755) and runs 'bash -s -- cat.py' with Yg on stdin; Bg and Yg are f()-encrypted strings that were not decoded, so the script's content is not recovered.",
      "Not modelled as gates: in IP, scanned GitHub tokens pass d(token).valid (server response) before S9 is added; when none was valid, ghs_old/ghs_jwt matches each run new ku(token).execute(). Q9.execute() runs in the finally block.",
      "SKIP_DOMAIN=='true' in IP selects the GitHub sender instead of the domain sender; it changes the exfil channel, not whether exfil runs."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "bun",
      "reason": "preinstall command is `bun run index.js`; bun is declared as a runtime dependency so the hook can execute index.js"
    },
    {
      "axis": "network",
      "value": [
        "t[.]m-kosche[.]com:443"
      ],
      "reason": "IP() builds a DomainSender for t[.]m-kosche[.]com port 443 path api/public/otel/v1/traces and POSTs the collected data there; with SKIP_DOMAIN=true or an unhealthy domain it falls back to a GitHub-based sender"
    },
    {
      "axis": "other",
      "value": "ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN set (GitHub Actions job with id-token: write)",
      "reason": "g6's M9.execute() fetches an OIDC id token from ACTIONS_ID_TOKEN_REQUEST_URL with ACTIONS_ID_TOKEN_REQUEST_TOKEN without checking them; without them the fetch throws and DP's catch returns"
    }
  ],
  "conditions": [
    {
      "id": "c2",
      "category": "file_or_dir_exists",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "%TMP%/tmp.0987654321.lock",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_7360973273",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494409,
            "end_byte": 494422,
            "node_type": "call_expression",
            "sha256": "9ac46e357e994172",
            "line": 1
          }
        },
        {
          "candidate": "k_d8a35f6c4e",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494644,
            "end_byte": 494657,
            "node_type": "call_expression",
            "sha256": "9ac46e357e994172",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
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
            "derived_from": "d2",
            "start_byte": 388930,
            "end_byte": 388964,
            "node_type": "call_expression",
            "sha256": "5a468bcdb066b121",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
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
            "derived_from": "d2",
            "start_byte": 173778,
            "end_byte": 173876,
            "node_type": "call_expression",
            "sha256": "5222649a5abae458",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "locale_language",
      "api": "process.env.LC_ALL||LC_MESSAGES||LANGUAGE||LANG",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 173899,
            "end_byte": 174037,
            "node_type": "call_expression",
            "sha256": "47e991af608aed87",
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
      "operator": "not_includes",
      "value": "/somerepository",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434241,
            "end_byte": 434275,
            "node_type": "call_expression",
            "sha256": "c13490afa0b6175d",
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
      "operator": "truthy",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434003,
            "end_byte": 434032,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "ci_marker",
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
            "derived_from": "d2",
            "start_byte": 434113,
            "end_byte": 434147,
            "node_type": "call_expression",
            "sha256": "bc8e11011a13105d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
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
            "derived_from": "d2",
            "start_byte": 434149,
            "end_byte": 434183,
            "node_type": "call_expression",
            "sha256": "c13490afa0b6175d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "hardware",
      "api": "os.cpus().length",
      "operator": ">=",
      "value": 4,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 242736,
            "end_byte": 242761,
            "node_type": "binary_expression",
            "sha256": "ab43fe157de3ab2b",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
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
            "derived_from": "d2",
            "start_byte": 242776,
            "end_byte": 242802,
            "node_type": "binary_expression",
            "sha256": "a1e133353ca470cc",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
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
            "derived_from": "d2",
            "start_byte": 242804,
            "end_byte": 242842,
            "node_type": "binary_expression",
            "sha256": "40e7bb5a102680cb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
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
            "derived_from": "d2",
            "start_byte": 242844,
            "end_byte": 242882,
            "node_type": "binary_expression",
            "sha256": "60afb22bc3c52114",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c14",
      "category": "locale_language",
      "api": "process.env.SystemRoot?process.env.LANG||LANGUAGE||LC_ALL",
      "operator": "not_startswith",
      "value": "ru",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 174052,
            "end_byte": 174191,
            "node_type": "call_expression",
            "sha256": "3c94fd068061623d",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c15",
      "category": "ci_marker",
      "api": "process.env.GITHUB_ACTIONS",
      "operator": "falsy",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434003,
            "end_byte": 434032,
            "node_type": "subscript_expression",
            "sha256": "f7c694e204eaed8a",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c2",
      "guards": [
        {
          "candidate": "q_a503be1583",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494406,
            "end_byte": 494526,
            "node_type": "if_statement",
            "sha256": "22def24b67717976",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": "q_ccad5d9036",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494641,
            "end_byte": 494672,
            "node_type": "if_statement",
            "sha256": "93da865ef1b9fa01",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "single-instance / reinfection lock: f6() checks a pid file in the OS temp dir, keeps it only if the recorded process is still alive (process.kill(pid,0)) and otherwise deletes the stale file; _9() removes it on exit. Phase 2 must ensure the lock file is absent so the payload runs.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "delete_file"
        ],
        "env_recipe": {
          "file_present": [
            "%TMP%/tmp.0987654321.lock"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494423,
            "end_byte": 494526,
            "node_type": "statement_block",
            "sha256": "8447608d4a19e69b",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 494658,
            "end_byte": 494672,
            "node_type": "expression_statement",
            "sha256": "c8fd819277ec834c",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 494511,
              "end_byte": 494524,
              "node_type": "call_expression",
              "sha256": "b3abc27ee6fce850",
              "line": 1
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "preinstall",
      "expression": "c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434416,
            "end_byte": 434445,
            "node_type": "if_statement",
            "sha256": "b4cf7e9bb00709ff",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 434965,
              "end_byte": 434969,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "N6() returns true (and YP() calls process.exit(0)) when GITHUB_TOKEN starts with the decoy prefix 'ghp_decoyGitHubToken' (the only uP entry), a honeytoken check to back off inside analysis sandboxes.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434970,
            "end_byte": 435106,
            "node_type": "lexical_declaration",
            "sha256": "a41b5357dc215bc7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435106,
            "end_byte": 435347,
            "node_type": "for_in_statement",
            "sha256": "8c70b7523785b0cb",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435347,
            "end_byte": 435426,
            "node_type": "lexical_declaration",
            "sha256": "e5f56f59f62b3350",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435426,
            "end_byte": 435552,
            "node_type": "if_statement",
            "sha256": "dc9565fed506c7b5",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435552,
            "end_byte": 435578,
            "node_type": "lexical_declaration",
            "sha256": "85f53a65c40a1b58",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435578,
            "end_byte": 435860,
            "node_type": "if_statement",
            "sha256": "4e012d8154474527",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435860,
            "end_byte": 436004,
            "node_type": "lexical_declaration",
            "sha256": "8b5a300ef0f4e43f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436004,
            "end_byte": 436066,
            "node_type": "for_in_statement",
            "sha256": "3da3fabfa82bd056",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436066,
            "end_byte": 436171,
            "node_type": "lexical_declaration",
            "sha256": "611f624a028b7636",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436171,
            "end_byte": 436457,
            "node_type": "for_in_statement",
            "sha256": "8f822da71b7d8d60",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436457,
            "end_byte": 436897,
            "node_type": "if_statement",
            "sha256": "7fefd95b8e8591af",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 423992,
              "end_byte": 424110,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 436571,
                  "end_byte": 436594,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435969,
                  "end_byte": 436001,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435882,
                  "end_byte": 435901,
                  "node_type": "pair",
                  "sha256": "faa8693963f2575d",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 423756,
                  "end_byte": 424224,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
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
      "expression": "c4 && c6 && c14",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434445,
            "end_byte": 434516,
            "node_type": "if_statement",
            "sha256": "6f209f58a61aefe9",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c6",
            "c14"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 434965,
              "end_byte": 434969,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "jg() returns true (and YP() calls process.exit(0)) when the Intl locale (c4), or LC_ALL/LC_MESSAGES/LANGUAGE/LANG (c6, lower-cased), starts with 'ru', or, when SystemRoot is set, LANG/LANGUAGE/LC_ALL in that order does (c14, which reads a different first variable than c6); there is no timezone check. Machines with a Russian locale are skipped.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {
          "locale": "en-US"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434970,
            "end_byte": 435106,
            "node_type": "lexical_declaration",
            "sha256": "a41b5357dc215bc7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435106,
            "end_byte": 435347,
            "node_type": "for_in_statement",
            "sha256": "8c70b7523785b0cb",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435347,
            "end_byte": 435426,
            "node_type": "lexical_declaration",
            "sha256": "e5f56f59f62b3350",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435426,
            "end_byte": 435552,
            "node_type": "if_statement",
            "sha256": "dc9565fed506c7b5",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435552,
            "end_byte": 435578,
            "node_type": "lexical_declaration",
            "sha256": "85f53a65c40a1b58",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435578,
            "end_byte": 435860,
            "node_type": "if_statement",
            "sha256": "4e012d8154474527",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435860,
            "end_byte": 436004,
            "node_type": "lexical_declaration",
            "sha256": "8b5a300ef0f4e43f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436004,
            "end_byte": 436066,
            "node_type": "for_in_statement",
            "sha256": "3da3fabfa82bd056",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436066,
            "end_byte": 436171,
            "node_type": "lexical_declaration",
            "sha256": "611f624a028b7636",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436171,
            "end_byte": 436457,
            "node_type": "for_in_statement",
            "sha256": "8f822da71b7d8d60",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436457,
            "end_byte": 436897,
            "node_type": "if_statement",
            "sha256": "7fefd95b8e8591af",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 423992,
              "end_byte": 424110,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 436571,
                  "end_byte": 436594,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435969,
                  "end_byte": 436001,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435882,
                  "end_byte": 435901,
                  "node_type": "pair",
                  "sha256": "faa8693963f2575d",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 423756,
                  "end_byte": 424224,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
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
      "gate_id": "g5",
      "hook": "preinstall",
      "expression": "c15 || c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434000,
            "end_byte": 434299,
            "node_type": "if_statement",
            "sha256": "3ae87079c8d57951",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c15",
            "c5"
          ],
          "via": [
            {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 434454,
              "end_byte": 434489,
              "node_type": "call_expression",
              "sha256": "13c9e55fcb9601a3",
              "line": 1
            },
            {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 434965,
              "end_byte": 434969,
              "node_type": "call_expression",
              "sha256": "04fb860ab07de527",
              "line": 1
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "DP('release.yml','/somerepository') acts only when GITHUB_ACTIONS is set; it then calls process.exit(0) whenever GITHUB_REPOSITORY includes '/somerepository' (first running the M9 tarball-republish class when GITHUB_WORKFLOW_REF also includes 'release.yml'), so that repository's CI runs skip the main payload. The payload continues when GITHUB_ACTIONS is unset (c15) or the repository does not match (c5).",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "self_propagation",
          "spawn_process"
        ],
        "env_recipe": {
          "env_var_absent": [
            "GITHUB_ACTIONS"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434970,
            "end_byte": 435106,
            "node_type": "lexical_declaration",
            "sha256": "a41b5357dc215bc7",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435106,
            "end_byte": 435347,
            "node_type": "for_in_statement",
            "sha256": "8c70b7523785b0cb",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435347,
            "end_byte": 435426,
            "node_type": "lexical_declaration",
            "sha256": "e5f56f59f62b3350",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435426,
            "end_byte": 435552,
            "node_type": "if_statement",
            "sha256": "dc9565fed506c7b5",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435552,
            "end_byte": 435578,
            "node_type": "lexical_declaration",
            "sha256": "85f53a65c40a1b58",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435578,
            "end_byte": 435860,
            "node_type": "if_statement",
            "sha256": "4e012d8154474527",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 435860,
            "end_byte": 436004,
            "node_type": "lexical_declaration",
            "sha256": "8b5a300ef0f4e43f",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436004,
            "end_byte": 436066,
            "node_type": "for_in_statement",
            "sha256": "3da3fabfa82bd056",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436066,
            "end_byte": 436171,
            "node_type": "lexical_declaration",
            "sha256": "611f624a028b7636",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436171,
            "end_byte": 436457,
            "node_type": "for_in_statement",
            "sha256": "8f822da71b7d8d60",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 436457,
            "end_byte": 436897,
            "node_type": "if_statement",
            "sha256": "7fefd95b8e8591af",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 423992,
              "end_byte": 424110,
              "node_type": "call_expression",
              "sha256": "640aabab0108bc1c",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 436571,
                  "end_byte": 436594,
                  "node_type": "call_expression",
                  "sha256": "bda9aafd61546f71",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188958,
                  "end_byte": 189104,
                  "node_type": "method_definition",
                  "sha256": "f24db54e29d53b84",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189048,
                  "end_byte": 189063,
                  "node_type": "call_expression",
                  "sha256": "88eeb538f412a97b",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188596,
                  "end_byte": 188958,
                  "node_type": "method_definition",
                  "sha256": "e731cb5805aeea7e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435969,
                  "end_byte": 436001,
                  "node_type": "pair",
                  "sha256": "94e14041643833a1",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 188854,
                  "end_byte": 188881,
                  "node_type": "call_expression",
                  "sha256": "b0774e574dabec09",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 189916,
                  "end_byte": 190677,
                  "node_type": "arrow_function",
                  "sha256": "b0455d4c5fd21cdf",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 435882,
                  "end_byte": 435901,
                  "node_type": "pair",
                  "sha256": "faa8693963f2575d",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 190547,
                  "end_byte": 190575,
                  "node_type": "call_expression",
                  "sha256": "3ac901a83a2bf3ae",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 423756,
                  "end_byte": 424224,
                  "node_type": "method_definition",
                  "sha256": "6a41f603f4292667",
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
      "gate_id": "g6",
      "hook": "preinstall",
      "expression": "c7 && c8 && c9",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434000,
            "end_byte": 434299,
            "node_type": "if_statement",
            "sha256": "3ae87079c8d57951",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434110,
            "end_byte": 434298,
            "node_type": "if_statement",
            "sha256": "220098f1f36cef9a",
            "line": 1
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8",
            "c9"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "DP('release.yml','/somerepository') runs new M9().execute() only inside GitHub Actions (GITHUB_ACTIONS set) when GITHUB_WORKFLOW_REF includes 'release.yml' and GITHUB_REPOSITORY includes '/somerepository': it requests a GitHub OIDC id token for npm and republishes packages through npm trusted publishing, then exits.",
      "then": {
        "behaviours": [
          "cred_read",
          "self_propagation"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKFLOW_REF": "release.yml",
            "GITHUB_REPOSITORY": "/somerepository"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 434184,
            "end_byte": 434233,
            "node_type": "expression_statement",
            "sha256": "e9e68f1610716c98",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 242244,
              "end_byte": 242345,
              "node_type": "call_expression",
              "sha256": "481d459fc5643e42",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 434190,
                  "end_byte": 434211,
                  "node_type": "call_expression",
                  "sha256": "e757d093015924bb",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 242041,
                  "end_byte": 242477,
                  "node_type": "method_definition",
                  "sha256": "da8701de45ccfe3a",
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
              "derived_from": "d2",
              "start_byte": 241916,
              "end_byte": 241954,
              "node_type": "call_expression",
              "sha256": "114b2c413146d4a3",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 434190,
                  "end_byte": 434211,
                  "node_type": "call_expression",
                  "sha256": "e757d093015924bb",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 242041,
                  "end_byte": 242477,
                  "node_type": "method_definition",
                  "sha256": "da8701de45ccfe3a",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 242416,
                  "end_byte": 242454,
                  "node_type": "call_expression",
                  "sha256": "6859a892acbf0e07",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 239879,
                  "end_byte": 241381,
                  "node_type": "method_definition",
                  "sha256": "78ac31644a5d26db",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 240329,
                  "end_byte": 241278,
                  "node_type": "variable_declarator",
                  "sha256": "a547912d7d220cf9",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 240339,
                  "end_byte": 241278,
                  "node_type": "arrow_function",
                  "sha256": "9190269bbe8fc222",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 241165,
                  "end_byte": 241228,
                  "node_type": "call_expression",
                  "sha256": "21bbcdadc88574ea",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "index.js",
                  "derived_from": "d2",
                  "start_byte": 241381,
                  "end_byte": 242041,
                  "node_type": "method_definition",
                  "sha256": "ef871ac6075717e2",
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
      "gate_id": "g7",
      "hook": "preinstall",
      "expression": "c10 && c11 && c12 && c13",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 243028,
            "end_byte": 243044,
            "node_type": "if_statement",
            "sha256": "6ca019ce8a326442",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c10",
            "c11",
            "c12",
            "c13"
          ]
        }
      ],
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "$g() (called in IP()'s finally block once YP() has let the run through) returns unless Pw() holds: at least 4 CPUs and none of CI=='true', GITHUB_ACTIONS=='true' or JENKINS_HOME set; it skips CI runners and small sandbox machines before dropping and running its script.",
      "then": {
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "cpu_count": 4,
          "env_var_absent": [
            "CI",
            "GITHUB_ACTIONS",
            "JENKINS_HOME"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 243044,
            "end_byte": 243123,
            "node_type": "lexical_declaration",
            "sha256": "32a64737096c2d24",
            "line": 1
          },
          {
            "file": "index.js",
            "derived_from": "d2",
            "start_byte": 243123,
            "end_byte": 243468,
            "node_type": "try_statement",
            "sha256": "5375881336d1590c",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 243127,
              "end_byte": 243165,
              "node_type": "call_expression",
              "sha256": "4c54a6b9a2716d81",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": "d2",
              "start_byte": 243180,
              "end_byte": 243271,
              "node_type": "call_expression",
              "sha256": "cb15028c9605d5c4",
              "line": 1
            },
            "witness": []
          }
        ],
        "min_conditions": 4
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "delete_file",
      "recon",
      "cred_read",
      "exfil",
      "self_propagation",
      "spawn_process",
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "obfuscator.io string-array with base64 + URI decoder",
      "secondary per-string decoder helper (f2959c600)",
      "hexadecimal identifiers",
      "bracket-member property access through the decoder",
      "very long single line",
      "escaped / encoded string literals",
      "bespoke per-string substitution cipher behind globalThis.f2959c600 (pbkdf2 key schedule, sha256-seeded S-boxes)"
    ],
    "decoded": true,
    "unrecovered": [
      {
        "file": "index.js",
        "reason": "Bg (cat.py body) and Yg (bash stdin) used by $g are f()-encrypted strings with no registered decoder"
      }
    ]
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://t[.]m-kosche[.]com:443/api/public/otel/v1/traces",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs an obfuscated payload under bun that re-spawns itself as a detached background process, takes a pid-file lock, and after region/decoy-token/repository evasion checks collects host and CI data, scans for secrets and credentials, exfiltrates them to a remote HTTPS host, and uses GitHub repository access to self-propagate. This is a compromised release of the legitimate @antv/data-samples package; the install code is unambiguously malicious.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set gates g3/g4/g5 and conditions c3/c4/c5/c6 (condition functions reached:false in the candidate set, added via the IP()->YP() flow)",
    "exfil witness ends in a run-time senders array (DomainSender or GitHub fallback), kept as unresolved dynamic_dispatch",
    "out-of-set gates g6 (DP's M9 republish branch) and g7 (Pw() before $g()) and conditions c7 to c15, added in repair",
    "cat.py content (Bg) and its stdin script (Yg) written and run by $g are f()-encrypted strings that were not decoded",
    "token-dependent branches in IP (S9 after d(token).valid, ku for ghs_old/ghs_jwt tokens) are not modelled as gates",
    "out-of-set claim pending verification",
    "payload path not fully traced",
    "unrecovered code"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
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
        "output_sha256": "4e6e99960f741939"
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d1"
        },
        "params": {
          "key": "a8269c01069452afb8a54de904e6419578d155fdbdb9e566bab8576a4266b61e",
          "salt": "7f44e4ba6f6a71bd0f789e7f83bd3104",
          "fn": "f2959c600",
          "decoder": "scramble_feistel",
          "lang": "js"
        },
        "output_sha256": "99cf81e2b43f88a7"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "802e30935ed6dc53"
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
        "candidate": "k_c3d4066646",
        "reason_code": "re_entry_guard",
        "note": "process.env.__DAEMONIZED test inside z6(); re-entry guard for the detached child z6 spawns with __DAEMONIZED=1",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493488,
          "end_byte": 493512,
          "node_type": "member_expression",
          "sha256": "08e4ec2c1b30613e",
          "line": 1
        }
      },
      {
        "candidate": "q_13b92544b9",
        "reason_code": "re_entry_guard",
        "note": "if(process.env.__DAEMONIZED)return in z6(); guards only the daemonize re-spawn, not an environment gate",
        "anchor": {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 493485,
          "end_byte": 493524,
          "node_type": "if_statement",
          "sha256": "5c2fbc3955369d6c",
          "line": 1
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 2,
    "conditions_in_set": 1,
    "conditions_out_of_set": 13,
    "guard_candidates": 8,
    "gates_in_set": 1,
    "gates_out_of_set": 5,
    "out_of_set_ids": [
      "c3",
      "c4",
      "c6",
      "c5",
      "c7",
      "c8",
      "c9",
      "c10",
      "c11",
      "c12",
      "c13",
      "c14",
      "c15",
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
