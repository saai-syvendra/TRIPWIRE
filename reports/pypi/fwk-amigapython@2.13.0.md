# pypi fwk-amigapython@2.13.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`fwk-amigapython` is a PyPI sdist that disguises a targeted credential-stealer and command beacon as an "Amiga Python framework" telemetry component. At install, the `cmdclass` install/develop overrides call `_register()`, which imports `amigapython._internal` only when a CI marker is set; that import runs `_bootstrap()`, which (unless `AMIGA_TELEMETRY` is disabled, and only in CI) starts a daemon thread that sleeps 1.5-6.0s then runs `collect_environment_context()` and `submit_metrics()`. The payload only activates inside an Inditex CI/build pipeline, detected by hostname (`icr-`+`sca`), `GITHUB_REPOSITORY` owner `inditex`, an `inditex.jfrog.io` package proxy, the `/opt/icr/hooks` directory, a specific `DP_TOKEN`, or a `RUNNER_NAME` starting `icr-inditex`. When those gates open it harvests CI/cloud secrets (GitHub/AWS/Azure/GCP/Vault/npm/maven tokens, the k8s service-account token, docker config), mints OIDC tokens, and exfiltrates everything to the hard-coded C2 `77.91.65[.]24:443` over TLS-verification-disabled HTTPS, then runs a beacon loop that executes arbitrary shell commands returned by the server. There is no ungated behaviour.

## Execution

- **cmdclass** `cmdclass[install] = PostInstallCommand`: 8-file chain; direct_script; errors hidden.
- **cmdclass** `cmdclass[develop] = PostDevelopCommand`: 8-file chain; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c12 (c12: os.environ.get('AMIGA_TELEMETRY') not_in [false, 0, no]) | then | 1 | recon, cred_read, exfil, reverse_shell | env_var_absent=AMIGA_TELEMETRY |
| g2 | cmdclass | (c1 \|\| c2 \|\| c3 \|\| c13) && (c1 \|\| c2 \|\| c3 \|\| c4) && ((c5 && c6) \|\| c7 \|\| c8 \|\| c9 \|\| c10 \|\| c11) (c1: os.environ.get('GITHUB_ACTIONS') truthy; c2: os.environ.get('JENKINS_URL') truthy; c3: os.environ.get('BUILD_BUILDID') truthy; c13: os.environ.get('CI') truthy; c4: os.environ.get('GITLAB_CI') truthy; c5: hostname startswith icr-; c6: hostname includes sca; c7: file_or_dir_exists exists /opt/icr/hooks; c8: os.environ.get('GITHUB_REPOSITORY') == inditex; c9: os.environ.get includes inditex.jfrog.io; c10: os.environ.get('DP_TOKEN') includes reftkn:01:1795796587; c11: os.environ.get('RUNNER_NAME') startswith icr-inditex) | then | 2 | recon, cred_read, exfil, reverse_shell | env_var=GITHUB_ACTIONS=(set); file_present=/opt/icr/hooks; ci=github |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/targeting

Grounding: 4 of 13 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c1, c2, c3, c8, c9, c10, c11, c12, c13, g1, g2.

## Requirements

- network: 77.91.65[.]24:443 (C2 endpoint for checkin, credential/OIDC exfil and the command beacon; TLS verification is disabled for it)
- installed_tool: sh (beacon executes C2 directives via subprocess.run(shell=True))

## Behaviour

- Ungated: none
- Gated: recon, cred_read, exfil, reverse_shell

## Notes

- Gates recorded: g1 = `AMIGA_TELEMETRY` kill-switch (activate, purpose unclear); g2 = CI + Inditex-scope targeting gate (activate), expression `(c1||c2||c3||c13) && (c1||c2||c3||c4) && ((c5&&c6)||c7||c8||c9||c10||c11)`. g2 carries four guards across three frames: `_register`'s early return guards the import, `collect_environment_context`'s two early returns (provider, scope) guard the recon/cred_read/OIDC region, and `_deferred_init`'s `if ctx:` (ctx truthy only when those passed) guards the `submit_metrics` call whose downstream sinks are the checkin-exfil and directive-exec.
- CI is checked three times with different marker sets (`_register`, `_bootstrap`, `_ci_provider`). End-to-end a marker in {GITHUB_ACTIONS, JENKINS_URL, BUILD_BUILDID} is enough, and so is CI together with GITLAB_CI; bare CI or GITLAB_CI alone is not. `_bootstrap`'s test always passes once `_register`'s has, so it is not a g2 guard; see execution.notes.
- `submit_metrics` returns when the C2 gives no session id (empty or `-`), so credential exfil and the beacon depend on that reply. It is not recorded as a `server_response` gate and is left for a reviewer; see review_reasons.
- The extractor mis-modelled the `_ci_provider` and `_validate_framework_scope` helper `if ... return` statements as nested early-exit gates (prefilled g1-g6). Those six q_ guards are dropped (they compute helper results, not the payload gate); the real guards are `_register`'s and `collect`'s early returns and `_deferred_init`'s `if ctx:`. All seven k_ condition sites are kept; c8-c13, the setup.py sites of c1-c3 and every guard are out of set, so the record forces manual review.
- C2 host `77.91.65[.]24:443` and the `X-B` service header (redacted `sL5x...`) are built from `chr()` code-point lists in transport.py. TLS verification is disabled (`check_hostname=False`, `CERT_NONE`). No on-disk persistence; both beacon/collection threads are daemons that die with the install process.
- All files (setup.py, `amigapython/__init__.py`, config.py, lifecycle.py, logging.py, `_internal/__init__.py`, resolver.py, transport.py) are package code, read in full; nothing bundled or unrecovered.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "fwk-amigapython",
    "version": "2.13.0",
    "archive_sha256": "f8ed3b1f670e46d17d48bb53ccbc5d708c2aa3f7165c85c1d25488eaf2d764d7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/fwk_amigapython-2.13.0.tar.gz",
    "package_root": "layer0/fwk_amigapython-2.13.0",
    "cluster_key": "23b1a87abd20f45c67f8d9b0a59e149908cac684d975d54927abe67e5bd770e4",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "amigapython/__init__.py",
          "amigapython/config.py",
          "amigapython/lifecycle.py",
          "amigapython/logging.py",
          "amigapython/_internal/__init__.py",
          "amigapython/_internal/resolver.py",
          "amigapython/_internal/transport.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "cmdclass",
        "command": "cmdclass[develop] = PostDevelopCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "amigapython/__init__.py",
          "amigapython/config.py",
          "amigapython/lifecycle.py",
          "amigapython/logging.py",
          "amigapython/_internal/__init__.py",
          "amigapython/_internal/resolver.py",
          "amigapython/_internal/transport.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [
      {
        "site": "amigapython/_internal/__init__.py:46",
        "seconds": 6.0,
        "purpose": "random.uniform(1.5, 6.0)s sleep in _deferred_init before telemetry/payload runs"
      }
    ],
    "notes": [
      "Payload is reached only through the cmdclass install/develop overrides: PostInstall/PostDevelop.run calls _register(), which imports amigapython._internal only if a CI marker (CI/GITHUB_ACTIONS/JENKINS_URL/BUILD_BUILDID) is set; that import runs __init__._bootstrap() at module top level.",
      "The setup_py hook (top-level setup.py) only defines the command classes and calls setup(); it does not import the package, so it reaches no payload. file_chain for that entry trimmed to setup.py.",
      "develop (PostDevelopCommand) runs only on legacy editable installs (pip install -e / setup.py develop); install (PostInstallCommand) is the normal sdist-install vector. Both kept as runs_on always.",
      "_bootstrap starts daemon thread _deferred_init only if AMIGA_TELEMETRY is not false/0/no and one of 6 CI markers is set; the thread sleeps 1.5-6.0s then runs collect_environment_context() and submit_metrics().",
      "CI is tested at 3 sites with different marker sets. g2 carries two: _register (c1, c2, c3, c13) and _ci_provider (c1-c4). A marker in {GITHUB_ACTIONS,JENKINS_URL,BUILD_BUILDID}, or CI together with GITLAB_CI, opens both; bare CI or GITLAB_CI alone does not.",
      "_bootstrap's own CI test (__init__.py:27) is not a g2 guard: all four _register markers are in its list, so on the install path it always passes. SYSTEM_TEAMFOUNDATIONSERVERURI there opens nothing alone, since _register and _ci_provider do not accept it.",
      "g1 keeps expression c12: it records the kill switch alone and is not widened with the CI and scope conditions. The payload behind it also needs g2 to open.",
      "setup.py's `import amigapython._internal` first runs amigapython/__init__.py, which imports config.py, lifecycle.py and logging.py. All four were read in full: they only define classes and functions, with no gate or sink at import.",
      "Server response not recorded as a gate: submit_metrics returns when _do_checkin yields no sid (empty or '-', transport.py:92, 169), so credential exfil (_submit_result, transport.py:110) and the beacon need the C2 to accept the checkin. The cited exfil sink (checkin) sends host, user and OS only.",
      "g2 spans three guard regions: _register's early return guards the import, the collect_environment_context early-returns (provider + scope) guard recon/cred_read/OIDC, and the _deferred_init `if ctx:` check guards the checkin-exfil and directive-exec sinks in submit_metrics.",
      "Inditex-scope (g2 second group) is ANY of: hostname icr-*sca* (c5&&c6); /opt/icr/hooks dir (c7); GITHUB_REPOSITORY owner inditex (c8); a *_PROXY/INDEX var contains inditex.jfrog.io (c9); DP_TOKEN decodes to contain reftkn:01:1795796587 (c10); RUNNER_NAME icr-inditex (c11).",
      "transport disables TLS verification for all C2 calls (ssl check_hostname=False, CERT_NONE). The C2 endpoint 77.91.65[.]24:443 and the X-B service header are built at runtime from chr() code-point lists (_EP_SEGMENTS, _SVC_HDR).",
      "Misleading text: module docstrings and identifiers describe anonymous usage metrics / telemetry, contradicted by the code, which harvests CI and cloud credentials, reads secret files, mints and exfiltrates OIDC tokens, and executes remote shell commands.",
      "submit_metrics also starts a second daemon thread _beacon_loop that polls /b/q and runs returned shell commands via subprocess.run(shell=True), sending output back. Both threads are daemons and end when the install process exits; no on-disk persistence is written.",
      "Witnesses cross two thread hand-offs: threading.Thread(target=...) then .start() at __init__.py:31-36 and transport.py:173-177. The targets are literal names and the code confirms both hops on re-reading; the deterministic checker does not follow a library constructor."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "77.91.65[.]24:443"
      ],
      "reason": "C2 endpoint for checkin, credential/OIDC exfil and the command beacon; TLS verification is disabled for it"
    },
    {
      "axis": "installed_tool",
      "value": "sh",
      "reason": "beacon executes C2 directives via subprocess.run(shell=True)"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "ci_marker",
      "api": "os.environ.get('GITHUB_ACTIONS')",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_099850967e",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 1984,
            "end_byte": 2016,
            "node_type": "call",
            "sha256": "d21cf314d3ed977b",
            "line": 64
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 585,
            "end_byte": 602,
            "node_type": "call",
            "sha256": "d7714f95df429e89",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "ci_marker",
      "api": "os.environ.get('JENKINS_URL')",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_3b34e932cb",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 2049,
            "end_byte": 2078,
            "node_type": "call",
            "sha256": "5979cb1364fe4673",
            "line": 66
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 585,
            "end_byte": 602,
            "node_type": "call",
            "sha256": "d7714f95df429e89",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "ci_marker",
      "api": "os.environ.get('BUILD_BUILDID')",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_4419e7851d",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 2112,
            "end_byte": 2143,
            "node_type": "call",
            "sha256": "07c37bf2ff9e614c",
            "line": 68
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 585,
            "end_byte": 602,
            "node_type": "call",
            "sha256": "d7714f95df429e89",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "ci_marker",
      "api": "os.environ.get('GITLAB_CI')",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_275e4a23bf",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 2174,
            "end_byte": 2201,
            "node_type": "call",
            "sha256": "418b0ca6071d53f1",
            "line": 70
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "hostname",
      "api": "platform.node()",
      "operator": "startswith",
      "value": "icr-",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_82455e027b",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 4793,
            "end_byte": 4816,
            "node_type": "call",
            "sha256": "afc73603de5c1fdb",
            "line": 156
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "hostname",
      "api": "platform.node()",
      "operator": "includes",
      "value": "sca",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_4ebd5c2a7f",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 4821,
            "end_byte": 4834,
            "node_type": "comparison_operator",
            "sha256": "6eaf57f7fac23315",
            "line": 156
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c7",
      "category": "file_or_dir_exists",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "/opt/icr/hooks",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1f6de125c7",
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5209,
            "end_byte": 5240,
            "node_type": "call",
            "sha256": "406f4b1108848f99",
            "line": 167
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c8",
      "category": "env_var",
      "api": "os.environ.get('GITHUB_REPOSITORY')",
      "operator": "==",
      "value": "inditex",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 4981,
            "end_byte": 4999,
            "node_type": "comparison_operator",
            "sha256": "4054ec69b385ff5f",
            "line": 161
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "env_var",
      "api": "os.environ.get",
      "operator": "includes",
      "value": "inditex.jfrog.io",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5151,
            "end_byte": 5176,
            "node_type": "comparison_operator",
            "sha256": "b6c68d1e97ac842a",
            "line": 165
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "env_var",
      "api": "os.environ.get('DP_TOKEN')",
      "operator": "includes",
      "value": "reftkn:01:1795796587",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5423,
            "end_byte": 5456,
            "node_type": "comparison_operator",
            "sha256": "7b7b470dfd0b7117",
            "line": 173
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "env_var",
      "api": "os.environ.get('RUNNER_NAME')",
      "operator": "startswith",
      "value": "icr-inditex",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5571,
            "end_byte": 5603,
            "node_type": "call",
            "sha256": "b5ba06d371aa0ad7",
            "line": 178
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "env_var",
      "api": "os.environ.get('AMIGA_TELEMETRY')",
      "operator": "not_in",
      "value": [
        "false",
        "0",
        "no"
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "amigapython/_internal/__init__.py",
            "derived_from": null,
            "start_byte": 556,
            "end_byte": 629,
            "node_type": "comparison_operator",
            "sha256": "23d749ea8b5eaa03",
            "line": 20
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c13",
      "category": "ci_marker",
      "api": "os.environ.get('CI')",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 585,
            "end_byte": 602,
            "node_type": "call",
            "sha256": "d7714f95df429e89",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "cmdclass",
      "expression": "c12",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "amigapython/_internal/__init__.py",
            "derived_from": null,
            "start_byte": 553,
            "end_byte": 645,
            "node_type": "if_statement",
            "sha256": "a8deb4b7470c922f",
            "line": 20
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "AMIGA_TELEMETRY=false/0/no is a documented user opt-out (module docstring) that suppresses the whole payload; the payload runs by default and the check does not detect analysis, CI or a sandbox",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "reverse_shell"
        ],
        "env_recipe": {
          "env_var_absent": [
            "AMIGA_TELEMETRY"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "amigapython/_internal/__init__.py",
            "derived_from": null,
            "start_byte": 868,
            "end_byte": 1073,
            "node_type": "try_statement",
            "sha256": "36f971304c36578f",
            "line": 30
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "amigapython/_internal/transport.py",
              "derived_from": null,
              "start_byte": 2694,
              "end_byte": 2746,
              "node_type": "call",
              "sha256": "2e0e9c1c164015ce",
              "line": 90
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 890,
                  "end_byte": 1015,
                  "node_type": "call",
                  "sha256": "84be81d7d86dbf21",
                  "line": 31
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 920,
                  "end_byte": 941,
                  "node_type": "keyword_argument",
                  "sha256": "7ea1f855eea1dddc",
                  "line": 32
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1024,
                  "end_byte": 1038,
                  "node_type": "call",
                  "sha256": "9242bcf1160f57ef",
                  "line": 36
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1076,
                  "end_byte": 1587,
                  "node_type": "function_definition",
                  "sha256": "ad56a082ac5362f1",
                  "line": 41
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1477,
                  "end_byte": 1496,
                  "node_type": "call",
                  "sha256": "b4e6a2ef4386cc5b",
                  "line": 54
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5240,
                  "end_byte": 5684,
                  "node_type": "function_definition",
                  "sha256": "c1eef5369ce55eed",
                  "line": 165
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5363,
                  "end_byte": 5402,
                  "node_type": "call",
                  "sha256": "963484cbb86b3a3c",
                  "line": 168
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 2056,
                  "end_byte": 2982,
                  "node_type": "function_definition",
                  "sha256": "9f63673741af8802",
                  "line": 74
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 1925,
              "end_byte": 1940,
              "node_type": "call",
              "sha256": "3613983265a9a4b1",
              "line": 59
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 890,
                  "end_byte": 1015,
                  "node_type": "call",
                  "sha256": "84be81d7d86dbf21",
                  "line": 31
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 920,
                  "end_byte": 941,
                  "node_type": "keyword_argument",
                  "sha256": "7ea1f855eea1dddc",
                  "line": 32
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1024,
                  "end_byte": 1038,
                  "node_type": "call",
                  "sha256": "9242bcf1160f57ef",
                  "line": 36
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1076,
                  "end_byte": 1587,
                  "node_type": "function_definition",
                  "sha256": "ad56a082ac5362f1",
                  "line": 41
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1419,
                  "end_byte": 1448,
                  "node_type": "call",
                  "sha256": "5fdfa33d60f7f633",
                  "line": 52
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5644,
                  "end_byte": 6076,
                  "node_type": "function_definition",
                  "sha256": "296f5edb3fd9bbf9",
                  "line": 183
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5847,
                  "end_byte": 5864,
                  "node_type": "call",
                  "sha256": "600c65e35874e2cd",
                  "line": 189
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 1693,
                  "end_byte": 1947,
                  "node_type": "function_definition",
                  "sha256": "e9c8b72310cdbf17",
                  "line": 54
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 2975,
              "end_byte": 2993,
              "node_type": "call",
              "sha256": "3183bd0b9807e274",
              "line": 101
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 890,
                  "end_byte": 1015,
                  "node_type": "call",
                  "sha256": "84be81d7d86dbf21",
                  "line": 31
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 920,
                  "end_byte": 941,
                  "node_type": "keyword_argument",
                  "sha256": "7ea1f855eea1dddc",
                  "line": 32
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1024,
                  "end_byte": 1038,
                  "node_type": "call",
                  "sha256": "9242bcf1160f57ef",
                  "line": 36
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1076,
                  "end_byte": 1587,
                  "node_type": "function_definition",
                  "sha256": "ad56a082ac5362f1",
                  "line": 41
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1419,
                  "end_byte": 1448,
                  "node_type": "call",
                  "sha256": "5fdfa33d60f7f633",
                  "line": 52
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5644,
                  "end_byte": 6076,
                  "node_type": "function_definition",
                  "sha256": "296f5edb3fd9bbf9",
                  "line": 183
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5940,
                  "end_byte": 5959,
                  "node_type": "call",
                  "sha256": "7b2a5c23aef6e3c0",
                  "line": 192
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 2434,
                  "end_byte": 3456,
                  "node_type": "function_definition",
                  "sha256": "8bddc868a17f8ec1",
                  "line": 84
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 3932,
              "end_byte": 3970,
              "node_type": "call",
              "sha256": "f4adcf69bcdb43f3",
              "line": 130
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 890,
                  "end_byte": 1015,
                  "node_type": "call",
                  "sha256": "84be81d7d86dbf21",
                  "line": 31
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 920,
                  "end_byte": 941,
                  "node_type": "keyword_argument",
                  "sha256": "7ea1f855eea1dddc",
                  "line": 32
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1024,
                  "end_byte": 1038,
                  "node_type": "call",
                  "sha256": "9242bcf1160f57ef",
                  "line": 36
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1076,
                  "end_byte": 1587,
                  "node_type": "function_definition",
                  "sha256": "ad56a082ac5362f1",
                  "line": 41
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1419,
                  "end_byte": 1448,
                  "node_type": "call",
                  "sha256": "5fdfa33d60f7f633",
                  "line": 52
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5644,
                  "end_byte": 6076,
                  "node_type": "function_definition",
                  "sha256": "296f5edb3fd9bbf9",
                  "line": 183
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 6008,
                  "end_byte": 6021,
                  "node_type": "call",
                  "sha256": "1979a8a07d63dda4",
                  "line": 195
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 3459,
                  "end_byte": 4715,
                  "node_type": "function_definition",
                  "sha256": "76821d9a1cf7fc3f",
                  "line": 119
                }
              }
            ]
          },
          {
            "behaviour": "reverse_shell",
            "sink_kind": "exec",
            "sink": {
              "file": "amigapython/_internal/transport.py",
              "derived_from": null,
              "start_byte": 4211,
              "end_byte": 4339,
              "node_type": "call",
              "sha256": "ab8ae4bb0919379d",
              "line": 134
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 890,
                  "end_byte": 1015,
                  "node_type": "call",
                  "sha256": "84be81d7d86dbf21",
                  "line": 31
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 920,
                  "end_byte": 941,
                  "node_type": "keyword_argument",
                  "sha256": "7ea1f855eea1dddc",
                  "line": 32
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1024,
                  "end_byte": 1038,
                  "node_type": "call",
                  "sha256": "9242bcf1160f57ef",
                  "line": 36
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1076,
                  "end_byte": 1587,
                  "node_type": "function_definition",
                  "sha256": "ad56a082ac5362f1",
                  "line": 41
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1477,
                  "end_byte": 1496,
                  "node_type": "call",
                  "sha256": "b4e6a2ef4386cc5b",
                  "line": 54
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5240,
                  "end_byte": 5684,
                  "node_type": "function_definition",
                  "sha256": "c1eef5369ce55eed",
                  "line": 165
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5538,
                  "end_byte": 5665,
                  "node_type": "call",
                  "sha256": "77b346f60bf1eca2",
                  "line": 173
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5564,
                  "end_byte": 5583,
                  "node_type": "keyword_argument",
                  "sha256": "a46a0de7fa156dc9",
                  "line": 174
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5670,
                  "end_byte": 5684,
                  "node_type": "call",
                  "sha256": "ff7723ffe3165113",
                  "line": 177
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4577,
                  "end_byte": 5237,
                  "node_type": "function_definition",
                  "sha256": "3b5719ca9eac9733",
                  "line": 146
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4855,
                  "end_byte": 4884,
                  "node_type": "call",
                  "sha256": "76cb28e52f7b2ceb",
                  "line": 154
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4118,
                  "end_byte": 4574,
                  "node_type": "function_definition",
                  "sha256": "b6f6a069bac48de7",
                  "line": 131
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
      "hook": "cmdclass",
      "expression": "(c1 || c2 || c3 || c13) && (c1 || c2 || c3 || c4) && ((c5 && c6) || c7 || c8 || c9 || c10 || c11)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 574,
            "end_byte": 643,
            "node_type": "if_statement",
            "sha256": "db7d53e4a2a2fa81",
            "line": 19
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2",
            "c3",
            "c13"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5731,
            "end_byte": 5776,
            "node_type": "if_statement",
            "sha256": "96b14067075d5ee8",
            "line": 185
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
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5781,
            "end_byte": 5836,
            "node_type": "if_statement",
            "sha256": "3a0b6a1f5211ce23",
            "line": 187
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5",
            "c6",
            "c7",
            "c8",
            "c9",
            "c10",
            "c11"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "amigapython/_internal/__init__.py",
            "derived_from": null,
            "start_byte": 1457,
            "end_byte": 1496,
            "node_type": "if_statement",
            "sha256": "3c978bfa854740b4",
            "line": 53
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
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
            "c11"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "restricts the payload to an Inditex CI/build host identified by hostname, repo owner, internal jfrog proxy, a marker dir, a specific DP_TOKEN or runner name; collect gates guard recon/cred, the if-ctx check guards submit",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "recon",
          "cred_read",
          "exfil",
          "reverse_shell"
        ],
        "env_recipe": {
          "env_var": {
            "GITHUB_ACTIONS": null
          },
          "file_present": [
            "/opt/icr/hooks"
          ],
          "ci": "github"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 652,
            "end_byte": 754,
            "node_type": "try_statement",
            "sha256": "5512951d956da86b",
            "line": 21
          },
          {
            "file": "amigapython/_internal/resolver.py",
            "derived_from": null,
            "start_byte": 5841,
            "end_byte": 6076,
            "node_type": "stmt_range",
            "sha256": "7277be72b06f542e",
            "line": 189
          },
          {
            "file": "amigapython/_internal/__init__.py",
            "derived_from": null,
            "start_byte": 1477,
            "end_byte": 1496,
            "node_type": "call",
            "sha256": "b4e6a2ef4386cc5b",
            "line": 54
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "other",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 1925,
              "end_byte": 1940,
              "node_type": "call",
              "sha256": "3613983265a9a4b1",
              "line": 59
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5847,
                  "end_byte": 5864,
                  "node_type": "call",
                  "sha256": "600c65e35874e2cd",
                  "line": 189
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 1693,
                  "end_byte": 1947,
                  "node_type": "function_definition",
                  "sha256": "e9c8b72310cdbf17",
                  "line": 54
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 2975,
              "end_byte": 2993,
              "node_type": "call",
              "sha256": "3183bd0b9807e274",
              "line": 101
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 5940,
                  "end_byte": 5959,
                  "node_type": "call",
                  "sha256": "7b2a5c23aef6e3c0",
                  "line": 192
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 2434,
                  "end_byte": 3456,
                  "node_type": "function_definition",
                  "sha256": "8bddc868a17f8ec1",
                  "line": 84
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "network",
            "sink": {
              "file": "amigapython/_internal/resolver.py",
              "derived_from": null,
              "start_byte": 3932,
              "end_byte": 3970,
              "node_type": "call",
              "sha256": "f4adcf69bcdb43f3",
              "line": 130
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 6008,
                  "end_byte": 6021,
                  "node_type": "call",
                  "sha256": "1979a8a07d63dda4",
                  "line": 195
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/resolver.py",
                  "derived_from": null,
                  "start_byte": 3459,
                  "end_byte": 4715,
                  "node_type": "function_definition",
                  "sha256": "76821d9a1cf7fc3f",
                  "line": 119
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "amigapython/_internal/transport.py",
              "derived_from": null,
              "start_byte": 2694,
              "end_byte": 2746,
              "node_type": "call",
              "sha256": "2e0e9c1c164015ce",
              "line": 90
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1477,
                  "end_byte": 1496,
                  "node_type": "call",
                  "sha256": "b4e6a2ef4386cc5b",
                  "line": 54
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5240,
                  "end_byte": 5684,
                  "node_type": "function_definition",
                  "sha256": "c1eef5369ce55eed",
                  "line": 165
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5363,
                  "end_byte": 5402,
                  "node_type": "call",
                  "sha256": "963484cbb86b3a3c",
                  "line": 168
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 2056,
                  "end_byte": 2982,
                  "node_type": "function_definition",
                  "sha256": "9f63673741af8802",
                  "line": 74
                }
              }
            ]
          },
          {
            "behaviour": "reverse_shell",
            "sink_kind": "exec",
            "sink": {
              "file": "amigapython/_internal/transport.py",
              "derived_from": null,
              "start_byte": 4211,
              "end_byte": 4339,
              "node_type": "call",
              "sha256": "ab8ae4bb0919379d",
              "line": 134
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/__init__.py",
                  "derived_from": null,
                  "start_byte": 1477,
                  "end_byte": 1496,
                  "node_type": "call",
                  "sha256": "b4e6a2ef4386cc5b",
                  "line": 54
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5240,
                  "end_byte": 5684,
                  "node_type": "function_definition",
                  "sha256": "c1eef5369ce55eed",
                  "line": 165
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5538,
                  "end_byte": 5665,
                  "node_type": "call",
                  "sha256": "77b346f60bf1eca2",
                  "line": 173
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5564,
                  "end_byte": 5583,
                  "node_type": "keyword_argument",
                  "sha256": "a46a0de7fa156dc9",
                  "line": 174
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 5670,
                  "end_byte": 5684,
                  "node_type": "call",
                  "sha256": "ff7723ffe3165113",
                  "line": 177
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4577,
                  "end_byte": 5237,
                  "node_type": "function_definition",
                  "sha256": "3b5719ca9eac9733",
                  "line": 146
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4855,
                  "end_byte": 4884,
                  "node_type": "call",
                  "sha256": "76cb28e52f7b2ceb",
                  "line": 154
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "amigapython/_internal/transport.py",
                  "derived_from": null,
                  "start_byte": 4118,
                  "end_byte": 4574,
                  "node_type": "function_definition",
                  "sha256": "b6f6a069bac48de7",
                  "line": 131
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
      "reverse_shell"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "C2 IP and X-B service header encoded as chr() code-point sequences",
      "disguised as anonymous telemetry; docstrings and identifiers claim metrics collection",
      "misleading text"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "77.91.65[.]24:443",
        "role": "c2"
      },
      {
        "indicator": "77.91.65[.]24:443",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "inditex-ci-credential-exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "The cmdclass install/develop overrides run code that, only inside an Inditex CI/build pipeline (hostname icr-*sca*, GITHUB_REPOSITORY owner inditex, inditex.jfrog.io package proxies, /opt/icr/hooks, a specific DP_TOKEN, or RUNNER_NAME icr-inditex) and unless AMIGA_TELEMETRY is disabled, harvests CI and cloud credentials, reads the k8s service-account token and docker config, mints OIDC tokens, and exfiltrates them to a hard-coded external IP over HTTPS with TLS verification disabled, then runs a beacon loop executing arbitrary shell commands from that server. The telemetry framing is a disguise the code contradicts.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out of set: scope conditions c8-c11, the AMIGA_TELEMETRY kill-switch c12, the CI marker c13, the setup.py sites of c1-c3, and all gate guards are null-candidate; the extractor mis-modelled the _ci_provider / _validate_framework_scope helper structure as nested early-exit gates.",
    "submit_metrics' `if not sid` test of the C2 checkin reply (empty or '-') guards credential exfil and the beacon but is not recorded as a server_response gate; a person should decide whether to add it and how it nests in g2.",
    "Rule 8 misleading text: docstrings/identifiers claim anonymous telemetry while the code steals credentials and runs a remote-command beacon.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "25cb26561fbafaef"
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
        "candidate": "q_61236564eb",
        "reason_code": "other",
        "note": "Computes the CI provider string (returns 'github'); not the payload gate, which is collect's `if provider == \"unknown\"` (g2). c1 kept at its k_ site.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 1981,
          "end_byte": 2041,
          "node_type": "if_statement",
          "sha256": "0a771f965a4a2abf",
          "line": 64
        }
      },
      {
        "candidate": "q_759bdc1998",
        "reason_code": "other",
        "note": "Computes the CI provider string (returns 'jenkins'); not the payload gate (collect's provider check, g2). c2 kept at its k_ site.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 2046,
          "end_byte": 2104,
          "node_type": "if_statement",
          "sha256": "2d4e1675c8d308e6",
          "line": 66
        }
      },
      {
        "candidate": "q_8a4a492c63",
        "reason_code": "other",
        "note": "Computes the CI provider string (returns 'azdo'); not the payload gate (collect's provider check, g2). c3 kept at its k_ site.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 2109,
          "end_byte": 2166,
          "node_type": "if_statement",
          "sha256": "452c746a2deaa69d",
          "line": 68
        }
      },
      {
        "candidate": "q_cf80b32774",
        "reason_code": "other",
        "note": "Computes the CI provider string (returns 'gitlab'); not the payload gate (collect's provider check, g2). c4 kept at its k_ site.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 2171,
          "end_byte": 2226,
          "node_type": "if_statement",
          "sha256": "15c0c340fd6aa045",
          "line": 70
        }
      },
      {
        "candidate": "q_27bef7acc7",
        "reason_code": "other",
        "note": "Scope sub-decision in _validate_framework_scope (returns True); not the payload gate, which is collect's `if not _validate_framework_scope()` (g2). c5/c6 kept at their k_ sites.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 4790,
          "end_byte": 4855,
          "node_type": "if_statement",
          "sha256": "15ce52c9202ef5dc",
          "line": 156
        }
      },
      {
        "candidate": "q_c1a5443f16",
        "reason_code": "other",
        "note": "Scope sub-decision in _validate_framework_scope (returns True); not the payload gate, which is collect's `if not _validate_framework_scope()` (g2). c7 kept at its k_ site.",
        "anchor": {
          "file": "amigapython/_internal/resolver.py",
          "derived_from": null,
          "start_byte": 5206,
          "end_byte": 5261,
          "node_type": "if_statement",
          "sha256": "7f43f2c5ac558208",
          "line": 167
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 0,
    "condition_sites_cited": 7,
    "guards_cited": 0,
    "candidates_dropped": 6,
    "conditions_in_set": 4,
    "conditions_out_of_set": 9,
    "guard_candidates": 6,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c8",
      "c9",
      "c10",
      "c11",
      "c12",
      "c13",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
