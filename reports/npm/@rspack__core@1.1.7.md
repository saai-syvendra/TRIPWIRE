# npm @rspack/core@1.1.7

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node dist/util/support.js`, an obfuscator.io-protected webpack bundle whose own module (0x1fdc) silences all console output and then runs two nested gates. The first exits unless `process.platform` is linux, then looks up the host's country via ipinfo[.]io and runs the payload only for CN, RU, HK, BY, IR or a literal 'UNK' country, or when that lookup fails or returns a non-200 status (the helper then returns 'UNK'). Behind that gate it downloads a binary from a GitHub blob to /tmp/vant (falling back to the XMRig 6.22.2 static x64 release run with a wallet and pool.supportxmr[.]com:443 in the background), spawns it and unlinks it. A second, nested gate reads whichever of ~/.aliyun/config.json, ~/.hcloud/config.json and ~/.tccli/default.credential exist and POSTs them base64-encoded to 80[.]78[.]28[.]72/tokens. A Linux VM with ipinfo blocked (or a matching geo IP) plus a planted cloud CLI credential file opens everything.

## Execution

- **postinstall** `node dist/util/support.js`: runs dist/util/support.js; direct_script, download_then_exec, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && (c2 \|\| c3) (c1: os == linux; c2: external_ip_geo in [CN, RU, HK, UNK, BY, IR]; c3: network_reachability other request to ipinfo[.]io/json throws or returns a status other than 200 (helper returns 'UNK')) | then | 2 | download, write_file, exec_downloaded, crypto_mining, delete_file | os=linux; network=ipinfo[.]io:80=unreachable |
| g2 | postinstall | c1 && (c2 \|\| c3) && (c4 \|\| c5 \|\| c6) (c1: os == linux; c2: external_ip_geo in [CN, RU, HK, UNK, BY, IR]; c3: network_reachability other request to ipinfo[.]io/json throws or returns a status other than 200 (helper returns 'UNK'); c4: target_artifact exists; c5: target_artifact exists; c6: target_artifact exists) | then | 3 | cred_read, exfil | os=linux; network=ipinfo[.]io:80=unreachable; file_present=~/.aliyun/config.json |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/data_availability

Grounding: 1 of 6 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, c6, g1, g2.

## Requirements

- network: api[.]github[.]com:443, github[.]com:443 (second-stage miner binary is downloaded from the GitHub blob API, with the XMRig release on GitHub as fallback)
- network: pool[.]supportxmr[.]com:443 (XMRig fallback mines to this pool over TLS)
- network: 80[.]78[.]28[.]72:80 (cloud credential files are POSTed here)
- arch: x64 (the XMRig fallback is the linux-static-x64 build)
- file_present: /tmp (binaries and archives are written to and extracted in /tmp)

## Behaviour

- Ungated: none
- Gated: download, write_file, exec_downloaded, crypto_mining, delete_file, cred_read, exfil

## Notes

- String table recovered by prepare.py (d1, no unresolved calls). The real webpack entry is 0x1fdc, not 0x552 as the units summary says; the extractor did not see the async IIFE call, so it prefilled nothing.
- All other bundle modules are libraries (axios 1.7.9, tar, follow-redirects, form-data, debug, mime-types and others), audited by sink inventory; child_process and every non-default host only appear in 0x1fdc.
- The GitHub blob second stage is remote and not recovered; it is run with no arguments, so whether it is also a miner is unknown from the package alone.
- ipinfo[.]io is marked role c2 only because the schema has no role for a geolocation lookup.
- c2 lists all six switch literals, because a status-200 response carrying country 'UNK' reaches the same case as the helper's failure value. c3 covers only the failure path.
- A credential file that exists but fails to read is dropped as null, so a planted decoy must be readable. This is swallowed error handling, not a separate condition.
- The country gate's 'UNK' case means that blocking network to ipinfo in a sandbox *opens* the payload rather than hiding it, provided GitHub is reachable.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@rspack/core",
    "version": "1.1.7",
    "archive_sha256": "ccb55d450eef5dec8732fbe4d9df92b31511198ab38b00ab1c50dbb83bdcd34d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2024-12-20-@rspack_core-v1.1.7.zip",
    "package_root": "layer0/tmp/tmpz_hivk2s/@rspack-core/package",
    "cluster_key": "e597f7f6b2384997af8e4bce2d2ecb75431188b61e70a122b176d8d3643d7c14",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node dist/util/support.js",
        "runs_on": "always",
        "file_chain": [
          "dist/util/support.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "dropped_binary",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "dist/util/support.js: obfuscator.io string table recovered by prepare.py (d1, checksum matched, 0 unresolved). Webpack bundle, real entry is module 0x1fdc (trailing require), not 0x552 as the units summary says.",
      "Module 0x1fdc (package code) read in full. Remaining modules audited by sink inventory: axios 1.7.9, follow-redirects, form-data, combined/delayed-stream, asynckit, mime-types, debug, ms, supports-color, proxy-from-env, tar, mkdirp, node builtin shims. All hits library behaviour; nothing unread.",
      "child_process is only used in 0x1fdc; the only hosts besides library defaults (localhost) are the five in 0x1fdc. Env vars read by libraries: DEBUG, USER, FORCE_COLOR/TERM/CI family, tar/mkdirp test vars.",
      "Prefilled 0s delay was asynckit's setTimeout(fn, 0) fallback (library), removed.",
      "Entry overrides process.stdout.write, process.stderr.write, console.log and console.error with no-ops before running, and the whole async main ends in .catch(() => {}).",
      "Country lookup helper returns 'UNK' when the ipinfo request throws or status is not 200, and 'UNK' is one of the switch cases that runs the payload, so blocking ipinfo also opens the gate (c3).",
      "On status 200 the helper returns data.country unchanged, so a response whose country is the literal 'UNK' also reaches the UNK case. c2 therefore lists all six switch literals; c3 covers only the helper's failure path.",
      "Credential reads: a file that exists but fails to read (the catch returns null) is dropped by the null filter, so it counts as absent. That is swallowed error handling, not a deliberate test, so it is not a condition; a planted decoy must be readable.",
      "Inside the payload, a failed download of the GitHub blob (/tmp/vant) falls back to downloading the XMRig release to /tmp/vant_helper. That is a fallback chain, not a gate. Both binaries are spawned and then unlinked from disk.",
      "The GitHub blob (a git blob in a third-party repo) is fetched at install and run with no arguments; its content is remote and not recovered. The XMRig fallback is run with a wallet, pool.supportxmr[.]com:443, --tls and --background.",
      "If both downloads fail, spawn('') throws inside a Promise executor, giving an unhandled rejection that may end node before the credential step runs.",
      "Platform helper switch also has darwin/win32/default cases (k_0a921e9daa, k_a05f295276, k_65d4e5c753); they only map to an enum, and only the linux value avoids the early exit, so c1 cites the linux case."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]github[.]com:443",
        "github[.]com:443"
      ],
      "reason": "second-stage miner binary is downloaded from the GitHub blob API, with the XMRig release on GitHub as fallback"
    },
    {
      "axis": "network",
      "value": "pool[.]supportxmr[.]com:443",
      "reason": "XMRig fallback mines to this pool over TLS"
    },
    {
      "axis": "network",
      "value": "80[.]78[.]28[.]72:80",
      "reason": "cloud credential files are POSTed here"
    },
    {
      "axis": "arch",
      "value": "x64",
      "reason": "the XMRig fallback is the linux-static-x64 build"
    },
    {
      "axis": "file_present",
      "value": "/tmp",
      "reason": "binaries and archives are written to and extracted in /tmp"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "linux",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8208979bae",
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300154,
            "end_byte": 300193,
            "node_type": "switch_case",
            "sha256": "ea11deb849999887",
            "line": 1
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "external_ip_geo",
      "api": "axios.get(ipinfo.io/json).data.country",
      "operator": "in",
      "value": [
        "CN",
        "RU",
        "HK",
        "UNK",
        "BY",
        "IR"
      ],
      "value_recovered": "decoded",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300575,
            "end_byte": 300603,
            "node_type": "subscript_expression",
            "sha256": "c724d327777939eb",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "network_reachability",
      "api": "axios.get",
      "operator": "other",
      "value": "request to ipinfo[.]io/json throws or returns a status other than 200 (helper returns 'UNK')",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300462,
            "end_byte": 300642,
            "node_type": "try_statement",
            "sha256": "5c2a70657c710012",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.aliyun/config.json",
        "accessor": "exists"
      }
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.hcloud/config.json",
        "accessor": "exists"
      }
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
            "line": 1
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.tccli/default.credential",
        "accessor": "exists"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1 && (c2 || c3)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300082,
            "end_byte": 300359,
            "node_type": "binary_expression",
            "sha256": "5342b2b130a60627",
            "line": 1
          },
          "kind": "short_circuit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300697,
            "end_byte": 300724,
            "node_type": "switch_case",
            "sha256": "f165834f9a166508",
            "line": 1
          },
          "kind": "switch_case",
          "arm": "then",
          "conditions": [
            "c2",
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "miner only runs on Linux (x64 static build) and only when the lookup reports CN, RU, HK, BY, IR or the literal UNK, or the lookup fails",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "download",
          "write_file",
          "exec_downloaded",
          "crypto_mining",
          "delete_file"
        ],
        "env_recipe": {
          "os": "linux",
          "network": {
            "ipinfo[.]io:80": "unreachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300706,
            "end_byte": 300724,
            "node_type": "expression_statement",
            "sha256": "ee6f435f3239375c",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 296702,
              "end_byte": 296806,
              "node_type": "call_expression",
              "sha256": "b92ae1e1970f9a46",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 300712,
                  "end_byte": 300723,
                  "node_type": "call_expression",
                  "sha256": "b25d16a63d22f2d8",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296127,
                  "end_byte": 299625,
                  "node_type": "function_declaration",
                  "sha256": "052a098eebb19390",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296242,
                  "end_byte": 297364,
                  "node_type": "call_expression",
                  "sha256": "bdaf867f09621faa",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296242,
                  "end_byte": 297320,
                  "node_type": "function_expression",
                  "sha256": "e59aad4f30ae6000",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 296817,
              "end_byte": 296858,
              "node_type": "call_expression",
              "sha256": "111f1c3c76f529cc",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 300712,
                  "end_byte": 300723,
                  "node_type": "call_expression",
                  "sha256": "b25d16a63d22f2d8",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296127,
                  "end_byte": 299625,
                  "node_type": "function_declaration",
                  "sha256": "052a098eebb19390",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296242,
                  "end_byte": 297364,
                  "node_type": "call_expression",
                  "sha256": "bdaf867f09621faa",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296242,
                  "end_byte": 297320,
                  "node_type": "function_expression",
                  "sha256": "e59aad4f30ae6000",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 295967,
              "end_byte": 296006,
              "node_type": "call_expression",
              "sha256": "a9491dcabf8c2ab2",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 300712,
                  "end_byte": 300723,
                  "node_type": "call_expression",
                  "sha256": "b25d16a63d22f2d8",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296127,
                  "end_byte": 299625,
                  "node_type": "function_declaration",
                  "sha256": "052a098eebb19390",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 298738,
                  "end_byte": 298761,
                  "node_type": "call_expression",
                  "sha256": "ca96b7a692e3358f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 295848,
                  "end_byte": 296127,
                  "node_type": "function_declaration",
                  "sha256": "fe2484b360576d59",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "crypto_mining",
            "sink_kind": "exec",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 295967,
              "end_byte": 296006,
              "node_type": "call_expression",
              "sha256": "a9491dcabf8c2ab2",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 300712,
                  "end_byte": 300723,
                  "node_type": "call_expression",
                  "sha256": "b25d16a63d22f2d8",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296127,
                  "end_byte": 299625,
                  "node_type": "function_declaration",
                  "sha256": "052a098eebb19390",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 297383,
                  "end_byte": 298732,
                  "node_type": "call_expression",
                  "sha256": "69160a1885adf885",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 295848,
                  "end_byte": 296127,
                  "node_type": "function_declaration",
                  "sha256": "fe2484b360576d59",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 296007,
              "end_byte": 296041,
              "node_type": "call_expression",
              "sha256": "ee7f571fab3a1262",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 300712,
                  "end_byte": 300723,
                  "node_type": "call_expression",
                  "sha256": "b25d16a63d22f2d8",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 296127,
                  "end_byte": 299625,
                  "node_type": "function_declaration",
                  "sha256": "052a098eebb19390",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 298738,
                  "end_byte": 298761,
                  "node_type": "call_expression",
                  "sha256": "ca96b7a692e3358f",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/util/support.js",
                  "derived_from": "d1",
                  "start_byte": 295848,
                  "end_byte": 296127,
                  "node_type": "function_declaration",
                  "sha256": "fe2484b360576d59",
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
      "hook": "postinstall",
      "expression": "c1 && (c2 || c3) && (c4 || c5 || c6)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300082,
            "end_byte": 300359,
            "node_type": "binary_expression",
            "sha256": "5342b2b130a60627",
            "line": 1
          },
          "kind": "short_circuit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 300697,
            "end_byte": 300724,
            "node_type": "switch_case",
            "sha256": "f165834f9a166508",
            "line": 1
          },
          "kind": "switch_case",
          "arm": "then",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299099,
            "node_type": "ternary_expression",
            "sha256": "8ebb2b9a60d24e5e",
            "line": 1
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c4",
            "c5",
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299316,
            "end_byte": 299352,
            "node_type": "if_statement",
            "sha256": "28cafe826de92db3",
            "line": 1
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c5",
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "reads only the Alibaba Cloud, Huawei Cloud and Tencent Cloud CLI credential files that exist, and skips the upload when none do",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "os": "linux",
          "network": {
            "ipinfo[.]io:80": "unreachable"
          },
          "file_present": [
            "~/.aliyun/config.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299037,
            "end_byte": 299094,
            "node_type": "yield_expression",
            "sha256": "33e98e4a6a873fd2",
            "line": 1
          },
          {
            "file": "dist/util/support.js",
            "derived_from": "d1",
            "start_byte": 299448,
            "end_byte": 299605,
            "node_type": "try_statement",
            "sha256": "ecf817b03b5386e3",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 299043,
              "end_byte": 299094,
              "node_type": "call_expression",
              "sha256": "f499648a5c0cbde2",
              "line": 1
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "dist/util/support.js",
              "derived_from": "d1",
              "start_byte": 299459,
              "end_byte": 299526,
              "node_type": "call_expression",
              "sha256": "d9c526db9dd6769b",
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
    "ungated": [],
    "gated": [
      "download",
      "write_file",
      "exec_downloaded",
      "crypto_mining",
      "delete_file",
      "cred_read",
      "exfil"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "obfuscator.io string array with rotation and decoder aliases (recovered)",
      "hex-renamed identifiers",
      "escaped strings",
      "single-line webpack bundle hiding a small payload module among bundled libraries",
      "file named like a legitimate rspack utility (dist/util/support.js)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api[.]github[.]com/repos/youzan/vant/git/blobs/",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://80[.]78[.]28[.]72/tokens",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxp://ipinfo[.]io/json",
        "role": "c2"
      },
      {
        "indicator": "hxxps://github[.]com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-linux-static-x64.tar.gz",
        "role": "second_stage"
      },
      {
        "indicator": "80[.]78[.]28[.]72",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "rspack-xmrig-cloudcreds",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script, on Linux hosts whose lookup reports CN, RU, HK, BY, IR or the literal UNK (or where the geolocation lookup fails), downloads and launches a cryptominer in the background and deletes it from disk. It then reads Alibaba, Huawei and Tencent cloud CLI credential files and POSTs them base64-encoded to a hard-coded IP.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "ipinfo.io endpoint is a geolocation lookup, not attacker C2; recorded as role c2 because the schema has no lookup role",
    "c3 (lookup failure opens the gate) and the country switch_case guard (cited on the IR case the other matching cases fall through to) are analyst-added, out of set",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "obfuscatorio_strings",
        "recipe_version": 1,
        "input": {
          "file": "dist/util/support.js",
          "derived_from": null
        },
        "params": {
          "provider": "a0_0x4b44",
          "decoder": "a0_0x4e61",
          "offset": 279,
          "variant": "none",
          "form": "v2",
          "table_size": 1292,
          "rotations": 285,
          "checksum_target": 353678,
          "callables": 866
        },
        "output_sha256": "a033285a14c3c270",
        "stats": {
          "calls_total": 5876,
          "substituted": 5876,
          "unresolved": 0
        }
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "192ac153cad1fb4f"
    },
    "units_summary": [
      {
        "file": "dist/util/support.js",
        "derived_from": "d1",
        "bundler": "webpack",
        "count": 92,
        "entry": "0x552",
        "by_role": {
          "unknown": 91,
          "package": 1
        }
      }
    ],
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
    "condition_sites_cited": 1,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 5,
    "guard_candidates": 22,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
