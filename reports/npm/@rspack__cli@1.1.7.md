# npm @rspack/cli@1.1.7

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

A postinstall hook runs `node dist/utils/config.js`, an obfuscator.io protected webpack bundle whose entry module (0x1fdc) is the payload; the rest is axios, tar and friends. It silences stdout, stderr and console, then exits unless `process.platform` is linux (g1). It asks ipinfo.io for the country and only continues for CN, RU, HK, BY, IR or "UNK", which is also what a failed or non-200 lookup returns (g2), so blocking ipinfo.io opens the gate. The payload downloads a "vant" blob from the GitHub API and runs it, falling back to downloading XMRig 6.22.2 and starting it in the background against a Monero pool, and deletes the binary after spawning it. It then reads whichever of the Alibaba, Huawei and Tencent cloud CLI credential files exist and POSTs them base64 encoded to 80[.]78[.]28[.]72/tokens (g3).

## Execution

- **postinstall** `node dist/utils/config.js`: runs dist/utils/config.js; direct_script, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: os == linux) | then | 1 | recon | os=linux |
| g2 | postinstall | c1 && c2 (c1: os == linux; c2: external_ip_geo in [CN, RU, HK, UNK, BY, IR]) | then | 2 | download, write_file, exec_downloaded, crypto_mining, delete_file | os=linux; network=ipinfo[.]io:80=unreachable |
| g3 | postinstall | c1 && c2 && (c3 \|\| c4 \|\| c5) (c1: os == linux; c2: external_ip_geo in [CN, RU, HK, UNK, BY, IR]; c3: target_artifact exists; c4: target_artifact exists; c5: target_artifact exists) | then | 3 | cred_read, exfil | os=linux; network=ipinfo[.]io:80=unreachable; file_present=~/.aliyun/config.json, ~/.hcloud/config.json, ~/.tccli/default.credential |

Gate intent: g1 activate/enables/targeting; g2 activate/enables/targeting; g3 activate/enables/data_availability

Grounding: 1 of 5 conditions and 0 of 3 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, g1, g2, g3.

## Requirements

- network: api[.]github[.]com:443, github[.]com:443 (second stage: the vant blob from the GitHub API, else the XMRig release archive from github.com)
- network: 80[.]78[.]28[.]72:80 (exfil sink for base64 encoded cloud credential files)
- arch: x64 (the XMRig fallback is the linux-static-x64 build)
- file_present: /tmp (downloads are written and extracted under /tmp)

## Behaviour

- Ungated: defense_evasion
- Gated: recon, download, write_file, exec_downloaded, crypto_mining, delete_file, cred_read, exfil

## Notes

- The tool's units list names 0x552 as the entry; the bootstrap actually requires 0x1fdc, so the extractor saw none of the payload gates. All conditions except the Linux case are out of set.
- The country check is category external_ip_geo (out of scope), but its fail-open "UNK" default means an environment with ipinfo.io unreachable satisfies it; that is what the recipes use.
- vant blob versus XMRig is a download fallback chain, recorded as a requirement rather than a gate.
- If both downloads fail, `spawn('')` rejects inside a non-awaited Promise, which may end the process before the credential step on Node 15+.
- Credential-theft regions sit inside the payload helper, reached from the geo switch case, so the outer guards enclose the call rather than the region.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@rspack/cli",
    "version": "1.1.7",
    "archive_sha256": "f77f3b9068bb0478b3f005249370489038bef26fd9de6c5978d7a3a1dc997646",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2024-12-20-@rspack_cli-v1.1.7.zip",
    "package_root": "layer0/tmp/tmpaxjeb7no/@rspack-cli/package",
    "cluster_key": "99365d6ff664e80ccc1b5be76682a13a81d61a2c47436413a76c0d9020aeb401",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node dist/utils/config.js",
        "runs_on": "always",
        "file_chain": [
          "dist/utils/config.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): rspack",
      "dist/utils/config.js: string table recovered (d1, all calls); webpack module 0x1fdc (the real bootstrap entry, not 0x552) read in full; other units audited by sink inventory, all hits library behaviour; nothing unread.",
      "Audited libraries in the bundle: axios 1.7.9, tar, mkdirp, follow-redirects, form-data, mime-types, supports-color, debug, ms.",
      "child_process is only used by module 0x1fdc; hard-coded hosts outside it are library defaults (localhost in axios).",
      "Module 0x1fdc replaces process.stdout.write, process.stderr.write, console.log and console.error with no-ops before running, so nothing shows in the install log; the main async IIFE ends in .catch(() => {}).",
      "Geo check: ipinfo.io/json country, falling back to 'UNK' on any error or non-200 status. 'UNK' is in the allow list, so blocking ipinfo.io opens the payload gate.",
      "Inside the payload: a GitHub blob of a repo named vant is fetched to /tmp/vant.tar.gz and extracted; if any step fails ('' returned) it falls back to downloading XMRig 6.22.2 and running it as /tmp/vant_helper. Fallback chain, treated as a requirement, not a gate.",
      "XMRig is started with a Monero wallet, pool pool[.]supportxmr[.]com:443 over TLS, --cpu-max-threads-hint=75 and --background; the spawned binary is unlinked right after spawn.",
      "If both downloads fail, spawn('') throws inside a non-awaited Promise; on Node 15+ the unhandled rejection likely ends the process before the credential exfil step. Not modelled as a gate.",
      "Credential theft: ~/.aliyun/config.json, ~/.hcloud/config.json, ~/.tccli/default.credential are each read if existsSync; any found are joined, base64 encoded and POSTed to 80[.]78[.]28[.]72/tokens.",
      "Gate regions for the credential theft sit inside _0x490324, which is only called from the geo switch case; the outer guards enclose that call, not the region lexically.",
      "Endpoint ipinfo.io is a geolocation lookup whose answer selects behaviour; tagged c2 for lack of a closer role."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]github[.]com:443, github[.]com:443",
      "reason": "second stage: the vant blob from the GitHub API, else the XMRig release archive from github.com"
    },
    {
      "axis": "network",
      "value": "80[.]78[.]28[.]72:80",
      "reason": "exfil sink for base64 encoded cloud credential files"
    },
    {
      "axis": "arch",
      "value": "x64",
      "reason": "the XMRig fallback is the linux-static-x64 build"
    },
    {
      "axis": "file_present",
      "value": "/tmp",
      "reason": "downloads are written and extracted under /tmp"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "process.platform",
      "operator": "==",
      "value": "linux",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": "k_71029cae14",
          "anchor": {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 300154,
            "end_byte": 300193,
            "node_type": "switch_case",
            "sha256": "ea11deb849999887",
            "line": 1
          }
        }
      ],
      "in_scope": true,
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
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 300548,
            "end_byte": 300609,
            "node_type": "ternary_expression",
            "sha256": "61d3573cb833b217",
            "line": 1
          }
        }
      ],
      "in_scope": false,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.aliyun/config.json",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
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
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.hcloud/config.json",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.tccli/default.credential",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 299002,
            "end_byte": 299036,
            "node_type": "call_expression",
            "sha256": "4e210851c88c9d7e",
            "line": 1
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "exits on anything but Linux; the miner and paths are Linux-only",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "dist/utils/config.js",
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
        }
      ],
      "then": {
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 300360,
            "end_byte": 300754,
            "node_type": "switch_statement",
            "sha256": "400f576c1123dac1",
            "line": 1
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "dist/utils/config.js",
              "derived_from": "d1",
              "start_byte": 300488,
              "end_byte": 300540,
              "node_type": "call_expression",
              "sha256": "f28e33eb26356568",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 300373,
                  "end_byte": 300648,
                  "node_type": "call_expression",
                  "sha256": "d4a209ab0b5fa673",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 300373,
                  "end_byte": 300646,
                  "node_type": "function_expression",
                  "sha256": "84faeb2aeae26217",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 300391,
                  "end_byte": 300644,
                  "node_type": "call_expression",
                  "sha256": "40f2b7ab64a157fb",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 300424,
                  "end_byte": 300643,
                  "node_type": "generator_function",
                  "sha256": "9a1eef06654aadc2",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c1 && c2",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "payload only runs when ipinfo reports CN, RU, HK, BY or IR, or the lookup fails (UNK)",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "dist/utils/config.js",
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
            "file": "dist/utils/config.js",
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
            "c2"
          ]
        }
      ],
      "then": {
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
            "file": "dist/utils/config.js",
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
              "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296155,
                  "end_byte": 299623,
                  "node_type": "call_expression",
                  "sha256": "3e3b19bb45bf7d8e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296188,
                  "end_byte": 299622,
                  "node_type": "generator_function",
                  "sha256": "80a68fdccb288e7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296242,
                  "end_byte": 297320,
                  "node_type": "function_expression",
                  "sha256": "e59aad4f30ae6000",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296269,
                  "end_byte": 297318,
                  "node_type": "call_expression",
                  "sha256": "f5efb416136d876a",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296302,
                  "end_byte": 297317,
                  "node_type": "generator_function",
                  "sha256": "f022cffed97b21cb",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "crypto_mining",
            "sink_kind": "network",
            "sink": {
              "file": "dist/utils/config.js",
              "derived_from": "d1",
              "start_byte": 297725,
              "end_byte": 297895,
              "node_type": "call_expression",
              "sha256": "eda314ae2395299e",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296155,
                  "end_byte": 299623,
                  "node_type": "call_expression",
                  "sha256": "3e3b19bb45bf7d8e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296188,
                  "end_byte": 299622,
                  "node_type": "generator_function",
                  "sha256": "80a68fdccb288e7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297399,
                  "end_byte": 298538,
                  "node_type": "call_expression",
                  "sha256": "65c41ef1c47198a6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297399,
                  "end_byte": 298536,
                  "node_type": "function_expression",
                  "sha256": "e974539831925a0d",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297417,
                  "end_byte": 298534,
                  "node_type": "call_expression",
                  "sha256": "41379d41d7b1dd48",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297450,
                  "end_byte": 298533,
                  "node_type": "generator_function",
                  "sha256": "51954e0d68eed77e",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "dist/utils/config.js",
              "derived_from": "d1",
              "start_byte": 297906,
              "end_byte": 297947,
              "node_type": "call_expression",
              "sha256": "47c474f52d42d448",
              "line": 1
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296155,
                  "end_byte": 299623,
                  "node_type": "call_expression",
                  "sha256": "3e3b19bb45bf7d8e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296188,
                  "end_byte": 299622,
                  "node_type": "generator_function",
                  "sha256": "80a68fdccb288e7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297399,
                  "end_byte": 298538,
                  "node_type": "call_expression",
                  "sha256": "65c41ef1c47198a6",
                  "line": 1
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297399,
                  "end_byte": 298536,
                  "node_type": "function_expression",
                  "sha256": "e974539831925a0d",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297417,
                  "end_byte": 298534,
                  "node_type": "call_expression",
                  "sha256": "41379d41d7b1dd48",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 297450,
                  "end_byte": 298533,
                  "node_type": "generator_function",
                  "sha256": "51954e0d68eed77e",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296155,
                  "end_byte": 299623,
                  "node_type": "call_expression",
                  "sha256": "3e3b19bb45bf7d8e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296188,
                  "end_byte": 299622,
                  "node_type": "generator_function",
                  "sha256": "80a68fdccb288e7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295848,
                  "end_byte": 296127,
                  "node_type": "function_declaration",
                  "sha256": "fe2484b360576d59",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295895,
                  "end_byte": 296125,
                  "node_type": "new_expression",
                  "sha256": "1929f8ee7e957317",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295907,
                  "end_byte": 296124,
                  "node_type": "arrow_function",
                  "sha256": "1a10b5c9aebcbcc4",
                  "line": 1
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296155,
                  "end_byte": 299623,
                  "node_type": "call_expression",
                  "sha256": "3e3b19bb45bf7d8e",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 296188,
                  "end_byte": 299622,
                  "node_type": "generator_function",
                  "sha256": "80a68fdccb288e7e",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
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
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295848,
                  "end_byte": 296127,
                  "node_type": "function_declaration",
                  "sha256": "fe2484b360576d59",
                  "line": 1
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295895,
                  "end_byte": 296125,
                  "node_type": "new_expression",
                  "sha256": "1929f8ee7e957317",
                  "line": 1
                }
              },
              {
                "hop": "bind",
                "anchor": {
                  "file": "dist/utils/config.js",
                  "derived_from": "d1",
                  "start_byte": 295907,
                  "end_byte": 296124,
                  "node_type": "arrow_function",
                  "sha256": "1a10b5c9aebcbcc4",
                  "line": 1
                }
              }
            ]
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "postinstall",
      "expression": "c1 && c2 && (c3 || c4 || c5)",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "each cloud CLI credential file is read only if it exists, and the POST is skipped when none was found",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "dist/utils/config.js",
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
            "file": "dist/utils/config.js",
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
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/utils/config.js",
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
            "c3",
            "c4",
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "dist/utils/config.js",
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
            "c3",
            "c4",
            "c5"
          ]
        }
      ],
      "then": {
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
            "~/.aliyun/config.json",
            "~/.hcloud/config.json",
            "~/.tccli/default.credential"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "dist/utils/config.js",
            "derived_from": "d1",
            "start_byte": 299043,
            "end_byte": 299094,
            "node_type": "call_expression",
            "sha256": "f499648a5c0cbde2",
            "line": 1
          },
          {
            "file": "dist/utils/config.js",
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
              "file": "dist/utils/config.js",
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
              "file": "dist/utils/config.js",
              "derived_from": "d1",
              "start_byte": 299459,
              "end_byte": 299526,
              "node_type": "call_expression",
              "sha256": "d9c526db9dd6769b",
              "line": 1
            },
            "witness": []
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "defense_evasion"
    ],
    "gated": [
      "recon",
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
      "obfuscator.io string array with rotation and decoder aliases (recovered by the tool)",
      "hex identifiers",
      "escaped strings",
      "webpack bundle with the payload module hidden among axios and tar",
      "single very long line",
      "install output silenced by overriding stdout, stderr and console"
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
      },
      {
        "indicator": "pool[.]supportxmr[.]com:443",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "rspack-vant-xmrig",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script, injected into the real @rspack/cli package, silences output, exits unless on Linux and in a small set of countries (or when the geo lookup fails), then downloads and runs a second-stage binary or XMRig, and posts Alibaba, Huawei and Tencent cloud CLI credential files to a hard-coded IP.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "obfuscatorio_strings",
        "recipe_version": 1,
        "input": {
          "file": "dist/utils/config.js",
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
      "generator": "gate_extract@88c7907d65",
      "sha256": "565f5a4ce084a555"
    },
    "units_summary": [
      {
        "file": "dist/utils/config.js",
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
    "conditions_out_of_set": 4,
    "guard_candidates": 22,
    "gates_in_set": 0,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "g1",
      "g2",
      "g3"
    ],
    "anchor_refusals": 0
  }
}
```
