# npm lambda-sns-dynatrace-sdk@1.1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-01-13 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. With no gate in front, the script collects the install path, home dir, hostname, username, DNS servers and package.json, and POSTs them over HTTPS to an OAST collector (Burp Collaborator style host). The only gates are two `fs.existsSync` tests that decide whether `/etc/passwd` and `/etc/hosts` get read into the payload; when a file is missing, null is sent in its place. Any Linux or macOS VM with outbound HTTPS opens both gates; on Windows the beacon still fires, just without the file contents.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: target_artifact exists /etc/passwd) | then | 1 | recon | file_present=/etc/passwd |
| g2 | preinstall | c2 (c2: target_artifact exists /etc/hosts) | then | 1 | recon | file_present=/etc/hosts |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 2 of 2 conditions and 2 of 2 gates from the candidate set.

## Requirements

- network: cgwp….oastify.com:443 (HTTPS POST of the collected host data to an OAST collector host (subdomain id redacted))

## Behaviour

- Ungated: recon, exfil
- Gated: recon

## Notes

- The package name looks like an internal scope name, which points to dependency confusion. There is no obfuscation.
- The collector subdomain is a per-tester id and is redacted here to its first 4 characters.
- The existsSync checks are kept as data_availability gates because flipping them changes whether the file read runs. The exfil itself is ungated.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lambda-sns-dynatrace-sdk",
    "version": "1.1.0",
    "archive_sha256": "38723c37fe9513340cfcd5b0f94229e968b60a8f581600fcd9eed1812b807540",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-01-13",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-01-13-lambda-sns-dynatrace-sdk-v1.1.0.zip",
    "package_root": "layer0/tmp/tmpnnk86n62/lambda-sns-dynatrace-sdk/package",
    "cluster_key": "04c3577f6d0f62146fb48d5a34c2fa46fded08e7ee5623a1a237b385929d8341",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
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
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "index.js (55 lines): package code read in full; nothing bundled, nothing unread.",
      "Host details (cwd, home dir, hostname, username, DNS servers, package.json) are collected and POSTed with no gate; only the /etc/passwd and /etc/hosts reads sit behind existsSync tests.",
      "The request error handler only logs; it does not change behaviour and is not a gate. The response body is printed to stdout and not acted on."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cgwp….oastify.com:443",
      "reason": "HTTPS POST of the collected host data to an OAST collector host (subdomain id redacted)",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1667,
          "end_byte": 1812,
          "node_type": "call_expression",
          "sha256": "03fbbd706dd176e6",
          "line": 43
        }
      ]
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "/etc/passwd",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_5248d1dbff",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 786,
            "end_byte": 814,
            "node_type": "call_expression",
            "sha256": "fac840862030414d",
            "line": 18
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "/etc/hosts",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_21183d0abd",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 918,
            "end_byte": 945,
            "node_type": "call_expression",
            "sha256": "b4ad68c3f0d13ca3",
            "line": 19
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_f659c3d5c2",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 786,
            "end_byte": 862,
            "node_type": "ternary_expression",
            "sha256": "9e0bee5430bd3bd3",
            "line": 18
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Reads /etc/passwd for exfiltration only when it exists; otherwise sends null in its place.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "file_present": [
            "/etc/passwd"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 817,
            "end_byte": 855,
            "node_type": "call_expression",
            "sha256": "aca73865419aad3c",
            "line": 18
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 817,
              "end_byte": 855,
              "node_type": "call_expression",
              "sha256": "aca73865419aad3c",
              "line": 18
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "preinstall",
      "expression": "c2",
      "guards": [
        {
          "candidate": "q_f15b5946c2",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 918,
            "end_byte": 992,
            "node_type": "ternary_expression",
            "sha256": "465a4b2154f29b07",
            "line": 19
          },
          "kind": "ternary",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Reads /etc/hosts for exfiltration only when it exists; otherwise sends null in its place.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "file_present": [
            "/etc/hosts"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 948,
            "end_byte": 985,
            "node_type": "call_expression",
            "sha256": "df3a63d3f567a844",
            "line": 19
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "fs_read",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 948,
              "end_byte": 985,
              "node_type": "call_expression",
              "sha256": "df3a63d3f567a844",
              "line": 19
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
      "recon",
      "exfil"
    ],
    "gated": [
      "recon"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://cgwp…[.]oastify[.]com:443/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook collects hostname, username, home dir, install path, DNS servers and the contents of /etc/passwd and /etc/hosts, and POSTs them to an OAST collector without asking. Install-time exfiltration of host data is malicious whatever the intent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "0941d7f540cd2af4"
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
    "condition_candidates": 2,
    "condition_sites_cited": 2,
    "guards_cited": 2,
    "candidates_dropped": 0,
    "conditions_in_set": 2,
    "conditions_out_of_set": 0,
    "guard_candidates": 2,
    "gates_in_set": 2,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
