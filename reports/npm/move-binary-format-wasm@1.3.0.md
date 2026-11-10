# npm move-binary-format-wasm@1.3.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. With no gate in front, the script collects the package name, install directory, home directory, hostname, username, DNS servers and package.json, and POSTs them over HTTPS to a Burp Collaborator host on port 443. The only gates are two `fs.existsSync` ternaries (g1 `/etc/passwd`, g2 `/etc/hosts`). Each one adds the file's contents to the same payload when the file exists and sends null when it does not. Any Linux or macOS host opens both gates, and the exfil runs on every OS.

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

- network: 2mpg….burpcollaborator.net:443 (ungated HTTPS POST of the collected host data; a failed connection only logs an error)

## Behaviour

- Ungated: recon, exfil
- Gated: recon

## Notes

- The Collaborator subdomain is redacted to its first 4 characters. The tool found no endpoints because the host sits in an `options.hostname` field rather than a URL, so I added the endpoint by hand.
- `attack_type: dependency_confusion` comes from the pattern (an unscoped package with an internal-looking name, a host-fingerprint beacon to Burp Collaborator, version 1.3.0 and nothing else in the package). No code proves it.
- The comments describe the code accurately. Nothing in them is misleading or addressed to a reviewer.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "move-binary-format-wasm",
    "version": "1.3.0",
    "archive_sha256": "a835118bc209116aacd9034efb3c3dc915ac7fdc8668d4dbf576250b0e8b1293",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-23-move-binary-format-wasm-v1.3.0.zip",
    "package_root": "layer0/tmp/tmpd_yvq32z/move-binary-format-wasm/package",
    "cluster_key": "bd937ed32f81de2bfea8e697303a7184a47c5ab1eaab980cf5d781bd29c53068",
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
      "index.js: package code read in full (55 lines, the only code file); nothing bundled, nothing unread.",
      "Ungated: collects package name, __dirname, homedir, hostname, username, DNS servers and package.json, then POSTs them with https.request to a Burp Collaborator host on port 443.",
      "The /etc/passwd and /etc/hosts contents read under g1/g2 go into the same ungated POST; when a file is missing (e.g. Windows) its field is null and the POST still goes out.",
      "silent_failure left false: the request error handler logs the error to stderr rather than hiding it, and nothing in the script exits non-zero."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "2mpg….burpcollaborator.net:443",
      "reason": "ungated HTTPS POST of the collected host data; a failed connection only logs an error",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 1674,
          "end_byte": 1819,
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
      "purpose_reason": "existsSync ternary reads /etc/passwd into the exfil payload only when it exists, otherwise sends null",
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
      "purpose_reason": "existsSync ternary reads /etc/hosts into the exfil payload only when it exists, otherwise sends null",
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
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://2mpg…[.]burpcollaborator[.]net/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "burp-collaborator dependency-confusion recon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which gathers host identity data (hostname, username, home dir, DNS servers, install path) plus /etc/passwd and /etc/hosts and POSTs it to a Burp Collaborator host without consent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
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
