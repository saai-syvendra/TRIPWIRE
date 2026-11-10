# npm publish-private-provider-action@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-02-07 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`, a 54-line plain script. It builds a JSON blob with the package name and version, install directory, home directory, hostname, username and DNS servers, and POSTs it over HTTPS to an oastify (out-of-band interaction) host. Two small gates exist: `fs.existsSync('/etc/passwd')` and `fs.existsSync('/etc/hosts')` decide whether those files' contents are added to the blob. Any Linux or macOS host opens both. The beacon itself is ungated and runs on every OS.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: file_or_dir_exists exists /etc/passwd) | then | 1 | recon | file_present=/etc/passwd |
| g2 | preinstall | c2 (c2: file_or_dir_exists exists /etc/hosts) | then | 1 | recon | file_present=/etc/hosts |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability

Grounding: 2 of 2 conditions and 2 of 2 gates from the candidate set.

## Requirements

- network: a1cdng68iz59mlth18k35a1wdnjg76vv[.]oastify[.]com:443 (collected host data is POSTed over HTTPS to this out-of-band interaction host)

## Behaviour

- Ungated: recon, exfil
- Gated: recon

## Notes

- The package name looks like an internal GitHub Action name, and the code is an install-time recon beacon with no other function. That fits a dependency-confusion probe. No second stage, no persistence.
- The existsSync gates only enrich the exfil. They do not decide whether it runs, so a scanner sees the beacon on any OS.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "publish-private-provider-action",
    "version": "1.0.0",
    "archive_sha256": "dc113fb73db865803e2bdce09d98b856631b68ac6fc4f3d603eaf513fb20f55b",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-02-07",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-02-07-publish-private-provider-action-v1.0.0.zip",
    "package_root": "layer0/tmp/tmp5j6rfkqd/publish-private-provider-action/package",
    "cluster_key": "c54116bd76a31a9816c9338b592d90fab2f41b2f2593dbb80e418a40f27dec19",
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
      "index.js (54 lines, the only code file) read in full; the preinstall hook runs it directly. Nothing bundled, nothing unread.",
      "The two existsSync ternaries only decide whether /etc/passwd and /etc/hosts contents go into the beacon; the beacon with hostname, username, home dir, install dir and DNS servers is sent either way.",
      "Request errors go to an error listener that logs them with console.error, so failures are visible in install output and not treated as silent_failure."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "a1cdng68iz59mlth18k35a1wdnjg76vv[.]oastify[.]com:443",
      "reason": "collected host data is POSTed over HTTPS to this out-of-band interaction host"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
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
      "category": "file_or_dir_exists",
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
      "purpose_reason": "reads /etc/passwd into the beacon only when the file exists (absent on Windows)",
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
      "purpose_reason": "reads /etc/hosts into the beacon only when the file exists",
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
        "indicator": "hxxps://a1cdng68iz59mlth18k35a1wdnjg76vv[.]oastify[.]com/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally collects hostname, username, home dir, install dir and DNS servers, plus /etc/passwd and /etc/hosts when present, and POSTs them to an oastify (out-of-band interaction) host. This is a dependency-confusion style recon beacon.",
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
