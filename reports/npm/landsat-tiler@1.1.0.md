# npm landsat-tiler@1.1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2025-05-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every registry install. The script builds a JSON blob with the package name and version, install directory, home directory, hostname, username, DNS servers and the full package.json, and POSTs it over HTTPS to an oastify[.]com interaction host with no gate in front. The only gates are two `fs.existsSync` ternaries that add the contents of `/etc/passwd` (g1) and `/etc/hosts` (g2) to the blob when those files exist; on a host without them the field is null and the beacon still goes out. Any Unix-like VM with outbound HTTPS opens both gates.

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

- network: muknbiszlkx9tkjnea9ew54xbohn5dt2[.]oastify[.]com:443 (Collected host data is POSTed over HTTPS to this OAST endpoint; without it the exfil fails.)

## Behaviour

- Ungated: recon, exfil
- Gated: recon

## Notes

- Shape matches a dependency-confusion probe (bare package.json, OAST endpoint, host fingerprint); the attack_type rests on that pattern, not on knowing an internal package of this name.
- The comments describe the code accurately (Burp Collaborator collection); no misleading text.
- `os.userInfo()` can throw in some containers without a passwd entry for the uid, which would abort the script before the request; not a deliberate check, so not recorded as a gate.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "landsat-tiler",
    "version": "1.1.0",
    "archive_sha256": "2e6bf52f5389eb306d5a0fa2f60651c745dfc3ee34dbd7439c9114f501f984c5",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-05-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-05-04-landsat-tiler-v1.1.0.zip",
    "package_root": "layer0/tmp/tmpx66nbvrz/landsat-tiler/package",
    "cluster_key": "a2efdc2a733f25c5b94ea6f882132ce5c293700be78eddceaeba6b8a9d0cc05a",
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
      "index.js (55 lines, package code) read in full; it is the only code file and nothing is unread.",
      "Host details (homedir, hostname, username, DNS servers, install dir, package.json) are collected and POSTed with no gate; only the /etc/passwd and /etc/hosts reads sit behind existsSync ternaries.",
      "The request error handler only logs to stderr; the install exit status is not affected, so silent_failure is false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "muknbiszlkx9tkjnea9ew54xbohn5dt2[.]oastify[.]com:443",
      "reason": "Collected host data is POSTed over HTTPS to this OAST endpoint; without it the exfil fails.",
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
      "purpose_reason": "Reads /etc/passwd into the exfil payload only when the file exists (Unix hosts); otherwise the field is null.",
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
      "purpose_reason": "Reads /etc/hosts into the exfil payload only when the file exists; otherwise the field is null.",
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
        "indicator": "muknbiszlkx9tkjnea9ew54xbohn5dt2.oastify[.]com:443",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST recon beacon (oastify[.]com)",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js, which collects hostname, username, home directory, DNS servers, install path and the contents of /etc/passwd and /etc/hosts, then POSTs them to an oastify[.]com interaction host. This is unconditional host recon and exfiltration at install time.",
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
