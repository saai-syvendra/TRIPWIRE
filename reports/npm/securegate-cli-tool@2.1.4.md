# npm securegate-cli-tool@2.1.4

**Source:** datadog · **Source label:** malicious · **Released:** 2026-02-22 (registry) · **Assessment:** suspicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

npm runs `node scripts/postinstall.js` on every install. The script has one gate: `fs.existsSync(~/.openclaw)`. When the OpenClaw AI agent folder exists, it creates `~/.openclaw/skills/securegate/` if needed and copies the bundled `templates/SKILL.md` there, so the agent loads it as a skill. A fresh sandbox has no `~/.openclaw`, so the copy only happens if Phase 2 plants that folder. The whole thing sits in a try/catch that hides failures, and nothing is contacted at install.

## Execution

- **postinstall** `node scripts/postinstall.js`: runs scripts/postinstall.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: target_artifact exists ~/.openclaw) | then | 1 | write_file, persistence | file_present=~/.openclaw |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: write_file, persistence

## Notes

- The dropped skill file is agent instructions: it tells the agent to run the package's CLI, create `SG_` keys, swap raw provider keys for them and point SDK base URLs at the vendor's proxy (securegate[.]xyz). I read it as data only. Install code itself only copies a file.
- The two inner existsSync checks only create missing destination folders, so I dropped them as plumbing.
- Assessed as suspicious, not malicious: there is no exfil or exec at install. The risk is that the agent gets steered into sending API traffic through a third party. Needs a reviewer's call.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "securegate-cli-tool",
    "version": "2.1.4",
    "archive_sha256": "7e5e6dd9d37d8ecd13d1e610b483d8a91cd1ede0bd2ada2799ea4ae732003473",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-02-22",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-02-22-securegate-cli-tool-v2.1.4.zip",
    "package_root": "layer0/tmp/tmpkn_5z0v9/securegate-cli-tool/package",
    "cluster_key": "22367d6fb504d1f59c4a8d7bcf3f6bafb8ecccb0080710a698de09fb9e038b74",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node scripts/postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/postinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): securegate. src/ is the CLI and only runs when invoked or loaded.",
      "scripts/postinstall.js: read in full (38 lines, no obfuscation). templates/SKILL.md read as data: it is the copied file, not executed by the install.",
      "The two existsSync checks on ~/.openclaw/skills and ~/.openclaw/skills/securegate only create missing folders before the copy (mkdirSync recursive). Plumbing, dropped as gates.",
      "Whole body is in try/catch that prints one warning, so any failure (e.g. missing template) is hidden from the install."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "fs.existsSync",
      "operator": "exists",
      "value": "~/.openclaw",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_00a0b046df",
          "anchor": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 553,
            "end_byte": 580,
            "node_type": "call_expression",
            "sha256": "9bd440edf45b20b4",
            "line": 16
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "file",
        "callee": "fs.existsSync",
        "target": "~/.openclaw",
        "accessor": "exists"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_450f2986e7",
          "site": {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 549,
            "end_byte": 1134,
            "node_type": "if_statement",
            "sha256": "9889e3289feb6209",
            "line": 16
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Only drops the agent skill file on machines where the OpenClaw AI agent config folder exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "persistence"
        ],
        "env_recipe": {
          "file_present": [
            "~/.openclaw"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/postinstall.js",
            "derived_from": null,
            "start_byte": 582,
            "end_byte": 1134,
            "node_type": "statement_block",
            "sha256": "5558cd99a58c233b",
            "line": 16
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 963,
              "end_byte": 1026,
              "node_type": "call_expression",
              "sha256": "ba4c6a22cc3a8e08",
              "line": 29
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "scripts/postinstall.js",
              "derived_from": null,
              "start_byte": 963,
              "end_byte": 1026,
              "node_type": "call_expression",
              "sha256": "ba4c6a22cc3a8e08",
              "line": 29
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
      "write_file",
      "persistence"
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
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "openclaw-skill-drop",
  "claude_assessment": "suspicious",
  "assessment_reason": "The postinstall silently plants an OpenClaw agent skill in the user's home when ~/.openclaw exists, without asking. The skill tells the AI agent to route provider API calls through the package's own third-party key service, a persistent change to agent behaviour; the install itself contacts nothing.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Install code is only a gated file copy; whether planting an agent skill that steers the agent to a third-party API proxy counts as malicious is a judgement call for a reviewer."
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "7cdd905168b8936a"
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
        "candidate": "k_8263f63648",
        "reason_code": "other",
        "note": "Plumbing: existsSync on ~/.openclaw/skills only decides whether to mkdir the destination folder before the copy; both sides end in the same copy.",
        "anchor": {
          "file": "scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 712,
          "end_byte": 736,
          "node_type": "call_expression",
          "sha256": "0805d0d3ebdb7634",
          "line": 20
        }
      },
      {
        "candidate": "q_e88cc53dbe",
        "reason_code": "other",
        "note": "Plumbing guard for mkdir of ~/.openclaw/skills; same behaviour either way.",
        "anchor": {
          "file": "scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 707,
          "end_byte": 809,
          "node_type": "if_statement",
          "sha256": "e264cddfb8f88fd7",
          "line": 20
        }
      },
      {
        "candidate": "k_8ad84143e8",
        "reason_code": "other",
        "note": "Plumbing: existsSync on ~/.openclaw/skills/securegate only decides whether to mkdir the destination folder; the copy runs either way.",
        "anchor": {
          "file": "scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 826,
          "end_byte": 850,
          "node_type": "call_expression",
          "sha256": "5467007652a09a58",
          "line": 24
        }
      },
      {
        "candidate": "q_94cd4b303f",
        "reason_code": "other",
        "note": "Plumbing guard for mkdir of ~/.openclaw/skills/securegate; same behaviour either way.",
        "anchor": {
          "file": "scripts/postinstall.js",
          "derived_from": null,
          "start_byte": 821,
          "end_byte": 923,
          "node_type": "if_statement",
          "sha256": "b39bb0f7678a2272",
          "line": 24
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 4,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 3,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
