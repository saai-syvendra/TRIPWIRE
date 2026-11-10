# npm @emilgroup/billing-sdk@1.56.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-03-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node index.js`, a 48-line script wrapped in a silent try/catch. It takes a base64 payload from `process.env.PAYLOAD`, falling back to `config.payload` in its own package.json, and exits at once if neither is set (gate g1, condition c1). When a payload is present, it decodes it into `~/.local/share/<pkg name>/service.py`, writes a systemd user unit that runs it with `/usr/bin/python3` with `Restart=always`, then enables and starts the unit through `systemctl --user`. This version's package.json has no `config` block, so the only way to open the gate is to set `PAYLOAD` in the install environment.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script, dropped_binary, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: process.env.PAYLOAD truthy) | then | 1 | write_file, persistence, spawn_process | env_var=PAYLOAD=(set) |

Gate intent: g1 activate/enables/data_availability

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: linux (writes a systemd user unit and drives systemctl --user)
- installed_tool: systemctl (daemon-reload, enable and start of the user unit)
- other: systemd user session (user D-Bus) available to the installing user (systemctl --user fails without a user manager, and the error is swallowed)
- file_present: /usr/bin/python3 (ExecStart of the dropped unit runs the decoded script with this interpreter)

## Behaviour

- Ungated: none
- Gated: write_file, persistence, spawn_process

## Notes

- No payload ships in this archive. A normal install does nothing, which fits a staged or test release of a dropper template on a compromised scope.
- The `config.payload` fallback reads the package's own manifest and is not an environment check, so it is not a condition. Here it is always empty.
- `scripts.deploy` points to `scripts/deploy.js`, which is in the archive but is not an install hook, and `index.js` does not launch it, so the install never reaches it. It uses npm tokens to republish packages and never sets `config.payload`.
- Phase 2 note: the dropped service only runs on Linux with a working systemd user session. Without one, systemctl fails and the error is swallowed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@emilgroup/billing-sdk",
    "version": "1.56.1",
    "archive_sha256": "7d40906a1a197aaa75ddc9eb0ee127bdc8defe229aec3d1a279f6f482b6db36b",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-03-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-03-20-@emilgroup_billing-sdk-v1.56.1.zip",
    "package_root": "layer0/tmp/tmpy2oxg4bl/@emilgroup-billing-sdk/package",
    "cluster_key": "8233aa3fc392ace016f4b606ce0dfc667a90c3dcaf9d5b629d93224b458cc644",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "dropped_binary",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js (48 lines): package code read in full; nothing unread. Whole body is in a try/catch with an empty handler, so any failure is silent.",
      "Payload source is process.env.PAYLOAD || pkg.config.payload read from the package's own package.json. This version's package.json has no config block, so only the PAYLOAD env var can open the gate; the package.json fallback is not an environment check and is not recorded as a condition.",
      "When open: base64-decodes the payload to ~/.local/share/<pkg name>/service.py (mode 755), writes a systemd user unit running /usr/bin/python3 on it with Restart=always, then daemon-reload, enable and start via systemctl --user.",
      "With no payload shipped, a normal install exits at line 14 and does nothing. Looks like a staged or test build of a dropper template.",
      "scripts/deploy.js is in the archive but the install never reaches it: it is only the scripts.deploy entry, not a hook, and index.js does not launch it. It uses npm tokens to republish packages; it never sets config.payload."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "writes a systemd user unit and drives systemctl --user"
    },
    {
      "axis": "installed_tool",
      "value": "systemctl",
      "reason": "daemon-reload, enable and start of the user unit"
    },
    {
      "axis": "other",
      "value": "systemd user session (user D-Bus) available to the installing user",
      "reason": "systemctl --user fails without a user manager, and the error is swallowed"
    },
    {
      "axis": "file_present",
      "value": "/usr/bin/python3",
      "reason": "ExecStart of the dropped unit runs the decoded script with this interpreter"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.PAYLOAD",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_651b6f0019",
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 355,
            "end_byte": 374,
            "node_type": "member_expression",
            "sha256": "609dd52106a6288f",
            "line": 12
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_62e466f327",
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 423,
            "end_byte": 460,
            "node_type": "if_statement",
            "sha256": "c59719a257e52125",
            "line": 14
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the test checks that the data the dropper uses exists: the env var carries the payload itself, and without it (or a config.payload, absent here) the script exits before decoding and writing it",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "persistence",
          "spawn_process"
        ],
        "env_recipe": {
          "env_var": {
            "PAYLOAD": null
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 464,
            "end_byte": 1603,
            "node_type": "stmt_range",
            "sha256": "6aedd7414b0509dc",
            "line": 16
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 841,
              "end_byte": 942,
              "node_type": "call_expression",
              "sha256": "72713550ed8ee980",
              "line": 23
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 1000,
              "end_byte": 1340,
              "node_type": "call_expression",
              "sha256": "16b9fd11d340a805",
              "line": 26
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 1432,
              "end_byte": 1515,
              "node_type": "call_expression",
              "sha256": "91aa4004f9896549",
              "line": 43
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 1519,
              "end_byte": 1602,
              "node_type": "call_expression",
              "sha256": "7246374c9977598f",
              "line": 44
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
      "persistence",
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "payload expected as base64 in an env var or package config, decoded at install and written to disk (no payload shipped in this version)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "compromised_maintainer",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script is a persistence dropper: it decodes a base64 payload into a Python script under ~/.local/share and installs, enables and starts a systemd user service with Restart=always to run it. This version ships no payload, so it only acts when PAYLOAD is set in the install environment.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "1e183886a1ae0e20"
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
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
