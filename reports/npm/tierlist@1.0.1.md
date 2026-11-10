# npm tierlist@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-11-29 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`tierlist@1.0.1` runs `node .index.js` as a `postinstall` hook on every install. `start()` runs three payload stages with no outer gate: `runRCChecker()` (persistence), `wipe()` which spawns `rm -rf /sdcard/Android` every millisecond to destroy Android/Termux storage, and `bomb()` which spawns `bash .bomb.sh` (a harmless decoy that only echoes a word). `block()` then puts the terminal in raw mode, ignores SIGINT/SIGTSTP/SIGQUIT/SIGTERM/SIGHUP and loops forever to stop the user interrupting the wipe. The only real gates sit in the persistence routine: it appends a `wifi-a` autostart line to any existing shell rc file (`~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.bash_profile`, `~/.config/fish/config.fish`) that does not already contain the marker, and spawns the login shell to source it only when `$SHELL` is bash or zsh. The destructive and spawn behaviour is ungated and fires on any machine with `rm`/`bash`.

## Execution

- **postinstall** `node .index.js`: 5-file chain; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 && c4 (c1: target_artifact exists; c4: file_content not_includes wifi-a) | then | 2 | persistence, write_file | file_present=~/.bashrc |
| g2 | postinstall | c1 && (c2 \|\| c3) (c1: target_artifact exists; c2: process.env.SHELL includes bash; c3: process.env.SHELL includes zsh) | then | 2 | spawn_process | env_var=SHELL=/bin/bash; file_present=~/.bashrc |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/portability

Grounding: 0 of 4 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c1, c2, c3, c4, g1, g2.

## Requirements

- installed_tool: rm (wipe() spawns rm -rf /sdcard/Android to delete storage.)
- installed_tool: bash (bomb() spawns bash to run .bomb.sh; autoSource spawns the login shell to source the rc file.)
- installed_tool: chmod (bomb() spawns chmod +x to make .bomb.sh executable.)

## Behaviour

- Ungated: destructive, delete_file, spawn_process, other
- Gated: persistence, write_file, spawn_process

## Notes

- Two gates, both on the `postinstall` hook. g1 (`c1 && c4`, min 2): a shell rc file must exist (`fs.access`) and not already contain `wifi-a` (reinfection guard) for the append to run. g2 (`c1 && (c2 || c3)`, min 2): `$SHELL` must include `bash` or `zsh` to spawn the sourcing shell. All conditions and guards are out of set (the extractor produced no candidates), so they need verification.
- `.bomb.sh` was listed as not-chained/unrecovered. It does run at install (via `bomb()` -> `start()`), so it is added to the file_chain; it only `echo "aman"`, so it is a decoy. Entry removed from `obfuscation.unrecovered`.
- The destructive wipe targets `/sdcard/Android`, an Android/Termux path, so the real damage only lands on such devices, but the `rm -rf` is attempted unconditionally.
- `time.js` (no dot prefix) duplicates `.time.js` but is never imported on the install path.
- Family hint `android-sdcard-wiper` is derived from the `/sdcard/Android` wipe target, not from any name or comment.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "tierlist",
    "version": "1.0.1",
    "archive_sha256": "ac84b4431b0edbda39c8cb0027f1866c907e350a0ef1cba12b61e2a332839904",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-11-29",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-11-29-tierlist-v1.0.1.zip",
    "package_root": "layer0/tmp/tmpt_0nw43a/tierlist/package",
    "cluster_key": "cbf80f791a7c452308d957407c7e700693563204b62a070f7b2c7d75a1766cd6",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node .index.js",
        "runs_on": "always",
        "file_chain": [
          ".index.js",
          ".hitam.js",
          ".time.js",
          ".bahagia.js",
          ".bomb.sh"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": ".index.js:11",
        "seconds": 1.2
      },
      {
        "site": ".index.js:14",
        "seconds": 0.1
      },
      {
        "site": ".index.js:17",
        "seconds": 0.3
      },
      {
        "site": ".time.js:26",
        "seconds": 2.2
      },
      {
        "site": ".time.js:25",
        "seconds": 0.06
      }
    ],
    "notes": [
      "bin command not analysed (runs only when invoked): wifi-a -> ./.index.js.",
      ".bomb.sh resolved: .bahagia.js bomb() spawns chmod +x .bomb.sh then bash .bomb.sh, and bomb() is called by start() in .index.js, so it runs at install. Added to file_chain, removed from obfuscation.unrecovered.",
      ".bomb.sh read in full: it only `echo \"aman\"`, a harmless decoy. All four .js files are package code read in full.",
      "wipe() in .index.js runs ungated: setInterval every 1ms spawns rm -rf /sdcard/Android, wiping Android/Termux storage. Recorded as ungated destructive/delete_file.",
      "block() from .time.js runs ungated: puts stdin in raw mode, installs no-op handlers for SIGINT/SIGTSTP/SIGQUIT/SIGTERM/SIGHUP and runs an infinite setImmediate loop, keeping the process alive and blocking the user from interrupting the wipe. Recorded as ungated 'other'.",
      "clear() spawns the benign 'clear' command (cosmetic); not recorded as a behaviour.",
      "time.js (no dot prefix) is a near-identical copy of .time.js but is never imported by any install-reached file; not in the install path.",
      "No re-entry guard set for a respawned child; the only on-disk marker check is the wifi-a reinfection guard in c4."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "rm",
      "reason": "wipe() spawns rm -rf /sdcard/Android to delete storage."
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "bomb() spawns bash to run .bomb.sh; autoSource spawns the login shell to source the rc file."
    },
    {
      "axis": "installed_tool",
      "value": "chmod",
      "reason": "bomb() spawns chmod +x to make .bomb.sh executable."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "fs.access",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.access",
        "target": "~/.bashrc, ~/.zshrc, ~/.profile, ~/.bash_profile, ~/.config/fish/config.fish",
        "accessor": "exists"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 453,
            "end_byte": 468,
            "node_type": "call_expression",
            "sha256": "1812e730085ebd3e",
            "line": 21
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
      "category": "env_var",
      "api": "process.env.SHELL",
      "operator": "includes",
      "value": "bash",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 787,
            "end_byte": 809,
            "node_type": "call_expression",
            "sha256": "26fd52aac1d527dd",
            "line": 33
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "env_var",
      "api": "process.env.SHELL",
      "operator": "includes",
      "value": "zsh",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 813,
            "end_byte": 834,
            "node_type": "call_expression",
            "sha256": "db9259f91531b57a",
            "line": 33
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "file_content",
      "api": "fs.readFile",
      "operator": "not_includes",
      "value": "wifi-a",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "fs.readFile",
        "target": "*",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 624,
            "end_byte": 647,
            "node_type": "call_expression",
            "sha256": "29b0bde4d2118c12",
            "line": 28
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
      "expression": "c1 && c4",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Appends the wifi-a autostart line only to shell rc files that already exist (fs.access) and do not yet contain the marker (reinfection guard).",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "conditions": [
            "c1"
          ],
          "arm": "else",
          "site": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 1004,
            "end_byte": 1046,
            "node_type": "if_statement",
            "sha256": "a17d57d6671c6bbc",
            "line": 38
          }
        },
        {
          "candidate": null,
          "kind": "early_exit",
          "conditions": [
            "c4"
          ],
          "arm": "else",
          "site": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 620,
            "end_byte": 666,
            "node_type": "if_statement",
            "sha256": "3ade09b101de6f0e",
            "line": 28
          }
        }
      ],
      "then": {
        "behaviours": [
          "persistence",
          "write_file"
        ],
        "regions": [
          {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 667,
            "end_byte": 707,
            "node_type": "expression_statement",
            "sha256": "7499f8d013a8293c",
            "line": 30
          }
        ],
        "payload": [
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": ".hitam.js",
              "derived_from": null,
              "start_byte": 673,
              "end_byte": 706,
              "node_type": "call_expression",
              "sha256": "a55b1afc5256707b",
              "line": 30
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": ".hitam.js",
              "derived_from": null,
              "start_byte": 673,
              "end_byte": 706,
              "node_type": "call_expression",
              "sha256": "a55b1afc5256707b",
              "line": 30
            },
            "witness": []
          }
        ],
        "env_recipe": {
          "file_present": [
            "~/.bashrc"
          ]
        },
        "recipe_guessed_fields": [],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "postinstall",
      "expression": "c1 && (c2 || c3)",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "Spawns a shell to source the just-modified rc file only when the login shell is bash or zsh.",
      "guards": [
        {
          "candidate": null,
          "kind": "early_exit",
          "conditions": [
            "c1"
          ],
          "arm": "else",
          "site": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 1004,
            "end_byte": 1046,
            "node_type": "if_statement",
            "sha256": "a17d57d6671c6bbc",
            "line": 38
          }
        },
        {
          "candidate": null,
          "kind": "if",
          "conditions": [
            "c2",
            "c3"
          ],
          "arm": "then",
          "site": {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 783,
            "end_byte": 919,
            "node_type": "if_statement",
            "sha256": "cb44fbf489cc8fc2",
            "line": 33
          }
        }
      ],
      "then": {
        "behaviours": [
          "spawn_process"
        ],
        "regions": [
          {
            "file": ".hitam.js",
            "derived_from": null,
            "start_byte": 842,
            "end_byte": 907,
            "node_type": "expression_statement",
            "sha256": "c12ec3d610f379c2",
            "line": 34
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": ".hitam.js",
              "derived_from": null,
              "start_byte": 842,
              "end_byte": 906,
              "node_type": "call_expression",
              "sha256": "b9571221cd3c3e61",
              "line": 34
            },
            "witness": []
          }
        ],
        "env_recipe": {
          "env_var": {
            "SHELL": "/bin/bash"
          },
          "file_present": [
            "~/.bashrc"
          ]
        },
        "recipe_guessed_fields": [],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "destructive",
      "delete_file",
      "spawn_process",
      "other"
    ],
    "gated": [
      "persistence",
      "write_file",
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "all install scripts use dot-prefixed hidden file names (.index.js, .hitam.js, .time.js, .bahagia.js, .bomb.sh)",
      "decoy content: an ASCII banner presents a free 'wifi attack' tool and the launched .bomb.sh only echoes a word, while the code wipes /sdcard/Android and installs shell persistence"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "android-sdcard-wiper",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook runs on every install and, with no gate, repeatedly spawns rm -rf /sdcard/Android to wipe Android/Termux storage while blocking interrupt signals to stop the user aborting it. It also installs persistence by appending a wifi-a autostart line to any existing shell rc file. This is clearly destructive malware.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "All conditions and guards are out of set: the extractor found no candidates for this package, so every gate claim was added by hand and should be checked against the code.",
    "c4 is recorded as a gate because it is a reinfection guard (skips the append when the rc file already contains the wifi-a marker); Phase 2 must plant rc files without that marker.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "428960f5b8cf6c20"
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
    "condition_candidates": 0,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 0,
    "conditions_out_of_set": 4,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c1",
      "c2",
      "c3",
      "c4",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
