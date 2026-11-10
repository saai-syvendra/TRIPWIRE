# pypi custogtkinter@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

custogtkinter 1.0.0 is a typosquat of customtkinter whose setup.py overrides the `install` command with a randomly named class. Its `run()` checks `os.name == "nt"` and, on Windows only, executes a Fernet-encrypted string. Decrypted statically (decoder `fernet_exec`, derived d1), the stage fetches hxxps://funcaptcha[.]ru/paste2?package=custogtkinter, strips `<pre>` tags and exec()s the response. One gate (c1, OS is Windows) opens the download-and-exec; on other platforms the install proceeds normally.

## Execution

- **cmdclass** `cmdclass[install] = EwdwwdhIgsDqRxUltsypgGXXpvTDPAlvLzjwinasAugkLWDBhIJgpYDqkCeiZuxoUinfzLrGCYNlUDzDjhhoEioNrndcfikwXSfYwJmaMXJDUAeaTWeYKHUKzAsYYcWfFLaPxYovYaFZbTpPgJkPGFJlaFDzpKMPzLDgbjOBojVvPqKjTpyYrBkjr`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS and exec'd)
- other: requests and fernet importable in the build environment (setup_requires) (imported inside the gated block before the fetch)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The second stage is remote and was not fetched, so what it does is not recovered.
- The classifier "Operating System :: Microsoft :: Windows" is descriptive metadata only, not an installer restriction, so it is not a manifest gate.
- `requests` and `fernet` come in through `setup_requires`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "custogtkinter",
    "version": "1.0.0",
    "archive_sha256": "b9c86ca05442b762ad4c38156f57d5da89b7b8d31b8c3abcc92e2d7e57de9ed7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/custogtkinter-1.0.0.tar.gz",
    "package_root": "layer0/custogtkinter-1.0.0",
    "cluster_key": "e6195868d2227f87ec1bde8712b136de9b0e90466526069dceb78451658d423f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = EwdwwdhIgsDqRxUltsypgGXXpvTDPAlvLzjwinasAugkLWDBhIJgpYDqkCeiZuxoUinfzLrGCYNlUDzDjhhoEioNrndcfikwXSfYwJmaMXJDUAeaTWeYKHUKzAsYYcWfFLaPxYovYaFZbTpPgJkPGFJlaFDzpKMPzLDgbjOBojVvPqKjTpyYrBkjr",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "decoded_eval",
          "download_then_exec"
        ],
        "silent_failure": false
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
    "delays": [],
    "notes": [
      "setup_requires (dependency tree): ['fernet', 'requests']",
      "setup.py: read in full, including the Fernet-encrypted exec argument, decrypted statically with the registered fernet_exec decoder (derived d1); nothing unread.",
      "Decrypted stage is a one-liner: GET a paste URL, strip <pre> tags, exec the response. The second stage is remote and not available, so what it does is not recovered.",
      "Top-level setup.py code (setup_py hook) only calls setup(); the payload sits in the install cmdclass run()."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS and exec'd"
    },
    {
      "axis": "other",
      "value": "requests and fernet importable in the build environment (setup_requires)",
      "reason": "imported inside the gated block before the fetch"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "os.name",
      "operator": "==",
      "value": "nt",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_96b3b17712",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 731,
            "end_byte": 746,
            "node_type": "comparison_operator",
            "sha256": "03f6fcec9e8705f1",
            "line": 13
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "cmdclass",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_c2c6f541a1",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 728,
            "end_byte": 1160,
            "node_type": "if_statement",
            "sha256": "f16172b32faf22b9",
            "line": 13
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
      "purpose_reason": "Download-and-exec stage only runs on Windows (os.name == 'nt'); other platforms just install.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "exec_downloaded"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 764,
            "end_byte": 1160,
            "node_type": "block",
            "sha256": "30d30cfc714fe516",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 843,
              "end_byte": 909,
              "node_type": "call",
              "sha256": "dd9304ab4cf1400d",
              "line": 16
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 838,
              "end_byte": 956,
              "node_type": "call",
              "sha256": "eb0ab19adad536db",
              "line": 16
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
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "Fernet-encrypted stage passed to exec()",
      "random long class name and filler description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=custogtkinter",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec paste2 dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass decrypts a hidden Fernet stage that, on Windows only, downloads code from a remote paste endpoint and exec()s it during pip install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "decoder": "fernet_exec",
          "lang": "py"
        },
        "output_sha256": "5b6681d0ec7b6a0c"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "c3ee70acc7d1e444"
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
