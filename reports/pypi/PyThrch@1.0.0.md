# pypi PyThrch@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

PyThrch is an sdist whose `setup.py` registers an `install` cmdclass override, so its `run()` executes on a normal pip install. Inside `run()` a single gate, `os.name == "nt"`, guards an `exec()` of a Fernet-encrypted string. Decrypted (decoder `fernet_exec`, derivation d1), the stage downloads Python code from `hxxps://funcaptcha[.]ru/paste2?package=PyThrch`, strips `<pre>` tags and `exec()`s it. Only a Windows build environment with outbound HTTPS to that host opens the payload; elsewhere the override just runs the normal install.

## Execution

- **cmdclass** `cmdclass[install] = wEEMCHqRWZtakTKNCyKxHQMSJuPcAcXLFwkWZhejfuKWsbJWaXnzUQhsdQNkvLosOsVqvfZmLIBlHXgnMvplnXdwInjza`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (requests.get fetches the second-stage Python code over HTTPS; without it the exec has nothing to run (exception aborts the install))
- other: Python modules requests and fernet importable in the build environment (run() imports both before the decrypt and download; they are declared in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The second stage is remote and was not fetched, so what it does and whether it adds its own gates is unknown.
- The name imitates PyTorch (typosquat); the description, author fields and class name are random strings.
- `requests` and `fernet` come in through `setup_requires`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "PyThrch",
    "version": "1.0.0",
    "archive_sha256": "06b0c126760a53709cbe2def8ea3c8380f2e90c9d7cb4eadf716adb80f1ae715",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/PyThrch-1.0.0.tar.gz",
    "package_root": "layer0/PyThrch-1.0.0",
    "cluster_key": "42c27a0d7d348297500cf27f1884341d6c6d88ad05ddfa428060aafb87c576de",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = wEEMCHqRWZtakTKNCyKxHQMSJuPcAcXLFwkWZhejfuKWsbJWaXnzUQhsdQNkvLosOsVqvfZmLIBlHXgnMvplnXdwInjza",
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
      "setup.py: read in full (one file, 44 lines). The Fernet token in the install override's run() was decrypted with the fernet_exec decoder (derivation d1); the plaintext is one exec(requests.get(...).text) line. Nothing unread.",
      "setup.py top-level code only calls setup(); the setup_py hook does nothing beyond registering the cmdclass override.",
      "The fetched second stage (paste served from funcaptcha[.]ru) is not in the package and was not fetched; its behaviour and any further gates are unknown."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "requests.get fetches the second-stage Python code over HTTPS; without it the exec has nothing to run (exception aborts the install)"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable in the build environment",
      "reason": "run() imports both before the decrypt and download; they are declared in setup_requires"
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
          "candidate": "k_0f6e239bd8",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 577,
            "end_byte": 592,
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
          "candidate": "q_fe86900e60",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 574,
            "end_byte": 1006,
            "node_type": "if_statement",
            "sha256": "0d490f798ccdcadf",
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
      "purpose_reason": "The download-and-exec stage only exists for Windows; on other OSes the override just runs the normal install.",
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
            "derived_from": "d1",
            "start_byte": 610,
            "end_byte": 796,
            "node_type": "stmt_range",
            "sha256": "015b26daa3acd1f9",
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
              "start_byte": 689,
              "end_byte": 749,
              "node_type": "call",
              "sha256": "da51d8a3d101becc",
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
              "start_byte": 684,
              "end_byte": 796,
              "node_type": "call",
              "sha256": "756ed50fd2e9ef89",
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
      "Fernet-encrypted stage passed to exec() (key literal next to the token)",
      "random-string class name, description and author metadata"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=PyThrch",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha fernet setup.py dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install override decrypts a hidden Fernet stage that, on Windows only, downloads Python code from a remote paste endpoint and exec()s it during pip install. The name imitates PyTorch.",
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
        "output_sha256": "ea6f441a211e1b7d"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "78ebdbd8d4138306"
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
