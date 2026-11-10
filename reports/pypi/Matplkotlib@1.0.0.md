# pypi Matplkotlib@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Matplkotlib is a matplotlib typosquat whose sdist overrides the setuptools `install` command, so its `run` method executes during pip install. One gate exists: `os.name == "nt"`. On Windows the override decrypts a Fernet token (key in the code) and execs the result, which downloads text from hxxps://funcaptcha[.]ru/paste2?package=Matplkotlib, strips `<pre>` tags and execs it. On any other OS only the normal install runs. A Windows VM with outbound HTTPS and the `requests` and `fernet` modules available opens the gate.

## Execution

- **cmdclass** `cmdclass[install] = ialFOqPipkxaprBeNHbFEkArQftMPDTKDgEOzCIjmGyUcshVczePEuMjJqbZgRUTyjmPidpIRKKRswhhGlPkaYuehZBcnxkvaDbB`: runs setup.py; direct_script, download_then_exec, decoded_eval.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is downloaded over HTTPS and executed)
- other: Python modules requests and fernet importable in the build environment (declared in setup_requires) (the payload imports both before the download)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet stage was decoded with the registered `fernet_exec` decoder (derivation d1); the payload sinks are cited in the decoded copy.
- The second stage was not fetched, so what it does is unknown.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "Matplkotlib",
    "version": "1.0.0",
    "archive_sha256": "2820fc63e6fe0f4b516c267c8cdb918dd8239d395d16de2378cf16e1b36c2099",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/Matplkotlib-1.0.0.tar.gz",
    "package_root": "layer0/Matplkotlib-1.0.0",
    "cluster_key": "3528005db02983ac30828c9000d2e325ec8d48073321be0b760abe2b28463a45",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = ialFOqPipkxaprBeNHbFEkArQftMPDTKDgEOzCIjmGyUcshVczePEuMjJqbZgRUTyjmPidpIRKKRswhhGlPkaYuehZBcnxkvaDbB",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "decoded_eval"
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
      "setup.py: package code read in full; the Fernet-encrypted stage (key and token are literals at the call site) was decoded with the registered fernet_exec decoder (derivation d1); nothing unread.",
      "Decoded stage: GET hxxps://funcaptcha[.]ru/paste2?package=Matplkotlib, strip <pre> tags, exec() the response text. The second stage was not fetched and is not analysed.",
      "setup_py entry: top-level setup.py only defines metadata and the cmdclass; the payload runs through the install override, which pip's sdist build runs."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is downloaded over HTTPS and executed"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable in the build environment (declared in setup_requires)",
      "reason": "the payload imports both before the download"
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
          "candidate": "k_583d3b5881",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 726,
            "end_byte": 741,
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
          "candidate": "q_dfd8e4e385",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 723,
            "end_byte": 1155,
            "node_type": "if_statement",
            "sha256": "05ee25ac9746a542",
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
      "purpose_reason": "the download-and-exec stage only exists for Windows; elsewhere the normal install runs",
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
            "start_byte": 759,
            "end_byte": 1155,
            "node_type": "block",
            "sha256": "8c578e48932b7dd7",
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
              "start_byte": 838,
              "end_byte": 902,
              "node_type": "call",
              "sha256": "2e17f0b7b4779ebd",
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
              "start_byte": 833,
              "end_byte": 949,
              "node_type": "call",
              "sha256": "460d983c4d37d542",
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
    "level": "light",
    "techniques": [
      "Fernet-encrypted stage (key in the code) run through exec()",
      "random class name and filler description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=Matplkotlib",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha[.]ru Fernet exec dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override, on Windows only, decrypts a Fernet-hidden stage that downloads code from a remote paste endpoint and executes it during pip install. The name typosquats matplotlib.",
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
        "output_sha256": "4868cb2306000c64"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "86d0de1c329e3d3b"
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
