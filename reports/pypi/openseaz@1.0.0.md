# pypi openseaz@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command with a randomly named subclass, so its `run()` executes on a normal pip install. One gate, `os.name == "nt"`, guards the payload: on Windows it imports `requests` and `fernet` and calls `exec()` on a Fernet-decrypted string whose key sits inline. The decrypted stage downloads text from hxxps://funcaptcha[.]ru/paste2?package=openseaz, strips `<pre>` tags and runs it with `exec()`. On other platforms the install proceeds normally with no other behaviour.

## Execution

- **cmdclass** `cmdclass[install] = HdZloVndaRlJcMEMNkBjIQBFQxSXMtejQKpbTcBrZKWmOYzjDbRwMOmtElyTXoSNZTNXaKwQajplzLAQFlTOAIBcvBwsQfxMONsrubqRLcPcIvImuGpeLHNjBxPGqaAItyEaZyuLRAnUJKyOasItVrFxmhHPpMeEBRDuNfIklwlIKbUCUrESQtrhMGXIO`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS and exec'd)
- other: python modules requests and fernet importable (imported inside the gate before the decrypt; supplied through setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was decrypted statically with the registered `fernet_exec` decoder (derived d1); the second stage is remote and was not recovered.
- The code imports the PyPI `fernet` package (via setup_requires), not `cryptography.fernet`; API compatibility was not checked, so the stager may fail in practice.
- Name looks like a typosquat of the OpenSea brand; description and author fields are random filler.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "openseaz",
    "version": "1.0.0",
    "archive_sha256": "02b5130d9265cba6d0f2cf1244e96b42e5500beb48b511b1760a061d6f2100fb",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/openseaz-1.0.0.tar.gz",
    "package_root": "layer0/openseaz-1.0.0",
    "cluster_key": "cd796d089def6776d1b5fe7594a26eb00a0dbcb7fa340875cdf7ce05fc517c33",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = HdZloVndaRlJcMEMNkBjIQBFQxSXMtejQKpbTcBrZKWmOYzjDbRwMOmtElyTXoSNZTNXaKwQajplzLAQFlTOAIBcvBwsQfxMONsrubqRLcPcIvImuGpeLHNjBxPGqaAItyEaZyuLRAnUJKyOasItVrFxmhHPpMeEBRDuNfIklwlIKbUCUrESQtrhMGXIO",
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
      "setup.py: read in full; the Fernet-encrypted exec() argument was decrypted with the registered fernet_exec decoder (key is a literal at the call), derived d1; nothing unread.",
      "setup_py hook: top level only defines constants and the install subclass and calls setup(); no gate or payload outside the cmdclass run().",
      "Decoded stage fetches text from a remote paste endpoint, strips <pre> tags and passes it to exec(). The second stage is not in the package and was not recovered.",
      "Code imports `fernet` (a PyPI package pulled by setup_requires) rather than cryptography.fernet; whether that module's API matches was not checked, so the decrypt may fail at install."
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
      "value": "python modules requests and fernet importable",
      "reason": "imported inside the gate before the decrypt; supplied through setup_requires"
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
          "candidate": "k_21180158ca",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 619,
            "end_byte": 634,
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
          "candidate": "q_4f84e79bf1",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 616,
            "end_byte": 1048,
            "node_type": "if_statement",
            "sha256": "a82ca781531a7a2c",
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
      "purpose_reason": "the download-and-exec stager only runs on Windows (os.name nt); elsewhere the install just proceeds",
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
            "start_byte": 652,
            "end_byte": 1048,
            "node_type": "block",
            "sha256": "5a3dcb54974e4092",
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
              "start_byte": 731,
              "end_byte": 792,
              "node_type": "call",
              "sha256": "5388dc015ab13f43",
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
              "start_byte": 726,
              "end_byte": 839,
              "node_type": "call",
              "sha256": "34c7cbbc5098c19f",
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
      "Fernet-encrypted exec() stage with the key inline",
      "random class name and filler description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=openseaz",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha[.]ru paste2 Fernet stager",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the install command override decrypts an embedded Fernet stage that downloads code from a remote paste endpoint and runs it with exec() during pip install.",
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
        "output_sha256": "61e25bf3c3da4159"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "516863aa976e7f04"
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
