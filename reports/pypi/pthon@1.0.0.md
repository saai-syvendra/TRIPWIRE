# pypi pthon@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with a randomly named class whose `run` method executes during a normal pip install. One gate, `os.name == "nt"`, guards the payload: on Windows it imports `requests` and `fernet`, decrypts a Fernet token whose key sits next to it, and execs the plaintext. The plaintext fetches Python from a paste endpoint on funcaptcha[.]ru and execs it after stripping `<pre>` tags. On other platforms only the normal install runs, so a stock Linux sandbox sees nothing.

## Execution

- **cmdclass** `cmdclass[install] = XvKrnCZpwXHzEOMsqgUMQlRtwVvhlUPqVnNxUCfqcRXTCElWsuruCohkvOWYlMrhfNNWoJUQoROjzewbQGBwrmTuhgSWYklVgtBjHTWSPpKyFF`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS from a paste endpoint and exec'd)
- other: python packages requests and fernet importable in the build environment (the gated block imports both before decrypting and fetching; declared only in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- Fernet stage recovered with the registered `fernet_exec` decoder (derived d1); the remote second stage is not recovered.
- The payload also needs `requests` and `fernet` importable at build time (declared via `setup_requires`) and the endpoint reachable.
- Random filler in description, long description and author fields; family hint is based on the endpoint path pattern in the decrypted code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pthon",
    "version": "1.0.0",
    "archive_sha256": "36d005a0d15b185977290bc0214d32d38456776b7a498d171b89300374c94a2f",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pthon-1.0.0.tar.gz",
    "package_root": "layer0/pthon-1.0.0",
    "cluster_key": "7f60c3ab043b887ab9780c3e314864775f125d1e58d9aeb22fe6adda2380c128",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = XvKrnCZpwXHzEOMsqgUMQlRtwVvhlUPqVnNxUCfqcRXTCElWsuruCohkvOWYlMrhfNNWoJUQoROjzewbQGBwrmTuhgSWYklVgtBjHTWSPpKyFF",
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
      "setup.py: read in full; the Fernet token in the install override was decrypted with the registered fernet_exec decoder (derived d1, key literal at the call site) and the plaintext read in full; nothing unread.",
      "Top-level setup.py code (setup_py hook) only calls setup() with literal metadata; all behaviour is in the cmdclass install override.",
      "Decrypted stage: exec(requests.get(<paste URL>).text with <pre> tags stripped). The fetched code is remote and not recovered; its own gates, if any, are unknown.",
      "Classifier 'Operating System :: Microsoft :: Windows' is descriptive metadata and does not restrict install, so it is not a manifest gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS from a paste endpoint and exec'd"
    },
    {
      "axis": "other",
      "value": "python packages requests and fernet importable in the build environment",
      "reason": "the gated block imports both before decrypting and fetching; declared only in setup_requires"
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
          "candidate": "k_9281b98305",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 903,
            "end_byte": 918,
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
          "candidate": "q_66ed331f6b",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 900,
            "end_byte": 1312,
            "node_type": "if_statement",
            "sha256": "28bffc5157eeaec7",
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
      "purpose_reason": "The download-and-exec stage only exists for Windows (os.name == 'nt'); other platforms just run the normal install.",
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
            "start_byte": 936,
            "end_byte": 1312,
            "node_type": "block",
            "sha256": "f3ce47dccae0dd46",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 936,
            "end_byte": 1120,
            "node_type": "stmt_range",
            "sha256": "fa24bd97720e3bc8",
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
              "start_byte": 1015,
              "end_byte": 1073,
              "node_type": "call",
              "sha256": "9fd08ec0d274dc4b",
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
              "start_byte": 1010,
              "end_byte": 1120,
              "node_type": "call",
              "sha256": "8a4fa41cb81455df",
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
      "Fernet-encrypted stage with the key literal at the call site, passed to exec()",
      "random-looking class name, description and long_description"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=pthon",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha paste2 Fernet dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override decrypts a Fernet blob and execs it; the plaintext fetches Python from a remote paste endpoint and execs it, only when os.name is 'nt'.",
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
        "output_sha256": "eef7567a15a9428e"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "85b3d35d110fb78a"
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
