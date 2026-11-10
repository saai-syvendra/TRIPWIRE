# pypi 3web@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the `install` command, so its `run()` executes on a normal pip install. One gate (g1, `os.name == "nt"`) guards the payload: on Windows it decrypts an inline Fernet token and execs the plaintext, which fetches Python code from hxxps://funcaptcha[.]ru/paste2?package=3web, strips `<pre>` tags and execs it. On any other OS the install just runs normally. Opening the gate needs a Windows environment plus HTTPS reachability to the paste host.

## Execution

- **cmdclass** `cmdclass[install] = mJowwTqoErudaVwmWspimPYBAluUDzKFnJeJNqDsweftEtPzfwuSbeAwcAKhSjRqZUcWAznpthGjUlHUwABp`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched with requests.get over HTTPS and exec'd)
- installed_tool: requests, fernet (Python packages) (imported inside the gated block; declared in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was decoded with the existing `fernet_exec` decoder (derivation d1); payload anchors point into the decoded copy.
- The fetched second stage is not in the package and was not retrieved, so any gates inside it are unknown.
- Package name, class name and metadata strings are random or look-alike (3web vs web3); `setup_requires` pulls `fernet` and `requests`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "3web",
    "version": "1.0.0",
    "archive_sha256": "9481ac53c634fec9d75d943aaeee72d9a64dc8e24e28ec2433b547925158e8d1",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/3web-1.0.0.tar.gz",
    "package_root": "layer0/3web-1.0.0",
    "cluster_key": "470051f3018605b8ee1af4a25ad69794d08b86a1e67861d4dddbdacb1c9cd344",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = mJowwTqoErudaVwmWspimPYBAluUDzKFnJeJNqDsweftEtPzfwuSbeAwcAKhSjRqZUcWAznpthGjUlHUwABp",
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
      "setup.py: read in full. The exec'd Fernet token was decrypted with the registered fernet_exec decoder (derivation d1); the plaintext is one line that fetches a paste and execs it. Nothing unread in the package.",
      "The second stage served by the paste URL is not in the package and was not fetched; any gates it holds are unknown.",
      "Name 3web looks like a typosquat of web3 (name only; no copied web3 code).",
      "Both entry points are the same setup.py; setup.py top level only calls setup(), the payload sits in the install cmdclass run()."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage fetched with requests.get over HTTPS and exec'd"
    },
    {
      "axis": "installed_tool",
      "value": "requests, fernet (Python packages)",
      "reason": "imported inside the gated block; declared in setup_requires"
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
          "candidate": "k_c0776dc424",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 835,
            "end_byte": 850,
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
          "candidate": "q_46688c0788",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 832,
            "end_byte": 1244,
            "node_type": "if_statement",
            "sha256": "74475dce0faf139c",
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
      "purpose_reason": "The encrypted downloader only runs on Windows (os.name == 'nt'); other systems just run the normal install.",
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
            "start_byte": 868,
            "end_byte": 1244,
            "node_type": "block",
            "sha256": "62c437685f3cbc25",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 868,
            "end_byte": 1051,
            "node_type": "stmt_range",
            "sha256": "9fcdb625447ea787",
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
              "start_byte": 947,
              "end_byte": 1004,
              "node_type": "call",
              "sha256": "8b89ce4e66c33fa4",
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
              "start_byte": 942,
              "end_byte": 1051,
              "node_type": "call",
              "sha256": "5d2e5318af7bda2e",
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
      "Fernet-encrypted code passed to exec() with the key inline",
      "random-string class name, description and author fields"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=3web",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet exec paste downloader",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the overridden install command decrypts an inline Fernet blob and execs it; the plaintext downloads Python code from a remote paste and execs it during pip install.",
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
        "output_sha256": "ef03638955d6231b"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "c83dde23dd9abace"
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
