# pypi BeaitifulSoop@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command, so the override's `run` executes during a normal pip install. One gate (`os.name == "nt"`) guards the payload: on Windows it decrypts an embedded Fernet token (key literal beside it) and `exec`s the plaintext, which fetches text from hxxps://funcaptcha[.]ru/paste2?package=BeaitifulSoop, strips `<pre>` tags and `exec`s it. On any other OS the override just runs the normal install. A Windows machine with HTTPS access to that host, plus `requests` and `fernet` available from `setup_requires`, opens the gate.

## Execution

- **cmdclass** `cmdclass[install] = SdkyjKanrBTEfBpHlMewtSQnHHDDtrLDcyDwdkTSWzPyDoipviaReOCQsegfRUYDvMIvhIQwFvspYfRDngHPUZJRZEWynjMbFemcCQYaxbuJerMeJMYHOEQMCCWHQVLlTdAiS`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (the second stage is downloaded over HTTPS from this host and exec'd)
- other: Python packages requests and fernet importable during the build (declared in setup_requires) (the override imports requests and fernet.Fernet before decrypting and running the stage)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was decoded with the registered `fernet_exec` decoder (derivation d1); the download sink is cited in the decoded copy, the exec sink in the original file.
- The remote second stage was not fetched, so its behaviour is not recovered.
- The Windows classifier in `setup()` is metadata only and not enforced by pip, so it is not recorded as a manifest gate.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeaitifulSoop",
    "version": "1.0.0",
    "archive_sha256": "135fa54416d95c905205b09b31f98c048c90bdc1c591d184d268e371d26f8505",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeaitifulSoop-1.0.0.tar.gz",
    "package_root": "layer0/BeaitifulSoop-1.0.0",
    "cluster_key": "e1076bbc46fb1355b70c59ce07dd774e05c53697eb7021491ff122fc9371ef59",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = SdkyjKanrBTEfBpHlMewtSQnHHDDtrLDcyDwdkTSWzPyDoipviaReOCQsegfRUYDvMIvhIQwFvspYfRDngHPUZJRZEWynjMbFemcCQYaxbuJerMeJMYHOEQMCCWHQVLlTdAiS",
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
      "setup.py: read in full. The install override's exec() argument is a Fernet token with the key literal beside it; the extractor did not decode it, so I registered decoder fernet_exec (derivation d1) and read the plaintext: a requests.get of a remote paste whose text is exec'd.",
      "setup.py top level only calls setup(); the Windows classifier is descriptive metadata pip does not enforce, so it is not a manifest gate.",
      "The remote second stage is not in the package and was not fetched, so what it does is not recovered."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "the second stage is downloaded over HTTPS from this host and exec'd"
    },
    {
      "axis": "other",
      "value": "Python packages requests and fernet importable during the build (declared in setup_requires)",
      "reason": "the override imports requests and fernet.Fernet before decrypting and running the stage"
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
          "candidate": "k_476ec087cf",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 710,
            "end_byte": 725,
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
          "candidate": "q_be3c4f5aa6",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 707,
            "end_byte": 1139,
            "node_type": "if_statement",
            "sha256": "a3bf509330f7cfc8",
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
      "purpose_reason": "the download-and-exec stage only runs on Windows; other OSes just get the normal install",
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
            "start_byte": 743,
            "end_byte": 1139,
            "node_type": "block",
            "sha256": "08efd756cb5af611",
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
              "start_byte": 822,
              "end_byte": 888,
              "node_type": "call",
              "sha256": "0ee5598f076bed24",
              "line": 16
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 817,
              "end_byte": 1139,
              "node_type": "call",
              "sha256": "b4b58efd42f64cde",
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
      "Fernet-encrypted stage with key literal at the call site, passed to exec()",
      "random-letter class name and description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeaitifulSoop",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec setup.py dropper (funcaptcha[.]ru paste2)",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override, on Windows only, decrypts an embedded Fernet token whose plaintext downloads code from a remote paste and exec's it during pip install. The name typosquats BeautifulSoup.",
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
        "output_sha256": "ff5613bf5dced833"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "b9fe5037b7bd750f"
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
