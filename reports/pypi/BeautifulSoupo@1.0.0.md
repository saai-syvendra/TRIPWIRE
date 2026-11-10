# pypi BeautifulSoupo@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

BeautifulSoupo is an sdist whose `setup.py` overrides the setuptools `install` command, so the override runs on a normal pip install. Inside the override one gate, `os.name == "nt"`, guards the payload: on Windows it imports `requests` and `fernet` and passes a Fernet-decrypted string to `exec()`. The decrypted stage downloads code from hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoupo, strips `<pre>` tags and runs it with `exec()`. Any Windows host with the C2 reachable opens the gate; elsewhere only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = jleGCslecfyWiflyUmrzeSxSHQnJbWBSOBboFVrCCRbOzXyPyaITwtlbtarrtrBk`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is downloaded over HTTPS and passed to exec())
- other: Python modules requests and fernet importable during the build (setup_requires) (imported inside the gated block before the decrypt and download)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- Fernet key and token are literals at the call site; the decode is registered as derivation d1 (decoder `fernet_exec`) and the payload sinks are cited in it.
- The fetched second stage is not in the package and was not retrieved, so what it does is unknown.
- Name typosquats BeautifulSoup; `setup_requires` pulls in `fernet` and `requests`, which the gated block needs.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifulSoupo",
    "version": "1.0.0",
    "archive_sha256": "05733685a21291b06354a7a3fca27c36fe77d9d2628897064ea1fe0735174884",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifulSoupo-1.0.0.tar.gz",
    "package_root": "layer0/BeautifulSoupo-1.0.0",
    "cluster_key": "ed70a473f50dd9efc331fdde0d5ebdfe3615207242ed1e3940ed0d77224d0363",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = jleGCslecfyWiflyUmrzeSxSHQnJbWBSOBboFVrCCRbOzXyPyaITwtlbtarrtrBk",
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
      "setup.py: package code read in full; the Fernet token on line 16 was decrypted as data with the registered fernet_exec decoder (derivation d1) and the plaintext read in full. Nothing unread.",
      "The decrypted stage fetches hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoupo, strips <pre> tags and passes the response text to exec(). The fetched second stage is not in the package and was not retrieved.",
      "setup_py hook: top-level code only sets metadata and calls setup(). The Windows classifier is descriptive metadata, not a platform restriction pip enforces.",
      "If requests or fernet cannot be imported inside the gated block, the install override raises and the install fails; no error is swallowed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is downloaded over HTTPS and passed to exec()"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable during the build (setup_requires)",
      "reason": "imported inside the gated block before the decrypt and download"
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
          "candidate": "k_03f58c74e5",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 515,
            "end_byte": 530,
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
          "candidate": "q_4edb9ccd32",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 944,
            "node_type": "if_statement",
            "sha256": "8933bf447e1b6a4a",
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
      "purpose_reason": "The download-and-exec stage exists only for Windows; other OSes just run the normal install.",
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
            "start_byte": 548,
            "end_byte": 944,
            "node_type": "block",
            "sha256": "ccbcfbe324a41ad7",
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
              "start_byte": 627,
              "end_byte": 694,
              "node_type": "call",
              "sha256": "6b71f916306cec9c",
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
              "start_byte": 622,
              "end_byte": 741,
              "node_type": "call",
              "sha256": "02ffa67000f594cf",
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
      "random class name and metadata strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoupo",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha[.]ru Fernet exec dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override, on Windows only, decrypts a Fernet-encrypted stage that downloads code from a remote paste endpoint and runs it with exec(). The name typosquats BeautifulSoup.",
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
        "output_sha256": "89196d844df06e26"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "1efceaccb63a27ea"
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
