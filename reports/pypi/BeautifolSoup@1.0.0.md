# pypi BeautifolSoup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

On `pip install` of the sdist, setuptools runs the package's `install` cmdclass override. Its `run` method has one gate, `os.name == "nt"`. On Windows it imports `requests` and `fernet`, decrypts a Fernet token whose key sits next to it, and exec()s the result. That stage fetches Python code from a remote paste URL (hxxps://funcaptcha[.]ru/paste2?package=BeautifolSoup) and exec()s it. On other platforms only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = EqncTsBRijLGcHsoUxSkvBVEeDINDIqofyCdLWkMpkkfTOdMeeEMXzmFrabHSPFwYuZYxmuoQVvfMknCkifhAWIsUhpsFDxsBZsYYMFbtsEyAPVwZVYrTdQmWlgzkxJBpTnetuLYhZNnFRndMqDYjOSJutHJEmAfnPrpmXJZNQLOcDOVK`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched over HTTPS and exec()d)
- other: Python packages fernet and requests importable (declared in setup_requires) (the override imports both before decrypting and fetching)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was decoded statically with the registered `fernet_exec` decoder (derivation d1). The remote second stage was not fetched, so its behaviour is unknown.
- `fernet` and `requests` come from `setup_requires`; the payload needs them plus HTTPS access to the paste host.
- The name typosquats BeautifulSoup.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifolSoup",
    "version": "1.0.0",
    "archive_sha256": "498dd59690195f6c272c56a9849d0c41d3a500fa0337e406c426910aa390c28f",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifolSoup-1.0.0.tar.gz",
    "package_root": "layer0/BeautifolSoup-1.0.0",
    "cluster_key": "5b9d40335bad1572035c019712fe2534810a06d2d7143361ce2775578f4a377c",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = EqncTsBRijLGcHsoUxSkvBVEeDINDIqofyCdLWkMpkkfTOdMeeEMXzmFrabHSPFwYuZYxmuoQVvfMknCkifhAWIsUhpsFDxsBZsYYMFbtsEyAPVwZVYrTdQmWlgzkxJBpTnetuLYhZNnFRndMqDYjOSJutHJEmAfnPrpmXJZNQLOcDOVK",
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
      "setup.py: read in full. The install override exec()s a Fernet token decrypted with a key literal at the call site; decoded statically with the registered fernet_exec decoder (derivation d1). Nothing unread.",
      "Decoded stage fetches a paste URL with requests.get, strips <pre> tags and exec()s the response. The remote stage was not fetched, so what it does is not known.",
      "setup_py hook: top-level code only defines the class and calls setup(); no behaviour outside the cmdclass install override.",
      "The Windows classifier in setup() is descriptive metadata, not an installer restriction, so it is not a gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage fetched over HTTPS and exec()d"
    },
    {
      "axis": "other",
      "value": "Python packages fernet and requests importable (declared in setup_requires)",
      "reason": "the override imports both before decrypting and fetching"
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
          "candidate": "k_e1134b049a",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 747,
            "end_byte": 762,
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
          "candidate": "q_41859eae33",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 744,
            "end_byte": 1176,
            "node_type": "if_statement",
            "sha256": "e48c82b743cc6842",
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
      "purpose_reason": "the encrypted downloader only runs on Windows (os.name == 'nt'); other platforms just install",
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
            "start_byte": 780,
            "end_byte": 1176,
            "node_type": "block",
            "sha256": "a5f82dcf4a33724c",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 780,
            "end_byte": 972,
            "node_type": "stmt_range",
            "sha256": "a46b5710434c0728",
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
              "start_byte": 859,
              "end_byte": 925,
              "node_type": "call",
              "sha256": "078311483da19c48",
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
              "start_byte": 854,
              "end_byte": 972,
              "node_type": "call",
              "sha256": "0afcd859197a621e",
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
      "Fernet-encrypted stage exec()d, key embedded at the call site",
      "remote code fetched and exec()d",
      "random-looking class name, description and author strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifolSoup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec paste downloader",
  "claude_assessment": "malicious",
  "assessment_reason": "The custom install command, on Windows only, decrypts an embedded Fernet stage that downloads Python code from a remote paste endpoint and exec()s it. The name imitates BeautifulSoup.",
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
        "output_sha256": "52c0088416f441fc"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "1832097c07985917"
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
