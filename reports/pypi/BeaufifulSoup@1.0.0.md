# pypi BeaufifulSoup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command, so its `run()` executes during a normal pip install. One gate, `os.name == "nt"`, guards the payload: on Windows it imports requests and fernet, then execs a Fernet-encrypted blob whose key is inline. The decrypted code (registered decoder `fernet_exec`, derivation d2) fetches a paste from hxxps://funcaptcha[.]ru/paste2?package=BeaufifulSoup, strips `<pre>` tags and execs the response. On any other OS only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = eGjCWqhktwlobYMUUWuEmihHPrTOCrnZOtPVcJowAQjcAGRSEKOvEbnSPErxIhbANKHyTGHPhPPrmpZgFaNZpruwnjmhqJsQLZWwSSQJTKowQrYePfmBIrUFrbAtlEHCSBbDpDetHFLTTiSkPotUwalqeWO`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (requests.get of the second-stage paste over HTTPS; exec of the response body)
- other: Python modules requests and fernet (providing Fernet) importable in the build env (imported inside the gated block before the fetch; pulled in via setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The second stage is remote and was not fetched, so what it does is unknown. A scanner needs Windows plus HTTPS access to funcaptcha[.]ru.
- `from fernet import Fernet` depends on the `fernet` package from setup_requires actually providing that name; if it does not, the import fails before the fetch. I could not check this statically.
- `derived/d1` was already in the folder with no matching derivation in prepared.json; its content matches the d2 I registered, and the record only cites d2.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeaufifulSoup",
    "version": "1.0.0",
    "archive_sha256": "c6d2c95ade7310592d63ef3a449e0c78d8ddbddcbb3901cef750e49f217767c5",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeaufifulSoup-1.0.0.tar.gz",
    "package_root": "layer0/BeaufifulSoup-1.0.0",
    "cluster_key": "f01c1acc969ad474ac52d7e176d33852fa2bcd3f3a82480c56a4b77f3a6b3fa5",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = eGjCWqhktwlobYMUUWuEmihHPrTOCrnZOtPVcJowAQjcAGRSEKOvEbnSPErxIhbANKHyTGHPhPPrmpZgFaNZpruwnjmhqJsQLZWwSSQJTKowQrYePfmBIrUFrbAtlEHCSBbDpDetHFLTTiSkPotUwalqeWO",
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
      "setup.py: read in full (39 lines, the only code file). Top-level code only builds metadata and calls setup(); the payload sits in the install cmdclass override run().",
      "The tool did not recover the Fernet-encrypted exec argument; registered decoder fernet_exec as derivation d2 (key and token are literals at the call site, HMAC verifies). Plaintext is a fetch of a remote paste that is exec'd.",
      "Fetched second stage (paste served from a .ru host, <pre> tags stripped, then exec) is not in the package and was not fetched; its behaviour is unknown.",
      "The Windows trove classifier is metadata only; pip does not refuse install on it, so no resolve gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "requests.get of the second-stage paste over HTTPS; exec of the response body"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet (providing Fernet) importable in the build env",
      "reason": "imported inside the gated block before the fetch; pulled in via setup_requires"
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
          "candidate": "k_9258e473ec",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 772,
            "end_byte": 787,
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
          "candidate": "q_74e822e983",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 769,
            "end_byte": 1201,
            "node_type": "if_statement",
            "sha256": "58005ecd02e935e5",
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
      "purpose_reason": "the download-and-exec stage only runs on Windows; other OSes just get a normal install",
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
            "derived_from": "d2",
            "start_byte": 805,
            "end_byte": 997,
            "node_type": "stmt_range",
            "sha256": "7eae1b02aaf90a38",
            "line": 14
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 884,
              "end_byte": 950,
              "node_type": "call",
              "sha256": "58fb608d12adc3e4",
              "line": 16
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 879,
              "end_byte": 997,
              "node_type": "call",
              "sha256": "4e8f74e5e96acece",
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
      "Fernet-encrypted stage with the key inline, passed to exec",
      "random junk class name and junk description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeaufifulSoup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet exec setup.py dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass decrypts an inline Fernet blob and execs it on Windows; the plaintext downloads code from a remote paste and execs it during pip install. The name typosquats beautifulsoup.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d2",
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
        "output_sha256": "0eb337735d35f5b4"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "46877ba88545c539"
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
