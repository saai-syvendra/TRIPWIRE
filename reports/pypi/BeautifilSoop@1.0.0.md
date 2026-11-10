# pypi BeautifilSoop@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with a randomly named class whose `run()` executes on a normal pip install. One gate, `os.name == "nt"`, guards everything: on Windows the code imports `requests` and `fernet` (both pulled in through `setup_requires`) and `exec()`s a Fernet-encrypted stage whose key sits at the call site. Decrypted as data, that stage downloads text from hxxps://funcaptcha[.]ru/paste2?package=BeautifilSoop and executes it. On other platforms only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = rocmHHrijBcmzijaSQkTVWOSuJgNbxjOVdrmnKcuCnfDITHmkggIyLMhPqDPSvLEWHZTZKTfpYivmJOsRvfIONEGauijLFsKkqtjGNykwGIUmBhKbJxLAeXPyyqBbRBPTufzrzOCORQMcwqrxIziqydHkcWBwfFhyqsNyWeTKfzOeGnelATiClIhTgLgwZQIigYTeOuv`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched over HTTPS and executed)
- other: setup_requires fernet and requests installable (PyPI reachable) (both are imported inside the gated block before the fetch)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet decode is registered as derivation d1 (decoder `fernet_exec`), and the payload sinks are cited in the decoded file.
- The second stage is remote and was not fetched, so what it does is unknown.
- The name typosquats beautifulsoup4.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifilSoop",
    "version": "1.0.0",
    "archive_sha256": "21287854fe23183b9664861377aa0be38331958554f179df2b86d2a7a0620c40",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifilSoop-1.0.0.tar.gz",
    "package_root": "layer0/BeautifilSoop-1.0.0",
    "cluster_key": "c56cca76e9f4e9e0d72b268c7814059ff5cfbdd049256c310562ff656e0b5946",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = rocmHHrijBcmzijaSQkTVWOSuJgNbxjOVdrmnKcuCnfDITHmkggIyLMhPqDPSvLEWHZTZKTfpYivmJOsRvfIONEGauijLFsKkqtjGNykwGIUmBhKbJxLAeXPyyqBbRBPTufzrzOCORQMcwqrxIziqydHkcWBwfFhyqsNyWeTKfzOeGnelATiClIhTgLgwZQIigYTeOuv",
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
      "setup.py: read in full; the Fernet token at line 16 was decrypted as data with the registered decoder fernet_exec (derivation d1) and the decoded stage read in full; nothing unread.",
      "The decoded stage fetches a remote paste and exec()s its text after stripping <pre> tags. The second stage is not in the package and was not fetched.",
      "setup_py hook: top-level code only defines the install override and calls setup(); no behaviour outside the cmdclass run().",
      "Package name typosquats beautifulsoup4."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage fetched over HTTPS and executed"
    },
    {
      "axis": "other",
      "value": "setup_requires fernet and requests installable (PyPI reachable)",
      "reason": "both are imported inside the gated block before the fetch"
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
          "candidate": "k_c578b32766",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 897,
            "end_byte": 912,
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
          "candidate": "q_c2493c6ccb",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 894,
            "end_byte": 1326,
            "node_type": "if_statement",
            "sha256": "b4efe4725f5a4e18",
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
      "purpose_reason": "the download-and-exec stage only runs on Windows (os.name == nt); nothing runs on other platforms",
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
            "start_byte": 930,
            "end_byte": 1326,
            "node_type": "block",
            "sha256": "761db96d58fe8a0b",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 930,
            "end_byte": 1122,
            "node_type": "stmt_range",
            "sha256": "7735d35be742c2ec",
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
              "start_byte": 1009,
              "end_byte": 1075,
              "node_type": "call",
              "sha256": "1aa32e32cf21b8fd",
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
              "start_byte": 1004,
              "end_byte": 1122,
              "node_type": "call",
              "sha256": "b06d83b8f8152b49",
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
      "Fernet-encrypted stage with the key literal at the call site, passed to exec()",
      "random identifier and description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifilSoop",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha paste2 Fernet dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override decrypts a Fernet-hidden stage that, on Windows only, downloads code from a remote paste and executes it during pip install. The package name typosquats beautifulsoup4.",
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
        "output_sha256": "c781f4415fab4069"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "e2fb6f876935c774"
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
