# pypi BeautifullSooup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command, so its `run` method executes on a normal pip install of the sdist. Inside it one gate, `os.name == "nt"`, guards an `exec()` of a Fernet-encrypted string whose key and token are literals at the call site. Decrypted (registered decoder `fernet_exec`, derived d1), the stage calls `requests.get` on a paste endpoint at funcaptcha[.]ru, strips `<pre>` tags from the response and `exec()`s it. A Windows host with outbound HTTPS to that host opens the gate; on other platforms the install just proceeds.

## Execution

- **cmdclass** `cmdclass[install] = vYBRdBcibKUqIekECLEWINRcyTTjpvYnzlLkFAkAeoUQvGUTPOBCSVJrElcQVaonxnlcWyuPbSvSDCUUuegPNfUyEXPgKiYtURJtXuaDlkXSTEGHNDJIADfdyZKVEZUrSKPcqKtXYFpHJghJIBmviudZmWAQlbxcFEPZDKIjPsVWmIvTBEvTwDVmTr`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched over HTTPS and exec'd)
- other: python packages requests and fernet importable at build time (imported inside the gated block; declared in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The second stage is remote and was not fetched, so what it does is unknown.
- `requests` and `fernet` come in through `setup_requires`; there is no try/except, so a failed fetch breaks the install.
- The package name looks like a typosquat of BeautifulSoup; the description and author fields are random strings.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifullSooup",
    "version": "1.0.0",
    "archive_sha256": "b2a6e5d9a92c8870b973c391a608b4132bb45cfae1dd6b5a9c5eb1f0a4835fa7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifullSooup-1.0.0.tar.gz",
    "package_root": "layer0/BeautifullSooup-1.0.0",
    "cluster_key": "1330303243d7b890cba43a7d12a640c78887b8f35f90543c7aa0573d1e1c3b81",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = vYBRdBcibKUqIekECLEWINRcyTTjpvYnzlLkFAkAeoUQvGUTPOBCSVJrElcQVaonxnlcWyuPbSvSDCUUuegPNfUyEXPgKiYtURJtXuaDlkXSTEGHNDJIADfdyZKVEZUrSKPcqKtXYFpHJghJIBmviudZmWAQlbxcFEPZDKIjPsVWmIvTBEvTwDVmTr",
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
      "setup.py: read in full. The install override exec()s a Fernet-encrypted stage (key and token literal at the call site); decrypted with registered decoder fernet_exec as derived d1. Nothing unread.",
      "Decrypted stage (d1 line 16): requests.get on a paste URL, strips <pre> tags from the response text and exec()s it. The second stage is remote and was not fetched.",
      "setup_py hook: top-level setup.py only defines the override class and calls setup(); no gates or behaviour outside the cmdclass install override.",
      "No try/except around the fetch or exec, so a failed fetch aborts the install rather than failing silently."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage fetched over HTTPS and exec'd"
    },
    {
      "axis": "other",
      "value": "python packages requests and fernet importable at build time",
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
          "candidate": "k_294136ae41",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 939,
            "end_byte": 954,
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
          "candidate": "q_cea0798fe1",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 936,
            "end_byte": 1368,
            "node_type": "if_statement",
            "sha256": "3e687e3563df1c6c",
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
      "purpose_reason": "the remote stage is fetched and run only on Windows (os.name == 'nt'); elsewhere the install just proceeds",
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
            "start_byte": 972,
            "end_byte": 1368,
            "node_type": "block",
            "sha256": "998d5f6a4d17a312",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 972,
            "end_byte": 1166,
            "node_type": "stmt_range",
            "sha256": "7a8c65a7de1106be",
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
              "start_byte": 1051,
              "end_byte": 1119,
              "node_type": "call",
              "sha256": "fd07c44f7e4fff6e",
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
              "start_byte": 1046,
              "end_byte": 1166,
              "node_type": "call",
              "sha256": "19d037936516074e",
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
      "Fernet-encrypted stage passed to exec() (key and token literal at the call site)",
      "random long class name and random metadata strings",
      "second stage fetched from a remote paste endpoint at install"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifullSooup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec paste loader",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, the install override decrypts a Fernet-hidden stage that downloads code from a remote paste endpoint and exec()s it during pip install. The name typosquats beautifulsoup4/BeautifulSoup.",
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
        "output_sha256": "e9b83934aca2e7f6"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "a76e00f5eb22ae67"
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
