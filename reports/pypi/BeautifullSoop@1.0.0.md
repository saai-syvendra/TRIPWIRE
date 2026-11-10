# pypi BeautifullSoop@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

BeautifullSoop is an sdist whose `setup.py` overrides the setuptools `install` command, so its `run` method executes on a normal pip install. One gate (`os.name == "nt"`) guards everything: on Windows the override decrypts a Fernet token (key literal in the file) and `exec()`s it. The decoded stage fetches code from hxxps://funcaptcha[.]ru/paste2?package=BeautifullSoop, strips `<pre>` tags and `exec()`s the response. On other OSes the package just installs with no extra behaviour.

## Execution

- **cmdclass** `cmdclass[install] = luFYZSxyDVnwtWlFzKtzatJBjiEdDrzgVxIujpIzDkaJGBEmiVqTMfSUevIhhpEUeGQtLEhBLpterDuSSUSyRQPQpdDHfqfBZktZiflATTDfTQRtgfUFdkyanxkOHmQjSRmSqeKonINgTbnYavvuHT`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched over HTTPS and exec()d)
- other: python modules fernet and requests importable (imported inside the gate before the fetch; supplied through setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- Fernet stage decoded with the registered `fernet_exec` decoder (derivation d1); the download sink is cited in the decoded copy, the exec sink in the original file.
- The remote second stage is not available and was not analysed, so any gates inside it are unknown.
- Name typosquats beautifulsoup4; `fernet` and `requests` come in through `setup_requires`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifullSoop",
    "version": "1.0.0",
    "archive_sha256": "4108e0a81430fac7a8a5bf1ea199802b9000da9cf129651a4555eba1213b84b7",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifullSoop-1.0.0.tar.gz",
    "package_root": "layer0/BeautifullSoop-1.0.0",
    "cluster_key": "2e8120e913e552dc0e1484ed2e2fd4c5a0bbf585c19193deeed8ea2c54ec152a",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = luFYZSxyDVnwtWlFzKtzatJBjiEdDrzgVxIujpIzDkaJGBEmiVqTMfSUevIhhpEUeGQtLEhBLpterDuSSUSyRQPQpdDHfqfBZktZiflATTDfTQRtgfUFdkyanxkOHmQjSRmSqeKonINgTbnYavvuHT",
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
      "setup.py: read in full; the Fernet-encrypted stage (key and token both literal in setup.py) decoded with the registered decoder fernet_exec (derivation d1) and read in full; nothing unread.",
      "Decoded stage fetches hxxps://funcaptcha[.]ru/paste2?package=BeautifullSoop, strips <pre> tags and exec()s the response, Windows only. The remote second stage is not available and was not analysed.",
      "setup_py entry: top-level setup.py only declares setup() with the cmdclass override; no other install-time code. The Windows classifier is metadata, not an install restriction."
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
      "value": "python modules fernet and requests importable",
      "reason": "imported inside the gate before the fetch; supplied through setup_requires"
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
          "candidate": "k_2f6f7fb89a",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 774,
            "end_byte": 789,
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
          "candidate": "q_1e1f84fac5",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 771,
            "end_byte": 1203,
            "node_type": "if_statement",
            "sha256": "868c8672cf10c80e",
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
      "purpose_reason": "the remote stage is fetched and run only on Windows (os.name == nt); other OSes just install normally",
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
            "start_byte": 807,
            "end_byte": 1203,
            "node_type": "block",
            "sha256": "3463234c21aa3002",
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
              "start_byte": 886,
              "end_byte": 953,
              "node_type": "call",
              "sha256": "dc1b513c3a38ef5c",
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
              "start_byte": 881,
              "end_byte": 1203,
              "node_type": "call",
              "sha256": "4ba636e7b1b4205e",
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
      "Fernet-encrypted stage with literal key passed to exec()",
      "random-looking class name and description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifullSoop",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha paste2 Fernet setup.py dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The cmdclass install override decrypts a Fernet-hidden stage that, on Windows, downloads code from a remote paste endpoint and exec()s it during pip install. The name typosquats beautifulsoup4.",
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
        "output_sha256": "32ce751482958138"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "677a8fa964a821eb"
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
