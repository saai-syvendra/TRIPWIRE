# pypi BeautifoulSoup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

BeautifoulSoup 1.0.0 is a typosquat of beautifulsoup4 whose `setup.py` overrides the `install` command, so the payload runs during a normal pip install of the sdist. The override has one gate, `os.name == "nt"` (Windows only). On Windows it exec()s a Fernet-encrypted stage whose key is a literal at the call site; decrypted (derivation d1), the stage fetches Python code from hxxps://funcaptcha[.]ru/paste2?package=BeautifoulSoup and exec()s the response text. Any other OS just gets the normal install.

## Execution

- **cmdclass** `cmdclass[install] = PSSdJkBTFFwntdOXTnLKrevoRUgqNCqGHILZOnbaxKyCYeOvjWLePkflKmigumbsBQZNQIMzHjX`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS from a paste endpoint and exec()d)
- other: Python packages requests and fernet importable in the build environment (the gated block imports both before the fetch; they are only declared in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet token was decrypted with the existing `fernet_exec` decoder module, not by running package code.
- The second stage is remote and was not fetched, so what it does is unknown. The paste endpoint needs to be reachable for anything past the download to happen.
- `requests` and `fernet` must be importable in the build environment; they are only declared in `setup_requires`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifoulSoup",
    "version": "1.0.0",
    "archive_sha256": "ffea41fc2d46cd37497186c6df951b496a5c48e072752a443da3b7874fc37527",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifoulSoup-1.0.0.tar.gz",
    "package_root": "layer0/BeautifoulSoup-1.0.0",
    "cluster_key": "6f1cf6504b4c15baa93e886ed5da190d695dec9b3823140bf736cdc8efc2e987",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PSSdJkBTFFwntdOXTnLKrevoRUgqNCqGHILZOnbaxKyCYeOvjWLePkflKmigumbsBQZNQIMzHjX",
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
      "setup.py: read in full. The Fernet token in the exec() call was not recovered by prepare.py; decrypted with the registered fernet_exec decoder (derivation d1, key literal at the call site). Nothing unread.",
      "Decoded stage is one line: exec() of requests.get(...).text with <pre> tags stripped. The fetched second stage is remote and not available, so behaviour past the exec is unknown.",
      "Top-level setup.py code (setup_py hook) only calls setup(); the payload sits in the install cmdclass override, which pip runs during the sdist wheel build."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS from a paste endpoint and exec()d"
    },
    {
      "axis": "other",
      "value": "Python packages requests and fernet importable in the build environment",
      "reason": "the gated block imports both before the fetch; they are only declared in setup_requires"
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
          "candidate": "k_5d44c2e6b7",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 618,
            "end_byte": 633,
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
          "candidate": "q_83f6a56b8a",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 615,
            "end_byte": 1047,
            "node_type": "if_statement",
            "sha256": "1ab8e481afaaf78d",
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
      "purpose_reason": "The download-and-exec stage only runs on Windows (os.name == nt); other platforms just do the normal install.",
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
            "start_byte": 651,
            "end_byte": 1047,
            "node_type": "block",
            "sha256": "51692a021601b668",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 651,
            "end_byte": 844,
            "node_type": "stmt_range",
            "sha256": "9674f8eb363e2cbf",
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
              "start_byte": 730,
              "end_byte": 797,
              "node_type": "call",
              "sha256": "be4c5d31884ae6ad",
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
              "start_byte": 725,
              "end_byte": 844,
              "node_type": "call",
              "sha256": "24e89abfa4e8d6a8",
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
      "Fernet-encrypted stage with the key as a literal at the call site, passed to exec()",
      "random-letter class name, description and long description"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifoulSoup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha paste2 Fernet dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override, on Windows only, decrypts a hidden stage that downloads Python code from a remote paste endpoint and exec()s it during pip install. The name typosquats beautifulsoup4.",
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
        "output_sha256": "75d544915a067e3e"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "dc616220fa0cc159"
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
