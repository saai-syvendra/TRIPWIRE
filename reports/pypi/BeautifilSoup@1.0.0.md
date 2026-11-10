# pypi BeautifilSoup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

BeautifilSoup 1.0.0 is an sdist whose setup.py overrides the setuptools `install` command, so the payload runs in `run()` on a normal pip install. One gate (`os.name == "nt"`) limits it to Windows. On Windows, `run()` imports `requests` and `fernet` (both from `setup_requires`) and execs a Fernet-encrypted stage; decrypted with the literal key, that stage downloads text from hxxps://funcaptcha[.]ru/paste2?package=BeautifilSoup and execs it. On other OSes only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = gSBKJYOsSblSQcGMHqBqnqGystlyiNOpJShlaeCqcaTaPhJJGsXiqYfjMPwhrQRFzlSNVrKuDSzljOqGTSPFRAGoNgWFtcQNxPMCXC`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (the second stage is fetched over HTTPS with requests.get and then exec'd)
- other: python modules fernet and requests importable during the build (run() imports both before the exec; they are pulled in through setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet stage was decrypted with the registered `fernet_exec` decoder (derivation d1); payload sinks are cited in the decoded copy.
- The fetched second stage was not retrieved, so what it does is unknown.
- The name typosquats beautifulsoup4; description strings and the class name are random letters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifilSoup",
    "version": "1.0.0",
    "archive_sha256": "0c27d85bf5a4215879b77260b910272686d2ff4014620130c3188d767df53a3a",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifilSoup-1.0.0.tar.gz",
    "package_root": "layer0/BeautifilSoup-1.0.0",
    "cluster_key": "b9f41e1a0ed74edaf12be599cca254216778e01630e0ea08f4533ac61817fce0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = gSBKJYOsSblSQcGMHqBqnqGystlyiNOpJShlaeCqcaTaPhJJGsXiqYfjMPwhrQRFzlSNVrKuDSzljOqGTSPFRAGoNgWFtcQNxPMCXC",
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
      "setup.py: read in full, including the Fernet-decrypted stage (derivation d1; key and token are literals at the exec call site); nothing unread",
      "setup_py hook: top-level setup.py only defines constants and calls setup(); the payload sits in run() of the install cmdclass override",
      "The decrypted stage fetches a remote paste and execs the response text after stripping <pre> tags; the fetched second stage was not retrieved (static only)"
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "the second stage is fetched over HTTPS with requests.get and then exec'd"
    },
    {
      "axis": "other",
      "value": "python modules fernet and requests importable during the build",
      "reason": "run() imports both before the exec; they are pulled in through setup_requires"
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
          "candidate": "k_57d3db4fbb",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 843,
            "end_byte": 858,
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
          "candidate": "q_681edbeae6",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 840,
            "end_byte": 1272,
            "node_type": "if_statement",
            "sha256": "8a0a3a71304f554e",
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
      "purpose_reason": "Windows only: on other OSes the payload is skipped and the normal install runs",
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
            "start_byte": 876,
            "end_byte": 1272,
            "node_type": "block",
            "sha256": "035bc333155d3b61",
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
              "start_byte": 955,
              "end_byte": 1021,
              "node_type": "call",
              "sha256": "ab219e9e36ffc47b",
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
              "start_byte": 950,
              "end_byte": 1068,
              "node_type": "call",
              "sha256": "04067b39f7944313",
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
      "Fernet-encrypted stage passed to exec (key literal in the code)",
      "random-letter class name and description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifilSoup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec paste dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override decrypts a Fernet-hidden stage that, on Windows, downloads code from a remote paste URL and execs it during pip install. The name typosquats beautifulsoup4.",
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
        "output_sha256": "ce9d2cbcbda0f89a"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "aae61642cd8595f1"
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
