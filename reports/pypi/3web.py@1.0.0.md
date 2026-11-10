# pypi 3web.py@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command, so its `run` method executes during a normal pip install. One gate, `os.name == "nt"`, guards the payload: on Windows it imports `requests` and `fernet`, decrypts a Fernet token whose key is a literal, and execs the plaintext. The plaintext fetches a paste from funcaptcha[.]ru and execs the response text, so the real stage 2 comes from the server. On any other OS the install just continues with no extra behaviour.

## Execution

- **cmdclass** `cmdclass[install] = DpFMhODvroGoDnCshCTGkwqQxrBivxFhzDTcXDYgkdrGHVIyrOByNKEzBelYdSArSczWqNFJNwGAxarCectQKEOOiPXdaAZbIrNwONyRcRVvikLVubKSNNizGe`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (stage 2 is fetched over HTTPS with requests.get and then exec'd)
- other: Python modules requests and fernet importable during the build (imported inside the gated block; declared in setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- Stage 1 was decoded with the registered `fernet_exec` decoder (derivation d1); the payload sinks are cited in that copy.
- Stage 2 is remote and not in the package; whatever gates it contains are not recorded.
- Name, description and author strings are random filler; the Windows classifier is metadata only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "3web.py",
    "version": "1.0.0",
    "archive_sha256": "d5d208fb7bcd8b2408865952da37d9a47d76579bb4257f1d061469b1a272f5e0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/3web.py-1.0.0.tar.gz",
    "package_root": "layer0/3web.py-1.0.0",
    "cluster_key": "9f5d807a063e238c9630eb7eef589ba7575d2550dfb3ea0b044225e914303d25",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = DpFMhODvroGoDnCshCTGkwqQxrBivxFhzDTcXDYgkdrGHVIyrOByNKEzBelYdSArSczWqNFJNwGAxarCectQKEOOiPXdaAZbIrNwONyRcRVvikLVubKSNNizGe",
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
      "setup.py: read in full. The tool did not recover the exec(Fernet(key).decrypt(token)) call; key and token are literals, so it was decoded with registered decoder fernet_exec as d1. Nothing unread in the package.",
      "Decoded stage 1 fetches a remote paste and execs its text at install. Stage 2 lives on the server and is not in the package, so any gates inside it are not recorded here.",
      "Top-level setup.py only defines the install override and calls setup(); the payload runs only through cmdclass install. The Windows classifier is metadata, not an install restriction."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "stage 2 is fetched over HTTPS with requests.get and then exec'd"
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable during the build",
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
          "candidate": "k_fd98278765",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 943,
            "end_byte": 958,
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
          "candidate": "q_7bbd79f489",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 940,
            "end_byte": 1372,
            "node_type": "if_statement",
            "sha256": "9e38f77ad7fc90bb",
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
      "purpose_reason": "The download-and-exec stage only runs on Windows (os.name == 'nt'); elsewhere the install proceeds normally.",
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
            "start_byte": 976,
            "end_byte": 1372,
            "node_type": "block",
            "sha256": "68b7a1a69b4e4ff0",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 976,
            "end_byte": 1162,
            "node_type": "stmt_range",
            "sha256": "959e7bebd0ad6483",
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
              "start_byte": 1055,
              "end_byte": 1115,
              "node_type": "call",
              "sha256": "3bdacc65b9714c53",
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
              "start_byte": 1050,
              "end_byte": 1162,
              "node_type": "call",
              "sha256": "fbbd3ab129f33c49",
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
      "Fernet-encrypted stage 1 with the key as a literal, passed to exec",
      "random-looking class name, description and author strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=3web.py",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "fernet-exec funcaptcha paste dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override, on Windows only, decrypts a Fernet blob whose plaintext downloads Python code from a remote paste endpoint and execs it during pip install.",
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
        "output_sha256": "b355969f00413599"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "1bf7ffef363e3ec5"
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
