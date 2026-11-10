# pypi BeautifulSoop@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with a randomly named class whose `run` method executes during pip install. One gate (`os.name == "nt"`) guards the payload: on Windows it imports `requests` and `fernet`, decrypts a Fernet token with a literal key, and exec's the result. The decrypted stage fetches code from a remote paste (hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoop), strips `<pre>` tags and exec's it. On any other OS the override just runs the normal install. A Windows environment with the endpoint reachable opens it.

## Execution

- **cmdclass** `cmdclass[install] = FvHmSBbLcOYBrYrAtClmNHAKDbPgwLNBgqsZUnRRaTihQPNlsviITFYnuGDENxGZQwbccvuNwGcaPDstmrwWEwZmBAgwzhMghRSybWtwMnBgqSvkmXgvduFzazaCOlXe`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage fetched over HTTPS and exec'd)
- other: pip packages fernet and requests importable in the build environment (setup_requires) (both are imported before the exec; an ImportError aborts the payload)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet layer was recovered with the registered `fernet_exec` decoder (derivation d1); the payload sinks are cited in the decoded copy.
- The second stage is remote and was not fetched, so what it does is unknown.
- The name looks like a typosquat of BeautifulSoup. The other descriptive metadata is random filler.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifulSoop",
    "version": "1.0.0",
    "archive_sha256": "7a8eaffdfca478edcb1c07902f5dc55f1a3eb9eb98e782958c65772b7a35a748",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifulSoop-1.0.0.tar.gz",
    "package_root": "layer0/BeautifulSoop-1.0.0",
    "cluster_key": "799ebfed4191ea59be8289a5a436745bb4815b33d2777ea9e92fde79001612b6",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = FvHmSBbLcOYBrYrAtClmNHAKDbPgwLNBgqsZUnRRaTihQPNlsviITFYnuGDENxGZQwbccvuNwGcaPDstmrwWEwZmBAgwzhMghRSybWtwMnBgqSvkmXgvduFzazaCOlXe",
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
      "setup.py read in full. The install override exec's a Fernet token the tool did not decode; the registered fernet_exec decoder (derivation d1) recovers it as a requests.get of a remote paste whose text is exec'd.",
      "setup_py hook: top-level setup.py only defines the install class and calls setup(); nothing else runs outside the install override.",
      "The Windows-only classifier is metadata pip does not enforce, so it is not recorded as a gate."
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
      "value": "pip packages fernet and requests importable in the build environment (setup_requires)",
      "reason": "both are imported before the exec; an ImportError aborts the payload"
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
          "candidate": "k_390f8d078c",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 854,
            "end_byte": 869,
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
          "candidate": "q_fb6abc2614",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 851,
            "end_byte": 1283,
            "node_type": "if_statement",
            "sha256": "de6852ddfca75184",
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
      "purpose_reason": "the remote stage is fetched and run only on Windows (os.name == nt); other OSes just install",
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
            "start_byte": 887,
            "end_byte": 1283,
            "node_type": "block",
            "sha256": "9dcc07e306e42705",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 887,
            "end_byte": 1079,
            "node_type": "stmt_range",
            "sha256": "928c49c4856d2450",
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
              "start_byte": 966,
              "end_byte": 1032,
              "node_type": "call",
              "sha256": "623f16225010e9f2",
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
              "start_byte": 961,
              "end_byte": 1079,
              "node_type": "call",
              "sha256": "ab2a61146324a4cf",
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
      "Fernet-encrypted stage passed to exec (key literal at the call site)",
      "random class name and random descriptive metadata"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoop",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "funcaptcha paste dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override decrypts a Fernet-wrapped stage that, on Windows, downloads code from a remote paste and exec's it during pip install.",
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
        "output_sha256": "06ba8111c576966a"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "9875639a01ff7387"
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
