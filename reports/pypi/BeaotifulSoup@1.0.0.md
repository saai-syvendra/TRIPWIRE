# pypi BeaotifulSoup@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` command, so the override's `run` method executes on a normal pip install. Inside it a single gate, `os.name == "nt"`, guards an `exec` of a Fernet-encrypted string whose key is a literal in the code. Decrypted, the stage fetches Python code from hxxps://funcaptcha[.]ru/paste2?package=BeaotifulSoup, strips `<pre>` tags and execs it. So a Windows install environment with outbound HTTPS to that host opens the gate; on other OSes the override only runs the normal install.

## Execution

- **cmdclass** `cmdclass[install] = JvCsidRcJZqnmMvZPfSQosMPLcSzhikXERKxXXcBPvJnUsaAJnWYlAtCCQXeGaQQuNmNYMFhwwyQtSFlVArSgUBslbwLnfDqTsESqPkxPtvtFXqsigbwcbnsqUrVMpzsEbdZGLCmDUAXNsTKL`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (the second stage is fetched over HTTPS from a paste endpoint and exec'd)
- other: python packages requests and fernet importable (pulled in by setup_requires) (the gated block imports both before fetching)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- Decoded with the registered `fernet_exec` decoder (derivation d1). The payload sinks and region are cited in d1.
- The remote second stage was not fetched, so what it does is unknown. The endpoint is probably dead by now.
- `requests` and `fernet` come from `setup_requires`, so they have to be installable for the gated block to get past its imports.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeaotifulSoup",
    "version": "1.0.0",
    "archive_sha256": "6385bc63336e43f5fdf8f7f4f3d3deea960fad6ecbb56d037b917f124dedc448",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeaotifulSoup-1.0.0.tar.gz",
    "package_root": "layer0/BeaotifulSoup-1.0.0",
    "cluster_key": "a89e0d0468f2796b2626c554db3433ed9aa46ac56c615cde0ab052237a50cbfd",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = JvCsidRcJZqnmMvZPfSQosMPLcSzhikXERKxXXcBPvJnUsaAJnWYlAtCCQXeGaQQuNmNYMFhwwyQtSFlVArSgUBslbwLnfDqTsESqPkxPtvtFXqsigbwcbnsqUrVMpzsEbdZGLCmDUAXNsTKL",
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
      "setup.py: read in full (38 lines, package code only). The exec(Fernet(key).decrypt(token)) call was decoded with the registered fernet_exec decoder (derivation d1); the key is a literal in the code. Nothing unread.",
      "Decrypted stage (d1 line 16): exec of the text of requests.get(hxxps://funcaptcha[.]ru/paste2?package=BeaotifulSoup) with <pre> tags stripped. The remote second stage was not fetched and is not analysed.",
      "Top-level setup.py code (setup_py hook) only calls setup(); all behaviour is in the cmdclass install override, which then calls install.run on every OS."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "the second stage is fetched over HTTPS from a paste endpoint and exec'd"
    },
    {
      "axis": "other",
      "value": "python packages requests and fernet importable (pulled in by setup_requires)",
      "reason": "the gated block imports both before fetching"
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
          "candidate": "k_4876482c21",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 810,
            "end_byte": 825,
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
          "candidate": "q_7fc823d297",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 807,
            "end_byte": 1239,
            "node_type": "if_statement",
            "sha256": "bcdc5620f9f939cb",
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
      "purpose_reason": "the download-and-exec stage only exists for Windows (os.name == nt); on other OSes the override just runs the normal install",
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
            "derived_from": "d1",
            "start_byte": 843,
            "end_byte": 1035,
            "node_type": "stmt_range",
            "sha256": "e6649b45a9f26772",
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
              "start_byte": 922,
              "end_byte": 988,
              "node_type": "call",
              "sha256": "a9863178c352119a",
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
              "start_byte": 917,
              "end_byte": 1035,
              "node_type": "call",
              "sha256": "190f364b56ef062d",
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
      "Fernet-encrypted stage with a literal key, passed to exec",
      "random-looking class name and filler description strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeaotifulSoup",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec remote paste dropper (funcaptcha[.]ru)",
  "claude_assessment": "malicious",
  "assessment_reason": "The setup.py install override hides a Fernet-encrypted stage that, on Windows, downloads Python code from a remote paste endpoint and execs it during pip install. The name typosquats BeautifulSoup.",
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
        "output_sha256": "9d1af4380941629f"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "d0abae9119bd4f42"
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
