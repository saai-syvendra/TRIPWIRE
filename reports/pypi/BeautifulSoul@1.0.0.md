# pypi BeautifulSoul@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command, so the payload runs on a normal pip install of the sdist. The override has one gate, `os.name == "nt"`, and only on Windows does it exec a Fernet-encrypted stage. That stage, decrypted with the literal key in the code (decoder `fernet_exec`, derivation d1), fetches code from hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoul, strips `<pre>` tags and execs it. A Windows VM with outbound HTTPS to that host and the `requests` and `fernet` modules available opens the gate; on other platforms only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = qqWQhvLNsovuqnngHtBKDVgDDkmukZHpayhYXFVRHjFNpZgKQpOBdVgVmamCrWIXFJGFZtGmmXGVDlYfKuPoBrygnMJNrOssbLKTwYLqnvuwNhIpHwTsMzrQadpdSKP`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage downloaded over HTTPS and exec'd)
- other: Python modules requests and fernet importable during the build (declared in setup_requires) (the install override imports both before decrypting and fetching the stage)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The second stage is remote and was not fetched, so any gates or behaviour inside it are unknown. The host is very likely dead.
- The name imitates beautifulsoup4; the description and author fields are random strings.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "BeautifulSoul",
    "version": "1.0.0",
    "archive_sha256": "630d8152bae3323546ca5b94b97f9d356cd8d1bfa54ce13a463728df518e04e2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/BeautifulSoul-1.0.0.tar.gz",
    "package_root": "layer0/BeautifulSoul-1.0.0",
    "cluster_key": "ae8b4dad800e024a6d9f6065b73ea3dc86ca5a16bbe270d3f69ccb44c37aeac0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = qqWQhvLNsovuqnngHtBKDVgDDkmukZHpayhYXFVRHjFNpZgKQpOBdVgVmamCrWIXFJGFZtGmmXGVDlYfKuPoBrygnMJNrOssbLKTwYLqnvuwNhIpHwTsMzrQadpdSKP",
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
      "setup.py: read in full. The tool did not recover the exec(Fernet(key).decrypt(token)) stage because it is Fernet encrypted; key and token are literals, decoded with the registered decoder fernet_exec (derivation d1).",
      "Decrypted stage (d1 line 16) fetches hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoul, strips <pre> tags and execs the response text. The remote second stage is not in the package and was not fetched; any gates inside it are unknown.",
      "setup_py hook: top-level setup.py only defines constants and calls setup(); build plumbing only, no behaviour of its own."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage downloaded over HTTPS and exec'd",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 861,
          "end_byte": 927,
          "node_type": "call",
          "sha256": "9a18a7dd931d07ee",
          "line": 16
        }
      ]
    },
    {
      "axis": "other",
      "value": "Python modules requests and fernet importable during the build (declared in setup_requires)",
      "reason": "the install override imports both before decrypting and fetching the stage"
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
          "candidate": "k_1240e1fe70",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 749,
            "end_byte": 764,
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
          "candidate": "q_c23121bec7",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 746,
            "end_byte": 1178,
            "node_type": "if_statement",
            "sha256": "c0e30cf74891beef",
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
      "purpose_reason": "the payload only exists for Windows (os.name == 'nt'); other platforms just run the normal install",
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
            "start_byte": 782,
            "end_byte": 1178,
            "node_type": "block",
            "sha256": "ee588dc53ab2a5a7",
            "line": 14
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 782,
            "end_byte": 974,
            "node_type": "stmt_range",
            "sha256": "ec8da8a2feee52cf",
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
              "start_byte": 861,
              "end_byte": 927,
              "node_type": "call",
              "sha256": "9a18a7dd931d07ee",
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
              "start_byte": 856,
              "end_byte": 974,
              "node_type": "call",
              "sha256": "8ae124cbb5a70db8",
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
      "Fernet-encrypted code passed to exec",
      "random-looking class name, description and author strings"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=BeautifulSoul",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": "fernet-exec paste dropper (funcaptcha[.]ru)",
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows the install command override decrypts a Fernet-encrypted stage that downloads code from a remote paste endpoint and execs it during pip install. The name imitates beautifulsoup4.",
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
        "output_sha256": "79dad34f0598b78f"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "b9a24b396644b761"
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
