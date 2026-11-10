# pypi requirmentstxtt@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command with a randomly named class, so its `run()` executes on a normal pip install. One gate, `os.name == "nt"`, guards the only package behaviour: on Windows, `run()` imports requests and fernet and exec()s a Fernet-decrypted string. The decrypted code fetches text from a remote paste endpoint on funcaptcha[.]ru, strips `<pre>` tags and exec()s it as Python. Opening the gate needs a Windows VM plus reachability of that host; on other platforms only the normal install runs.

## Execution

- **cmdclass** `cmdclass[install] = IuYmNcKvAawOyYhRyjahjIHPSHmOWjQoWdXDWXxgayuWrixocpLjkePTQdrTJkxOKketvBFwluYvwwjwcIaVuhfqGGQxmzwtDHylfSbHuhNcdKKpRIKXeSRmeyCkQuEoPHGqkkhJZSuCMtNEshfOtlEDvSIFhhxuiAdVoeQlMREdufPWCx`: runs setup.py; direct_script, decoded_eval, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | download, exec_downloaded | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- network: funcaptcha[.]ru:443 (second stage is fetched over HTTPS with requests.get and exec'd; the fetch must succeed for the payload to run)
- other: requests and fernet importable during the build (setup_requires) (run() imports requests and fernet inside the gate before the exec; pip normally provides them via setup_requires)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded

## Notes

- The Fernet key is a literal at the call site; decoded with the registered `fernet_exec` decoder (derivation d1). Payload sinks are cited in the decoded copy.
- The second stage was not fetched, so what it does is unknown.
- requests and fernet come in through `setup_requires`, so pip has them available when `run()` executes.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "requirmentstxtt",
    "version": "1.0.0",
    "archive_sha256": "9c39a0211345e649a50948832d9b719a7b912f5de029840bb3efe60e09a9e9cd",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/requirmentstxtt-1.0.0.tar.gz",
    "package_root": "layer0/requirmentstxtt-1.0.0",
    "cluster_key": "2305de22a765d3dcb69336343655d9731057aa717f199984740913348bf97651",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = IuYmNcKvAawOyYhRyjahjIHPSHmOWjQoWdXDWXxgayuWrixocpLjkePTQdrTJkxOKketvBFwluYvwwjwcIaVuhfqGGQxmzwtDHylfSbHuhNcdKKpRIKXeSRmeyCkQuEoPHGqkkhJZSuCMtNEshfOtlEDvSIFhhxuiAdVoeQlMREdufPWCx",
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
      "setup.py: read in full (46 lines). The extractor did not recover the Fernet blob passed to exec() in run(); decoded with the registered fernet_exec decoder (derivation d1), key literal at the call site, and the plaintext read in full.",
      "setup_py hook top level only defines constants and calls setup(); all package behaviour is in the cmdclass install override's run(), which ends with install.run(self).",
      "The downloaded second stage is not in the package and was not fetched; what it does is unknown."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "funcaptcha[.]ru:443",
      "reason": "second stage is fetched over HTTPS with requests.get and exec'd; the fetch must succeed for the payload to run"
    },
    {
      "axis": "other",
      "value": "requests and fernet importable during the build (setup_requires)",
      "reason": "run() imports requests and fernet inside the gate before the exec; pip normally provides them via setup_requires"
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
          "candidate": "k_a3faaee677",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 688,
            "end_byte": 703,
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
          "candidate": "q_cf1f1e558d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 685,
            "end_byte": 1117,
            "node_type": "if_statement",
            "sha256": "1f26b0c5b4d263b4",
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
      "purpose_reason": "the remote-code downloader only runs on Windows (os.name == 'nt'); other platforms just get the normal install",
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
            "start_byte": 721,
            "end_byte": 1117,
            "node_type": "block",
            "sha256": "818a3fbab77ffa9d",
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
              "start_byte": 800,
              "end_byte": 868,
              "node_type": "call",
              "sha256": "ea1b1b279bbeb057",
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
              "start_byte": 795,
              "end_byte": 915,
              "node_type": "call",
              "sha256": "519370a82dce69ff",
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
      "Fernet-encrypted stage passed to exec(), key literal at the call site",
      "random-letter class name for the cmdclass install override"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://funcaptcha[.]ru/paste2?package=requirmentstxtt",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "funcaptcha[.]ru fernet-exec dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The cmdclass install override decrypts a Fernet blob whose plaintext fetches code from a remote paste endpoint and exec()s it, only when os.name is 'nt'. The package does no legitimate build work.",
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
        "output_sha256": "641110d3a59cfe7b"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "4c67be86ad211f4b"
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
