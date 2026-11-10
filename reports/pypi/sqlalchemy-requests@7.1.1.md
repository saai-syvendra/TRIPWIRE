# pypi sqlalchemy-requests@7.1.1

**Source:** datadog · **Source label:** malicious · **Released:** 2023-05-20 (dataset) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs at install. After the normal setup() call it checks for a marker file named after the author in the build directory and exits if it exists (gate g1, opened when the file is absent). Past that gate it imports requests and execs a base64-decoded blob. The decoded text was meant to download a Windows.exe from Discord CDN and run it, but it is not valid Python, so exec raises SyntaxError and nothing further runs at install.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists hifrom<author handle, redacted>) | then | 1 | other | file_absent=hifrom<author handle, redacted> |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- other: python module requests importable in the build environment (setup.py imports requests at line 26 before the exec but declares no dependency on it (install_requires is ['']))

## Behaviour

- Ungated: none
- Gated: other

## Notes

- The working dropper (download Windows.exe from cdn[.]discordapp[.]com to a temp file, then run it) is in reqinstaller/__init__.py and only runs on import.
- setup.py imports requests without declaring it; under pip build isolation that import likely fails before the exec.
- The marker file name contains the author handle, redacted in the record.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "sqlalchemy-requests",
    "version": "7.1.1",
    "archive_sha256": "51a983166778853322273f0336b970f3406b1bac6cf84cf2353b04f14679c7c8",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-05-20",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-05-20-sqlalchemy-requests-v7.1.1.zip",
    "package_root": "layer0/2023-05-20-sqlalchemy-requests-v7.1.1/sqlalchemy-requests-7.1.1",
    "cluster_key": "fd7b7467c21969f7b069f167968a015d945939713c1448baa7fc9073f22373c8",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "decoded_eval"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full. setup() runs first (metadata only), then the marker-file check, then exec(base64.b64decode(code)) at line 38.",
      "The base64 blob decodes to text that is not valid Python (garbled lines such as 'interface url= ...' and 'temporfile.NamedText'). exec raises SyntaxError, so nothing in it runs.",
      "The garbled decoded text names a Discord CDN Windows.exe URL; it is never contacted because the decoded code fails to compile.",
      "reqinstaller/__init__.py (read in full) downloads a Windows.exe from cdn[.]discordapp[.]com and runs it, but only when imported; setup.py never imports it, so it is not install time.",
      "Under pip's default build isolation requests is likely missing, so 'import requests' at line 26 would raise ImportError before the exec is reached."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "setup.py imports requests at line 26 before the exec but declares no dependency on it (install_requires is [''])"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "hifrom<author handle, redacted>",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_327230143f",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 705,
            "end_byte": 738,
            "node_type": "call",
            "sha256": "c391a34ca87a040e",
            "line": 24
          }
        }
      ],
      "provenance": "in_set",
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "hifrom<author handle, redacted>",
        "accessor": "exists"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_de6d40e39a",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 702,
            "end_byte": 752,
            "node_type": "if_statement",
            "sha256": "22ebcbfd1b7bb6af",
            "line": 24
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "A marker file named after the author, relative to the build directory, makes setup.py exit before the payload. Nothing in the package creates it, so the code does not show whether it is a kill switch for the author's machine or a reinfection marker.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "other"
        ],
        "env_recipe": {
          "file_absent": [
            "hifrom<author handle, redacted>"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 754,
            "end_byte": 1227,
            "node_type": "stmt_range",
            "sha256": "b8f2ab15f8173a3c",
            "line": 26
          }
        ],
        "payload": [
          {
            "behaviour": "other",
            "sink_kind": "eval",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1188,
              "end_byte": 1216,
              "node_type": "call",
              "sha256": "8952b0832787b760",
              "line": 38
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
      "other"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "base64-encoded code passed to exec"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "Unless an author marker file exists, setup.py execs base64-decoded code meant to download and run a Windows exe from Discord CDN. The decoded code is not valid Python, so at install it only raises SyntaxError; the working dropper is in reqinstaller/__init__.py and runs only on import.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Install-time payload is broken: the decoded exec code is a SyntaxError, so no download or execution happens at install; behaviour recorded as other.",
    "Gate value is a file name containing the author handle; redacted."
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "89c5c73023b47e8c"
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
