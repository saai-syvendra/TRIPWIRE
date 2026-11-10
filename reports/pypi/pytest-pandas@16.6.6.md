# pypi pytest-pandas@16.6.6

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs at install; after an ordinary setup() call, injected module-level code checks for a file named `hifromDreamyOak` in the current directory and exits if it exists (gate g1, file_or_dir_exists, opened by the file being absent). Past that gate it imports requests and execs a base64-decoded blob. The decoded text is meant to download a Windows.exe from a Discord CDN attachment and run it, but it is not valid Python, so exec raises SyntaxError and the install fails without the payload running.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists hifromDreamyOak) | then | 1 | other | file_absent=hifromDreamyOak |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- other: python module requests importable (setup.py does 'import requests' at line 26 before the exec; without it the install aborts with ImportError before the payload attempt.)

## Behaviour

- Ungated: none
- Gated: other

## Notes

- The decoded blob is garbled (`if os.exceptions "\"list\" exit(0)`, `interface url= ...`, `tempfile.NamedText(delete=Commonly)`); it cannot compile. Behaviour on the gated branch is recorded as `other` (attempted decoded exec) rather than download/exec_downloaded.
- `reqinstaller/__init__.py` contains a working version of the dropper (requests.get of Windows.exe from a discordapp CDN attachment, temp file, subprocess.call). It is never imported by setup.py, so it only runs at import time.
- The marker check has no creator in the package; purpose left `unclear`.
- `import requests` before the exec is a requirement: without requests installed the build aborts with ImportError first.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pytest-pandas",
    "version": "16.6.6",
    "archive_sha256": "d7f50ccc7deb7ae14afd366933293571d8269d262a4235272019826fd70d6906",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pytest-pandas-16.6.6.tar.gz",
    "package_root": "layer0/pytest-pandas-16.6.6",
    "cluster_key": "cd8b9ea206f9ab8ebebfdd6a82342c9949229bcdb7809f18c723279a6f88ed33",
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
      "setup.py: read in full. setup() runs first with plain metadata; the injected block after it runs at module level on every setup.py invocation.",
      "The base64 blob exec'd at line 38 decodes to text that is not valid Python (e.g. 'if os.exceptions \"\\\"list\\\" exit(0)', 'interface url= ...'). exec() raises SyntaxError at compile time, so none of the decoded code runs and the build fails.",
      "The decoded text names a Windows.exe download from a discordapp CDN attachment URL and a subprocess.call of it; recorded as intent only, not as reachable behaviour or endpoint.",
      "reqinstaller/__init__.py holds a working downloader (fetch Windows.exe from a discordapp CDN attachment, write to a temp file, subprocess.call). setup.py never imports it; it runs only if the package is imported, so it is out of install scope."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module requests importable",
      "reason": "setup.py does 'import requests' at line 26 before the exec; without it the install aborts with ImportError before the payload attempt."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "hifromDreamyOak",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_5197a158d2",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 696,
            "end_byte": 729,
            "node_type": "call",
            "sha256": "c391a34ca87a040e",
            "line": 24
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_f75eeef70e",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 693,
            "end_byte": 743,
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
      "purpose_reason": "Marker file in the current directory; nothing in the package creates it, so likely the author's own kill switch or a reinfection guard.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "other"
        ],
        "env_recipe": {
          "file_absent": [
            "hifromDreamyOak"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 745,
            "end_byte": 1218,
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
              "start_byte": 1179,
              "end_byte": 1207,
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
      "base64-encoded code passed to exec()"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord-cdn-exe-dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py, behind a marker-file check, execs a base64 blob whose text describes downloading and running a Windows.exe from a Discord CDN; the bundled reqinstaller module is a working version of that dropper. The decoded blob is not valid Python, so at install it raises SyntaxError and nothing beyond the attempt runs.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "Install-time payload is broken: decoded exec text is not valid Python, so the gated branch only attempts an exec that fails; behaviour recorded as 'other'. Working dropper exists only in import-time reqinstaller/__init__.py."
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "ee789cd714f6850a"
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
