# pypi matplotlib-requests@16.12.4

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

Code runs at install through `setup.py`, which pip executes when building the sdist. After the `setup()` call there is one gate: if a marker file (named after the author, relative to the build directory) exists, the script calls `exit(0)`; otherwise it imports `requests` and `exec()`s a base64 blob. Any normal victim or sandbox opens the gate, since the file is not shipped and nothing creates it. The decoded blob is meant to download a Windows executable from a Discord CDN link and run it, but it is not valid Python, so `exec()` raises SyntaxError and nothing is downloaded or started at install.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists hifrom<author handle, redacted>) | then | 1 | other | file_absent=hifrom<author handle, redacted> |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- other: python module requests importable in the build environment (setup.py imports requests unconditionally after the marker check, before the exec)

## Behaviour

- Ungated: none
- Gated: other

## Notes

- The decoded blob has an unterminated string on line 2 and garbled names (`interface url=`, `temporfile`, `delete=Commonly`). Behaviour on the gate is recorded as `other` for the attempted eval, not as download or exec.
- `import requests` comes before the exec. In pip's isolated build env requests is normally missing, so the build likely stops with ImportError even earlier.
- `reqinstaller/__init__.py` holds a working download-and-run of a Windows.exe from a Discord CDN attachment link, but nothing at install imports it (import-time only).
- The marker file name in c1 is redacted because it contains the author handle.
- A leftover `b64.txt` (copy of the blob used for decoding) sits in this scratch folder; I could not delete it in this session.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "matplotlib-requests",
    "version": "16.12.4",
    "archive_sha256": "8b533a135e42742f3c8532b0149ad1f7aaf48b9db3386569b923afbf777c8494",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/matplotlib-requests-16.12.4.tar.gz",
    "package_root": "layer0/matplotlib-requests-16.12.4",
    "cluster_key": "a1c00e8c0efb021ff5a6b8cd51262fc4d42fdd942abf1e7623c2486cd1c7003c",
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
      "setup.py: read in full (43 lines). Code after setup() checks a marker file in the build directory, imports requests, then exec()s a base64 blob. Nothing unread.",
      "The decoded blob is not valid Python (line 2 holds an unterminated string literal; later lines use 'interface url=', 'temporfile', 'delete=Commonly'). exec() raises SyntaxError, so no download or process start happens at install.",
      "The blob's apparent intent is to fetch a Windows.exe from a Discord CDN link and run it with subprocess.call, the same as reqinstaller/__init__.py. That intent is not reachable.",
      "import requests at line 26 runs before the exec; in pip's isolated build env requests is usually absent, so the build would stop with ImportError there first.",
      "reqinstaller/__init__.py (packaged module) downloads a Windows.exe from a Discord CDN attachment link into a temp file and runs it. Nothing at install imports it; it only runs when the module is imported.",
      "The marker name in c1 embeds the author handle; redacted per rule 5. It is a relative path (build working directory), not shipped in the sdist and not created by the payload."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "setup.py imports requests unconditionally after the marker check, before the exec"
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
          "candidate": "k_4afdfe1ba3",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 719,
            "end_byte": 752,
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
          "candidate": "q_a48a9d526d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 716,
            "end_byte": 766,
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
      "purpose_reason": "exit(0) when a marker file named after the author exists in the build directory; the payload never creates it, likely an author kill switch, not confirmed",
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
            "start_byte": 768,
            "end_byte": 1241,
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
              "start_byte": 1202,
              "end_byte": 1230,
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
      "base64-encoded Python passed to exec()"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord-cdn exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py exec()s a base64 blob meant to download and run a Windows executable from a Discord CDN link, behind a marker-file kill switch. The blob is broken Python and raises SyntaxError, so nothing harmful completes at install; the packaged reqinstaller module carries a working version that runs only on import.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "d9723379c69550d4"
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
