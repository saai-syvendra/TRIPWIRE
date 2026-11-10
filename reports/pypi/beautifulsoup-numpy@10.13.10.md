# pypi beautifulsoup-numpy@10.13.10

**Source:** datadog · **Source label:** malicious · **Released:** 2023-05-20 (dataset) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

Installing the sdist runs `setup.py`, which calls `setup()` and then runs extra top-level code. One gate (g1) checks that a relative marker file named after the author handle does not exist; if it does, the script exits cleanly. Past the gate, `setup.py` base64-decodes a blob and passes it to `exec()`. The decoded text was meant to download a Windows.exe from the Discord CDN and run it, but it is not valid Python, so `exec()` raises SyntaxError and nothing runs. In a fresh sandbox the gate is always open (the marker is never there), but no behaviour follows.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists hifrom<author handle, redacted>) | then | 1 | - | file_absent=hifrom<author handle, redacted> |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- Decoded with `tools/common/decode.py base64`. Line 2 of the result (`if os.exceptions "\"list\" exit(0)`) and later lines (`interface url=`, `temporfile.NamedText`) are syntax errors, so the whole blob fails to compile.
- `reqinstaller/__init__.py` holds a working version of the same dropper (Discord CDN Windows.exe, written to a temp file, then `subprocess.call`). It runs only on import, so it is outside install-time scope.
- Classifiers say Windows only, but nothing in the install code checks the OS.
- I kept g1 with empty behaviours instead of dropping it. A reviewer should confirm that choice.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "beautifulsoup-numpy",
    "version": "10.13.10",
    "archive_sha256": "185594beac54aae7825f13a97466ac03618750e9370a7134a87c0a9f509dce47",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-05-20",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-05-20-beautifulsoup-numpy-v10.13.10.zip",
    "package_root": "layer0/2023-05-20-beautifulsoup-numpy-v10.13.10/beautifulsoup-numpy-10.13.10",
    "cluster_key": "e1e804eb9d0eea4ed5db5ce72561830e8ca2337f74e12e26520c9fb75c2302a6",
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
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full. setup() runs first, then the c1 marker check, then exec(base64.b64decode(code)) at line 38.",
      "The base64 blob decodes (tools/common/decode.py) to text that is not valid Python (line 2 `if os.exceptions \"\\\"list\\\" exit(0)`, also `interface url=`, `temporfile.NamedText`). exec() raises SyntaxError at compile, so none of it runs.",
      "Decoded text names a Discord CDN Windows.exe download and subprocess.call of it; that intent never executes at install. The SyntaxError propagates (not swallowed), so the build of the sdist fails after setup() returns.",
      "reqinstaller/__init__.py (working download of a Discord-hosted Windows.exe to a temp file and subprocess.call) runs only when the package is imported, not at install.",
      "g1 is kept with no behaviours: the c1 marker test (setup.py line 24) is a real environment check whose then side is taken on any machine without the marker, so it is not a dead branch; only the exec()'d payload inside it fails to compile."
    ]
  },
  "requirements": [],
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
          "candidate": "k_0bd8b08fe7",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 721,
            "end_byte": 754,
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
          "candidate": "q_cd97bcd914",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 718,
            "end_byte": 768,
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
      "purpose_reason": "relative marker file named after the author handle, never created by the package; likely the author's own kill switch",
      "then": {
        "min_conditions": 1,
        "behaviours": [],
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
            "start_byte": 770,
            "end_byte": 1243,
            "node_type": "stmt_range",
            "sha256": "b8f2ab15f8173a3c",
            "line": 26
          }
        ],
        "payload": []
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "base64-encoded blob passed to exec() in setup.py"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "typosquat",
  "family_hint": "discord-cdn-exe-dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py execs a base64 blob that is meant to download and run a Discord-hosted Windows.exe, behind a marker-file check. The decoded blob is not valid Python, so exec() raises SyntaxError and nothing harmful runs at install; the working dropper sits in reqinstaller/__init__.py and runs only on import.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "dbd9fabbcea3c53e"
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
