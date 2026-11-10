# pypi libminerandomosint@2.54

**Source:** datadog · **Source label:** malicious · **Released:** 2023-03-03 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs at every pip build step (setuptools.build_meta backend). At top level, inside a bare try/except, it checks `not os.path.exists('tahg')` (gate g1, a relative path in the build working directory) and, when that path is absent, starts a hidden PowerShell through `subprocess.Popen` with an `-EncodedCommand`. Decoded, the command downloads Stage1.exe from a GitHub raw URL to `~/WindowsCache.exe` and runs it. A normal sandbox opens the gate, since the marker path is never there; the payload still needs Windows, PowerShell and GitHub reachable, because `subprocess.CREATE_NO_WINDOW` fails silently on other OSes.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, decoded_eval, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists tahg) | then | 1 | download, exec_downloaded, defense_evasion | file_absent=tahg |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (subprocess.CREATE_NO_WINDOW and powershell exist only on Windows; elsewhere the call fails silently)
- installed_tool: powershell (the payload is a PowerShell encoded command)
- network: github[.]com:443 (Stage1.exe is downloaded from a GitHub raw URL)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded, defense_evasion

## Notes

- Nothing in the package creates `tahg`, so the gate's purpose is unclear (author-side marker or reinfection guard).
- The setup() call carries version 1.16 while pyproject.toml says 2.54; no effect on the install path.
- The descriptive metadata claims a terminal UI library; this is impersonation-style text, not a claim about install behaviour, so no rule 8 flag.
- The second stage URL's owner handle is redacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "libminerandomosint",
    "version": "2.54",
    "archive_sha256": "41c9743e6510dcf1ff06acd63f8ff112603caa6d5ab2af87c6d743020e44d3d9",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-03-03",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-03-03-libminerandomosint-v2.54.zip",
    "package_root": "layer0/2023-03-03-libminerandomosint-v2.54/libminerandomosint-2.54",
    "cluster_key": "c4e9b2d0da45e40f15a4ac90d3435c2f25de672ed592e4ba3be46d5c47d71e39",
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
          "inline_shell",
          "decoded_eval",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (36 lines); it is the only install-reached file. pyproject.toml uses setuptools.build_meta, so setup.py runs on every pip build step.",
      "The Popen command is a PowerShell -EncodedCommand (base64 UTF-16LE), decoded with decode.py: Invoke-WebRequest of Stage1.exe from a GitHub raw URL to ~/WindowsCache.exe, then Invoke-Expression on that file.",
      "subprocess.CREATE_NO_WINDOW exists only on Windows; elsewhere the attribute lookup raises AttributeError, swallowed by the bare except, so nothing runs. Recorded as an os requirement, not a gate.",
      "Popen is not waited on, so the PowerShell child keeps running after setup.py returns. setup() is wrapped in a second bare except."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "subprocess.CREATE_NO_WINDOW and powershell exist only on Windows; elsewhere the call fails silently"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the payload is a PowerShell encoded command"
    },
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "Stage1.exe is downloaded from a GitHub raw URL"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "tahg",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_cb43857d35",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 87,
            "end_byte": 109,
            "node_type": "call",
            "sha256": "015d1beec9fe6119",
            "line": 7
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
          "candidate": "q_a0ec6a2a5f",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 80,
            "end_byte": 651,
            "node_type": "if_statement",
            "sha256": "ebdb3fe6a33efedc",
            "line": 7
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
      "purpose": "unclear",
      "purpose_reason": "Payload runs only when no file or folder named 'tahg' exists in the build working directory; nothing creates it, so likely an author-side marker or reinfection guard",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "exec_downloaded",
          "defense_evasion"
        ],
        "env_recipe": {
          "file_absent": [
            "tahg"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 144,
            "end_byte": 651,
            "node_type": "block",
            "sha256": "d7236a3d439c2a92",
            "line": 9
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 144,
              "end_byte": 651,
              "node_type": "call",
              "sha256": "d7236a3d439c2a92",
              "line": 9
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 144,
              "end_byte": 651,
              "node_type": "call",
              "sha256": "d7236a3d439c2a92",
              "line": 9
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 144,
              "end_byte": 651,
              "node_type": "call",
              "sha256": "d7236a3d439c2a92",
              "line": 9
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
      "exec_downloaded",
      "defense_evasion"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "PowerShell -EncodedCommand (base64 UTF-16LE) download-and-run command",
      "hidden PowerShell window and CREATE_NO_WINDOW"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/<author handle, redacted>/eee/raw/master/Stage1.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "powershell-encodedcommand-stage1-dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py starts a hidden PowerShell with an encoded command that downloads Stage1.exe from GitHub into the home folder and runs it, unless a local 'tahg' path exists. Works on Windows only.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "d348050efea8453d"
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
