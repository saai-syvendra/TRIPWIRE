# pypi esqreultramask@6.89

**Source:** datadog · **Source label:** malicious · **Released:** 2023-02-27 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist builds through setuptools, so the top level of `setup.py` runs at install. Before calling `setup()`, it checks `os.path.exists('tahg')` and, when that file is absent from the build directory, starts a hidden PowerShell process with a base64 `-EncodedCommand`. The decoded command downloads an executable from a Discord CDN attachment to `~/WindowsCache.exe` and runs it. The only gate is that marker-file check (c1, `file_absent: tahg`), which a fresh sandbox satisfies. The payload also needs Windows: `subprocess.CREATE_NO_WINDOW` and PowerShell only exist there, and on other systems the failure is swallowed by a bare `except: pass`.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_eval, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists tahg) | then | 1 | download, exec_downloaded, defense_evasion | file_absent=tahg |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (PowerShell command and subprocess.CREATE_NO_WINDOW only exist on Windows; elsewhere the call fails silently)
- installed_tool: powershell (the payload is a PowerShell -EncodedCommand)
- network: cdn[.]discordapp[.]com:443 (second-stage executable downloaded from a Discord CDN attachment)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded, defense_evasion

## Notes

- The `tahg` file is never created by the payload, so this is not a reinfection guard. It looks like an opt-out switch for the author's own machine; purpose recorded as unclear.
- The Windows dependency is recorded as a requirement, not a gate, because there is no deliberate OS test.
- Attachment ids in the endpoint are redacted. The second stage was not fetched.
- A comment above the payload names a domain; it is text only and was not used for any label.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "esqreultramask",
    "version": "6.89",
    "archive_sha256": "011ff17702e86efe12bc96325479d535686320b0ca92d327ac8077f3aa7bb2ab",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-02-27",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-02-27-esqreultramask-v6.89.zip",
    "package_root": "layer0/2023-02-27-esqreultramask-v6.89/esqreultramask-6.89",
    "cluster_key": "df5b5bdfd7cfcb2b1fd5251389710362b9532e99dfcaa12bb20f3989c489b9ab",
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
          "inline_eval",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full (37 lines); no other package code is reached at install. pyproject uses setuptools.build_meta, so setup.py top level runs on every build step.",
      "The payload block and setup() each sit in a bare try/except: pass, so any failure of the download or launch is hidden.",
      "subprocess.CREATE_NO_WINDOW is only defined on Windows; elsewhere the attribute lookup raises before Popen runs and the error is swallowed, so the payload is effectively Windows-only (requirement, not a gate).",
      "Decoded -EncodedCommand (UTF-16LE base64): Invoke-WebRequest of an .exe from a Discord CDN attachment to ~/WindowsCache.exe, then Invoke-Expression on that file. Window hidden via -WindowStyle Hidden and CREATE_NO_WINDOW."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "PowerShell command and subprocess.CREATE_NO_WINDOW only exist on Windows; elsewhere the call fails silently"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the payload is a PowerShell -EncodedCommand"
    },
    {
      "axis": "network",
      "value": "cdn[.]discordapp[.]com:443",
      "reason": "second-stage executable downloaded from a Discord CDN attachment"
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
          "candidate": "q_23927ce1cd",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 80,
            "end_byte": 763,
            "node_type": "if_statement",
            "sha256": "ac8f143722092cf8",
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
      "purpose_reason": "kill-switch marker file in the build directory; the payload never creates it, so likely the author's own opt-out on a dev machine",
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
            "end_byte": 763,
            "node_type": "block",
            "sha256": "867c603e6ef502ef",
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
              "end_byte": 763,
              "node_type": "call",
              "sha256": "867c603e6ef502ef",
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
              "end_byte": 763,
              "node_type": "call",
              "sha256": "867c603e6ef502ef",
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
              "end_byte": 763,
              "node_type": "call",
              "sha256": "867c603e6ef502ef",
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
      "PowerShell -EncodedCommand (base64 of UTF-16LE) hiding the download URL and commands"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://cdn[.]discordapp[.]com/attachments/1031…/1079…/Esquele.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "Discord-CDN PowerShell EncodedCommand dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a hidden PowerShell -EncodedCommand at install that downloads an executable from a Discord CDN attachment and runs it, guarded only by the absence of a marker file in the build directory.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "6948dbddaf631210"
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
