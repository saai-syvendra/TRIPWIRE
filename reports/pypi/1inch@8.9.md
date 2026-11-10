# pypi 1inch@8.9

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Top-level code in `setup.py` runs on every sdist build step, so the payload fires on `pip install`. One gate (g1) checks that `C:/ProgramData/Updater` does not exist, a reinfection guard on the folder the second stage unpacks into. Behind it, a hidden PowerShell command downloads a zip from transfer[.]sh, expands it into `C:/ProgramData`, deletes the zip, pip-installs screenshot, input-capture, clipboard and crypto modules, and launches `Updater\launch.vbs` and `Updater\server.pyw` hidden. Any Windows machine without that folder, with PowerShell, python.exe and network access, opens the gate.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists C:/ProgramData/Updater) | then | 1 | download, write_file, delete_file, exec_downloaded, defense_evasion | file_absent=C:/ProgramData/Updater |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (payload is a PowerShell command using WScript.exe and C:/ProgramData paths)
- installed_tool: powershell (the whole payload is a powershell -command line)
- installed_tool: python.exe (Start-Process python.exe for pip install and to run server.pyw)
- network: transfer[.]sh:443 (second-stage zip is downloaded with Invoke-WebRequest)

## Behaviour

- Ungated: none
- Gated: download, write_file, delete_file, exec_downloaded, defense_evasion

## Notes

- There is no OS check. On Linux the guard passes but the PowerShell command just fails, with errors swallowed (output piped and discarded, exit code ignored).
- The package claims to be an official 1inch API wrapper with a metamask author field. That is brand impersonation, recorded as `malicious_new_package`; no real PyPI project of this exact name was confirmed.
- The second stage is not in the archive, so what `server.pyw` does is not recovered. The pip module list suggests a remote-control/stealer tool, but that is an inference.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "1inch",
    "version": "8.9",
    "archive_sha256": "23915c9434509cfb98ac61235b9592deddbb2d23dc420fd79a35b0e116dbe502",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/1inch-8.9.tar.gz",
    "package_root": "layer0/1inch-8.9",
    "cluster_key": "9249e9dbc386ef809a0a620fba68fb221c88e5573cd2cdf922e22196252d49bf",
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
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: package code read in full (30 lines); no other install-reached files. 1inch/__init__.py is not run at install.",
      "Top-level setup.py code runs a PowerShell one-liner through subprocess.Popen(shell=True) via run(); exit status is never checked and stderr is merged into a pipe that is read and discarded.",
      "PowerShell sets ErrorActionPreference SilentlyContinue, downloads a zip from transfer[.]sh to %TMP%, expands it into C:/ProgramData, deletes the zip, pip-installs a list of RAT/stealer-style modules, then runs Updater\\launch.vbs and Updater\\server.pyw hidden.",
      "No OS check: on Linux or macOS the guard passes (path absent) but the powershell command simply fails silently. The payload effectively needs Windows.",
      "WScript.exe and Start-Process launch the dropped scripts hidden; these very likely keep running after the install returns (detached_child), not confirmed statically.",
      "README.md read at line 16 is ordinary build plumbing (long_description)."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "payload is a PowerShell command using WScript.exe and C:/ProgramData paths"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the whole payload is a powershell -command line"
    },
    {
      "axis": "installed_tool",
      "value": "python.exe",
      "reason": "Start-Process python.exe for pip install and to run server.pyw"
    },
    {
      "axis": "network",
      "value": "transfer[.]sh:443",
      "reason": "second-stage zip is downloaded with Invoke-WebRequest"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "C:/ProgramData/Updater",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_f43b0ff1e0",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 329,
            "end_byte": 370,
            "node_type": "call",
            "sha256": "9e8d184348f0abb5",
            "line": 12
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
          "candidate": "q_1194bd9f7c",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 322,
            "end_byte": 1210,
            "node_type": "if_statement",
            "sha256": "e895b1794a36583f",
            "line": 12
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
      "purpose_reason": "reinfection guard: C:/ProgramData/Updater is the folder the downloaded zip expands into, so the payload skips machines already infected",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "delete_file",
          "exec_downloaded",
          "defense_evasion"
        ],
        "env_recipe": {
          "file_absent": [
            "C:/ProgramData/Updater"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 377,
            "end_byte": 1210,
            "node_type": "block",
            "sha256": "161519219e9fe376",
            "line": 13
          }
        ],
        "payload": [
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 149,
              "end_byte": 271,
              "node_type": "call",
              "sha256": "a78c3fd58176eac1",
              "line": 8
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 431,
                  "end_byte": 1210,
                  "node_type": "call",
                  "sha256": "01fc8b4e8eec3aa8",
                  "line": 14
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 121,
                  "end_byte": 318,
                  "node_type": "function_definition",
                  "sha256": "ac07ecdc195f5f1b",
                  "line": 7
                }
              }
            ]
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
      "write_file",
      "delete_file",
      "exec_downloaded",
      "defense_evasion"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "hidden windows and suppressed PowerShell errors and progress output"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://transfer[.]sh/W7c4…/transfer.zip",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "ProgramData Updater dropper (launch.vbs/server.pyw)",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a hidden PowerShell command at install that downloads a zip from a file-share, unpacks it into C:/ProgramData, pip-installs screenshot, keylogging and crypto modules and launches the dropped server.pyw. The only gate is a reinfection check on C:/ProgramData/Updater.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "4f6df3930f7160ff"
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
