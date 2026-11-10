# pypi 1inch@8.6

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs its top-level code whenever pip builds it. There is one gate: if `C:/ProgramData/Updater` does not exist, it calls a `subprocess.Popen(shell=True)` wrapper with a PowerShell one-liner. The one-liner downloads a zip from transfer[.]sh into `%TMP%`, extracts it to `C:/ProgramData`, deletes the zip, runs `python -m pip install` for a list of input-capture, screenshot, keyring and crypto libraries, then starts the dropped `launch.vbs` and `server.pyw` with hidden windows. The folder check is a reinfection guard, since the zip itself creates that folder. To open the gate you need a Windows host without that folder, with PowerShell, python.exe on PATH and outbound HTTPS.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists C:/ProgramData/Updater) | then | 1 | download, write_file, delete_file, spawn_process, exec_downloaded, defense_evasion | file_absent=C:/ProgramData/Updater |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (payload is a PowerShell command using C:/ProgramData, $env:tmp, WScript.exe and python.exe)
- installed_tool: powershell (the whole payload runs through powershell -command)
- installed_tool: python.exe (Start-Process python.exe must resolve on PATH for the pip install and for server.pyw)
- installed_tool: WScript.exe (runs C:/ProgramData/Updater/launch.vbs)
- network: transfer[.]sh:443 (second-stage zip download)
- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (python -m pip install of the second stage's dependencies)

## Behaviour

- Ungated: none
- Gated: download, write_file, delete_file, spawn_process, exec_downloaded, defense_evasion

## Notes

- Errors are hidden: PowerShell runs with ErrorActionPreference set to SilentlyContinue, and the wrapper discards the output.
- The package borrows the 1inch/MetaMask name and description; the package module is a stub.
- The second stage (the zip contents) is not in the sample, so it was not analysed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "1inch",
    "version": "8.6",
    "archive_sha256": "34d90396fa38233e71a488618672e9471ee2b517f57641706c764f582d9fb957",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/1inch-8.6.tar.gz",
    "package_root": "layer0/1inch-8.6",
    "cluster_key": "c717bfcc4dd6cb1d651635adc3860f9c477157e87dacc56a06a486e4a307ac43",
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
      "setup.py: package code read in full; 1inch/__init__.py is a stub and is not reached at install. Nothing unread.",
      "silent_failure: the PowerShell line sets ErrorActionPreference to SilentlyContinue, and run() captures stdout/stderr and never checks the exit code.",
      "C:/ProgramData/Updater is the folder the downloaded zip unpacks into (launch.vbs and server.pyw are run from it), so c1 is a reinfection guard.",
      "The github URL appears only in long_description and is never contacted."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "payload is a PowerShell command using C:/ProgramData, $env:tmp, WScript.exe and python.exe"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the whole payload runs through powershell -command"
    },
    {
      "axis": "installed_tool",
      "value": "python.exe",
      "reason": "Start-Process python.exe must resolve on PATH for the pip install and for server.pyw"
    },
    {
      "axis": "installed_tool",
      "value": "WScript.exe",
      "reason": "runs C:/ProgramData/Updater/launch.vbs"
    },
    {
      "axis": "network",
      "value": "transfer[.]sh:443",
      "reason": "second-stage zip download"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443, files[.]pythonhosted[.]org:443",
      "reason": "python -m pip install of the second stage's dependencies"
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
          "candidate": "k_564d5c7e7c",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 263,
            "end_byte": 304,
            "node_type": "call",
            "sha256": "9e8d184348f0abb5",
            "line": 9
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
          "candidate": "q_5b6d83ef5b",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 256,
            "end_byte": 1144,
            "node_type": "if_statement",
            "sha256": "e895b1794a36583f",
            "line": 9
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
      "purpose_reason": "reinfection guard: skips the payload when its own drop folder C:/ProgramData/Updater already exists",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
          "delete_file",
          "spawn_process",
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
            "start_byte": 311,
            "end_byte": 1144,
            "node_type": "block",
            "sha256": "161519219e9fe376",
            "line": 10
          }
        ],
        "payload": [
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 83,
              "end_byte": 205,
              "node_type": "call",
              "sha256": "a78c3fd58176eac1",
              "line": 5
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 365,
                  "end_byte": 1144,
                  "node_type": "call",
                  "sha256": "01fc8b4e8eec3aa8",
                  "line": 11
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 55,
                  "end_byte": 252,
                  "node_type": "function_definition",
                  "sha256": "ac07ecdc195f5f1b",
                  "line": 4
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
      "spawn_process",
      "exec_downloaded",
      "defense_evasion"
    ]
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
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
  "family_hint": "ProgramData Updater server.pyw dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a hidden PowerShell command at build time that downloads a zip from a file-share host, unpacks it into C:/ProgramData, pip-installs input-capture, screenshot, keyring and crypto libraries and launches the dropped launch.vbs and server.pyw hidden. The only gate is a check that the drop folder does not already exist.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "def7e56d5cd4e680"
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
