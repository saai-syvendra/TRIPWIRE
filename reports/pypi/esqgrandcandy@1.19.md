# pypi esqgrandcandy@1.19

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Code runs at install through the top level of `setup.py`, which pip executes when it builds the sdist. There is one gate, g1: `if not os.path.exists(<marker>)`, where the marker is a relative path in the build directory named after the author handle. When the marker is missing, which is the case on any fresh machine, it starts a hidden `powershell -EncodedCommand`. That command downloads an exe from a Dropbox share to `~/WindowsCache.exe` and runs it. The payload only works on Windows: `subprocess.CREATE_NO_WINDOW` and PowerShell are needed, and on other systems the bare `except: pass` hides the failure.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_eval, download_then_exec, dropped_binary; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists <author handle, redacted>) | then | 1 | download, exec_downloaded, defense_evasion | file_absent=<author handle, redacted> |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (powershell and subprocess.CREATE_NO_WINDOW (attribute missing elsewhere, raising inside the bare except))
- installed_tool: powershell (the payload is a PowerShell -EncodedCommand)
- network: dl[.]dropbox[.]com:443 (Invoke-WebRequest fetches the second-stage exe)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded, defense_evasion

## Notes

- I decoded the EncodedCommand (UTF-16LE base64) as data with `decode.py`. I kept the endpoint but redacted the share id.
- The c1 marker value is redacted because it matches the author handle in the metadata. The payload never creates the marker, so the gate is probably an author self-exclusion. That reading is inferred, so the purpose is recorded as `unclear`.
- The only other code is the `setup()` metadata call. There is no cmdclass and no other install code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "esqgrandcandy",
    "version": "1.19",
    "archive_sha256": "a5899af7e1bda482e393a4b7763575dbe4920a6d0ab300410bc2b795ab556f31",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/esqgrandcandy-1.19.tar.gz",
    "package_root": "layer0/esqgrandcandy-1.19",
    "cluster_key": "f4c1b5ae1e3c2280b00b019a61f038d77d875b5662983c52951d5eaf7fb63fff",
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
          "download_then_exec",
          "dropped_binary"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (36 lines). Top-level try/except: pass wraps a Popen of powershell -WindowStyle Hidden -EncodedCommand; the base64 is UTF-16LE PowerShell, decoded as data with decode.py.",
      "Decoded command: Invoke-WebRequest of an .exe from a Dropbox share link to ~/WindowsCache.exe, then Invoke-Expression on that path, which runs the downloaded exe.",
      "subprocess.CREATE_NO_WINDOW only exists on Windows Python; on Linux/macOS the attribute lookup raises AttributeError inside the bare except, so nothing runs there.",
      "The checked marker is a relative path in the build cwd, named after the author handle in the metadata (value redacted per rule 5). The payload never creates it, so it is not a reinfection guard; likely excludes the author's own working folder.",
      "c1 value is a plain literal at setup.py line 6, fully recovered and only redacted; a fresh install cwd lacks it, so the gate opens by default.",
      "setup() itself is plain distutils metadata wrapped in try/except: pass; no cmdclass. modlib package is listed but not shipped in the sdist; nothing else runs at install."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "powershell and subprocess.CREATE_NO_WINDOW (attribute missing elsewhere, raising inside the bare except)"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the payload is a PowerShell -EncodedCommand"
    },
    {
      "axis": "network",
      "value": "dl[.]dropbox[.]com:443",
      "reason": "Invoke-WebRequest fetches the second-stage exe"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "<author handle, redacted>",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_8955f3d215",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 85,
            "end_byte": 107,
            "node_type": "call",
            "sha256": "015d1beec9fe6119",
            "line": 6
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
          "candidate": "q_bb33ac333d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 78,
            "end_byte": 701,
            "node_type": "if_statement",
            "sha256": "5711a2caa10b7418",
            "line": 6
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
      "purpose_reason": "Relative-path marker named like the author handle, not created by the payload; probably skips the author's own build folder, not confirmed from code.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "exec_downloaded",
          "defense_evasion"
        ],
        "env_recipe": {
          "file_absent": [
            "<author handle, redacted>"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 142,
            "end_byte": 701,
            "node_type": "block",
            "sha256": "772d3b3182e47111",
            "line": 8
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 142,
              "end_byte": 701,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 8
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 142,
              "end_byte": 701,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 8
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 142,
              "end_byte": 701,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 8
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
      "base64 UTF-16LE PowerShell passed via -EncodedCommand",
      "hidden PowerShell window (-WindowStyle Hidden, CREATE_NO_WINDOW)",
      "downloaded exe saved as WindowsCache.exe"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://dl.dropbox[.]com/s/szgn…/Esquele.exe?dl=0",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "PowerShell EncodedCommand Dropbox exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a hidden PowerShell EncodedCommand at install that downloads an exe from a Dropbox share to the user's home and runs it, all inside a bare except so failures are silent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "647c370c38ab2bdf"
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
