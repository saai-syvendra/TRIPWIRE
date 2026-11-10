# pypi paypalad@8.27

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist builds with setuptools, so `setup.py` runs on pip install. Its top level, inside a bare `try/except: pass`, checks `os.path.exists('tahg')` and, when that relative path is absent, starts a hidden `powershell -EncodedCommand` via `subprocess.Popen` with `CREATE_NO_WINDOW`. The decoded command downloads an .exe from a Dropbox share to `~/WindowsCache.exe` and runs it. The only gate is the `tahg` absence check (g1); the Windows-only `CREATE_NO_WINDOW` attribute makes the payload effectively Windows-only, recorded as a requirement rather than a gate.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, detached_child, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists tahg) | then | 1 | download, exec_downloaded, defense_evasion | file_absent=tahg |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (subprocess.CREATE_NO_WINDOW is Windows-only; on other OSes the Popen argument evaluation raises and the payload is silently skipped)
- installed_tool: powershell (the payload is a PowerShell -EncodedCommand)
- network: dl[.]dropbox[.]com:443 (second-stage .exe is downloaded from a Dropbox share over HTTPS)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded, defense_evasion

## Notes

- Endpoint: hxxps://dl.dropbox[.]com/s/szgn…/Esquele.exe?dl=0 (share id redacted), second stage.
- The `tahg` path is never created by the payload, so it is not a reinfection marker; purpose left `unclear` (probably keeps the payload off the author's own build tree).
- `setup()` sets version 3.36 while the archive and pyproject say 8.27; descriptive metadata only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "paypalad",
    "version": "8.27",
    "archive_sha256": "6bd4680d70b1fdac303019d01355fdd72b4dff2bf80d5d5db549702bc73bb63a",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/paypalad-8.27.tar.gz",
    "package_root": "layer0/paypalad-8.27",
    "cluster_key": "63f5e28d0437f1c2dba7a6e190fcea0975582c7f81da7de2ef7434560956d570",
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
          "detached_child",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (34 lines). Payload block and setup() call are each wrapped in bare except: pass.",
      "The -EncodedCommand blob is base64 of UTF-16LE PowerShell, decoded with decode.py: Invoke-WebRequest of an .exe from a Dropbox share to ~/WindowsCache.exe, then Invoke-Expression on that file.",
      "subprocess.CREATE_NO_WINDOW only exists on Windows; elsewhere the attribute lookup raises AttributeError before Popen runs, which the bare except swallows. Recorded as an os requirement, not a gate.",
      "pyproject.toml uses setuptools.build_meta, so setup.py runs on pip install of the sdist. setup() itself is plain metadata plumbing."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "subprocess.CREATE_NO_WINDOW is Windows-only; on other OSes the Popen argument evaluation raises and the payload is silently skipped",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 645,
          "end_byte": 672,
          "node_type": "attribute",
          "sha256": "97afbb2e3d0e61f9",
          "line": 7
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "the payload is a PowerShell -EncodedCommand"
    },
    {
      "axis": "network",
      "value": "dl[.]dropbox[.]com:443",
      "reason": "second-stage .exe is downloaded from a Dropbox share over HTTPS"
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
          "candidate": "q_2c0f46aeee",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 78,
            "end_byte": 673,
            "node_type": "if_statement",
            "sha256": "dcfa6ad9852b075b",
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
      "purpose_reason": "payload runs only when a relative path 'tahg' is absent from the build directory; the payload never creates it, so likely a guard against running in the author's own working tree",
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
            "start_byte": 114,
            "end_byte": 673,
            "node_type": "block",
            "sha256": "772d3b3182e47111",
            "line": 7
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 114,
              "end_byte": 673,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 7
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 114,
              "end_byte": 673,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 7
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 114,
              "end_byte": 673,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
              "line": 7
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
      "PowerShell -EncodedCommand (base64 UTF-16LE) hiding the download URL and commands",
      "hidden window (-WindowStyle Hidden, CREATE_NO_WINDOW)",
      "bare except: pass around payload"
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
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py silently launches a hidden PowerShell encoded command at install that downloads an .exe from a Dropbox share and executes it. It runs on Windows when no 'tahg' path exists in the build directory.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@44d785b257",
      "sha256": "38a2d70cfa60131a"
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
