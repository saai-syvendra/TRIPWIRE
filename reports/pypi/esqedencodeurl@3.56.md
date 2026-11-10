# pypi esqedencodeurl@3.56

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist builds through setuptools, so top-level code in `setup.py` runs on install. A single gate checks that a file or folder named `tahg` does not exist in the build directory (`os.path.exists`). When it is absent, which is the normal case, `subprocess.Popen` starts a hidden PowerShell with an `-EncodedCommand` that downloads an executable from Dropbox to `~/WindowsCache.exe` and runs it. The call only works on Windows (it uses `subprocess.CREATE_NO_WINDOW`), and every failure is swallowed by a bare `except: pass`.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, download_then_exec, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists tahg) | then | 1 | download, write_file, exec_downloaded, defense_evasion | file_absent=tahg |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (subprocess.CREATE_NO_WINDOW only exists on Windows Python and the command is PowerShell; elsewhere the call fails silently)
- installed_tool: powershell (payload runs through powershell -EncodedCommand)
- network: dl[.]dropbox[.]com:443 (second stage executable downloaded over HTTPS from Dropbox)

## Behaviour

- Ungated: none
- Gated: download, write_file, exec_downloaded, defense_evasion

## Notes

- The encoded command decodes as UTF-16LE base64 to `Invoke-WebRequest` from `hxxps://dl.dropbox[.]com/s/szgn…/Esquele.exe?dl=0` to `~/WindowsCache.exe`, then `Invoke-Expression` on that file.
- The payload never creates `tahg`, so this is not a reinfection guard. Its purpose is recorded as unclear; most likely it keeps the payload from running in the author's own checkout.
- Windows is a requirement, not a gate. On other platforms, looking up `CREATE_NO_WINDOW` raises and the exception is swallowed.
- The `version` in `setup()` (3.97) differs from the archive version (3.56). This is metadata only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "esqedencodeurl",
    "version": "3.56",
    "archive_sha256": "0ed0ebbd542f5f36453f3e30ff779f349dfe746427106e7e84290c4517d70fa4",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/esqedencodeurl-3.56.tar.gz",
    "package_root": "layer0/esqedencodeurl-3.56",
    "cluster_key": "a00d80bed56dd9a89fa7218c18c6ffb3b086c774e3f050db052aad5a1140bcf7",
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
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (single short file). The payload block at module top level runs on every setuptools build step; both it and the setup() call sit in bare try/except: pass.",
      "Popen starts powershell -WindowStyle Hidden -EncodedCommand (UTF-16LE base64, decoded with decode.py): Invoke-WebRequest fetches a Dropbox-hosted Esquele.exe to ~/WindowsCache.exe, then Invoke-Expression runs it.",
      "Popen is not waited on, so the hidden PowerShell keeps running after setup.py returns (detached_child).",
      "subprocess.CREATE_NO_WINDOW exists only on Windows Python; elsewhere the attribute lookup raises before Popen and the bare except swallows it. Recorded as an os requirement, not a gate, since it is not a deliberate check.",
      "pyproject.toml uses setuptools.build_meta, so setup.py runs under pip. setup() declares version 3.97 while the archive is 3.56; metadata only, no effect on install code."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "subprocess.CREATE_NO_WINDOW only exists on Windows Python and the command is PowerShell; elsewhere the call fails silently"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "payload runs through powershell -EncodedCommand"
    },
    {
      "axis": "network",
      "value": "dl[.]dropbox[.]com:443",
      "reason": "second stage executable downloaded over HTTPS from Dropbox"
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
          "candidate": "q_e291673a7f",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 80,
            "end_byte": 703,
            "node_type": "if_statement",
            "sha256": "5711a2caa10b7418",
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
      "purpose_reason": "relative marker 'tahg' in the build directory, never created by the payload; likely a kill switch for the author's own checkout, not confirmed",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "write_file",
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
            "end_byte": 703,
            "node_type": "block",
            "sha256": "772d3b3182e47111",
            "line": 9
          }
        ],
        "payload": [
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 144,
              "end_byte": 703,
              "node_type": "call",
              "sha256": "772d3b3182e47111",
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
      "write_file",
      "exec_downloaded",
      "defense_evasion"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "PowerShell -EncodedCommand (base64 of UTF-16LE) hiding the download URL and run command",
      "hidden window (-WindowStyle Hidden, CREATE_NO_WINDOW)"
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
  "family_hint": "powershell-encodedcommand-dropbox-exe-dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a hidden PowerShell command at build time that downloads an executable from Dropbox to ~/WindowsCache.exe and runs it, gated only on a 'tahg' marker being absent from the build directory.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "e13bc495bee851b7"
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
