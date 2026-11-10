# pypi libgrandlibpyw@9.89

**Source:** datadog · **Source label:** malicious · **Released:** 2023-03-08 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs at build time and, at top level, launches a hidden PowerShell with a base64 `-EncodedCommand`. Decoded, it downloads an exe from hxxps://esquelestl.000webhostapp[.]com to `~/WindowsCache.exe` and runs it. One gate: the launch only happens when a file named `tahg` does not exist in the working directory (c1). The payload also needs Windows, since `subprocess.CREATE_NO_WINDOW` only exists there and the error is swallowed elsewhere.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: file_or_dir_exists not_exists tahg) | then | 1 | download, exec_downloaded, write_file | file_absent=tahg |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (subprocess.CREATE_NO_WINDOW only exists on Windows; powershell launched by name)
- installed_tool: powershell (payload is a PowerShell -EncodedCommand)
- network: esquelestl[.]000webhostapp[.]com:443 (second-stage exe download)

## Behaviour

- Ungated: none
- Gated: download, exec_downloaded, write_file

## Notes

- The `tahg` check uses a relative path, so it is tested in the build's working directory; its purpose is not clear from code (possibly an author or reinfection marker).
- Family hint left generic: the obvious campaign name comes from the author handle and the matching host name (rule 5).
- Popen is fire and forget, inside bare `except: pass`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "libgrandlibpyw",
    "version": "9.89",
    "archive_sha256": "82e97b538156695a2813f3ce420158016b9a13b8408bd11581df2b3b901a9355",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-03-08",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-03-08-libgrandlibpyw-v9.89.zip",
    "package_root": "layer0/2023-03-08-libgrandlibpyw-v9.89/libgrandlibpyw-9.89",
    "cluster_key": "d77ffd1081a8d5be5db7f59aa0b9338c3bbda1327d38ec75dd3cd85c3c6666f4",
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
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full (36 lines); it is the only install-reached file. pyproject.toml uses setuptools.build_meta, so setup.py top-level code runs on the sdist build.",
      "The Popen call and setup() are each wrapped in bare except: pass. Popen is not waited on, so the PowerShell child keeps running after setup.py returns.",
      "subprocess.CREATE_NO_WINDOW exists only on Windows Python; elsewhere the attribute lookup raises and the except swallows it, so the payload only runs on Windows. This is a requirement, not a deliberate check.",
      "Decoded (base64 of UTF-16LE): Invoke-WebRequest to hxxps://esquelestl.000webhostapp[.]com/xEsquelesquad.exe -OutFile ~/WindowsCache.exe, then Invoke-Expression on that file.",
      "The 'tahg' file check is a relative path, tested in the build's working directory (usually a temp unpack dir), so in practice it is almost always absent."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "subprocess.CREATE_NO_WINDOW only exists on Windows; powershell launched by name"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "payload is a PowerShell -EncodedCommand"
    },
    {
      "axis": "network",
      "value": "esquelestl[.]000webhostapp[.]com:443",
      "reason": "second-stage exe download"
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
          "candidate": "q_1282f2fbd7",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 80,
            "end_byte": 667,
            "node_type": "if_statement",
            "sha256": "259d82fe7ed0d6d5",
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
      "purpose_reason": "Skips the download when a file named 'tahg' exists in the build working directory; looks like an author or reinfection marker, intent not clear from code.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "exec_downloaded",
          "write_file"
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
            "end_byte": 667,
            "node_type": "block",
            "sha256": "a6b93f52803f630d",
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
              "end_byte": 667,
              "node_type": "call",
              "sha256": "a6b93f52803f630d",
              "line": 9
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 144,
              "end_byte": 667,
              "node_type": "call",
              "sha256": "a6b93f52803f630d",
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
              "end_byte": 667,
              "node_type": "call",
              "sha256": "a6b93f52803f630d",
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
      "write_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "PowerShell -EncodedCommand (base64 of UTF-16LE) holding the download-and-run command",
      "hidden PowerShell window (-WindowStyle Hidden, CREATE_NO_WINDOW)"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://esquelestl.000webhostapp[.]com/xEsquelesquad.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "powershell-encoded exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py top-level code launches a hidden PowerShell with an encoded command that downloads an exe from a free web host to the home folder and runs it, unless a file named 'tahg' exists in the working directory.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "42cfeb1e66bdd0dd"
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
