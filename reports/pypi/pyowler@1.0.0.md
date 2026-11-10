# pypi pyowler@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command, so `InstallCommand.run` runs on a normal pip install. It XOR-decodes an escaped string literal with a digit-string key that is also in the code, and evals the result inside a bare `except: pass`. The decoded code has one gate: it only acts when `C:\Users\<login>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System64\` does not exist. That folder is one the payload creates itself, so the check is a reinfection guard. When the folder is absent, the code creates it, writes a Startup `.vbs` for persistence and a hidden-launch `.vbs` plus a `.bat`, then runs the `.vbs`. The `.bat` downloads three executables with bitsadmin from 51.178.25[.]148:8081, starts them through the Startup script, and posts the login name to a Discord webhook. There is no explicit OS check, but the chain only works on Windows.

## Execution

- **cmdclass** `cmdclass[install] = InstallCommand`: runs setup.py; direct_script, decoded_eval, detached_child, download_then_exec; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: file_or_dir_exists not_exists C:\Users\<?>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System64\) | then | 1 | write_file, persistence, download, exec_downloaded, exfil, defense_evasion | os=win32; file_absent=C:\Users\<login>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System64 |

Gate intent: g1 activate/enables/unclear

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- os: win32 (all dropped paths are under C:\Users\<login>\AppData and the chain runs .vbs/.bat files through Windows Script Host and cmd)
- installed_tool: wscript, bitsadmin, curl (WIN32.vbs is started via file association, the bat downloads with bitsadmin and posts with curl)
- network: 51[.]178[.]25[.]148:8081, canary[.]discord[.]com:443 (second-stage executables are fetched from the IP; the login name is posted to a Discord webhook)

## Behaviour

- Ungated: none
- Gated: write_file, persistence, download, exec_downloaded, exfil, defense_evasion

## Notes

- The decode was registered as derivation d1 with a new candidate decoder, `scratch/pypi__pyowler@1.0.0/decoders/py_escaped_xor_literal.py`, which unescapes the literal and XORs it with the key literal. The decoder needs review before it moves into `tools/common/decoders/`.
- The gate is out of set because the candidate extractor never sees code inside the eval'd string.
- The fs_write sinks are anchored on the `open(..., "a")` calls. I could not cite the enclosing `.write(...)` calls separately.
- The Discord webhook id is redacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pyowler",
    "version": "1.0.0",
    "archive_sha256": "56e5884d24e97508aeaea82cd5b257dfc2e75eb62451480138008b226e5a6918",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pyowler-1.0.0.tar.gz",
    "package_root": "layer0/pyowler-1.0.0",
    "cluster_key": "bc459aac601c1d9fb01f3427d877c84dc23ca9389e7e66e08cfeb2e422c3697d",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = InstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "decoded_eval",
          "detached_child",
          "download_then_exec"
        ],
        "silent_failure": true
      },
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
      "setup.py: read in full. InstallCommand.run XORs a 4.4 KB escaped literal with a digit-string key literal and passes it to eval(compile(...,'exec')) inside a bare except. Decoded as data to derived d1 (decoder py_escaped_xor_literal, candidate); d1 read in full; nothing unread.",
      "Top-level setup.py code (setup_py hook) only reads README.md for long_description and calls setup(); no behaviour. pyowler/__init__.py and pyowler/modules/__init__.py are empty and not reached at install.",
      "d1 has no OS check, but every path is a Windows path. On Linux/macOS os.mkdir/open would create odd backslash-named files in the build cwd and subprocess.run on the .vbs would fail, swallowed by the bare except.",
      "Launch chain in d1: subprocess.run(shell=True) opens WIN32.vbs, which runs WIN32.bat with a hidden window (WshShell.Run ..., 0, no wait). The bat fetches three exes with bitsadmin, starts Startup\\WIN64.vbs to run two of them, and curls the login name to a Discord webhook.",
      "d1 line 9 holds a commented-out bitsadmin line (/dl/runtime) inside the triple-quoted WIN64.vbs text; it is written to the vbs file as text, not run as a batch command."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "all dropped paths are under C:\\Users\\<login>\\AppData and the chain runs .vbs/.bat files through Windows Script Host and cmd"
    },
    {
      "axis": "installed_tool",
      "value": [
        "wscript",
        "bitsadmin",
        "curl"
      ],
      "reason": "WIN32.vbs is started via file association, the bat downloads with bitsadmin and posts with curl"
    },
    {
      "axis": "network",
      "value": [
        "51[.]178[.]25[.]148:8081",
        "canary[.]discord[.]com:443"
      ],
      "reason": "second-stage executables are fetched from the IP; the login name is posted to a Discord webhook"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "C:\\Users\\<?>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\",
      "value_recovered": "partial",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 53,
            "end_byte": 162,
            "node_type": "call",
            "sha256": "1f62fb1204e76978",
            "line": 4
          }
        }
      ],
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\",
        "accessor": "exists"
      },
      "in_scope": true,
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "cmdclass",
      "expression": "c1",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 50,
            "end_byte": 2788,
            "node_type": "if_statement",
            "sha256": "6d02240db36aebbc",
            "line": 4
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "reinfection guard: the System64 folder is created by this payload, so the drop only runs when it is absent",
      "then": {
        "behaviours": [
          "write_file",
          "persistence",
          "download",
          "exec_downloaded",
          "exfil",
          "defense_evasion"
        ],
        "env_recipe": {
          "os": "win32",
          "file_absent": [
            "C:\\Users\\<login>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64"
          ]
        },
        "recipe_guessed_fields": [
          "os"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 178,
            "end_byte": 2765,
            "node_type": "stmt_range",
            "sha256": "085ee9aa37b8fca3",
            "line": 6
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 1577,
              "end_byte": 1690,
              "node_type": "call",
              "sha256": "c656be273dff4724",
              "line": 12
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 621,
              "end_byte": 733,
              "node_type": "call",
              "sha256": "24dd46626a4dd892",
              "line": 8
            },
            "witness": []
          },
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2623,
              "end_byte": 2765,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 13
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2623,
              "end_byte": 2765,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 13
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2623,
              "end_byte": 2765,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 13
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2623,
              "end_byte": 2765,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 13
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "write_file",
      "persistence",
      "download",
      "exec_downloaded",
      "exfil",
      "defense_evasion"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "repeating-key XOR of an escaped string literal with the key in code",
      "eval(compile(..., 'exec')) of the decoded source",
      "random-looking identifier names",
      "very long single-line literal"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://51[.]178[.]25[.]148:8081/dl/system",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://51[.]178[.]25[.]148:8081/dl/sys86",
        "role": "second_stage"
      },
      {
        "indicator": "hxxp://51[.]178[.]25[.]148:8081/dl/gamesdk",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://canary[.]discord[.]com/api/webhooks/1153…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "bitsadmin System64 Startup-vbs dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass decodes and evals hidden code that, when its System64 marker folder is absent, writes a Startup .vbs for persistence, drops a .bat that downloads three executables with bitsadmin and runs them, and posts the login name to a Discord webhook.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "condition value not fully recovered",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "data_site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 380,
            "end_byte": 4870
          },
          "key_site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 4905,
            "end_byte": 5007
          },
          "decoder": "py_escaped_xor_literal",
          "lang": "py"
        },
        "output_sha256": "6a4a9631f05be132"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "428960f5b8cf6c20"
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
    "condition_candidates": 0,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 0,
    "conditions_in_set": 0,
    "conditions_out_of_set": 1,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
