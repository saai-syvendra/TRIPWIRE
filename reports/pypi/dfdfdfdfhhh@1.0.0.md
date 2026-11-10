# pypi dfdfdfdfhhh@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

On a pip install from the sdist, the `install` cmdclass override in `setup.py` runs `exec(base64.b64decode(...))`, a single base64 stage hidden off-screen behind a run of spaces. The stage has one gate: it only acts when its own drop folder (`System64` under the user's Start Menu Programs folder) does not exist yet, a reinfection guard. When that folder is absent it writes VBS, BAT and `.pyw` launchers, puts a VBS in the Startup folder for persistence, and runs a hidden VBS that starts a batch file. The batch file uses bitsadmin to download a zipped Python runtime and an executable from api-hw[.]com and starts them. There is no OS check, but the payload only works on Windows (on other systems the final `subprocess.run(check=True)` raises and the install fails).

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script, decoded_eval, detached_child, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: file_or_dir_exists not_exists C:\Users\<os.getlogin()>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System64\) | then | 1 | write_file, persistence, defense_evasion, spawn_process, download, exec_downloaded | file_absent=C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\System64\ |

Gate intent: g1 activate/enables/unclear

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- os: win32 (Hard-coded C:\Users paths, VBS launcher via WScript.Shell, cmd batch file and bitsadmin; elsewhere subprocess.run(check=True) fails and aborts the install.)
- installed_tool: wscript, cmd, bitsadmin (The .vbs is launched through its file association, it starts a .bat, which uses bitsadmin to fetch the second stage.)
- network: api-hw[.]com:443 (bitsadmin downloads runtime.zip and Windows Helper.exe over HTTPS from this host.)

## Behaviour

- Ungated: none
- Gated: write_file, persistence, defense_evasion, spawn_process, download, exec_downloaded

## Notes

- The tool did not recover the stage because `exec` sits inside a tuple statement (`type("By HW"), exec(...)`), which the existing `b64_exec` decoder skips. I wrote a candidate decoder `b64_exec_tuple` in `scratch/<key>/decoders/` and registered it as `d1`. It needs a person to review it and add a round-trip test before it moves into `tools/common/decoders/`.
- The download and execution of the second stage happen in the detached batch file, which keeps running after the install returns. The record anchors `download` and `exec_downloaded` on the `subprocess.run` that starts the chain.
- The second-stage contents (`runtime.zip`, `stub.pyw`, `Windows Helper.exe`) are not in the package and were not fetched.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "dfdfdfdfhhh",
    "version": "1.0.0",
    "archive_sha256": "3d60ebe5c1c0daaaca3c534ec45755a0b319f6eaf9594b4fffb783d55d793db4",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/dfdfdfdfhhh-1.0.0.tar.gz",
    "package_root": "layer0/dfdfdfdfhhh-1.0.0",
    "cluster_key": "1e1e6240dfa2f066ba1ef0e7bc133aa61e3d00469ea69e0619931447962b407a",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstallCommand",
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
        "silent_failure": false
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
      "setup.py: CustomInstallCommand.run executes a base64 stage via exec(base64.b64decode(...)), hidden as the second item of a tuple statement after ~350 spaces of padding. Not recovered by the tool.",
      "Registered candidate decoder b64_exec_tuple (scratch decoders/, needs review) as derivation d1; the existing b64_exec decoder skips exec calls inside a tuple statement. All anchors for the gate point into d1.",
      "setup.py: read in full, including the decoded stage (d1); nothing unread. Top-level setup.py code only calls setup(); the payload runs from the install cmdclass override.",
      "Decoded stage: creates a System64 folder under the Start Menu Programs folder, writes WIN32.vbs, WIN32.bat, sh.pyw there and WIN64.vbs into Startup, then runs WIN32.vbs with subprocess.run(shell=True, check=True).",
      "WIN32.vbs runs WIN32.bat with a hidden window (Run ..., 0) and does not wait, so the bat keeps running after install: bitsadmin downloads runtime.zip and Windows Helper.exe from the C2, then starts sh.pyw and WIN64.vbs.",
      "sh.pyw unpacks runtime.zip and runs its bundled pythonw.exe on stub.pyw, then deletes stub.pyw; WIN64.vbs (also in Startup) runs Windows Helper.exe hidden. Second stage contents are not in the package.",
      "No OS check. On non-Windows os.path.exists is False, mkdir/open create oddly named files in the cwd, and subprocess.run(check=True) of the .vbs path fails and raises, so the install aborts. Windows is an implicit requirement.",
      "dfdfdfdfhhh/__init__.py and requester.py are not reached at install (requester.py only prints at import)."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "Hard-coded C:\\Users paths, VBS launcher via WScript.Shell, cmd batch file and bitsadmin; elsewhere subprocess.run(check=True) fails and aborts the install."
    },
    {
      "axis": "installed_tool",
      "value": [
        "wscript",
        "cmd",
        "bitsadmin"
      ],
      "reason": "The .vbs is launched through its file association, it starts a .bat, which uses bitsadmin to fetch the second stage."
    },
    {
      "axis": "network",
      "value": "api-hw[.]com:443",
      "reason": "bitsadmin downloads runtime.zip and Windows Helper.exe over HTTPS from this host."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "C:\\Users\\<os.getlogin()>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 446,
            "end_byte": 564,
            "node_type": "comparison_operator",
            "sha256": "e70729af788e38fc",
            "line": 19
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\",
        "accessor": "exists"
      }
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
            "start_byte": 443,
            "end_byte": 3191,
            "node_type": "if_statement",
            "sha256": "a6ec91b71e2f1228",
            "line": 19
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Reinfection guard: the whole drop runs only when the System64 folder that the payload itself creates is absent.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "persistence",
          "defense_evasion",
          "spawn_process",
          "download",
          "exec_downloaded"
        ],
        "env_recipe": {
          "file_absent": [
            "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System64\\"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 579,
            "end_byte": 3157,
            "node_type": "stmt_range",
            "sha256": "edd6eb54e129a9b9",
            "line": 21
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2255,
              "end_byte": 3002,
              "node_type": "call",
              "sha256": "73700a05d6f47cc4",
              "line": 25
            },
            "witness": []
          },
          {
            "behaviour": "persistence",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 1038,
              "end_byte": 1378,
              "node_type": "call",
              "sha256": "09211dc3476124e3",
              "line": 23
            },
            "witness": []
          },
          {
            "behaviour": "defense_evasion",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 693,
              "end_byte": 1025,
              "node_type": "call",
              "sha256": "bdf33682019ccb2c",
              "line": 22
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 3015,
              "end_byte": 3157,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 26
            },
            "witness": []
          },
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 3015,
              "end_byte": 3157,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 26
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 3015,
              "end_byte": 3157,
              "node_type": "call",
              "sha256": "e326e98942cbcadc",
              "line": 26
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
      "write_file",
      "persistence",
      "defense_evasion",
      "spawn_process",
      "download",
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "single base64 layer executed with exec (dynamic_eval)",
      "exec call pushed off-screen by a long run of spaces on the same line (very_long_lines)",
      "decoy no-op type(\"By HW\") in front of the exec in a tuple statement"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api-hw[.]com/dl/runtime",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://api-hw[.]com/dl/w",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "startup-vbs bitsadmin dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override execs a hidden base64 stage that drops VBS/BAT launchers, adds a Startup-folder VBS for persistence and runs a batch file that downloads and starts a Python runtime stub and an executable from a remote host. The only check is a reinfection guard on its own drop folder.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
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
          "decoder": "b64_exec_tuple",
          "lang": "py"
        },
        "output_sha256": "1a03062e2f8c61fe"
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
