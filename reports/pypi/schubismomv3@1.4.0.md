# pypi schubismomv3@1.4.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`setup.py` registers a `cmdclass` install override (`GruppeInstall`) that runs on a normal pip install of the sdist. Its `run` method is guarded by a single gate, `if os.name == "nt"`: only on Windows does it write an embedded one-line script to `%APPDATA%\gruppe.py` and launch it with `subprocess.Popen([sys.executable, gruppe_path], creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS)`, leaving a hidden child running after install returns. The dropped script is `exec(Fernet(b'<key>').decrypt(b'<blob>').decode())`, so the real payload is a Fernet-encrypted second stage. On any non-Windows OS the hook falls through to the normal `install.run(self)` and does nothing malicious. The install-time behaviours are therefore dropping a file and spawning the hidden child; the second stage itself is encrypted and not recovered.

## Execution

- **cmdclass** `cmdclass[install] = GruppeInstall`: runs setup.py; direct_script, detached_child.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 (c1: os == nt) | then | 1 | write_file, spawn_process | os=win32 |

Gate intent: g1 activate/enables/targeting

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process

## Notes

- One gate, g1: `c1` = `os.name == "nt"` (category `os`, in scope). Polarity activate, effect enables, purpose targeting. No else behaviour (the else side just proceeds to the normal install).
- The second stage is Fernet (AES-CBC+HMAC) encrypted. It was not decrypted: AES is not available to the replayable stdlib decoder framework, and it runs in a detached child. Its own behaviours and C2 are not recovered, so the record is flagged for manual review and `needs_remote` is set from the readable install code only (false).
- `install_requires=['fernet']` pulls the `fernet` package so the dropped child can decrypt the payload (dependency tree).
- `setup.py` is read in full. Package metadata (`keywords=['ratting']`, author, Windows-only classifier) is consistent with a Windows RAT dropper but is package text and does not drive the label; the label rests on the drop-and-exec code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "schubismomv3",
    "version": "1.4.0",
    "archive_sha256": "ad69b41870bac36f48682dd4fc5b5d43ac7515a3fb88c66c3972dd135d21c7f2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/schubismomv3-1.4.0.tar.gz",
    "package_root": "layer0/schubismomv3-1.4.0",
    "cluster_key": "53ccc266c1f8a5272905922c92fccd87f83b55852ac0da18859701f7285ff76a",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = GruppeInstall",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "detached_child"
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
      "setup.py: package code read in full. The malicious code lives in GruppeInstall.run (the cmdclass install override), which runs on a normal pip install of the sdist; top-level setup() only registers it.",
      "On os.name == nt the install writes an embedded one-line script to %APPDATA%/gruppe.py and launches it with subprocess.Popen([sys.executable, gruppe_path], creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS), so a hidden child survives after install returns.",
      "The embedded gruppe.py content is `exec(Fernet(b'<key>').decrypt(b'<blob>').decode())`; the Fernet (AES-CBC+HMAC) blob is the second stage.",
      "The Fernet blob is not decrypted (AES is unavailable to the replayable stdlib decoder framework) and runs in the detached child, so its own behaviours and C2 endpoints are not recovered.",
      "install_requires=['fernet'] pulls the fernet package so the dropped child can decrypt the payload (dependency tree)."
    ]
  },
  "requirements": [],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "os.name",
      "operator": "==",
      "value": "nt",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_3da5be7493",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 291,
            "end_byte": 306,
            "node_type": "comparison_operator",
            "sha256": "03f6fcec9e8705f1",
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
      "hook": "cmdclass",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_0f6d368420",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 288,
            "end_byte": 35688,
            "node_type": "if_statement",
            "sha256": "a1238ba98d61b1ce",
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
      "purpose": "targeting",
      "purpose_reason": "The drop-and-exec payload only exists for Windows (writes to %APPDATA%, hides the child with CREATE_NO_WINDOW); the else side only runs the normal install.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 324,
            "end_byte": 35688,
            "node_type": "block",
            "sha256": "e7a57726ea081258",
            "line": 13
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 35479,
              "end_byte": 35501,
              "node_type": "call",
              "sha256": "91c88024a44f1487",
              "line": 22
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 35569,
              "end_byte": 35688,
              "node_type": "call",
              "sha256": "29dd6c6abaa0abeb",
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
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "Fernet-encrypted second stage",
      "long base64 literal",
      "very long lines"
    ],
    "decoded": null,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "The embedded gruppe.py second stage is a Fernet (AES-CBC+HMAC) encrypted blob; AES is not available to the replayable stdlib decoder framework, so the plaintext is not recovered. It runs in the detached child."
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "On Windows, the pip install hook writes a Fernet-encrypted Python second stage to %APPDATA%/gruppe.py and launches it as a hidden, detached process during install. This drop-and-exec of an encrypted payload in a concealed child process has no benign purpose.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "The Fernet-encrypted second stage (dropped gruppe.py) is not decrypted, so the child process's own behaviours and C2 endpoints are not recovered; needs_remote is set from the readable install code only.",
    "unrecovered code"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "5a1af77e0a78ff79"
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
