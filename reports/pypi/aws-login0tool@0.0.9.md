# pypi aws-login0tool@0.0.9

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides setuptools' `install` command with `SneakyInstall`, so the code runs on a normal pip install from source. Its `run` method downloads `syswin32.exe` from hxxps://tryg[.]ga into the build directory and starts it through `cmd`'s `start` builtin with `shell=True`. There are no gates: nothing checks the OS or anything else first, and a `try/except` prints and swallows any error. The exec step only works on Windows, which is recorded as a requirement along with reaching the download host.

## Execution

- **cmdclass** `cmdclass[install] = SneakyInstall`: runs setup.py; direct_script, download_then_exec, dropped_binary, inline_shell; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: tryg[.]ga:443 (second-stage exe is downloaded from this host before it is started)
- os: win32 (the downloaded file is launched with the cmd.exe builtin 'start' and is a Windows executable)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- The github and example[.]com URLs come from a source comment and the `setup()` metadata. The install never contacts them, so they were removed from the endpoints.
- On non-Windows hosts the download still happens and the file is written; only the `start` launch fails, and `run()` does not raise because `check` is not set.
- No family hint: the code is a generic download-and-run dropper.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aws-login0tool",
    "version": "0.0.9",
    "archive_sha256": "047b79094e652de23c8b474e13e93fbdc52761a1453c178b0f321f90605fc526",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/aws-login0tool-0.0.9.tar.gz",
    "package_root": "layer0/aws-login0tool-0.0.9",
    "cluster_key": "be648d57275eac7a8098227634ca0e0d300cc78fcef3c6f087536028d3a7d47d",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = SneakyInstall",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "download_then_exec",
          "dropped_binary",
          "inline_shell"
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
      "setup.py read in full. SneakyInstall.run downloads an exe to the build cwd and starts it with the cmd builtin 'start' (shell=True). No environment check precedes it; the except only prints the error.",
      "The setup_py hook top level only reads README.md and calls setup(); build plumbing. src/aws-login0tool/ (empty __init__.py, example.py) is not reached at install.",
      "The 'start' builtin only exists in cmd.exe, so the exec step only succeeds on Windows; on Linux/macOS the shell reports command not found and run() returns without raising (no check=True). Recorded as a requirement, not a gate.",
      "SneakyInstall.run never calls super().run(), so the real install step does nothing."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "tryg[.]ga:443",
      "reason": "second-stage exe is downloaded from this host before it is started"
    },
    {
      "axis": "os",
      "value": "win32",
      "reason": "the downloaded file is launched with the cmd.exe builtin 'start' and is a Windows executable"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
      "write_file",
      "exec_downloaded"
    ],
    "gated": []
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
        "indicator": "hxxps://tryg[.]ga/syswin32.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "A cmdclass install override downloads syswin32.exe from a remote host and starts it with no environment check. Errors are swallowed and the real install step is never run.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
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
    "conditions_out_of_set": 0,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
