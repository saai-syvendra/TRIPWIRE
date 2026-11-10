# pypi larpexodus@0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command, so `CustomInstallCommand.run` runs on a normal pip install. It shells out to `powershell -Command Invoke-WebRequest` to download CBLines.exe from a GitHub raw URL (hxxps://github[.]com/holdthatcode/e/raw/main/CBLines.exe) into the current directory. If that command exits 0 and the file exists, it starts the file with `Start-Process`, then runs the normal install. There are no environment gates; the only branch checks that its own download worked.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script, inline_shell, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- installed_tool: powershell (Both the download (Invoke-WebRequest) and the launch (Start-Process) run through powershell -Command.)
- os: win32 (The second stage is a Windows .exe started with Start-Process; powershell is native only on Windows.)
- network: github[.]com:443 (The second stage CBLines.exe is downloaded from a GitHub raw URL; launch only happens when the download succeeds.)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- The line 15 candidate (exit code plus `os.path.exists` on the downloaded file) is dropped as a prerequisite check. The needs are recorded as requirements: powershell, Windows, and github.com:443.
- The second stage was not retrieved or analysed (static only, no URL fetches).
- A comment calls the file an "MP3" while the code downloads and starts an .exe. The comment contradicts the code, so it is recorded as misleading text and flagged for review. It does not raise the obfuscation level.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "larpexodus",
    "version": "0.1",
    "archive_sha256": "d6942ef7bff3c44886dc01ab155d0a40967974ed9c0b3e442ff6f451924fbf4d",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/larpexodus-0.1.tar.gz",
    "package_root": "layer0/larpexodus-0.1",
    "cluster_key": "49cf99c67dd26dcb27f0a31b121c5be7f98348c496d87be4af48f6f366f8c708",
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
          "inline_shell",
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
      "setup.py: read in full (41 lines). Top level only calls setup(); the install override CustomInstallCommand.run holds all behaviour. larpexodus/ package code only prints hello and is not reached at install.",
      "The only branch (line 15) tests the payload's own download: PowerShell exit code 0 and the downloaded CBLines.exe existing in the cwd. It is a prerequisite check on the download, not an environment gate, so it is dropped and the needs go in requirements.",
      "Download and launch both go through powershell via shell=True, so the payload effectively needs Windows (or pwsh on PATH). Start-Process result is printed but not checked.",
      "Misleading text: the comment at setup.py:18 calls the file a downloaded MP3, but the code downloads and starts an .exe."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "Both the download (Invoke-WebRequest) and the launch (Start-Process) run through powershell -Command.",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 541,
          "end_byte": 596,
          "node_type": "call",
          "sha256": "6323d04f3408a2b9",
          "line": 13
        }
      ]
    },
    {
      "axis": "os",
      "value": "win32",
      "reason": "The second stage is a Windows .exe started with Start-Process; powershell is native only on Windows."
    },
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "The second stage CBLines.exe is downloaded from a GitHub raw URL; launch only happens when the download succeeds."
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
    "techniques": [
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/holdthatcode/e/raw/main/CBLines.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override downloads an executable from a GitHub raw URL with PowerShell and starts it with Start-Process during pip install, with no environment checks beyond the download succeeding.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Rule 8: comment at setup.py:18 says the code opens a downloaded MP3 file; the code downloads and starts CBLines.exe."
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "51e32a3d89886fbe"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_9299f491be",
        "reason_code": "not_environmental",
        "note": "os.path.exists on the CBLines.exe the payload itself just downloaded, together with the download's exit code: a success check on its own download, recorded as a network requirement.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 647,
          "end_byte": 674,
          "node_type": "call",
          "sha256": "e1f5366564f7e23a",
          "line": 15
        }
      },
      {
        "candidate": "q_3575928f06",
        "reason_code": "not_environmental",
        "note": "The if around Start-Process tests only the download result (returncode == 0 and the downloaded file existing); prerequisite, not a gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 608,
          "end_byte": 1169,
          "node_type": "if_statement",
          "sha256": "41ab9e1621b722b2",
          "line": 15
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 2,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
