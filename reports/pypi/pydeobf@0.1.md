# pypi pydeobf@0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2024-10-15 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command (`cmdclass`), so `CustomInstallCommand.run` runs on a normal pip install. It shells out to PowerShell `Invoke-WebRequest` to fetch `CBLines.exe` from hxxps://github[.]com/holdthatcode/e/raw/main/CBLines.exe into the build directory, then starts it with `Start-Process`, then runs the normal install. There is no environment gate. The only branch checks that the download exited 0 and the file exists, which is a prerequisite. The payload needs Windows, the `powershell` binary and outbound access to github.com:443.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script, inline_shell, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- os: win32 (Uses Windows PowerShell (powershell binary) and Start-Process on a Windows .exe)
- installed_tool: powershell (Download and launch are both powershell -Command lines)
- network: github[.]com:443 (Second stage fetched from a GitHub raw URL; the launch only runs if the download exits 0 and the file exists)

## Behaviour

- Ungated: download, exec_downloaded
- Gated: none

## Notes

- Dropped candidates `k_9299f491be`/`q_3575928f06`: download-success check, not a deliberate environment test.
- The comment above the launch calls the file an "MP3 file", but the code runs an `.exe`. Recorded as misleading text.
- The package modules only print "hello" and are not reached at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pydeobf",
    "version": "0.1",
    "archive_sha256": "91a38bc0e5379e3f6f13b61d4a9785b0855244aa726e7230a64089cfca86f6cf",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-10-15",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2024-10-15-pydeobf-v0.1.zip",
    "package_root": "layer0/tmp/tmpihk9yo3k/pydeobf/pydeobf-0.1",
    "cluster_key": "2a0133122872cce2392891470940b483c0de71ff28efbffdd41cf0b94c5c76f2",
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
      "setup.py read in full; pydeobf/__init__.py and pydeobf/pydeobf.py only print a string and are not reached at install.",
      "CustomInstallCommand.run downloads CBLines.exe from GitHub into os.getcwd() via powershell Invoke-WebRequest (subprocess.run, shell=True), then runs it with powershell Start-Process, then calls install.run.",
      "The only decision (line 15: returncode == 0 and os.path.exists(output_file)) tests that the payload's own download succeeded; recorded as requirements (network, powershell, Windows), not a gate.",
      "Comment at line 18 calls the downloaded file an MP3 file being opened; the code launches CBLines.exe, an executable. Recorded as misleading text.",
      "setup_py hook: top-level code only calls setup(); no behaviour of its own."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "Uses Windows PowerShell (powershell binary) and Start-Process on a Windows .exe"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "Download and launch are both powershell -Command lines"
    },
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "Second stage fetched from a GitHub raw URL; the launch only runs if the download exits 0 and the file exists",
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
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
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
  "assessment_reason": "The install command override downloads an executable from a GitHub raw URL with PowerShell and launches it before running the normal install. No environment gate; it only needs Windows, PowerShell and network access.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: comment at setup.py line 18 calls the launched CBLines.exe an MP3 file"
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
        "note": "os.path.exists on the file the payload just downloaded, together with its returncode: download success, a prerequisite (network requirement)",
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
        "note": "if on download returncode == 0 and the downloaded file existing; only checks the payload's own download worked",
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
