# pypi proxycpz@1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2023-04-02 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs top-level code on every pip build. It writes a one-line Python loader to a temp file and starts it with `os.system("start pythonw.exe <tempfile>")`, wrapped in a bare `try/except: pass`. The loader fetches a paste-site text file and `exec`s it, so the real payload is a remote second stage that is not in the package. There are no gates. The launch only works on Windows (`start` builtin, `pythonw.exe`) and needs the paste host to be reachable, which are recorded as requirements.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, detached_child, download_then_exec; errors hidden.

## Gates

None.

## Requirements

- os: win32 (launch uses the cmd.exe builtin 'start' and pythonw.exe derived from sys.executable; fails silently elsewhere)
- installed_tool: pythonw.exe (the loader is started with pythonw.exe next to the installing interpreter)
- network: paste[.]website:443 (the loader downloads the second stage from a paste site and execs it)

## Behaviour

- Ungated: write_file, spawn_process, download, exec_downloaded
- Gated: none

## Notes

- Paste URL share id redacted to `400c…`. Second stage not recovered (remote, not fetched).
- `proxycpz/solver.py` is not reached at install.
- On non-Windows hosts the `start` command fails and the failure is hidden, so a stock Linux sandbox sees only a temp file write.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "proxycpz",
    "version": "1.0",
    "archive_sha256": "7f16f3865e18b65793456642b2d2ea6184716ced6a162c481c3a4616005aea92",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-04-02",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-04-02-proxycpz-v1.0.zip",
    "package_root": "layer0/2023-04-02-proxycpz-v1.0/proxycpz-1.0",
    "cluster_key": "3f35bcd6e8cf7a10b53a3c3e2ad6955c2d6de797b4ac8873ed8bd101743dbb6c",
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
          "detached_child",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (24 lines). Top-level code writes a one-line Python loader to a NamedTemporaryFile(delete=False), then os.system runs 'start <pythonw.exe> <tempfile>' inside try/except: pass.",
      "The loader does urlopen(<paste URL>).read() and exec()s the response, so the second stage is fetched and run by the detached pythonw process; its content is not in the package.",
      "No environmental check exists. 'start' is a cmd.exe builtin and the '.exe' -> 'w.exe' rewrite only makes sense on Windows; on Linux/macOS the shell command fails silently. Recorded as an os requirement, not a gate.",
      "proxycpz/solver.py is not reached at install (only listed in packages=); out of scope."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "launch uses the cmd.exe builtin 'start' and pythonw.exe derived from sys.executable; fails silently elsewhere",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 373,
          "end_byte": 444,
          "node_type": "call",
          "sha256": "8ee8fb76a2223640",
          "line": 9
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "pythonw.exe",
      "reason": "the loader is started with pythonw.exe next to the installing interpreter"
    },
    {
      "axis": "network",
      "value": "paste[.]website:443",
      "reason": "the loader downloads the second stage from a paste site and execs it"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "write_file",
      "spawn_process",
      "download",
      "exec_downloaded"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "imports aliased to underscore-doubled names (_ssystem, _eexecutable, _uurlopen)",
      "second-stage loader embedded as a string and written to a temp file",
      "remote code fetched and exec'd at runtime"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://paste[.]website/p/400c…",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "tempfile pythonw paste-loader",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py unconditionally writes a loader to a temp file and starts it detached with pythonw.exe; the loader downloads code from a paste site and execs it. No legitimate build purpose.",
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
