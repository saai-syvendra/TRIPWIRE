# pypi pycolorz@0.0.8

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs its malicious code at top level, so it executes on any pip build of the sdist. It writes a one-line Python stager to a temp file and launches it detached and windowless with `start pythonw.exe <tmpfile>` through `os.system`, wrapped in a bare `try/except: pass`. The stager fetches `hxxps://paste[.]bingner[.]com/paste/39kv9/raw` and execs the response. There are no gates: nothing checks the environment. The launch only works on Windows (cmd `start`, `pythonw.exe`), which is recorded as a requirement.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, detached_child, download_then_exec; errors hidden.

## Gates

None.

## Requirements

- os: win32 (launch uses the cmd 'start' builtin and pythonw.exe (sys.executable with .exe replaced); fails elsewhere)
- network: paste[.]bingner[.]com:443 (stager downloads the second stage over HTTPS and execs it)

## Behaviour

- Ungated: write_file, spawn_process, download, exec_downloaded
- Gated: none

## Notes

- The second stage was not fetched, so what it does is unknown.
- On non-Windows hosts the `os.system` call fails silently. A Linux-only scanner would see only the temp file write.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pycolorz",
    "version": "0.0.8",
    "archive_sha256": "b132bbbecee1a89ebd88bd6c2fd7793170a80bd2042c5dcd0585b5011e7e1fd0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/pycolorz-0.0.8.tar.gz",
    "package_root": "layer0/pycolorz-0.0.8",
    "cluster_key": "a7950329f71793f5409216a84dcc0539b1e185798888633e90c1406aea99131c",
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
      "setup.py read in full (26 lines). Top-level code writes a one-line Python stager to a NamedTemporaryFile, then os.system(\"start <pythonw.exe> <tmpfile>\") inside a bare try/except: pass.",
      "The stager does urlopen(paste URL).read() and exec()s the response; the second stage was not fetched and is not analysed.",
      "No environment check of any kind. The 'start' shell builtin and pythonw.exe make the launch work only on Windows; on Linux/macOS os.system fails silently. Recorded as an os requirement, not a gate.",
      "pycolorz/ package modules run only on import, not at install; not read for this record."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "launch uses the cmd 'start' builtin and pythonw.exe (sys.executable with .exe replaced); fails elsewhere",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 679,
          "end_byte": 750,
          "node_type": "call",
          "sha256": "8ee8fb76a2223640",
          "line": 18
        }
      ]
    },
    {
      "axis": "network",
      "value": "paste[.]bingner[.]com:443",
      "reason": "stager downloads the second stage over HTTPS and execs it"
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
      "underscore-prefixed import aliases (_ssystem, _ffile, _eexecutable) to hide os.system/tempfile/sys.executable",
      "payload stager embedded as a bytes literal written to a temp file",
      "remote second stage fetched and exec'd at runtime"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://paste[.]bingner[.]com/paste/39kv9/raw",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pythonw-tempfile-urlopen-exec stager",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py unconditionally writes a stager that downloads code from a paste site and execs it, and launches it windowless and detached with pythonw via 'start', swallowing errors. Classic install-time downloader.",
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
