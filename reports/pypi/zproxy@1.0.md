# pypi zproxy@1.0

**Source:** datadog · **Source label:** malicious · **Released:** 2023-03-17 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs its payload at top level on every build step. It writes a one-line Python stager to a temp file and starts it detached with `start pythonw.exe <tmpfile>` through `os.system`, inside a bare `try/except: pass`. The stager fetches code from a paste site (hxxps://paste[.]bingner[.]com/paste/dsvc4/raw) and `exec()`s it. There are no gates: the only environmental dependency is that the launch only works on Windows (cmd `start`, `pythonw.exe`), recorded as a requirement along with network access to the paste host.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell, detached_child, download_then_exec; errors hidden.

## Gates

None.

## Requirements

- os: win32 (launch uses the cmd.exe 'start' builtin and pythonw.exe; it fails silently elsewhere)
- network: paste[.]bingner[.]com:443 (the stager downloads the second stage over HTTPS and execs it)

## Behaviour

- Ungated: write_file, spawn_process, download, exec_downloaded
- Gated: none

## Notes

- The second stage was not fetched, so its behaviour is not recovered.
- On non-Windows hosts `os.system` returns non-zero without raising, so the install completes cleanly and nothing launches.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "zproxy",
    "version": "1.0",
    "archive_sha256": "db50119270ba526dcd494396e9e6f14f21c93ca36a9a38f7010ab6bf7d085503",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-03-17",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-03-17-zproxy-v1.0.zip",
    "package_root": "layer0/2023-03-17-zproxy-v1.0/zproxy-1.0",
    "cluster_key": "2374db72a78b95e33b1c4c18e256d9fa24cceb6b9941c1a173727ee829009421",
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
      "setup.py: read in full (21 lines). Top-level code writes a one-line Python stager to a NamedTemporaryFile, then runs os.system('start <pythonw.exe> <tmpfile>') inside a bare try/except: pass.",
      "The stager, run by the detached pythonw process, fetches a paste URL with urllib and exec()s the response. The second stage was not fetched (static only), so what it does is not recovered.",
      "No environmental checks. 'start' is a cmd.exe builtin and the .exe to w.exe rewrite assumes Windows; on Linux or macOS os.system only returns a non-zero status and setup() continues, so the payload launches only on Windows.",
      "setup.cfg, PKG-INFO and egg-info files are metadata only; install_requires is [''] (empty). No zproxy package directory ships in the sdist."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "launch uses the cmd.exe 'start' builtin and pythonw.exe; it fails silently elsewhere",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 348,
          "end_byte": 419,
          "node_type": "call",
          "sha256": "8ee8fb76a2223640",
          "line": 8
        }
      ]
    },
    {
      "axis": "network",
      "value": "paste[.]bingner[.]com:443",
      "reason": "the stager downloads the second stage over HTTPS and execs it"
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
      "underscore-doubled import aliases (_ssystem, _uurlopen) that hide API names",
      "second-stage loader kept as a string, written to a temp file and run in a separate windowless interpreter"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://paste[.]bingner[.]com/paste/dsvc4/raw",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pythonw temp-file paste stager",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py unconditionally writes a stager to a temp file and launches it detached with pythonw on Windows; the stager downloads code from a paste site and executes it. The package ships no functional code.",
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
