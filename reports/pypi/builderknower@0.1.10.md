# pypi builderknower@0.1.10

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command, so `CustomInstallCommand.run` executes on a normal pip install. It writes `install_log.txt`, touches `/tmp/pytest`, tries `mkdir -p /var/task/icanhavewrite` (the AWS Lambda task root), and then runs curl to send the base64-encoded output of `env` to a remote host. There are no gates: the try/except blocks around `os.system` never change course because `os.system` does not raise on command failure. Any Linux environment with curl, GNU base64 and outbound HTTPS triggers the exfil.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script, inline_shell; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: diddlydingusdu[.]de:443 (curl sends the base64-encoded environment to this host)
- installed_tool: curl (exfil is done with curl via os.system)
- installed_tool: base64 (env output is encoded with GNU base64 -w 0 inside the command substitution)
- os: linux (POSIX shell command substitution and the GNU-only base64 -w flag)

## Behaviour

- Ungated: write_file, recon, exfil
- Gated: none

## Notes

- The tool's try/except candidate (k_15b3645825, q_b645ea0bb3) was dropped as not environmental; it is error swallowing only.
- The `/var/task` mkdir and `/tmp/pytest` touch look like probing for a serverless or CI build environment, but no result is read back.
- The `TEST_SITE` URL and the `requests` call are in commented-out code only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "builderknower",
    "version": "0.1.10",
    "archive_sha256": "cd18dd0d42fc519c172d28bb0675bbf1727303383dde272ca5887bd97f895ab0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/builderknower-0.1.10.tar.gz",
    "package_root": "layer0/builderknower-0.1.10",
    "cluster_key": "7ee29ab5ebb9bc394ba8747392c88b00cd9187e5e255425c2300b4f45ea8199c",
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
      "setup.py read in full (the only install-reached file; no pyproject.toml, so setuptools runs it). Top level only calls setup(). builderknower/ modules are not reached at install.",
      "CustomInstallCommand.run writes install_log.txt, runs echo, touch /tmp/pytest and mkdir -p /var/task/icanhavewrite, then curl sends base64 of the full env output to a remote URL.",
      "The try/except blocks around os.system are not gates: os.system does not raise when the command fails, so both try bodies always run; exit codes are discarded (silent_failure).",
      "/var/task is the AWS Lambda task root; the mkdir there looks like a write-permission probe, but its result is never tested, so it is not a condition.",
      "The TEST_SITE URL and the requests call appear only in commented-out code and are not contacted."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "diddlydingusdu[.]de:443",
      "reason": "curl sends the base64-encoded environment to this host"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "exfil is done with curl via os.system"
    },
    {
      "axis": "installed_tool",
      "value": "base64",
      "reason": "env output is encoded with GNU base64 -w 0 inside the command substitution"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX shell command substitution and the GNU-only base64 -w flag"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "write_file",
      "recon",
      "exfil"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "environment dump base64-encoded inside a shell command substitution before exfil"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://diddlydingusdu[.]de/X/$",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The cmdclass install override runs curl at install to send base64 of every environment variable (which can hold tokens and cloud credentials) to a remote host, with no gate in front. It also probes write access to the AWS Lambda path /var/task.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "e54f689356b87ac3"
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
        "candidate": "k_15b3645825",
        "reason_code": "not_environmental",
        "note": "os.system inside the try never raises when curl fails; the try body always runs, so this is not a check on the environment",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1536,
          "end_byte": 1606,
          "node_type": "call",
          "sha256": "c5d6d2fa0a7ad885",
          "line": 49
        }
      },
      {
        "candidate": "q_b645ea0bb3",
        "reason_code": "not_environmental",
        "note": "try/except around os.system only swallows errors; recorded as silent_failure on the entry point, not a gate",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1519,
          "end_byte": 1658,
          "node_type": "try_statement",
          "sha256": "5abd2c5be1d20875",
          "line": 48
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
