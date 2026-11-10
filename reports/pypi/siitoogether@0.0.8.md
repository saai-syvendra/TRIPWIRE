# pypi siitoogether@0.0.8

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command (`CustomInstall`). After the normal install it does `import siitoogether`, which runs the package's `__init__.py` top level during the build. That code sends stdout and stderr to devnull and starts `run_client` in a daemon thread. The thread pip installs `discord` and `aiohttp` if they are missing, then logs in to Discord with a base64-encoded bot token, registers a session id built from host info, polls a C2 channel and runs operator commands through a shell, posting the output back. There is no environment gate: the only `platform.system()` check picks the shell (default or `/bin/bash`) for the same command, so it is plumbing.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: 2-file chain; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 (pip installs discord and aiohttp if they are missing)
- network: 8[.]8[.]8[.]8:53, 8[.]8[.]4[.]4:53, 1[.]1[.]1[.]1:53 (aiohttp AsyncResolver uses these nameservers for the Discord connection)
- network: discord[.]com:443, gateway[.]discord[.]gg:443 (discord.py bot client logs in with an embedded bot token and polls a C2 channel)
- installed_tool: pip (sys.executable -m pip install for discord/aiohttp)
- file_present: /bin/bash (operator commands run with executable=/bin/bash on non-Windows)
- other: Discord C2 guild with channels command-and-control, get-commands, command-results and commands posted for this session (on_ready only registers and polls when all three channels are found)

## Behaviour

- Ungated: recon, download, spawn_process, reverse_shell, exfil
- Gated: none

## Notes

- The payload runs in a daemon thread of the build process, so at install it only lives until setup.py finishes. It is reachable, but a scanner may see only the pip install of `discord`/`aiohttp` and the start of the Discord connection.
- The embedded bot token is not recorded (rule 5). It decodes to a Discord bot token string.
- C2 behaviour depends on the attacker's Discord guild state (three named channels, commands addressed to the session). These are listed as requirements.
- The package describes itself as "a security tool for CTF exercises". The install code is a working remote command backdoor, so this text does not change the label.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "siitoogether",
    "version": "0.0.8",
    "archive_sha256": "ab3206c6cc49175de86d036d6d021cab73221ee6e201f6d41b9e0750b4f74cb0",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/siitoogether-0.0.8.tar.gz",
    "package_root": "layer0/siitoogether-0.0.8",
    "cluster_key": "2515dc6a93b37259792c1f05f7f1d58287cd95f10b88779f67935763ce8261b2",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstall",
        "runs_on": "always",
        "file_chain": [
          "setup.py",
          "siitoogether/__init__.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
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
    "delays": [
      {
        "site": "siitoogether/__init__.py:144",
        "seconds": 5
      },
      {
        "site": "siitoogether/__init__.py:150",
        "seconds": 10
      },
      {
        "site": "siitoogether/__init__.py:165",
        "seconds": 3
      },
      {
        "site": "siitoogether/__init__.py:168",
        "seconds": 10
      }
    ],
    "notes": [
      "CustomInstall.run calls install.run, then post_install does `import siitoogether`, which runs __init__.py top level: stdout/stderr go to devnull and run_client starts in a daemon thread.",
      "The thread is a daemon of the build process, so the C2 loop only lives as long as the setup.py process after the import; the payload is racy at install time but reachable.",
      "setup.py and siitoogether/__init__.py read in full. siitoogether/main.py is only a console_scripts entry and is not reached at install.",
      "The platform.system() == 'Windows' check in execute_command only picks the shell (default vs /bin/bash) for the same operator command; treated as plumbing, not a gate.",
      "find_spec checks for discord/aiohttp only decide whether to pip install them first; a failed pip install aborts. Prerequisite plumbing, listed under requirements.",
      "C2 protocol checks (guild has command-and-control/get-commands/command-results channels, message Session matches SESSION_ID) depend on the attacker's Discord server state; recorded as requirements, not gates.",
      "setup_py hook: setup.py top level only reads README.md and calls setup(); the import of the package happens only inside the cmdclass install override, so __init__.py is removed from that chain.",
      "write_error_log appends exception text to ~/.siitoogether_errors only when post_install raises; not recorded as a behaviour."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "pip installs discord and aiohttp if they are missing"
    },
    {
      "axis": "network",
      "value": [
        "8[.]8[.]8[.]8:53",
        "8[.]8[.]4[.]4:53",
        "1[.]1[.]1[.]1:53"
      ],
      "reason": "aiohttp AsyncResolver uses these nameservers for the Discord connection"
    },
    {
      "axis": "network",
      "value": [
        "discord[.]com:443",
        "gateway[.]discord[.]gg:443"
      ],
      "reason": "discord.py bot client logs in with an embedded bot token and polls a C2 channel"
    },
    {
      "axis": "installed_tool",
      "value": "pip",
      "reason": "sys.executable -m pip install for discord/aiohttp"
    },
    {
      "axis": "file_present",
      "value": "/bin/bash",
      "reason": "operator commands run with executable=/bin/bash on non-Windows"
    },
    {
      "axis": "other",
      "value": "Discord C2 guild with channels command-and-control, get-commands, command-results and commands posted for this session",
      "reason": "on_ready only registers and polls when all three channels are found"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "download",
      "spawn_process",
      "reverse_shell",
      "exfil"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "base64-encoded Discord bot token",
      "stdout and stderr redirected to devnull to hide activity during install"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "discord[.]com",
        "role": "c2"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord bot C2 backdoor",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass imports the package, whose top-level code silently pip installs discord/aiohttp and starts a Discord bot that registers host info and runs operator shell commands, returning the output. No environment gate guards it.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "60026cb9b5bcf851"
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
        "candidate": "k_eeafdbe8fb",
        "reason_code": "other",
        "note": "OS check only picks the shell (default vs /bin/bash) for the same operator command; plumbing",
        "anchor": {
          "file": "siitoogether/__init__.py",
          "derived_from": null,
          "start_byte": 7055,
          "end_byte": 7085,
          "node_type": "comparison_operator",
          "sha256": "90c6b5a13d986f8a",
          "line": 196
        }
      },
      {
        "candidate": "q_73c8c3444a",
        "reason_code": "other",
        "note": "if on platform.system() only picks the shell for the same Popen of the C2 command; plumbing",
        "anchor": {
          "file": "siitoogether/__init__.py",
          "derived_from": null,
          "start_byte": 7052,
          "end_byte": 7477,
          "node_type": "if_statement",
          "sha256": "bc2c252bfa742c16",
          "line": 196
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 0,
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
