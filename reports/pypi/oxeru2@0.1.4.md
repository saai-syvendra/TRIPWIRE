# pypi oxeru2@0.1.4

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` command (`PostInstallCommand`), so `createfile()` runs during a pip install. It sends a GET request to an attacker domain (the response is not used, probably a check-in), then connects a TCP socket to 134.209.85[.]64:8080, duplicates stdin, stdout and stderr onto it and starts `/bin/sh` with `pty.spawn`. There are no environment gates: the shell runs on any machine that can import `pty` (so not Windows) and reach both hosts.

## Execution

- **cmdclass** `cmdclass[install] = PostInstallCommand`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: minagolosinastorpedolocutormarcar[.]com:443 (urlopen GET must succeed or the exception aborts install.run before the reverse shell)
- network: 134[.]209[.]85[.]64:8080 (reverse shell socket.connect target; a failed connect raises and aborts)
- installed_tool: /bin/sh (pty.spawn('/bin/sh') is the shell handed to the socket)
- os: linux (top-level import pty needs termios, so setup.py fails on win32; linux or darwin works)

## Behaviour

- Ungated: reverse_shell
- Gated: none

## Notes

- Neither network call is guarded or caught, so a dead domain or closed port aborts the install before the shell starts. Phase 2 needs both endpoints reachable (or sinkholed to accept the connection) to see the payload.
- The urlopen has role `c2` as a likely check-in; nothing from the response is used.
- The `url` metadata (google[.]com) is never contacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "oxeru2",
    "version": "0.1.4",
    "archive_sha256": "3d2546a4cf86b972bb763af8e56cad597c989a8cdaff982ea37e0ab0676b2a14",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/oxeru2-0.1.4.tar.gz",
    "package_root": "layer0/oxeru2-0.1.4",
    "cluster_key": "94dbab755de6c5b46fa835ec47e42ebf03f099119e8274a79e983069eafa6d7b",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
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
      "setup.py: package code read in full (35 lines); nothing bundled or unread.",
      "createfile() is called only from PostInstallCommand.run, so the setup_py hook's top-level code only imports modules and calls setup(); the payload runs on the install command of a pip sdist build.",
      "No gates: urlopen of an attacker page (response unused), then a TCP connect to 134.209.85[.]64:8080, fds 0-2 duplicated onto the socket and pty.spawn('/bin/sh'). Nothing catches errors.",
      "If the urlopen or connect fails, the exception aborts the install before the shell; these are requirements, not gates. pty.spawn blocks the install until the shell exits.",
      "Top-level 'import pty' needs termios, which is missing on Windows, so setup.py aborts there before setup(); recorded as an os requirement, not a gate.",
      "The url field in setup() (google[.]com) is metadata only and never contacted."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "minagolosinastorpedolocutormarcar[.]com:443",
      "reason": "urlopen GET must succeed or the exception aborts install.run before the reverse shell"
    },
    {
      "axis": "network",
      "value": "134[.]209[.]85[.]64:8080",
      "reason": "reverse shell socket.connect target; a failed connect raises and aborts"
    },
    {
      "axis": "installed_tool",
      "value": "/bin/sh",
      "reason": "pty.spawn('/bin/sh') is the shell handed to the socket"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "top-level import pty needs termios, so setup.py fails on win32; linux or darwin works"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "reverse_shell"
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
        "indicator": "hxxps://minagolosinastorpedolocutormarcar[.]com/golosinapastortorpedopularie.html",
        "role": "c2"
      },
      {
        "indicator": "134[.]209[.]85[.]64",
        "role": "reverse_shell"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The cmdclass install override fetches an attacker page and then opens an ungated reverse shell (/bin/sh over a socket to 134.209.85[.]64:8080) during pip install of the sdist.",
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
