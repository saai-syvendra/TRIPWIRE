# pypi roblcx_cookie3@0.0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py overrides the setuptools `install` and `develop` commands; both `run` methods call `execute()` before anything else. `execute()` downloads Cleaner.exe from a repl.co host with `requests.get`, writes it to the current directory and starts it with `os.system("set __COMPACT_LAYER=RunAsInvoker | start Cleaner.exe")`. There are no gates: nothing checks the OS, user, env or files before the payload. The exec step only works on Windows (cmd builtins and an .exe), and the whole thing needs the undeclared `requests` module and the download host to be reachable.

## Execution

- **cmdclass** `cmdclass[develop] = PostDevelopCommand`: runs on git or local install only; runs setup.py; direct_script, inline_shell, download_then_exec.
- **cmdclass** `cmdclass[install] = PostInstallCommand`: runs setup.py; direct_script, inline_shell, download_then_exec.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- other: python module requests importable in the build environment (execute() imports requests, which the package does not declare; without it ImportError aborts before the download)
- network: a4a08d21-3950-435e-8b39-12ab7788cd10[.]id[.]repl[.]co:443 (second stage Cleaner.exe is downloaded over HTTPS)
- os: win32 (the launch command uses cmd builtins set and start to run a downloaded .exe)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- `requests` is not in `install_requires` or build requirements, so in an isolated pip build the import probably fails and the install aborts before the download. Recorded as a requirement, not a gate.
- The env var name is misspelt (`__COMPACT_LAYER` instead of `__COMPAT_LAYER`) and `set` sits on the left of a pipe, so it has no effect on how the exe starts.
- The `develop` override only runs on legacy editable installs.
- The download host is long dead most likely; the second stage was not recovered and was not fetched.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "roblcx_cookie3",
    "version": "0.0.1",
    "archive_sha256": "158f9ece7e4fc52e5272d07f6f1a8d1b65fd161abf68c9bffcd7acb4831cc7e8",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/roblcx_cookie3-0.0.1.tar.gz",
    "package_root": "layer0/roblcx_cookie3-0.0.1",
    "cluster_key": "9c16cac89de6cb8ce351b4aee82628020bc7bb2681c01199a3502cbba1c47f6d",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[develop] = PostDevelopCommand",
        "runs_on": "git_or_local_install_only",
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
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstallCommand",
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
      "setup.py: read in full (79 lines, the only code file). Top-level code only reads README.md and computes unused getpass/time/path values; no gates anywhere.",
      "Both cmdclass overrides call execute() first, unconditionally: requests.get of Cleaner.exe, write to cwd, then os.system 'set __COMPACT_LAYER=RunAsInvoker | start Cleaner.exe'.",
      "develop override runs only on legacy editable installs of a local checkout, so runs_on is git_or_local_install_only. It calls install.run(self) on a develop instance afterwards, which happens after the payload.",
      "requests is imported inside execute() but not declared in install_requires or build requirements; with pip build isolation the import likely fails and aborts the install before the payload. Recorded as a requirement.",
      "The os.system command uses cmd builtins (set, start) and an .exe, so the exec step only works on Windows. There is no OS check; the download and file write run on any OS.",
      "hxxps://github[.]com/ is only the setup() url metadata, not contacted; removed from endpoints."
    ]
  },
  "requirements": [
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "execute() imports requests, which the package does not declare; without it ImportError aborts before the download",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 629,
          "end_byte": 644,
          "node_type": "import_statement",
          "sha256": "06185522e4085460",
          "line": 28
        }
      ]
    },
    {
      "axis": "network",
      "value": "a4a08d21-3950-435e-8b39-12ab7788cd10[.]id[.]repl[.]co:443",
      "reason": "second stage Cleaner.exe is downloaded over HTTPS",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 744,
          "end_byte": 761,
          "node_type": "call",
          "sha256": "bfee170b662f4f0c",
          "line": 31
        }
      ]
    },
    {
      "axis": "os",
      "value": "win32",
      "reason": "the launch command uses cmd builtins set and start to run a downloaded .exe",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 820,
          "end_byte": 885,
          "node_type": "call",
          "sha256": "94b3063e974f01b2",
          "line": 33
        }
      ]
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
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://a4a08d21-3950-435e-8b39-12ab7788cd10[.]id[.]repl[.]co/Cleaner.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "replit-hosted exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install and develop cmdclass overrides unconditionally download Cleaner.exe from a repl.co host, write it to the working directory and start it through cmd (with a misspelt __COMPACT_LAYER=RunAsInvoker set that has no effect). No environment check guards it.",
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
