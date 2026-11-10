# pypi rblxsetup@0.0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py overrides the setuptools `install` and `develop` commands, and both `run()` methods call `execute()` before the normal install. `execute()` downloads `main.exe` from a Discord CDN attachment with `requests.get`, writes it to the working directory and starts it with `os.system("set __COMPACT_LAYER=RunAsInvoker | start main.exe")`. There are no gates: nothing checks the OS, user or anything else before the download. The launch only works on Windows (`start` is a cmd.exe builtin), so on Linux the binary is fetched and written but never started.

## Execution

- **cmdclass** `cmdclass[develop] = PostDevelopCommand`: runs on git or local install only; runs setup.py; direct_script, download_then_exec, dropped_binary; errors hidden.
- **cmdclass** `cmdclass[install] = PostInstallCommand`: runs setup.py; direct_script, download_then_exec, dropped_binary; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: cdn[.]discordapp[.]com:443 (main.exe is downloaded from a Discord CDN attachment over HTTPS)
- other: python module requests importable in the build environment (execute() imports requests, which the package does not declare as a dependency)
- os: win32 (the dropped main.exe is started with the cmd.exe builtin start; it only launches on Windows)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- The download URL's attachment ids are redacted in the record. The second-stage host must be reachable and `requests` must already be installed (it is not declared), otherwise the payload fails before writing anything.
- The package presents itself as a "roblox cheat setup" (description and README). That is a lure, not a claim about what the code does, so it is not recorded as misleading text.
- Unused top-level values (`ashed` paths, username, timestamp) look like leftovers from a copied template and are never read.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "rblxsetup",
    "version": "0.0.1",
    "archive_sha256": "69ee2bb6251a62cc36f086a9937bf163da20244f00eac42316614844b3440099",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/rblxsetup-0.0.1.tar.gz",
    "package_root": "layer0/rblxsetup-0.0.1",
    "cluster_key": "d52a54c7c2216b5d09efb724ad611887837667b8082fc23c1a5b0105c2b6f176",
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
          "download_then_exec",
          "dropped_binary"
        ],
        "silent_failure": true
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
          "download_then_exec",
          "dropped_binary"
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
      "setup.py: read in full (79 lines, package code only); nothing bundled, nothing unread. No other install-reached files.",
      "Both cmdclass run() methods call execute() first: requests.get of main.exe from a Discord CDN attachment, write to ./main.exe, then os.system('set __COMPACT_LAYER=RunAsInvoker | start main.exe').",
      "develop override runs only on legacy editable (local) installs, hence runs_on git_or_local_install_only. It calls install.run(self) on a develop instance, but only after the payload has run.",
      "silent_failure: the os.system exit status is discarded. 'start' is a cmd.exe builtin, so the exec step only succeeds on Windows; on Linux the download and file write still happen and the start fails quietly.",
      "requests is imported inside execute() but not declared in install_requires; if it is missing from the build environment the install aborts with ImportError before any download.",
      "Top-level setup.py only reads README.md for long_description and computes FILENAME, ROOT_PATH, USER_PATH, USER, TIME, none of which are used. No environment check anywhere, so no gates.",
      "hxxps://github[.]com/ appears only as the setup() url metadata and is never contacted; removed from endpoints."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "cdn[.]discordapp[.]com:443",
      "reason": "main.exe is downloaded from a Discord CDN attachment over HTTPS",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 764,
          "end_byte": 781,
          "node_type": "call",
          "sha256": "bfee170b662f4f0c",
          "line": 31
        }
      ]
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "execute() imports requests, which the package does not declare as a dependency",
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
      "axis": "os",
      "value": "win32",
      "reason": "the dropped main.exe is started with the cmd.exe builtin start; it only launches on Windows",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 837,
          "end_byte": 899,
          "node_type": "call",
          "sha256": "02bc302051d9b211",
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
        "indicator": "hxxps://cdn[.]discordapp[.]com/attachments/1030…/1031…/main.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord-cdn exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "The install and develop cmdclass overrides unconditionally download main.exe from a Discord CDN attachment, write it to the working directory and start it through cmd with __COMPACT_LAYER=RunAsInvoker. No environment check gates it.",
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
