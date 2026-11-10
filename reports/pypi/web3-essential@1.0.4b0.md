# pypi web3-essential@1.0.4b0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs top-level code on every pip build step, before `setup()` is called. It downloads `ily.exe` from a Discord CDN attachment with `requests.get`, writes it to `%APPDATA%\ily.exe` and launches it with `os.startfile`. There are no gates. The payload needs Windows (the APPDATA path and `os.startfile` fail unconditionally elsewhere), the `requests` module in the build environment and a reachable Discord CDN.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, download_then_exec.

## Gates

None.

## Requirements

- os: win32 (Path built from the APPDATA env var (TypeError when unset) and the dropped file is run with os.startfile, which exists only on Windows.)
- network: cdn[.]discordapp[.]com:443 (Second-stage exe is fetched from a Discord CDN attachment.)
- other: Python module requests importable in the build environment (setup.py imports requests at top level without declaring it as a build requirement; an isolated pip build without requests fails before the download.)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- The Discord attachment ids in the endpoint are redacted to 4 characters.
- `libname/web3_essentials.py` only prints a warning and is not reached at install.
- Package name, description and author fields are generic "web3" metadata; no specific project is copied, so attack type is `malicious_new_package`.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "web3-essential",
    "version": "1.0.4b0",
    "archive_sha256": "05640a588e0be0ecfce7f86dbda5e86ebd238a27c492cbecdc1783cd332c311c",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/web3-essential-1.0.4b0.tar.gz",
    "package_root": "layer0/web3-essential-1.0.4b0",
    "cluster_key": "b84648955aab42a0d42b54df02135ad746aab76500cf64ae46282df91ef174cc",
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
          "download_then_exec"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (35 lines). Top-level code runs before setup(): downloads an exe from a Discord CDN attachment, writes it to %APPDATA%/ily.exe and launches it with os.startfile. No conditions, no error handling.",
      "No gate: on non-Windows, os.getenv('APPDATA') is None so os.path.join raises TypeError and the build aborts; os.startfile is also Windows-only. These are unconditional failures, recorded as requirements, not gates.",
      "libname/web3_essentials.py only prints an unsupported-OS warning and is not reached at install. The url field in setup() is metadata only, not contacted; dropped from endpoints."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "Path built from the APPDATA env var (TypeError when unset) and the dropped file is run with os.startfile, which exists only on Windows.",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 100,
          "end_byte": 120,
          "node_type": "call",
          "sha256": "b988f970aaf5c34d",
          "line": 6
        }
      ]
    },
    {
      "axis": "network",
      "value": "cdn[.]discordapp[.]com:443",
      "reason": "Second-stage exe is fetched from a Discord CDN attachment."
    },
    {
      "axis": "other",
      "value": "Python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level without declaring it as a build requirement; an isolated pip build without requests fails before the download."
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
        "indicator": "hxxps://cdn[.]discordapp[.]com/attachments/1068…/1068…/ily.exe",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord-cdn exe dropper",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py unconditionally downloads an executable from a Discord CDN attachment into %APPDATA% and runs it at install time. There are no environment gates; it only works on Windows because of unconditional Windows-only calls.",
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
