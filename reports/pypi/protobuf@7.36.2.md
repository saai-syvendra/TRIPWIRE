# pypi protobuf@7.36.2

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-09-17 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Installing the sdist runs `setup.py` under setuptools (no `pyproject.toml`). It execs `google/protobuf/__init__.py` to read `__version__`, globs the vendored upb and utf8_range C sources, and declares the `google._upb._message` C extension, which build_ext compiles. A `sys.platform.startswith('win')` branch only chooses linker or compiler flags for that same build, so it is recorded as plumbing, not a gate. There are no gates; the install needs a C compiler.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, native_build.

## Gates

None.

## Requirements

- installed_tool: C compiler (gcc/cc on Linux and macOS, MSVC on Windows) (setup() declares the google._upb._message C extension, which build_ext compiles at install.)

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The tool's `sys.platform` candidate (k_8d2ba0020b, q_0e16ace065) was dropped as plumbing: both branches compile the same extension.
- All URLs are `setup()` metadata and are never contacted at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "protobuf",
    "version": "7.36.2",
    "archive_sha256": "497d0463ff3316681da6c0b9e8d06cb465d61abce00b613ab42226175644d1bb",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-09-17",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/protobuf-7.36.2.tar.gz",
    "package_root": "layer0/protobuf-7.36.2",
    "cluster_key": "318345c4e67437c2559f822729f9291ee9b16515edaac1d54bf4379f92bf24b6",
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
          "native_build"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (96 lines). No pyproject.toml, so setuptools runs it directly. It execs google/protobuf/__init__.py only to read __version__; that file was read in full and holds only the version string.",
      "The sys.platform.startswith('win') branch at setup.py:38 only picks linker/compiler flags (-static vs -fvisibility=hidden) for the same C extension build; both sides compile google._upb._message, so it is plumbing, not a gate.",
      "The vendored C sources (upb/, utf8_range/, python/) are compiled by setuptools build_ext as the declared ext_modules; they are library code built, not run, at install."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "C compiler (gcc/cc on Linux and macOS, MSVC on Windows)",
      "reason": "setup() declares the google._upb._message C extension, which build_ext compiles at install."
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "benign_build"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "exec() of the package's own version file to read __version__ (build plumbing, not obfuscation)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "benign",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "setup.py reads the version from google/protobuf/__init__.py and compiles the upb C extension with platform-specific flags. No network, credential, or process activity at install.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "5379951896794136"
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
        "candidate": "k_8d2ba0020b",
        "reason_code": "other",
        "note": "sys.platform check only picks compiler/linker flags for the same C extension build; both branches end in the same behaviour (plumbing, not a gate).",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 996,
          "end_byte": 1026,
          "node_type": "call",
          "sha256": "39552adb0f8f4fb7",
          "line": 38
        }
      },
      {
        "candidate": "q_0e16ace065",
        "reason_code": "other",
        "note": "if/else on sys.platform only sets extra_link_args or extra_compile_args; both sides build the same extension (plumbing).",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 993,
          "end_byte": 1112,
          "node_type": "if_statement",
          "sha256": "2170711bbba45fed",
          "line": 38
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
