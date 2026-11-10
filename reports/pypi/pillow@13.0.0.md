# pypi pillow@13.0.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-16 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Pillow 13.0.0 is an sdist built through an in-tree backend (`_custom_build/backend.py`) that subclasses setuptools' `build_meta` backend, forwards pip `config_settings` as extra `sys.argv` flags, and then runs `setup.py`. `setup.py` registers a custom `build_ext` that finds system image libraries (through env vars, pkg-config, ldconfig, Homebrew and xcrun probes) and compiles the C extensions. Its many platform, env var and file-existence checks only pick search paths, library names and which optional extensions to build, so none of them is a gate. Install-time behaviour is an ungated native build.

## Execution

- **build_backend** `in-tree build backend backend`: 2-file chain; direct_script, native_build.

## Gates

None.

## Requirements

- installed_tool: cc (build_ext compiles the C extensions with the platform C compiler)
- file_present: /usr/include/zlib.h, /usr/include/jpeglib.h, libz and libjpeg in /usr/lib (zlib and jpeg are required features; setup.py raises RequiredDependencyException when their headers or libraries are not found in any search dir (paths given are one typical layout))

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- The tool said the backend does not run `setup.py`. That's wrong: `run_setup` is inherited from setuptools and called via `super()`. I added `setup.py` to the file chain, so the extractor generated no candidates for it and my "no gates" call is from manual reading only.
- The build needs a C compiler plus zlib and libjpeg headers and libraries. If they are missing, the build raises `RequiredDependencyException`.
- The readthedocs URLs only appear in printed help and error text.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pillow",
    "version": "13.0.0",
    "archive_sha256": "cdcd1ba258178f7356d74170c9a81ba4eab6a5d55748bc402a5a2a6fe6be3510",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-16",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/pillow-13.0.0.tar.gz",
    "package_root": "layer0/pillow-13.0.0",
    "cluster_key": "cd7c27371ab0832c571469be9d2b6a36f263d24331816fb8d952eaef83406664",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "build_backend",
        "command": "in-tree build backend backend",
        "runs_on": "always",
        "file_chain": [
          "_custom_build/backend.py",
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
      "Tool note 'build backend does not run setup.py' is wrong: _custom_build/backend.py subclasses setuptools.build_meta's backend and calls super().run_setup(), so setup.py runs at every build. Added setup.py to file_chain.",
      "backend.py read in full: only forwards pip config_settings into sys.argv as --pillow-configuration= flags for setup.py. No environment checks.",
      "setup.py read in full: registers cmdclass build_ext=pil_build_ext, which locates image libraries (pkg-config, ldconfig -p, brew --prefix, xcrun probes) and compiles the C extensions.",
      "All sys.platform, env var (*_ROOT, CFLAGS, PKG_CONFIG, ANDROID_ROOT, ProgramFiles) and header/library existence checks in setup.py only pick search paths, library names or which optional extensions to build: build plumbing, not gates.",
      "pkg-config and probe subprocess errors are swallowed in try/except, but these are optional library lookups; the build itself fails loudly, so silent_failure is false.",
      "The two readthedocs URLs are only printed in help text and error messages; nothing is fetched by package code. Build requirements pybind11 and setuptools>=77 come from PyPI (dependency tree).",
      "Repair: gate_extract.py run directly on setup.py (build_backend) gives 29 candidate conditions: platform, Python version, env var, cpu_count and path checks.",
      "Each extracted condition only picks search dirs, compile flags (LIB_FUZZING_ENGINE, setup.py:454), parallelism (setup.py:398) or a warning (setup.py:62).",
      "The only extracted sinks are probes: ldconfig (setup.py:206), pkg-config (297, 303), xcrun (468, 491), brew --prefix (616). No condition gates a payload."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "cc",
      "reason": "build_ext compiles the C extensions with the platform C compiler"
    },
    {
      "axis": "file_present",
      "value": "/usr/include/zlib.h, /usr/include/jpeglib.h, libz and libjpeg in /usr/lib",
      "reason": "zlib and jpeg are required features; setup.py raises RequiredDependencyException when their headers or libraries are not found in any search dir (paths given are one typical layout)"
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
    "techniques": [],
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
  "assessment_reason": "The in-tree backend wraps setuptools and setup.py only locates system image libraries and compiles Pillow's C extensions. No network access, credential reads or code outside the build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@97d6974e53",
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
