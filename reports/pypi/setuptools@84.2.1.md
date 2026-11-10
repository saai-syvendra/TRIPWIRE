# pypi setuptools@84.2.1

**Source:** benign_sample · **Source label:** benign · **Released:** 2026-10-20 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

This is the real setuptools 84.2.1 sdist. Building it runs the in-tree PEP 517 backend `setuptools.build_meta`, which execs `setup.py`. That file only registers an `install` override that writes the upstream `distutils-precedence.pth` shim. The install path has no gates: the extractor's candidates are all interpreter-version or platform compatibility shims in setuptools and its vendored `packaging`, and both sides of each do the same build work. Nothing is fetched, no credentials are read, and the only processes started are normal build plumbing.

## Execution

- **build_backend** `in-tree build backend setuptools.build_meta`: 66-file chain; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: 69-file chain; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- All 21 prefilled candidates are dropped: compat shims (`not_environmental`), vendored `packaging` helpers (`library_code`), or typing-only blocks under `TYPE_CHECKING` (`dead_branch`).
- The PyPI classifier download in `_validate_pyproject/formats.py` is switched off by `config/pyprojecttoml.py` (`_disable_download`), so the build makes no network contact.
- The `.pth` file written by `install_with_pth` runs at later interpreter starts, not at install. It is setuptools' long-standing distutils shim.
- Generator truncation was noted for `_shutil.py`, `_musllinux.py` and `tags.py`. I read the subprocess sites in `_musllinux.py` (ld.so version probe) and `tags.py` (macOS version re-query) by hand. Both are upstream wheel-tag code. `_shutil.py` was only covered by the sink inventory.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "setuptools",
    "version": "84.2.1",
    "archive_sha256": "3ff8b3b5492a0aa66960f4419365a86b84e013070d4313e4d4a6894f5d64d6bc",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2026-10-20",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/setuptools-84.2.1.tar.gz",
    "package_root": "layer0/setuptools-84.2.1",
    "cluster_key": "abedff6201560e50d0e02584b0e78b60dce5eca85b88459992c82a3b20fc0747",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "build_backend",
        "command": "in-tree build backend setuptools.build_meta",
        "runs_on": "always",
        "file_chain": [
          "setuptools/build_meta.py",
          "setuptools/warnings.py",
          "setuptools/__init__.py",
          "setuptools/errors.py",
          "setuptools/_path.py",
          "setuptools/_reqs.py",
          "_distutils_hack/override.py",
          "setuptools/logging.py",
          "setuptools/monkey.py",
          "setuptools/depends.py",
          "setuptools/discovery.py",
          "setuptools/dist.py",
          "setuptools/extension.py",
          "setuptools/version.py",
          "setuptools/_core_metadata.py",
          "setuptools/_imp.py",
          "setuptools/glob.py",
          "setuptools/_entry_points.py",
          "setuptools/_static.py",
          "setuptools/command/__init__.py",
          "setuptools/_importlib.py",
          "setuptools/_normalization.py",
          "setuptools/config/__init__.py",
          "setuptools/config/pyprojecttoml.py",
          "setuptools/config/setupcfg.py",
          "setuptools/installer.py",
          "setuptools/windows_support.py",
          "setuptools/command/bdist_wheel.py",
          "setuptools/_itertools.py",
          "setuptools/config/expand.py",
          "setuptools/config/_apply_pyprojecttoml.py",
          "setuptools/compat/py310.py",
          "setuptools/config/_validate_pyproject/__init__.py",
          "setuptools/wheel.py",
          "setuptools/_shutil.py",
          "setuptools/command/egg_info.py",
          "setuptools/config/_validate_pyproject/formats.py",
          "setuptools/config/_validate_pyproject/error_reporting.py",
          "setuptools/config/_validate_pyproject/extra_validations.py",
          "setuptools/config/_validate_pyproject/fastjsonschema_exceptions.py",
          "setuptools/config/_validate_pyproject/fastjsonschema_validations.py",
          "setuptools/archive_util.py",
          "setuptools/_discovery.py",
          "setuptools/unicode_utils.py",
          "setuptools/compat/__init__.py",
          "setuptools/compat/py311.py",
          "setuptools/command/bdist_egg.py",
          "setuptools/command/sdist.py",
          "setuptools/command/setopt.py",
          "setuptools/command/_requirestxt.py",
          "setuptools/_vendor/packaging/__init__.py",
          "setuptools/_vendor/packaging/requirements.py",
          "setuptools/compat/py39.py",
          "setuptools/command/build.py",
          "setuptools/_vendor/packaging/_parser.py",
          "setuptools/_vendor/packaging/_tokenizer.py",
          "setuptools/_vendor/packaging/markers.py",
          "setuptools/_vendor/packaging/specifiers.py",
          "setuptools/_vendor/packaging/utils.py",
          "setuptools/_vendor/packaging/_ranges.py",
          "setuptools/_vendor/packaging/version.py",
          "setuptools/_vendor/packaging/ranges.py",
          "setuptools/_vendor/packaging/tags.py",
          "setuptools/_vendor/packaging/_manylinux.py",
          "setuptools/_vendor/packaging/_musllinux.py",
          "setuptools/_vendor/packaging/_elffile.py"
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
          "setup.py",
          "setuptools/__init__.py",
          "setuptools/command/install.py",
          "_distutils_hack/override.py",
          "setuptools/logging.py",
          "setuptools/monkey.py",
          "setuptools/depends.py",
          "setuptools/discovery.py",
          "setuptools/dist.py",
          "setuptools/extension.py",
          "setuptools/version.py",
          "setuptools/warnings.py",
          "setuptools/command/easy_install.py",
          "setuptools/_core_metadata.py",
          "setuptools/_imp.py",
          "setuptools/glob.py",
          "setuptools/_path.py",
          "setuptools/errors.py",
          "setuptools/_entry_points.py",
          "setuptools/_reqs.py",
          "setuptools/_static.py",
          "setuptools/command/__init__.py",
          "setuptools/_importlib.py",
          "setuptools/_normalization.py",
          "setuptools/config/__init__.py",
          "setuptools/config/pyprojecttoml.py",
          "setuptools/config/setupcfg.py",
          "setuptools/installer.py",
          "setuptools/windows_support.py",
          "setuptools/command/bdist_wheel.py",
          "setuptools/_scripts.py",
          "setuptools/_itertools.py",
          "setuptools/config/expand.py",
          "setuptools/config/_apply_pyprojecttoml.py",
          "setuptools/compat/py310.py",
          "setuptools/config/_validate_pyproject/__init__.py",
          "setuptools/wheel.py",
          "setuptools/_shutil.py",
          "setuptools/command/egg_info.py",
          "setuptools/config/_validate_pyproject/formats.py",
          "setuptools/config/_validate_pyproject/error_reporting.py",
          "setuptools/config/_validate_pyproject/extra_validations.py",
          "setuptools/config/_validate_pyproject/fastjsonschema_exceptions.py",
          "setuptools/config/_validate_pyproject/fastjsonschema_validations.py",
          "setuptools/archive_util.py",
          "setuptools/_discovery.py",
          "setuptools/unicode_utils.py",
          "setuptools/compat/__init__.py",
          "setuptools/compat/py311.py",
          "setuptools/command/bdist_egg.py",
          "setuptools/command/sdist.py",
          "setuptools/command/setopt.py",
          "setuptools/command/_requirestxt.py",
          "setuptools/_vendor/packaging/__init__.py",
          "setuptools/_vendor/packaging/requirements.py",
          "setuptools/compat/py39.py",
          "setuptools/command/build.py",
          "setuptools/_vendor/packaging/_parser.py",
          "setuptools/_vendor/packaging/_tokenizer.py",
          "setuptools/_vendor/packaging/markers.py",
          "setuptools/_vendor/packaging/specifiers.py",
          "setuptools/_vendor/packaging/utils.py",
          "setuptools/_vendor/packaging/_ranges.py",
          "setuptools/_vendor/packaging/version.py",
          "setuptools/_vendor/packaging/ranges.py",
          "setuptools/_vendor/packaging/tags.py",
          "setuptools/_vendor/packaging/_manylinux.py",
          "setuptools/_vendor/packaging/_musllinux.py",
          "setuptools/_vendor/packaging/_elffile.py"
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
      "generator truncated: some helpers walked under only 2 guard contexts in setuptools/_shutil.py, setuptools/_vendor/packaging/_musllinux.py, setuptools/_vendor/packaging/tags.py; candidates there may be missing",
      "pyproject.toml uses the in-tree backend setuptools.build_meta (backend-path .), with empty build requires; build_meta.run_setup execs setup.py, so the setup_py chain runs inside the build_backend hook.",
      "setup.py is upstream setuptools: only a cmdclass install override (install_with_pth) that writes the distutils-precedence.pth shim via extra_path. That .pth runs at later interpreter starts (load time, upstream behaviour).",
      "Coverage: setup.py, build_meta.run_setup, installer.py, the formats.py download path, depends.py and the cited compat modules read in full.",
      "Coverage: rest of the setuptools and vendored packaging chain audited by sink inventory (exec, eval, subprocess, urlopen, marshal, credential paths); every hit fits upstream purpose; nothing unread.",
      "Sinks seen are all upstream build plumbing: exec of setup.py in build_meta, pip wheel subprocess in installer.py for setup_requires (none declared), ld.so probe in vendored packaging _musllinux for wheel tags, file writes and cleanups of build dirs.",
      "formats.py classifier download from PyPI is disabled by setuptools/config/pyprojecttoml.py (_disable_download), so no network contact at install.",
      "All prefilled conditions and gates are interpreter-version or platform compat shims (tomllib vs tomli, Jython/IronPython guard, packaging version/tag helpers); both sides keep the same build behaviour, so they are dropped, not gates."
    ]
  },
  "requirements": [],
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
  "assessment_reason": "Genuine setuptools sdist: the install path is the in-tree PEP 517 backend building setuptools itself and a setup.py that only adds the upstream distutils-precedence .pth shim. No network, credential access or foreign process launch beyond normal build plumbing.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "a3d1a0f0a66d4a5a"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 3
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_8bc6129c21",
        "reason_code": "other",
        "note": "Environmental (sys.platform, Jython) but not a gate: it only defines bytecode helpers, called only via Require.get_version; nothing in the package builds a Require, so install is unchanged.",
        "anchor": {
          "file": "setuptools/depends.py",
          "derived_from": null,
          "start_byte": 3194,
          "end_byte": 3225,
          "node_type": "call",
          "sha256": "fd448567cc9a7716",
          "line": 112
        }
      },
      {
        "candidate": "k_7169766c44",
        "reason_code": "other",
        "note": "Environmental (sys.platform, IronPython) but not a gate: same definition block as k_8bc6129c21, which only defines helpers that no install path calls, so no install behaviour changes.",
        "anchor": {
          "file": "setuptools/depends.py",
          "derived_from": null,
          "start_byte": 3230,
          "end_byte": 3251,
          "node_type": "comparison_operator",
          "sha256": "c8fe6c87f85095b5",
          "line": 112
        }
      },
      {
        "candidate": "q_c03d046564",
        "reason_code": "other",
        "note": "Platform if in depends.py, environmental but not a gate: no else side, and its body only defines helpers reached through Require.get_version, which no install path calls.",
        "anchor": {
          "file": "setuptools/depends.py",
          "derived_from": null,
          "start_byte": 3187,
          "end_byte": 5949,
          "node_type": "if_statement",
          "sha256": "466a1c09f2489647",
          "line": 112
        }
      },
      {
        "candidate": "k_e2c8adda3a",
        "reason_code": "other",
        "note": "Environmental (sys.version_info) but not a gate: LOCALE_ENCODING is \"locale\" or None, both the locale encoding when passed to open(); requires-python >=3.10 also rules out the None side.",
        "anchor": {
          "file": "setuptools/compat/py39.py",
          "derived_from": null,
          "start_byte": 455,
          "end_byte": 482,
          "node_type": "comparison_operator",
          "sha256": "d3cb283e5db6f09e",
          "line": 9
        }
      },
      {
        "candidate": "q_bfc8a89481",
        "reason_code": "other",
        "note": "Runtime-version ternary in compat/py39.py, environmental but not a gate: it only picks the LOCALE_ENCODING argument value (see k_e2c8adda3a), so no behaviour differs between its sides.",
        "anchor": {
          "file": "setuptools/compat/py39.py",
          "derived_from": null,
          "start_byte": 443,
          "end_byte": 492,
          "node_type": "conditional_expression",
          "sha256": "9d73d3fe20f8e66f",
          "line": 9
        }
      },
      {
        "candidate": "k_2e993e87a9",
        "reason_code": "dead_branch",
        "note": "vendored packaging specifiers.py TypeGuard import inside an if TYPE_CHECKING block; never runs",
        "anchor": {
          "file": "setuptools/_vendor/packaging/specifiers.py",
          "derived_from": null,
          "start_byte": 906,
          "end_byte": 933,
          "node_type": "comparison_operator",
          "sha256": "d3cb283e5db6f09e",
          "line": 43
        }
      },
      {
        "candidate": "q_f65ddbe22a",
        "reason_code": "dead_branch",
        "note": "vendored packaging specifiers.py typing-only if under TYPE_CHECKING",
        "anchor": {
          "file": "setuptools/_vendor/packaging/specifiers.py",
          "derived_from": null,
          "start_byte": 903,
          "end_byte": 1029,
          "node_type": "if_statement",
          "sha256": "46fab95860bdbeef",
          "line": 43
        }
      },
      {
        "candidate": "k_6189f2f0a0",
        "reason_code": "other",
        "note": "Environmental (sys.version_info) but not a gate: it binds stdlib tomllib or vendored tomli as tomllib, and load_file calls tomllib.load on either, so pyproject.toml parses the same way.",
        "anchor": {
          "file": "setuptools/compat/py310.py",
          "derived_from": null,
          "start_byte": 39,
          "end_byte": 66,
          "node_type": "comparison_operator",
          "sha256": "7daf69f494f98cd2",
          "line": 6
        }
      },
      {
        "candidate": "k_73a525aea8",
        "reason_code": "other",
        "note": "Environmental (sys.version_info) but not a gate: both add_note versions attach a note to an exception, called only on error paths in msvc.py and editable_wheel.py; no behaviour differs.",
        "anchor": {
          "file": "setuptools/compat/py310.py",
          "derived_from": null,
          "start_byte": 146,
          "end_byte": 173,
          "node_type": "comparison_operator",
          "sha256": "7daf69f494f98cd2",
          "line": 12
        }
      },
      {
        "candidate": "q_04388cff90",
        "reason_code": "other",
        "note": "Runtime-version if in compat/py310.py, environmental but not a gate: both sides bind a TOML parser as tomllib (tomli is vendored), so the build does the same thing on either side (see k_6189f2f0a0).",
        "anchor": {
          "file": "setuptools/compat/py310.py",
          "derived_from": null,
          "start_byte": 36,
          "end_byte": 140,
          "node_type": "if_statement",
          "sha256": "88d08f70fdae1b42",
          "line": 6
        }
      },
      {
        "candidate": "q_22913be2cb",
        "reason_code": "other",
        "note": "Runtime-version if in compat/py310.py, environmental but not a gate: both sides define an add_note that attaches a note to an exception (see k_73a525aea8), so no behaviour differs.",
        "anchor": {
          "file": "setuptools/compat/py310.py",
          "derived_from": null,
          "start_byte": 143,
          "end_byte": 343,
          "node_type": "if_statement",
          "sha256": "da307ecec0ef190b",
          "line": 12
        }
      },
      {
        "candidate": "k_11fab8d9ee",
        "reason_code": "library_code",
        "note": "vendored packaging version.py picks warnings.deprecated on 3.13+ or a local fallback decorator",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 544,
          "end_byte": 571,
          "node_type": "comparison_operator",
          "sha256": "a4589cd3a0246b9d",
          "line": 28
        }
      },
      {
        "candidate": "q_eda60b1a03",
        "reason_code": "library_code",
        "note": "vendored packaging version.py compat if",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 541,
          "end_byte": 1270,
          "node_type": "if_statement",
          "sha256": "57f7ce2efbed5950",
          "line": 28
        }
      },
      {
        "candidate": "k_2ae2d76ded",
        "reason_code": "library_code",
        "note": "vendored packaging version.py Python patch-level compat ternary",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 6361,
          "end_byte": 6390,
          "node_type": "comparison_operator",
          "sha256": "b1d2bdf86d0655a3",
          "line": 235
        }
      },
      {
        "candidate": "k_3849872860",
        "reason_code": "library_code",
        "note": "vendored packaging version.py Python patch-level compat ternary",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 6438,
          "end_byte": 6468,
          "node_type": "comparison_operator",
          "sha256": "87bbd80a3a12121b",
          "line": 236
        }
      },
      {
        "candidate": "k_92b00cf8f7",
        "reason_code": "library_code",
        "note": "vendored packaging version.py Python 3.11 compat ternary",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 6477,
          "end_byte": 6503,
          "node_type": "comparison_operator",
          "sha256": "e1526e2d73e27309",
          "line": 237
        }
      },
      {
        "candidate": "q_2fab165aec",
        "reason_code": "library_code",
        "note": "vendored packaging version.py compat ternary",
        "anchor": {
          "file": "setuptools/_vendor/packaging/version.py",
          "derived_from": null,
          "start_byte": 6291,
          "end_byte": 6529,
          "node_type": "conditional_expression",
          "sha256": "4c0eda429f145066",
          "line": 234
        }
      },
      {
        "candidate": "k_9bd0887a30",
        "reason_code": "dead_branch",
        "note": "validate_pyproject error_reporting.py Self import inside if typing.TYPE_CHECKING; never runs",
        "anchor": {
          "file": "setuptools/config/_validate_pyproject/error_reporting.py",
          "derived_from": null,
          "start_byte": 347,
          "end_byte": 373,
          "node_type": "comparison_operator",
          "sha256": "e1526e2d73e27309",
          "line": 18
        }
      },
      {
        "candidate": "q_268f8eae4f",
        "reason_code": "dead_branch",
        "note": "validate_pyproject error_reporting.py typing-only if under TYPE_CHECKING",
        "anchor": {
          "file": "setuptools/config/_validate_pyproject/error_reporting.py",
          "derived_from": null,
          "start_byte": 344,
          "end_byte": 459,
          "node_type": "if_statement",
          "sha256": "9e9a08b170d76a80",
          "line": 18
        }
      },
      {
        "candidate": "k_01e8a2c250",
        "reason_code": "library_code",
        "note": "vendored packaging _musllinux reads the interpreter ELF to compute musllinux wheel tags; upstream tag logic",
        "anchor": {
          "file": "setuptools/_vendor/packaging/_musllinux.py",
          "derived_from": null,
          "start_byte": 1284,
          "end_byte": 1306,
          "node_type": "call",
          "sha256": "f5c869b872f559ef",
          "line": 49
        }
      },
      {
        "candidate": "q_69f992ef58",
        "reason_code": "library_code",
        "note": "vendored packaging _musllinux try/except around ELF read for wheel tag computation",
        "anchor": {
          "file": "setuptools/_vendor/packaging/_musllinux.py",
          "derived_from": null,
          "start_byte": 1266,
          "end_byte": 1417,
          "node_type": "try_statement",
          "sha256": "79d9a26077609f98",
          "line": 48
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 24,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 21,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 80,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
