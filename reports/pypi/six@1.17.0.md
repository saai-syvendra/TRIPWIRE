# pypi six@1.17.0

**Source:** benign_sample · **Source label:** benign · **Released:** 2024-12-04 (registry) · **Assessment:** benign (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

On an sdist install, pip runs `setup.py` through setuptools. It imports `six` to read `__version__`, reads `README.rst` and calls `setup()` with static metadata. `six.py` is the unmodified compatibility library: its top-level code only defines Python 2/3 aliases and registers a `six.moves` meta path importer. There are no gates; every interpreter-version and platform check picks equivalent compatibility definitions, so the only install behaviour is the ordinary build (`benign_build`).

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: 2-file chain; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: benign_build
- Gated: none

## Notes

- All 11 condition candidates and 18 guard candidates were dropped as compatibility shims (flipping them changes no behaviour class).
- The `exec` sinks in `six.py` run literal source strings that define `reraise` and `raise_from`; no decoded or external input.
- The prefilled `silent_failure` was set to false: the swallowed exceptions are library-helper fallbacks and the setuptools/distutils import fallback, which hide no install work.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "six",
    "version": "1.17.0",
    "archive_sha256": "ff70335d468e7eb6ec65b95b99d3a2836546063f63acc5171de367e834932a81",
    "source_dataset": "benign_sample",
    "source_label": "benign",
    "released_at": "2024-12-04",
    "released_at_source": "registry",
    "sample_path": "benign_sample/pypi/benign/six-1.17.0.tar.gz",
    "package_root": "layer0/six-1.17.0",
    "cluster_key": "fc2e07a800f15353cb4db547d8e10e543c0094bce9a343b5ebcdde05f9180ece",
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
          "setup.py",
          "six.py"
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
      "setup.py: read in full. It imports setuptools (distutils fallback on ImportError), imports six for __version__, reads README.rst and calls setup() with static metadata. Nothing else runs.",
      "six.py: read in full. Imported by setup.py only to read __version__; its top level defines Python 2/3 compatibility aliases and registers a sys.meta_path importer for six.moves. No process, network or file activity.",
      "All version_info and sys.platform checks in six.py pick equivalent compat definitions per interpreter (str vs basestring, winreg alias, etc.); flipping them changes no behaviour class, so none is a gate.",
      "exec sites at six.py:740 and :751 run literal source strings defining reraise/raise_from; no external or decoded input. The 740 site is on the Python 2 branch only.",
      "silent_failure set false: the swallowed exceptions (six.py:103, :209, :841) are AttributeError/KeyError fallbacks in library helpers, and the setup.py ImportError fallback is a distutils import, none hiding install work.",
      "The github URL in setup.py is the url= metadata field and is never contacted at install."
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
  "assessment_reason": "The install runs a standard setuptools setup.py that imports the unmodified six module for its version string and builds the package. No network, process, credential or file activity beyond the normal build.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@de0a7fa35b",
      "sha256": "668cc6fbce49d92f"
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
        "candidate": "k_33c3f1b65f",
        "reason_code": "other",
        "note": "PY3 flag (version_info[0] == 3): Python 2/3 compat shim choosing equivalent aliases and helpers; no behaviour class changes.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1446,
          "end_byte": 1470,
          "node_type": "comparison_operator",
          "sha256": "cd91ed5f80f5cae4",
          "line": 37
        }
      },
      {
        "candidate": "k_461defb882",
        "reason_code": "other",
        "note": "Jython check only picks the MAXSIZE constant on Python 2; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1828,
          "end_byte": 1859,
          "node_type": "call",
          "sha256": "eab47b4fd933c0ed",
          "line": 55
        }
      },
      {
        "candidate": "k_6c44040ba6",
        "reason_code": "other",
        "note": "PY34 flag picks where spec_from_loader / reload are imported from; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1478,
          "end_byte": 1509,
          "node_type": "comparison_operator",
          "sha256": "b0d744da7cf50a32",
          "line": 38
        }
      },
      {
        "candidate": "k_c4de5ab08b",
        "reason_code": "other",
        "note": "Picks collections.abc vs collections module name for a lazy alias; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 8597,
          "end_byte": 8623,
          "node_type": "comparison_operator",
          "sha256": "fd6519f115ea32bb",
          "line": 274
        }
      },
      {
        "candidate": "k_52fe8593a3",
        "reason_code": "other",
        "note": "Picks _dummy_thread vs _thread module name for a lazy alias; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 8848,
          "end_byte": 8873,
          "node_type": "comparison_operator",
          "sha256": "42ed9a796b45fa9d",
          "line": 278
        }
      },
      {
        "candidate": "k_76a19642b6",
        "reason_code": "other",
        "note": "win32 check only adds a lazy winreg alias to six.moves; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 11625,
          "end_byte": 11648,
          "node_type": "comparison_operator",
          "sha256": "81d76343f3bfcc14",
          "line": 323
        }
      },
      {
        "candidate": "k_4c2757c535",
        "reason_code": "other",
        "note": "Adds URLopener aliases on Python < 3.14; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 17209,
          "end_byte": 17239,
          "node_type": "comparison_operator",
          "sha256": "96c57e82f7746a3c",
          "line": 442
        }
      },
      {
        "candidate": "k_635955c5da",
        "reason_code": "other",
        "note": "Picks unittest assertion method names on Python 3.0/3.1; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 23583,
          "end_byte": 23607,
          "node_type": "comparison_operator",
          "sha256": "7fc7962389a0ebfc",
          "line": 665
        }
      },
      {
        "candidate": "k_9a8d5e2de4",
        "reason_code": "other",
        "note": "Defines raise_from via literal exec on Python 3, plain def otherwise; same helper either way, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 25854,
          "end_byte": 25881,
          "node_type": "comparison_operator",
          "sha256": "f019988407712260",
          "line": 750
        }
      },
      {
        "candidate": "k_cb2ec65f95",
        "reason_code": "other",
        "note": "Wraps print_ with flush support on Python < 3.3; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 28027,
          "end_byte": 28056,
          "node_type": "comparison_operator",
          "sha256": "24d4ecc605199c90",
          "line": 817
        }
      },
      {
        "candidate": "k_3e6d64719f",
        "reason_code": "other",
        "note": "Defines a wraps backport on Python < 3.4; compat shim, no behaviour.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 28343,
          "end_byte": 28373,
          "node_type": "comparison_operator",
          "sha256": "fd2744467159aed6",
          "line": 829
        }
      },
      {
        "candidate": "q_5f43a9a3a1",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1511,
          "end_byte": 2317,
          "node_type": "if_statement",
          "sha256": "be85e3193f461bec",
          "line": 40
        }
      },
      {
        "candidate": "q_006614b37c",
        "reason_code": "duplicate_of",
        "note": "Else side of the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1511,
          "end_byte": 2317,
          "node_type": "if_statement",
          "sha256": "be85e3193f461bec",
          "line": 40
        }
      },
      {
        "candidate": "q_1c687ccc40",
        "reason_code": "duplicate_of",
        "note": "Guard on the Jython MAXSIZE shim, see k_461defb882.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 1825,
          "end_byte": 2317,
          "node_type": "if_statement",
          "sha256": "50d3da639f59ee73",
          "line": 55
        }
      },
      {
        "candidate": "q_be34db2e54",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 20316,
          "end_byte": 20709,
          "node_type": "if_statement",
          "sha256": "a6673496c03512b7",
          "line": 531
        }
      },
      {
        "candidate": "q_2f1cb10814",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 20996,
          "end_byte": 21586,
          "node_type": "if_statement",
          "sha256": "73bd3d36b5c27696",
          "line": 564
        }
      },
      {
        "candidate": "q_fdddd1caf7",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 22022,
          "end_byte": 22837,
          "node_type": "if_statement",
          "sha256": "ce7691572d340d33",
          "line": 602
        }
      },
      {
        "candidate": "q_97b0ce962e",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 23184,
          "end_byte": 24494,
          "node_type": "if_statement",
          "sha256": "d1565ebfca936c25",
          "line": 647
        }
      },
      {
        "candidate": "q_167c2c22e6",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY3 compat shim, see k_33c3f1b65f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 24981,
          "end_byte": 25848,
          "node_type": "if_statement",
          "sha256": "dd7aee796d69afe8",
          "line": 715
        }
      },
      {
        "candidate": "q_a44a5e2890",
        "reason_code": "duplicate_of",
        "note": "Guard on the PY34 compat shim, see k_6c44040ba6.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 2319,
          "end_byte": 2409,
          "node_type": "if_statement",
          "sha256": "4e223c00419f5825",
          "line": 74
        }
      },
      {
        "candidate": "q_92e9659deb",
        "reason_code": "duplicate_of",
        "note": "Ternary on the PY34 compat shim, see k_6c44040ba6.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 7772,
          "end_byte": 7802,
          "node_type": "conditional_expression",
          "sha256": "b3ce16fdfbd1008a",
          "line": 262
        }
      },
      {
        "candidate": "q_cf4f35947c",
        "reason_code": "duplicate_of",
        "note": "Ternary on the collections.abc shim, see k_c4de5ab08b.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 8576,
          "end_byte": 8642,
          "node_type": "conditional_expression",
          "sha256": "d842edbb56ed0a5d",
          "line": 274
        }
      },
      {
        "candidate": "q_2508047e11",
        "reason_code": "duplicate_of",
        "note": "Ternary on the _dummy_thread shim, see k_52fe8593a3.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 8829,
          "end_byte": 8888,
          "node_type": "conditional_expression",
          "sha256": "ca457763fe99a9f3",
          "line": 278
        }
      },
      {
        "candidate": "q_ebb508809c",
        "reason_code": "duplicate_of",
        "note": "Guard on the winreg alias shim, see k_76a19642b6.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 11622,
          "end_byte": 11724,
          "node_type": "if_statement",
          "sha256": "d7f021fadc66319f",
          "line": 323
        }
      },
      {
        "candidate": "q_d336a9f6a5",
        "reason_code": "duplicate_of",
        "note": "Guard on the URLopener alias shim, see k_4c2757c535.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 17206,
          "end_byte": 17454,
          "node_type": "if_statement",
          "sha256": "8fdcf2e011c930af",
          "line": 442
        }
      },
      {
        "candidate": "q_03f62689fd",
        "reason_code": "duplicate_of",
        "note": "Guard on the assertion-name shim, see k_635955c5da.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 23580,
          "end_byte": 23893,
          "node_type": "if_statement",
          "sha256": "8bf4d6d1051a2f15",
          "line": 665
        }
      },
      {
        "candidate": "q_83ca5e7bd4",
        "reason_code": "duplicate_of",
        "note": "Guard on the raise_from shim, see k_9a8d5e2de4.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 25851,
          "end_byte": 26079,
          "node_type": "if_statement",
          "sha256": "8cabcebffd6fec5e",
          "line": 750
        }
      },
      {
        "candidate": "q_6afedeb41c",
        "reason_code": "duplicate_of",
        "note": "Guard on the print_ flush shim, see k_cb2ec65f95.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 28024,
          "end_byte": 28290,
          "node_type": "if_statement",
          "sha256": "a8ac54c38af4616e",
          "line": 817
        }
      },
      {
        "candidate": "q_034cee3034",
        "reason_code": "duplicate_of",
        "note": "Guard on the wraps backport shim, see k_3e6d64719f.",
        "anchor": {
          "file": "six.py",
          "derived_from": null,
          "start_byte": 28340,
          "end_byte": 29649,
          "node_type": "if_statement",
          "sha256": "9d393748e5460cd1",
          "line": 829
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 12,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 29,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 24,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
