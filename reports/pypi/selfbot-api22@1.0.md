# pypi selfbot-api22@1.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

Installing the sdist runs `setup.py`, which at module top level (before `setup()`) calls `exec(marshal.loads(...))` on a literal wrapped in base85, base32, base16, base64, lzma and zlib. The visible code has no environment checks, so the exec runs on every build with no gate in front. The executed code is a marshal'd Python code object that was not decoded or disassembled, so any gates and behaviours inside it are unknown. The only visible requirement is a CPython version matching the one the code object was compiled for.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval.

## Gates

None.

## Requirements

- runtime_version: CPython minor version matching the marshal'd code object (not recovered) (marshal.loads of a code object only works on the interpreter version it was compiled for; on another version the exec fails and the payload never runs)

## Behaviour

- Ungated: other
- Gated: none

## Notes

- Lines 4-566 of `setup.py` append hex-escaped filler strings to an unused variable (a sampled fragment decodes to repeated filler text); this is padding to bloat the file, not payload.
- The marshal'd payload stays in `obfuscation.unrecovered`. Recovering it needs a data-only base85/base32/lzma decode and a bytecode disassembler that does not load the object; this session's allowlist allowed neither.
- `needs_remote` is false and no endpoints are listed only because none appear in the visible code.
- The package's import-time module `selfbot-api22/main.py` is outside install scope and was not analysed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "selfbot-api22",
    "version": "1.0",
    "archive_sha256": "b8ac9a8fe9132caa11870c54ff77eccb14f5cd1d122d3ad5b48b23467a6aebfc",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/selfbot-api22-1.0.tar.gz",
    "package_root": "layer0/selfbot-api22-1.0",
    "cluster_key": "a61a57af2bc373cb2ee062532bc250ed60accbd30f7e0b3cc8ca19617a1952ba",
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
          "decoded_eval"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: lines 1-3, 567 and 571-583 read in full. Line 567 runs exec(marshal.loads(...)) on a base85/base32/base16/base64/lzma/zlib-wrapped literal at module top level, before setup(), so it runs on every build step.",
      "setup.py: lines 4-566 append hex-escaped strings to a padding variable; a sampled fragment decodes (unescape, base64) to filler text. The variable is never read, so it is dead padding, not payload.",
      "setup.py: the exec'd payload is a marshal'd code object; per the PyPI reference it is never loaded, and this session's allowlist had no base85/base32/lzma decoder, so its strings and logic stay unread.",
      "No gates are recorded only because the visible code has none; checks inside the marshal'd code are not recovered and must not be read as 'no gate'.",
      "selfbot-api22/main.py is the package's import-time module, not reached at install; not analysed."
    ]
  },
  "requirements": [
    {
      "axis": "runtime_version",
      "value": "CPython minor version matching the marshal'd code object (not recovered)",
      "reason": "marshal.loads of a code object only works on the interpreter version it was compiled for; on another version the exec fails and the payload never runs"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "other"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "exec of marshal'd code object",
      "layered encoding: base85, base32, base16, base64, lzma, zlib",
      "junk padding: 560+ lines of hex-escaped filler strings appended to an unused variable",
      "very long single lines"
    ],
    "decoded": null,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "line 567 execs a marshal'd code object behind a base85/base32/base16/base64/lzma/zlib chain; bytecode is not loaded under the static rules and no allowed tool decodes base85/base32/lzma"
      }
    ]
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py executes a marshal'd code object hidden under six layers of encoding at module top level, so it runs on every sdist build, and buries it in hundreds of lines of junk padding. No legitimate build needs this; the payload's own behaviour and any gates inside it are not recovered.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "install payload is a marshal'd code object that was not decoded or disassembled; its gates, behaviours and endpoints are unknown (needs_remote false reflects visible code only)",
    "unrecovered code"
  ],
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
