# pypi very-hackerman@0.0.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` runs at build time and, inside a try with a bare `except: pass`, imports `requests` and POSTs a fixed message to a Discord webhook. It then execs an escaped string that base64-decodes a second stage, which POSTs to a second webhook and execs a Fernet-encrypted third stage (key embedded as a base64 literal). The third stage is a plain reverse shell to 2[.]58[.]56[.]173:5003 that runs C2 commands through `subprocess.getoutput`. There are no environment gates in any stage. The beacons need only `requests` and discord[.]com; the shell also needs the `cryptography` module in the build environment and the C2 reachable.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval; errors hidden.

## Gates

None.

## Requirements

- network: discord[.]com:443 (both stages POST to Discord webhooks; a connection failure raises into the bare except and stops every later stage)
- network: 2[.]58[.]56[.]173:5003 (stage 3 reverse shell connects here; without it the connect raises and the shell never starts)
- other: python module requests importable in the build environment (import requests at the top of the try; listed in build-system.requires so present under build isolation)
- other: python module cryptography importable in the build environment (stage 2 imports cryptography.fernet before running stage 3; not a declared build requirement, so the reverse shell only runs without build isolation or where cryptography is present)

## Behaviour

- Ungated: other, reverse_shell
- Gated: none

## Notes

- All three stages were decoded statically with a new candidate decoder, `exec_str_b64_fernet` (derivation d1). It needs review before it joins `tools/common/decoders/`.
- The Fernet token has a stray `#`. Python's lenient base64 drops it and the HMAC then verifies, so the stage does decrypt at runtime.
- `cryptography` is not a declared build requirement (`pycryptodome` in `install_requires` is a different module). Under default pip build isolation the import probably fails silently and only the beacons run. A dynamic scanner should build with `cryptography` available, or without isolation, to see the shell.
- The webhook messages are constant strings with no host data, so the POSTs are recorded as `other` (install beacon). The endpoints are tagged `exfil_sink` because that is the closest available role.
- The `exit`/`cd` tests in the shell loop act on C2 commands, not the environment, so they are not gates.
- `src/example_package/__init__.py` repeats the same payload at import time, which is out of install scope.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "very-hackerman",
    "version": "0.0.1",
    "archive_sha256": "bd7e618ed57b4090833f6c85469c5c1cf5a91aaa44c1e1a569b890dd1c0682c2",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/very-hackerman-0.0.1.tar.gz",
    "package_root": "layer0/very-hackerman-0.0.1",
    "cluster_key": "29209cba1ea1d711638d892a071341fb88cb930401676865941944fb53a79f36",
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
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full, all three nested stages decoded (derivation d1, candidate decoder exec_str_b64_fernet); nothing unread. The tool did not recover the stages because they sit inside exec'd string literals.",
      "Stage 1 (top-level try, bare except: pass): import requests, POST a constant message to Discord webhook 1, then exec an escaped string that base64-decodes and execs stage 2.",
      "Stage 2: POST a constant message to Discord webhook 2, then exec stage 3, a Fernet token decrypted with a key that is itself a base64 literal in the stage (Fernet imported from cryptography under the alias b_).",
      "The Fernet token contains one '#' outside the urlsafe base64 alphabet. Python's non-validating b64decode drops it, and with it dropped the HMAC verifies, so the token decrypts at runtime.",
      "Stage 3: plain reverse shell. socket connect to 2[.]58[.]56[.]173:5003, sends cwd, then loops: recv a command, 'exit' breaks, 'cd' chdirs, anything else runs via subprocess.getoutput and the output is sent back.",
      "The exit/cd tests in the shell loop dispatch on commands from the C2, not on the environment; they are part of the reverse_shell behaviour, not gates. No environment checks exist in any stage.",
      "Stage 3 imports cryptography, which is not in build-system.requires (setuptools, requests) or install_requires (pycryptodome, a different module). Under pip build isolation the import fails and the bare except hides it, so only the beacons run.",
      "The connect blocks the build while the shell is live; the shell runs in the foreground of setup.py, not as a detached child.",
      "src/example_package/__init__.py holds the same exec/base64 payload but only runs when the package is imported, not at install. README.md read for long_description is plumbing (its value is then unused)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "both stages POST to Discord webhooks; a connection failure raises into the bare except and stops every later stage"
    },
    {
      "axis": "network",
      "value": "2[.]58[.]56[.]173:5003",
      "reason": "stage 3 reverse shell connects here; without it the connect raises and the shell never starts",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 864,
          "end_byte": 904,
          "node_type": "call",
          "sha256": "d0f3b3fb75eb44f7",
          "line": 20
        }
      ]
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "import requests at the top of the try; listed in build-system.requires so present under build isolation"
    },
    {
      "axis": "other",
      "value": "python module cryptography importable in the build environment",
      "reason": "stage 2 imports cryptography.fernet before running stage 3; not a declared build requirement, so the reverse shell only runs without build isolation or where cryptography is present",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": "d1",
          "start_byte": 452,
          "end_byte": 497,
          "node_type": "import_from_statement",
          "sha256": "bc8ded1e1dceb12f",
          "line": 8
        }
      ]
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "other",
      "reverse_shell"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "exec of an escaped source string",
      "nested exec of a base64-encoded stage",
      "Fernet-encrypted third stage decrypted with an embedded base64 key and exec'd",
      "stray '#' inserted into the Fernet token",
      "module aliases (b_, _b) and pyobfuscate-style spacing",
      "very long single lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://discord[.]com/api/webhooks/9815…",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://discord[.]com/api/webhooks/9814…",
        "role": "exfil_sink"
      },
      {
        "indicator": "2[.]58[.]56[.]173:5003",
        "role": "reverse_shell"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py, with errors swallowed, beacons to two Discord webhooks at install and then runs a three-layer (string, base64, Fernet) hidden stage that opens a reverse shell to 2[.]58[.]56[.]173:5003. There are no environment gates; the shell only needs the cryptography module in the build environment and the C2 reachable.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "decode relies on candidate decoder scratch decoders/exec_str_b64_fernet.py, which needs human review before it joins tools/common/decoders"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "decoder": "exec_str_b64_fernet",
          "lang": "py"
        },
        "output_sha256": "dee4210cb6dc58d9"
      }
    ],
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
