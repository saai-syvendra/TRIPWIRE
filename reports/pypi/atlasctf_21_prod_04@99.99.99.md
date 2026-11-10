# pypi atlasctf_21_prod_04@99.99.99

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py overrides the `install` command with `CustomInstallCommand`, which runs on a normal pip install of the sdist. After the regular install it opens `/flag.txt` and POSTs the content, plus the package name, to a webhook.site URL. There are no gates: the only environmental dependency is that `/flag.txt` exists, and a missing file just raises into a bare `except: pass`, so it is recorded as a requirement. The install code exfiltrates whenever the file is present and the webhook is reachable.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- file_present: /flag.txt (read unconditionally; if absent the open raises and the bare except skips the POST)
- network: webhook[.]site:443 (flag content is POSTed to a webhook.site URL)
- other: python module requests importable in the build environment (setup.py imports requests at top level without declaring it as a build requirement)

## Behaviour

- Ungated: exfil
- Gated: none

## Notes

- `requests` is imported at the top of setup.py but never declared as a build requirement, so in an isolated build the import fails and nothing runs. A scanner needs `requests` available in the build environment to see the POST.
- The package `__init__.py` repeats the same read and POST at import time (out of scope).
- Version 99.99.99 and the CTF-style name suggest a dependency-confusion exercise; webhook id redacted.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "atlasctf_21_prod_04",
    "version": "99.99.99",
    "archive_sha256": "7ba25fde023bee416b8be88fa7ff977f1250b3c3429202f543e9c49a0c70f1c6",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/atlasctf_21_prod_04-99.99.99.tar.gz",
    "package_root": "layer0/atlasctf_21_prod_04-99.99.99",
    "cluster_key": "a918108c7f8fd56f896be96f69a4a75f58edcf28718eb69efe268ed97a55d4bf",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstallCommand",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
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
      "setup.py: package code read in full (21 lines); nothing bundled, nothing unread.",
      "CustomInstallCommand.run calls install.run, then unconditionally opens /flag.txt and POSTs its content to a webhook. A missing file raises into a bare except: pass, so the read is a requirement, not a gate.",
      "setup.py top level only imports requests and calls setup(); no other behaviour on the setup_py hook. requests is not declared, so under isolated builds the import itself fails before setup() runs.",
      "atlasctf_21_prod_04/__init__.py repeats the same flag read and POST at import time; not install time, out of scope here."
    ]
  },
  "requirements": [
    {
      "axis": "file_present",
      "value": "/flag.txt",
      "reason": "read unconditionally; if absent the open raises and the bare except skips the POST",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 220,
          "end_byte": 237,
          "node_type": "call",
          "sha256": "4887afb460d79182",
          "line": 9
        }
      ]
    },
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "flag content is POSTed to a webhook.site URL"
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "setup.py imports requests at top level without declaring it as a build requirement",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 91,
          "end_byte": 106,
          "node_type": "import_statement",
          "sha256": "06185522e4085460",
          "line": 3
        }
      ]
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "exfil"
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
        "indicator": "hxxps://webhook[.]site/0b19…/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "atlasctf flag exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "A custom install command reads /flag.txt and POSTs its contents to a webhook.site URL with no gate, inside a silent except. Version 99.99.99 and a CTF-internal-looking name point to a dependency-confusion style exfil (likely a CTF exercise).",
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
