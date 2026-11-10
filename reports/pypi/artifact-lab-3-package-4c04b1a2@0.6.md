# pypi artifact-lab-3-package-4c04b1a2@0.6

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's `setup.py` overrides the setuptools `install` and `develop` commands; each calls the parent `run()` and then `notmalfunc()`. That function copies `os.environ` into a dict, URL-encodes it and POSTs it to `hxxps://5cecdbdb0328[.]ngrok[.]app/collect` with `urllib.request.urlopen`. There are no gates: any pip install of the sdist (or a legacy editable install, through `develop`) sends the whole environment. The only thing the payload needs is outbound HTTPS to the ngrok host; a failed request is caught and printed, so the install still succeeds.

## Execution

- **cmdclass** `cmdclass[develop] = AfterDevelop`: runs on git or local install only; runs setup.py; direct_script; errors hidden.
- **cmdclass** `cmdclass[install] = AfterInstall`: runs setup.py; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: 5cecdbdb0328[.]ngrok[.]app:443 (environment variables are POSTed to this ngrok endpoint over HTTPS)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Package name pattern (`artifact-lab-3-package-<hex>`) and the env-dump-to-ngrok shape look like a lab or test exercise, but the install code exfiltrates real environment contents, so it is labelled malicious.
- The function name `notmalfunc` is attacker-chosen text; the comment directly above it says it leaks environment variables, which matches the code, so no misleading-text flag.
- The environment is also printed to stdout before sending (debug print), which is output only.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "artifact-lab-3-package-4c04b1a2",
    "version": "0.6",
    "archive_sha256": "aa303afacfd04819ecfdcfcdb36604a45644a6747d84c5db16edff2eacf7a39b",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/artifact-lab-3-package-4c04b1a2-0.6.tar.gz",
    "package_root": "layer0/artifact-lab-3-package-4c04b1a2-0.6",
    "cluster_key": "1c3c380a4ffb46bd9437ee66555fb32b57583de1e8b8246db631530c37ddbac2",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[develop] = AfterDevelop",
        "runs_on": "git_or_local_install_only",
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
        "hook": "cmdclass",
        "command": "cmdclass[install] = AfterInstall",
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
      "setup.py read in full (51 lines). No environment checks anywhere on the install path; notmalfunc() runs unconditionally after install.run()/develop.run().",
      "develop override runs only on legacy editable installs (pip install -e / setup.py develop), so runs_on is git_or_local_install_only for that entry; the install override covers a normal pip install of the sdist.",
      "The urlopen call is wrapped in try/except Exception that only prints, so a failed POST does not fail the install.",
      "Package modules (__init__.py, flag.py with a hello() print) are not reached at install and contain nothing of note."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "5cecdbdb0328[.]ngrok[.]app:443",
      "reason": "environment variables are POSTed to this ngrok endpoint over HTTPS",
      "sites": [
        {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 754,
          "end_byte": 781,
          "node_type": "call",
          "sha256": "c06b43e6d4cfa9f0",
          "line": 23
        }
      ]
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
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
        "indicator": "hxxps://5cecdbdb0328[.]ngrok[.]app/collect",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "artifact-lab env exfil",
  "claude_assessment": "malicious",
  "assessment_reason": "Custom install and develop commands collect the full os.environ dict and POST it to an ngrok endpoint with no gate, which leaks any secrets in the installing environment. Errors are swallowed so the install still succeeds.",
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
