# pypi artifact-lab-3-package-a18ff5d9@0.1.1

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the setuptools `install` and `develop` commands; after the normal run, both call `notmalfunc()`. That function copies `os.environ`, urlencodes it and builds a `urllib.request.Request` aimed at an ngrok tunnel, but never opens it, so nothing is sent. There are no gates: the env read runs unconditionally on every sdist install (and on legacy editable installs through `develop`). No environment is needed to reach it.

## Execution

- **cmdclass** `cmdclass[develop] = AfterDevelop`: runs on git or local install only; runs setup.py; direct_script.
- **cmdclass** `cmdclass[install] = AfterInstall`: runs setup.py; direct_script.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: recon
- Gated: none

## Notes

- Intended exfil host: hxxps://2edb-85-48-187-158[.]ngrok-free[.]app. Left out of `reachability.endpoints` because it is not contacted at install.
- The function name `notmalfunc` claims the code is harmless, so it is recorded as misleading text.
- Package names and `flag.py` look like a CTF or lab exercise, but that is only a naming hint and does not change the label.
- The assessment is malicious by intent with medium confidence; a reviewer may prefer suspicious because the exfil does not work.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "artifact-lab-3-package-a18ff5d9",
    "version": "0.1.1",
    "archive_sha256": "c1169bd1f2924585b7c21be2d7eab48875685ffdd4a8946db87416b5b7d6914c",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/artifact-lab-3-package-a18ff5d9-0.1.1.tar.gz",
    "package_root": "layer0/artifact-lab-3-package-a18ff5d9-0.1.1",
    "cluster_key": "4d85252ba6716494c567788a264ef9cfaf9dd63c1f48a630f746ec2ab89d5347",
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
        "silent_failure": false
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
        "silent_failure": false
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
      "setup.py: read in full (41 lines). Top level only defines the two cmdclass overrides and calls setup(); nothing unread.",
      "AfterInstall.run and AfterDevelop.run call notmalfunc() after super run. develop runs only on legacy editable installs, so that entry is marked git_or_local_install_only.",
      "notmalfunc() copies os.environ, urlencodes it and builds urllib.request.Request to an ngrok host, but never calls urlopen, so no request is sent. Only the env read runs at install.",
      "The intended exfil sink is hxxps://2edb-85-48-187-158[.]ngrok-free[.]app; it is not contacted at install because the Request is never opened, so it is left out of endpoints.",
      "Function name notmalfunc ('not mal func') claims the code is harmless while it collects all env vars for an outbound POST.",
      "Package modules (empty __init__.py, flag.py with a hello() print) are not reached at install."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass override collects every environment variable and prepares a POST to an ngrok tunnel, which is clear exfil intent. The request object is never opened, so no data actually leaves the machine at install; only the env read runs.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "misleading text: function name notmalfunc claims harmlessness while the code prepares env var exfil",
    "exfil is non-functional (Request built, urlopen never called); check whether malicious is the right assessment for code that sends nothing"
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
