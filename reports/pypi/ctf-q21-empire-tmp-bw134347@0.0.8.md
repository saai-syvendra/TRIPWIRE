# pypi ctf-q21-empire-tmp-bw134347@0.0.8

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py runs at install, and after the setup() call it has one top-level line that runs `id` via os.popen and sends the output to hxxp://52[.]246[.]190[.]141:1338/?a= with requests.get. There are no gates: no condition, try/except or delay around the payload. Any environment that runs setup.py with requests importable and the host reachable triggers it.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: 52[.]246[.]190[.]141:1338 (HTTP GET carrying the `id` output; the request is not wrapped, so an unreachable host raises after the output is already gathered.)
- other: python module requests importable during the sdist build (setup.py imports requests at top level; with build isolation it is absent and setup.py fails before the payload.)
- installed_tool: id (os.popen("id") output is what gets sent; without it the request still goes out with an empty value.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- setup.py imports requests at top level, but install_requires does not make it available to the build. Under pip's default build isolation the import fails and nothing runs, so a scanner needs requests present in the build environment (for example `--no-build-isolation` or a legacy setup.py install).
- A trailing comment mentions `cat /flag.txt | base64`, a leftover from an earlier command; the code runs only `id`. The name suggests a CTF exercise, but no family is labelled.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "ctf-q21-empire-tmp-bw134347",
    "version": "0.0.8",
    "archive_sha256": "2c91fdc39f3a0de58eef3000723980e597926abf50444d31bf3605619be6ff25",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/ctf-q21-empire-tmp-bw134347-0.0.8.tar.gz",
    "package_root": "layer0/ctf-q21-empire-tmp-bw134347-0.0.8",
    "cluster_key": "e29441d0a7c0303a215ef67e47f2c7b8a0f6aa9259655d7109d2eda2f2fecb99",
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
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full (15 lines). The payload is one top-level line after setup(): it runs `id` through os.popen and sends the output in a GET query string to a hard-coded IP. No condition, try/except or delay around it.",
      "setup.py imports requests at the top, but install_requires does not install it before setup.py runs. Under pip build isolation (setuptools only), the import fails and nothing runs, so the payload needs requests already importable in the build environment.",
      "The trailing comment `#cat /flag.txt | base64\").read())` is a leftover of an earlier command (a CTF flag read); the code only runs `id`. Not treated as misleading text.",
      "main/__init__.py only defines main() that prints a string; not reached at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "52[.]246[.]190[.]141:1338",
      "reason": "HTTP GET carrying the `id` output; the request is not wrapped, so an unreachable host raises after the output is already gathered."
    },
    {
      "axis": "other",
      "value": "python module requests importable during the sdist build",
      "reason": "setup.py imports requests at top level; with build isolation it is absent and setup.py fails before the payload."
    },
    {
      "axis": "installed_tool",
      "value": "id",
      "reason": "os.popen(\"id\") output is what gets sent; without it the request still goes out with an empty value."
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
        "indicator": "hxxp://52[.]246[.]190[.]141:1338/?a=",
        "role": "exfil_sink"
      },
      {
        "indicator": "52[.]246[.]190[.]141:1338",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs `id` unconditionally during the sdist build and sends the output to a hard-coded IP over HTTP. No gates; the name and the flag comment suggest a CTF exercise, but the install-time behaviour is command execution plus exfiltration.",
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
