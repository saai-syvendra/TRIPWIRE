# pypi dependency_confusion111@9.9.9

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py overrides the setuptools `install`, `develop` and `egg_info` commands. Each one calls `custom_command()` after the parent `run()`, so the payload runs on any pip install of the sdist. There are no gates. The payload builds JSON with the package name, hostname, username and current directory, hex-encodes it, splits it into 60-character DNS labels and sends raw UDP DNS queries straight to ns1.uchpuchmak[.]lol:53. All it needs from the environment is outbound UDP 53 and a resolvable nameserver hostname.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script; errors hidden.
- **cmdclass** `cmdclass[develop] = CustomDevelopCommand`: runs setup.py; direct_script; errors hidden.
- **cmdclass** `cmdclass[egg_info] = CustomEggInfoCommand`: runs setup.py; direct_script; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: ns1[.]uchpuchmak[.]lol:53 (raw UDP DNS queries are sent directly to the attacker nameserver; its hostname must also resolve through the system resolver)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The 127[.]0[.]0[.]53 default address in `dns_request` is never used, because every call passes the attacker nameserver.
- The `setup()` description says the package only confirms installation and is not malicious. The code also sends identifying host data, so this is recorded as misleading text and flagged for review.
- Typical dependency-confusion probe (version 9.9.9, query labels `v2_f.<n>.<id>.<hex>.v2_e.<domain>`).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "dependency_confusion111",
    "version": "9.9.9",
    "archive_sha256": "3bffbcdfbca62c97d1deb712983ed5a64e137c11651de5e8b0813ea249d59c6e",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/dependency_confusion111-9.9.9.tar.gz",
    "package_root": "layer0/dependency_confusion111-9.9.9",
    "cluster_key": "e30268e18e0da7820337bca93cfcb7c797b3949188ca9e8836b4a28e29cb30c5",
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
        "hook": "cmdclass",
        "command": "cmdclass[develop] = CustomDevelopCommand",
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
        "hook": "cmdclass",
        "command": "cmdclass[egg_info] = CustomEggInfoCommand",
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
      "setup.py: package code read in full (81 lines); no other install-reached files. Top-level code only calls setup().",
      "custom_command() runs after install.run/develop.run/egg_info.run with no environment checks; egg_info and install run on any pip install of the sdist, develop only on legacy editable installs.",
      "Payload hex-encodes JSON {package, hostname, username, cwd} into 60-char DNS labels and sends raw UDP queries straight to ns1.uchpuchmak[.]lol:53; the 127[.]0[.]0[.]53 default in dns_request is overridden by every call, so it is not contacted.",
      "Only socket.timeout on recvfrom is swallowed, so a missing reply goes unnoticed; a failure to resolve the ns1 hostname would raise and fail the build step.",
      "setup() description claims the package's only function is to confirm installation and that it is not malicious; the code also sends hostname, username and cwd (misleading text)."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "ns1[.]uchpuchmak[.]lol:53",
      "reason": "raw UDP DNS queries are sent directly to the attacker nameserver; its hostname must also resolve through the system resolver"
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
    "techniques": [
      "misleading text"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "ns1.uchpuchmak[.]lol:53",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "dns-exfil install beacon (v2_f/v2_e labels)",
  "claude_assessment": "malicious",
  "assessment_reason": "Every pip install of the sdist runs install/egg_info overrides that collect hostname, username and working directory and exfiltrate them hex-encoded in DNS queries to an attacker-controlled nameserver. There are no gates; it reads as a dependency-confusion probe, but it sends identifying host data without consent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "setup() description claims the package only confirms installation and is not malicious, while the code exfiltrates hostname, username and cwd (misleading text)"
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
