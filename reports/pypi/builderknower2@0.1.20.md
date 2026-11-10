# pypi builderknower2@0.1.20

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist overrides the setuptools `install` command (`CustomInstallCommand`), so its `run()` executes on a normal pip install from source. It runs shell commands through `os.system` with no environment checks: it installs `requests`, fetches hxxp://self[.]diddlydingusdu[.]de/latest/ twice and the cloud instance metadata service hxxp://169[.]254[.]169[.]254/latest/ (with proxy variables unset), and appends the responses to the package's `LICENSE` file. It then touches `/tmp/pytest2` as a marker. There are no gates; every behaviour runs on any POSIX host with python3 and network access.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstallCommand`: runs setup.py; direct_script, inline_shell, inline_eval; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: self[.]diddlydingusdu[.]de:80, 169[.]254[.]169[.]254:80, pypi[.]org:443 (fetches from the attacker host and the cloud metadata service; pip install requests needs the package index)
- installed_tool: python3 (the fetches and pip install are run as python3 through the shell)
- os: linux (shell syntax (unset, >>) and touch /tmp/pytest2 assume a POSIX shell; darwin would also work)

## Behaviour

- Ungated: spawn_process, download, recon, write_file
- Gated: none

## Notes

- Commented-out code would have sent `env` and `ls -al` output base64-encoded to diddlydingusdu[.]de via curl; it does not run in this version and its endpoints were left out.
- The metadata service fetch is recon of the build host's cloud environment; it has no endpoint role in the schema, so it is a network requirement and a note.
- Failures are silent: exit codes are ignored and exceptions are caught and printed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "builderknower2",
    "version": "0.1.20",
    "archive_sha256": "5f47ecbaad9ef4dfe29155465aa83cd0bce5b3feb158f140c0640bbf44893249",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/builderknower2-0.1.20.tar.gz",
    "package_root": "layer0/builderknower2-0.1.20",
    "cluster_key": "6dfc7f1f69614afaab50e36bc7300854d1986226abd8f3da8221ee3af2a696e1",
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
          "direct_script",
          "inline_shell",
          "inline_eval"
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
      "setup.py read in full (77 lines); the only install code is CustomInstallCommand.run. setup_py hook top level only calls setup(); package modules are a hello-world stub and run only when imported.",
      "run() calls os.system unconditionally: pip install requests, then three python3 -c one-liners that GET hxxp://self[.]diddlydingusdu[.]de/latest/ (twice) and the cloud metadata service hxxp://169[.]254[.]169[.]254/latest/, writing responses into LICENSE in the build dir.",
      "Two of the fetches unset HTTP_PROXY/HTTPS_PROXY first so the requests go direct. Then touch /tmp/pytest2 as a marker. No check on the environment anywhere: no gates.",
      "The curl calls exfiltrating env and ls output (diddlydingusdu[.]de/X/ and /D/) and the make_http_request TEST_SITE call are commented out and do not run; those endpoints were removed.",
      "Errors are swallowed: os.system exit codes are ignored and the try blocks catch Exception and only print it."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "self[.]diddlydingusdu[.]de:80, 169[.]254[.]169[.]254:80, pypi[.]org:443",
      "reason": "fetches from the attacker host and the cloud metadata service; pip install requests needs the package index"
    },
    {
      "axis": "installed_tool",
      "value": "python3",
      "reason": "the fetches and pip install are run as python3 through the shell"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "shell syntax (unset, >>) and touch /tmp/pytest2 assume a POSIX shell; darwin would also work"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "spawn_process",
      "download",
      "recon",
      "write_file"
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
        "indicator": "hxxp://self[.]diddlydingusdu[.]de/latest/",
        "role": "c2"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "At install the cmdclass install override unconditionally beacons to an attacker host and queries the cloud instance metadata service with proxies unset, saving the responses into the package's LICENSE file. It reads like build-infrastructure probing (SSRF-style metadata recon); the env exfil curl lines are commented out.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "The cloud metadata URL hxxp://169[.]254[.]169[.]254/latest/ is fetched at install but is a victim-side service, not attacker infrastructure, so it has no fitting endpoint role; recorded as a network requirement and in notes instead."
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
