# npm @emilgroup/partner-portal-sdk-node@1.1.2

**Source:** datadog · **Source label:** malicious · **Released:** 2026-03-20 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`, which, inside one try with an empty catch, decodes a base64 Python script to `~/.local/share/pgmon/service.py`, writes a systemd user unit `pgmon.service`, and runs `systemctl --user daemon-reload`, `enable` and `start`. There are no environment gates: the only check (`if (!BASE64_PAYLOAD)`) tests a constant. The payload simply needs Linux with a systemd user session and python3; elsewhere the systemctl calls fail silently. The started service waits 300s, then polls an ICP canister (hxxps://tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io/) for a URL and downloads and runs the binary it names.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script, detached_child; errors hidden.

## Gates

None.

## Requirements

- os: linux (persistence uses a systemd user unit and /usr/bin/python3; on other OSes systemctl fails and the catch swallows it)
- installed_tool: systemctl, python3 (systemctl --user enables and starts the unit; the unit runs /usr/bin/python3)
- other: systemd user session (user D-Bus) available (systemctl --user daemon-reload/enable/start fail without a user manager, e.g. in minimal containers)
- network: tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io:443 (the started service polls this canister for a second-stage URL (after the install, 300s delay))

## Behaviour

- Ungated: write_file, persistence, spawn_process
- Gated: none

## Notes

- The service.py checks (reply starts with `http`, does not contain youtube[.]com, differs from `/tmp/.pg_state`) are server-response tests that run after the install returns; they are not recorded as install-time gates.
- `scripts/deploy.js` is an npm-token worm (republishes this package under every package the token owns) but only runs through the `deploy` script, not at install.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@emilgroup/partner-portal-sdk-node",
    "version": "1.1.2",
    "archive_sha256": "5f4db2c1d7d6e226e22dfebcbc51793308cfff243be9e35984bb92297afb697d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-03-20",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-03-20-@emilgroup_partner-portal-sdk-node-v1.1.2.zip",
    "package_root": "layer0/tmp/tmpd2g9xun6/@emilgroup-partner-portal-sdk-node/package",
    "cluster_key": "33a65a75d561ca7e5c23b50557b60210904e51116664a86637324de6d8a46754",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "index.js:12 (decoded service.py, time.sleep(300))",
        "seconds": 300,
        "purpose": "dropped systemd service waits 5 minutes before first C2 poll"
      },
      {
        "site": "index.js:12 (decoded service.py, time.sleep(3000))",
        "seconds": 3000,
        "purpose": "poll interval of the dropped service loop"
      }
    ],
    "notes": [
      "index.js: read in full, including the base64 Python script at line 12 (decoded with decode.py base64); whole body sits in one try with an empty catch; nothing unread.",
      "index.js:14 `if (!BASE64_PAYLOAD) process.exit(0)` tests a non-empty string constant, so it is not an environmental check and not a gate.",
      "Install writes ~/.local/share/pgmon/service.py and ~/.config/systemd/user/pgmon.service, then runs systemctl --user daemon-reload, enable and start. The service outlives the install (Restart=always).",
      "Decoded service.py (started by systemctl at install, runs after the install returns): sleeps 300s, polls an ICP canister URL, and if the reply starts with http, differs from /tmp/.pg_state and does not contain youtube[.]com, downloads it to /tmp/pglog, chmods and runs it.",
      "Those service.py checks are server-response tests in a process that runs after the install and are not recorded as install-time gates; the download/exec they guard is covered by persistence. The service is a separate systemd process that sleeps 300s before its first check.",
      "scripts/deploy.js (npm token worm: whoami, list owned packages, republish this package under each name) is only run by the `deploy` script, never by an install hook. Not install-time."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "linux",
      "reason": "persistence uses a systemd user unit and /usr/bin/python3; on other OSes systemctl fails and the catch swallows it"
    },
    {
      "axis": "installed_tool",
      "value": [
        "systemctl",
        "python3"
      ],
      "reason": "systemctl --user enables and starts the unit; the unit runs /usr/bin/python3"
    },
    {
      "axis": "other",
      "value": "systemd user session (user D-Bus) available",
      "reason": "systemctl --user daemon-reload/enable/start fail without a user manager, e.g. in minimal containers"
    },
    {
      "axis": "network",
      "value": "tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io:443",
      "reason": "the started service polls this canister for a second-stage URL (after the install, 300s delay)"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "write_file",
      "persistence",
      "spawn_process"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "Python second stage embedded as a base64 string literal and written to disk decoded",
      "persistence disguised as a service named pgmon"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://tdtqy-oyaaa-aaaae-af2dq-cai[.]raw[.]icp0[.]io/",
        "role": "c2"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "ICP canister systemd backdoor (CanisterWorm-style)",
  "claude_assessment": "malicious",
  "assessment_reason": "postinstall drops a Python backdoor and installs, enables and starts it as a persistent systemd user service with no environment checks. The service polls an ICP canister for a URL and downloads and runs whatever binary it names.",
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
