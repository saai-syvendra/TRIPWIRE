# npm @swiggy-private/js-utils@3.13.999999999999

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-14 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The preinstall and postinstall hooks both run `node index.js`, followed by an `echo` that discards the exit code. index.js has no gates: it always collects the install directory, home directory, hostname and username and POSTs them as form data to an external host with `https.request`. Any environment triggers it, so nothing needs to be set up beyond outbound network access.

## Execution

- **preinstall** `node index.js; echo "pre done"`: runs index.js; direct_script; errors hidden.
- **postinstall** `node index.js ; echo "post done"`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: securityhuman[.]pythonanywhere[.]com:443 (Exfil POST target. As written the hostname option carries the 'https://' scheme, so resolution likely fails even with the host reachable.)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The request options put the full URL with its scheme (`hxxps://securityhuman[.]pythonanywhere[.]com`) in `hostname`, so the lookup should fail and the empty error handler hides that. The exfil is recorded as attempted. A scanner would still see a DNS lookup attempt.
- The scoped name and the `3.13.999999999999` version fit dependency confusion against a private scope.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@swiggy-private/js-utils",
    "version": "3.13.999999999999",
    "archive_sha256": "a0bb3619066bcc025c47204d794507132491f4c0ab355e46a03371dfea02c077",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-14",
    "released_at_source": "dataset",
    "sample_path": "datadog/npm/malicious_intent/2024-12-14-@swiggy-private_js-utils-v3.13.999999999999.zip",
    "package_root": "layer0/tmp/tmpvnkd_2dt/@swiggy-private-js-utils/package",
    "cluster_key": "8812a6675de31b0b87d3630267c81470f0f81d6af4cf01e9c3f924dcb260e25f",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js; echo \"pre done\"",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      },
      {
        "hook": "postinstall",
        "command": "node index.js ; echo \"post done\"",
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
      "index.js (40 lines, package code) read in full; nothing bundled, nothing unread. The same script runs in both preinstall and postinstall.",
      "silent_failure: the hook commands end with '; echo', discarding node's exit code, and req.on('error') has an empty handler.",
      "index.js collects __dirname, os.homedir(), os.hostname() and os.userInfo().username, JSON-encodes them and POSTs them unconditionally via https.request. No environment check anywhere.",
      "The request options set hostname to a full URL ('hxxps://securityhuman[.]pythonanywhere[.]com') instead of a bare host, so the DNS lookup should fail and the send likely never completes; the error is swallowed. Exfil is recorded as attempted.",
      "https.request, req.write(postData) and req.end() all run synchronously at install, so the exfil code is reached; the failure would come later in the async DNS lookup and is swallowed by the empty error handler. No later code depends on it."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "securityhuman[.]pythonanywhere[.]com:443",
      "reason": "Exfil POST target. As written the hostname option carries the 'https://' scheme, so resolution likely fails even with the host reachable.",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 362,
          "end_byte": 414,
          "node_type": "pair",
          "sha256": "714c9b95f1bd62f5",
          "line": 20
        }
      ]
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
        "indicator": "hxxps://securityhuman[.]pythonanywhere[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "Both preinstall and postinstall run index.js, which unconditionally sends the install directory, home directory, hostname and username to an external server. It is a dependency-confusion recon beacon under a private-looking scope with an inflated version; a bug in the hostname option probably stops the send from completing.",
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
