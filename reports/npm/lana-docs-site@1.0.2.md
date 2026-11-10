# npm lana-docs-site@1.0.2

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-30 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js` on every install. The script reads `/etc/passwd`, or uses the error text if the read fails. It also collects the install directory, home directory, hostname, username, DNS servers and the whole package.json, then POSTs everything form-encoded over HTTPS to an oastify[.]com callback host. There are no gates: nothing checks the environment before collecting or sending, so any environment with outbound HTTPS to that host shows the full behaviour.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: ysu71spaxfzre4lgsrqwzsjt5kbbz2nr[.]oastify[.]com:443 (collected host data is POSTed over HTTPS to this OAST callback host)

## Behaviour

- Ungated: recon, cred_read, exfil
- Gated: none

## Notes

- The passwd try/catch only changes the data that gets sent, so it is recorded as silent failure and not as a gate.
- attack_type `dependency_confusion` is inferred from the generic internal-looking name and the usual recon beacon template (it reads `___resolved`). The registry metadata in the sample only shows a new package (one maintainer, three 1.0.x versions in four days, no description or readme). It cannot show whether a private package of that name exists, so the record stays flagged.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lana-docs-site",
    "version": "1.0.2",
    "archive_sha256": "4b33c8ec47d8ff820a72c1bdab8acb95000106209a6c371f1174aadc0992edc6",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-30",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-30-lana-docs-site-v1.0.2.zip",
    "package_root": "layer0/tmp/tmporu7m2gn/lana-docs-site/package",
    "cluster_key": "3511dc3aeec0033b58f4d493d2b96df169d0d5ec9954272be2460ebee97f5d40",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
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
      "index.js: read in full (56 lines, all package code); nothing bundled or unread.",
      "The try/catch around the /etc/passwd read is not a gate: both sides build and send the same payload, the handler only puts the error text in place of the file content.",
      "silent_failure: the passwd read error is caught and the https request error handler is empty, so a failed send does not fail the install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "ysu71spaxfzre4lgsrqwzsjt5kbbz2nr[.]oastify[.]com:443",
      "reason": "collected host data is POSTed over HTTPS to this OAST callback host"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "cred_read",
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
        "indicator": "hxxps://ysu71spaxfzre4lgsrqwzsjt5kbbz2nr[.]oastify[.]com/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oastify[.]com callback recon beacon",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs index.js unconditionally. It reads /etc/passwd and collects the home dir, hostname, username, DNS servers and package.json, then POSTs all of it to an oastify[.]com (Burp Collaborator) host. There are no environment gates.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "attack_type dependency_confusion is inferred from the internal-looking unscoped name, the read of the ___resolved field and the OAST exfil pattern; the registry metadata in the sample (package_info json) only shows a new package (one maintainer, 1.0.0 to 1.0.2 published 2024-12-26 to 2024-12-30, no description or readme, no inflated version) and nothing available shows a private package of that name exists, so dependency_confusion versus malicious_new_package needs a person"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@497d11fbce",
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
