# npm @navancorp/icons@1.0.4

**Source:** datadog · **Source label:** malicious · **Released:** 2025-08-21 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

A `postinstall` hook runs `node postinstall.js` on every registry install. The script first asks a public geo-IP service for the machine's public IP, ASN and location, then (whether or not that lookup worked) builds a JSON blob with hostname, OS, arch, username, home directory, working directories, node version and pid, and POSTs it to three hosts under insomnia1102[.]online. There are no gates: nothing in the code checks the environment, so any install with outbound HTTPS reaches the payload.

## Execution

- **postinstall** `node postinstall.js`: runs postinstall.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: insomnia1102[.]online:443, d2jfhn9doh01rfec4hj0crgmujkd55sq1[.]insomnia1102[.]online:443, d2jfhjpdoh01rlh6gm40tdkbbd54ppgoq[.]insomnia1102[.]online:443 (the host info JSON is POSTed to all three hosts; any one reachable receives it)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Errors are swallowed everywhere (empty POST error handlers, lookup failure ignored), so the install never fails visibly.
- `attack_type` is dependency confusion based on the shape of the package: a corporate-looking private scope, a generic name, and a pure recon beacon with no real content (`index.js` is an empty export). Nothing in the code confirms which organisation was targeted.
- One exfil URL path is `/s/xss.js`, but the script only POSTs to it; nothing is downloaded or run.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@navancorp/icons",
    "version": "1.0.4",
    "archive_sha256": "705a687c46b3a7667f9d631a51b47501e0881d2f09303feea210c3281fb8fdbf",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-08-21",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-08-21-@navancorp_icons-v1.0.4.zip",
    "package_root": "layer0/tmp/tmppdvr52kx/@navancorp-icons/package",
    "cluster_key": "101433e429ac9eea5f7f647b923d6d14df3af8f407fa396f0af41f0de6f22a56",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node postinstall.js",
        "runs_on": "always",
        "file_chain": [
          "postinstall.js"
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
      "postinstall.js read in full (97 lines, plain JS). index.js is an empty module.exports and is not reached at install.",
      "No environment checks: the getIPInfo callback ignores err, so sendData runs whether or not the geo lookup succeeds; missing geo fields become 'unknown'.",
      "The GET to hxxps://ipapi[.]co/json/ is a public geo-IP lookup that only adds public IP, ASN, org and location to the beacon (recon). It is not attacker infrastructure and is not needed to complete, so it is not listed under endpoints or requirements.",
      "silent_failure: each POST has an empty error handler, and lookup errors and the 5 s lookup timeout are swallowed into the callback.",
      "The req.setTimeout(5000) on the geo lookup is a network timeout, not a deliberate delay, so delays stays empty."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "insomnia1102[.]online:443, d2jfhn9doh01rfec4hj0crgmujkd55sq1[.]insomnia1102[.]online:443, d2jfhjpdoh01rlh6gm40tdkbbd54ppgoq[.]insomnia1102[.]online:443",
      "reason": "the host info JSON is POSTed to all three hosts; any one reachable receives it"
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
        "indicator": "hxxps://insomnia1102[.]online/s/xss.js",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://d2jfhn9doh01rfec4hj0crgmujkd55sq1[.]insomnia1102[.]online",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://d2jfhjpdoh01rlh6gm40tdkbbd54ppgoq[.]insomnia1102[.]online",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script unconditionally collects hostname, username, home directory, working directories, OS and node details plus public IP and geo data, and POSTs it as JSON to three attacker-controlled hosts. It does no legitimate install work.",
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
