# npm @monkey-tilt/client@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-18 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js` on every registry install. The script first sends a GET to the public site of the company the scope is named after, then, whether that succeeds or fails, sends the OS type and release, working directory and hostname as query parameters to an oast[.]fun callback host (plus the status code of the first request). There are no gates: the only branches pick the value of one extra query parameter. Any environment with outbound HTTPS to the callback host triggers the full behaviour.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script.

## Gates

None.

## Requirements

- network: hfurdkpbwhysofeebwnnv9euhsfardfru[.]oast[.]fun:443 (OAST callback host receiving OS type and release, working directory and hostname over HTTPS GET)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- Shape matches dependency-confusion recon beacons: a scoped name matching a real company, a tiny install script, and an OAST interaction host as sink.
- The first request to the company site is not listed as an endpoint because no role fits; it only contributes a status code to the exfil.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@monkey-tilt/client",
    "version": "1.0.1",
    "archive_sha256": "5c8acf5249cf6c4fd5e1604fa2534316b9c5ca326968e27322b582d2898fa3d2",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-18",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-19-@monkey-tilt_client-v1.0.1.zip",
    "package_root": "layer0/tmp/tmp4spxb2we/@monkey-tilt-client/package",
    "cluster_key": "f0fb0e96d9e2fe7e5599e206c22f704ff17206d6a23128dc6920fd8e025a2270",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
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
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "index.js: 58 lines of plain package code, read in full; nothing unread. package.json has only the postinstall hook, no os/cpu/libc fields.",
      "makeSecondRequest() GETs the public site of the scope's namesake company; on response or on error it calls makeFirstRequest(), so the exfil runs either way. Not a gate.",
      "The ternary on status in makeFirstRequest only adds a &4= query parameter (status code or 'error'); same behaviour and host, so not a gate.",
      "The probe of the company site is not listed in reachability.endpoints because no endpoint role fits it; its only use is the status code it adds to the exfil query.",
      "Request errors are caught by .on('error') handlers that log to the console; the hook exits 0 either way, but nothing is hidden, so silent_failure is false."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "hfurdkpbwhysofeebwnnv9euhsfardfru[.]oast[.]fun:443",
      "reason": "OAST callback host receiving OS type and release, working directory and hostname over HTTPS GET",
      "sites": [
        {
          "file": "index.js",
          "derived_from": null,
          "start_byte": 569,
          "end_byte": 808,
          "node_type": "call_expression",
          "sha256": "f23e48f3d21c8897",
          "line": 18
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
        "indicator": "hxxps://hfurdkpbwhysofeebwnnv9euhsfardfru[.]oast[.]fun/?1=$",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "oast recon callback",
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall script unconditionally sends the OS type and release, working directory and hostname to an oast[.]fun out-of-band callback host. It is a dependency-confusion style recon beacon under a company-named scope, with no environment gate.",
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
