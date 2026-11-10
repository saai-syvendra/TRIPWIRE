# npm @accesshsc/access-forms-engine@0.999.999

**Source:** datadog · **Source label:** malicious · **Released:** 2025-03-05 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node preinstall.js` on every registry install. The script reads the current username and hostname and POSTs them as JSON to hxxps://xss8[.]uk/page_callback, with a 20 second abort timeout on the request. There are no gates: nothing checks the environment, so any install with outbound HTTPS and Node 18+ (global fetch) sends the data. The scoped name and 0.999.999 version fit a dependency confusion probe.

## Execution

- **preinstall** `node preinstall.js`: runs preinstall.js; direct_script.

## Gates

None.

## Requirements

- network: xss8[.]uk:443 (exfil POST target)
- runtime_version: node >= 18 (uses global fetch and AbortController without import)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The `preinstall2` (`calc.exe`) and `preinstall3` (PowerShell `curl.exe` POST including public IP) scripts are not lifecycle hooks and do not run on install.
- `test1/package.json` is a separate nested manifest with its own preinstall; it is not run when this package is installed.
- The 20 s timer only aborts the fetch; it is not a delay before the payload.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@accesshsc/access-forms-engine",
    "version": "0.999.999",
    "archive_sha256": "5ca74baec2f2ac080c1471ee71ee552f6c985b42664bb2a9d42e239c7d884b5f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-03-05",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-03-05-@accesshsc_access-forms-engine-v0.999.999.zip",
    "package_root": "layer0/tmp/tmp479fi4mj/@accesshsc-access-forms-engine/package",
    "cluster_key": "3d119143055845a83d8d84c00725e759b650634554d874ab406fad27c04eaaf1",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node preinstall.js",
        "runs_on": "always",
        "file_chain": [
          "preinstall.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      }
    ],
    "delays": [
      {
        "site": "preinstall.js:10",
        "seconds": 20.0
      }
    ],
    "notes": [
      "preinstall.js (24 lines): package code read in full; no conditionals, no gates. It reads os.userInfo().username and os.hostname() and POSTs them as JSON to the endpoint.",
      "The 20 s setTimeout at preinstall.js:10 is an abort timeout on the fetch, not a wait before the payload; the request is sent immediately.",
      "No .catch on the fetch promise chain, so a failed request is an unhandled rejection, not silenced; silent_failure stays false.",
      "Scripts preinstall2 (calc.exe) and preinstall3 (PowerShell curl.exe POST of whoami, hostname and public IP) are not npm lifecycle hooks and never run on install.",
      "test1/package.json is a nested manifest of a separate package (@accesshsc/using-dep-conf); npm does not run its preinstall when installing this package."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "xss8[.]uk:443",
      "reason": "exfil POST target"
    },
    {
      "axis": "runtime_version",
      "value": "node >= 18",
      "reason": "uses global fetch and AbortController without import"
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
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxps://xss8[.]uk/page_callback",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally sends the installing user's username and hostname to an external host. Scoped internal-looking name with version 0.999.999 is a dependency confusion probe; no further payload.",
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
