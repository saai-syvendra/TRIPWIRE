# npm @xayz/baileys@6.1.8

**Source:** datadog · **Source label:** malicious · **Released:** 2026-09-28 (registry) · **Assessment:** benign (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

Two hooks run at install. `preinstall` runs `engine-requirements.js`, which fails the install on Node below 20. `postinstall` runs `scripts/self-test.js` (errors silenced with `|| exit 0`). That script has one gate: it exits early when `BAILEYS_SKIP_SELFTEST=1`. Otherwise it imports `lib/index.js` (top-level code only prints a banner) and opens one WebSocket to WhatsApp Web as a connectivity test. Any environment without that variable set opens the gate, and nothing behind it collects, sends, writes or runs anything.

## Execution

- **preinstall** `node ./engine-requirements.js`: runs engine-requirements.js; direct_script.
- **postinstall** `node ./scripts/self-test.js || exit 0`: runs scripts/self-test.js; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | postinstall | c1 (c1: process.env.BAILEYS_SKIP_SELFTEST != 1) | then | 1 | other | env_var_absent=BAILEYS_SKIP_SELFTEST |

Gate intent: g1 activate/enables/unclear

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- runtime_version: node>=20 (preinstall exits 1 on Node below 20, failing the install so postinstall never runs)
- network: web[.]whatsapp[.]com:443 (self-test WebSocket reachability probe; a failure is caught and only changes the printed result)

## Behaviour

- Ungated: none
- Gated: other

## Notes

- The source label is malicious, but the install-time code is benign. The suspicious parts are runtime library features, for example `DEFAULT_AUTO_FOLLOW_CHANNELS` in `lib/Defaults/index.js` (a hard-coded channel followed on connect) and the newsletter helpers in `lib/Socket/luxu.js`. These run only when a consumer opens a socket. A reviewer should confirm the label is about runtime behaviour.
- The postinstall import runs the top-level code of every module in `lib/`. I audited it by sink inventory and a scan of top-level statements, not line by line.
- The `libsignal` dependency is aliased to `@xayz/libsignal-node@latest` and loads during the import. Its code was not reviewed (dependency tree).
- The endpoint list is left empty because the only host contacted, WhatsApp Web, is a legitimate service and none of the endpoint roles fit. It is listed under network requirements instead.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@xayz/baileys",
    "version": "6.1.8",
    "archive_sha256": "9505f372ff51c1136dfb03ca5309a95f46dd08017e5aaee307cee700c9a261ac",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-09-28",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2026-09-28-@xayz_baileys-v6.1.8.zip",
    "package_root": "layer0/tmp/tmpspvcm4vh/@xayz-baileys/package",
    "cluster_key": "b3271cfb00f220e37d0c13e5d084f28d5fc1427ba52d529110c10bf2eb0aeef9",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node ./engine-requirements.js",
        "runs_on": "always",
        "file_chain": [
          "engine-requirements.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": false
      },
      {
        "hook": "postinstall",
        "command": "node ./scripts/self-test.js || exit 0",
        "runs_on": "always",
        "file_chain": [
          "scripts/self-test.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "scripts/self-test.js:86",
        "seconds": 12.0
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in scripts/self-test.js; candidates there may be missing",
      "The prepare hook is an empty string in package.json, so it runs nothing; entry removed.",
      "engine-requirements.js (preinstall) read in full: exits 1 when the Node major version is below 20, failing the install before postinstall. Recorded as a runtime_version requirement, not a gate.",
      "scripts/self-test.js read in full: prints a banner, dynamically imports lib/index.js, opens one WebSocket to WhatsApp Web as a reachability test with a 12 s timeout, prints results, exits 0.",
      "The import of lib/index.js runs the library's top-level code at install. lib/ and WAProto/ audited by sink inventory and a scan of top-level statements: only banner console output, enum IIFEs, constant tables and createRequire. No install-time sink found.",
      "Runtime-only features in lib/ (a default auto-follow of a hard-coded WhatsApp channel in lib/Defaults/index.js, newsletter helpers in lib/Socket/luxu.js) run only when a consumer opens a socket, not at install.",
      "Dependency libsignal is aliased to npm:@xayz/libsignal-node@latest and is loaded through the lib import; its code is dependency tree and out of scope.",
      "The WhatsApp Web endpoint (wss://web[.]whatsapp[.]com/ws/chat) is a legitimate service contacted only as a connectivity check; no endpoint role fits, so it is listed as a network requirement instead.",
      "The WebSocket sink sits inside the Promise executor arrow in testNetworkReachability; the executor runs synchronously when the promise is built."
    ]
  },
  "requirements": [
    {
      "axis": "runtime_version",
      "value": "node>=20",
      "reason": "preinstall exits 1 on Node below 20, failing the install so postinstall never runs",
      "sites": [
        {
          "file": "engine-requirements.js",
          "derived_from": null,
          "start_byte": 70,
          "end_byte": 80,
          "node_type": "binary_expression",
          "sha256": "cbc6fc2562c8608b",
          "line": 3
        }
      ]
    },
    {
      "axis": "network",
      "value": "web[.]whatsapp[.]com:443",
      "reason": "self-test WebSocket reachability probe; a failure is caught and only changes the printed result"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "env_var",
      "api": "process.env.BAILEYS_SKIP_SELFTEST",
      "operator": "!=",
      "value": "1",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_effb7d8d5f",
          "anchor": {
            "file": "scripts/self-test.js",
            "derived_from": null,
            "start_byte": 5838,
            "end_byte": 5879,
            "node_type": "binary_expression",
            "sha256": "6ac3f2b9317426f2",
            "line": 124
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "postinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_0696134fac",
          "site": {
            "file": "scripts/self-test.js",
            "derived_from": null,
            "start_byte": 5834,
            "end_byte": 6010,
            "node_type": "if_statement",
            "sha256": "a5f1c784f792629c",
            "line": 124
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "user opt-out switch: BAILEYS_SKIP_SELFTEST=1 skips the self-test (library import and WhatsApp reachability probe)",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "other"
        ],
        "env_recipe": {
          "env_var_absent": [
            "BAILEYS_SKIP_SELFTEST"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "scripts/self-test.js",
            "derived_from": null,
            "start_byte": 6016,
            "end_byte": 6211,
            "node_type": "stmt_range",
            "sha256": "31558bc3354d2798",
            "line": 129
          }
        ],
        "payload": [
          {
            "behaviour": "other",
            "sink_kind": "network",
            "sink": {
              "file": "scripts/self-test.js",
              "derived_from": null,
              "start_byte": 3161,
              "end_byte": 3354,
              "node_type": "new_expression",
              "sha256": "d68604757757a92f",
              "line": 66
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "scripts/self-test.js",
                  "derived_from": null,
                  "start_byte": 6069,
                  "end_byte": 6094,
                  "node_type": "call_expression",
                  "sha256": "727250426270ef33",
                  "line": 131
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "scripts/self-test.js",
                  "derived_from": null,
                  "start_byte": 2924,
                  "end_byte": 4692,
                  "node_type": "function_declaration",
                  "sha256": "ef581b204589eb27",
                  "line": 58
                }
              }
            ]
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "other"
    ]
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
  "attack_type": "unknown",
  "family_hint": null,
  "claude_assessment": "benign",
  "assessment_reason": "Install-time code only checks the Node version, imports the library (banner output) and opens one WebSocket to WhatsApp Web as a connectivity test. No data is collected or sent and nothing is written or executed at install; whatever earned the malicious label is in runtime library code.",
  "label_disagreement": true,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "source label malicious but install-time code is benign; malicious intent is likely runtime library behaviour such as the hard-coded channel auto-follow",
    "lib/ top-level code reached by the postinstall import was audited by sink inventory, not read line by line",
    "label disagreement"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "a21d97af13d90632"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": []
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
