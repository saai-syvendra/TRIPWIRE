# npm crypto-encrypt-ts@5.4.3

**Source:** datadog · **Source label:** malicious · **Released:** 2025-04-26 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The postinstall hook runs `node scripts/setup.js`, which execs `npm install -g pm2 && pm2 start scripts/start.js --name hourly-hello`. pm2 keeps start.js running as a daemon after the install returns. start.js sends a full copy of `process.env` to a hardcoded Better Stack (Logtail) ingest source right away and then every hour, and dumps the MongoDB `wallet` collection reached through `process.env.DB_HOST`. There are no gates: every install that can fetch and start pm2 runs the payload.

## Execution

- **postinstall** `node scripts/setup.js`: 2-file chain; direct_script, inline_shell, download_then_exec, detached_child.

## Gates

None.

## Requirements

- installed_tool: npm (setup.js runs npm install -g pm2 and then the pm2 binary to start the payload)
- network: registry[.]npmjs[.]org:443, s128….eu-nbg-2.betterstackdata[.]com:443 (pm2 must be downloaded from the npm registry; collected data is sent to the Logtail ingest host)
- privilege: root_or_admin (npm install -g usually needs root on system Node installs; without it pm2 is not installed and start.js never runs (guessed, depends on the npm prefix))
- other: env var DB_HOST set to a reachable MongoDB URI with a 'wallet' collection (only needed for the wallet dump; the env exfil runs without it)

## Behaviour

- Ungated: download, spawn_process, persistence, recon, cred_read, exfil
- Gated: none

## Notes

- The Logtail source token (HNt2…) and ingest host (s128….eu-nbg-2.betterstackdata[.]com) are hardcoded in start.js.
- `DB_HOST` is used without any test. When it is missing, the connect error is caught and logged, and the env exfil still runs. Recorded as a requirement for the wallet dump only.
- The `readyState !== 1` check in the cron job only reconnects before the same actions, so it is plumbing, not a gate.
- A nested `crypto-encrypt-ts-5.4.2.tgz` ships in the package but no install code uses it.
- The privilege requirement is a guess: `npm install -g` needs root only when the npm prefix is not writable by the user.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "crypto-encrypt-ts",
    "version": "5.4.3",
    "archive_sha256": "29a3a1de8446bf6eccb02c47d5d94c18f8028830f9c20403690ac011b8b5cc20",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-04-26",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-04-26-crypto-encrypt-ts-v5.4.3.zip",
    "package_root": "layer0/tmp/tmpvwazrmdu/crypto-encrypt-ts/package",
    "cluster_key": "5664c7930bd66041be2b934e2329c71eb444da4b53bbd40b8568be21b1b30208",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "node scripts/setup.js",
        "runs_on": "always",
        "file_chain": [
          "scripts/setup.js",
          "scripts/start.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "inline_shell",
          "download_then_exec",
          "detached_child"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "scripts/setup.js read in full: one exec of 'npm install -g pm2 && pm2 start <dir>/start.js --name hourly-hello'. pm2 daemonises start.js, so it keeps running after the install returns.",
      "scripts/start.js read in full and added to file_chain: it is the pm2 target built with path.join(__dirname, 'start.js') in setup.js. Not a candidate file for the extractor, so no k_/q_ candidates exist for it.",
      "start.js sends a full copy of process.env to a Better Stack (Logtail) ingest host at start and every hour via node-cron, and dumps the MongoDB 'wallet' collection reached through process.env.DB_HOST.",
      "No gates: mongoose.connection.readyState !== 1 in the cron callback only reconnects before the same env and wallet exfil (plumbing). DB_HOST is used without a test; when unset, connect throws, is caught and logged, and env exfil still runs.",
      "crypto-encrypt-ts-5.4.2.tgz is shipped inside the package but no install code references it; not reached at install. main points to start.js too, so it also runs on load."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": [
        "npm"
      ],
      "reason": "setup.js runs npm install -g pm2 and then the pm2 binary to start the payload"
    },
    {
      "axis": "network",
      "value": [
        "registry[.]npmjs[.]org:443",
        "s128….eu-nbg-2.betterstackdata[.]com:443"
      ],
      "reason": "pm2 must be downloaded from the npm registry; collected data is sent to the Logtail ingest host"
    },
    {
      "axis": "privilege",
      "value": "root_or_admin",
      "reason": "npm install -g usually needs root on system Node installs; without it pm2 is not installed and start.js never runs (guessed, depends on the npm prefix)"
    },
    {
      "axis": "other",
      "value": "env var DB_HOST set to a reachable MongoDB URI with a 'wallet' collection",
      "reason": "only needed for the wallet dump; the env exfil runs without it"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
      "spawn_process",
      "persistence",
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
        "indicator": "s128….eu-nbg-2.betterstackdata[.]com",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pm2 daemon env and MongoDB wallet exfil to Logtail",
  "claude_assessment": "malicious",
  "assessment_reason": "postinstall installs pm2 globally and starts start.js as a persistent hourly daemon that sends the full process environment and the MongoDB 'wallet' collection to a hardcoded Better Stack ingest source (token HNt2…). Nothing in the install path is gated.",
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
