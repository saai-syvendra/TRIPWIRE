# npm @cheqplease/structured-logger@2.2.5

**Source:** datadog · **Source label:** malicious · **Released:** 2025-12-10 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node preinstall-hook.js` on every registry install. The script opens a TCP socket to port 8080 on an ngrok host and, once connected, sends a banner with hostname, username, platform, cwd and Node version, then spawns an interactive shell piped to the socket. There is no install-time gate. The `os.platform() === 'win32'` ternary inside that callback only picks `cmd.exe` or `/bin/bash -i` for the same reverse shell, which is plumbing, so it is dropped. Separately, and also ungated, it writes hostname and username to `./preinstall-evidence.log` inside an empty catch.

## Execution

- **preinstall** `node preinstall-hook.js`: runs preinstall-hook.js; direct_script; errors hidden.

## Gates

None.

## Requirements

- network: e437eec1aae5[.]ngrok-free[.]app:8080 (reverse shell socket target; the code passes the full https URL as the host, which will not resolve as written)
- installed_tool: bash (the reverse shell spawns /bin/bash -i on non-Windows hosts (cmd.exe on Windows))

## Behaviour

- Ungated: recon, exfil, write_file, reverse_shell
- Gated: none

## Notes

- The socket host argument is the full string `hxxps://e437eec1aae5[.]ngrok-free[.]app`, not a bare hostname, so the DNS lookup should fail and the connect callback (banner and shell) should not run as written. The behaviours are still recorded as what the hook attempts; the working connection is a requirement, not a gate.
- The ngrok endpoint is long dead in any case.
- `index.js` (main) carries a load-time variant (recon, HTTP GET exfil, reverse shell gated on `NODE_ENV`), out of install scope.
- The console text calls it an "authorized security test"; that does not change the labels.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@cheqplease/structured-logger",
    "version": "2.2.5",
    "archive_sha256": "3d7a73d851699f7bf5a1205d5a5add6da617cedfe713d4d246b74cdba7aa66ff",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-12-10",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-12-10-@cheqplease_structured-logger-v2.2.5.zip",
    "package_root": "layer0/tmp/tmpl9u7tsl9/@cheqplease-structured-logger/package",
    "cluster_key": "0d096126b55d0ae2f6198600b75e1dbd4c1286a23e2a426e4ff980138905c32e",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node preinstall-hook.js",
        "runs_on": "always",
        "file_chain": [
          "preinstall-hook.js"
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
      "preinstall-hook.js: package code, 69 lines, read in full; nothing bundled or unread.",
      "The socket is opened with net.Socket().connect(8080, host) where host is the full URL string 'hxxps://e437eec1aae5[.]ngrok-free[.]app'. A DNS lookup of that string fails, so as written the connect callback (banner exfil and the os-gated shell spawn) should not fire.",
      "The os.platform() === 'win32' ternary in the connect callback only picks cmd.exe or /bin/bash -i for the same reverse shell; that is shell-choice plumbing, so it is dropped and the package has no install-time gate. The successful connection is a prerequisite, recorded under requirements.",
      "The evidence log write (hostname and username to ./preinstall-evidence.log) runs at top level regardless of the connection, inside an empty catch.",
      "index.js (main) holds a second recon, HTTP exfil and reverse shell variant, but it only runs when the package is loaded, not at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "e437eec1aae5[.]ngrok-free[.]app:8080",
      "reason": "reverse shell socket target; the code passes the full https URL as the host, which will not resolve as written"
    },
    {
      "axis": "installed_tool",
      "value": "bash",
      "reason": "the reverse shell spawns /bin/bash -i on non-Windows hosts (cmd.exe on Windows)"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil",
      "write_file",
      "reverse_shell"
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
        "indicator": "hxxps://e437eec1aae5[.]ngrok-free[.]app",
        "role": "reverse_shell"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "ngrok reverse-shell preinstall PoC",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook tries to open a raw TCP reverse shell (cmd.exe or bash piped to a socket) to an ngrok host and sends hostname, username, platform and cwd, and writes hostname and username to a local log. The host is passed as a full URL, so the connection likely fails as written, but the intent is a remote shell on the installing machine.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "b185339e299f4ee0"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 0
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_f6bea5bfc3",
        "reason_code": "other",
        "note": "os.platform() === 'win32' only picks the shell executable (cmd.exe or /bin/bash -i) for the same reverse shell; shell choice is plumbing, not a gate",
        "anchor": {
          "file": "preinstall-hook.js",
          "derived_from": null,
          "start_byte": 1377,
          "end_byte": 1402,
          "node_type": "binary_expression",
          "sha256": "18dbb67b2b60a326",
          "line": 34
        }
      },
      {
        "candidate": "q_b471e690fd",
        "reason_code": "other",
        "note": "ternary choosing spawn('cmd.exe') or spawn('/bin/bash', ['-i']); both arms run the same reverse shell piped to the socket, so it is plumbing, not a gate",
        "anchor": {
          "file": "preinstall-hook.js",
          "derived_from": null,
          "start_byte": 1377,
          "end_byte": 1478,
          "node_type": "ternary_expression",
          "sha256": "164f2fc2c4a4c9b9",
          "line": 34
        }
      },
      {
        "candidate": "k_99dccb102f",
        "reason_code": "not_environmental",
        "note": "require('fs') of a Node builtin inside a try; always succeeds, the try only swallows write errors",
        "anchor": {
          "file": "preinstall-hook.js",
          "derived_from": null,
          "start_byte": 2140,
          "end_byte": 2153,
          "node_type": "call_expression",
          "sha256": "b110746fdd7b8851",
          "line": 63
        }
      },
      {
        "candidate": "q_0e1342d7e2",
        "reason_code": "not_environmental",
        "note": "try around the evidence log write is error swallowing, not a check; recorded as silent_failure",
        "anchor": {
          "file": "preinstall-hook.js",
          "derived_from": null,
          "start_byte": 2129,
          "end_byte": 2401,
          "node_type": "try_statement",
          "sha256": "d8af991f3a765da0",
          "line": 62
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 4,
    "conditions_in_set": 0,
    "conditions_out_of_set": 0,
    "guard_candidates": 2,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
