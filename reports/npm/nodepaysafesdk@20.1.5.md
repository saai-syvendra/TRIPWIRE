# npm nodepaysafesdk@20.1.5

**Source:** datadog · **Source label:** malicious · **Released:** 2024-11-21 (registry) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`, which passes one shell command to `child_process.exec`. The command uses curl to POST to fixing[.]my, putting `whoami` and `hostname` in the URL path and base64 of /etc/passwd, /etc/hosts and `id` output in the User-Agent header. That recon and exfil has no gate. The only gate is the shell test `[ -r /etc/shadow ]`: when the install user can read the shadow file (normally root), its hashed-password lines are added to the exfiltrated data. Otherwise a placeholder string is sent instead.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script, inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: privilege exists) | then | 1 | cred_read | os=linux; privilege=root_or_admin; file_present=/etc/shadow |

Gate intent: g1 activate/enables/data_availability

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- network: fixing[.]my:80 (curl POST to the exfil host (no scheme given, so plain http))
- installed_tool: sh, curl, base64, tr, grep, id, whoami, hostname (the exfil command line uses these)
- os: linux (POSIX shell syntax and /etc paths; on Windows exec uses cmd.exe and the command fails)
- file_present: /etc/passwd, /etc/hosts (read unconditionally; a missing file breaks the && chain before id and the shadow read)

## Behaviour

- Ungated: recon, exfil
- Gated: cred_read

## Notes

- The name, the inflated version 20.1.5, the "Nodejs SDK for Paysafe" description and the self-dependency on `nodepaysafesdk ^1.0.2` point to dependency confusion.
- The gate sits inside a JS template string, so its anchors cover the whole string fragment on line 5. The exec call on line 9 runs unconditionally, outside that region, and only launches the string, so the payload stops at a bind hop on `command` and is marked unresolved.
- Failures are only logged and curl runs silently, so the install succeeds even without network access.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "nodepaysafesdk",
    "version": "20.1.5",
    "archive_sha256": "f5052c7e65490cce243746e661ee2bda95ad69ceec059de93f77d8bebe4100fa",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2024-11-21",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/malicious_intent/2024-11-21-nodepaysafesdk-v20.1.5.zip",
    "package_root": "layer0/tmp/tmpjk5d7n5n/nodepaysafesdk/package",
    "cluster_key": "adfb18c88b60e85fd657f1df7fa45288e5998685e86341870bdb60ca7719baf5",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node index.js",
        "runs_on": "always",
        "file_chain": [
          "index.js"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "inline_shell"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "index.js: read in full (19 lines). It runs one shell command via child_process.exec: curl POSTs whoami and hostname in the URL path and base64 of /etc/passwd, /etc/hosts, id output and (if readable) /etc/shadow in the User-Agent header.",
      "Errors are only logged in the exec callback and curl runs with -s -o /dev/null, so a failed exfil never fails the install (silent_failure).",
      "The only gate is the shell test [ -r /etc/shadow ] inside the command string. A JS anchor cannot be narrower than the string fragment holding it, so the site, guard and region share one anchor.",
      "grep -v drops shadow lines containing * or ! (locked accounts), keeping hashed passwords. The else side only echoes 'No shadow access' into the same exfil, so it is not recorded as a branch.",
      "The gate's then side is only the cat /etc/shadow read (cred_read); the curl exfil runs whether or not the test passes, so it is ungated.",
      "The exec call on line 9 runs unconditionally and sits outside the region. The guarded cat runs in the shell exec starts, reached through the command variable; no hop models that, so the payload is unresolved.",
      "package.json depends on nodepaysafesdk ^1.0.2 (its own name); dependency tree, not followed."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "fixing[.]my:80",
      "reason": "curl POST to the exfil host (no scheme given, so plain http)"
    },
    {
      "axis": "installed_tool",
      "value": [
        "sh",
        "curl",
        "base64",
        "tr",
        "grep",
        "id",
        "whoami",
        "hostname"
      ],
      "reason": "the exfil command line uses these"
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "POSIX shell syntax and /etc paths; on Windows exec uses cmd.exe and the command fails"
    },
    {
      "axis": "file_present",
      "value": [
        "/etc/passwd",
        "/etc/hosts"
      ],
      "reason": "read unconditionally; a missing file breaks the && chain before id and the shadow read"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "privilege",
      "api": "test -r",
      "operator": "exists",
      "value": null,
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 123,
            "end_byte": 262,
            "node_type": "string_fragment",
            "sha256": "0404e1e090c16592",
            "line": 5
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "test -r",
        "target": "/etc/shadow",
        "accessor": "other"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "preinstall",
      "expression": "c1",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 123,
            "end_byte": 262,
            "node_type": "string_fragment",
            "sha256": "0404e1e090c16592",
            "line": 5
          },
          "kind": "other",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "shadow password hashes are only read when the install user can read /etc/shadow (normally root); the exfil of the collected data runs either way",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "privilege": "root_or_admin",
          "file_present": [
            "/etc/shadow"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "index.js",
            "derived_from": null,
            "start_byte": 123,
            "end_byte": 262,
            "node_type": "string_fragment",
            "sha256": "0404e1e090c16592",
            "line": 5
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "exec",
            "sink": {
              "file": "index.js",
              "derived_from": null,
              "start_byte": 320,
              "end_byte": 520,
              "node_type": "call_expression",
              "sha256": "ec0ed0c3d78d435f",
              "line": 9
            },
            "witness": [
              {
                "hop": "bind",
                "anchor": {
                  "file": "index.js",
                  "derived_from": null,
                  "start_byte": 50,
                  "end_byte": 317,
                  "node_type": "variable_declarator",
                  "sha256": "1b0b9163750f0655",
                  "line": 3
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil"
    ],
    "gated": [
      "cred_read"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "exfiltrated data base64 encoded with newlines replaced by dots and sent in the User-Agent header"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "fixing[.]my/paysafesdk/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook runs a shell command that sends the username, hostname, /etc/passwd, /etc/hosts, id output and, when readable, /etc/shadow hashes to fixing[.]my. It does nothing else.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "the gate condition is a shell test inside a JS string; site, guard and region anchors are the whole string fragment. The exec sink on line 9 sits outside that region and only launches the string, so the payload path is marked unresolved after a bind hop on the command variable",
    "out-of-set claim pending verification",
    "payload path not fully traced"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
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
    "conditions_out_of_set": 1,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
