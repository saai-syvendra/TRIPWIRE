# npm @squawk/airspace-data@0.5.3

**Source:** datadog · **Source label:** malicious · **Released:** 2026-05-11 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

Version 0.5.3 of this GeoJSON data package adds a `preinstall` hook, `node setup.mjs`. The script downloads the Bun runtime zip for the host platform from GitHub releases, extracts it to a temp dir (with unzip, PowerShell or its own ZIP reader) and runs Bun on `tanstack_runner.js` in the package root. There is one gate. If a `bun` binary already answers `--version`, `main()` returns and nothing runs, so the VM must not have Bun installed. The runner script is missing from this archive, so at install Bun is only fetched and started, and then the install fails.

## Execution

- **preinstall** `node setup.mjs`: runs setup.mjs; direct_script, download_then_exec; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | preinstall | c1 (c1: installed_tool not_exists) | then | 1 | download, write_file, spawn_process, exec_downloaded | (none) |

Gate intent: g1 activate/enables/unclear

Grounding: 0 of 1 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, g1.

## Requirements

- network: github[.]com:443 (Bun release zip is fetched from GitHub releases (redirects followed, likely to GitHub's release asset host).)
- os: linux, darwin or win32 (ra() throws for platforms without a Bun build in its map.)
- arch: x64 or arm64 (ra() throws for other architectures.)
- file_present: <package root>/tanstack_runner.js (The script Bun is told to run; absent from this archive, so the final stage cannot run.)

## Behaviour

- Ungated: none
- Gated: download, write_file, spawn_process, exec_downloaded

## Notes

- Platform, arch, musl and win32 checks only pick the Bun build, the file name, chmod and the extraction method. They are recorded as plumbing, and unsupported platform/arch is recorded as a requirement.
- `router_init.js` (2.3 MB) ships in the package, but nothing references it. It may be the intended runner under another name. It is not install-reached and was not analysed, so a reviewer should look at it alongside other versions in this campaign.
- The gate condition and guard are out of set because the extractor did not propose the `hc("bun")` early exit.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@squawk/airspace-data",
    "version": "0.5.3",
    "archive_sha256": "ee3030df5a6bc5652135a04f54d2be035713da222c979ccbf223553eedcfec0f",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-05-11",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-05-11-@squawk_airspace-data-v0.5.3.zip",
    "package_root": "layer0/tmp/tmpmcksviqe/@squawk-airspace-data/package",
    "cluster_key": "7247925580e6a7ab7d82b2fa0701864c4bb405999b43baccc4abc8850a1a3027",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "preinstall",
        "command": "node setup.mjs",
        "runs_on": "always",
        "file_chain": [
          "setup.mjs"
        ],
        "interpreter": "node",
        "launch_style": [
          "direct_script",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.mjs: read in full (205 lines, plain code, no bundled libraries); nothing unread.",
      "setup.mjs downloads the Bun runtime for the host platform from GitHub releases, extracts it to a temp dir and runs it on <package>/tanstack_runner.js. That file is not in this archive, so Bun starts and fails; main() rejects and exits 1.",
      "router_init.js (2.3 MB) is in the package but is not named by setup.mjs, package.json or dist/; the install never reaches it, so it was not analysed. It may be the intended runner shipped under another name.",
      "Not gates (plumbing): the platform/arch map picking the Bun build, the musl check (ldd --version, /etc/os-release), the win32 checks for the binary name, chmod and PowerShell Expand-Archive, and the unzip / PowerShell / built-in ZIP fallback chain.",
      "ra() throws for platform/arch pairs outside linux, darwin, win32 x x64, arm64; that ends the install with no download. Recorded as os/arch requirements, since it only aborts when no Bun build exists.",
      "g1 recipe is empty because the recipe keys cannot say 'tool absent': the VM must NOT have a bun binary on PATH, or main() returns before downloading anything.",
      "silent_failure: hc() swallows probe errors and the musl probes ignore failures; the final error is printed and exits 1, which fails the npm install. The temp dir is removed in a finally block."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "Bun release zip is fetched from GitHub releases (redirects followed, likely to GitHub's release asset host)."
    },
    {
      "axis": "os",
      "value": "linux, darwin or win32",
      "reason": "ra() throws for platforms without a Bun build in its map."
    },
    {
      "axis": "arch",
      "value": "x64 or arm64",
      "reason": "ra() throws for other architectures."
    },
    {
      "axis": "file_present",
      "value": "<package root>/tanstack_runner.js",
      "reason": "The script Bun is told to run; absent from this archive, so the final stage cannot run."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "installed_tool",
      "api": "child_process.execFileSync",
      "operator": "not_exists",
      "value": null,
      "value_recovered": "plain",
      "probe": {
        "kind": "exec",
        "callee": "child_process.execFileSync",
        "target": "bun --version",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 2041,
            "end_byte": 2080,
            "node_type": "call_expression",
            "sha256": "8b9ca327dfd2af56",
            "line": 77
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
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
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 4383,
            "end_byte": 4405,
            "node_type": "if_statement",
            "sha256": "25be2457dd55fd48",
            "line": 177
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "main() returns without doing anything when a bun binary already answers --version; the code never uses the existing bun, so the reason is not clear.",
      "then": {
        "behaviours": [
          "download",
          "write_file",
          "spawn_process",
          "exec_downloaded"
        ],
        "env_recipe": {},
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.mjs",
            "derived_from": null,
            "start_byte": 4409,
            "end_byte": 5002,
            "node_type": "stmt_range",
            "sha256": "ab7e9d2a16caf0a7",
            "line": 179
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "network",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 1236,
              "end_byte": 1889,
              "node_type": "call_expression",
              "sha256": "70b75f4569baa33a",
              "line": 48
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 4772,
                  "end_byte": 4781,
                  "node_type": "call_expression",
                  "sha256": "0090003b4a1cb2cc",
                  "line": 190
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 1160,
                  "end_byte": 1991,
                  "node_type": "function_declaration",
                  "sha256": "32d6065e8c400923",
                  "line": 46
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 1708,
              "end_byte": 1731,
              "node_type": "call_expression",
              "sha256": "4583effa38649232",
              "line": 62
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 4772,
                  "end_byte": 4781,
                  "node_type": "call_expression",
                  "sha256": "0090003b4a1cb2cc",
                  "line": 190
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 1160,
                  "end_byte": 1991,
                  "node_type": "function_declaration",
                  "sha256": "32d6065e8c400923",
                  "line": 46
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 3766,
              "end_byte": 3837,
              "node_type": "call_expression",
              "sha256": "15e71abc1801e588",
              "line": 150
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 4787,
                  "end_byte": 4811,
                  "node_type": "call_expression",
                  "sha256": "e0685f2806a6e000",
                  "line": 191
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.mjs",
                  "derived_from": null,
                  "start_byte": 3707,
                  "end_byte": 4355,
                  "node_type": "function_declaration",
                  "sha256": "859601a06dff949c",
                  "line": 148
                }
              }
            ]
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.mjs",
              "derived_from": null,
              "start_byte": 4878,
              "end_byte": 4930,
              "node_type": "call_expression",
              "sha256": "98161d8661d11056",
              "line": 195
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "download",
      "write_file",
      "spawn_process",
      "exec_downloaded"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "short single-letter identifiers in the dropper",
      "payload launched through a separately downloaded runtime (Bun) instead of node"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/oven-sh/bun/releases/download/bun-v$",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "A new preinstall hook added to a GeoJSON data package downloads the Bun runtime and runs a hidden runner script with it, which has no place in this package. The runner (tanstack_runner.js) is missing from this archive, so at install only Bun is fetched and started.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "The script setup.mjs launches (tanstack_runner.js) is absent from the archive; an unreferenced 2.3 MB router_init.js is present and may be the intended payload under another name. Not install-reached, not analysed.",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "abd357484d4cdedf"
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
        "candidate": "k_fb8d4a4bec",
        "reason_code": "other",
        "note": "Plumbing: process.platform == win32 only picks the binary name (bun.exe vs bun) and whether chmod runs; same behaviour on both sides.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 4437,
          "end_byte": 4465,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 180
        }
      },
      {
        "candidate": "k_ee268cee48",
        "reason_code": "other",
        "note": "Plumbing: win32 check in xb() picks PowerShell Expand-Archive as the extraction method; the fallback extracts the same binary.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 3862,
          "end_byte": 3890,
          "node_type": "binary_expression",
          "sha256": "8c9d46e65809c31c",
          "line": 154
        }
      },
      {
        "candidate": "k_e3b45e7ecc",
        "reason_code": "other",
        "note": "Plumbing: /etc/os-release Alpine check picks the musl vs glibc Bun build to download.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 562,
          "end_byte": 604,
          "node_type": "call_expression",
          "sha256": "9abd9a2757f3770f",
          "line": 23
        }
      },
      {
        "candidate": "q_1b5207c68a",
        "reason_code": "other",
        "note": "Plumbing: ternary choosing the Bun binary file name.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 4480,
          "end_byte": 4501,
          "node_type": "ternary_expression",
          "sha256": "49ae461ccb17b857",
          "line": 181
        }
      },
      {
        "candidate": "q_e15f376488",
        "reason_code": "other",
        "note": "Plumbing: picks PowerShell extraction on Windows; otherwise the built-in ZIP reader extracts the same file.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 3858,
          "end_byte": 4334,
          "node_type": "if_statement",
          "sha256": "21cd95d62baeb77a",
          "line": 154
        }
      },
      {
        "candidate": "q_d3f8d1a986",
        "reason_code": "other",
        "note": "Plumbing: chmod 755 on the extracted binary only off Windows.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 4841,
          "end_byte": 4873,
          "node_type": "if_statement",
          "sha256": "f752801d93ccc3ef",
          "line": 194
        }
      },
      {
        "candidate": "q_ef8ef5748f",
        "reason_code": "other",
        "note": "Plumbing: try/catch around the os-release read in the musl check that picks the Bun build.",
        "anchor": {
          "file": "setup.mjs",
          "derived_from": null,
          "start_byte": 545,
          "end_byte": 658,
          "node_type": "try_statement",
          "sha256": "d45f61b6e3931117",
          "line": 22
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 3,
    "condition_sites_cited": 0,
    "guards_cited": 0,
    "candidates_dropped": 7,
    "conditions_in_set": 0,
    "conditions_out_of_set": 1,
    "guard_candidates": 4,
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
