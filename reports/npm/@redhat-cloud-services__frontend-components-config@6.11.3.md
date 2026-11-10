# npm @redhat-cloud-services/frontend-components-config@6.11.3

**Source:** datadog · **Source label:** malicious · **Released:** 2026-06-01 (registry) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

The `preinstall` hook runs `node index.js`, a one-line wrapper that evals a char-code array put through a Caesar shift. The decoded wrapper decrypts two AES-128-GCM stages with keys sitting in the code: a small Bun installer and a 634 KB main stage. It writes the main stage to `/tmp`, downloads Bun v1.3.13 from the official GitHub releases with curl and unzip (unless it is already running under Bun), runs the stage with `bun run` during the install, then deletes the temp file. The readable layers have no gates; the `typeof Bun` branch only decides how Bun is found. The main stage is obfuscator.io code that was not deobfuscated, so its gates are unknown.

## Execution

- **preinstall** `node index.js`: runs index.js; direct_script, decoded_eval, download_then_exec; errors hidden.

## Gates

None.

## Requirements

- network: github[.]com:443 (Bun runtime downloaded from GitHub releases when the install is not already running under Bun)
- installed_tool: curl, unzip (getBunPath shells out to curl and unzip to fetch and unpack Bun)
- os: linux (the platform lookup is buggy and always fetches the linux build of Bun, so the stage only launches on Linux unless Bun is already the runtime)
- arch: x64 (the arch lookup is buggy and always fetches the x64 build of Bun)

## Behaviour

- Ungated: write_file, download, exec_downloaded, spawn_process, delete_file
- Gated: none

## Notes

- Decoding chain: d1 (char codes + Caesar shift n=10, candidate decoder `charcode_caesar_eval`), then d2 and d3 (AES-128-GCM, candidate decoder `aesgcm_hex_stage`). Both decoders are under `scratch/<key>/decoders/` and need review.
- The stock obfuscator.io recovery (`obfio_objprop`) failed on d3. That stage is unread and listed in `obfuscation.unrecovered`. The plain code there reads cloud, Vault and GitHub secret variables and defines GitHub API helpers, which points to credential theft, but this is not confirmed.
- `getBunPath` passes the `os.platform`/`os.arch` functions where it means their results, so it always fetches the linux-x64 build. On any other host that lacks Bun, the stage launch fails silently.
- Phase 2 needs network access to github[.]com plus curl and unzip for the stage to run at all.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "npm",
    "name": "@redhat-cloud-services/frontend-components-config",
    "version": "6.11.3",
    "archive_sha256": "628abc31e7ed7ecee53924cb6ba6d7173291357136a24a5cf50fd0427fd13b23",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2026-06-01",
    "released_at_source": "registry",
    "sample_path": "datadog/npm/compromised_lib/2026-06-01-@redhat-cloud-services_frontend-components-config-v6.11.3.zip",
    "package_root": "layer0/tmp/tmppy996tfl/@redhat-cloud-services-frontend-components-config/package",
    "cluster_key": "b61a1388ee4c54f915654c4ea8621f3977fb91f65f2859f6d9262a5255e2be9e",
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
          "decoded_eval",
          "download_then_exec"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "bin commands not analysed (run only when invoked): fec",
      "index.js layer 1: eval of a char-code array put through a Caesar shift (n=10); decoded with candidate decoder charcode_caesar_eval (d1). Wrapper read in full.",
      "d1 decrypts two AES-128-GCM stages with literal key/iv/tag (candidate decoder aesgcm_hex_stage): _b (d2, Bun installer, read in full) and _p (d3, 634 KB main stage).",
      "d1 writes _p to /tmp/p<random>.js and runs it with execSync('bun run ...', stdio inherit), so the stage runs synchronously during preinstall; the temp file is deleted afterwards.",
      "typeof Bun !== 'undefined' in d1 only picks how Bun is found (already running under Bun vs download Bun first); both sides run the same stage, so it is runtime-locating plumbing, not a gate.",
      "d2 getBunPath downloads bun-v1.3.13 from the official oven-sh GitHub releases with curl, unzips it into a mkdtemp folder and chmods it. The existsSync reuse check can never hit (fresh mkdtemp dir).",
      "d2 compares the os.arch and os.platform functions themselves (not their results) with strings, so it always fetches the linux-x64 build; on other hosts without Bun the stage launch fails (caught).",
      "d3 (decrypted _p): obfuscator.io output with a base64 string table indexed through const-object properties; tool recovery (obfio_objprop) failed, not decoded further. Left unread, in obfuscation.unrecovered.",
      "d3 plain code (not decoded) reads env names such as GITHUB_REPOSITORY, ARM_CLIENT_SECRET, VAULT_TOKEN, GOOGLE_APPLICATION_CREDENTIALS and defines githubFetch helpers: points to cloud and CI secret theft, not confirmed.",
      "No conditions or gates recorded because the main stage is unread; this is not evidence of no gate."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "github[.]com:443",
      "reason": "Bun runtime downloaded from GitHub releases when the install is not already running under Bun",
      "sites": [
        {
          "file": "index.js",
          "derived_from": "d2",
          "start_byte": 718,
          "end_byte": 777,
          "node_type": "call_expression",
          "sha256": "cc1bd763ec84588b",
          "line": 17
        }
      ]
    },
    {
      "axis": "installed_tool",
      "value": [
        "curl",
        "unzip"
      ],
      "reason": "getBunPath shells out to curl and unzip to fetch and unpack Bun",
      "sites": [
        {
          "file": "index.js",
          "derived_from": "d2",
          "start_byte": 718,
          "end_byte": 777,
          "node_type": "call_expression",
          "sha256": "cc1bd763ec84588b",
          "line": 17
        },
        {
          "file": "index.js",
          "derived_from": "d2",
          "start_byte": 780,
          "end_byte": 841,
          "node_type": "call_expression",
          "sha256": "cf791915a9df625e",
          "line": 18
        }
      ]
    },
    {
      "axis": "os",
      "value": "linux",
      "reason": "the platform lookup is buggy and always fetches the linux build of Bun, so the stage only launches on Linux unless Bun is already the runtime"
    },
    {
      "axis": "arch",
      "value": "x64",
      "reason": "the arch lookup is buggy and always fetches the x64 build of Bun"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "write_file",
      "download",
      "exec_downloaded",
      "spawn_process",
      "delete_file"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "dynamic_eval",
      "very_long_lines",
      "char-code array with Caesar shift",
      "AES-128-GCM encrypted stages with inline keys",
      "obfuscator.io string table (inner stage)"
    ],
    "decoded": true,
    "unrecovered": [
      {
        "file": "index.js",
        "reason": "inner stage d3 (AES-decrypted _p, 634 KB) is obfuscator.io code whose string table the tool could not recover; its conditions, gates and behaviours are not read"
      }
    ]
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://github[.]com/oven-sh/bun/releases/download/bun-v1.3.13/",
        "role": "second_stage"
      }
    ]
  },
  "attack_type": "compromised_maintainer",
  "family_hint": "bun-loader credential stealer",
  "claude_assessment": "malicious",
  "assessment_reason": "The preinstall hook decodes two layers (Caesar-shifted char codes, then AES-GCM), downloads the Bun runtime and runs a heavily obfuscated 634 KB stage at install. That stage references cloud, Vault and GitHub secret variables; its gates were not recovered.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": true,
  "review_reasons": [
    "inner stage d3 not deobfuscated: gates and behaviours of the main payload are unknown",
    "two candidate decoders (charcode_caesar_eval, aesgcm_hex_stage) need review before they join tools/common/decoders",
    "unrecovered code"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": null
        },
        "params": {
          "decoder": "charcode_caesar_eval",
          "lang": "js"
        },
        "output_sha256": "8b22863f8203c13d"
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d1"
        },
        "params": {
          "fn": "_d",
          "var": "_b",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "ac2a2208e1726e00"
      },
      {
        "id": "d3",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "index.js",
          "derived_from": "d1"
        },
        "params": {
          "fn": "_d",
          "var": "_p",
          "decoder": "aesgcm_hex_stage",
          "lang": "js"
        },
        "output_sha256": "0dc06ecdaa63fe24"
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
