# pypi aiohttp_sock@0.1.20

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`aiohttp_sock` typosquats the `aiohttp-proxy` project (same name, author and metadata) and hides a Windows infostealer in its `setup.py`, which runs at install. After a `sys.version_info >= (3, 5, 3)` floor check (g1), and when invoked for an install/bdist build, the script shells out to pip to install `aiofiles`, `aiohttp`, `cryptography` and `aiosqlite`, then unpacks a stickytape-bundled stealer (modules embedded as byte-string literals written to a `tempfile.mkdtemp()` dir, added to `sys.path`, imported, and run via `asyncio.run(main())`). The stealer collects browser passwords and cookies, crypto wallets (MetaMask, Phantom, Exodus), FileZilla and Telegram data, zips them, and POSTs the archive plus recon details to a hardcoded HTTP C2. The only real environment gate is the Python version floor; the payload is Windows-only by construction (reads `USERPROFILE`/`LOCALAPPDATA`, uses `ctypes.windll` DPAPI), recorded as an `os=win32` requirement rather than a deliberate gate.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: runtime_version >= [3, 5, 3]) | then | 1 | download, spawn_process, recon, cred_read, write_file, exfil | runtime_version=3.5.3 |

Gate intent: g1 activate/enables/portability

Grounding: 1 of 1 conditions and 1 of 1 gates from the candidate set.

## Requirements

- os: win32 (Stealer reads USERPROFILE/LOCALAPPDATA env vars and Windows browser, wallet, FileZilla and Telegram paths and uses ctypes.windll DPAPI; importing path_search on another OS raises KeyError and aborts.)
- network: 144[.]24[.]115[.]170:80 (Exfiltrates recon details (/receive_details) and a zip of stolen data (/receive_log) to the hardcoded HTTP C2.)
- installed_tool: pip (Payload shells out to `{sys.executable} -m pip install` to fetch aiofiles, aiohttp, cryptography and aiosqlite before stealing.)

## Behaviour

- Ungated: none
- Gated: download, spawn_process, recon, cred_read, write_file, exfil

## Notes

- Only one gate kept: g1, the `sys.version_info >= (3, 5, 3)` early-exit floor (category `runtime_version`). It may be inherited from the upstream aiohttp/aiohttp-proxy project, but the original source was not available to compare, so `inherited` was left off.
- The prefilled c2/g2 (`os.path.exists` at line 75) was dropped as `not_environmental`: it is stickytape's `make_package` helper doing idempotent directory creation on a path it just built under `mkdtemp()`; both arms end with the bundled module written, so it is plumbing, not a gate. The guard candidate `q_b9fb603138` was dropped with it.
- The `if ... "install" == sys.argv[1] or "bdist" in sys.argv[1]` check gates the malicious block but is build-command detection (fires on a normal pip wheel build / `setup.py install`), not an environment axis, so it is noted rather than recorded as a gate; `runs_on` stays `always`.
- Coverage: `setup.py` read in full, including every stickytape string-literal module (path_search, tools, config, logger, paths, plugins/*). Nothing unread. The cred_read/recon/exfil sinks sit inside those string literals and are not AST call nodes, so the anchored payload uses the real `setup.py` code (the pip `subprocess.call` and the aiohttp session/`session.post` in `main()`).
- C2: `hxxp://144[.]24[.]115[.]170` (`/receive_details`, `/receive_log`). Russian-language log strings suggest a Russian-speaking operator; no clear public campaign name, so `family_hint` is null.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "aiohttp_sock",
    "version": "0.1.20",
    "archive_sha256": "0dae61137382fa4adb9a710da4fe27fd3008df53c638bb8e20bf2eb57b1bdda4",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/aiohttp_sock-0.1.20.tar.gz",
    "package_root": "layer0/aiohttp_sock-0.1.20",
    "cluster_key": "fa754c56045d7461d1e288faa4da6f6b5a3d685e9562b2bd66a57d0a244d42ef",
    "analysis_type": "ai",
    "model_name": "claude-opus-4-8"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "setup_py",
        "command": "python setup.py (pip install from sdist)",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py reads __version__ from aiohttp_sock/__init__.py (build plumbing), then runs the version-floor check (g1).",
      "Malicious block further guarded by `if \"install\"==sys.argv[1] or \"bdist\" in sys.argv[1]`: build-command detection firing on a normal pip wheel build or `setup.py install`, not an environment axis, so runs_on stays always.",
      "Coverage: setup.py read in full, including the stickytape string-literal modules written to a tempfile.mkdtemp() dir (lines 66-108), added to sys.path and run via asyncio.run(main()) (109-194). Nothing unread.",
      "Embedded modules read in full: path_search, tools, config, logger, paths, plugins/* (browsers/chromium+decrypt, wallets/exodus, filezilla, telegram, details).",
      "Windows-only by construction: path_search.py/paths.py read os.environ['USERPROFILE'] at import; decrypt.py uses ctypes.windll DPAPI and LOCALAPPDATA. On non-Windows the path_search import raises KeyError and aborts. Recorded as os=win32 requirement, no platform test.",
      "silent_failure: subprocess.call pip exit codes discarded; main() wraps each stealer task in try/except that only logs, hiding install-time failures.",
      "cred_read/recon/exfil sinks sit inside stickytape string literals (not AST nodes); anchored payload uses real setup.py code (pip subprocess.call and the aiohttp session.post in main()).",
      "c1 version floor may be inherited from upstream aiohttp-proxy/aiohttp, but the original source was not available to compare, so inherited was left off."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "Stealer reads USERPROFILE/LOCALAPPDATA env vars and Windows browser, wallet, FileZilla and Telegram paths and uses ctypes.windll DPAPI; importing path_search on another OS raises KeyError and aborts."
    },
    {
      "axis": "network",
      "value": [
        "144[.]24[.]115[.]170:80"
      ],
      "reason": "Exfiltrates recon details (/receive_details) and a zip of stolen data (/receive_log) to the hardcoded HTTP C2."
    },
    {
      "axis": "installed_tool",
      "value": "pip",
      "reason": "Payload shells out to `{sys.executable} -m pip install` to fetch aiofiles, aiohttp, cryptography and aiosqlite before stealing."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "runtime_version",
      "api": "sys.version_info",
      "operator": ">=",
      "value": [
        3,
        5,
        3
      ],
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_d29d84acdf",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 508,
            "end_byte": 536,
            "node_type": "comparison_operator",
            "sha256": "1b2f7dda8e05b788",
            "line": 28
          }
        }
      ],
      "provenance": "in_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_504d98e87f",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 505,
            "end_byte": 599,
            "node_type": "if_statement",
            "sha256": "6cad8b6f26c635ff",
            "line": 28
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
      "purpose": "portability",
      "purpose_reason": "Aborts with RuntimeError on Python older than 3.5.3; the async/f-string stealer payload only runs on a new enough interpreter.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "download",
          "spawn_process",
          "recon",
          "cred_read",
          "write_file",
          "exfil"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 601,
            "end_byte": 41100,
            "node_type": "stmt_range",
            "sha256": "9f8d719f4347df73",
            "line": 31
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 1267,
              "end_byte": 1327,
              "node_type": "call",
              "sha256": "575e1448db9d5c03",
              "line": 50
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 40845,
              "end_byte": 40926,
              "node_type": "call",
              "sha256": "a8937851098f8033",
              "line": 188
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 41093,
                  "end_byte": 41099,
                  "node_type": "call",
                  "sha256": "ea1a0f9102305e02",
                  "line": 194
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 38916,
                  "end_byte": 41063,
                  "node_type": "function_definition",
                  "sha256": "8a25f338e3789b7a",
                  "line": 133
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
      "download",
      "spawn_process",
      "recon",
      "cred_read",
      "write_file",
      "exfil"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "escaped strings",
      "very long lines",
      "entire stealer bundled by stickytape as byte-string literal modules written to a temp dir and imported at runtime"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://144[.]24[.]115[.]170",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "typosquat",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "The install-time setup.py, behind only a Python version floor, pip-installs runtime dependencies then unpacks and runs a stickytape-bundled Windows infostealer that collects browser passwords and cookies, crypto wallets (MetaMask, Phantom, Exodus), FileZilla and Telegram data, zips them and POSTs them to a hardcoded HTTP C2. The package impersonates the aiohttp-proxy project by copying its name, author and metadata.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "34bdc8d51f6cd21e"
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
        "candidate": "k_f26f200a5a",
        "reason_code": "not_environmental",
        "note": "os.path.exists inside stickytape's make_package on a path it just built under tempfile.mkdtemp(); idempotent dir creation, both arms end with the module written.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2253,
          "end_byte": 2281,
          "node_type": "call",
          "sha256": "a3b8d15777205fbb",
          "line": 75
        }
      },
      {
        "candidate": "q_b9fb603138",
        "reason_code": "not_environmental",
        "note": "Guard of the same stickytape make_package os.path.exists plumbing (g2), not an environment gate.",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2246,
          "end_byte": 2461,
          "node_type": "if_statement",
          "sha256": "49a8486a1f727951",
          "line": 75
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 2,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 2,
    "conditions_in_set": 1,
    "conditions_out_of_set": 0,
    "guard_candidates": 2,
    "gates_in_set": 1,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
