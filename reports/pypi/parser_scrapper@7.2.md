# pypi parser_scrapper@7.2

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-4-8)

## Summary

`parser_scrapper` 7.2 is a PyPI sdist whose `setup.py` runs a malicious payload at install (setuptools runs `setup.py` for metadata/wheel build on a normal `pip install`). After the package metadata, trailing top-level code decodes and `exec`s one of two base64 blobs chosen by `os.name`: on Windows (`nt`) it writes an embedded PE executable to the temp dir and launches it with `os.startfile`; otherwise it runs a Python infostealer. The Linux stealer only proceeds when `platform()` contains `linux`, queries `ip-api.com` and bails out if the host ISP looks like Google or Mythic Beasts hosting (sandbox evasion), then steals browser/email/FileZilla/Pidgin/Telegram credentials and Electrum/Exodus wallets, grabs a screenshot, zips and RC4-encrypts the loot, and uploads it to a hard-coded Telegram bot. A whole-payload `if 'sdist' not in argv` wrapper keeps it from running when the author builds the sdist. This is unambiguous malware; the environment that opens the heavy payload is a Linux box on a non-hosting network.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval, dropped_binary.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: os == nt) | then | 1 | write_file, spawn_process | os=win32 |
| | |  | else | 1 | recon, cred_read, write_file, exfil, delete_file | os=linux |
| g2 | setup_py | c1 && c3 (c1: os == nt; c3: file_or_dir_exists not_exists %TEMP%/pee77a45c1d8776c05386cc5dcd6601a76c96fd.exe) | then | 2 | write_file, spawn_process | os=win32; file_absent=%TEMP%/pee77a45c1d8776c05386cc5dcd6601a76c96fd.exe |
| g3 | setup_py | c2 (c2: os includes linux) | then | 1 | recon | os=linux |
| g4 | setup_py | c2 && c4 && c5 (c2: os includes linux; c4: external_ip_geo not_includes google; c5: external_ip_geo not_includes mythic beasts) | then | 3 | cred_read, write_file, exfil, delete_file | os=linux |

Gate intent: g1 activate/selects/portability; g2 activate/enables/unclear; g3 activate/enables/targeting; g4 evade/enables/anti_analysis

Grounding: 1 of 5 conditions and 1 of 4 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, g2, g3, g4.

## Requirements

- network: api[.]telegram[.]org:443, ip-api[.]com:80 (Linux payload exfiltrates to the Telegram bot API and queries ip-api for the host ISP (ip-api falls back to 127[.]0[.]0[.]1 if unreachable).)
- other: urllib3 importable (else branch imports urllib3 at the top of the decoded exec; install_requires is empty, so urllib3 must already be present or the ImportError aborts the payload.)

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process, recon, cred_read, exfil, delete_file

## Notes

- `setup.py` was decoded with the `b64_exec` decoder registered as derivation `d2`; both per-OS `exec(b64decode(...))` stages were spliced in place and the resulting Python read in full. The dropped Windows PE is a compiled binary and is left unread (`obfuscation.unrecovered`).
- Gates: `g1` (os.name) selects Windows PE vs Linux Python; `g2` (`c1 && c3`) is the reinfection guard that only drops/runs the exe when it is absent from temp; `g3` (`c2`) restricts the non-Windows payload to actual Linux; `g4` (`c2 && c4 && c5`) is the ip-api ISP evade check, reached only after `g3`'s `exit(1)` at line 62.
- `g3` and `g4` physically sit inside `g1`'s else branch (`os.name != 'nt'`), which cannot be written in positive form, so their expressions leave out the non-Windows side of `c1`. `c2` (`platform()` contains `linux`) already implies `os.name` is not `nt`, so the recipes are complete; `min_conditions` does not count `g1`'s else side.
- `g4`'s ISP check lives in `m()`'s `try/else`: if the ip-api request fails, the evade check is skipped and the payload proceeds. Blocking ip-api does not trigger evasion.
- `c4`/`c5` are `external_ip_geo` (out of scope); the Telegram bot token is redacted and not stored. ip-api is listed only as a network requirement since none of the endpoint roles fit a geolocation lookup.
- `family_hint` `wsr-telegram-grabber` is from code artifacts (the `LWSR$` archive magic, `.wsr` upload extension, XML `<Commands>` grabber config), not from the author handle.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "parser_scrapper",
    "version": "7.2",
    "archive_sha256": "d5979f658d80ce7c4d91dfb2d60f11c49c12ae477cf81a0db59cf6103eb752dd",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/parser_scrapper-7.2.tar.gz",
    "package_root": "layer0/parser_scrapper-7.2",
    "cluster_key": "505ee9fa5baf39db055b9b8fd30ead5f60717df370bb185cfb0de8d85a0f050d",
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
          "direct_script",
          "decoded_eval",
          "dropped_binary"
        ],
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py decoded with b64_exec (derivation d2): the two exec(b64decode(...)) payloads were spliced in place and the package Python read in full. The embedded Windows PE bytes are a compiled binary, not statically analysed (see obfuscation.unrecovered).",
      "Outer guard `if 'sdist' not in argv:` skips the payload only when building an sdist (protects the author). On a normal pip install (egg_info/bdist_wheel) 'sdist' is absent, so the payload runs. Treated as a build-phase check, not an environmental gate.",
      "g3 and g4 sit in g1's else (os.name != 'nt'), which cannot be written positively; c2 (platform() has 'linux') implies it. g4 follows g3's exit(1) at line 62, so it includes c2.",
      "g1 else os=linux is read from the exit(1) at line 62 unless platform() contains 'linux', not guessed.",
      "g4 ISP check is inside m()'s try-else: if the ip-api request fails, the ISP check is skipped and the payload proceeds, so blocking ip-api does not trigger the evasion.",
      "Linux payload zips the loot, gzip+RC4-encrypts it (magic prefix LWSR$) and uploads it to a hard-coded Telegram bot (token redacted); recon JSON holds username, hostname, OS, IP and an optional PIL screenshot."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]telegram[.]org:443",
        "ip-api[.]com:80"
      ],
      "reason": "Linux payload exfiltrates to the Telegram bot API and queries ip-api for the host ISP (ip-api falls back to 127[.]0[.]0[.]1 if unreachable)."
    },
    {
      "axis": "other",
      "value": "urllib3 importable",
      "reason": "else branch imports urllib3 at the top of the decoded exec; install_requires is empty, so urllib3 must already be present or the ImportError aborts the payload."
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "os",
      "api": "os.name",
      "operator": "==",
      "value": "nt",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_cb9c10b6cf",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 662,
            "end_byte": 674,
            "node_type": "comparison_operator",
            "sha256": "967298d6abe68b73",
            "line": 27
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "os",
      "api": "platform.platform",
      "operator": "includes",
      "value": "linux",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 499416,
            "end_byte": 499436,
            "node_type": "comparison_operator",
            "sha256": "3987adb4f0298276",
            "line": 62
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "%TEMP%/pee77a45c1d8776c05386cc5dcd6601a76c96fd.exe",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 836,
            "end_byte": 852,
            "node_type": "call",
            "sha256": "cac2a1dc7a39559f",
            "line": 32
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "%TEMP%/pee77a45c1d8776c05386cc5dcd6601a76c96fd.exe",
        "accessor": "exists"
      }
    },
    {
      "id": "c4",
      "category": "external_ip_geo",
      "api": "urllib3.PoolManager.request",
      "operator": "not_includes",
      "value": "google",
      "value_recovered": "decoded",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 501597,
            "end_byte": 501605,
            "node_type": "string",
            "sha256": "516b6bb7d9ef4fb0",
            "line": 83
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "external_ip_geo",
      "api": "urllib3.PoolManager.request",
      "operator": "not_includes",
      "value": "mythic beasts",
      "value_recovered": "decoded",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 501606,
            "end_byte": 501621,
            "node_type": "string",
            "sha256": "5125e46c512f3af6",
            "line": 83
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c1",
      "guards": [
        {
          "candidate": "q_0fa7bb5f9c",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 659,
            "end_byte": 670259,
            "node_type": "if_statement",
            "sha256": "8e4e50519339b64f",
            "line": 27
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "portability",
      "purpose_reason": "os.name picks a Windows PE dropper (then) or a Linux Python infostealer (else).",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 693,
            "end_byte": 498539,
            "node_type": "stmt_range",
            "sha256": "97c3115302fe07ad",
            "line": 29
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 871,
              "end_byte": 884,
              "node_type": "call",
              "sha256": "d4eb3733bf0b8e3c",
              "line": 33
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 498525,
              "end_byte": 498539,
              "node_type": "call",
              "sha256": "b68730f7d13879b5",
              "line": 35
            },
            "witness": []
          }
        ]
      },
      "else": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "cred_read",
          "write_file",
          "exfil",
          "delete_file"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 498558,
            "end_byte": 503596,
            "node_type": "stmt_range",
            "sha256": "a342bfc596029e83",
            "line": 37
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 501402,
              "end_byte": 501456,
              "node_type": "call",
              "sha256": "31d08690bb9be465",
              "line": 79
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503550,
                  "end_byte": 503553,
                  "node_type": "call",
                  "sha256": "65171eae511de685",
                  "line": 123
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 501372,
                  "end_byte": 501986,
                  "node_type": "function_definition",
                  "sha256": "b996a36d70045fb5",
                  "line": 78
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 502414,
              "end_byte": 502445,
              "node_type": "call",
              "sha256": "2c50bc0385406196",
              "line": 102
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503564,
                  "end_byte": 503568,
                  "node_type": "call",
                  "sha256": "99b7bb81e3ab84d6",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502454,
                  "end_byte": 503287,
                  "node_type": "function_definition",
                  "sha256": "8bfd5c1683749747",
                  "line": 103
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502865,
                  "end_byte": 502873,
                  "node_type": "call",
                  "sha256": "696ee007b36b6393",
                  "line": 113
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 501995,
                  "end_byte": 502445,
                  "node_type": "function_definition",
                  "sha256": "119b9f28245ae13a",
                  "line": 91
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 501824,
              "end_byte": 501857,
              "node_type": "call",
              "sha256": "371e22f90fe6d074",
              "line": 90
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503550,
                  "end_byte": 503553,
                  "node_type": "call",
                  "sha256": "65171eae511de685",
                  "line": 123
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 501372,
                  "end_byte": 501986,
                  "node_type": "function_definition",
                  "sha256": "b996a36d70045fb5",
                  "line": 78
                }
              }
            ]
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503474,
              "end_byte": 503541,
              "node_type": "call",
              "sha256": "382dcecbd107415d",
              "line": 122
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503592,
                  "end_byte": 503596,
                  "node_type": "call",
                  "sha256": "807bce9e25f7628a",
                  "line": 126
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503367,
                  "end_byte": 503541,
                  "node_type": "function_definition",
                  "sha256": "79595b3fcda844c5",
                  "line": 122
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503214,
              "end_byte": 503218,
              "node_type": "call",
              "sha256": "258f39f1b5b5f0a1",
              "line": 118
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503564,
                  "end_byte": 503568,
                  "node_type": "call",
                  "sha256": "99b7bb81e3ab84d6",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502454,
                  "end_byte": 503287,
                  "node_type": "function_definition",
                  "sha256": "8bfd5c1683749747",
                  "line": 103
                }
              }
            ]
          }
        ]
      }
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c1 && c3",
      "guards": [
        {
          "candidate": "q_0fa7bb5f9c",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 659,
            "end_byte": 670259,
            "node_type": "if_statement",
            "sha256": "8e4e50519339b64f",
            "line": 27
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 829,
            "end_byte": 498539,
            "node_type": "if_statement",
            "sha256": "345382c1f3332332",
            "line": 32
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "Reinfection guard: drops and runs the exe only when it is not already present in the temp dir.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32",
          "file_absent": [
            "%TEMP%/pee77a45c1d8776c05386cc5dcd6601a76c96fd.exe"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 866,
            "end_byte": 498539,
            "node_type": "stmt_range",
            "sha256": "8a1cf9ce364d8b04",
            "line": 33
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 871,
              "end_byte": 884,
              "node_type": "call",
              "sha256": "d4eb3733bf0b8e3c",
              "line": 33
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 498525,
              "end_byte": 498539,
              "node_type": "call",
              "sha256": "b68730f7d13879b5",
              "line": 35
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 499413,
            "end_byte": 499444,
            "node_type": "if_statement",
            "sha256": "952d449c20780215",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "Non-Windows payload runs only when platform() contains 'linux'; exits on other systems such as macOS.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 499453,
            "end_byte": 503596,
            "node_type": "stmt_range",
            "sha256": "be799a4af237665a",
            "line": 63
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 501402,
              "end_byte": 501456,
              "node_type": "call",
              "sha256": "31d08690bb9be465",
              "line": 79
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503550,
                  "end_byte": 503553,
                  "node_type": "call",
                  "sha256": "65171eae511de685",
                  "line": 123
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 501372,
                  "end_byte": 501986,
                  "node_type": "function_definition",
                  "sha256": "b996a36d70045fb5",
                  "line": 78
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "setup_py",
      "expression": "c2 && c4 && c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 499413,
            "end_byte": 499444,
            "node_type": "if_statement",
            "sha256": "952d449c20780215",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 501635,
            "end_byte": 501660,
            "node_type": "if_statement",
            "sha256": "61a5ea8a6fbbf01b",
            "line": 84
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4",
            "c5"
          ],
          "via": [
            {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503550,
              "end_byte": 503553,
              "node_type": "call",
              "sha256": "65171eae511de685",
              "line": 123
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "Exits if ip-api reports the host ISP contains 'google' or 'mythic beasts' (cloud/hosting/sandbox infra); theft and exfil run only otherwise.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read",
          "write_file",
          "exfil",
          "delete_file"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 501670,
            "end_byte": 501986,
            "node_type": "stmt_range",
            "sha256": "454e12dddf12ebc3",
            "line": 85
          },
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 503550,
            "end_byte": 503596,
            "node_type": "stmt_range",
            "sha256": "4233459d17fa55d0",
            "line": 123
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503474,
              "end_byte": 503541,
              "node_type": "call",
              "sha256": "382dcecbd107415d",
              "line": 122
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503592,
                  "end_byte": 503596,
                  "node_type": "call",
                  "sha256": "807bce9e25f7628a",
                  "line": 126
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503367,
                  "end_byte": 503541,
                  "node_type": "function_definition",
                  "sha256": "79595b3fcda844c5",
                  "line": 122
                }
              }
            ]
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 502414,
              "end_byte": 502445,
              "node_type": "call",
              "sha256": "2c50bc0385406196",
              "line": 102
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503564,
                  "end_byte": 503568,
                  "node_type": "call",
                  "sha256": "99b7bb81e3ab84d6",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502454,
                  "end_byte": 503287,
                  "node_type": "function_definition",
                  "sha256": "8bfd5c1683749747",
                  "line": 103
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502865,
                  "end_byte": 502873,
                  "node_type": "call",
                  "sha256": "696ee007b36b6393",
                  "line": 113
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 501995,
                  "end_byte": 502445,
                  "node_type": "function_definition",
                  "sha256": "119b9f28245ae13a",
                  "line": 91
                }
              }
            ]
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503201,
              "end_byte": 503213,
              "node_type": "call",
              "sha256": "4d2b60170cb597b3",
              "line": 118
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503564,
                  "end_byte": 503568,
                  "node_type": "call",
                  "sha256": "99b7bb81e3ab84d6",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502454,
                  "end_byte": 503287,
                  "node_type": "function_definition",
                  "sha256": "8bfd5c1683749747",
                  "line": 103
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 503214,
              "end_byte": 503218,
              "node_type": "call",
              "sha256": "258f39f1b5b5f0a1",
              "line": 118
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 503564,
                  "end_byte": 503568,
                  "node_type": "call",
                  "sha256": "99b7bb81e3ab84d6",
                  "line": 124
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d2",
                  "start_byte": 502454,
                  "end_byte": 503287,
                  "node_type": "function_definition",
                  "sha256": "8bfd5c1683749747",
                  "line": 103
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
      "write_file",
      "spawn_process",
      "recon",
      "cred_read",
      "exfil",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "per-OS exec(base64.b64decode('...')) payloads",
      "embedded Windows PE executable dropped and run at install",
      "single-letter variable and import aliasing in the Linux stealer",
      "gzip + RC4 encoded exfil archive (LWSR$ magic)",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "Embedded Windows PE executable (MZ/PE) written to the temp dir and launched with os.startfile on Windows; compiled binary logic not statically analysed."
      }
    ]
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "api[.]telegram[.]org",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "wsr-telegram-grabber",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs at install and, after skipping sdist builds, branches on os.name: on Windows it drops an embedded PE to the temp dir and runs it; on Linux it runs a Python infostealer that collects browser/email/FTP/messaging credentials and crypto wallets, takes a screenshot, zips and RC4-encrypts them, and exfiltrates to a hard-coded Telegram bot. It also queries ip-api and aborts on Google/Mythic-Beasts hosting ISPs, a sandbox-evasion check.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Out-of-set conditions (c2, c3, c4, c5) and gates (g2, g3, g4) added by the analyst; verify against the decoded source.",
    "Embedded Windows PE dropped and executed is a compiled binary left unread (obfuscation.unrecovered).",
    "unrecovered code",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "decoder": "b64_exec",
          "lang": "py"
        },
        "output_sha256": "f8beeb9e22b3867b"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@497d11fbce",
      "sha256": "2d94f20f552c64c8"
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
    "condition_candidates": 1,
    "condition_sites_cited": 1,
    "guards_cited": 1,
    "candidates_dropped": 0,
    "conditions_in_set": 1,
    "conditions_out_of_set": 4,
    "guard_candidates": 1,
    "gates_in_set": 1,
    "gates_out_of_set": 3,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
