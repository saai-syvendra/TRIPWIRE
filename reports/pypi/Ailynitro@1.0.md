# pypi Ailynitro@1.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

`setup.py` runs at every sdist build and, at top level, calls `GatherAll()` and `Kiwi()`, a Windows Discord and browser stealer. Stealer functions run in threads and look for Discord and browser profile folders, wallet and Steam folders, and keyword-named files in Desktop, Downloads and Documents. Each source is only read when its folder exists (target-artifact gates), and harvested Discord tokens are validated against the Discord API before upload. Everything is sent to a Discord webhook and transfer.sh. A machine with Windows, the usual app data variables and those folders present opens all gates.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: target_artifact exists <browser profile dir under LOCALAPPDATA or APPDATA>) | then | 1 | cred_read | os=win32; file_present=%LOCALAPPDATA%/Google/Chrome/User Data/Default/Login Data |
| g2 | setup_py | (c1 \|\| c2) && c6 (c1: target_artifact exists <browser profile dir under LOCALAPPDATA or APPDATA>; c2: target_artifact exists <Discord client dir>/Local State; c6: server_response truthy) | then | 2 | exfil | os=win32; file_present=%APPDATA%/Discord/Local State; network=discord[.]com:443=reachable |
| g3 | setup_py | c3 (c3: target_artifact exists <browser, wallet or Steam data dir>) | then | 1 | spawn_process, exfil, delete_file | os=win32; file_present=%APPDATA%/Exodus/exodus.wallet |
| g4 | setup_py | c3 && c4 (c3: target_artifact exists <browser, wallet or Steam data dir>; c4: target_artifact exists C:\Program Files (x86)\Steam\config/loginusers.vdf) | then | 2 | cred_read | os=win32; file_present=C:\Program Files (x86)\Steam\config\loginusers.vdf |
| g5 | setup_py | c5 (c5: target_artifact exists file or folder under Desktop, Downloads or Documents) | then | 1 | exfil | os=win32; file_present=%USERPROFILE%/Desktop/passw.txt; network=transfer[.]sh:443=reachable |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability

Grounding: 5 of 6 conditions and 4 of 5 gates from the candidate set; out of set, pending verification: c6, g2.

## Requirements

- os: win32 (ctypes.windll and CryptUnprotectData are imported at the top of setup.py; the import fails elsewhere)
- network: discord[.]com:443 (webhook for exfiltration plus Discord API token validation)
- network: transfer[.]sh:443 (files found on Desktop, Downloads and Documents are uploaded here)
- network: pypi[.]org:443 (pip install of requests and pycryptodome when missing)
- other: LOCALAPPDATA, APPDATA and TEMP set (browser, Discord and temp paths are built from these variables)

## Behaviour

- Ungated: exfil, download
- Gated: cred_read, exfil, spawn_process, delete_file

## Notes

- Non-Windows hosts fail at `from ctypes import windll` (line 11), so this is recorded as an os requirement, not a gate.
- `Trust()` can never return True (`len(tim)<-1`), so the DETECTED checks are dead branches.
- The pip install of requests and pycryptodome is bootstrap plumbing and was dropped.
- The stealer functions are started through `threading.Thread(target=...)`. All gate payloads are traced from their regions; the calls inside each thread target are direct.
- The zip and upload at lines 511-516 are shared by every `ZipThings` caller, so they sit under g3 (`c3` only). g4 (`c3 && c4`) covers only the read of `loginusers.vdf` at lines 503-510. For the Steam entry the upload also needs `c4` and the `RememberPassword` test, because the elif returns otherwise.
- The Steam `RememberPassword` content test (line 507) is not recorded as a separate condition.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "Ailynitro",
    "version": "1.0",
    "archive_sha256": "c663a9bb771d724e611613a422ab0ed374f401052dee62ffefb70d6784c2df2f",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/Ailynitro-1.0.tar.gz",
    "package_root": "layer0/Ailynitro-1.0",
    "cluster_key": "8ac9a7b8cecad52054d1f41595f98044b3972b312376b17aa46cd769432e5f8b",
    "analysis_type": "ai",
    "model_name": "claude-sonnet-5-5"
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
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [
      {
        "site": "setup.py:38",
        "seconds": 3
      },
      {
        "site": "setup.py:668",
        "seconds": 0.2
      }
    ],
    "notes": [
      "generator truncated: some helpers walked under only 2 guard contexts in setup.py; candidates there may be missing",
      "setup.py: package code read in full (697 lines, plain Python, no decoding needed); setup.cfg and egg-info are metadata only; nothing unread.",
      "Stealer functions run in threading.Thread(target=...) started from GatherAll(), called unconditionally at top level (line 663). All gate sinks are traced from their regions; inside each thread target the calls to the sinks are direct.",
      "ZipThings lines 511-516 are shared by every caller, so the zip and upload sit under g3 (c3 only). For the Steam entry they also need c4 and the RememberPassword test (lines 502, 509), which the elif returns on; regions cannot express that, so g4 covers only the read at lines 503-510.",
      "g5 recipe file name passw.txt is built from the code's literals (keyword 'passw' line 624, '.txt' line 602); any listed name matching both opens the gate. %USERPROFILE% stands for temp.split('\\\\AppData')[0] (line 611).",
      "Line 11 imports windll from ctypes, which raises ImportError on non-Windows, so setup.py stops before any stealer code there. Not a deliberate test, so recorded as an os requirement only.",
      "Trust() tests len(tim)<-1, which is never true, so DETECTED is always False and the 'if DETECTED: return' and 'if not DETECTED' checks never change behaviour. Dead branch, not a gate.",
      "Lines 3-35: exec('') is a no-op. The __import__/pip install loop for requests and pycryptodome is dependency bootstrap plumbing, both branches continue to the same stealer.",
      "Gates g2 uses checkToken(), which asks the Discord API whether a harvested token is valid before uploading it; recorded as a server_response condition (out of scope).",
      "Unconditional code: getip() (api.ipify.org) is called while building each token report; GatherAll() always uploads the wppassw/wpcook files and the Kiwi file list to the webhook."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "ctypes.windll and CryptUnprotectData are imported at the top of setup.py; the import fails elsewhere"
    },
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "webhook for exfiltration plus Discord API token validation"
    },
    {
      "axis": "network",
      "value": "transfer[.]sh:443",
      "reason": "files found on Desktop, Downloads and Documents are uploaded here"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "pip install of requests and pycryptodome when missing"
    },
    {
      "axis": "other",
      "value": "LOCALAPPDATA, APPDATA and TEMP set",
      "reason": "browser, Discord and temp paths are built from these variables"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "<browser profile dir under LOCALAPPDATA or APPDATA>",
      "value_recovered": "partial",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_c1f5c0442f",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 14422,
            "end_byte": 14442,
            "node_type": "call",
            "sha256": "8b032456a79d8536",
            "line": 400
          }
        },
        {
          "candidate": "k_e0e2930b11",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 15130,
            "end_byte": 15150,
            "node_type": "call",
            "sha256": "8b032456a79d8536",
            "line": 415
          }
        },
        {
          "candidate": "k_b548d8f668",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 16372,
            "end_byte": 16392,
            "node_type": "call",
            "sha256": "8b032456a79d8536",
            "line": 445
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "<Discord client dir>/Local State",
      "value_recovered": "partial",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_756e513a61",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 17572,
            "end_byte": 17609,
            "node_type": "call",
            "sha256": "50dc5ba3e0d45d67",
            "line": 473
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "<browser, wallet or Steam data dir>",
      "value_recovered": "partial",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_61fed7766c",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18772,
            "end_byte": 18793,
            "node_type": "call",
            "sha256": "879594dbc7aafce2",
            "line": 496
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "C:\\Program Files (x86)\\Steam\\config/loginusers.vdf",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_1e652d5b73",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19051,
            "end_byte": 19092,
            "node_type": "call",
            "sha256": "9b71dd258389d0a0",
            "line": 502
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "os.path.isfile / os.path.isdir",
      "operator": "exists",
      "value": "file or folder under Desktop, Downloads or Documents",
      "value_recovered": "partial",
      "in_scope": true,
      "sites": [
        {
          "candidate": "k_9c7e7e56a7",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23340,
            "end_byte": 23370,
            "node_type": "call",
            "sha256": "6f3dadbfddd51dfd",
            "line": 586
          }
        },
        {
          "candidate": "k_cc5159ffee",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23841,
            "end_byte": 23870,
            "node_type": "call",
            "sha256": "1a8fe82c37d15b55",
            "line": 602
          }
        },
        {
          "candidate": "k_2620e96014",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 24023,
            "end_byte": 24051,
            "node_type": "call",
            "sha256": "a73155869e295c20",
            "line": 605
          }
        }
      ],
      "provenance": "in_set"
    },
    {
      "id": "c6",
      "category": "server_response",
      "api": "checkToken",
      "operator": "truthy",
      "value": null,
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 14889,
            "end_byte": 14906,
            "node_type": "call",
            "sha256": "e02d93a1ef8ce651",
            "line": 408
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18328,
            "end_byte": 18352,
            "node_type": "call",
            "sha256": "1455b1576abae6a3",
            "line": 485
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
          "candidate": "q_d5ea25a7e0",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 15123,
            "end_byte": 15157,
            "node_type": "if_statement",
            "sha256": "b6b1dbfe6a731a85",
            "line": 415
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_8685d98478",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 16365,
            "end_byte": 16399,
            "node_type": "if_statement",
            "sha256": "b6b1dbfe6a731a85",
            "line": 445
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
      "purpose": "data_availability",
      "purpose_reason": "Saved browser passwords and cookies are only read when the browser profile folder exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Login Data"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 15163,
            "end_byte": 16301,
            "node_type": "stmt_range",
            "sha256": "a876daa422a38152",
            "line": 416
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 16405,
            "end_byte": 17532,
            "node_type": "stmt_range",
            "sha256": "6f7310241a197ac5",
            "line": 446
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 15429,
              "end_byte": 15509,
              "node_type": "call",
              "sha256": "feb48cb36b6996e5",
              "line": 422
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "(c1 || c2) && c6",
      "guards": [
        {
          "candidate": "q_7028a20918",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 14415,
            "end_byte": 14449,
            "node_type": "if_statement",
            "sha256": "b6b1dbfe6a731a85",
            "line": 400
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": "q_3bec781b6a",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 17565,
            "end_byte": 17616,
            "node_type": "if_statement",
            "sha256": "e436e28fba58eb81",
            "line": 473
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
            "derived_from": null,
            "start_byte": 14889,
            "end_byte": 14906,
            "node_type": "call",
            "sha256": "e02d93a1ef8ce651",
            "line": 408
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18328,
            "end_byte": 18352,
            "node_type": "call",
            "sha256": "1455b1576abae6a3",
            "line": 485
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Discord tokens are only uploaded when a browser or Discord client folder exists and the token validates against the Discord API.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%/Discord/Local State"
          ],
          "network": {
            "discord[.]com:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 14937,
            "end_byte": 15064,
            "node_type": "if_statement",
            "sha256": "9bdd3c0ae17e98bc",
            "line": 409
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18379,
            "end_byte": 18519,
            "node_type": "if_statement",
            "sha256": "b667d8cc03f6a61f",
            "line": 486
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 3108,
              "end_byte": 3156,
              "node_type": "call",
              "sha256": "241bd14d368f3af7",
              "line": 92
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 15041,
                  "end_byte": 15064,
                  "node_type": "call",
                  "sha256": "861053502e27aa85",
                  "line": 411
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 8558,
                  "end_byte": 11162,
                  "node_type": "function_definition",
                  "sha256": "b22c66d0e2dfd587",
                  "line": 216
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 11105,
                  "end_byte": 11162,
                  "node_type": "call",
                  "sha256": "31dc8d5992a7b06b",
                  "line": 292
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2972,
                  "end_byte": 3314,
                  "node_type": "function_definition",
                  "sha256": "d340e9d3c469010f",
                  "line": 88
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c3",
      "guards": [
        {
          "candidate": "q_10b28b8781",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18765,
            "end_byte": 18800,
            "node_type": "if_statement",
            "sha256": "f8adce2d7e439538",
            "line": 496
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Browser extension, wallet and Steam folders are only killed, zipped and uploaded when they exist.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process",
          "exfil",
          "delete_file"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%/Exodus/exodus.wallet"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18806,
            "end_byte": 19585,
            "node_type": "stmt_range",
            "sha256": "515731d887a5c134",
            "line": 497
          }
        ],
        "payload": [
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 18806,
              "end_byte": 18864,
              "node_type": "call",
              "sha256": "d3ddd6bc906a504e",
              "line": 497
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2788,
              "end_byte": 2818,
              "node_type": "call",
              "sha256": "23b92230a6bdb155",
              "line": 83
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 19518,
                  "end_byte": 19547,
                  "node_type": "call",
                  "sha256": "3b499d2488e38cca",
                  "line": 515
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 11368,
                  "end_byte": 14101,
                  "node_type": "function_definition",
                  "sha256": "3e72732571a69ce7",
                  "line": 299
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 14064,
                  "end_byte": 14101,
                  "node_type": "call",
                  "sha256": "1a9cc81666603906",
                  "line": 390
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2430,
                  "end_byte": 2970,
                  "node_type": "function_definition",
                  "sha256": "2c0fc9fe6e14ba39",
                  "line": 74
                }
              }
            ]
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 19553,
              "end_byte": 19585,
              "node_type": "call",
              "sha256": "2520f3200c486bc7",
              "line": 516
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g4",
      "hook": "setup_py",
      "expression": "c3 && c4",
      "guards": [
        {
          "candidate": "q_10b28b8781",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 18765,
            "end_byte": 18800,
            "node_type": "if_statement",
            "sha256": "f8adce2d7e439538",
            "line": 496
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": "q_0e575003ef",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19044,
            "end_byte": 19099,
            "node_type": "if_statement",
            "sha256": "fca29312dcedf502",
            "line": 502
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "For the Steam folder, ZipThings returns before reading loginusers.vdf unless the file exists (line 502), so the read at lines 503-504 needs the folder and the file.",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "C:\\Program Files (x86)\\Steam\\config\\loginusers.vdf"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19109,
            "end_byte": 19361,
            "node_type": "stmt_range",
            "sha256": "8c2a6a5409c59988",
            "line": 503
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 19111,
              "end_byte": 19163,
              "node_type": "call",
              "sha256": "9955312a2ed82c56",
              "line": 503
            },
            "witness": []
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g5",
      "hook": "setup_py",
      "expression": "c5",
      "guards": [
        {
          "candidate": "q_c1dc6b4b2d",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23333,
            "end_byte": 23377,
            "node_type": "if_statement",
            "sha256": "4dea20bc92692b30",
            "line": 586
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": "q_0546ad25a0",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23838,
            "end_byte": 24002,
            "node_type": "if_statement",
            "sha256": "6026512b9bb065a5",
            "line": 602
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": "q_416ddc87f4",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 24020,
            "end_byte": 24170,
            "node_type": "if_statement",
            "sha256": "1295fb870741a6d0",
            "line": 605
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Files whose names suggest passwords, wallets or accounts are only uploaded to transfer.sh when they exist in Desktop, Downloads or Documents.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%/Desktop/passw.txt"
          ],
          "network": {
            "transfer[.]sh:443": "reachable"
          }
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23387,
            "end_byte": 23556,
            "node_type": "stmt_range",
            "sha256": "25d5ca999d228eec",
            "line": 587
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23911,
            "end_byte": 24002,
            "node_type": "block",
            "sha256": "f75351c04eff859f",
            "line": 603
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 24074,
            "end_byte": 24170,
            "node_type": "block",
            "sha256": "3c7304f554ab42b7",
            "line": 606
          }
        ],
        "payload": [
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 23030,
              "end_byte": 23079,
              "node_type": "call",
              "sha256": "481b1309dd1f6069",
              "line": 574
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 23941,
                  "end_byte": 23973,
                  "node_type": "call",
                  "sha256": "7ea6758ec5abee71",
                  "line": 603
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 22923,
                  "end_byte": 23159,
                  "node_type": "function_definition",
                  "sha256": "9fea64dbc82d3dc5",
                  "line": 571
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "exfil",
      "download"
    ],
    "gated": [
      "cred_read",
      "exfil",
      "spawn_process",
      "delete_file"
    ]
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
        "indicator": "hxxps://discord[.]com/api/webhooks/1092…",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://transfer[.]sh/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "Fade Stealer (per embedded string)",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a Windows information stealer at install: it harvests Discord tokens, browser passwords and cookies, wallet and Steam folders and keyword-matched documents, and sends them to a Discord webhook and transfer.sh.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "condition value not fully recovered",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "e2b335247640c719"
    },
    "units_summary": [],
    "truncation": {
      "walk_limit": false,
      "context_limited_files": 1
    }
  },
  "candidate_review": {
    "dropped": [
      {
        "candidate": "k_ee61418539",
        "reason_code": "other",
        "note": "pip bootstrap of requests and pycryptodome; both branches continue to the same stealer, so plumbing and dependency tree",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 987,
          "end_byte": 1006,
          "node_type": "call",
          "sha256": "1aef8fb18a33920c",
          "line": 35
        }
      },
      {
        "candidate": "q_51818e9113",
        "reason_code": "other",
        "note": "try/except around the dependency __import__; plumbing for the pip bootstrap, not an environment gate",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 983,
          "end_byte": 1121,
          "node_type": "try_statement",
          "sha256": "234950015e5c2a4a",
          "line": 35
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 1,
    "condition_sites_cited": 9,
    "guards_cited": 9,
    "candidates_dropped": 2,
    "conditions_in_set": 5,
    "conditions_out_of_set": 1,
    "guard_candidates": 10,
    "gates_in_set": 4,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c6",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
