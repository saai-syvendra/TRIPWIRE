# pypi Ailyboostbot@1.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

`setup.py` runs on every sdist build and, after installing `requests` and `pycryptodome` with pip if they are missing, calls `GatherAll()` and `Kiwi()` at module level. It is a Windows stealer (Fade Stealer style): it takes Discord tokens, saved browser passwords and cookies, Metamask, Atomic, Exodus, Steam and NationsGlory folders, and files on the Desktop, Downloads and Documents whose names hold credential keywords, and posts them to a Discord webhook and transfer[.]sh. Every theft step is behind a target-artifact check (the profile, wallet, Steam or document path must exist), and the Steam branch also needs `RememberPassword` set in `loginusers.vdf`. A VM that runs it needs Windows, the browser and Discord profile folders and wallet folders as decoys, and outbound HTTPS.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g2 | setup_py | c2 (c2: target_artifact exists browser profile dir (Opera, Opera GX, Chrome, Brave, Yandex, Edge under APPDATA or LOCALAPPDATA)) | then | 1 | cred_read, exfil | file_present=%LOCALAPPDATA%/Google/Chrome/User Data |
| g3 | setup_py | c3 (c3: target_artifact exists <Discord, Lightcord, discordcanary or discordptb dir under APPDATA>/Local State) | then | 1 | cred_read, exfil | file_present=%APPDATA%/Discord/Local State |
| g4 | setup_py | c4 (c4: target_artifact exists wallet or app dir (Metamask extension in browser profiles, Atomic, Exodus, Steam config, NationsGlory)) | then | 1 | spawn_process, cred_read, exfil | file_present=%APPDATA%/Exodus/exodus.wallet |
| g5 | setup_py | c4 && c5 && c7 (c4: target_artifact exists wallet or app dir (Metamask extension in browser profiles, Atomic, Exodus, Steam config, NationsGlory); c5: target_artifact exists C:\Program Files (x86)\Steam\config/loginusers.vdf; c7: file_content includes RememberPassword"		"1") | then | 3 | cred_read, exfil | file_present=C:\Program Files (x86)\Steam\config, C:\Program Files (x86)\Steam\config/loginusers.vdf |
| g6 | setup_py | c6 (c6: target_artifact exists entries under Desktop, Downloads, Documents whose name holds a credential keyword, and any child of a keyword-named folder there) | then | 1 | cred_read, exfil | file_present=%USERPROFILE%/Desktop/passw.txt |

Gate intent: g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/enables/data_availability

Grounding: 5 of 6 conditions and 4 of 5 gates from the candidate set; out of set, pending verification: c7, g5.

## Requirements

- os: win32 (setup.py imports ctypes.windll at top level and reads Windows profile paths; it fails on other systems)
- network: discord[.]com:443, transfer[.]sh:443 (stolen data is posted to a Discord webhook and files are uploaded to transfer.sh)
- installed_tool: taskkill, pip (taskkill is run through the shell before zipping wallet and browser folders; pip installs requests and pycryptodome when missing)
- other: LOCALAPPDATA, APPDATA and TEMP environment variables set (profile paths and temp copies are built from them; None would produce paths that do not exist)

## Behaviour

- Ungated: spawn_process, recon, exfil
- Gated: cred_read, exfil, spawn_process

## Notes

- The `Trust()` "detected" check can never be true, so it is not a gate.
- Off Windows, the top-level `ctypes.windll` import fails and nothing else runs.
- Endpoints for the IP lookup, Discord API enrichment calls and embed image links are not listed as roles because they are not second stage, C2 or exfil sinks.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "Ailyboostbot",
    "version": "1.0",
    "archive_sha256": "87959124b8262a6e351c9b00865dc7a2d429edbdb0b11c4d2c5614417e9ad306",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/Ailyboostbot-1.0.tar.gz",
    "package_root": "layer0/Ailyboostbot-1.0",
    "cluster_key": "0a6fc92072c34dd1139b7d59584d0da19a8433fbcb249922b3e958f4d6e93872",
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
          "inline_shell"
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
      "setup.py (696 lines): package code read in full, no bundled third-party code; setup.cfg is egg_info metadata only; nothing unread.",
      "Top-level `from ctypes import windll,...` raises ImportError off Windows, so setup.py dies before any payload. Windows is required (see requirements); there is no deliberate OS check.",
      "Trust(Cookies) can never return True (`len(tim)<-1` is impossible), so `if DETECTED==True: return` in GatherAll and `if not DETECTED` at module level never stop the run. Not gates.",
      "Dropped k_ee61418539 and q_51818e9113: try __import__ then `pip install` of requests/pycryptodome is dependency plumbing; the Popen and 3s sleep run ungated when a module is missing.",
      "GatherAll starts threading.Thread targets (lines 541-566); the gate regions sit inside the target functions themselves, so no bind hops are needed.",
      "g5: c5 only applies to the Steam entry of PathsToZip; `'Steam' in arg` and `'Wallet' in arg` compare literals from that list, not the environment. c7 (out of set) is the loginusers.vdf RememberPassword content check.",
      "g5 is scoped to the one Steam call of ZipThings. c5 and c7 sit in the Steam elif, so their own side is line 510; lines 511-516 are shared and run only after both pass on that call. Other calls reach them with c4 alone, which is g4.",
      "g5: cred_read rests on zf.write (line 513), which reads each file of the Steam config folder, loginusers.vdf included, into the zip that upload() then posts.",
      "g6: KiwiFile also requires a keyword in the lower-cased file name and a .txt suffix (or a directory); only the isfile/isdir tests are recorded as c6.",
      "g6 recipe: passw.txt is built from code literals: keyword 'passw' (line 624), '.txt' (line 602), '/Desktop' (line 613). The base is TEMP cut at \\AppData (line 611), the user profile under default Windows TEMP.",
      "g6: KiwiFolder (line 586) tests children of a keyword-named folder with no keyword of their own; the first non-file child returns and stops the upload of later children.",
      "Metadata borrows a well-known library's author and keyword, and declares packages=['Ailyboostbot'] though the sdist has no such directory; it makes no claim about what the code does."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "setup.py imports ctypes.windll at top level and reads Windows profile paths; it fails on other systems"
    },
    {
      "axis": "network",
      "value": [
        "discord[.]com:443",
        "transfer[.]sh:443"
      ],
      "reason": "stolen data is posted to a Discord webhook and files are uploaded to transfer.sh"
    },
    {
      "axis": "installed_tool",
      "value": [
        "taskkill",
        "pip"
      ],
      "reason": "taskkill is run through the shell before zipping wallet and browser folders; pip installs requests and pycryptodome when missing"
    },
    {
      "axis": "other",
      "value": "LOCALAPPDATA, APPDATA and TEMP environment variables set",
      "reason": "profile paths and temp copies are built from them; None would produce paths that do not exist"
    }
  ],
  "conditions": [
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "browser profile dir (Opera, Opera GX, Chrome, Brave, Yandex, Edge under APPDATA or LOCALAPPDATA)",
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
      "id": "c3",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "<Discord, Lightcord, discordcanary or discordptb dir under APPDATA>/Local State",
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
      "id": "c4",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "wallet or app dir (Metamask extension in browser profiles, Atomic, Exodus, Steam config, NationsGlory)",
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
      "id": "c5",
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
      "id": "c6",
      "category": "target_artifact",
      "api": "os.path.isfile / os.path.isdir",
      "operator": "exists",
      "value": "entries under Desktop, Downloads, Documents whose name holds a credential keyword, and any child of a keyword-named folder there",
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
      "id": "c7",
      "category": "file_content",
      "api": "open",
      "operator": "includes",
      "value": "RememberPassword\"\t\t\"1\"",
      "value_recovered": "plain",
      "in_scope": true,
      "probe": {
        "kind": "file",
        "callee": "open",
        "target": "C:\\Program Files (x86)\\Steam\\config/loginusers.vdf",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19253,
            "end_byte": 19282,
            "node_type": "comparison_operator",
            "sha256": "dabdd580e2cffbee",
            "line": 507
          }
        }
      ],
      "provenance": "out_of_set"
    }
  ],
  "gates": [
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c2",
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
            "c2"
          ]
        },
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
            "c2"
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
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Token, saved-password and cookie theft only proceeds for browsers whose profile folder exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_present": [
            "%LOCALAPPDATA%/Google/Chrome/User Data"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 14455,
            "end_byte": 15064,
            "node_type": "stmt_range",
            "sha256": "2321081be922bd4b",
            "line": 401
          },
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
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 15337,
              "end_byte": 15365,
              "node_type": "call",
              "sha256": "669670d11b2c0043",
              "line": 419
            },
            "witness": []
          },
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 16576,
              "end_byte": 16604,
              "node_type": "call",
              "sha256": "669670d11b2c0043",
              "line": 449
            },
            "witness": []
          },
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
      "provenance": "in_set"
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c3",
      "guards": [
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
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Discord client token theft only proceeds when the client's Local State file exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_present": [
            "%APPDATA%/Discord/Local State"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 17622,
            "end_byte": 18519,
            "node_type": "stmt_range",
            "sha256": "baee8bc20ddc7b3e",
            "line": 474
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 18009,
              "end_byte": 18049,
              "node_type": "call",
              "sha256": "aabf375f11e7a5aa",
              "line": 481
            },
            "witness": []
          },
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
                  "start_byte": 18489,
                  "end_byte": 18519,
                  "node_type": "call",
                  "sha256": "dd8b550bee06aee4",
                  "line": 488
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
      "provenance": "in_set"
    },
    {
      "gate_id": "g4",
      "hook": "setup_py",
      "expression": "c4",
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
            "c4"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Wallet, Metamask and game-client folders are only killed, zipped and uploaded when they exist.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process",
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
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
          }
        ]
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g5",
      "hook": "setup_py",
      "expression": "c4 && c5 && c7",
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
            "c4"
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
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19321,
            "end_byte": 19343,
            "node_type": "if_statement",
            "sha256": "25368b3e85e06473",
            "line": 509
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c7"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "The Steam config folder is only zipped and uploaded when loginusers.vdf exists and holds a remembered login.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_present": [
            "C:\\Program Files (x86)\\Steam\\config",
            "C:\\Program Files (x86)\\Steam\\config/loginusers.vdf"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19353,
            "end_byte": 19361,
            "node_type": "expression_statement",
            "sha256": "c139f039cc81c9be",
            "line": 510
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 19367,
            "end_byte": 19585,
            "node_type": "stmt_range",
            "sha256": "25589c24efcc85ce",
            "line": 511
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 19472,
              "end_byte": 19496,
              "node_type": "call",
              "sha256": "2042e9fab8056725",
              "line": 513
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
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g6",
      "hook": "setup_py",
      "expression": "c6",
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
            "c6"
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
            "c6"
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
            "c6"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Files in Desktop, Downloads and Documents are only uploaded when a matching file or folder exists.",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "file_present": [
            "%USERPROFILE%/Desktop/passw.txt"
          ]
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
      "spawn_process",
      "recon",
      "exfil"
    ],
    "gated": [
      "cred_read",
      "exfil",
      "spawn_process"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "no-op exec('') after re-importing builtins",
      "leetspeak labels in stolen-data output"
    ],
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
  "family_hint": "Fade Stealer (Discord token and browser data grabber)",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a Windows stealer at install: it collects Discord tokens, browser passwords and cookies, wallet and Steam folders and keyword-named files, then posts them to a Discord webhook and transfer.sh.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "c7 and its guard are out of set (loginusers.vdf content check added by the analyst)",
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
        "note": "environmental probe but plumbing, not a gate: a missing requests/pycryptodome is pip-installed, then lines 39-40 import both unconditionally and the same payload runs; pip is in requirements",
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
        "note": "try/except around the dependency probe: environmental, but the pip fallback only prepares a module the payload needs and both sides reach the same imports at lines 39-40, so it is plumbing, not a gate",
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
      "c7",
      "g5"
    ],
    "anchor_refusals": 0
  }
}
```
