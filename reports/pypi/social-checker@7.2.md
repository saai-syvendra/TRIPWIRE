# pypi social-checker@7.2

**Source:** datadog · **Source label:** malicious · **Released:** 2023-04-19 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

`setup.py` calls `setup()` and then, at top level, runs one of two base64-encoded stages with `exec(b64decode(...))`, skipping both when `sdist` is in `sys.argv`. On Windows (`os.name == 'nt'`) it writes an embedded PE to `%TEMP%\X244d7bd2a3c377d6f17f.exe` and starts it with `os.startfile`, only if that file is not already there (reinfection guard). On any other OS the stage exits unless `platform.platform()` contains `linux`, looks up its external IP and ISP at ip-api and exits when the ISP is Google or Mythic Beasts (evade), then writes host details and a screenshot to a temp folder, copies Firefox/Thunderbird, FileZilla, Pidgin, Telegram, Electrum and Exodus files from whichever of those folders exist, and uploads the RC4-encrypted zip to a Telegram bot. A scanner sees the Linux payload only on Linux from a network whose ISP is not Google or Mythic Beasts, and sees credential theft only when the app folders are planted.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, decoded_eval, dropped_binary.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c2 && c1 && c6 (c2: other not_includes sdist; c1: os == nt; c6: file_or_dir_exists not_exists %TEMP%\X244d7bd2a3c377d6f17f.exe) | then | 3 | write_file, spawn_process | os=win32; file_absent=%TEMP%\X244d7bd2a3c377d6f17f.exe |
| g2 | setup_py | c2 && c3 (c2: other not_includes sdist; c3: os includes linux) | then | 2 | recon | os=linux |
| g3 | setup_py | c2 && c3 && c4 (c2: other not_includes sdist; c3: os includes linux; c4: external_ip_geo not_includes [google, mythic beasts]) | then | 3 | recon, write_file, exfil | os=linux |
| g4 | setup_py | c2 && c3 && c4 && c5 (c2: other not_includes sdist; c3: os includes linux; c4: external_ip_geo not_includes [google, mythic beasts]; c5: target_artifact exists [~/snap/firefox/common/.mozilla/firefox, ~/.mozilla/firefox, ~/.thunderbird, ~/.config/filezilla, ~/.purple, ~/.local/share/TelegramDesktop/tdata, ~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata, ~/snap/telegram-desktop/current/.local/share/TelegramDesktop/tdata, ~/.electrum/wallets, ~/snap/electrum/current/.electrum/wallets, ~/.config/Exodus, <mozilla profile>/prefs.js]) | then | 4 | cred_read | os=linux; file_present=~/.config/filezilla/sitemanager.xml, ~/.purple/accounts.xml, ~/.config/Exodus/exodus.conf.json |

Gate intent: g1 activate/selects/targeting; g2 activate/enables/portability; g3 evade/enables/anti_analysis; g4 activate/enables/data_availability

Grounding: 1 of 6 conditions and 0 of 4 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, c6, g1, g2, g3, g4.

## Requirements

- network: api[.]telegram[.]org:443 (Linux stage uploads the encrypted archive to the Telegram Bot API; without it the exfil fails.)
- installed_tool: urllib3 (Python module) (Linux stage imports urllib3 PoolManager unconditionally; an ImportError aborts the stage before any behaviour.)
- other: Pillow (PIL) importable, optional (Only needed for the screenshot inside system.json; the stage runs without it.)

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process, recon, exfil, cred_read

## Notes

- Stages decoded with the registered `b64_exec` decoder (derivation d1); every condition beyond `os.name` and the `sdist` check is cited in the decoded copy and is out of set.
- The embedded Windows PE (looks like .NET) was not analysed; it may carry its own gates.
- The ISP check (c4) depends on a third-party lookup of the external IP, so it is `external_ip_geo` and out of scope; a failed lookup lets the payload continue.
- The seven artifact sources share one exists filter fed by an embedded XML list, so they are one condition (c5) listing all paths rather than one gate per source.
- Telegram bot token and chat id redacted (6003…, 6151…).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "social-checker",
    "version": "7.2",
    "archive_sha256": "a4519037d9000a51d448fdeadd26f2fd56a15b9efe29bbcd11fc11c6ca51197b",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-04-19",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-04-19-social-checker-v7.2.zip",
    "package_root": "layer0/2023-04-19-social-checker-v7.2/social-checker-7.2",
    "cluster_key": "b5c18312faf8a6cea37e57ddc06c9ddb24f23343cdcb4cffd4a6a15d4f887303",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
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
      "setup.py: top-level code after setup() runs exec(b64decode(<literal>)) per OS branch. The tool did not recover the stages; decoded with the registered b64_exec decoder (derivation d1) and both stages read in full.",
      "Windows stage (os.name == 'nt'): writes an embedded PE (MZ header, .text/.rsrc/.reloc, looks like a .NET build) to %TEMP%\\X244d7bd2a3c377d6f17f.exe and runs it with os.startfile, only when that file does not exist yet. The PE itself is compiled code and was not analysed.",
      "Linux stage (else side of os.name == 'nt'): exits unless platform.platform() contains 'linux', so macOS gets nothing. g2 to g4 sit on the false side of c1; c3 implies it, so no negated condition is written.",
      "Linux stage: queries ip-api (hxxp://ip-api[.]com/line?fields=query,isp) for external IP and ISP; exits when the ISP contains 'google' or 'mythic beasts'. A failed lookup is tolerated (IP 127[.]0[.]0[.]1, ISP Unknown) and the payload goes on, so ip-api is not a requirement.",
      "Linux stage: writes system.json (username, hostname, platform, IP, ISP, PIL screenshot when Pillow imports) into a random temp folder, copies Firefox/Thunderbird profile files (key4.db, logins.json, cookies.sqlite), FileZilla, Pidgin, Telegram tdata, Electrum and Exodus wallet files there.",
      "Linux stage: zips the folder, gzips and RC4-encrypts it with a random 16-byte key (magic LWSR$), and POSTs it as <user>@<host>.wsr to the Telegram Bot API sendDocument with a hardcoded bot token (6003…) and chat id (6151…).",
      "The artifact sources are driven by one embedded XML list and tested at one site (the R() exists filter, plus prefs.js for Mozilla profiles), so they are recorded as one target_artifact condition c5 whose value lists every path, not one gate per source.",
      "c2 ('sdist' not in sys.argv) keeps the payload from running when the author builds the sdist; any pip install satisfies it. Recorded as category other.",
      "PIL ImageGrab import in a try/except only decides whether a screenshot goes into system.json; same behaviour class (recon), so treated as an optional prerequisite, not a gate.",
      "social-checker/__init__.py is not reached at install."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "api[.]telegram[.]org:443",
      "reason": "Linux stage uploads the encrypted archive to the Telegram Bot API; without it the exfil fails."
    },
    {
      "axis": "installed_tool",
      "value": "urllib3 (Python module)",
      "reason": "Linux stage imports urllib3 PoolManager unconditionally; an ImportError aborts the stage before any behaviour."
    },
    {
      "axis": "other",
      "value": "Pillow (PIL) importable, optional",
      "reason": "Only needed for the screenshot inside system.json; the stage runs without it."
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
          "candidate": "k_41ff6513da",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 660,
            "end_byte": 672,
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
      "category": "other",
      "api": "sys.argv",
      "operator": "not_includes",
      "value": "sdist",
      "value_recovered": "plain",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 632,
            "end_byte": 651,
            "node_type": "comparison_operator",
            "sha256": "242edd6e4ae60e6a",
            "line": 26
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
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
            "derived_from": "d1",
            "start_byte": 175832,
            "end_byte": 175852,
            "node_type": "comparison_operator",
            "sha256": "29a9cae49f9751a7",
            "line": 62
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "external_ip_geo",
      "api": "urllib3.PoolManager.request",
      "operator": "not_includes",
      "value": [
        "google",
        "mythic beasts"
      ],
      "value_recovered": "decoded",
      "in_scope": false,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 178036,
            "end_byte": 178050,
            "node_type": "comparison_operator",
            "sha256": "33b0d88b82090abb",
            "line": 83
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": [
        "~/snap/firefox/common/.mozilla/firefox",
        "~/.mozilla/firefox",
        "~/.thunderbird",
        "~/.config/filezilla",
        "~/.purple",
        "~/.local/share/TelegramDesktop/tdata",
        "~/.var/app/org.telegram.desktop/data/TelegramDesktop/tdata",
        "~/snap/telegram-desktop/current/.local/share/TelegramDesktop/tdata",
        "~/.electrum/wallets",
        "~/snap/electrum/current/.electrum/wallets",
        "~/.config/Exodus",
        "<mozilla profile>/prefs.js"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 177431,
            "end_byte": 177443,
            "node_type": "call",
            "sha256": "d2e81c7471a99d44",
            "line": 70
          }
        },
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179377,
            "end_byte": 179407,
            "node_type": "call",
            "sha256": "f4ff8caae708992d",
            "line": 116
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "*",
        "accessor": "exists"
      }
    },
    {
      "id": "c6",
      "category": "file_or_dir_exists",
      "api": "os.path.exists",
      "operator": "not_exists",
      "value": "%TEMP%\\X244d7bd2a3c377d6f17f.exe",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 812,
            "end_byte": 832,
            "node_type": "not_operator",
            "sha256": "19f2634854ca5ae7",
            "line": 32
          }
        }
      ],
      "provenance": "out_of_set",
      "probe": {
        "kind": "file",
        "callee": "os.path.exists",
        "target": "%TEMP%\\X244d7bd2a3c377d6f17f.exe",
        "accessor": "exists"
      }
    }
  ],
  "gates": [
    {
      "gate_id": "g1",
      "hook": "setup_py",
      "expression": "c2 && c1 && c6",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 629,
            "end_byte": 238793,
            "node_type": "if_statement",
            "sha256": "93d6d38038ae37cf",
            "line": 26
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": "q_69c4f05f21",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 657,
            "end_byte": 238793,
            "node_type": "if_statement",
            "sha256": "9bc23af42269cab3",
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
            "derived_from": "d1",
            "start_byte": 809,
            "end_byte": 174955,
            "node_type": "if_statement",
            "sha256": "1ea3ef52bd178fa9",
            "line": 32
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "selects",
      "purpose": "targeting",
      "purpose_reason": "The dropped PE only exists for Windows; the exists check is a reinfection guard that skips the drop and launch when the exe is already in %TEMP%.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "write_file",
          "spawn_process"
        ],
        "env_recipe": {
          "os": "win32",
          "file_absent": [
            "%TEMP%\\X244d7bd2a3c377d6f17f.exe"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 846,
            "end_byte": 174955,
            "node_type": "stmt_range",
            "sha256": "6b0e4025debb0eb6",
            "line": 33
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 887,
              "end_byte": 174928,
              "node_type": "call",
              "sha256": "6de13f8485ef1f33",
              "line": 34
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 174941,
              "end_byte": 174955,
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
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 629,
            "end_byte": 238793,
            "node_type": "if_statement",
            "sha256": "93d6d38038ae37cf",
            "line": 26
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 175829,
            "end_byte": 175860,
            "node_type": "if_statement",
            "sha256": "62007d9547e1483a",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "portability",
      "purpose_reason": "The non-Windows stage reads only Linux app paths (~/.mozilla, ~/.config, snap and flatpak folders) and exits where the platform string lacks linux, so the check keeps it on the OS those paths fit; Windows gets its own stage in the other branch.",
      "then": {
        "min_conditions": 2,
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
            "derived_from": "d1",
            "start_byte": 175869,
            "end_byte": 179985,
            "node_type": "stmt_range",
            "sha256": "4c5bf0fea402ed3f",
            "line": 63
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 177800,
              "end_byte": 177854,
              "node_type": "call",
              "sha256": "923f59a42f6ca042",
              "line": 78
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 179939,
                  "end_byte": 179942,
                  "node_type": "call",
                  "sha256": "e9c88886e6534631",
                  "line": 122
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 177770,
                  "end_byte": 178375,
                  "node_type": "function_definition",
                  "sha256": "0353143b82c9292a",
                  "line": 77
                }
              }
            ]
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g3",
      "hook": "setup_py",
      "expression": "c2 && c3 && c4",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 629,
            "end_byte": 238793,
            "node_type": "if_statement",
            "sha256": "93d6d38038ae37cf",
            "line": 26
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 175829,
            "end_byte": 175860,
            "node_type": "if_statement",
            "sha256": "62007d9547e1483a",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 178033,
            "end_byte": 178058,
            "node_type": "if_statement",
            "sha256": "55d21f3f7ea5032e",
            "line": 83
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ],
          "via": [
            {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 179939,
              "end_byte": 179942,
              "node_type": "call",
              "sha256": "e9c88886e6534631",
              "line": 122
            }
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "evade",
      "effect": "enables",
      "purpose": "anti_analysis",
      "purpose_reason": "Exits when the external IP's ISP is Google or Mythic Beasts, i.e. cloud or hosting networks used by scanners and sandboxes.",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "recon",
          "write_file",
          "exfil"
        ],
        "env_recipe": {
          "os": "linux"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 178068,
            "end_byte": 178375,
            "node_type": "stmt_range",
            "sha256": "68610fd32ee42fa5",
            "line": 84
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179951,
            "end_byte": 179985,
            "node_type": "stmt_range",
            "sha256": "3df152e2c042ffdb",
            "line": 123
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 178260,
              "end_byte": 178375,
              "node_type": "call",
              "sha256": "002e9914f9201c97",
              "line": 89
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 179863,
              "end_byte": 179930,
              "node_type": "call",
              "sha256": "e044bd9590328add",
              "line": 121
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 179981,
                  "end_byte": 179985,
                  "node_type": "call",
                  "sha256": "3d196dadbb83c599",
                  "line": 125
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 179756,
                  "end_byte": 179930,
                  "node_type": "function_definition",
                  "sha256": "4e16ce27c1853c12",
                  "line": 121
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
      "expression": "c2 && c3 && c4 && c5",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 629,
            "end_byte": 238793,
            "node_type": "if_statement",
            "sha256": "93d6d38038ae37cf",
            "line": 26
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 175829,
            "end_byte": 175860,
            "node_type": "if_statement",
            "sha256": "62007d9547e1483a",
            "line": 62
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 178033,
            "end_byte": 178058,
            "node_type": "if_statement",
            "sha256": "55d21f3f7ea5032e",
            "line": 83
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ],
          "via": [
            {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 179939,
              "end_byte": 179942,
              "node_type": "call",
              "sha256": "e9c88886e6534631",
              "line": 122
            }
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179243,
            "end_byte": 179262,
            "node_type": "for_statement",
            "sha256": "17dab9cab6e7517a",
            "line": 112
          },
          "kind": "loop",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179357,
            "end_byte": 179561,
            "node_type": "for_statement",
            "sha256": "bdaafb7e6e51d94d",
            "line": 116
          },
          "kind": "loop",
          "arm": "then",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Copies browser, mail, FTP, chat and wallet files only from the app folders that exist on the victim.",
      "then": {
        "min_conditions": 4,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "linux",
          "file_present": [
            "~/.config/filezilla/sitemanager.xml",
            "~/.purple/accounts.xml",
            "~/.config/Exodus/exodus.conf.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179254,
            "end_byte": 179262,
            "node_type": "block",
            "sha256": "696ee007b36b6393",
            "line": 112
          },
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 179428,
            "end_byte": 179561,
            "node_type": "block",
            "sha256": "723eb1fe17971ecf",
            "line": 116
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 178803,
              "end_byte": 178834,
              "node_type": "call",
              "sha256": "2c50bc0385406196",
              "line": 101
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 179254,
                  "end_byte": 179262,
                  "node_type": "call",
                  "sha256": "696ee007b36b6393",
                  "line": 112
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 178384,
                  "end_byte": 178834,
                  "node_type": "function_definition",
                  "sha256": "45f6b9d4b4dbfcd3",
                  "line": 90
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
      "exfil",
      "cred_read"
    ]
  },
  "obfuscation": {
    "level": "moderate",
    "techniques": [
      "base64-encoded stages run with exec(b64decode(...)), one per OS branch",
      "very long single lines (embedded PE as a bytes literal inside the Windows stage)",
      "single-letter aliases for imports and constants in the Linux stage",
      "RC4 encryption of the exfiltrated archive"
    ],
    "decoded": true,
    "unrecovered": [
      {
        "file": "setup.py",
        "reason": "Windows stage embeds a compiled PE executable (written to %TEMP% and started); compiled code not analysed statically"
      }
    ]
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://api[.]telegram[.]org/bot6003…/sendDocument",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "telegram-bot infostealer (LWSR$ / .wsr archive)",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs base64-hidden stages at install: on Windows it drops and starts an embedded executable, on Linux it steals browser, FTP, chat and crypto-wallet files plus host details and uploads them encrypted to a Telegram bot, after an ISP check that backs off on Google and Mythic Beasts networks.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "Embedded Windows PE not analysed; its own gates are unknown.",
    "Seven artifact sources recorded as one target_artifact condition (one shared exists filter) rather than one gate per source.",
    "unrecovered code",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [
      {
        "id": "d1",
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
        "output_sha256": "3ce105937cccc1ba"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "5d6726fb6a80ebfc"
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
    "conditions_out_of_set": 5,
    "guard_candidates": 1,
    "gates_in_set": 0,
    "gates_out_of_set": 4,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "g1",
      "g2",
      "g3",
      "g4"
    ],
    "anchor_refusals": 0
  }
}
```
