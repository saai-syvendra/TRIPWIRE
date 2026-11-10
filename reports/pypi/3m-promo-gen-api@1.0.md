# pypi 3m-promo-gen-api@1.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

`setup.py` runs on every sdist build and, at module level, starts a Discord and browser credential stealer ("Fade Stealer") in threads. It reads Discord tokens from browser and Discord client storage, saved passwords and cookies from Chromium-family profiles (decrypted with the Windows DPAPI master key), zips wallet and Steam folders after killing the owning app's process, and searches Desktop, Downloads and Documents for credential-named files. Everything is posted to a Discord webhook or transfer[.]sh. The gates are all target-artifact existence checks (browser profile, Discord `Local State`, wallet and Steam folders, Steam `loginusers.vdf` with a remembered login, credential-named files), so a clean VM needs decoy Windows profile data to open them. The module-level `windll` import fails off Windows, so the install needs os win32.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g2 | setup_py | c2 (c2: target_artifact exists [%APPDATA%/Opera Software/Opera GX Stable, %APPDATA%/Opera Software/Opera Stable, %APPDATA%/Opera Software/Opera Neon/User Data/Default, %LOCALAPPDATA%/Google/Chrome/User Data, %LOCALAPPDATA%/Google/Chrome SxS/User Data, %LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data, %LOCALAPPDATA%/Yandex/YandexBrowser/User Data, %LOCALAPPDATA%/Microsoft/Edge/User Data]) | then | 1 | cred_read, exfil | os=win32; file_present=%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data, %LOCALAPPDATA%\Google\Chrome\User Data\Local State |
| g3 | setup_py | c3 (c3: target_artifact exists [%APPDATA%/Discord/Local State, %APPDATA%/Lightcord/Local State, %APPDATA%/discordcanary/Local State, %APPDATA%/discordptb/Local State]) | then | 1 | cred_read, exfil | os=win32; file_present=%APPDATA%\Discord\Local State |
| g4 | setup_py | c4 (c4: target_artifact exists [%APPDATA%/atomic/Local Storage/leveldb, %APPDATA%/Exodus/exodus.wallet, %APPDATA%/NationsGlory/Local Storage/leveldb, %APPDATA%/Opera Software/Opera GX Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Neon/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome SxS/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Yandex/YandexBrowser/User Data/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn]) | then | 1 | spawn_process, exfil | os=win32; file_present=%APPDATA%\Exodus\exodus.wallet |
| g5 | setup_py | c10 && c5 && c7 (c10: target_artifact exists C:\Program Files (x86)\Steam\config; c5: target_artifact exists C:\Program Files (x86)\Steam\config/loginusers.vdf; c7: file_content includes RememberPassword"		"1") | then | 3 | exfil | os=win32; file_present=C:\Program Files (x86)\Steam\config\loginusers.vdf |
| g6 | setup_py | c6 (c6: target_artifact exists <Desktop\|Downloads\|Documents>/<name>: a file whose name contains .txt and whose lowercased name contains one of passw, mdp, motdepasse, mot_de_passe, login, secret, account, acount, paypal, banque, metamask, wallet, crypto, exodus, discord, 2fa, code, memo, compte, token, backup, proxbinanceElectrumMycelium) | then | 1 | exfil | os=win32; file_present=%USERPROFILE%\Desktop\passw.txt |
| g7 | setup_py | c8 && c9 (c8: target_artifact exists <Desktop\|Downloads\|Documents>/<name>: a directory whose lowercased name contains one of passw, mdp, motdepasse, mot_de_passe, login, secret, account, acount, paypal, banque, metamask, wallet, crypto, exodus, discord, 2fa, code, memo, compte, token, backup, proxbinanceElectrumMycelium; c9: target_artifact exists <keyword-matching folder>/<entry>: each entry is a file; the walk returns at the first entry that is not) | then | 2 | exfil | os=win32; file_present=%USERPROFILE%\Desktop\passw\notes.txt |

Gate intent: g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/enables/data_availability; g7 activate/enables/data_availability

Grounding: 8 of 9 conditions and 5 of 6 gates from the candidate set; out of set, pending verification: c7, g5.

## Requirements

- os: win32 (module-level `from ctypes import windll` and DPAPI CryptUnprotectData calls only work on Windows)
- network: discord[.]com:443 (stolen data is posted to a Discord webhook; Discord API is also queried to validate tokens)
- network: transfer[.]sh:443 (files found by the Kiwi search are uploaded here)
- other: requests and pycryptodome importable, or pip with network access (setup.py imports requests and Crypto.Cipher after a pip install fallback)

## Behaviour

- Ungated: spawn_process, exfil
- Gated: cred_read, exfil, spawn_process

## Notes

- Webhook id and token are redacted. Discord API calls, ipify and the keyword site list are not recorded as endpoints: they validate stolen tokens, look up the public IP or are plain strings.
- `Trust()` can never set `DETECTED`, so the `if not DETECTED` branches always run.
- c7 and g5 (Steam `RememberPassword` check) are out of the candidate set.
- g5 covers the Steam call of `ZipThings`. Its c5 and c7 returns sit in the `elif` block, so the archive code after that block is reached by fall-through, and non-Steam calls share that code under g4.
- The `taskkill` before archiving frees the target app's files. It is `spawn_process`, not defense evasion: the processes are browsers, wallets and Steam, not security tools.
- The Kiwi search is two gates: g6 for a matching `.txt` file and g7 for a matching folder whose entries are files. The filename keyword filter (line 601) is folded into the values of c6 and c8.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "3m-promo-gen-api",
    "version": "1.0",
    "archive_sha256": "6fcda7ccf5f80bc6ec0a404ca9ba60ffcd08628f1204df207816614e60362f75",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/3m-promo-gen-api-1.0.tar.gz",
    "package_root": "layer0/3m-promo-gen-api-1.0",
    "cluster_key": "2f1ca75739855d1eb69991ea0ac6ea6c486b2a764a364e18ed41477e5cecdf6e",
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
      "setup.py: package code read in full (696 lines), no bundled third-party code, nothing unread. setup.cfg only holds egg_info tag settings.",
      "Top-level `from ctypes import windll, wintypes` raises ImportError off Windows before any payload runs, so the install effectively needs os win32. Recorded as a requirement, not a gate.",
      "Dropped g1 (try __import__ of requests / Crypto, else `pip install` via Popen shell=True): dependency bootstrap plumbing, both sides end with the libraries present.",
      "Trust(): `len(tim)<-1` can never be true, so DETECTED is always False and the `if not DETECTED` branches always run. Not a gate.",
      "GatherAll() and the Kiwi search run unconditionally at module level and start the payload functions as threading.Thread targets. Gate regions sit inside those functions, so no bind hops are needed.",
      "The Kiwi search filters on a filename keyword list (`worf in file.lower()`, line 601) and takes only .txt names for single files (line 602). Both are folded into the values of c6 and c8, not recorded as separate conditions.",
      "Kiwi splits into g6 (c6, a matching .txt file, line 602) and g7 (c8 && c9, a matching folder at line 605, then KiwiFolder's child-file early return at line 586). c9 sits in KiwiFolder, whose only caller is line 607, so it nests under c8.",
      "ZipThings tests one path at line 496, and the caller's table decides what it is: c4 for wallet and extension dirs, c10 for the Steam config dir. `'Steam' in arg` (line 501) reads that table value, not the environment, so it is not a condition.",
      "g5 is the Steam call of ZipThings. The c5 and c7 returns sit in the elif block, so the archive region after it is reached by fall-through on that call; non-Steam calls share that code under g4. taskkill (line 497) runs for Steam on c10 alone.",
      "LoadUrlib: uploadToken and upload always pass a non-empty headers dict, so their webhook posts run the headers request at line 92, not line 95.",
      "Repair: c2, c3, c4 and c5 now list every path from the GatherAll tables (lines 519-540), %APPDATA% and %LOCALAPPDATA% being the os.getenv values at lines 41-42. c6, c8 and c9 stay partial: the tested path ends in a name os.listdir returns at run time, so only the filter is known.",
      "Keyword list for c6 and c8: KiwiFile only ever gets key_wordsFiles (line 654); key_wordsFolder is unused. Missing commas at lines 647-650 fuse the last four strings into proxbinanceElectrumMycelium, which holds capitals and so can never match file.lower().",
      "g6 and g7 recipes: Kiwi builds the search roots from TEMP up to \\AppData (line 611) plus /Desktop, the name passw is the first keyword and .txt is what line 602 requires. The child name notes.txt in g7 is free: line 586 only needs each entry to be a file.",
      "Final unconditional uploads: wppassw.txt and wpcook.txt (line 570) and the Kiwi file listing (line 681) go to the webhook. Webhook id and token are redacted in the endpoint list."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "module-level `from ctypes import windll` and DPAPI CryptUnprotectData calls only work on Windows"
    },
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "stolen data is posted to a Discord webhook; Discord API is also queried to validate tokens"
    },
    {
      "axis": "network",
      "value": "transfer[.]sh:443",
      "reason": "files found by the Kiwi search are uploaded here"
    },
    {
      "axis": "other",
      "value": "requests and pycryptodome importable, or pip with network access",
      "reason": "setup.py imports requests and Crypto.Cipher after a pip install fallback"
    }
  ],
  "conditions": [
    {
      "id": "c2",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": [
        "%APPDATA%/Opera Software/Opera GX Stable",
        "%APPDATA%/Opera Software/Opera Stable",
        "%APPDATA%/Opera Software/Opera Neon/User Data/Default",
        "%LOCALAPPDATA%/Google/Chrome/User Data",
        "%LOCALAPPDATA%/Google/Chrome SxS/User Data",
        "%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data",
        "%LOCALAPPDATA%/Yandex/YandexBrowser/User Data",
        "%LOCALAPPDATA%/Microsoft/Edge/User Data"
      ],
      "value_recovered": "plain",
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": [
        "%APPDATA%/Discord/Local State",
        "%APPDATA%/Lightcord/Local State",
        "%APPDATA%/discordcanary/Local State",
        "%APPDATA%/discordptb/Local State"
      ],
      "value_recovered": "plain",
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": [
        "%APPDATA%/atomic/Local Storage/leveldb",
        "%APPDATA%/Exodus/exodus.wallet",
        "%APPDATA%/NationsGlory/Local Storage/leveldb",
        "%APPDATA%/Opera Software/Opera GX Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%APPDATA%/Opera Software/Opera Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%APPDATA%/Opera Software/Opera Neon/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Google/Chrome SxS/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Yandex/YandexBrowser/User Data/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
      ],
      "value_recovered": "plain",
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "C:\\Program Files (x86)\\Steam\\config/loginusers.vdf",
      "value_recovered": "plain",
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "<Desktop|Downloads|Documents>/<name>: a file whose name contains .txt and whose lowercased name contains one of passw, mdp, motdepasse, mot_de_passe, login, secret, account, acount, paypal, banque, metamask, wallet, crypto, exodus, discord, 2fa, code, memo, compte, token, backup, proxbinanceElectrumMycelium",
      "value_recovered": "partial",
      "sites": [
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
        }
      ],
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c8",
      "category": "target_artifact",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "<Desktop|Downloads|Documents>/<name>: a directory whose lowercased name contains one of passw, mdp, motdepasse, mot_de_passe, login, secret, account, acount, paypal, banque, metamask, wallet, crypto, exodus, discord, 2fa, code, memo, compte, token, backup, proxbinanceElectrumMycelium",
      "value_recovered": "partial",
      "sites": [
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "<keyword-matching folder>/<entry>: each entry is a file; the walk returns at the first entry that is not",
      "value_recovered": "partial",
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
        }
      ],
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": "C:\\Program Files (x86)\\Steam\\config",
      "value_recovered": "plain",
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
      "provenance": "in_set",
      "in_scope": true
    },
    {
      "id": "c7",
      "category": "file_content",
      "api": "in",
      "operator": "includes",
      "value": "RememberPassword\"\t\t\"1\"",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "open",
        "target": "*/loginusers.vdf",
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
      "provenance": "out_of_set",
      "in_scope": true
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
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "steals Discord tokens, saved passwords and cookies only from browser profiles that exist",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
            "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State"
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
      "else": null
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
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "steals Discord client tokens only when a Discord client profile with Local State exists",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%\\Discord\\Local State"
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
            "sink_kind": "decode",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 17768,
              "end_byte": 17819,
              "node_type": "call",
              "sha256": "c90710b328ef37d1",
              "line": 477
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
      "else": null
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
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "kills the wallet / browser process and zips and uploads the folder only when it exists",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "spawn_process",
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%APPDATA%\\Exodus\\exodus.wallet"
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
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "setup_py",
      "expression": "c10 && c5 && c7",
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
            "c10"
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
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Steam session files are zipped and uploaded only when loginusers.vdf exists and has a remembered login",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "exfil"
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
      "else": null
    },
    {
      "gate_id": "g6",
      "hook": "setup_py",
      "expression": "c6",
      "guards": [
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
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "uploads credential-named .txt files from user folders only when such a file exists",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%\\Desktop\\passw.txt"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23911,
            "end_byte": 24002,
            "node_type": "block",
            "sha256": "f75351c04eff859f",
            "line": 603
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
      "else": null
    },
    {
      "gate_id": "g7",
      "hook": "setup_py",
      "expression": "c8 && c9",
      "guards": [
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
            "c8"
          ]
        },
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
            "c9"
          ]
        }
      ],
      "provenance": "in_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "uploads the files of a credential-named folder only when the folder exists and its entries are files",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%\\Desktop\\passw\\notes.txt"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 24074,
            "end_byte": 24170,
            "node_type": "block",
            "sha256": "3c7304f554ab42b7",
            "line": 606
          },
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 23387,
            "end_byte": 23556,
            "node_type": "stmt_range",
            "sha256": "25d5ca999d228eec",
            "line": 587
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
                  "start_byte": 24116,
                  "end_byte": 24143,
                  "node_type": "call",
                  "sha256": "b41c52515edc41a5",
                  "line": 607
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 23161,
                  "end_byte": 23607,
                  "node_type": "function_definition",
                  "sha256": "4d25d6ab7787af6b",
                  "line": 579
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 23440,
                  "end_byte": 23473,
                  "node_type": "call",
                  "sha256": "8fb40c58d38d91c8",
                  "line": 589
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
      "else": null
    }
  ],
  "behaviours": {
    "ungated": [
      "spawn_process",
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
      "leetspeak labels in output strings",
      "no-op exec('') and builtins re-import at top of file"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://discord[.]com/api/webhooks/1069…",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://transfer[.]sh/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "Fade Stealer",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a Discord and browser credential stealer at install time: it harvests Discord tokens, saved passwords and cookies, wallet and Steam files, and credential-named documents, and posts them to a Discord webhook and transfer[.]sh. The only gates are existence checks for the victim data.",
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
        "reason_code": "not_environmental",
        "note": "try __import__ of requests / Crypto, handler pip-installs the missing library: dependency bootstrap plumbing",
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
        "reason_code": "not_environmental",
        "note": "guard of the dependency bootstrap try/except; both branches end with the libraries available",
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
    "conditions_in_set": 8,
    "conditions_out_of_set": 1,
    "guard_candidates": 10,
    "gates_in_set": 5,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c7",
      "g5"
    ],
    "anchor_refusals": 0
  }
}
```
