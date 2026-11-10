# pypi 3m-promo-link-gen@1.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-sonnet-5-5)

## Summary

`setup.py` runs its whole payload at module top level, so it executes on every build of the sdist. It starts threads that look for Discord clients, browser profiles (Opera, Chrome, Brave, Yandex, Edge), wallet and Steam folders, and keyword-named files on the Desktop, Downloads and Documents. Each source is behind an existence check (five target-artifact gates). Tokens, passwords and cookies are decrypted with the Windows DPAPI and posted to a Discord webhook, and matching files go to transfer[.]sh. The payload needs Windows: `from ctypes import windll` at the top fails elsewhere.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, inline_shell; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 (c1: target_artifact exists [%APPDATA%/Opera Software/Opera GX Stable, %APPDATA%/Opera Software/Opera Stable, %APPDATA%/Opera Software/Opera Neon/User Data/Default, %LOCALAPPDATA%/Google/Chrome/User Data, %LOCALAPPDATA%/Google/Chrome SxS/User Data, %LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data, %LOCALAPPDATA%/Yandex/YandexBrowser/User Data, %LOCALAPPDATA%/Microsoft/Edge/User Data]) | then | 1 | cred_read, exfil, delete_file | os=win32; file_present=%LOCALAPPDATA%/Google/Chrome/User Data |
| g2 | setup_py | c2 (c2: target_artifact exists [%APPDATA%/Discord/Local State, %APPDATA%/Lightcord/Local State, %APPDATA%/discordcanary/Local State, %APPDATA%/discordptb/Local State]) | then | 1 | cred_read, exfil | os=win32; file_present=%APPDATA%/Discord/Local State |
| g3 | setup_py | c3 (c3: target_artifact exists [%APPDATA%/Opera Software/Opera GX Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Neon/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome SxS/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Yandex/YandexBrowser/User Data/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/atomic/Local Storage/leveldb, %APPDATA%/Exodus/exodus.wallet, C:\Program Files (x86)\Steam\config, %APPDATA%/NationsGlory/Local Storage/leveldb]) | then | 1 | spawn_process, exfil, delete_file | os=win32; file_present=%APPDATA%/Exodus/exodus.wallet |
| g4 | setup_py | c3 && c4 (c3: target_artifact exists [%APPDATA%/Opera Software/Opera GX Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/Opera Software/Opera Neon/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Google/Chrome SxS/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Yandex/YandexBrowser/User Data/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn, %LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn, %APPDATA%/atomic/Local Storage/leveldb, %APPDATA%/Exodus/exodus.wallet, C:\Program Files (x86)\Steam\config, %APPDATA%/NationsGlory/Local Storage/leveldb]; c4: target_artifact exists C:\Program Files (x86)\Steam\config/loginusers.vdf) | then | 2 | cred_read | os=win32; file_present=C:\Program Files (x86)\Steam\config, C:\Program Files (x86)\Steam\config\loginusers.vdf |
| g5 | setup_py | c5 (c5: target_artifact exists [%USERPROFILE%/Desktop/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt, %USERPROFILE%/Downloads/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt, %USERPROFILE%/Documents/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt, %USERPROFILE%/Desktop/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*, %USERPROFILE%/Downloads/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*, %USERPROFILE%/Documents/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*]) | then | 1 | exfil | os=win32; file_present=%USERPROFILE%/Documents/passw.txt |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability

Grounding: 5 of 5 conditions and 5 of 5 gates from the candidate set.

## Requirements

- os: win32 (top-level 'from ctypes import windll' fails on non-Windows, and the browser, Discord and Steam paths use %APPDATA% and %LOCALAPPDATA%)
- network: discord[.]com:443 (stolen data is posted to a Discord webhook; tokens are validated against the Discord API)
- network: transfer[.]sh:443 (files found on Desktop, Downloads and Documents are uploaded there)
- network: pypi[.]org:443 (requests and pycryptodome are pip-installed when missing)

## Behaviour

- Ungated: download
- Gated: cred_read, exfil, delete_file, spawn_process

## Notes

- Unrecovered: none. The only code file is `setup.py` (read in full); `main.py` is an identical copy that is not run at install.
- Missing `requests` or `pycryptodome` is fixed with a shell `pip install` (dropped as bootstrap plumbing).
- The `Trust()` / `DETECTED` check can never be true (`len(...) < -1`), so it is not a gate.
- Setup metadata borrows a well-known colour library's author and keyword and describes "auto betting"; it does not match the code.
- Browser, Discord, wallet and Steam paths are read from the path tables in `GatherAll()` (environment variables written as `%APPDATA%`/`%LOCALAPPDATA%`). The Desktop, Downloads and Documents file names stay partial: they come from `os.listdir` on the victim's folders.
- The Steam `loginusers.vdf` check (c4) only stops the call of `ZipThings` for Steam; wallet folders reach the same zip-and-upload code with c3 alone.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "3m-promo-link-gen",
    "version": "1.0",
    "archive_sha256": "f0f3d90013b829a163d5ac1a170eb6c31a7c1a5ae2bc452ad3c5d19c60edc33a",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/3m-promo-link-gen-1.0.tar.gz",
    "package_root": "layer0/3m-promo-link-gen-1.0",
    "cluster_key": "90724b26ff2ac1713a9ab3f131b8fcc15c273dc12248757fef3afba2c2226058",
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
      "setup.py: package code read in full (696 lines, one file; 3m-promo-link-gen/main.py is a byte-identical copy and is not run at install); nothing unread, nothing bundled.",
      "Line 11 imports windll from ctypes at top level. On Linux or macOS this raises ImportError before any stealer code, so the payload only runs on Windows. This is an implicit platform dependence, not a deliberate check, so it is a requirement (os win32), not a gate.",
      "Lines 34-38: a missing requests or Crypto module triggers a shell 'pip install' of requests or pycryptodome. Dependency bootstrap plumbing, dropped as a candidate; needs PyPI reachable.",
      "Trust() at line 99 sets DETECTED only if len(...) < -1, which is never true, so the 'if DETECTED: return' and 'if not DETECTED' branches are dead and not gates.",
      "Stealer functions run as threading.Thread targets started from GatherAll() (called at line 663); payload sinks are given directly in each gate region or through a resolved call/def hop.",
      "The Discord API calls (token check, profile, billing, friends) use the stolen token and are not recorded as exfil endpoints; the stolen data goes to the webhook in line 21 and to transfer[.]sh.",
      "c5: the user folder is %TEMP% cut at '\\AppData' (%USERPROFILE% by default). KiwiFile keeps Desktop, Downloads and Documents entries whose lowercased name holds a key_wordsFiles keyword: a file named '*.txt' (line 602) or a folder (line 605), whose files KiwiFolder uploads (line 586).",
      "c5 value: the last keywords 'prox' 'binance' 'Electrum' 'Mycelium' lack commas and join into one string with capitals that never matches a lowercased name, so they are left out. Recipe file passw.txt is built from keyword 'passw' and the '.txt' test.",
      "Metadata copies the author field and keyword of a well-known colour library (impersonation, name not recorded); the setup() description does not match the code."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "top-level 'from ctypes import windll' fails on non-Windows, and the browser, Discord and Steam paths use %APPDATA% and %LOCALAPPDATA%"
    },
    {
      "axis": "network",
      "value": "discord[.]com:443",
      "reason": "stolen data is posted to a Discord webhook; tokens are validated against the Discord API"
    },
    {
      "axis": "network",
      "value": "transfer[.]sh:443",
      "reason": "files found on Desktop, Downloads and Documents are uploaded there"
    },
    {
      "axis": "network",
      "value": "pypi[.]org:443",
      "reason": "requests and pycryptodome are pip-installed when missing"
    }
  ],
  "conditions": [
    {
      "id": "c1",
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c2",
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c3",
      "category": "target_artifact",
      "api": "os.path.exists",
      "operator": "exists",
      "value": [
        "%APPDATA%/Opera Software/Opera GX Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%APPDATA%/Opera Software/Opera Stable/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%APPDATA%/Opera Software/Opera Neon/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Google/Chrome SxS/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/BraveSoftware/Brave-Browser/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Yandex/YandexBrowser/User Data/HougaBouga/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%LOCALAPPDATA%/Microsoft/Edge/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn",
        "%APPDATA%/atomic/Local Storage/leveldb",
        "%APPDATA%/Exodus/exodus.wallet",
        "C:\\Program Files (x86)\\Steam\\config",
        "%APPDATA%/NationsGlory/Local Storage/leveldb"
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c4",
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
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "os.path.isfile / os.path.isdir",
      "operator": "exists",
      "value": [
        "%USERPROFILE%/Desktop/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt",
        "%USERPROFILE%/Downloads/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt",
        "%USERPROFILE%/Documents/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*.txt",
        "%USERPROFILE%/Desktop/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*",
        "%USERPROFILE%/Downloads/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*",
        "%USERPROFILE%/Documents/*{passw,mdp,motdepasse,mot_de_passe,login,secret,account,acount,paypal,banque,metamask,wallet,crypto,exodus,discord,2fa,code,memo,compte,token,backup}*/*"
      ],
      "value_recovered": "plain",
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
      "in_scope": true,
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
      "purpose_reason": "each browser profile folder must exist before its tokens, saved passwords and cookies are read",
      "then": {
        "behaviours": [
          "cred_read",
          "exfil",
          "delete_file"
        ],
        "env_recipe": {
          "os": "win32",
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
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 14602,
              "end_byte": 14641,
              "node_type": "call",
              "sha256": "ebffe1847187ce53",
              "line": 404
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 15041,
              "end_byte": 15064,
              "node_type": "call",
              "sha256": "861053502e27aa85",
              "line": 411
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 15581,
              "end_byte": 15600,
              "node_type": "call",
              "sha256": "1e08532105137688",
              "line": 426
            },
            "witness": []
          }
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "in_set"
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c2",
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
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "a Discord client folder with a Local State file must exist before its stored tokens are decrypted and sent",
      "then": {
        "behaviours": [
          "cred_read",
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
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
              "start_byte": 18489,
              "end_byte": 18519,
              "node_type": "call",
              "sha256": "dd8b550bee06aee4",
              "line": 488
            },
            "witness": []
          }
        ],
        "min_conditions": 1
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
      "purpose_reason": "a wallet, browser extension or game-launcher folder must exist before its browser is killed and the folder is zipped and uploaded",
      "then": {
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
              "start_byte": 19518,
              "end_byte": 19547,
              "node_type": "call",
              "sha256": "3b499d2488e38cca",
              "line": 515
            },
            "witness": []
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
        ],
        "min_conditions": 1
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
      "purpose_reason": "for the Steam entry, loginusers.vdf must exist before it is read to check that a password is remembered; the zip and upload after the branch are shared with the other targets and sit under c3 alone (g3)",
      "then": {
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "C:\\Program Files (x86)\\Steam\\config",
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
        ],
        "min_conditions": 2
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
      "purpose_reason": "files and folders on the Desktop, Downloads and Documents whose names match password or wallet keywords must exist before they are uploaded",
      "then": {
        "behaviours": [
          "exfil"
        ],
        "env_recipe": {
          "os": "win32",
          "file_present": [
            "%USERPROFILE%/Documents/passw.txt"
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
          },
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
          },
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
        ],
        "min_conditions": 1
      },
      "else": null,
      "provenance": "in_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "download"
    ],
    "gated": [
      "cred_read",
      "exfil",
      "delete_file",
      "spawn_process"
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
        "indicator": "hxxps://discord[.]com/api/webhooks/1072…",
        "role": "exfil_sink"
      },
      {
        "indicator": "hxxps://transfer[.]sh/",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "discord token and browser data stealer (self-labelled Fade Stealer in embed text)",
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py runs a Windows credential stealer at install: Discord tokens, browser passwords and cookies, wallet and Steam folders and keyword-matched documents are collected and posted to a Discord webhook and transfer[.]sh. The package metadata is a decoy.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
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
        "note": "plumbing: __import__ probe only decides whether to pip install a dependency; both sides reach the same payload, so it is a requirement",
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
        "note": "plumbing: try/except around the dependency probe k_ee61418539; the handler only runs pip install and both sides reach the same payload",
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
    "conditions_out_of_set": 0,
    "guard_candidates": 10,
    "gates_in_set": 5,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
