# pypi attr_property@0.2.101

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

setup.py runs at install. After the normal setup() call (metadata copied from aiohttp-proxy) it reads USERPROFILE, exits unless sys.argv[1] is `install` or contains `bdist` (true for a pip install of the sdist), runs `pythonw -m pip install psutil`, writes a base64-encoded stage to `%USERPROFILE%\appdata\local\temp\__pycache__\main.cpython-39.py` and starts it detached with pythonw. The stage is a stickytape bundle of a Windows stealer: it posts username and hostname to `hxxp://185[.]121[.]81[.]66:1488`, takes a screenshot, copies Chromium-family logins, cookies and MetaMask/Phantom extension data, the Exodus wallet and backup passphrase, Telegram tdata, FileZilla server lists and WhatsApp leveldb, each only if the target file or folder exists (g2-g9), then zips and uploads the log. Unless a `DEBUG` file sits in the drop folder it deletes the drop and log folders (g10). To open everything: Windows with USERPROFILE set, a real pip install of the sdist, and the target artifacts planted.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script, detached_child; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 && (c2 \|\| c3) (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist) | then | 2 | write_file, spawn_process, recon, exfil | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install) |
| g2 | setup_py | c1 && (c2 \|\| c3) && c4 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c4: target_artifact exists <chromium browser dir>/user data/default/Login Data) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%LOCALAPPDATA%/Google/Chrome/User Data/Default/Login Data |
| g3 | setup_py | c1 && (c2 \|\| c3) && c5 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c5: target_artifact exists <chromium browser dir>/user data/default/network/Cookies) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%LOCALAPPDATA%/Google/Chrome/User Data/Default/Network/Cookies |
| g4 | setup_py | c1 && (c2 \|\| c3) && c6 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c6: target_artifact exists <chromium browser dir>/user data/default/local extension settings/{nkbihfbeogaeaoehlefnkodbefgpgknn (MetaMask), bfnaelmomeimhlpmgjnjophhpkkoljpa (Phantom)}) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn |
| g5 | setup_py | c1 && (c2 \|\| c3) && c7 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c7: target_artifact exists <...>/exodus/exodus.wallet) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%APPDATA%/Exodus/exodus.wallet |
| g6 | setup_py | c1 && (c2 \|\| c3) && c8 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c8: target_artifact == passphrase.json) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%APPDATA%/Exodus/backups/passphrase.json |
| g7 | setup_py | c1 && (c2 \|\| c3) && c9 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c9: target_artifact exists <...>/telegram desktop/tdata) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%APPDATA%/Telegram Desktop/tdata |
| g8 | setup_py | c1 && (c2 \|\| c3) && c10 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c10: target_artifact in [recentservers.xml, sitemanager.xml]) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%APPDATA%/FileZilla/sitemanager.xml |
| g9 | setup_py | c1 && (c2 \|\| c3) && c11 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c11: target_artifact exists <...>/whatsapp/local storage/leveldb) | then | 3 | cred_read | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_present=%APPDATA%/WhatsApp/Local Storage/leveldb |
| g10 | setup_py | c1 && (c2 \|\| c3) && c12 (c1: runtime_version >= [3, 5, 3] [inherited]; c2: sys.argv == install; c3: sys.argv includes bdist; c12: file_or_dir_exists not_exists %USERPROFILE%/appdata/local/temp/__pycache__/DEBUG) | then | 3 | delete_file | runtime_version=3.5.3; package_manager=pip install of the sdist (setup.py bdist_wheel or setup.py install); file_absent=%USERPROFILE%/appdata/local/temp/__pycache__/DEBUG |

Gate intent: g1 activate/enables/unclear; g2 activate/enables/data_availability; g3 activate/enables/data_availability; g4 activate/enables/data_availability; g5 activate/enables/data_availability; g6 activate/enables/data_availability; g7 activate/enables/data_availability; g8 activate/enables/data_availability; g9 activate/enables/data_availability; g10 activate/enables/unclear

Grounding: 1 of 12 conditions and 0 of 10 gates from the candidate set; out of set, pending verification: c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10.

## Requirements

- os: win32 (os.environ['USERPROFILE'] is read unconditionally after setup() (KeyError elsewhere); stage uses pythonw.exe, winreg, ctypes.windll, win32com and C:/ paths)
- other: env var USERPROFILE set (read without a default in setup.py and in the stage's paths/path_search modules)
- installed_tool: pythonw.exe (stage and pip are run with pythonw.exe from the interpreter's folder)
- network: 185[.]121[.]81[.]66:1488 (stage posts host details to /receive_details and the zipped log to /receive_log)
- network: pypi[.]org:443, files[.]pythonhosted[.]org:443 ('pythonw -m pip install psutil' before the stage starts; the stage imports psutil)
- other: pywin32 importable (win32api, pywintypes, pythoncom) (telegram plugin imports win32com.client at module load; pypiwin32 is in install_requires)

## Behaviour

- Ungated: none
- Gated: write_file, spawn_process, recon, exfil, cred_read, delete_file

## Notes

- The Python >= 3.5.3 guard (c1) is inherited from the impersonated project's setup.py.
- Windows is a requirement, not a gate: USERPROFILE is read with no default, so setup.py raises KeyError on Linux before the argv check.
- Stage-2 conditions are cited in derived files d2-d8, which are extracted from the stickytape bundle by a new candidate decoder (`decoders/stickytape_module.py`). d1 comes from a second new candidate decoder (`decoders/b64_wrapper_drop.py`). Both decoders need review.
- The exfil and recon payload witnesses stop at setup.py's `run()` because the stage is launched as a separate process by a computed path.
- Log strings in the stage are in Russian.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "attr_property",
    "version": "0.2.101",
    "archive_sha256": "ece7a75a7aa98dfa333b24c11af8512f91976a2167d6648c058b062bb95444ae",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/attr_property-0.2.101.tar.gz",
    "package_root": "layer0/attr_property-0.2.101",
    "cluster_key": "db3a1e4dd4a429d01767b6735cc092298a2788444a36ce4fe1ddff0cbe8ff3a0",
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
          "detached_child"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: read in full. After setup() it reads USERPROFILE, exits unless argv[1] is 'install' or contains 'bdist', runs 'pythonw -m pip install psutil', writes a base64 stage to %USERPROFILE%/appdata/local/temp/__pycache__/main.cpython-39.py and starts it with pythonw.",
      "The stage is started by Popen with DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP and all std streams piped, so it outlives the install and its errors are hidden (silent_failure, detached_child).",
      "d1 (decoded stage, 2.4 MB stickytape bundle): main body, path_search, tools, logger, config, paths, plugins/* (browsers, decrypt, details, wallets/exodus, filezilla, telegram, whatsapp) read in full; nothing unread.",
      "d1: capitalised duplicates (plugins/Details.py, Filezilla.py, Telegram.py, Whatsapp.py, browsers/Chromium.py, wallets/Exodus.py) have the same size as the lowercase copies and match where read; treated as duplicates.",
      "d1: bundled aiohttp, yarl, multidict, idna, frozenlist, aiosignal, async_timeout, attr, charset_normalizer, aiofiles, aiosqlite, cryptography, mss, win32com, typing_extensions audited by sink search; hits were aiohttp internals.",
      "d2-d8 are the plugin and helper modules extracted from d1's stickytape string literals (stickytape_module decoder) so their checks can be cited.",
      "The candidate isdir(main_dir)/mkdir pair (k_2a0e3f1d70, q_5e13612e45) only creates the drop folder; plumbing, dropped. Folder name __pycache__ and file name main.cpython-39.py mimic a bytecode cache.",
      "if len(sys.argv) == 0: sys.exit() (setup.py:61) can never be true when setup.py runs; not recorded.",
      "Telegram.callback dedupes paths via a class-level set (re-entry within the run, not a gate). Telegram sources also come from the tdesktop.tg registry key, desktop .lnk files and running telegram processes (psutil); all end in the same tdata check (c9).",
      "Stage-2 gates (g2-g9) sit in plugin callbacks reached through asyncio tasks and a folder-name to plugin dict in path_search.search_plugin_paths (folders google, opera software, exodus, telegram desktop, telegram, filezilla, whatsapp under the user profile, C:/, D:/, E:/ and other users' profiles).",
      "Version is read from attr_property/__init__.py and README.md by setup.py (build plumbing). The package modules under attr_property/ are not reached at install.",
      "Stage path: run() (setup.py:106) reaches Popen([pythonw, file]) (:93), which starts the file written from d1; d1 ends with run_until_complete(main()) (d1:363) and the /receive_log post (d1:346) is in main.",
      "Details recon runs from main through plugin.callback() on the other_plugins list (d1:303), not tied statically.",
      "c2/c3 are package_manager: sys.argv[1] is the setup.py command pip or the build frontend passes for the running install (install, bdist_wheel), as opposed to egg_info for metadata only.",
      "c1 (Python >= 3.5.3 raise) is copied from the aiohttp-socks/aiohttp-proxy setup.py the metadata impersonates (only the project name in the message changed); marked inherited."
    ]
  },
  "requirements": [
    {
      "axis": "os",
      "value": "win32",
      "reason": "os.environ['USERPROFILE'] is read unconditionally after setup() (KeyError elsewhere); stage uses pythonw.exe, winreg, ctypes.windll, win32com and C:/ paths"
    },
    {
      "axis": "other",
      "value": "env var USERPROFILE set",
      "reason": "read without a default in setup.py and in the stage's paths/path_search modules"
    },
    {
      "axis": "installed_tool",
      "value": [
        "pythonw.exe"
      ],
      "reason": "stage and pip are run with pythonw.exe from the interpreter's folder"
    },
    {
      "axis": "network",
      "value": [
        "185[.]121[.]81[.]66:1488"
      ],
      "reason": "stage posts host details to /receive_details and the zipped log to /receive_log"
    },
    {
      "axis": "network",
      "value": [
        "pypi[.]org:443",
        "files[.]pythonhosted[.]org:443"
      ],
      "reason": "'pythonw -m pip install psutil' before the stage starts; the stage imports psutil"
    },
    {
      "axis": "other",
      "value": "pywin32 importable (win32api, pywintypes, pythoncom)",
      "reason": "telegram plugin imports win32com.client at module load; pypiwin32 is in install_requires"
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
          "candidate": "k_cf6775aba5",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 515,
            "end_byte": 543,
            "node_type": "comparison_operator",
            "sha256": "1b2f7dda8e05b788",
            "line": 26
          }
        }
      ],
      "provenance": "in_set",
      "inherited": true
    },
    {
      "id": "c2",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "==",
      "value": "install",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1638,
            "end_byte": 1662,
            "node_type": "comparison_operator",
            "sha256": "5cac8381ec46e9c3",
            "line": 64
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "includes",
      "value": "bdist",
      "value_recovered": "plain",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1666,
            "end_byte": 1688,
            "node_type": "comparison_operator",
            "sha256": "5e10a9d9dc16c41e",
            "line": 64
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c4",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "<chromium browser dir>/user data/default/Login Data",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1530,
            "end_byte": 1539,
            "node_type": "call",
            "sha256": "9ecf162ec53297e9",
            "line": 56
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c5",
      "category": "target_artifact",
      "api": "os.path.isfile",
      "operator": "exists",
      "value": "<chromium browser dir>/user data/default/network/Cookies",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 3793,
            "end_byte": 3802,
            "node_type": "call",
            "sha256": "9ecf162ec53297e9",
            "line": 105
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c6",
      "category": "target_artifact",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "<chromium browser dir>/user data/default/local extension settings/{nkbihfbeogaeaoehlefnkodbefgpgknn (MetaMask), bfnaelmomeimhlpmgjnjophhpkkoljpa (Phantom)}",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6619,
            "end_byte": 6627,
            "node_type": "call",
            "sha256": "d51a0b9adf32efd8",
            "line": 171
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c7",
      "category": "target_artifact",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "<...>/exodus/exodus.wallet",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 670,
            "end_byte": 690,
            "node_type": "call",
            "sha256": "a05754805a5db938",
            "line": 26
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c8",
      "category": "target_artifact",
      "api": "os.walk",
      "operator": "==",
      "value": "passphrase.json",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 1012,
            "end_byte": 1034,
            "node_type": "comparison_operator",
            "sha256": "9c43e11af75cb420",
            "line": 34
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c9",
      "category": "target_artifact",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "<...>/telegram desktop/tdata",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d5",
            "start_byte": 769,
            "end_byte": 786,
            "node_type": "call",
            "sha256": "ca4d20d37f7e1f8d",
            "line": 34
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c10",
      "category": "target_artifact",
      "api": "os.scandir",
      "operator": "in",
      "value": [
        "recentservers.xml",
        "sitemanager.xml"
      ],
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d4",
            "start_byte": 463,
            "end_byte": 513,
            "node_type": "call",
            "sha256": "2460745358ec1249",
            "line": 20
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c11",
      "category": "target_artifact",
      "api": "os.path.isdir",
      "operator": "exists",
      "value": "<...>/whatsapp/local storage/leveldb",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d6",
            "start_byte": 461,
            "end_byte": 474,
            "node_type": "call",
            "sha256": "7c07cfa2fc0e6044",
            "line": 21
          }
        }
      ],
      "provenance": "out_of_set"
    },
    {
      "id": "c12",
      "category": "file_or_dir_exists",
      "api": "os.scandir",
      "operator": "not_exists",
      "value": "%USERPROFILE%/appdata/local/temp/__pycache__/DEBUG",
      "value_recovered": "decoded",
      "in_scope": true,
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 2396408,
            "end_byte": 2396475,
            "node_type": "comparison_operator",
            "sha256": "d6925b8ac16a39e9",
            "line": 353
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
      "expression": "c1 && (c2 || c3)",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "payload only runs when setup.py is invoked as install or bdist* (a real pip install), not for egg_info or other metadata-only calls; c1 is the impersonated project's inherited version guard",
      "then": {
        "min_conditions": 2,
        "behaviours": [
          "write_file",
          "spawn_process",
          "recon",
          "exfil"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1712,
            "end_byte": 3198395,
            "node_type": "stmt_range",
            "sha256": "f313658a045afdb0",
            "line": 68
          }
        ],
        "payload": [
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2582,
              "end_byte": 2646,
              "node_type": "call",
              "sha256": "890ef53a78737a92",
              "line": 103
            },
            "witness": []
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2353,
              "end_byte": 2477,
              "node_type": "call",
              "sha256": "0d74f2991f03494c",
              "line": 93
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 3198370,
                  "end_byte": 3198395,
                  "node_type": "call",
                  "sha256": "57631f660578ddc8",
                  "line": 106
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2267,
                  "end_byte": 2477,
                  "node_type": "function_definition",
                  "sha256": "cb8af7ee8a5208d2",
                  "line": 88
                }
              }
            ]
          },
          {
            "behaviour": "spawn_process",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 2531,
              "end_byte": 2571,
              "node_type": "call",
              "sha256": "fabba980ff89b2d2",
              "line": 100
            },
            "witness": []
          },
          {
            "behaviour": "exfil",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2396173,
              "end_byte": 2396253,
              "node_type": "call",
              "sha256": "8f83f951606683a6",
              "line": 346
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 3198370,
                  "end_byte": 3198395,
                  "node_type": "call",
                  "sha256": "57631f660578ddc8",
                  "line": 106
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2267,
                  "end_byte": 2477,
                  "node_type": "function_definition",
                  "sha256": "cb8af7ee8a5208d2",
                  "line": 88
                }
              },
              {
                "hop": "run_file",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2353,
                  "end_byte": 2477,
                  "node_type": "call",
                  "sha256": "0d74f2991f03494c",
                  "line": 93
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2396762,
                  "end_byte": 2396768,
                  "node_type": "call",
                  "sha256": "ea1a0f9102305e02",
                  "line": 363
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2393601,
                  "end_byte": 2396708,
                  "node_type": "function_definition",
                  "sha256": "2032c2d7cf0cef8c",
                  "line": 267
                }
              }
            ]
          },
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": "d8",
              "start_byte": 1014,
              "end_byte": 1052,
              "node_type": "call",
              "sha256": "4e07182c84d1618a",
              "line": 37
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 3198370,
                  "end_byte": 3198395,
                  "node_type": "call",
                  "sha256": "57631f660578ddc8",
                  "line": 106
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2267,
                  "end_byte": 2477,
                  "node_type": "function_definition",
                  "sha256": "cb8af7ee8a5208d2",
                  "line": 88
                }
              },
              {
                "hop": "run_file",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 2353,
                  "end_byte": 2477,
                  "node_type": "call",
                  "sha256": "0d74f2991f03494c",
                  "line": 93
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2396762,
                  "end_byte": 2396768,
                  "node_type": "call",
                  "sha256": "ea1a0f9102305e02",
                  "line": 363
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2393601,
                  "end_byte": 2396708,
                  "node_type": "function_definition",
                  "sha256": "2032c2d7cf0cef8c",
                  "line": 267
                }
              },
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": "d1",
                  "start_byte": 2394689,
                  "end_byte": 2394706,
                  "node_type": "call",
                  "sha256": "cf49c4e323e80ab0",
                  "line": 303
                }
              }
            ],
            "unresolved": "dynamic_dispatch"
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g2",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c4",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1523,
            "end_byte": 1574,
            "node_type": "if_statement",
            "sha256": "ec3336fa9e717f37",
            "line": 56
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c4"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "stage copies and decrypts Chromium-family saved logins only when a Login Data file exists in a Chrome, Opera, Opera GX or Yandex profile",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Login Data"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 1618,
            "end_byte": 2385,
            "node_type": "stmt_range",
            "sha256": "4708764c7507c7d0",
            "line": 59
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 1692,
              "end_byte": 1714,
              "node_type": "call",
              "sha256": "65814f5e24943903",
              "line": 60
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
      "expression": "c1 && (c2 || c3) && c5",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 3786,
            "end_byte": 3833,
            "node_type": "if_statement",
            "sha256": "e53a11eb52c2aef4",
            "line": 105
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c5"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "browser cookies are copied and decrypted only when a Cookies (or cookies.sqlite) file exists in a Chromium-family profile",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Network/Cookies"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 3853,
            "end_byte": 5281,
            "node_type": "stmt_range",
            "sha256": "4e588b625b4f879e",
            "line": 108
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 3920,
              "end_byte": 3942,
              "node_type": "call",
              "sha256": "65814f5e24943903",
              "line": 109
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g4",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c6",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6612,
            "end_byte": 6658,
            "node_type": "if_statement",
            "sha256": "a1ab62f1d74541cc",
            "line": 171
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c6"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "MetaMask or Phantom extension storage is copied only when its extension settings folder exists in a Chromium-family profile",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%LOCALAPPDATA%/Google/Chrome/User Data/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d2",
            "start_byte": 6694,
            "end_byte": 7226,
            "node_type": "stmt_range",
            "sha256": "b1a71ccd78de1e77",
            "line": 174
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d2",
              "start_byte": 7046,
              "end_byte": 7068,
              "node_type": "call",
              "sha256": "ee07fed3984ee042",
              "line": 183
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g5",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c7",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 667,
            "end_byte": 841,
            "node_type": "if_statement",
            "sha256": "f14c76fa1fb9c599",
            "line": 26
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c7"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Exodus desktop wallet folder is copied only when exodus.wallet exists",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%APPDATA%/Exodus/exodus.wallet"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 705,
            "end_byte": 841,
            "node_type": "stmt_range",
            "sha256": "002bce9203fdf1ad",
            "line": 27
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d3",
              "start_byte": 711,
              "end_byte": 751,
              "node_type": "call",
              "sha256": "aa5356903e5f43d2",
              "line": 27
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g6",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c8",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 1009,
            "end_byte": 1269,
            "node_type": "if_statement",
            "sha256": "cad6a32a6b9f9737",
            "line": 34
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c8"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "an Exodus backup passphrase.json is copied only when such a file is found under the Exodus backups folder",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%APPDATA%/Exodus/backups/passphrase.json"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d3",
            "start_byte": 1057,
            "end_byte": 1269,
            "node_type": "stmt_range",
            "sha256": "4649b40a43f2ca67",
            "line": 35
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d3",
              "start_byte": 1185,
              "end_byte": 1269,
              "node_type": "call",
              "sha256": "5506ea490274cfb4",
              "line": 38
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g7",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c9",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d5",
            "start_byte": 762,
            "end_byte": 807,
            "node_type": "if_statement",
            "sha256": "0ee55c2accefbfbf",
            "line": 34
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c9"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "Telegram Desktop session data is copied only when a tdata folder exists in a found Telegram install",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%APPDATA%/Telegram Desktop/tdata"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d5",
            "start_byte": 819,
            "end_byte": 1658,
            "node_type": "stmt_range",
            "sha256": "ee7cc03ea00692be",
            "line": 37
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d5",
              "start_byte": 1561,
              "end_byte": 1587,
              "node_type": "call",
              "sha256": "e2543bdf27687dde",
              "line": 60
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g8",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c10",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d4",
            "start_byte": 525,
            "end_byte": 558,
            "node_type": "if_statement",
            "sha256": "c54a959cb52b1b68",
            "line": 22
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c10"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "FileZilla saved server lists are copied only when recentservers.xml or sitemanager.xml exists in the FileZilla folder",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%APPDATA%/FileZilla/sitemanager.xml"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d4",
            "start_byte": 570,
            "end_byte": 955,
            "node_type": "stmt_range",
            "sha256": "926c8011786fbe1b",
            "line": 25
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d4",
              "start_byte": 849,
              "end_byte": 883,
              "node_type": "call",
              "sha256": "be76f1e9c16b7839",
              "line": 32
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g9",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c11",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d6",
            "start_byte": 454,
            "end_byte": 495,
            "node_type": "if_statement",
            "sha256": "9540194250b23b15",
            "line": 21
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c11"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "WhatsApp Desktop local storage is copied only when its leveldb folder exists",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "cred_read"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_present": [
            "%APPDATA%/WhatsApp/Local Storage/leveldb"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d6",
            "start_byte": 515,
            "end_byte": 840,
            "node_type": "stmt_range",
            "sha256": "4b7aaa08ff3b1180",
            "line": 24
          }
        ],
        "payload": [
          {
            "behaviour": "cred_read",
            "sink_kind": "fs_read",
            "sink": {
              "file": "setup.py",
              "derived_from": "d6",
              "start_byte": 748,
              "end_byte": 769,
              "node_type": "call",
              "sha256": "94587da7afb2f570",
              "line": 31
            },
            "witness": []
          }
        ]
      },
      "else": null
    },
    {
      "gate_id": "g10",
      "hook": "setup_py",
      "expression": "c1 && (c2 || c3) && c12",
      "guards": [
        {
          "candidate": "q_9596232560",
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 512,
            "end_byte": 608,
            "node_type": "if_statement",
            "sha256": "daa95e60ea733cfe",
            "line": 26
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 1630,
            "end_byte": 1706,
            "node_type": "if_statement",
            "sha256": "30f3bef377144478",
            "line": 64
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c2",
            "c3"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 2396405,
            "end_byte": 2396675,
            "node_type": "if_statement",
            "sha256": "49b416d4aa7b8620",
            "line": 353
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c12"
          ]
        }
      ],
      "provenance": "out_of_set",
      "polarity": "activate",
      "effect": "enables",
      "purpose": "unclear",
      "purpose_reason": "author debug switch: unless a file named DEBUG sits in the drop folder, the stage deletes the drop folder and its log folder after exfil",
      "then": {
        "min_conditions": 3,
        "behaviours": [
          "delete_file"
        ],
        "env_recipe": {
          "runtime_version": "3.5.3",
          "package_manager": "pip install of the sdist (setup.py bdist_wheel or setup.py install)",
          "file_absent": [
            "%USERPROFILE%/appdata/local/temp/__pycache__/DEBUG"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": "d1",
            "start_byte": 2396493,
            "end_byte": 2396675,
            "node_type": "stmt_range",
            "sha256": "2520159e5df6c2bc",
            "line": 354
          }
        ],
        "payload": [
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": "d1",
              "start_byte": 2396560,
              "end_byte": 2396593,
              "node_type": "call",
              "sha256": "5d84a03789350d41",
              "line": 356
            },
            "witness": []
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
      "cred_read",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "second stage stored as one long base64 literal in setup.py and written to disk",
      "stage is a stickytape single-file bundle of the stealer modules plus vendored libraries",
      "dropped file named main.cpython-39.py in a __pycache__ folder under %TEMP% to look like a bytecode cache"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxp://185[.]121[.]81[.]66:1488",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": "pycache-dropper Windows stealer (stickytape bundle)",
  "claude_assessment": "malicious",
  "assessment_reason": "On a pip install of the sdist on Windows, setup.py drops a base64-encoded stealer into %TEMP%/__pycache__ and starts it detached. The stage steals Chromium passwords, cookies and wallet extensions, Exodus, Telegram, FileZilla and WhatsApp data, takes a screenshot, and posts host details and a zipped log to an IP-based server.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "stage-2 gates are cited in derived files d2-d8 extracted from the stickytape bundle with a new candidate decoder (stickytape_module); check the decoder",
    "out-of-set claim pending verification",
    "payload path not fully traced: recon sink in Details.callback (d8) is reached through plugin.callback() on a list element inside create_task (dynamic_dispatch); the run_file hop into d1 names the dropped file main.cpython-39.py, not the derived file",
    "payload path not fully traced"
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
          "func": "b64",
          "nth": 0,
          "decoder": "b64_wrapper_drop",
          "lang": "py"
        },
        "output_sha256": "20d55e3b032283f5"
      },
      {
        "id": "d2",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/browsers/chromium.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "2f9865ff78a1606e"
      },
      {
        "id": "d3",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/wallets/exodus.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "04b241a646b6e2c9"
      },
      {
        "id": "d4",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/filezilla.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "7cf66eec1522a5f2"
      },
      {
        "id": "d5",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/telegram.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "4ccbbeeb4c0d5a6b"
      },
      {
        "id": "d6",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/whatsapp.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "911dc75292688756"
      },
      {
        "id": "d7",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "path_search.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "713e9b0cecab6cef"
      },
      {
        "id": "d8",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d1"
        },
        "params": {
          "module": "plugins/details.py",
          "decoder": "stickytape_module",
          "lang": "py"
        },
        "output_sha256": "2fb97579e4555efa"
      }
    ],
    "candidate_set": {
      "generator": "gate_extract@88c7907d65",
      "sha256": "22457401e89a5d00"
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
        "candidate": "k_2a0e3f1d70",
        "reason_code": "other",
        "note": "isdir(main_dir) only decides whether to create the drop folder; plumbing, the payload runs either way",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2490,
          "end_byte": 2505,
          "node_type": "call",
          "sha256": "0c7768f672ec7194",
          "line": 97
        }
      },
      {
        "candidate": "q_5e13612e45",
        "reason_code": "other",
        "note": "if not isdir(main_dir): mkdir(main_dir) prepares the drop folder; plumbing, not a gate",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2483,
          "end_byte": 2527,
          "node_type": "if_statement",
          "sha256": "e5d2af022007ef0e",
          "line": 97
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
    "conditions_out_of_set": 11,
    "guard_candidates": 2,
    "gates_in_set": 0,
    "gates_out_of_set": 10,
    "out_of_set_ids": [
      "c2",
      "c3",
      "c4",
      "c5",
      "c6",
      "c7",
      "c8",
      "c9",
      "c10",
      "c11",
      "c12",
      "g1",
      "g2",
      "g3",
      "g4",
      "g5",
      "g6",
      "g7",
      "g8",
      "g9",
      "g10"
    ],
    "anchor_refusals": 0
  }
}
```
