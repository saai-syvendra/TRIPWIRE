# pypi passport-snapchat@99.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py overrides the `install` command (`CustomInstall`), which runs on a normal pip install of the sdist. Its `run` collects host details (OS, hostname, user, cwd, home, resolv.conf, hosts file, interfaces with IPs and MACs, time zone, plus a fingerprint "key" from hashed home-folder names, a localhost:19000 probe and a hashed env var) and POSTs them to hxxps://pypi-index[.]org/process_data with no gate. An atexit hook then reads `~/.pip/pip.conf`; only when it exists and has an `index-url` line with a non-empty value (g1) does it reinstall passport-snapchat from that private index. When `bdist_wheel` is in `sys.argv` (g2), it also downloads the real wheel and moves it into the build output dir, deleting the wheel already there. Opening the gates needs a pip.conf with a private index-url and a wheel build by pip.

## Execution

- **cmdclass** `cmdclass[install] = CustomInstall`: runs setup.py; direct_script, inline_shell; errors hidden.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | cmdclass | c1 && c2 (c1: target_artifact exists ~/.pip/pip.conf; c2: file_content includes index-url) | then | 2 | download, exec_downloaded | file_present=~/.pip/pip.conf |
| g2 | cmdclass | c1 && c2 && c3 (c1: target_artifact exists ~/.pip/pip.conf; c2: file_content includes index-url; c3: sys.argv includes bdist_wheel) | then | 3 | download, write_file, delete_file | file_present=~/.pip/pip.conf; package_manager=bdist_wheel |

Gate intent: g1 activate/enables/data_availability; g2 activate/enables/targeting

Grounding: 1 of 3 conditions and 0 of 2 gates from the candidate set; out of set, pending verification: c2, c3, g1, g2.

## Requirements

- network: pypi-index[.]org:443 (collected host info is POSTed there; failure is swallowed so only the exfil is lost)
- other: the private index named by index-url in ~/.pip/pip.conf must be reachable and serve passport-snapchat (otherwise pip install raises CalledProcessError and _post_install returns before the wheel swap)
- installed_tool: pip (post-install step runs sys.executable -m pip install / download)

## Behaviour

- Ungated: recon, exfil
- Gated: download, exec_downloaded, write_file, delete_file

## Notes

- This is a dependency-confusion package (version 99.0) that covers its tracks by swapping in the genuine internal package.
- The hashed fingerprint checks (`detect_system`) feed a value into the exfiltrated JSON, and a home-folder match skips the loopback GET and the env hash check. Those only fill recon fields, so recon and exfil run either way and they are not gates.
- c2 and c3 and both guards are out of set: the extractor did not see the `index-url` content test or the `sys.argv` test.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "passport-snapchat",
    "version": "99.0",
    "archive_sha256": "8be2bd37d56006cc85f76bd8042cfbaa41f5efe64eeefab96f1f7263a1fae471",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/passport-snapchat-99.0.tar.gz",
    "package_root": "layer0/passport-snapchat-99.0",
    "cluster_key": "0767a217ae37461d2386f0e5c977ba25f0395c1fee4b254d1649c4fa7cc754e0",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = CustomInstall",
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
      },
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
      "setup.py: package code, read in full (344 lines); no other file runs at install. The passport-snapchat/ modules are not imported by setup.py.",
      "CustomInstall.run calls run_me() ungated: collects OS, hostname, user, cwd, home, /etc/resolv.conf, /etc/hosts, interfaces with IPs and MACs, and time zone, then POSTs JSON to hxxps://pypi-index[.]org/process_data.",
      "detect_system() sets a 'key' field (1: SHA-256-hashed folder and file in home on darwin/linux; 2: GET to hxxp://127[.]0[.]0[.]1:19000/certs succeeds; 3: SHA-256-hashed env var name and value). The key itself is only sent as data.",
      "detect_system() is an if/elif chain: a home-folder match skips the loopback GET and the env hash check, so 'optn' stays empty. Those steps only fill recon fields; recon and exfil run either way, so these are not gates.",
      "_post_install is registered with atexit, so it runs when the setup.py process exits, still inside the pip install. g1's conditions c1/c2 are read through get_index(); the decision is the early exit 'if not index_url: return'.",
      "get_index() returns the text after the last '=' on the first line containing index-url, so a line ending in '=' returns empty and exits at line 284. That is the same value c2 tests, not another condition, but Phase 2 must plant a non-empty value.",
      "Python version checks at lines 8-11 and 288 only pick an import or a PYTHONPATH prefix. Those at 110 and 125 decide whether one recon field is filled (time zone, else empty; IP, else UNKNOWN). Recon and exfil run either way. Dropped as plumbing or data collection.",
      "Per-OS branches in get_network_interfaces/get_ip_addresses only change how recon data is read. Dropped as data collection.",
      "Inside g2, os.path.exists(t_dir) picks makedirs+move or unlink-last-file+move; t_dir is sys.argv[-1] (the build output dir), so it is plumbing, not an environment check. The delete happens in the usual case where pip already created that dir.",
      "Line 55 GETs a loopback service (127[.]0[.]0[.]1:19000/certs); the reply goes out as 'optn' to the exfil sink. Local recon, not a remote endpoint, so not in reachability.",
      "pip install failure (CalledProcessError) returns early: needing the private index to answer is a requirement, not a gate. setup() itself is wrapped in try/except: pass.",
      "g2's recipe value bdist_wheel is the literal c3 tests in sys.argv at line 302. The code never checks which frontend started the build, so the recipe names the build command, not a tool."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "pypi-index[.]org:443",
      "reason": "collected host info is POSTed there; failure is swallowed so only the exfil is lost"
    },
    {
      "axis": "other",
      "value": "the private index named by index-url in ~/.pip/pip.conf must be reachable and serve passport-snapchat",
      "reason": "otherwise pip install raises CalledProcessError and _post_install returns before the wheel swap"
    },
    {
      "axis": "installed_tool",
      "value": "pip",
      "reason": "post-install step runs sys.executable -m pip install / download"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "target_artifact",
      "api": "open",
      "operator": "exists",
      "value": "~/.pip/pip.conf",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "open",
        "target": "~/.pip/pip.conf",
        "accessor": "throws"
      },
      "sites": [
        {
          "candidate": "k_ce4a710ce4",
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 6512,
            "end_byte": 6555,
            "node_type": "call",
            "sha256": "10af5ae86cdc2031",
            "line": 262
          }
        }
      ],
      "in_scope": true,
      "provenance": "in_set"
    },
    {
      "id": "c2",
      "category": "file_content",
      "api": "f.readlines()",
      "operator": "includes",
      "value": "index-url",
      "value_recovered": "plain",
      "probe": {
        "kind": "file",
        "callee": "f.readlines",
        "target": "~/.pip/pip.conf",
        "accessor": "content"
      },
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 6673,
            "end_byte": 6692,
            "node_type": "comparison_operator",
            "sha256": "bbf6d7d639ac532b",
            "line": 269
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c3",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "includes",
      "value": "bdist_wheel",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7576,
            "end_byte": 7601,
            "node_type": "comparison_operator",
            "sha256": "4a53bc6ea18e3104",
            "line": 302
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
      "hook": "cmdclass",
      "expression": "c1 && c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7020,
            "end_byte": 7060,
            "node_type": "if_statement",
            "sha256": "374f21f4150a4be8",
            "line": 284
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "data_availability",
      "purpose_reason": "the index URL read from pip.conf is the input of the pip install command; the code never tests its value and returns early when there is no URL to use",
      "then": {
        "behaviours": [
          "download",
          "exec_downloaded"
        ],
        "env_recipe": {
          "file_present": [
            "~/.pip/pip.conf"
          ]
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7088,
            "end_byte": 8362,
            "node_type": "stmt_range",
            "sha256": "2e556f417337d44c",
            "line": 288
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 7326,
              "end_byte": 7438,
              "node_type": "call",
              "sha256": "f25f76cbb1120288",
              "line": 296
            },
            "witness": []
          },
          {
            "behaviour": "exec_downloaded",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 7326,
              "end_byte": 7438,
              "node_type": "call",
              "sha256": "f25f76cbb1120288",
              "line": 296
            },
            "witness": []
          }
        ],
        "min_conditions": 2
      },
      "else": null,
      "provenance": "out_of_set"
    },
    {
      "gate_id": "g2",
      "hook": "cmdclass",
      "expression": "c1 && c2 && c3",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7020,
            "end_byte": 7060,
            "node_type": "if_statement",
            "sha256": "374f21f4150a4be8",
            "line": 284
          },
          "kind": "early_exit",
          "arm": "else",
          "conditions": [
            "c1",
            "c2"
          ]
        },
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7573,
            "end_byte": 8362,
            "node_type": "if_statement",
            "sha256": "52546f861be33675",
            "line": 302
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c3"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "during a wheel build, swaps the built wheel for the real package's wheel from the private index to hide the substitution",
      "then": {
        "behaviours": [
          "download",
          "write_file",
          "delete_file"
        ],
        "env_recipe": {
          "file_present": [
            "~/.pip/pip.conf"
          ],
          "package_manager": "bdist_wheel"
        },
        "recipe_guessed_fields": [],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 7636,
            "end_byte": 8362,
            "node_type": "stmt_range",
            "sha256": "7810c1bef0574741",
            "line": 304
          }
        ],
        "payload": [
          {
            "behaviour": "download",
            "sink_kind": "exec",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 7640,
              "end_byte": 7763,
              "node_type": "call",
              "sha256": "fd7f65974bce56e4",
              "line": 304
            },
            "witness": []
          },
          {
            "behaviour": "write_file",
            "sink_kind": "fs_write",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 8031,
              "end_byte": 8076,
              "node_type": "call",
              "sha256": "995e4dd55dde62bf",
              "line": 313
            },
            "witness": []
          },
          {
            "behaviour": "delete_file",
            "sink_kind": "fs_delete",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 8243,
              "end_byte": 8275,
              "node_type": "call",
              "sha256": "b2c44f9731946ebd",
              "line": 319
            },
            "witness": []
          }
        ],
        "min_conditions": 3
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil"
    ],
    "gated": [
      "download",
      "exec_downloaded",
      "write_file",
      "delete_file"
    ]
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "random-looking function names",
      "comparison values hidden as SHA-256 hashes (home folder, file and env var names)"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": true,
    "endpoints": [
      {
        "indicator": "hxxps://pypi-index[.]org/process_data",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": "pypi-index dependency confusion",
  "claude_assessment": "malicious",
  "assessment_reason": "The install command override sends host details (hostname, user, cwd, DNS and hosts files, IPs and MACs) to an external server on every install. When pip is configured with a private index-url it then reinstalls the real package from that index and, during wheel builds, swaps the built wheel for the real one, hiding the substitution.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
    "candidate_set": {
      "generator": "gate_extract@432915badc",
      "sha256": "ac872a54857b13bc"
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
        "candidate": "k_41d568be42",
        "reason_code": "other",
        "note": "Python version check that only picks a PYTHONPATH prefix; same pip command either way (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 7091,
          "end_byte": 7115,
          "node_type": "comparison_operator",
          "sha256": "05e1fe85e5bbf03a",
          "line": 288
        }
      },
      {
        "candidate": "k_49929842f8",
        "reason_code": "other",
        "note": "Python version check in getifip; on Python 2 the IP field is UNKNOWN instead of read by ioctl, recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2767,
          "end_byte": 2791,
          "node_type": "comparison_operator",
          "sha256": "05e1fe85e5bbf03a",
          "line": 125
        }
      },
      {
        "candidate": "k_d50ab6d3b5",
        "reason_code": "other",
        "note": "Python major version check that decides whether the time zone string is filled or left empty; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2385,
          "end_byte": 2409,
          "node_type": "comparison_operator",
          "sha256": "05e1fe85e5bbf03a",
          "line": 110
        }
      },
      {
        "candidate": "k_dff8dcc169",
        "reason_code": "other",
        "note": "Python minor version check that decides whether the time zone string is filled or left empty; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2414,
          "end_byte": 2438,
          "node_type": "comparison_operator",
          "sha256": "8ec6a24e69faf73d",
          "line": 110
        }
      },
      {
        "candidate": "k_4a0c260f6b",
        "reason_code": "other",
        "note": "Python version check that picks urllib.request vs urllib2 import; same behaviour (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 82,
          "end_byte": 106,
          "node_type": "comparison_operator",
          "sha256": "05e1fe85e5bbf03a",
          "line": 8
        }
      },
      {
        "candidate": "k_1523bfa150",
        "reason_code": "other",
        "note": "Python minor version check that only picks a PYTHONPATH prefix (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 7120,
          "end_byte": 7145,
          "node_type": "comparison_operator",
          "sha256": "38c5643ac0148deb",
          "line": 288
        }
      },
      {
        "candidate": "k_e380934d46",
        "reason_code": "other",
        "note": "Python 2 check that picks the urllib2 import; same behaviour (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 153,
          "end_byte": 177,
          "node_type": "comparison_operator",
          "sha256": "d0757726b52815b4",
          "line": 10
        }
      },
      {
        "candidate": "q_ffde2c7879",
        "reason_code": "other",
        "note": "guard of the PYTHONPATH prefix version branch; both sides run the same pip install (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 7088,
          "end_byte": 7273,
          "node_type": "if_statement",
          "sha256": "08c84e41a64bc932",
          "line": 288
        }
      },
      {
        "candidate": "q_47990afd34",
        "reason_code": "other",
        "note": "guard of a version branch in getifip; recon either way (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2764,
          "end_byte": 2930,
          "node_type": "if_statement",
          "sha256": "97fa62de9345960b",
          "line": 125
        }
      },
      {
        "candidate": "q_c6834b6084",
        "reason_code": "other",
        "note": "guard of the time zone version branch; recon either way (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 2382,
          "end_byte": 2538,
          "node_type": "if_statement",
          "sha256": "5c2fa9021a866b55",
          "line": 110
        }
      },
      {
        "candidate": "q_73c468bf50",
        "reason_code": "other",
        "note": "guard of the urllib import choice; same behaviour (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 79,
          "end_byte": 149,
          "node_type": "if_statement",
          "sha256": "ccd9513feabec53f",
          "line": 8
        }
      },
      {
        "candidate": "q_f9aa7aff3a",
        "reason_code": "other",
        "note": "guard of the urllib2 import choice; same behaviour (plumbing)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 150,
          "end_byte": 213,
          "node_type": "if_statement",
          "sha256": "15882254600bf1f1",
          "line": 10
        }
      },
      {
        "candidate": "k_7694cc91ae",
        "reason_code": "other",
        "note": "per-OS way of listing network interfaces for the recon payload; every branch is recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3186,
          "end_byte": 3209,
          "node_type": "comparison_operator",
          "sha256": "1879cca6146256c0",
          "line": 142
        }
      },
      {
        "candidate": "k_ec73b446af",
        "reason_code": "other",
        "note": "per-OS way of reading IPs/MACs for the recon payload; every branch is recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4031,
          "end_byte": 4054,
          "node_type": "comparison_operator",
          "sha256": "1879cca6146256c0",
          "line": 167
        }
      },
      {
        "candidate": "k_91f78649e6",
        "reason_code": "other",
        "note": "per-OS way of listing interfaces (ifconfig on darwin) for recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3430,
          "end_byte": 3454,
          "node_type": "comparison_operator",
          "sha256": "296a2a34cfce3311",
          "line": 149
        }
      },
      {
        "candidate": "k_6898806f80",
        "reason_code": "other",
        "note": "per-OS way of reading IPs/MACs (ifconfig on darwin) for recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4179,
          "end_byte": 4203,
          "node_type": "comparison_operator",
          "sha256": "296a2a34cfce3311",
          "line": 173
        }
      },
      {
        "candidate": "k_b87d1c2f03",
        "reason_code": "other",
        "note": "per-OS way of listing interfaces on windows for recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3808,
          "end_byte": 3833,
          "node_type": "comparison_operator",
          "sha256": "cdf706626966fc02",
          "line": 157
        }
      },
      {
        "candidate": "k_34a2ff9669",
        "reason_code": "other",
        "note": "per-OS way of reading IPs on windows for recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4641,
          "end_byte": 4666,
          "node_type": "comparison_operator",
          "sha256": "cdf706626966fc02",
          "line": 185
        }
      },
      {
        "candidate": "q_f45ae3a8f9",
        "reason_code": "other",
        "note": "guard of per-OS interface listing; recon on every branch (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3183,
          "end_byte": 3909,
          "node_type": "if_statement",
          "sha256": "d3448d7df161df66",
          "line": 142
        }
      },
      {
        "candidate": "q_5ccc73db93",
        "reason_code": "other",
        "note": "guard of per-OS IP/MAC reading; recon on every branch (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4028,
          "end_byte": 4726,
          "node_type": "if_statement",
          "sha256": "4b21e63b39da05ce",
          "line": 167
        }
      },
      {
        "candidate": "q_e41f5c33d1",
        "reason_code": "other",
        "note": "darwin elif of interface listing; recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3425,
          "end_byte": 3798,
          "node_type": "elif_clause",
          "sha256": "db7b45b3a65dca5e",
          "line": 149
        }
      },
      {
        "candidate": "q_7b6cfc3093",
        "reason_code": "other",
        "note": "darwin elif of IP/MAC reading; recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4174,
          "end_byte": 4618,
          "node_type": "elif_clause",
          "sha256": "bdc11bab9a0310ca",
          "line": 173
        }
      },
      {
        "candidate": "q_a36675be35",
        "reason_code": "other",
        "note": "windows elif of interface listing; recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 3803,
          "end_byte": 3909,
          "node_type": "elif_clause",
          "sha256": "7e1c8e877bc44dc4",
          "line": 157
        }
      },
      {
        "candidate": "q_b206121ffc",
        "reason_code": "other",
        "note": "windows elif of IP reading; recon (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 4636,
          "end_byte": 4726,
          "node_type": "elif_clause",
          "sha256": "d00e0785ea1b5f59",
          "line": 185
        }
      },
      {
        "candidate": "k_53a2a073c3",
        "reason_code": "other",
        "note": "OS check in mJdzrtzhMJ_1; a match sets 'key' and makes detect_system skip the loopback GET and env hash check; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 892,
          "end_byte": 940,
          "node_type": "comparison_operator",
          "sha256": "ac28e6f1a43181e5",
          "line": 39
        }
      },
      {
        "candidate": "k_4bd66fc71c",
        "reason_code": "other",
        "note": "home dir check in mJdzrtzhMJ_1; a match sets 'key' and makes detect_system skip the loopback GET and env hash check; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1004,
          "end_byte": 1027,
          "node_type": "call",
          "sha256": "cae07992564b0e9d",
          "line": 41
        }
      },
      {
        "candidate": "q_256c150c65",
        "reason_code": "other",
        "note": "OS guard in mJdzrtzhMJ_1 fingerprint; decides the 'key' value and whether detect_system goes on to the loopback GET and env hash check; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 889,
          "end_byte": 1251,
          "node_type": "if_statement",
          "sha256": "9bbd7c9651ab9515",
          "line": 39
        }
      },
      {
        "candidate": "q_cc6042522e",
        "reason_code": "other",
        "note": "home dir guard in mJdzrtzhMJ_1 fingerprint; decides the 'key' value and whether detect_system goes on to the loopback GET and env hash check; recon and exfil run either way (data collection)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 1001,
          "end_byte": 1251,
          "node_type": "if_statement",
          "sha256": "8e417d0c3a9ebd7f",
          "line": 41
        }
      },
      {
        "candidate": "k_150aad96d4",
        "reason_code": "not_environmental",
        "note": "os.path.exists on sys.argv[-1], the build output dir; picks makedirs vs unlink-then-move, plumbing inside g2",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 7949,
          "end_byte": 7970,
          "node_type": "call",
          "sha256": "cb6ac37def5c12a1",
          "line": 311
        }
      },
      {
        "candidate": "q_f53d440567",
        "reason_code": "not_environmental",
        "note": "guard of the build output dir existence check; plumbing inside g2",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 7942,
          "end_byte": 8362,
          "node_type": "if_statement",
          "sha256": "98244fe2695f4547",
          "line": 311
        }
      },
      {
        "candidate": "q_226c58a329",
        "reason_code": "duplicate_of",
        "note": "the try around open(~/.pip/pip.conf) is the c1 probe inside get_index(); the decision is the early exit at line 284 (g1 guard)",
        "anchor": {
          "file": "setup.py",
          "derived_from": null,
          "start_byte": 6495,
          "end_byte": 6625,
          "node_type": "try_statement",
          "sha256": "54b9e1be3a1f0df5",
          "line": 261
        }
      }
    ]
  },
  "candidate_check": {
    "condition_candidates": 19,
    "condition_sites_cited": 1,
    "guards_cited": 0,
    "candidates_dropped": 31,
    "conditions_in_set": 1,
    "conditions_out_of_set": 2,
    "guard_candidates": 15,
    "gates_in_set": 0,
    "gates_out_of_set": 2,
    "out_of_set_ids": [
      "c2",
      "c3",
      "g1",
      "g2"
    ],
    "anchor_refusals": 0
  }
}
```
