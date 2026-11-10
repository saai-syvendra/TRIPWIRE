# pypi groq_ppe_pkg@1.0.0

**Source:** pypi_malregistry · **Source label:** malicious · **Released:** not found · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist uses `setuptools.build_meta`, so `setup.py` runs as a module on each build step. One gate (g1) sits in front of the payload: `if "install" in sys.argv or "bdist_wheel" in sys.argv`, which holds on pip's wheel-build step but not on metadata generation. When it opens, `send_ip()` fetches the public IP from api[.]ipify[.]org and POSTs it with the package name and an "installed" status to a webhook[.]site URL. Both requests are wrapped in a bare `except Exception: pass`. Any normal pip install from the sdist with outbound HTTPS to both hosts opens the gate.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script; errors hidden.

## Gates

| gate | hook | expression | branch | min | behaviours | recipe |
|---|---|---|---|---|---|---|
| g1 | setup_py | c1 \|\| c2 (c1: sys.argv includes install; c2: sys.argv includes bdist_wheel) | then | 1 | recon, exfil | package_manager=pip building the sdist with setuptools.build_meta (sys.argv contains bdist_wheel) |

Gate intent: g1 activate/enables/targeting

Grounding: 0 of 2 conditions and 0 of 1 gates from the candidate set; out of set, pending verification: c1, c2, g1.

## Requirements

- network: api[.]ipify[.]org:443, webhook[.]site:443 (the public IP lookup must succeed before the POST to the webhook runs; both sit in one try block)

## Behaviour

- Ungated: none
- Gated: recon, exfil

## Notes

- The extractor produced no candidates. c1/c2 and the guard are out of set and anchored by hand with `cite.py`.
- Category `package_manager` was chosen for the argv test because the build frontend sets argv. The recipe value is guessed, since no recipe key expresses argv directly.
- The ipify lookup is recorded as recon and as a network requirement, not as an endpoint, because no endpoint role fits an IP-echo service.
- The comments in setup.py ("Silent fail", "Run when package is being installed") match what the code does. No misleading text.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "groq_ppe_pkg",
    "version": "1.0.0",
    "archive_sha256": "ae4348f083837508ca29b36923301099a4e554da1bf9d905a6b95723def567ec",
    "source_dataset": "pypi_malregistry",
    "source_label": "malicious",
    "released_at": null,
    "released_at_source": null,
    "sample_path": "pypi_malregistry/pypi/malicious_intent/groq_ppe_pkg-1.0.0.tar.gz",
    "package_root": "layer0/groq_ppe_pkg-1.0.0",
    "cluster_key": "0f22ab68977a8b1d698c1b7fd0eaaf980750a4d603f62b1cd0d04dad0c4c27e4",
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
          "direct_script"
        ],
        "silent_failure": true
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: package code read in full (37 lines, no bundled or third-party code); nothing unread. pyproject.toml uses setuptools.build_meta, so setup.py top-level code runs on every build step.",
      "The extractor found no candidates; the sys.argv test on line 30 is added out of set. Under setuptools.build_meta, metadata steps run with egg_info/dist_info in sys.argv and build_wheel with bdist_wheel, so the beacon fires during a normal pip install.",
      "send_ip() wraps both requests in try/except Exception: pass, so a failed IP lookup or POST is silent. If the ipify lookup fails, the webhook POST never runs.",
      "api[.]ipify[.]org is a public IP-echo service used only to learn the installer's public IP; it is listed under requirements, not reachability endpoints, since no endpoint role fits it."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": [
        "api[.]ipify[.]org:443",
        "webhook[.]site:443"
      ],
      "reason": "the public IP lookup must succeed before the POST to the webhook runs; both sit in one try block"
    }
  ],
  "conditions": [
    {
      "id": "c1",
      "category": "package_manager",
      "api": "sys.argv",
      "operator": "includes",
      "value": "install",
      "value_recovered": "plain",
      "sites": [
        {
          "candidate": null,
          "anchor": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 812,
            "end_byte": 833,
            "node_type": "comparison_operator",
            "sha256": "ee886826f8c25a3b",
            "line": 30
          }
        }
      ],
      "in_scope": true,
      "provenance": "out_of_set"
    },
    {
      "id": "c2",
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
            "start_byte": 837,
            "end_byte": 862,
            "node_type": "comparison_operator",
            "sha256": "4a53bc6ea18e3104",
            "line": 30
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
      "hook": "setup_py",
      "expression": "c1 || c2",
      "guards": [
        {
          "candidate": null,
          "site": {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 809,
            "end_byte": 877,
            "node_type": "if_statement",
            "sha256": "a4a48d2c506c3011",
            "line": 30
          },
          "kind": "if",
          "arm": "then",
          "conditions": [
            "c1",
            "c2"
          ]
        }
      ],
      "polarity": "activate",
      "effect": "enables",
      "purpose": "targeting",
      "purpose_reason": "fires only on the install or wheel-build step a victim's pip runs, not on metadata generation or the author's own sdist or upload commands",
      "then": {
        "min_conditions": 1,
        "behaviours": [
          "recon",
          "exfil"
        ],
        "env_recipe": {
          "package_manager": "pip building the sdist with setuptools.build_meta (sys.argv contains bdist_wheel)"
        },
        "recipe_guessed_fields": [
          "package_manager"
        ],
        "regions": [
          {
            "file": "setup.py",
            "derived_from": null,
            "start_byte": 868,
            "end_byte": 877,
            "node_type": "block",
            "sha256": "335051859d2f4ade",
            "line": 31
          }
        ],
        "payload": [
          {
            "behaviour": "recon",
            "sink_kind": "network",
            "sink": {
              "file": "setup.py",
              "derived_from": null,
              "start_byte": 124,
              "end_byte": 171,
              "node_type": "call",
              "sha256": "34f903bc361fe734",
              "line": 7
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 868,
                  "end_byte": 877,
                  "node_type": "call",
                  "sha256": "335051859d2f4ade",
                  "line": 31
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 63,
                  "end_byte": 769,
                  "node_type": "function_definition",
                  "sha256": "154d2c0bfcc91469",
                  "line": 4
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
              "start_byte": 635,
              "end_byte": 673,
              "node_type": "call",
              "sha256": "f4adcf69bcdb43f3",
              "line": 23
            },
            "witness": [
              {
                "hop": "call",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 868,
                  "end_byte": 877,
                  "node_type": "call",
                  "sha256": "335051859d2f4ade",
                  "line": 31
                }
              },
              {
                "hop": "def",
                "anchor": {
                  "file": "setup.py",
                  "derived_from": null,
                  "start_byte": 63,
                  "end_byte": 769,
                  "node_type": "function_definition",
                  "sha256": "154d2c0bfcc91469",
                  "line": 4
                }
              }
            ]
          }
        ]
      },
      "else": null,
      "provenance": "out_of_set"
    }
  ],
  "behaviours": {
    "ungated": [],
    "gated": [
      "recon",
      "exfil"
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
        "indicator": "hxxps://webhook[.]site/6b67…",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "malicious_new_package",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "At install, setup.py looks up the installer's public IP and silently POSTs it with the package name to a webhook, gated on install or bdist_wheel being in sys.argv. Low impact and shaped like an install-tracking beacon, but it sends data off the machine without consent.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": true,
  "review_reasons": [
    "attack_type uncertain: beacon resembles a dependency-confusion or research canary, but nothing in the code ties it to an internal package name",
    "guessed recipe fields",
    "out-of-set claim pending verification"
  ],
  "normalisation": {
    "derivations": [],
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
    "conditions_out_of_set": 2,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 1,
    "out_of_set_ids": [
      "c1",
      "c2",
      "g1"
    ],
    "anchor_refusals": 0
  }
}
```
