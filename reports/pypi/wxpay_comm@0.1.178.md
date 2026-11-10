# pypi wxpay_comm@0.1.178

**Source:** datadog · **Source label:** malicious · **Released:** 2023-06-09 (dataset) · **Assessment:** malicious (high) · **Analysis:** ai (claude-opus-5-5)

## Summary

The sdist's setup.py holds its payload as top-level code, so it runs whenever pip builds the package (the metadata step included). It reads the login name, hostname, platform.uname(), the working directory and the local outbound IP (found through a UDP socket connect to 8[.]8[.]8[.]8:53), base64-encodes them behind a `PYPI_Victim-wxpay_comm-0.1.178` tag and sends them in an HTTP GET to a hard-coded IP. There are no gates: any environment that can run setup.py and reach the server triggers it.

## Execution

- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

- network: 129[.]226[.]195[.]123:80 (HTTP GET carrying the base64 host data; the response is not used)
- other: python module requests importable in the build environment (imported unconditionally before the payload; not in setup_requires or build-system.requires)
- other: os.getlogin() succeeds (controlling terminal or login record present) (os.getlogin raises OSError without a controlling terminal, which aborts setup.py before the request)
- other: an IPv4 route that lets a UDP socket connect to 8[.]8[.]8[.]8:53 (used to read the local outbound IP; connect fails with no route)

## Behaviour

- Ungated: recon, exfil
- Gated: none

## Notes

- 8[.]8[.]8[.]8 is left out of reachability because the UDP connect only selects a local route; nothing is exchanged with it.
- The payload needs `requests` already importable and `os.getlogin()` to succeed (it raises without a controlling terminal). These are requirements, not checks, but a headless scanner VM can break the payload on the second one.
- attack_type dependency_confusion is inferred from the internal-looking name, the victim tag and the beacon-only payload.

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "wxpay_comm",
    "version": "0.1.178",
    "archive_sha256": "b7c22a99e70b4b7428a235a0d4c97bdd1b05e526c91f14dd09ef59c91a2781c1",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2023-06-09",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2023-06-09-wxpay-comm-v0.1.178.zip",
    "package_root": "layer0/2023-06-09-wxpay-comm-v0.1.178",
    "cluster_key": "1c59d2a2bc630170fa67d07271cde300945f1159bff271cb62d94434bfd0e831",
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
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py read in full: the payload is top-level code, so it runs on every setup.py invocation (pip's metadata step included) with no checks in front of it.",
      "The UDP socket connect to 8[.]8[.]8[.]8:53 only selects the local outbound IP to report; nothing depends on a reply, so it is recon, not a reachability gate.",
      "Files under wxpay_comm/ are not imported by setup.py and are not reached at install.",
      "requests is imported at the top of setup.py but only declared in install_requires, so the build fails before the payload unless requests is already in the build environment."
    ]
  },
  "requirements": [
    {
      "axis": "network",
      "value": "129[.]226[.]195[.]123:80",
      "reason": "HTTP GET carrying the base64 host data; the response is not used"
    },
    {
      "axis": "other",
      "value": "python module requests importable in the build environment",
      "reason": "imported unconditionally before the payload; not in setup_requires or build-system.requires"
    },
    {
      "axis": "other",
      "value": "os.getlogin() succeeds (controlling terminal or login record present)",
      "reason": "os.getlogin raises OSError without a controlling terminal, which aborts setup.py before the request"
    },
    {
      "axis": "other",
      "value": "an IPv4 route that lets a UDP socket connect to 8[.]8[.]8[.]8:53",
      "reason": "used to read the local outbound IP; connect fails with no route"
    }
  ],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [
      "recon",
      "exfil"
    ],
    "gated": []
  },
  "obfuscation": {
    "level": "light",
    "techniques": [
      "base64 encoding of the exfiltrated host data in the URL path"
    ],
    "decoded": null,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": [
      {
        "indicator": "hxxp://129[.]226[.]195[.]123/v/%s",
        "role": "exfil_sink"
      },
      {
        "indicator": "129[.]226[.]195[.]123",
        "role": "exfil_sink"
      }
    ]
  },
  "attack_type": "dependency_confusion",
  "family_hint": null,
  "claude_assessment": "malicious",
  "assessment_reason": "setup.py collects login name, hostname, uname, working directory and local IP at top level and sends them base64-encoded in an HTTP GET to a hard-coded IP during install, with no gates. The victim tag in the data and the internal-looking SDK name fit a dependency-confusion probe.",
  "label_disagreement": false,
  "confidence": "high",
  "needs_manual_review": false,
  "review_reasons": [],
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
    "conditions_out_of_set": 0,
    "guard_candidates": 0,
    "gates_in_set": 0,
    "gates_out_of_set": 0,
    "out_of_set_ids": [],
    "anchor_refusals": 0
  }
}
```
