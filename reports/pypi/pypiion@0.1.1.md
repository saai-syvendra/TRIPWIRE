# pypi pypiion@0.1.1

**Source:** datadog · **Source label:** malicious · **Released:** 2025-07-04 (dataset) · **Assessment:** malicious (medium) · **Analysis:** ai (claude-opus-5-5)

## Summary

pypiion 0.1.1 is an sdist whose setup.py registers a custom `install` command. `PostInstall.run` decodes a nested reversed-base64/zlib stage and exec()s it. That stage holds an unused anti-debug check, then decodes a second stage (base85 + XOR + zlib, with a base64 fallback): a Windows Chrome stealer that impersonates lsass to unwrap the app-bound key and takes cookies, saved logins, cards and four wallet extensions, then uploads a zip to railway.app hosts. As written, the first stage crashes with a NameError, because its helper function cannot see names defined at the top level of the exec'd string. So no stealer code runs at install, and no gate or behaviour is recorded.

## Execution

- **cmdclass** `cmdclass[install] = PostInstall`: runs setup.py; direct_script, decoded_eval.
- **setup_py** `python setup.py (pip install from sdist)`: runs setup.py; direct_script.

## Gates

None.

## Requirements

None.

## Behaviour

- Ungated: none
- Gated: none

## Notes

- The whole decision rests on Python exec() scoping: exec() is called inside `run()` without a globals dict, so top-level names go into a locals snapshot and functions defined there look names up in setup.py's module globals. `_2EVM4JC` uses `__6xnzCmPT` (sys) and fails at `_debug_status=_2EVM4JC()`, which is outside any try. Stage 2's `main()` has the same flaw (`is_admin`).
- If a reviewer disagrees, these would be the gates: `is_admin()` (privilege, Windows), Local State readable with `os_crypt.app_bound_encrypted_key` (target artifact), and per-profile existence checks on Network/Cookies, Login Data, Web Data and the four wallet extension folders.
- Decoders were registered as candidates (`d10`, `d11`) for replay. Both stages were read in full, and the stage-2 except branch is the same payload as the try branch (same functions in the same order; spot-read, not diffed).

## Record

```json
{
  "schema_version": "3.2",
  "record_type": "analysed",
  "package": {
    "ecosystem": "pypi",
    "name": "pypiion",
    "version": "0.1.1",
    "archive_sha256": "2af02504580acd8fa58460c7c7b80b73aba97c5ac728db6ccf033668dc2fe0c8",
    "source_dataset": "datadog",
    "source_label": "malicious",
    "released_at": "2025-07-04",
    "released_at_source": "dataset",
    "sample_path": "datadog/pypi/malicious_intent/2025-07-04-pypiion-v0.1.1.zip",
    "package_root": "layer0/tmp/tmp58x8cza5/pypiion/pypiion-0.1.1",
    "cluster_key": "181dbb6694c843df6a7e489b4940b4191d33b9df84b58a3ed63f40a1b1c40b21",
    "analysis_type": "ai",
    "model_name": "claude-opus-5-5"
  },
  "execution": {
    "entry_points": [
      {
        "hook": "cmdclass",
        "command": "cmdclass[install] = PostInstall",
        "runs_on": "always",
        "file_chain": [
          "setup.py"
        ],
        "interpreter": "python",
        "launch_style": [
          "direct_script",
          "decoded_eval"
        ],
        "silent_failure": false
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
        "silent_failure": false
      }
    ],
    "delays": [],
    "notes": [
      "setup.py: PostInstall.run exec()s stage 1 (nested reversed base64 + zlib; decoder rev_b64_zlib_lambda, d10), which exec()s stage 2 (base85 + XOR + zlib, base64 fallback; decoder exec_alias_b85xor_zlib, d11).",
      "setup.py coverage: tool did not recover the layers; both decoded stages read in full via d10/d11; nothing unread.",
      "setup.py top level only calls setup(); the setup_py hook does nothing beyond build plumbing.",
      "Stage 1 is exec()'d inside run() with no globals, so its top-level names land in a locals snapshot while its functions resolve free names in setup.py's globals.",
      "So the anti-debug helper _2EVM4JC (sys.gettrace, stack depth > 8, pdb in inspect.stack) raises NameError on __6xnzCmPT at _debug_status=_2EVM4JC(), outside any try. The install fails there and stage 2 never runs.",
      "Repair check: d10 lines 7-18 sit at stage 1 top level with no enclosing try (the only try, d10 line 34, wraps the stage 2 exec); exec compiles stage 1 as module code, so __6xnzCmPT in _2EVM4JC is a global lookup in setup.py's module dict, which never receives it.",
      "Its result _debug_status is never read anyway, so even if it worked it would not gate anything (only side effect: sys.modules[__name__]=None under a tracer).",
      "Stage 2 is a Windows Chrome app-bound-key stealer: cookies, logins, cards, CVCs and Phantom/MetaMask/Trust/Solflare extension data, zipped and posted. It is also broken: main() would raise NameError on is_admin for the same scoping reason, which is caught and logged.",
      "Not recorded as gates because unreachable: is_admin() early return (privilege), Local State read in try/except return, app_bound_encrypted_key lookup, os.path.exists on Cookies/Login Data/Web Data/extension folders, shadow-copy fallback.",
      "Stage 2 upload hosts (unreached): vell-production.up.railway[.]app, chrome-data-receiver.up.railway[.]app, chrome-extract.up.railway[.]app (/upload), then a placeholder Discord webhook, then local copies under USERPROFILE.",
      "if __name__=='__main__' guard in stage 2 is not environmental (true under pip's setup.py runners); not a gate.",
      "install_requires PythonForWindows, pycryptodome, requests: dependency tree, needed by the stage 2 stealer."
    ]
  },
  "requirements": [],
  "conditions": [],
  "gates": [],
  "behaviours": {
    "ungated": [],
    "gated": []
  },
  "obfuscation": {
    "level": "heavy",
    "techniques": [
      "dynamic_eval",
      "nested reversed base64 + zlib exec layers",
      "base85 + repeating-key XOR + zlib stage with base64 fallback",
      "exec aliased to a junk name",
      "junk variable assignments",
      "anti-debug check (sys.gettrace, stack depth, pdb)",
      "very_long_lines"
    ],
    "decoded": true,
    "unrecovered": []
  },
  "reachability": {
    "needs_remote": false,
    "endpoints": []
  },
  "attack_type": "malicious_new_package",
  "family_hint": "chrome app-bound key stealer",
  "claude_assessment": "malicious",
  "assessment_reason": "The install cmdclass decodes and execs a multi-layer obfuscated Windows Chrome credential, card and crypto wallet stealer that uploads to railway.app hosts. As written it crashes with a NameError in its first stage (exec scoping), so no stealer behaviour is reachable at install.",
  "label_disagreement": false,
  "confidence": "medium",
  "needs_manual_review": false,
  "review_reasons": [],
  "normalisation": {
    "derivations": [
      {
        "id": "d10",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": null
        },
        "params": {
          "decoder": "rev_b64_zlib_lambda",
          "lang": "py"
        },
        "output_sha256": "55151c414fc7ede9"
      },
      {
        "id": "d11",
        "recipe": "decode_spec",
        "recipe_version": 1,
        "input": {
          "file": "setup.py",
          "derived_from": "d10"
        },
        "params": {
          "decoder": "exec_alias_b85xor_zlib",
          "lang": "py"
        },
        "output_sha256": "7677ba459554822b"
      }
    ],
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
