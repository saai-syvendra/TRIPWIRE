import copy
import urllib.error
import urllib.request

import pytest

from tools.analysis import release_date
from tools.common import paths
from tools.tests.helpers import anchor


RECORD = {
    "schema_version": "3.1",
    "record_type": "analysed",
    "package": {
        "ecosystem": "npm", "name": "demo-pkg", "version": "1.0.0", "archive_sha256": "ab" * 32,
        "source_dataset": "datadog", "source_label": "malicious", "cluster_key": "cd" * 32,
        "released_at": "2025-11-24", "released_at_source": "registry", "analysis_type": "ai",
        "model_name": "claude-test", "sample_path": "datadog/npm/malicious_intent/demo.zip",
        "package_root": "layer1/package",
    },
    "execution": {
        "entry_points": [{
            "hook": "postinstall", "command": "node index.js", "runs_on": "always",
            "file_chain": ["index.js"], "interpreter": "node", "launch_style": ["direct_script"],
            "silent_failure": False,
        }],
        "delays": [],
        "notes": [],
    },
    "requirements": [],
    "conditions": [
        {"id": "c1", "category": "os", "api": "process.platform", "operator": "==", "value": "win32",
         "value_recovered": "plain", "in_scope": True, "provenance": "in_set",
         "sites": [{"candidate": "k_0000000001", "anchor": anchor(40, 68, "binary_expression", 3)}]},
        {"id": "c2", "category": "target_artifact", "api": "fs.existsSync", "operator": "exists",
         "value": "~/.ssh", "value_recovered": "plain", "in_scope": True, "provenance": "in_set",
         "sites": [{"candidate": "k_0000000002", "anchor": anchor(72, 95, "call_expression", 3)}]},
    ],
    "gates": [{
        "gate_id": "g1", "hook": "postinstall", "expression": "c1 && c2",
        "guards": [{"candidate": "q_0000000001", "site": anchor(36, 160, "if_statement", 3), "kind": "if",
                    "arm": "then", "conditions": ["c1", "c2"]}],
        "provenance": "in_set",
        "polarity": "activate", "effect": "enables", "purpose": "targeting",
        "purpose_reason": "only steals on Windows hosts with keys",
        "then": {"min_conditions": 2, "behaviours": ["cred_read", "exfil"],
                 "env_recipe": {"os": "win32", "file_present": ["~/.ssh"]}, "recipe_guessed_fields": [],
                 "regions": [anchor(97, 160, "statement_block", 3)],
                 "payload": [{"behaviour": "exfil", "sink_kind": "network", "sink": anchor(110, 150, "call_expression", 4),
                              "witness": []}]},
        "else": None,
    }],
    "behaviours": {"ungated": ["recon"], "gated": ["cred_read", "exfil"]},
    "obfuscation": {"level": "none", "techniques": [], "decoded": None, "unrecovered": []},
    "reachability": {"needs_remote": True, "endpoints": [{"indicator": "hxxps://evil[.]example/x", "role": "exfil_sink"}]},
    "attack_type": "typosquat",
    "family_hint": None,
    "claude_assessment": "malicious",
    "assessment_reason": "Steals SSH keys on Windows.",
    "label_disagreement": False,
    "confidence": "high",
    "needs_manual_review": False,
    "review_reasons": [],
    "normalisation": {"derivations": [], "candidate_set": {"generator": "gate_extract@3", "sha256": "0" * 16}},
    "candidate_review": {"dropped": []},
    "candidate_check": {"condition_candidates": 2, "condition_sites_cited": 2, "guards_cited": 1,
                        "candidates_dropped": 0, "conditions_in_set": 2, "conditions_out_of_set": 0,
                        "guard_candidates": 1, "gates_in_set": 1, "gates_out_of_set": 0,
                        "out_of_set_ids": [], "anchor_refusals": 0},
}


@pytest.fixture
def record():
    return copy.deepcopy(RECORD)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """Points every data root (samples, scratch, reports, dataset) at a temporary repo."""
    for name, path in paths.point_at(tmp_path).items():
        monkeypatch.setattr(paths, name, path)
    return tmp_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """prepare.main() asks the registry by default; tests never reach the network."""
    def refuse(*args, **kwargs):
        raise urllib.error.URLError("network disabled in tests")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(release_date, "_sleep", lambda seconds: None)  # retries never wait in tests
