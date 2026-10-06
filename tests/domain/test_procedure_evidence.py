"""Repository-level bridge for the procedure-evidence package tests."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills" / "domain" / "procedure-evidence" / "tests" / "test_procedure_evidence.py"
SPEC = importlib.util.spec_from_file_location("procedure_evidence_package_tests", PACKAGE_TESTS)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(MODULE))
    return tests


from pathlib import Path as _Path
_policy_module_path = _Path(__file__).resolve().parents[2] / "scripts" / "implementation_policy.py"
_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", _policy_module_path)
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)

class ProcedureEvidenceContractTests(unittest.TestCase):
    def test_package_layer_and_category_align(self):
        manifest = (ROOT / "skills" / "domain" / "procedure-evidence" / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("category: domain", manifest)
        self.assertIn("version: 0.1.0", manifest)

    def test_fixtures_stay_generic(self):
        stages = ROOT / "skills" / "domain" / "procedure-evidence" / "examples" / "stages"
        for fixture in stages.glob("*.jsonl"):
            text = fixture.read_text(encoding="utf-8").lower()
            for token in ["registration", "attach", "ims", "mobility", "voice"] + sorted(_POLICY.PROHIBITED_TOKENS):
                self.assertNotIn(token, text, fixture.name)

    def test_records_carry_no_subscriber_data(self):
        records_path = ROOT / "skills" / "domain" / "procedure-evidence" / "examples" / "stages" / "observed-flow.jsonl"
        blob = json.dumps([json.loads(line) for line in records_path.read_text(encoding="utf-8").splitlines() if line.strip()]).lower()
        for token in ("imsi", "supi", "suci", "msisdn", "guti", "subscriber"):
            self.assertNotIn(token, blob)
