"""Repository-level bridge for the cross-protocol-evidence package tests."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills" / "correlation" / "cross-protocol-evidence" / "tests" / "test_cross_protocol_evidence.py"
SPEC = importlib.util.spec_from_file_location("cross_protocol_evidence_package_tests", PACKAGE_TESTS)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(MODULE))
    return tests


class CorrelationPackageContractTests(unittest.TestCase):
    def test_package_local_trace_schema_matches_shared(self):
        shared = ROOT / "shared" / "schemas" / "trace-event.schema.json"
        local = ROOT / "skills" / "correlation" / "cross-protocol-evidence" / "schemas" / "trace-event.schema.json"
        self.assertEqual(shared.read_bytes(), local.read_bytes())

    def test_expected_groups_stay_derived_and_verdict_free(self):
        import json

        groups_path = ROOT / "skills" / "correlation" / "cross-protocol-evidence" / "examples" / "expected" / "join-flow-correlation.jsonl"
        groups = [json.loads(line) for line in groups_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(groups)
        blob = json.dumps(groups).lower()
        for forbidden in ("root_cause", "success", "failure", "subscriber"):
            self.assertNotIn(forbidden, blob)
        for group in groups:
            for event in group["events"]:
                identity = event.get("identity")
                if isinstance(identity, dict):
                    self.assertIsNone(identity.get("value"))
