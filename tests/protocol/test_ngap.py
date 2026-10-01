"""Repository-level bridge for the ngap package test suite."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills" / "protocol" / "ngap" / "tests" / "test_ngap.py"
SPEC = importlib.util.spec_from_file_location("ngap_package_tests", PACKAGE_TESTS)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(MODULE))
    return tests


class NgapPackageContractTests(unittest.TestCase):
    def test_package_local_trace_schema_matches_shared(self):
        shared = ROOT / "shared" / "schemas" / "trace-event.schema.json"
        local = ROOT / "skills" / "protocol" / "ngap" / "schemas" / "trace-event.schema.json"
        self.assertEqual(shared.read_bytes(), local.read_bytes())

    def test_expected_fixture_evidence_stays_observed(self):
        events = MODULE.jsonl(ROOT / "skills" / "protocol" / "ngap" / "examples" / "expected" / "ue-context-events.jsonl")
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event["evidence"]["level"], "OBSERVED")
