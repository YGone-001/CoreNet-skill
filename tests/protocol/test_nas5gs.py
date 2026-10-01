"""Repository-level bridge for the nas-5gs package test suite."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills" / "protocol" / "nas-5gs" / "tests" / "test_nas5gs.py"
SPEC = importlib.util.spec_from_file_location("nas5gs_package_tests", PACKAGE_TESTS)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(MODULE))
    return tests


class Nas5gsPackageContractTests(unittest.TestCase):
    def test_package_local_trace_schema_matches_shared(self):
        shared = ROOT / "shared" / "schemas" / "trace-event.schema.json"
        local = ROOT / "skills" / "protocol" / "nas-5gs" / "schemas" / "trace-event.schema.json"
        self.assertEqual(shared.read_bytes(), local.read_bytes())

    def test_expected_fixture_evidence_stays_observed(self):
        events_path = ROOT / "skills" / "protocol" / "nas-5gs" / "examples" / "expected" / "registration-flow-events.jsonl"
        events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertTrue(events)
        for event in events:
            self.assertEqual(event["evidence"]["level"], "OBSERVED")
            self.assertIsNone(event["identity"]["value"])
