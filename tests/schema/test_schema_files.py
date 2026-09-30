import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SchemaFixtureTests(unittest.TestCase):
    def test_schemas_are_json_objects(self):
        for path in sorted((ROOT / "shared" / "schemas").glob("*.json")):
            with self.subTest(path=path.name):
                self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_fixture_examples_are_json_objects(self):
        for path in sorted((ROOT / "tests" / "fixtures").glob("*.json")):
            with self.subTest(path=path.name):
                self.assertIsInstance(json.loads(path.read_text(encoding="utf-8")), dict)

    def test_trace_fixture_has_minimum_contract(self):
        data = json.loads((ROOT / "tests" / "fixtures" / "trace-event.example.json").read_text(encoding="utf-8"))
        self.assertIn("timestamp", data)
        self.assertIn("protocol", data)
        self.assertEqual(data["evidence"]["level"], "OBSERVED")
        self.assertTrue(data["evidence"]["source"])

    def test_evidence_fixture_has_required_fields(self):
        data = json.loads((ROOT / "tests" / "fixtures" / "evidence.example.json").read_text(encoding="utf-8"))
        self.assertEqual({"level", "statement", "source"} - data.keys(), set())
        self.assertEqual(data["level"], "OBSERVED")

    def test_diagnostic_fixture_is_explicitly_unconfirmed(self):
        data = json.loads((ROOT / "tests" / "fixtures" / "diagnostic-result.example.json").read_text(encoding="utf-8"))
        self.assertEqual(data["root_cause"]["status"], "UNCONFIRMED")
        self.assertEqual(data["failure_boundary"]["status"], "UNKNOWN")
