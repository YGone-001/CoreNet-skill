"""Repository-level tests for the ngap package validator."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-ngap.py"
SPEC = importlib.util.spec_from_file_location("validate_ngap", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class NgapValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/protocol/ngap/manifest.yaml").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(any("missing required package file" in error for error in errors))

    def test_trace_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/ngap/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("trace schema" in error for error in VALIDATOR.validate(root)))

    def test_binary_capture_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            capture = root / "skills/protocol/ngap/examples/extracted/unsanctioned.pcapng"
            capture.write_bytes(b"synthetic")
            self.assertTrue(any("binary capture fixture" in error for error in VALIDATOR.validate(root)))

    def test_absolute_workstation_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/ngap/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nC:\\Users\\analyst\\capture.pcapng\n", encoding="utf-8")
            self.assertTrue(any("absolute workstation path" in error for error in VALIDATOR.validate(root)))

    def test_implementation_reference_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            reference = root / "skills/protocol/ngap/references/protocol-model.md"
            reference.write_text(reference.read_text(encoding="utf-8") + "\nSee open5gs source.\n", encoding="utf-8")
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_nas_5gs_creation_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/protocol/nas-5gs").mkdir()
            self.assertTrue(any("nas-5gs" in error for error in VALIDATOR.validate(root)))

    def test_subscriber_field_in_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/ngap/examples/extracted/ue-context-flow.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            lines = fixture.read_text(encoding="utf-8").splitlines()
            lines.append('{"frame.number":"99","frame.time_epoch":"1704164700.000000","ngap.procedureCode":"15","imsi": "001010000000001"}')
            fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertTrue(any("subscriber identity" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
