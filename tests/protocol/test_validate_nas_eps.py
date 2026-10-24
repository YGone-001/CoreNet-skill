#!/usr/bin/env python3
"""Repository-level tests for the nas-eps validator and Skill package contract."""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

def imported_modules(text: str) -> set[str]:
    """Return the top-level modules a script imports."""
    tree = ast.parse(text)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "protocol" / "nas-eps"


def load_validator():
    path = ROOT / "scripts" / "validate-nas-eps.py"
    spec = importlib.util.spec_from_file_location("validate_nas_eps_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        target = self.root / "skills" / "protocol" / "nas-eps"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SKILL, target)
        self.skill = target

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_repository_package_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_reported(self) -> None:
        (self.skill / "references" / "protection-rules.md").unlink()
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("protection-rules.md" in error for error in errors), errors)

    def test_expected_event_mismatch_is_reported(self) -> None:
        expected = self.skill / "examples" / "expected" / "attach-flow-events.jsonl"
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
        records[0]["message_type"] = "Detach request"
        expected.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("do not match" in error for error in errors), errors)

    def test_published_identity_field_is_rejected(self) -> None:
        expected = self.skill / "examples" / "expected" / "attach-flow-events.jsonl"
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
        records[0]["imsi"] = "001010000000001"
        expected.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("forbidden evidence field" in error for error in errors), errors)

    def test_invented_protected_identity_is_rejected(self) -> None:
        expected = self.skill / "examples" / "expected" / "protected-inner-events.jsonl"
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
        records[1]["message_type"] = "Attach request"
        expected.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(
            any("must not be given an invented identity" in error for error in errors), errors
        )

    def test_lifecycle_marker_is_reported(self) -> None:
        readme = self.skill / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8") + "\nMilestone 7 delivery notes.\n", encoding="utf-8"
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("lifecycle marker" in error for error in errors), errors)


class PackageContractTests(unittest.TestCase):
    def test_package_is_standalone(self) -> None:
        for required in (
            "SKILL.md", "README.md", "manifest.yaml", "references", "schemas",
            "scripts", "examples", "tests", "filters",
        ):
            self.assertTrue((SKILL / required).exists(), required)

    def test_scripts_do_not_import_other_skills(self) -> None:
        forbidden = {"s1ap_model", "ngap_model", "nas5gs_model"}
        for script in (SKILL / "scripts").glob("*.py"):
            imported = imported_modules(script.read_text(encoding="utf-8"))
            self.assertFalse(
                forbidden & imported,
                f"{script.name} must not import another Protocol Skill module",
            )

    def test_manifest_declares_no_required_dependency(self) -> None:
        manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("required: []", manifest)

    def test_no_raw_capture_is_tracked(self) -> None:
        for path in SKILL.rglob("*"):
            self.assertNotIn(path.suffix.lower(), {".pcap", ".pcapng", ".cap"}, str(path))

    def test_no_payload_bearing_fixture_value(self) -> None:
        for fixture in (SKILL / "examples" / "extracted").glob("*.jsonl"):
            for line in fixture.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, dict):
                    continue
                for field in ("nas-eps.emm.esm_msg_cont", "nas-eps.ciphered_msg", "nas-eps.msg_auth_code"):
                    value = record.get(field, "")
                    if value:
                        self.assertTrue(set(value) <= {"0"}, f"{fixture.name}: {field} must be zero-filled")


if __name__ == "__main__":
    unittest.main()
