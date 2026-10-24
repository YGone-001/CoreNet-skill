#!/usr/bin/env python3
"""Repository-level tests for the s1ap validator and Skill package contract."""

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
SKILL = ROOT / "skills" / "protocol" / "s1ap"


def load_validator():
    path = ROOT / "scripts" / "validate-s1ap.py"
    spec = importlib.util.spec_from_file_location("validate_s1ap_under_test", path)
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
        target = self.root / "skills" / "protocol" / "s1ap"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SKILL, target)
        self.skill = target

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_repository_package_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_reported(self) -> None:
        (self.skill / "filters" / "wireshark.txt").unlink()
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("filters/wireshark.txt" in error for error in errors), errors)

    def test_wrong_manifest_category_is_reported(self) -> None:
        manifest = self.skill / "manifest.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace("category: protocol", "category: domain"),
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("category must be protocol" in error for error in errors), errors)

    def test_expected_event_mismatch_is_reported(self) -> None:
        expected = self.skill / "examples" / "expected" / "s1-setup-events.jsonl"
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
        records[0]["message_type"] = "NotARealMessage"
        expected.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("do not match" in error for error in errors), errors)

    def test_published_payload_field_is_rejected(self) -> None:
        expected = self.skill / "examples" / "expected" / "ue-release-events.jsonl"
        records = [json.loads(line) for line in expected.read_text(encoding="utf-8").splitlines()]
        records[0]["nas_pdu"] = "00" * 8
        expected.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("forbidden evidence field" in error for error in errors), errors)

    def test_conflicting_identifiers_must_stay_ambiguous(self) -> None:
        fixture = self.skill / "examples" / "extracted" / "conflicting-ids.jsonl"
        records = [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]
        records[2]["s1ap.MME_UE_S1AP_ID"] = "100"
        fixture.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("AMBIGUOUS" in error for error in errors), errors)

    def test_lifecycle_marker_is_reported(self) -> None:
        readme = self.skill / "README.md"
        readme.write_text(
            readme.read_text(encoding="utf-8") + "\nPhase 3 delivery notes.\n", encoding="utf-8"
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
        forbidden = {"nas_eps_model", "ngap_model", "nas5gs_model"}
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


if __name__ == "__main__":
    unittest.main()
