#!/usr/bin/env python3
"""Repository-level tests for the gtpv2 validator and Skill package contract."""

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
SKILL = ROOT / "skills" / "protocol" / "gtpv2"


def load_validator():
    path = ROOT / "scripts" / "validate-gtpv2.py"
    spec = importlib.util.spec_from_file_location("validate_gtpv2_under_test", path)
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
        target = self.root / "skills" / "protocol" / "gtpv2"
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
        self.assertTrue(any("filters/wireshark.txt" in error for error in errors))

    def test_missing_reference_is_reported(self) -> None:
        (self.skill / "references" / "correlation.md").unlink()
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("references/correlation.md" in error for error in errors))

    def test_tampered_expected_events_are_reported(self) -> None:
        expected = self.skill / "examples" / "expected" / "session-control-events.jsonl"
        rows = expected.read_text(encoding="utf-8").splitlines()
        record = json.loads(rows[0])
        record["message_type_code"] = 1
        rows[0] = json.dumps(record, sort_keys=True, separators=(",", ":"))
        expected.write_text("\n".join(rows) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("produced events do not match" in error for error in errors))

    def test_tampered_expected_transactions_are_reported(self) -> None:
        expected = self.skill / "examples" / "expected" / "session-control-transactions.json"
        payload = json.loads(expected.read_text(encoding="utf-8"))
        payload["matched_count"] = 0
        expected.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("produced transactions do not match" in error for error in errors))

    def test_subscriber_identity_in_pdml_fixture_is_reported(self) -> None:
        fixture = self.skill / "examples" / "pdml" / "session-control.pdml"
        text = fixture.read_text(encoding="utf-8").replace("000000000000000", "460020000000001", 1)
        fixture.write_text(text, encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("subscriber identity" in error for error in errors))

    def test_raw_capture_inside_the_skill_is_reported(self) -> None:
        (self.skill / "examples" / "leak.pcap").write_bytes(b"")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("raw capture committed" in error for error in errors))

    def test_lifecycle_marker_is_reported(self) -> None:
        readme = self.skill / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nDelivered in Phase 4.\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("lifecycle marker" in error for error in errors))

    def test_manifest_identity_is_checked(self) -> None:
        manifest = self.skill / "manifest.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace("name: gtpv2", "name: other", 1),
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("manifest name must be gtpv2" in error for error in errors))


class PackageContractTests(unittest.TestCase):
    def test_scripts_only_use_the_standard_library(self) -> None:
        allowed = {
            "argparse",
            "csv",
            "json",
            "os",
            "re",
            "shutil",
            "subprocess",
            "sys",
            "tempfile",
            "xml",
            "datetime",
            "decimal",
            "pathlib",
            "typing",
            "dataclasses",
            "__future__",
            "gtpv2_model",
        }
        for script in (SKILL / "scripts").glob("*.py"):
            names = imported_modules(script.read_text(encoding="utf-8"))
            unexpected = names - allowed
            self.assertEqual(unexpected, set(), f"{script.name} imports {sorted(unexpected)}")

    def test_no_raw_capture_or_private_subscriber_values(self) -> None:
        for path in SKILL.rglob("*"):
            if not path.is_file():
                continue
            self.assertNotIn(path.suffix.lower(), {".pcap", ".pcapng", ".cap"})
            if path.suffix.lower() in {".md", ".py", ".yaml", ".json", ".jsonl", ".txt", ".pdml"}:
                text = path.read_text(encoding="utf-8")
                for marker in ("460020000000001", "919000001", "1122334455667788"):
                    self.assertNotIn(marker, text, f"{path.relative_to(SKILL)} contains a subscriber identity")

    def test_skill_documents_the_required_boundaries(self) -> None:
        skill_md = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for statement in (
            "No session, PDN-connection or bearer lifecycle reconstruction",
            "No subscriber identity, APN name, PAA address or raw IE byte publication",
            "No bearer-context grouping inferred from flat list order",
        ):
            self.assertIn(statement, skill_md)

    def test_manifest_lists_every_example(self) -> None:
        manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
        for path in sorted((SKILL / "examples").rglob("*")):
            if path.is_file() and path.suffix in {".jsonl", ".json", ".pdml"}:
                relative = path.relative_to(SKILL).as_posix()
                self.assertIn(relative, manifest, f"{relative} is not declared in manifest.yaml")


if __name__ == "__main__":
    unittest.main()
