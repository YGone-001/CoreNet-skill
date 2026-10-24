#!/usr/bin/env python3
"""Repository-level tests for the epc-procedures validator and Domain contract."""

from __future__ import annotations

import ast
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "domain" / "epc-procedures"


def load_validator():
    path = ROOT / "scripts" / "validate-epc-procedures.py"
    spec = importlib.util.spec_from_file_location("validate_epc_procedures_under_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR = load_validator()


def imported_modules(text: str) -> set[str]:
    tree = ast.parse(text)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        target = self.root / "skills" / "domain" / "epc-procedures"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SKILL, target)
        self.skill = target

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_repository_package_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_reported(self) -> None:
        (self.skill / "references" / "evidence-rules.md").unlink()
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("evidence-rules.md" in error for error in errors), errors)

    def test_expected_analysis_mismatch_is_reported(self) -> None:
        path = self.skill / "examples" / "expected" / "attach-reject-analysis.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["instance_count"] = 99
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("does not match" in error for error in errors), errors)

    def test_invented_global_boundary_is_reported(self) -> None:
        path = self.skill / "examples" / "expected" / "attach-reject-analysis.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["global_first_abnormal_boundary"] = {"frame_number": 47}
        document["global_boundary_evaluation"] = "SELECTED"
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("global" in error for error in errors), errors)

    def test_deviation_without_evidence_reference_is_reported(self) -> None:
        path = self.skill / "examples" / "expected" / "auth-failure-analysis.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        deviation = document["procedure_instances"][0]["deviations"][0]
        deviation["evidence_refs"] = []
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("without an evidence reference" in error for error in errors), errors)

    def test_success_claim_is_reported(self) -> None:
        path = self.skill / "examples" / "expected" / "attach-reject-analysis.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        document["limitations"].append("bearer_active confirmed")
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("forbidden success" in error for error in errors), errors)

    def test_lifecycle_marker_is_reported(self) -> None:
        readme = self.skill / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nPhase 5 notes.\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("lifecycle marker" in error for error in errors), errors)


class PackageContractTests(unittest.TestCase):
    def test_package_layout(self) -> None:
        for required in (
            "SKILL.md", "README.md", "manifest.yaml", "references", "rules",
            "schemas", "scripts", "examples", "tests",
        ):
            self.assertTrue((SKILL / required).exists(), required)

    def test_scripts_do_not_import_other_skill_models(self) -> None:
        forbidden = {"s1ap_model", "nas_eps_model", "ngap_model", "nas5gs_model", "corenet_analyze"}
        for script in (SKILL / "scripts").glob("*.py"):
            imported = imported_modules(script.read_text(encoding="utf-8"))
            self.assertFalse(forbidden & imported, f"{script.name} must stay standalone")

    def test_manifest_declares_no_required_dependency(self) -> None:
        manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("required: []", manifest)

    def test_no_raw_capture_is_tracked(self) -> None:
        for path in SKILL.rglob("*"):
            self.assertNotIn(path.suffix.lower(), {".pcap", ".pcapng", ".cap"}, str(path))

    def test_analysis_schema_matches_expected_documents(self) -> None:
        schema = json.loads(
            (SKILL / "schemas" / "epc-attach-analysis.schema.json").read_text(encoding="utf-8")
        )
        required = set(schema["required"])
        for path in (SKILL / "examples" / "expected").glob("*-analysis.json"):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(required.issubset(document), f"{path.name} misses {required - set(document)}")


if __name__ == "__main__":
    unittest.main()
