#!/usr/bin/env python3
"""Repository-level tests for the epc-failure-boundary validator."""

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
    tree = ast.parse(text)
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "orchestration" / "epc-failure-boundary"


def load_validator():
    path = ROOT / "scripts" / "validate-epc-failure-boundary.py"
    spec = importlib.util.spec_from_file_location("validate_epc_boundary_under_test", path)
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
        target = self.root / "skills" / "orchestration" / "epc-failure-boundary"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(SKILL, target)
        self.skill = target

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def expected_path(self, case: str = "attach-reject") -> Path:
        return self.skill / "examples" / "expected" / f"{case}-analysis.json"

    def rewrite(self, path: Path, mutate) -> None:
        payload = json.loads(path.read_text(encoding="utf-8"))
        mutate(payload)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_repository_package_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_reported(self) -> None:
        (self.skill / "rules" / "epc-boundary-rules.json").unlink()
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("rules/epc-boundary-rules.json" in error for error in errors))

    def test_tampered_expected_analysis_is_reported(self) -> None:
        self.rewrite(self.expected_path(), lambda payload: payload["diagnostic_groups"][0].update(
            {"boundary_selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED"}
        ))
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("does not match the committed expected result" in error for error in errors))

    def test_causal_wording_is_reported(self) -> None:
        self.rewrite(
            self.expected_path(),
            lambda payload: payload["limitations"].append("the root cause is the MME"),
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("causal claim" in error for error in errors))

    def test_boundary_frame_outside_evidence_is_reported(self) -> None:
        def mutate(payload: dict) -> None:
            boundary = payload["diagnostic_groups"][0]["first_abnormal_boundary"]
            boundary["frame_number"] = 999
        self.rewrite(self.expected_path(), mutate)
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("absent from its evidence references" in error for error in errors))

    def test_selected_group_without_confidence_is_reported(self) -> None:
        self.rewrite(
            self.expected_path(),
            lambda payload: payload["diagnostic_groups"][0].update({"boundary_confidence": None}),
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("confidence level" in error for error in errors))

    def test_cross_subject_link_is_reported(self) -> None:
        self.rewrite(
            self.expected_path(),
            lambda payload: payload["diagnostic_groups"][0]["subject_link"].update(
                {"cross_subject_link": "ESTABLISHED"}
            ),
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("cross-subject link" in error for error in errors))

    def test_rules_mismatch_is_reported(self) -> None:
        path = self.skill / "rules" / "epc-boundary-rules.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["selectable_attach_deviations"] = ["ATTACH_REJECT_OBSERVED"]
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("Attach selectable set" in error for error in errors))

    def test_manifest_identity_is_checked(self) -> None:
        manifest = self.skill / "manifest.yaml"
        manifest.write_text(
            manifest.read_text(encoding="utf-8").replace("name: epc-failure-boundary", "name: other", 1),
            encoding="utf-8",
        )
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("manifest name must be epc-failure-boundary" in error for error in errors))

    def test_lifecycle_marker_is_reported(self) -> None:
        readme = self.skill / "README.md"
        readme.write_text(readme.read_text(encoding="utf-8") + "\nDelivered in Phase 5.\n", encoding="utf-8")
        errors = VALIDATOR.validate(self.root)
        self.assertTrue(any("lifecycle marker" in error for error in errors))


class PackageContractTests(unittest.TestCase):
    def test_scripts_use_only_the_standard_library(self) -> None:
        allowed = {
            "argparse", "hashlib", "json", "os", "re", "sys", "tempfile", "dataclasses",
            "pathlib", "typing", "__future__", "epc_boundary_model", "epc_boundary_report",
        }
        for script in (SKILL / "scripts").glob("*.py"):
            unexpected = imported_modules(script.read_text(encoding="utf-8")) - allowed
            self.assertEqual(unexpected, set(), f"{script.name} imports {sorted(unexpected)}")

    def test_skill_documents_the_required_boundaries(self) -> None:
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        for statement in (
            "No root cause, no network-function blame, no severity ranking.",
            "No Attach-to-session or S11-to-S5/S8 identity bridge",
            "Refuse to claim an earliest boundary when the source candidate list is",
        ):
            self.assertIn(statement, text)

    def test_manifest_declares_every_example(self) -> None:
        manifest = (SKILL / "manifest.yaml").read_text(encoding="utf-8")
        for path in sorted((SKILL / "examples").rglob("*")):
            if path.is_file() and path.suffix in {".json", ".txt"}:
                relative = path.relative_to(SKILL).as_posix()
                self.assertIn(relative, manifest, f"{relative} is not declared in manifest.yaml")


if __name__ == "__main__":
    unittest.main()
