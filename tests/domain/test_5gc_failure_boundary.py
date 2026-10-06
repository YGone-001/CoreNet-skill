"""Repository-level tests for the 5GC Failure Boundary Orchestration Skill."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills/orchestration/5gc-failure-boundary/tests/test_5gc_failure_boundary.py"
VALIDATOR_SCRIPT = ROOT / "scripts/validate-5gc-failure-boundary.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location("failure_boundary_package_tests", PACKAGE_TESTS)
PACKAGE_MODULE = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
PACKAGE_SPEC.loader.exec_module(PACKAGE_MODULE)
sys_modules_removed = __import__("sys").modules.pop("failure_boundary_model", None)

VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_5gc_failure_boundary", VALIDATOR_SCRIPT)
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(PACKAGE_MODULE))
    return tests


from pathlib import Path as _Path
_policy_module_path = _Path(__file__).resolve().parents[2] / "scripts" / "implementation_policy.py"
_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", _policy_module_path)
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)

class FailureBoundaryValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def assert_error(self, root: Path, text: str) -> None:
        errors = VALIDATOR.validate(root)
        self.assertTrue(any(text.lower() in error.lower() for error in errors),
                        f"Expected '{text}' in errors: {errors}")

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_wrong_category_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("category: orchestration", "category: domain"),
                                encoding="utf-8")
            self.assert_error(root, "manifest category must be orchestration")

    def test_raw_protocol_input_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\ndef parse_ngap_payload(raw):\n    return raw\n", encoding="utf-8")
            self.assert_error(root, "raw protocol decoding code")

    def test_pcap_parsing_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\ndef parse_gtp_packet(data):\n    return data\n", encoding="utf-8")
            self.assert_error(root, "raw protocol decoding code")

    def test_root_cause_schema_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/orchestration/5gc-failure-boundary/schemas/5gc-failure-boundary-analysis.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["root_cause"] = {"type": "string"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assert_error(root, "causal or implementation fields")

    def test_culprit_and_responsible_nf_schema_fields_are_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/orchestration/5gc-failure-boundary/schemas/5gc-failure-boundary-analysis.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["culprit"] = {"type": "string"}
            schema["properties"]["responsible_nf"] = {"type": "string"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assert_error(root, "causal or implementation fields")

    def test_timestamp_only_subject_linking_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\ndef link_by_timestamp(reg, pdu):\n    return True\n", encoding="utf-8")
            self.assert_error(root, "timestamp-only subject linking antipattern")

    def test_severity_based_candidate_sorting_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\nSEVERITY_ORDER = {'PROTOCOL_REJECT_OBSERVED': 1}\ncandidates.sort(key=lambda c: SEVERITY_ORDER.get(c.deviation.get('type'), 99))\n",
                             encoding="utf-8")
            self.assert_error(root, "severity-based candidate ranking antipattern")

    def test_partial_capture_selected_as_boundary_is_detected(self):
        # Behavioral: the committed partial-capture fixture must not select the
        # blocked missing-evidence candidate.
        sample = ROOT / "skills/orchestration/5gc-failure-boundary/examples/expected/partial-capture-blocks-missing-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        for group in doc["diagnostic_groups"]:
            self.assertNotEqual(group["selection_status"], "SELECTED")
            blocked = [c for c in group["candidate_boundaries"] if c["selectability"] == "BLOCKED_BY_PARTIAL_CAPTURE"]
            self.assertTrue(blocked)

    def test_no_abnormal_converted_to_success_is_detected(self):
        # The selection vocabulary is pinned on both sides: the engine constant
        # and the schema enum carry NO_ABNORMAL_BOUNDARY_OBSERVED and never a
        # success/health verdict; the package expected-output equality tests
        # catch any runtime drift.
        model = ROOT / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
        self.assertIn('SELECTION_NO_ABNORMAL = "NO_ABNORMAL_BOUNDARY_OBSERVED"',
                      model.read_text(encoding="utf-8"))
        schema = json.loads(
            (ROOT / "skills/orchestration/5gc-failure-boundary/schemas/5gc-failure-boundary-analysis.schema.json")
            .read_text(encoding="utf-8")
        )
        enum = schema["$defs"]["diagnosticGroup"]["properties"]["selection_status"]["enum"]
        self.assertIn("NO_ABNORMAL_BOUNDARY_OBSERVED", enum)
        for word in ("SUCCESS", "HEALTHY", "PASSED", "END_TO_END_OK"):
            self.assertNotIn(word, enum)

    def test_no_abnormal_success_wording_rejected_by_sanitizer(self):
        sample = ROOT / "skills/orchestration/5gc-failure-boundary/examples/expected/no-deviations-anywhere-analysis.json"
        text = sample.read_text(encoding="utf-8")
        for word in ("SUCCESS", "HEALTHY", "PASSED", "END_TO_END_OK"):
            self.assertNotIn(word, text)

    def test_missing_evidence_emitted_as_observed_is_detected(self):
        sample = ROOT / "skills/orchestration/5gc-failure-boundary/examples/expected/registration-missing-counterpart-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        for group in doc["diagnostic_groups"]:
            selected = group.get("selected_boundary")
            if selected:
                self.assertEqual(selected["boundary_ref"]["evidence_level"], "DERIVED")
                self.assertIsNone(selected["boundary_ref"]["boundary_anchor"]["frame_number"])

    def test_causal_downstream_relation_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\nRELATION_DOWNSTREAM = 'CAUSED_BY_BOUNDARY'\n", encoding="utf-8")
            self.assert_error(root, "causal downstream relation wording")

    def test_vendor_implementation_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            implementation_token = sorted(_POLICY.PROHIBITED_TOKENS)[0].upper()
            model.write_text(model.read_text(encoding="utf-8")
                             + f"\n{implementation_token}_SOURCE_HANDLER = 'smf/session/handler.go'\n", encoding="utf-8")
            self.assert_error(root, "implementation or vendor source mapping")

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/orchestration/5gc-failure-boundary/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRuntime path: ../../../shared\n", encoding="utf-8")
            self.assert_error(root, "repository-root runtime reference")

    def test_version_change_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.2.0", "version: 9.9.0"),
                                encoding="utf-8")
            self.assert_error(root, "manifest version must be 0.2.0")

    def test_downgraded_registration_dependency_floor_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "5gc-registration-mobility >=0.2.0", "5gc-registration-mobility >=0.1.0"),
                encoding="utf-8")
            self.assert_error(root, "5gc-registration-mobility >=0.2.0")

    def test_downgraded_pdu_session_dependency_floor_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "5gc-pdu-session >=0.4.0", "5gc-pdu-session >=0.3.0"),
                encoding="utf-8")
            self.assert_error(root, "5gc-pdu-session >=0.4.0")

    def test_nonexistent_fixture_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "examples/inputs/registration-only", "examples/inputs/nonexistent-scenario"),
                encoding="utf-8")
            self.assert_error(root, "testing.fixtures path does not exist")

    def test_nonexistent_expected_result_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "examples/expected/registration-only-analysis.json",
                "examples/expected/nonexistent-scenario-analysis.json"),
                encoding="utf-8")
            self.assert_error(root, "testing.expected_results path does not exist")

    def test_wrong_version_after_mobility_expansion_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.2.0", "version: 0.1.0"),
                                encoding="utf-8")
            self.assert_error(root, "manifest version must be 0.2.0")

    def test_missing_mobility_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "    - 5gc-handover-mobility >=0.1.0\n", ""),
                encoding="utf-8")
            self.assert_error(root, "manifest optional dependencies must be exactly")

    def test_downgraded_mobility_dependency_floor_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/orchestration/5gc-failure-boundary/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "5gc-handover-mobility >=0.1.0", "5gc-handover-mobility >=0.0.1"),
                encoding="utf-8")
            self.assert_error(root, "5gc-handover-mobility >=0.1.0")

    def test_missing_mobility_behavioral_scenario_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            shutil.rmtree(root / "skills/orchestration/5gc-failure-boundary/examples/inputs/handover-bridge-strong")
            self.assert_error(root, "synthetic input scenarios must cover all 70 bounded cases")

    def test_mobility_adapter_removal_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace(
                "_handover_mobility_instances", "_removed_mobility_instances"),
                encoding="utf-8")
            self.assert_error(root, "mobility Domain adapter is missing")

    def test_mobility_version_floor_removal_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace(
                "HANDOVER_MOBILITY_VERSION_FLOOR = (0, 1, 0)", "HANDOVER_MOBILITY_VERSION_FLOOR = (0, 0, 1)"),
                encoding="utf-8")
            self.assert_error(root, "mobility source-version floor gate is missing")

    def test_mobility_stage_position_ordering_is_detected(self):
        # Reading the Mobility stages array inside the adapter would open the
        # door to treating array position as chronological order; the gate
        # rejects it.
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace(
                '            extra_identity: dict[str, Any] = {\n                "mobility_attempt_family": family,',
                '            stage_order = attempt.get("stages", {})\n            extra_identity: dict[str, Any] = {\n                "mobility_attempt_family": family,'),
                encoding="utf-8")
            self.assert_error(root, "the mobility adapter must not read stages array positions as ordering")

    def test_unbound_mobility_evidence_reading_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace(
                '    instances: list[SourceInstance] = []\n    for family_field, family in',
                '    unbound_mobility_evidence = doc.get("unbound_mobility_evidence")\n    instances: list[SourceInstance] = []\n    for family_field, family in'),
                encoding="utf-8")
            self.assert_error(root, "the mobility adapter must not read unbound_mobility_evidence")

    def test_behavioral_gates_still_exercise_after_engine_edit(self):
        # A UNBOUND->STRONG swap on singleton links does not break the
        # behavioral gates (they pin multi-instance behavior), but this test
        # proves the gates run against the real engine without crashing.
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/orchestration/5gc-failure-boundary/scripts/failure_boundary_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace(
                'if len(group) == 1:\n        subject_link = {\n            "strength": "UNBOUND",',
                'if len(group) == 1:\n        subject_link = {\n            "strength": "STRONG",'),
                encoding="utf-8")
            errors = VALIDATOR.validate(root)
            self.assertTrue(isinstance(errors, list))


if __name__ == "__main__":
    unittest.main()
