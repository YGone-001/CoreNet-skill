"""Repository-level tests for the nas-5gs package validator."""

from __future__ import annotations

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-nas-5gs.py"
SPEC = importlib.util.spec_from_file_location("validate_nas5gs", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)

_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", ROOT / "scripts" / "implementation_policy.py")
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)


class Nas5gsValidatorTests(unittest.TestCase):
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
            (root / "skills/protocol/nas-5gs/manifest.yaml").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(any("missing required package file" in error for error in errors))

    def test_trace_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/nas-5gs/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("trace schema" in error for error in VALIDATOR.validate(root)))

    def test_binary_capture_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            capture = root / "skills/protocol/nas-5gs/examples/extracted/unsanctioned.pcapng"
            capture.write_bytes(b"synthetic")
            self.assertTrue(any("binary capture fixture" in error for error in VALIDATOR.validate(root)))

    def test_absolute_workstation_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/nas-5gs/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nC:\\Users\\analyst\\capture.pcapng\n", encoding="utf-8")
            self.assertTrue(any("absolute workstation path" in error for error in VALIDATOR.validate(root)))

    def test_implementation_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            reference = root / "skills/protocol/nas-5gs/references/protocol-model.md"
            reference.write_text(reference.read_text(encoding="utf-8") + "\nSee " + sorted(_POLICY.PROHIBITED_TOKENS)[0] + " source tree.\n", encoding="utf-8")
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_ngap_ownership_duplication_in_scripts_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/nas-5gs/scripts/nas5gs_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nNGAP_ID_FIELD = 'amf_ue_ngap_id'\n", encoding="utf-8")
            self.assertTrue(any("NGAP identifier ownership" in error for error in VALIDATOR.validate(root)))

    def test_raw_subscriber_identity_in_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/nas-5gs/examples/extracted/mobility-types.jsonl"
            fixture.write_text(
                fixture.read_text(encoding="utf-8")
                + '{"frame.number":"9","frame.time_epoch":"1704164770.000009","imsi": "001010000000001"}\n',
                encoding="utf-8",
            )
            self.assertTrue(any("raw subscriber identity" in error for error in VALIDATOR.validate(root)))

    def test_authentication_secret_in_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/nas-5gs/examples/extracted/mobility-types.jsonl"
            fixture.write_text(
                fixture.read_text(encoding="utf-8")
                + '{"frame.number":"9","frame.time_epoch":"1704164770.000009","rand": "00112233445566778899aabbccddeeff"}\n',
                encoding="utf-8",
            )
            self.assertTrue(any("authentication secret material" in error for error in VALIDATOR.validate(root)))

    def test_concrete_domain_package_does_not_change_nas_validation_scope(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_wrong_version_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/nas-5gs/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.2.0", "version: 0.1.0"), encoding="utf-8")
            self.assertTrue(any("manifest version must be 0.2.0" in error for error in VALIDATOR.validate(root)))

    def test_missing_5gsm_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/protocol/nas-5gs/examples/extracted/sm-establishment-request.jsonl").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(
                any("missing required package file" in error or "5GSM fixture is missing" in error for error in errors),
                errors,
            )

    def test_foreign_protocol_semantics_are_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/nas-5gs/scripts/nas5gs_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nPFCP_SESSION_ESTABLISHMENT = 1\n", encoding="utf-8")
            self.assertTrue(any("foreign protocol semantics" in error for error in VALIDATOR.validate(root)))

    def test_session_field_fabrication_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/nas-5gs/scripts/nas5gs_model.py"
            model.write_text(model.read_text(encoding="utf-8") + '\nFABRICATED = {"teid": None}\n', encoding="utf-8")
            self.assertTrue(any("session field fabrication" in error for error in VALIDATOR.validate(root)))

    def test_production_ip_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/nas-5gs/examples/extracted/sm-establishment-accept.jsonl"
            fixture.write_text(
                fixture.read_text(encoding="utf-8").replace("192.0.2.10", "10.44.12.9"),
                encoding="utf-8",
            )
            self.assertTrue(any("non-documentation IP address" in error for error in VALIDATOR.validate(root)))

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/nas-5gs/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRun ../../../scripts/validate-repository.py\n", encoding="utf-8")
            self.assertTrue(any("repository-root runtime reference" in error for error in VALIDATOR.validate(root)))

    def test_forbidden_pdu_session_protocol_package_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/protocol/5gc-pdu-session").mkdir(parents=True)
            self.assertTrue(any("5gc-pdu-session" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
