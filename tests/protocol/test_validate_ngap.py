"""Repository-level tests for the ngap package validator."""

from __future__ import annotations

import importlib.util
import json
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

_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", ROOT / "scripts" / "implementation_policy.py")
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)

RESOURCE_EXPECTED = (
    "pdu-session-setup-events.jsonl",
    "pdu-session-modify-events.jsonl",
    "pdu-session-release-events.jsonl",
    "initial-context-resources-events.jsonl",
    "pdu-session-qfi-events.jsonl",
    "pdu-session-identity-events.jsonl",
    "pdu-session-recognition-events.jsonl",
    "pdu-session-ordering-events.jsonl",
)


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
            reference.write_text(reference.read_text(encoding="utf-8") + "\nSee " + sorted(_POLICY.PROHIBITED_TOKENS)[0] + " source.\n", encoding="utf-8")
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_concrete_domain_package_does_not_change_ngap_validation_scope(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_subscriber_field_in_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/ngap/examples/extracted/ue-context-flow.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            lines = fixture.read_text(encoding="utf-8").splitlines()
            lines.append('{"frame.number":"99","frame.time_epoch":"1704164700.000000","ngap.procedureCode":"15","imsi": "001010000000001"}')
            fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertTrue(any("subscriber identity" in error for error in VALIDATOR.validate(root)))

    def test_wrong_version_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/ngap/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.3.2", "version: 0.1.0"), encoding="utf-8")
            self.assertTrue(any("manifest version must be 0.3.2" in error for error in VALIDATOR.validate(root)))

    def test_version_left_at_previous_release_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/ngap/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.3.2", "version: 0.3.1"), encoding="utf-8")
            self.assertTrue(any("manifest version must be 0.3.2" in error for error in VALIDATOR.validate(root)))

    def test_missing_field_spec_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace("FieldSpec", "OtherSpec"), encoding="utf-8")
            self.assertTrue(any("FieldSpec" in error for error in VALIDATOR.validate(root)))

    def test_fuzzy_field_matching_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\n# fuzzy candidate matching\n", encoding="utf-8")
            self.assertTrue(any("fuzzy" in error for error in VALIDATOR.validate(root)))

    def test_missing_direct_capture_doc_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            ref = root / "skills/protocol/ngap/references/field-reference.md"
            ref.write_text(ref.read_text(encoding="utf-8").replace("Direct-Capture TShark Compatibility", "Old Compatibility"), encoding="utf-8")
            self.assertTrue(any("direct-capture" in error for error in VALIDATOR.validate(root)))

    def test_handover_excluded_in_scope_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/ngap/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace(
                "- NAS-PDU decoding or any NAS semantic field (handoff to nas-5gs)",
                "- NAS-PDU decoding or any NAS semantic field (handoff to nas-5gs)\n    - NGAP handover and path-switch procedures"),
                encoding="utf-8")
            self.assertTrue(any("must no longer exclude handover/path-switch" in error for error in VALIDATOR.validate(root)))

    def test_missing_mobility_scope_declaration_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/ngap/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("handover and path-switch mobility evidence", "mobility evidence"),
                                encoding="utf-8")
            self.assertTrue(any("must declare the bounded handover/path-switch" in error for error in VALIDATOR.validate(root)))

    def assert_forbidden_schema_field_detected(self, field: str) -> None:
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/protocol/ngap/schemas/ngap-event.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"][field] = {"type": "string"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assertTrue(any("mobility verdict fields" in error for error in VALIDATOR.validate(root)))

    def test_handover_success_field_is_detected(self):
        self.assert_forbidden_schema_field_detected("handover_success")

    def test_path_switch_success_field_is_detected(self):
        self.assert_forbidden_schema_field_detected("path_switch_success")

    def test_root_cause_field_is_detected(self):
        self.assert_forbidden_schema_field_detected("root_cause")

    def test_radio_failure_field_is_detected(self):
        self.assert_forbidden_schema_field_detected("radio_failure")

    def test_transparent_container_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\ndef decode_transparent_container(raw):\n    return raw\n", encoding="utf-8")
            self.assertTrue(any("transparent-container decoder" in error for error in VALIDATOR.validate(root)))

    def test_raw_mobility_container_persistence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\nCONTAINER_BYTES = SourceToTarget_container\n", encoding="utf-8")
            self.assertTrue(any("raw container/transfer byte persistence" in error for error in VALIDATOR.validate(root)))

    def test_teid_from_opaque_transfer_bytes_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\nTEID = handoverCommandTransfer[:4]\n", encoding="utf-8")
            self.assertTrue(any("foreign protocol semantics" in error for error in VALIDATOR.validate(root)))

    def test_positional_resource_zip_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\nfor sid, qfi in zip(session_ids, qfis):\n    pass\n", encoding="utf-8")
            self.assertTrue(any("positional resource-item zip" in error for error in VALIDATOR.validate(root)))

    def test_timestamp_based_association_join_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8")
                             + "\ndef link_by_timestamp(source_events, target_events):\n    return True\n", encoding="utf-8")
            self.assertTrue(any("timestamp-based association joining" in error for error in VALIDATOR.validate(root)))

    def test_singular_only_resource_schema_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/protocol/ngap/schemas/ngap-event.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["pdu_session_resources"] = {"type": "integer"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assertTrue(any("must be an array" in error for error in VALIDATOR.validate(root)))

    def test_required_resource_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/protocol/ngap/schemas/ngap-event.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["required"].append("pdu_session_resources")
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assertTrue(any("must stay optional" in error for error in VALIDATOR.validate(root)))

    def test_missing_multi_resource_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            for name in RESOURCE_EXPECTED:
                expected = root / "skills/protocol/ngap/examples/expected" / name
                kept = []
                for line in expected.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    event.pop("pdu_session_resources", None)
                    kept.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
                expected.write_text("\n".join(kept) + "\n", encoding="utf-8")
            self.assertTrue(any("two or more PDU Session resources" in error for error in VALIDATOR.validate(root)))

    def test_missing_mixed_outcome_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            for name in RESOURCE_EXPECTED:
                expected = root / "skills/protocol/ngap/examples/expected" / name
                kept = []
                for line in expected.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    items = event.get("pdu_session_resources")
                    if isinstance(items, list):
                        for item in items:
                            item["resource_list_role"] = "SUCCESS"
                    kept.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
                expected.write_text("\n".join(kept) + "\n", encoding="utf-8")
            self.assertTrue(any("mixing successful and failed" in error for error in VALIDATOR.validate(root)))

    def test_foreign_protocol_semantics_are_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nPFCP_SESSION_ESTABLISHMENT = 1\n", encoding="utf-8")
            self.assertTrue(any("foreign protocol semantics" in error for error in VALIDATOR.validate(root)))

    def test_asn1_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nimport pyasn1\n", encoding="utf-8")
            self.assertTrue(any("ASN.1 decoder" in error for error in VALIDATOR.validate(root)))

    def test_session_field_fabrication_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/ngap/scripts/ngap_model.py"
            model.write_text(model.read_text(encoding="utf-8") + '\nFABRICATED = {"teid": None}\n', encoding="utf-8")
            self.assertTrue(any("session field fabrication" in error for error in VALIDATOR.validate(root)))

    def test_production_ip_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/ngap/examples/extracted/ue-context-flow.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8").replace("192.0.2.10", "10.44.12.9"), encoding="utf-8")
            self.assertTrue(any("non-documentation IP address" in error for error in VALIDATOR.validate(root)))

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/ngap/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRun ../../../scripts/validate-repository.py\n", encoding="utf-8")
            self.assertTrue(any("repository-root runtime reference" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
