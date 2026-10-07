"""Repository-level tests for the gtpu package validator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-gtpu.py"
SPEC = importlib.util.spec_from_file_location("validate_gtpu", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)

_policy_spec = importlib.util.spec_from_file_location(
    "implementation_policy", ROOT / "scripts" / "implementation_policy.py")
_POLICY = importlib.util.module_from_spec(_policy_spec)
assert _policy_spec.loader is not None
_policy_spec.loader.exec_module(_POLICY)


class GtpuValidatorTests(unittest.TestCase):
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
            (root / "skills/protocol/gtpu/manifest.yaml").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(any("missing required package file" in error for error in errors))

    def test_wrong_version_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/gtpu/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.1.1", "version: 0.2.0"), encoding="utf-8")
            self.assertTrue(any("manifest version must be 0.1.1" in error for error in VALIDATOR.validate(root)))

    def test_missing_field_spec_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8").replace("FieldSpec", "OtherSpec"), encoding="utf-8")
            self.assertTrue(any("FieldSpec compatibility model" in error for error in VALIDATOR.validate(root)))

    def test_wrong_category_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/gtpu/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("category: protocol", "category: domain"), encoding="utf-8")
            self.assertTrue(any("manifest category must be protocol" in error for error in VALIDATOR.validate(root)))

    def test_unauthorized_n9_interface_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/gtpu/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("interfaces: [N3]", "interfaces: [N3, N9]"), encoding="utf-8")
            self.assertTrue(any("interface ownership must be N3 only" in error for error in VALIDATOR.validate(root)))

    def test_network_function_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/gtpu/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("network_functions: []", "network_functions: [UPF]"), encoding="utf-8")
            self.assertTrue(any("network_functions must stay empty" in error for error in VALIDATOR.validate(root)))

    def test_required_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/gtpu/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("  required: []", "  required:\n    - pfcp >=0.1.0"), encoding="utf-8")
            self.assertTrue(any("must not require another CoreNet Skill" in error for error in VALIDATOR.validate(root)))

    def test_trace_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/gtpu/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("trace schema" in error for error in VALIDATOR.validate(root)))

    def test_raw_gtpu_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nFLAGS = int.from_bytes(b'\\x30', 'big')\n", encoding="utf-8")
            self.assertTrue(any("byte-level GTP-U decoder" in error for error in VALIDATOR.validate(root)))

    def test_pfcp_join_logic_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nMATCH = match_pfcp(teid)\n", encoding="utf-8")
            self.assertTrue(any("PFCP join logic" in error for error in VALIDATOR.validate(root)))

    def test_ngap_join_logic_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nNGAP_TEID = 1\n", encoding="utf-8")
            self.assertTrue(any("NGAP join logic" in error for error in VALIDATOR.validate(root)))

    def test_nas_join_logic_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\ndef decode_nas(payload):\n    return payload\n", encoding="utf-8")
            self.assertTrue(any("NAS join logic" in error for error in VALIDATOR.validate(root)))

    def test_sbi_semantics_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nSBI_CLIENT = 1\n", encoding="utf-8")
            self.assertTrue(any("SBI semantics" in error for error in VALIDATOR.validate(root)))

    def test_application_payload_persistence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + '\nevent["payload_bytes"] = b"deadbeef"\n', encoding="utf-8")
            self.assertTrue(any("application payload handling" in error for error in VALIDATOR.validate(root)))

    def test_application_protocol_decoding_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\ndef decode_sip(payload):\n    return payload\n", encoding="utf-8")
            self.assertTrue(any("application payload handling" in error for error in VALIDATOR.validate(root)))

    def test_packet_loss_verdict_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nPACKET_LOSS = True\n", encoding="utf-8")
            self.assertTrue(any("packet-loss verdict" in error for error in VALIDATOR.validate(root)))

    def test_global_teid_only_stream_key_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/gtpu/scripts/gtpu_model.py"
            text = model.read_text(encoding="utf-8").replace('f"gtpu-path:', 'f"gtpu-teid:')
            model.write_text(text, encoding="utf-8")
            self.assertTrue(any("directed stream key" in error for error in VALIDATOR.validate(root)))

    def test_vendor_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            reference = root / "skills/protocol/gtpu/references/protocol-model.md"
            reference.write_text(reference.read_text(encoding="utf-8") + "\nSee " + sorted(_POLICY.PROHIBITED_TOKENS)[0] + " source tree.\n", encoding="utf-8")
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_production_address_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/gtpu/examples/extracted/g-pdu-basic.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8").replace("192.0.2.10", "10.44.12.9"), encoding="utf-8")
            self.assertTrue(any("non-documentation IP address" in error for error in VALIDATOR.validate(root)))

    def test_subscriber_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/gtpu/examples/extracted/g-pdu-basic.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8") + '{"frame.number":"99","frame.time_epoch":"1","imsi": "001010000000001"}\n', encoding="utf-8")
            self.assertTrue(any("subscriber identity field" in error for error in VALIDATOR.validate(root)))

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/gtpu/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRun ../../../scripts/validate-repository.py\n", encoding="utf-8")
            self.assertTrue(any("repository-root runtime reference" in error for error in VALIDATOR.validate(root)))

    def test_binary_capture_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            capture = root / "skills/protocol/gtpu/examples/extracted/unsanctioned.pcapng"
            capture.write_bytes(b"synthetic")
            self.assertTrue(any("binary capture fixture" in error for error in VALIDATOR.validate(root)))

    def test_missing_g_pdu_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            for name in VALIDATOR.EXPECTED_EVENTS:
                expected = root / "skills/protocol/gtpu" / name
                kept = []
                for line in expected.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    if (event.get("header") or {}).get("message_type") == "G-PDU":
                        continue
                    kept.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
                expected.write_text("\n".join(kept) + "\n", encoding="utf-8")
            self.assertTrue(any("observed G-PDU" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
