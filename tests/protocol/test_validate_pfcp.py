"""Repository-level tests for the pfcp package validator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-pfcp.py"
SPEC = importlib.util.spec_from_file_location("validate_pfcp", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class PfcpValidatorTests(unittest.TestCase):
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
            (root / "skills/protocol/pfcp/manifest.yaml").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(any("missing required package file" in error for error in errors))

    def test_wrong_version_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/pfcp/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.1.0", "version: 0.2.0"), encoding="utf-8")
            self.assertTrue(any("manifest version must be 0.1.0" in error for error in VALIDATOR.validate(root)))

    def test_wrong_category_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/pfcp/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("category: protocol", "category: domain"), encoding="utf-8")
            self.assertTrue(any("manifest category must be protocol" in error for error in VALIDATOR.validate(root)))

    def test_network_function_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/pfcp/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("network_functions: []", "network_functions: [SMF, UPF]"), encoding="utf-8")
            self.assertTrue(any("network_functions must stay empty" in error for error in VALIDATOR.validate(root)))

    def test_required_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/pfcp/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("  required: []", "  required:\n    - ngap >=0.2.0"), encoding="utf-8")
            self.assertTrue(any("must not require another CoreNet Skill" in error for error in VALIDATOR.validate(root)))

    def test_trace_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/pfcp/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("trace schema" in error for error in VALIDATOR.validate(root)))

    def test_singular_only_rule_structure_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/protocol/pfcp/schemas/pfcp-event.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["rule_operations"]["properties"]["pdrs"] = {"type": "object"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assertTrue(any("must be an array" in error for error in VALIDATOR.validate(root)))

    def test_positional_zip_logic_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nPAIRS = list(zip(pdr_ids, teids))\n", encoding="utf-8")
            self.assertTrue(any("positional zipping" in error for error in VALIDATOR.validate(root)))

    def test_raw_pfcp_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nHEADER = int.from_bytes(b'\\x20\\x01', 'big')\n", encoding="utf-8")
            self.assertTrue(any("binary PFCP decoder" in error for error in VALIDATOR.validate(root)))

    def test_gtpu_semantic_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nGTPU_TEID_FORWARDING = 1\n", encoding="utf-8")
            self.assertTrue(any("foreign protocol semantics" in error for error in VALIDATOR.validate(root)))

    def test_sbi_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nSBI_CLIENT = 1\n", encoding="utf-8")
            self.assertTrue(any("foreign protocol semantics" in error for error in VALIDATOR.validate(root)))

    def test_nas_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\ndef decode_nas(payload):\n    return payload\n", encoding="utf-8")
            self.assertTrue(any("NAS/NGAP decoding" in error for error in VALIDATOR.validate(root)))

    def test_ngap_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/pfcp/scripts/pfcp_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nAMF_UE_NGAP_ID = 1\n", encoding="utf-8")
            self.assertTrue(any("NAS/NGAP decoding" in error for error in VALIDATOR.validate(root)))

    def test_vendor_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            reference = root / "skills/protocol/pfcp/references/protocol-model.md"
            reference.write_text(reference.read_text(encoding="utf-8") + "\nSee open5gs source tree.\n", encoding="utf-8")
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_production_ip_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/pfcp/examples/extracted/addresses.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8").replace("192.0.2.55", "10.44.12.9"), encoding="utf-8")
            self.assertTrue(any("non-documentation IP address" in error for error in VALIDATOR.validate(root)))

    def test_subscriber_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/pfcp/examples/extracted/node-signaling.jsonl"
            fixture.write_text(fixture.read_text(encoding="utf-8") + '{"frame.number":"99","frame.time_epoch":"1","imsi": "001010000000001"}\n', encoding="utf-8")
            self.assertTrue(any("subscriber identity field" in error for error in VALIDATOR.validate(root)))

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/protocol/pfcp/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRun ../../../scripts/validate-repository.py\n", encoding="utf-8")
            self.assertTrue(any("repository-root runtime reference" in error for error in VALIDATOR.validate(root)))

    def test_binary_capture_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            capture = root / "skills/protocol/pfcp/examples/extracted/unsanctioned.pcapng"
            capture.write_bytes(b"synthetic")
            self.assertTrue(any("binary capture fixture" in error for error in VALIDATOR.validate(root)))

    def test_missing_multi_rule_fixture_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            for name in VALIDATOR.EXPECTED_EVENTS:
                expected = root / "skills/protocol/pfcp" / name
                kept = []
                for line in expected.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    event.pop("rule_operations", None)
                    kept.append(json.dumps(event, sort_keys=True, separators=(",", ":")))
                expected.write_text("\n".join(kept) + "\n", encoding="utf-8")
            self.assertTrue(any("two or more rule groups" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
