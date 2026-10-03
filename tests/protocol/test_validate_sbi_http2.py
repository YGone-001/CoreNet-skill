"""Repository-level tests for the sbi-http2 package validator."""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "validate-sbi-http2.py"
SPEC = importlib.util.spec_from_file_location("validate_sbi_http2", SCRIPT)
VALIDATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VALIDATOR)


class SbiHttp2ValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        destination.mkdir()
        shutil.copytree(ROOT / "skills/protocol/sbi-http2", destination / "skills/protocol/sbi-http2")
        shutil.copytree(ROOT / "shared", destination / "shared")
        return temporary, destination

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_missing_required_file_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/protocol/sbi-http2/manifest.yaml").unlink()
            errors = VALIDATOR.validate(root)
            self.assertTrue(any("missing required package file" in error for error in errors))

    def test_wrong_version_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/sbi-http2/manifest.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace("version: 0.2.0", "version: 0.3.0"),
                encoding="utf-8",
            )
            self.assertTrue(any("manifest version must be 0.2.0" in error for error in VALIDATOR.validate(root)))

    def test_wrong_interface_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/sbi-http2/manifest.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace("interfaces:\n  - N11", "interfaces:\n  - N11\n  - N12"),
                encoding="utf-8",
            )
            self.assertTrue(any("interface ownership must be N11 only" in error for error in VALIDATOR.validate(root)))

    def test_network_function_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/sbi-http2/manifest.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace("network_functions: []", "network_functions: [AMF, SMF]"),
                encoding="utf-8",
            )
            self.assertTrue(any("network_functions must stay empty" in error for error in VALIDATOR.validate(root)))

    def test_required_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/protocol/sbi-http2/manifest.yaml"
            manifest.write_text(
                manifest.read_text(encoding="utf-8").replace("required: []", "required:\n    - nas-5gs >=0.1.0"),
                encoding="utf-8",
            )
            self.assertTrue(any("must not require another CoreNet Skill" in error for error in VALIDATOR.validate(root)))

    def test_trace_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/protocol/sbi-http2/schemas/trace-event.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assertTrue(any("trace schema" in error for error in VALIDATOR.validate(root)))

    def test_hpack_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\ndef decode_hpack(raw):\n    return raw\n",
                encoding="utf-8",
            )
            self.assertTrue(any("HPACK decoder" in error for error in VALIDATOR.validate(root)))

    def test_manual_http2_frame_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\ndef parse_http2_frame(b):\n    return struct.unpack('>I', b[:4])\n",
                encoding="utf-8",
            )
            self.assertTrue(any("manual HTTP/2 binary frame parser" in error for error in VALIDATOR.validate(root)))

    def test_tls_key_decryption_handling_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\ndef decrypt_tls(record):\n    return None\n",
                encoding="utf-8",
            )
            self.assertTrue(any("TLS decryption or key handling" in error for error in VALIDATOR.validate(root)))

    def test_nas_decode_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\ndef decode_nas(payload):\n    return payload\n",
                encoding="utf-8",
            )
            self.assertTrue(any("NAS decoding logic" in error for error in VALIDATOR.validate(root)))

    def test_ngap_decode_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\ndef decode_ngap(payload):\n    return payload\n",
                encoding="utf-8",
            )
            self.assertTrue(any("NGAP decoding logic" in error for error in VALIDATOR.validate(root)))

    def test_pfcp_join_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\nMATCH = match_pfcp(seid)\n",
                encoding="utf-8",
            )
            self.assertTrue(any("PFCP or GTP-U join logic" in error for error in VALIDATOR.validate(root)))

    def test_gtpu_join_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\nMATCH = match_gtpu(teid)\n",
                encoding="utf-8",
            )
            self.assertTrue(any("PFCP or GTP-U join logic" in error for error in VALIDATOR.validate(root)))

    def test_raw_json_body_persistence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + '\nevent["raw_body"] = json_body\n',
                encoding="utf-8",
            )
            self.assertTrue(any("raw JSON body or binary persistence" in error for error in VALIDATOR.validate(root)))

    def test_raw_multipart_binary_persistence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + '\nevent["binary_bytes"] = b"raw"\n',
                encoding="utf-8",
            )
            self.assertTrue(any("raw JSON body or binary persistence" in error for error in VALIDATOR.validate(root)))

    def test_authorization_token_persistence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + '\nevent["authorization_token"] = "secret-token"\n',
                encoding="utf-8",
            )
            self.assertTrue(any("Authorization token persistence" in error for error in VALIDATOR.validate(root)))

    def test_unredacted_supi_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/sbi-http2/examples/expected/create-sm-context-events.jsonl"
            lines = fixture.read_text(encoding="utf-8").splitlines()
            if lines:
                ev = json.loads(lines[0])
                ev["supi"] = "001010000000001"
                lines[0] = json.dumps(ev)
                fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertTrue(any("unredacted subscriber field" in error for error in VALIDATOR.validate(root)))

    def test_stream_id_only_correlation_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            text = model.read_text(encoding="utf-8").replace("conn_ctx", "unscoped_ctx")
            model.write_text(text, encoding="utf-8")
            self.assertTrue(any("transaction key must scope stream ID" in error for error in VALIDATOR.validate(root)))

    def test_multipart_positional_zip_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + "\nPAIRS = list(zip(n1_parts, n2_parts))\n",
                encoding="utf-8",
            )
            self.assertTrue(any("multipart positional zip" in error for error in VALIDATOR.validate(root)))

    def test_end_to_end_success_verdict_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + '\nVERDICT = "pdu_session_success"\n',
                encoding="utf-8",
            )
            self.assertTrue(any("complete PDU Session domain verdicts" in error for error in VALIDATOR.validate(root)))

    def test_smf_blame_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/protocol/sbi-http2/scripts/sbi_model.py"
            model.write_text(
                model.read_text(encoding="utf-8") + '\nVERDICT = "smf_failure"\n',
                encoding="utf-8",
            )
            self.assertTrue(any("complete PDU Session domain verdicts" in error for error in VALIDATOR.validate(root)))

    def test_vendor_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            ref = root / "skills/protocol/sbi-http2/references/protocol-model.md"
            ref.write_text(
                ref.read_text(encoding="utf-8") + "\nReference implementation: open5gs smf.c\n",
                encoding="utf-8",
            )
            self.assertTrue(any("implementation mapping" in error for error in VALIDATOR.validate(root)))

    def test_repository_root_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            script = root / "skills/protocol/sbi-http2/scripts/extract-sbi-http2.py"
            script.write_text(
                script.read_text(encoding="utf-8") + "\n# See ../../../scripts/validate-repository.py\n",
                encoding="utf-8",
            )
            self.assertTrue(any("repository-root runtime reference" in error for error in VALIDATOR.validate(root)))

    def test_unredacted_ue_context_id_in_path_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            fixture = root / "skills/protocol/sbi-http2/examples/expected/namf-transfer-events.jsonl"
            lines = fixture.read_text(encoding="utf-8").splitlines()
            if lines:
                ev = json.loads(lines[0])
                ev["http2"]["path"] = "/namf-comm/v1/ue-contexts/imsi-001010000000001/n1-n2-messages"
                lines[0] = json.dumps(ev)
                fixture.write_text("\n".join(lines) + "\n", encoding="utf-8")
            self.assertTrue(any("unredacted subscriber identity in path" in error for error in VALIDATOR.validate(root)))


if __name__ == "__main__":
    unittest.main()
