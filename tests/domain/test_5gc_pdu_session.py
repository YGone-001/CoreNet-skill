"""Repository-level tests for the 5GC PDU Session Domain Skill."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE_TESTS = ROOT / "skills/domain/5gc-pdu-session/tests/test_5gc_pdu_session.py"
VALIDATOR_SCRIPT = ROOT / "scripts/validate-5gc-pdu-session.py"

PACKAGE_SPEC = importlib.util.spec_from_file_location("pdu_session_package_tests", PACKAGE_TESTS)
PACKAGE_MODULE = importlib.util.module_from_spec(PACKAGE_SPEC)
assert PACKAGE_SPEC.loader is not None
PACKAGE_SPEC.loader.exec_module(PACKAGE_MODULE)
sys.modules.pop("pdu_session_model", None)

VALIDATOR_SPEC = importlib.util.spec_from_file_location("validate_5gc_pdu_session", VALIDATOR_SCRIPT)
VALIDATOR = importlib.util.module_from_spec(VALIDATOR_SPEC)
assert VALIDATOR_SPEC.loader is not None
VALIDATOR_SPEC.loader.exec_module(VALIDATOR)


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromModule(PACKAGE_MODULE))
    return tests


class PduSessionValidatorTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        destination = Path(temporary.name) / "repo"
        shutil.copytree(ROOT, destination, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        return temporary, destination

    def assert_error(self, root: Path, text: str) -> None:
        errors = VALIDATOR.validate(root)
        self.assertTrue(any(text.lower() in error.lower() for error in errors), f"Expected '{text}' in errors: {errors}")

    def test_committed_contract_passes(self):
        self.assertEqual(VALIDATOR.validate(ROOT), [])

    def test_wrong_category_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("category: domain", "category: protocol"), encoding="utf-8")
            self.assert_error(root, "category must be domain")

    def test_required_local_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("required: []", "required:\n    - nas-5gs"), encoding="utf-8")
            self.assert_error(root, "required dependencies must be empty")

    def test_protocol_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("protocols: []", "protocols:\n  - pfcp"), encoding="utf-8")
            self.assert_error(root, "protocols must remain empty")

    def test_network_function_ownership_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("network_functions: []", "network_functions:\n  - smf"), encoding="utf-8")
            self.assert_error(root, "network_functions must remain empty")

    def test_root_cause_schema_field_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/domain/5gc-pdu-session/schemas/5gc-pdu-session-analysis.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["properties"]["root_cause"] = {"type": "string"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assert_error(root, "causal or implementation fields")

    def test_vendor_implementation_mapping_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/domain/5gc-pdu-session/scripts/pdu_session_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\nOPEN5GS_SOURCE_HANDLER = 'smf/pfcp/handler.go'\n", encoding="utf-8")
            self.assert_error(root, "implementation or vendor source mapping")

    def test_raw_decoder_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            model = root / "skills/domain/5gc-pdu-session/scripts/pdu_session_model.py"
            model.write_text(model.read_text(encoding="utf-8") + "\ndef decode_pfcp_payload(data):\n    return data\n", encoding="utf-8")
            self.assert_error(root, "raw protocol decoding code")

    def test_missing_procedure_evidence_schema_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            (root / "skills/domain/5gc-pdu-session/schemas/procedure-evidence.schema.json").unlink()
            self.assert_error(root, "missing required package file")

    def test_procedure_evidence_schema_divergence_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema = root / "skills/domain/5gc-pdu-session/schemas/procedure-evidence.schema.json"
            schema.write_text("{}\n", encoding="utf-8")
            self.assert_error(root, "procedure-evidence schema")

    def test_repository_root_runtime_dependency_is_detected(self):
        temporary, root = self.fixture()
        with temporary:
            readme = root / "skills/domain/5gc-pdu-session/README.md"
            readme.write_text(readme.read_text(encoding="utf-8") + "\nRuntime path: ../../../shared\n", encoding="utf-8")
            self.assert_error(root, "repository-root runtime reference")

    def test_global_pdu_session_id_key_prevented(self):
        # Multi-UE with same PSI must produce distinct instance_ids with NGAP context
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/multi-ue-same-psi-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["instances"]), 2)
        inst1, inst2 = doc["instances"][0], doc["instances"][1]
        self.assertNotEqual(inst1["instance_id"], inst2["instance_id"])
        self.assertIn("ran1", inst1["instance_id"])
        self.assertIn("ran2", inst2["instance_id"])

    def test_timestamp_only_ue_association_prevented(self):
        # Two UEs with overlapping timestamps remain isolated
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/multi-ue-same-psi-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        for inst in doc["instances"]:
            self.assertEqual(inst["association_strength"], "STRONG")
            self.assertIn("ngap_ue_context", inst["association_basis"])

    def test_teid_only_association_prevented(self):
        # TEID reuse across different UPF endpoint IPs prevents false binding
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/teid-reuse-different-endpoints-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        by_psi = {inst["pdu_session_id"]: inst for inst in doc["instances"]}
        self.assertIsNotNone(by_psi[1]["plane_bindings"]["n3"])
        self.assertIsNone(by_psi[2]["plane_bindings"]["n3"])

    def test_pending_202_is_not_delivered(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/namf-pending-202-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        stage = next(s for s in doc["instances"][0]["stages"] if s["stage_id"] == "n1_n2_delivery")
        self.assertEqual(stage["status"], "PENDING")
        self.assertNotEqual(stage["status"], "OBSERVED")

    def test_missing_gtpu_is_not_failure(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/no-gtpu-traffic-analysis.json"
        text = sample.read_text(encoding="utf-8")
        self.assertNotIn("USER_PLANE_FAILED", text)
        doc = json.loads(text)
        stage = next(s for s in doc["instances"][0]["stages"] if s["stage_id"] == "user_plane_observation")
        self.assertEqual(stage["status"], "MISSING")
        self.assertIn("no matching N3 G-PDU evidence observed within the available capture window", stage["missing_evidence"])

    def test_mixed_ngap_resources_not_collapsed(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/ngap-mixed-resources-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["instances"]), 2)
        by_psi = {inst["pdu_session_id"]: inst for inst in doc["instances"]}
        self.assertEqual(len(by_psi[10]["deviations"]), 0)
        self.assertTrue(any(d["type"] == "RESOURCE_FAILED_ITEM_OBSERVED" for d in by_psi[11]["deviations"]))

    def test_version_remains_010_detected(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8").replace("version: 0.2.0", "version: 0.1.0"), encoding="utf-8")
            self.assert_error(root, "version must be 0.2.0")

    def test_static_modification_object_instead_of_array_detected(self):
        temporary, root = self.fixture()
        with temporary:
            schema_path = root / "skills/domain/5gc-pdu-session/schemas/5gc-pdu-session-analysis.schema.json"
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            schema["$defs"]["instanceAnalysis"]["properties"]["modification_attempts"] = {"type": "object"}
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            self.assert_error(root, "modification_attempts property must be an array")

    def test_two_attempts_collapsed_into_one_prevented(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/two-sequential-modifications-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        inst = doc["instances"][0]
        self.assertEqual(len(inst["modification_attempts"]), 2)
        att1, att2 = inst["modification_attempts"][0], inst["modification_attempts"][1]
        self.assertNotEqual(att1["attempt_id"], att2["attempt_id"])
        self.assertEqual(att1["procedure_transaction_identity"], 2)
        self.assertEqual(att2["procedure_transaction_identity"], 3)

    def test_pti_used_globally_prevented(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/same-pti-two-ues-modify-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["instances"]), 2)
        inst1, inst2 = doc["instances"][0], doc["instances"][1]
        self.assertNotEqual(inst1["instance_id"], inst2["instance_id"])
        self.assertEqual(inst1["modification_attempts"][0]["procedure_transaction_identity"], 5)
        self.assertEqual(inst2["modification_attempts"][0]["procedure_transaction_identity"], 5)

    def test_qfi_used_as_identity_key_prevented(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/qfi-cross-plane-conflict-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["instances"]), 1)
        inst = doc["instances"][0]
        self.assertTrue(any(d["type"] == "FIELD_CONFLICT" for d in inst["modification_attempts"][0]["deviations"]))

    def test_timestamp_only_modification_binding_prevented(self):
        # Behavioral validation: run the real analyzer against the committed
        # concurrent-ambiguity fixture. Two distinct-PTI attempts stay intact,
        # and the SBI/PFCP/GTP-U cross-plane events without attempt-specific
        # identity are not assigned to any attempt by frame position or by
        # first/nearest-attempt fallback.
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = PACKAGE_MODULE.run_scenario(
                "ambiguous-concurrent-modifications", Path(directory),
            )
        inst = analysis["instances"][0]
        attempts = inst["modification_attempts"]
        self.assertEqual(len(attempts), 2)
        self.assertEqual({a["procedure_transaction_identity"] for a in attempts}, {2, 3})

        cross_plane = {("3GPP-SBI", "test.pcap", 12), ("PFCP", "test.pcap", 13), ("GTP-U", "test.pcap", 14)}
        owned = set()
        for attempt in attempts:
            for ref in attempt["event_ownership"]["owned_event_refs"]:
                owned.add((ref["protocol"], ref["capture_file"], ref["frame_number"]))
        self.assertEqual(cross_plane & owned, set(), "no first/nearest attempt fallback may own cross-plane events")

        unbound_refs = {
            (r["event_ref"]["protocol"], r["event_ref"]["capture_file"], r["event_ref"]["frame_number"])
            for r in inst["unbound_evidence"]
        }
        self.assertTrue(cross_plane <= unbound_refs, "ambiguity record must exist for every cross-plane event")
        self.assertTrue(any(d["type"] == "CORRELATION_AMBIGUITY" for d in inst["deviations"]))

    def test_modification_event_ownership_is_exclusive(self):
        # Gather every attempt-owned event reference per fixture; duplicates
        # would mean one event belongs to multiple attempts (GTP-U bleed or
        # double cross-plane assignment).
        for scenario in ("two-sequential-modifications", "ue-requested-modification", "concurrent-distinct-pti-modifications"):
            with self.subTest(scenario=scenario):
                sample = ROOT / f"skills/domain/5gc-pdu-session/examples/expected/{scenario}-analysis.json"
                doc = json.loads(sample.read_text(encoding="utf-8"))
                for inst in doc["instances"]:
                    owned_refs = []
                    for attempt in inst["modification_attempts"]:
                        for ref in attempt["event_ownership"]["owned_event_refs"]:
                            owned_refs.append((ref["protocol"], ref["capture_file"], ref["frame_number"]))
                    self.assertEqual(len(owned_refs), len(set(owned_refs)), scenario)

    def test_gtpu_does_not_bleed_across_sequential_attempts(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/two-sequential-modifications-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        inst = doc["instances"][0]
        att1, att2 = inst["modification_attempts"]
        teids1 = {ref["frame_number"] for ref in att1["event_ownership"]["owned_event_refs"] if ref["protocol"] == "GTP-U"}
        teids2 = {ref["frame_number"] for ref in att2["event_ownership"]["owned_event_refs"] if ref["protocol"] == "GTP-U"}
        self.assertEqual(teids1, {19})
        self.assertEqual(teids2, {29})
        self.assertEqual(att1["observation_window"]["window_end_basis"], "next_modification_attempt_start_exclusive")
        self.assertEqual(att2["observation_window"]["window_end_basis"], "capture_window_end")

    def test_network_only_partial_capture_not_collapsed(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/network-only-modification-transactions-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        inst = doc["instances"][0]
        self.assertEqual(inst["modification_attempts"], [])
        unbound = inst["unbound_evidence"]
        self.assertEqual(len(unbound), 2)
        self.assertEqual({r["event_ref"]["frame_number"] for r in unbound}, {11, 14})
        self.assertTrue(all(r["association_strength"] == "UNBOUND" for r in unbound))

    def test_no_gtpu_not_promoted_to_user_plane_failure(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/fteid-changed-no-gtpu-analysis.json"
        text = sample.read_text(encoding="utf-8")
        self.assertNotIn("USER_PLANE_FAILED", text)
        doc = json.loads(text)
        attempt = doc["instances"][0]["modification_attempts"][0]
        pmo_stage = next(s for s in attempt["stages"] if s["stage_id"] == "post_modification_observation")
        self.assertEqual(pmo_stage["status"], "NOT_OBSERVED")
        self.assertEqual(pmo_stage["missing_evidence"], [])
        pmo_deviations = [d for d in attempt["deviations"] if d["stage_id"] == "post_modification_observation"]
        self.assertEqual(pmo_deviations, [])

    def test_n2_teid_terminology_distinct_from_pfcp_f_teid(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/fteid-changed-matching-gtpu-analysis.json"
        text = sample.read_text(encoding="utf-8")
        self.assertNotIn("F-TEID tunnel endpoint updated", text)
        doc = json.loads(text)
        attempt = doc["instances"][0]["modification_attempts"][0]
        teid_findings = [f for f in attempt["field_findings"] if f["field_name"] == "gtp_teid"]
        self.assertTrue(teid_findings)
        self.assertTrue(any(
            isinstance(f["observed_value"], dict) and f["observed_value"].get("tunnel_role") == "N2_SIGNALED_TRANSPORT_ENDPOINT"
            for f in teid_findings
        ))

    def test_qfi_wording_evidence_bounded(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/qfi-updated-qer-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        attempt = doc["instances"][0]["modification_attempts"][0]
        qfi_findings = [f for f in attempt["field_findings"] if f["field_name"] == "qfi"]
        self.assertTrue(qfi_findings)
        for finding in qfi_findings:
            self.assertNotIn("Modified QoS Flow Identifier", finding["interpretation"])
        self.assertTrue(any("explicit PFCP QER operation" in f["interpretation"] for f in qfi_findings))

    def test_duplicate_wording_non_causal(self):
        for scenario in ("duplicate-nas-modify-request", "duplicate-pfcp-modify-request"):
            with self.subTest(scenario=scenario):
                text = (ROOT / f"skills/domain/5gc-pdu-session/examples/expected/{scenario}-analysis.json").read_text(encoding="utf-8")
                self.assertNotIn("likely response delay", text)
                self.assertNotIn("packet duplication", text)
                self.assertIn("duplicate/retransmission cause cannot be distinguished from this capture alone", text)

    def test_network_requested_branch_does_not_require_ue_request(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/network-requested-no-ue-request-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        inst = doc["instances"][0]
        self.assertEqual(len(inst["modification_attempts"]), 1)
        attempt = inst["modification_attempts"][0]
        self.assertEqual(attempt["trigger_type"], "NETWORK_REQUESTED")
        init_stage = next(s for s in attempt["stages"] if s["stage_id"] == "modification_initiation")
        self.assertEqual(init_stage["status"], "OBSERVED")
        self.assertEqual(len(init_stage["missing_evidence"]), 0)
        self.assertEqual(attempt["terminal_observation"]["observation"], "MODIFICATION_COMPLETE_OBSERVED")
        self.assertEqual(len(attempt["deviations"]), 0)

    def test_pfcp_accepted_not_promoted_to_modification_success(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/pfcp-modification-accepted-analysis.json"
        doc = json.loads(sample.read_text(encoding="utf-8"))
        attempt = doc["instances"][0]["modification_attempts"][0]
        user_plane_stage = next(s for s in attempt["stages"] if s["stage_id"] == "user_plane_control_update")
        self.assertEqual(user_plane_stage["status"], "OBSERVED")
        completion_stage = next(s for s in attempt["stages"] if s["stage_id"] == "modification_completion")
        self.assertEqual(completion_stage["status"], "MISSING")
        self.assertNotEqual(attempt["terminal_observation"]["observation"], "MODIFICATION_COMPLETE_OBSERVED")
        self.assertEqual(attempt["terminal_observation"]["observation"], "NO_N1_TERMINAL_OBSERVATION")

    def test_no_gtpu_not_promoted_to_user_plane_failure_old_missing_status(self):
        sample = ROOT / "skills/domain/5gc-pdu-session/examples/expected/no-gtpu-traffic-analysis.json"
        text = sample.read_text(encoding="utf-8")
        self.assertNotIn("USER_PLANE_FAILED", text)
        doc = json.loads(text)
        stage = next(s for s in doc["instances"][0]["stages"] if s["stage_id"] == "user_plane_observation")
        self.assertEqual(stage["status"], "MISSING")

    def test_release_lifecycle_detected_if_added(self):
        temporary, root = self.fixture()
        with temporary:
            manifest = root / "skills/domain/5gc-pdu-session/manifest.yaml"
            manifest.write_text(manifest.read_text(encoding="utf-8") + "\nstages:\n  - pdu_session_release\n", encoding="utf-8")
            self.assert_error(root, "Release Domain remains excluded")


if __name__ == "__main__":
    unittest.main()
