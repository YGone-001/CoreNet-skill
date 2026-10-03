"""Package-local test suite for 5gc-pdu-session."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
INPUTS = PACKAGE / "examples" / "inputs"
EXPECTED = PACKAGE / "examples" / "expected"

sys.path.insert(0, str(SCRIPTS))

import pdu_session_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ANALYZE = load_script("analyze_pdu_session")
TIMELINE = load_script("pdu_session_timeline")


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_scenario(name: str, directory: Path) -> tuple[dict, list[dict]]:
    source = INPUTS / name
    analysis_path = directory / f"{name}-analysis.json"
    stages_path = directory / f"{name}-stages.jsonl"
    argv = [
        "--input-dir", str(source),
        "--output", str(analysis_path),
        "--stages-output", str(stages_path),
        "--force",
    ]
    rc = ANALYZE.main(argv)
    assert rc == 0, f"scenario {name} failed with {rc}"
    return json.loads(analysis_path.read_text(encoding="utf-8")), jsonl(stages_path)


class ModificationAssociationSafetyTests(unittest.TestCase):
    """Behavioral association-safety tests: these exercise the real analyzer
    against the committed ambiguity and multi-attempt fixtures instead of
    matching source-code tokens."""

    @staticmethod
    def _owned_refs(attempt):
        return [
            (ref["protocol"], ref["capture_file"], ref["frame_number"])
            for ref in attempt["event_ownership"]["owned_event_refs"]
        ]

    def test_concurrent_ambiguity_keeps_attempts_distinct_and_events_unbound(self):
        # Two distinct-PTI attempts plus an SBI, a PFCP, and a GTP-U event that
        # carry no attempt-specific identity: none may be attached by position.
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("ambiguous-concurrent-modifications", Path(directory))
            inst = analysis["instances"][0]
            attempts = inst["modification_attempts"]
            self.assertEqual(len(attempts), 2)
            self.assertEqual({a["procedure_transaction_identity"] for a in attempts}, {2, 3})
            cross_plane = {("3GPP-SBI", "test.pcap", 12), ("PFCP", "test.pcap", 13), ("GTP-U", "test.pcap", 14)}
            owned = set()
            for attempt in attempts:
                owned.update(self._owned_refs(attempt))
            self.assertEqual(cross_plane & owned, set(), "cross-plane events must not be owned by either attempt")
            unbound = inst["unbound_evidence"]
            unbound_refs = {(r["event_ref"]["protocol"], r["event_ref"]["capture_file"], r["event_ref"]["frame_number"]) for r in unbound}
            self.assertTrue(cross_plane <= unbound_refs)
            for record in unbound:
                if record["association_strength"] == "AMBIGUOUS":
                    self.assertEqual(set(record["candidate_attempt_ids"]), {"mod-1", "mod-2"})
            self.assertTrue(any(d["type"] == "CORRELATION_AMBIGUITY" for d in inst["deviations"]))

    def test_event_ownership_is_exclusive_across_attempts(self):
        for scenario in ("two-sequential-modifications", "concurrent-distinct-pti-modifications", "ue-requested-modification"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _ = run_scenario(scenario, Path(directory))
                    for inst in analysis["instances"]:
                        all_refs = []
                        for attempt in inst["modification_attempts"]:
                            all_refs.extend(self._owned_refs(attempt))
                        self.assertEqual(len(all_refs), len(set(all_refs)), scenario)

    def test_gtpu_does_not_bleed_across_sequential_attempts(self):
        # Attempt 1 provisions tunnel 6001, attempt 2 provisions tunnel 6002.
        # Packet A (frame 19) belongs to attempt 1 only, packet B (frame 29)
        # to attempt 2 only; neither attempt may absorb the other's traffic.
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("two-sequential-modifications", Path(directory))
            inst = analysis["instances"][0]
            attempts = inst["modification_attempts"]
            self.assertEqual(len(attempts), 2)
            gtpu_a = {(19, 6001)}
            gtpu_b = {(29, 6002)}
            owned1 = {r[2] for r in self._owned_refs(attempts[0]) if r[0] == "GTP-U"}
            owned2 = {r[2] for r in self._owned_refs(attempts[1]) if r[0] == "GTP-U"}
            self.assertEqual(owned1, {19})
            self.assertEqual(owned2, {29})
            self.assertFalse(gtpu_b & {19} or gtpu_a & {29})
            self.assertEqual(attempts[0]["observation_window"]["window_end_frame"], 19)
            self.assertEqual(attempts[0]["observation_window"]["window_end_basis"], "next_modification_attempt_start_exclusive")

    def test_no_post_modification_gtpu_is_conditional_not_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("fteid-changed-no-gtpu", Path(directory))
            attempt = analysis["instances"][0]["modification_attempts"][0]
            stage = next(s for s in attempt["stages"] if s["stage_id"] == "post_modification_observation")
            self.assertEqual(stage["status"], "NOT_OBSERVED")
            self.assertEqual(stage["missing_evidence"], [])
            self.assertIn("No matching post-modification N3 packet observed within the capture window.", stage["observed_evidence"])
            pmo_deviations = [d for d in attempt["deviations"] if d["stage_id"] == "post_modification_observation"]
            self.assertEqual(pmo_deviations, [])

    def test_network_only_transactions_not_collapsed_into_attempt(self):
        # Two UpdateSMContext transactions without any N1 modification anchor:
        # no attempt may be invented and no transactions merged.
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("network-only-modification-transactions", Path(directory))
            inst = analysis["instances"][0]
            self.assertEqual(inst["modification_attempts"], [])
            unbound = inst["unbound_evidence"]
            self.assertEqual(len(unbound), 2)
            self.assertEqual({r["event_ref"]["frame_number"] for r in unbound}, {11, 14})
            for record in unbound:
                self.assertEqual(record["association_strength"], "UNBOUND")
                self.assertIn("safe attempt construction impossible", record["reason"])

    def test_n2_gtp_teid_not_labeled_f_teid(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("fteid-changed-matching-gtpu", Path(directory))
            serialized = json.dumps(analysis)
            self.assertNotIn("F-TEID tunnel endpoint updated", serialized)
            attempt = analysis["instances"][0]["modification_attempts"][0]
            teid_findings = [f for f in attempt["field_findings"] if f["field_name"] == "gtp_teid"]
            self.assertTrue(teid_findings)
            self.assertTrue(any(f["observed_value"].get("tunnel_role") == "N2_SIGNALED_TRANSPORT_ENDPOINT" for f in teid_findings))

    def test_qfi_wording_is_evidence_bounded(self):
        # Observed QFI without an explicit QER operation must use neutral
        # wording; explicit update_qer keeps the operation wording.
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("qfi-updated-qer", Path(directory))
            attempt = analysis["instances"][0]["modification_attempts"][0]
            qfi_findings = [f for f in attempt["field_findings"] if f["field_name"] == "qfi"]
            self.assertTrue(any("explicit PFCP QER operation" in f["interpretation"] for f in qfi_findings))
            self.assertTrue(all("Modified QoS Flow Identifier" not in f["interpretation"] for f in qfi_findings))

    def test_duplicate_wording_remains_non_causal(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("duplicate-nas-modify-request", Path(directory))
            serialized = json.dumps(analysis)
            self.assertNotIn("likely response delay", serialized)
            self.assertNotIn("packet duplication", serialized)
            self.assertIn("duplicate/retransmission cause cannot be distinguished from this capture alone", serialized)


class ScenarioExpectedTests(unittest.TestCase):
    """Every committed scenario reproduces its committed expected output."""

    def test_all_scenarios_match_expected(self):
        for source in sorted(path for path in INPUTS.iterdir() if path.is_dir()):
            name = source.name
            with self.subTest(scenario=name):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, stages = run_scenario(name, Path(directory))
                    expected_analysis = json.loads((EXPECTED / f"{name}-analysis.json").read_text(encoding="utf-8"))
                    expected_stages = jsonl(EXPECTED / f"{name}-stages.jsonl")
                    self.assertEqual(analysis, expected_analysis, name)
                    self.assertEqual(stages, expected_stages, name)

    def test_deterministic_rerun(self):
        with tempfile.TemporaryDirectory() as directory:
            first = run_scenario("normal-establishment", Path(directory))
            second = run_scenario("normal-establishment", Path(directory))
            self.assertEqual(first, second)


class NormalEstablishmentTests(unittest.TestCase):
    def test_all_stages_observed_and_accept_found(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, stages = run_scenario("normal-establishment", Path(directory))
            inst = analysis["instances"][0]
            self.assertEqual(inst["terminal_observation"]["observation"], "ESTABLISHMENT_ACCEPT_OBSERVED")
            self.assertEqual(len(inst["deviations"]), 0)
            self.assertIsNone(inst["earliest_observed_deviation"])
            for st in inst["stages"]:
                self.assertEqual(st["status"], "OBSERVED", st["stage_id"])
            bindings = inst["plane_bindings"]
            self.assertEqual(bindings["n1"]["strength"], "STRONG")
            self.assertEqual(bindings["n2"]["strength"], "STRONG")
            self.assertEqual(bindings["n3"]["strength"], "STRONG")
            self.assertEqual(bindings["n4"]["strength"], "SUPPORTED")
            self.assertEqual(bindings["n11"]["strength"], "SUPPORTED")


class DeviationAndRejectionTests(unittest.TestCase):
    def test_establishment_reject_cause_and_deviation(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("establishment-reject", Path(directory))
            inst = analysis["instances"][0]
            self.assertEqual(inst["terminal_observation"]["observation"], "ESTABLISHMENT_REJECT_OBSERVED")
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("PROTOCOL_REJECT_OBSERVED", dev_types)
            self.assertEqual(inst["earliest_observed_deviation"]["type"], "PROTOCOL_REJECT_OBSERVED")
            self.assertEqual(inst["earliest_observed_deviation"]["stage_id"], "session_decision")

    def test_create_sm_context_error(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("create-sm-context-error", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", dev_types)
            self.assertEqual(inst["earliest_observed_deviation"]["stage_id"], "sm_context_control")

    def test_pfcp_negative_cause(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("pfcp-negative-cause", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", dev_types)
            self.assertEqual(inst["earliest_observed_deviation"]["stage_id"], "user_plane_control")

    def test_ngap_failed_resource(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("ngap-failed-resource", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("RESOURCE_FAILED_ITEM_OBSERVED", dev_types)
            self.assertEqual(inst["earliest_observed_deviation"]["stage_id"], "access_resource_control")

    def test_ngap_mixed_resources_scoped_per_item(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("ngap-mixed-resources", Path(directory))
            self.assertEqual(len(analysis["instances"]), 2)
            by_psi = {inst["pdu_session_id"]: inst for inst in analysis["instances"]}
            self.assertEqual(len(by_psi[10]["deviations"]), 0)
            failed_types = [d["type"] for d in by_psi[11]["deviations"]]
            self.assertIn("RESOURCE_FAILED_ITEM_OBSERVED", failed_types)

    def test_namf_pending_202_not_converted_to_delivered(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("namf-pending-202", Path(directory))
            inst = analysis["instances"][0]
            stage = next(s for s in inst["stages"] if s["stage_id"] == "n1_n2_delivery")
            self.assertEqual(stage["status"], "PENDING")

    def test_namf_failure_notification(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("namf-failure-notification", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("DELIVERY_FAILURE_NOTIFICATION_OBSERVED", dev_types)
            self.assertEqual(inst["earliest_observed_deviation"]["stage_id"], "n1_n2_delivery")

    def test_no_gtpu_traffic_reported_neutrally_without_verdict(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("no-gtpu-traffic", Path(directory))
            inst = analysis["instances"][0]
            stage = next(s for s in inst["stages"] if s["stage_id"] == "user_plane_observation")
            self.assertEqual(stage["status"], "MISSING")
            self.assertEqual(stage["missing_evidence"], ["no matching N3 G-PDU evidence observed within the available capture window"])
            serialized = json.dumps(analysis)
            self.assertNotIn("USER_PLANE_FAILED", serialized)


class AssociationAndIsolationTests(unittest.TestCase):
    def test_multi_ue_same_psi_isolated(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("multi-ue-same-psi", Path(directory))
            self.assertEqual(len(analysis["instances"]), 2)
            inst_ids = [inst["instance_id"] for inst in analysis["instances"]]
            self.assertIn("5gc-pdu-session:sample.pcap:ran1-amf1:psi5", inst_ids)
            self.assertIn("5gc-pdu-session:sample.pcap:ran2-amf2:psi5", inst_ids)

    def test_sbi_ambiguity_preserved_unbound(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("sbi-ambiguity", Path(directory))
            unbound_n11 = analysis["unbound_evidence"]["unbound_n11"]
            self.assertTrue(len(unbound_n11) > 0)
            ambiguous_events = analysis["unbound_evidence"]["ambiguous_events"]
            self.assertTrue(len(ambiguous_events) > 0)
            for inst in analysis["instances"]:
                self.assertIsNone(inst["plane_bindings"]["n11"])
                dev_types = [d["type"] for d in inst["deviations"]]
                self.assertIn("CORRELATION_AMBIGUITY", dev_types)

    def test_teid_reuse_endpoint_isolation(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("teid-reuse-different-endpoints", Path(directory))
            self.assertEqual(len(analysis["instances"]), 2)
            by_psi = {inst["pdu_session_id"]: inst for inst in analysis["instances"]}
            self.assertIsNotNone(by_psi[1]["plane_bindings"]["n3"])
            self.assertIsNone(by_psi[2]["plane_bindings"]["n3"])

    def test_address_and_qfi_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("address-and-qfi-conflict", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("CORRELATION_CONFLICT", dev_types)
            interpretations = [f["interpretation"] for f in inst["field_findings"]]
            self.assertTrue(any("FIELD_CONFLICT" in interp for interp in interpretations))

    def test_partial_capture_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("partial-capture", Path(directory))
            inst = analysis["instances"][0]
            dev_types = [d["type"] for d in inst["deviations"]]
            self.assertIn("PARTIAL_CAPTURE", dev_types)
            self.assertEqual(inst["terminal_observation"]["observation"], "PARTIAL_CAPTURE")


class TimelineAndSanitizationTests(unittest.TestCase):
    def test_timeline_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis_path = Path(directory) / "norm.json"
            stages_path = Path(directory) / "norm-stages.jsonl"
            rc = ANALYZE.main([
                "--input-dir", str(INPUTS / "normal-establishment"),
                "--output", str(analysis_path),
                "--stages-output", str(stages_path),
                "--force",
            ])
            self.assertEqual(rc, 0)
            text_out = Path(directory) / "timeline.txt"
            rc_tl = TIMELINE.main([str(analysis_path), "--output", str(text_out), "--force"])
            self.assertEqual(rc_tl, 0)
            self.assertTrue(text_out.is_file())
            content = text_out.read_text(encoding="utf-8")
            self.assertIn("5gc-pdu-session", content)
            self.assertIn("ESTABLISHMENT_ACCEPT_OBSERVED", content)

    def test_forbidden_words_trigger_sanitization_error(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.sanitize_output({"some_field": "identified root cause of failure"})


if __name__ == "__main__":
    unittest.main()
