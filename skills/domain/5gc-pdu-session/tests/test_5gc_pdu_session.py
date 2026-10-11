"""Package-local test suite for 5gc-pdu-session."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
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


class ReleaseLifecycleTests(unittest.TestCase):
    """Behavioral release-lifecycle tests exercising the real analyzer."""

    @staticmethod
    def _owned_refs(attempt):
        return [
            (ref["protocol"], ref["capture_file"], ref["frame_number"])
            for ref in attempt["event_ownership"]["owned_event_refs"]
        ]

    def test_ue_requested_release_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-ue-requested", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            self.assertEqual(att["trigger_type"], "UE_REQUESTED")
            self.assertEqual(att["terminal_observation"]["observation"], "RELEASE_COMPLETE_OBSERVED")
            upt = next(s for s in att["stages"] if s["stage_id"] == "user_plane_teardown_control")
            self.assertIn("PFCP_DELETION_ACCEPTED_OBSERVED", upt["observed_evidence"][0])
            term = next(s for s in att["stages"] if s["stage_id"] == "release_terminal")
            self.assertIn("does not independently prove", term["limitations"][0])
            serialized = json.dumps(analysis)
            self.assertNotIn("PDU_SESSION_RELEASE_SUCCESS", serialized)
            self.assertNotIn("RELEASE_SUCCESS", serialized)

    def test_release_reject_does_not_terminate_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-ue-requested-reject", Path(directory))
            self.assertEqual(len(analysis["instances"]), 1)
            att = analysis["instances"][0]["release_attempts"][0]
            self.assertEqual(att["terminal_observation"]["observation"], "RELEASE_REJECT_OBSERVED")
            self.assertIn("PROTOCOL_REJECT_OBSERVED", [d["type"] for d in att["deviations"]])

    def test_repeated_release_attempts_stay_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-repeated-attempts", Path(directory))
            attempts = analysis["instances"][0]["release_attempts"]
            self.assertEqual(len(attempts), 2)
            self.assertEqual([a["procedure_transaction_identity"] for a in attempts], [4, 5])
            self.assertEqual(attempts[0]["terminal_observation"]["observation"], "RELEASE_REJECT_OBSERVED")
            self.assertEqual(attempts[1]["terminal_observation"]["observation"], "RELEASE_COMPLETE_OBSERVED")
            all_refs = []
            for att in attempts:
                all_refs.extend(self._owned_refs(att))
            self.assertEqual(len(all_refs), len(set(all_refs)))

    def test_network_requested_release_no_false_missing_request(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-network-requested", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            self.assertEqual(att["trigger_type"], "NETWORK_REQUESTED")
            init = next(s for s in att["stages"] if s["stage_id"] == "release_initiation")
            self.assertEqual(init["status"], "OBSERVED")
            self.assertEqual(init["missing_evidence"], [])
            n2 = next(s for s in att["stages"] if s["stage_id"] == "access_resource_release")
            self.assertEqual(n2["status"], "OBSERVED")

    def test_lifecycle_generation_split_on_release_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-psi-reuse-after-complete", Path(directory))
            instances = analysis["instances"]
            self.assertEqual(len(instances), 2)
            self.assertEqual([i.get("session_generation") for i in instances], [1, 2])
            self.assertTrue(instances[0]["instance_id"].endswith(":g1"))
            self.assertTrue(instances[1]["instance_id"].endswith(":g2"))
            self.assertEqual(instances[1].get("reuse_status"), "REESTABLISHED_AFTER_RELEASE_COMPLETE")
            # No event reference may be owned by both generations.
            g1_refs = {
                (r["protocol"], r["frame_number"])
                for att in instances[0]["release_attempts"] + instances[0]["modification_attempts"]
                for r in att["event_ownership"]["owned_event_refs"]
            }
            g2_refs = {
                (r["protocol"], r["frame_number"])
                for att in instances[1]["release_attempts"] + instances[1]["modification_attempts"]
                for r in att["event_ownership"]["owned_event_refs"]
            }
            self.assertEqual(g1_refs & g2_refs, set())
            # Generation 1 carries the release attempt; generation 2 the new establishment.
            self.assertEqual(len(instances[0]["release_attempts"]), 1)
            self.assertEqual(instances[1]["release_attempts"], [])
            self.assertEqual(instances[1]["stages"][0]["stage_id"], "session_request")

    def test_incomplete_release_boundary_stays_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-psi-reuse-incomplete-boundary", Path(directory))
            self.assertEqual(len(analysis["instances"]), 1)
            inst = analysis["instances"][0]
            self.assertEqual(inst.get("reuse_status"), "LIFECYCLE_AMBIGUOUS_UNPROVEN_BOUNDARY")
            self.assertIn("LIFECYCLE_AMBIGUITY", [d["type"] for d in inst["deviations"]])

    def test_no_anchor_release_evidence_stays_unbound(self):
        for scenario in ("release-n11-release-smcontext-no-anchor", "release-pfcp-deletion-no-anchor"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _ = run_scenario(scenario, Path(directory))
                    inst = analysis["instances"][0]
                    self.assertEqual(inst["release_attempts"], [])
                    self.assertTrue(inst["unbound_evidence"])
                    self.assertTrue(all(r["association_strength"] == "UNBOUND" for r in inst["unbound_evidence"]))

    def test_post_release_n3_is_conditional_and_neutral(self):
        cases = {
            "release-end-marker-observed": "OBSERVED",
            "release-gtpu-after-complete": "OBSERVED",
            "release-error-indication": "OBSERVED",
            "release-no-gtpu-after-complete": "NOT_OBSERVED",
            "release-teid-reuse-endpoint": "NOT_OBSERVED",
        }
        for scenario, expected_status in cases.items():
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _ = run_scenario(scenario, Path(directory))
                    att = analysis["instances"][0]["release_attempts"][0]
                    pro = next(s for s in att["stages"] if s["stage_id"] == "post_release_observation")
                    self.assertEqual(pro["status"], expected_status)
                    pmo_deviations = [d for d in att["deviations"] if d.get("stage_id") == "post_release_observation"]
                    self.assertEqual(pmo_deviations, [])
                    serialized = json.dumps(analysis)
                    self.assertNotIn("STALE_TRAFFIC", serialized)
                    self.assertNotIn("TEARDOWN_FAILURE", serialized)
                    self.assertNotIn("RELEASE_SUCCESS", serialized)

    def test_release_event_ownership_exclusive_across_fixtures(self):
        for scenario in ("release-ue-requested", "release-repeated-attempts", "release-ngap-resource-release",
                         "release-modification-before-release", "release-interleaved-two-ues"):
            with self.subTest(scenario=scenario):
                with tempfile.TemporaryDirectory() as directory:
                    analysis, _ = run_scenario(scenario, Path(directory))
                    for inst in analysis["instances"]:
                        all_refs = []
                        for att in inst["release_attempts"]:
                            all_refs.extend(self._owned_refs(att))
                        self.assertEqual(len(all_refs), len(set(all_refs)), scenario)

    def test_pfcp_deletion_bounded_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-pfcp-deletion-negative-cause", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", [d["type"] for d in att["deviations"]])
            serialized = json.dumps(analysis)
            self.assertNotIn("UPF_FAILURE", serialized)

        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-pfcp-deletion-no-response", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            upt = next(s for s in att["stages"] if s["stage_id"] == "user_plane_teardown_control")
            self.assertIn("not observed within the available capture window", upt["missing_evidence"][0])

    def test_end_marker_absence_is_not_a_deviation(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-no-end-marker", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            types = [d["type"] for d in att["deviations"]]
            self.assertNotIn("MISSING_EXPECTED_COUNTERPART", types)

    def test_delivery_failure_makes_missing_terminal_branch_aware(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-namf-failure-notification", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            term_devs = [d for d in att["deviations"] if d.get("stage_id") == "release_terminal"]
            self.assertTrue(term_devs)
            self.assertIn("delivery failure", term_devs[0]["description"])

    def test_release_smcontext_204_is_not_release_success(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-n11-release-smcontext-204", Path(directory))
            att = analysis["instances"][0]["release_attempts"][0]
            s = next(s for s in att["stages"] if s["stage_id"] == "sm_context_release_control")
            self.assertEqual(s["status"], "OBSERVED")
            self.assertIn("does not prove PDU Session release completed end-to-end", s["limitations"][0])


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


class NgapInputContractTests(unittest.TestCase):
    """The Domain input contract separates valid unowned evidence from malformed input."""

    UNOWNED = {
        "amf_ue_ngap_id": None,
        "capture_file": "sample.pcap",
        "cause": None,
        "derivations": ["procedure_name"],
        "destination": {"address": "127.0.0.5", "port": 38412},
        "evidence": {"level": "OBSERVED",
                     "source": "capture:sample.pcap#frame=900; procedure-code=21; tshark-info=NGSetupRequest"},
        "frame_number": 900,
        "message_type": None,
        "nas_pdu_length": None,
        "nas_pdu_present": False,
        "paging_identity_present": False,
        "pdu_type": None,
        "pdu_type_basis": None,
        "procedure_code": 21,
        "procedure_name": "NGSetup",
        "ran_ue_ngap_id": None,
        "result": None,
        "rrc_establishment_cause": None,
        "sctp": {"association_id": 1, "dstport": 38412, "srcport": 52677, "stream_id": 0},
        "sender_role": None,
        "source": {"address": "127.0.0.1", "port": 52677},
        "support_status": "UNSUPPORTED",
        "timestamp": "2026-03-01T09:59:59.000000Z",
        "user_location_information_present": False,
    }

    @staticmethod
    def unowned(**overrides) -> dict:
        """Canonical ngap Skill output for a recognized but unowned procedure."""
        record = dict(NgapInputContractTests.UNOWNED)
        record.update(overrides)
        return record

    def write_ngap(self, directory: Path, records: list[dict]) -> Path:
        path = directory / "ngap.jsonl"
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return path

    def run_scenario_with(self, directory: Path, name: str, extra: list[dict]) -> tuple[dict, list[dict]]:
        variant = f"{name}-{len(extra)}"
        source = directory / variant
        shutil.copytree(INPUTS / name, source)
        with (source / "ngap.jsonl").open("a", encoding="utf-8") as handle:
            for record in extra:
                handle.write(json.dumps(record) + "\n")
        analysis_path = directory / f"{variant}-analysis.json"
        stages_path = directory / f"{variant}-stages.jsonl"
        rc = ANALYZE.main(["--input-dir", str(source), "--output", str(analysis_path),
                           "--stages-output", str(stages_path), "--force"])
        self.assertEqual(rc, 0, f"scenario {name} with {len(extra)} unowned record(s) failed with {rc}")
        return json.loads(analysis_path.read_text(encoding="utf-8")), jsonl(stages_path)

    def test_case_a_supported_with_identity_is_accepted(self):
        record = self.unowned(support_status="SUPPORTED", message_type="InitialUEMessage")
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))
            self.assertEqual(len(events), 1)
            self.assertFalse(MODEL.is_unowned_ngap_event(events[0]))

    def test_case_c_recognized_unsupported_is_accepted_as_unowned(self):
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.write_ngap(Path(directory), [self.unowned()]))
            self.assertEqual(len(events), 1)
            self.assertTrue(MODEL.is_unowned_ngap_event(events[0]))
            self.assertIsNone(events[0]["message_type"])
            self.assertEqual(events[0]["frame_number"], 900)
            self.assertEqual(events[0]["capture_file"], "sample.pcap")

    def test_case_b_supported_without_identity_fails_loudly(self):
        record = self.unowned(support_status="SUPPORTED")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "support_status SUPPORTED"):
                MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))

    def test_case_d_unknown_status_without_identity_fails_loudly(self):
        record = self.unowned(support_status="UNKNOWN", procedure_name=None, derivations=[])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "not a reviewed Protocol ownership declaration"):
                MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))

    def test_case_d_absent_status_without_identity_fails_loudly(self):
        record = self.unowned(support_status=None)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "not a reviewed Protocol ownership declaration"):
                MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))

    def test_reviewed_contradictory_status_with_identity_stays_owned(self):
        # Reviewed decision: identity decides usability, matching the Protocol
        # health contract, so a named message is never reclassified as unowned.
        record = self.unowned(message_type="PDUSessionResourceNotify")
        with tempfile.TemporaryDirectory() as directory:
            events = MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))
            self.assertFalse(MODEL.is_unowned_ngap_event(events[0]))

    def test_missing_mandatory_provenance_fails_loudly(self):
        record = self.unowned()
        del record["capture_file"]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(MODEL.InputError, "capture_file"):
                MODEL.load_ngap_events(self.write_ngap(Path(directory), [record]))

    def test_malformed_frame_number_fails_loudly(self):
        for bad in (0, "900", True, None):
            with self.subTest(frame=bad):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaisesRegex(MODEL.InputError, "frame_number"):
                        MODEL.load_ngap_events(self.write_ngap(Path(directory), [self.unowned(frame_number=bad)]))

    def test_unsupported_only_capture_creates_no_instance(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            output = directory / "analysis.json"
            rc = ANALYZE.main(["--ngap", str(self.write_ngap(directory, [self.unowned(), self.unowned(frame_number=901)])),
                               "--output", str(output), "--force"])
            self.assertEqual(rc, 0)
            analysis = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(analysis["instances"], [])
            self.assertEqual(len(analysis["unbound_evidence"]["unbound_n2"]), 2)

    def test_unsupported_preamble_does_not_block_pdu_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = self.run_scenario_with(directory, "normal-establishment", [])
            with_preamble = self.run_scenario_with(directory, "normal-establishment", [self.unowned()])
            self.assertEqual(with_preamble[0]["instances"], baseline[0]["instances"])
            self.assertEqual(with_preamble[1], baseline[1])

    def test_unsupported_record_sharing_a_ue_frame_stays_unbound(self):
        # Same capture and frame as a bound NAS event: the frame join must not
        # pull an unowned node-level record into the session instance.
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = self.run_scenario_with(directory, "normal-establishment", [])
            collision = self.run_scenario_with(directory, "normal-establishment", [self.unowned(frame_number=6)])
            self.assertEqual(collision[0]["instances"], baseline[0]["instances"])
            self.assertEqual(collision[1], baseline[1])

    def test_unsupported_records_do_not_duplicate_procedure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = self.run_scenario_with(directory, "normal-establishment", [])
            repeated = self.run_scenario_with(
                directory, "normal-establishment", [self.unowned(), self.unowned(frame_number=901)])
            self.assertEqual(repeated[0]["instances"], baseline[0]["instances"])
            for instance in repeated[0]["instances"]:
                self.assertNotIn("DUPLICATE", json.dumps([deviation["type"] for deviation in instance["deviations"]]))

    def test_unsupported_records_do_not_merge_sctp_associations(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = self.run_scenario_with(directory, "normal-establishment", [])
            other = self.run_scenario_with(
                directory, "normal-establishment",
                [self.unowned(sctp={"association_id": 77, "dstport": 38412, "srcport": 52677, "stream_id": 0})])
            self.assertEqual(other[0]["instances"], baseline[0]["instances"])

    def test_unsupported_records_do_not_merge_ue_contexts(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            baseline = self.run_scenario_with(directory, "multi-ue-same-psi", [])
            with_unowned = self.run_scenario_with(
                directory, "multi-ue-same-psi", [self.unowned(), self.unowned(frame_number=901)])
            self.assertEqual(with_unowned[0]["instances"], baseline[0]["instances"])
            self.assertEqual(len(with_unowned[0]["instances"]), len(baseline[0]["instances"]))

    def test_unsupported_record_does_not_become_the_session_ue_context(self):
        # A UE-associated unowned record is the sole NGAP context here. It must
        # not lend its RAN/AMF UE NGAP IDs to a session instance formed from NAS.
        nas = MODEL.load_nas_events(INPUTS / "normal-establishment" / "nas.jsonl")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            without_ngap = MODEL.analyze(nas, [], [], [], [], [])
            with_unowned = MODEL.analyze(
                nas,
                MODEL.load_ngap_events(self.write_ngap(
                    directory, [self.unowned(ran_ue_ngap_id=1, amf_ue_ngap_id=2, frame_number=7)])),
                [], [], [], [])
            self.assertEqual(with_unowned[0]["instances"], without_ngap[0]["instances"])
            self.assertEqual(with_unowned[1], without_ngap[1])

    def test_unsupported_record_keeps_protocol_provenance_when_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            with_unowned = self.run_scenario_with(Path(directory), "normal-establishment", [self.unowned()])
            retained = [event for event in with_unowned[0]["unbound_evidence"]["unbound_n2"]
                        if event.get("procedure_code") == 21]
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0]["frame_number"], 900)
            self.assertEqual(retained[0]["capture_file"], "sample.pcap")
            self.assertEqual(retained[0]["timestamp"], "2026-03-01T09:59:59.000000Z")
            self.assertEqual(retained[0]["sctp"]["association_id"], 1)
            self.assertIsNone(retained[0]["message_type"])
            self.assertEqual(retained[0]["support_status"], "UNSUPPORTED")


class SessionIdentityGatingTests(unittest.TestCase):
    """A PDU Session instance requires an explicit, bindable session identity.

    Generic UE-context signalling, security-protected NAS, an unrelated PFCP
    transaction, or unbound SBI traffic is valid packet evidence but never
    establishes a particular PDU Session, and no identifier may be assumed.
    """

    CAPTURE = "identity.pcap"

    @staticmethod
    def _ts(frame: int) -> str:
        return f"2026-10-05T08:00:{frame:02d}.000000Z"

    def nas(self, frame, message_type=None, **fields):
        event = {"frame_number": frame, "timestamp": self._ts(frame), "capture_file": self.CAPTURE,
                 "message_type": message_type}
        event.update(fields)
        return event

    def ngap(self, frame, message_type, ran=1, amf=1, resources=None, **fields):
        event = {"frame_number": frame, "timestamp": self._ts(frame), "capture_file": self.CAPTURE,
                 "message_type": message_type, "ran_ue_ngap_id": ran, "amf_ue_ngap_id": amf}
        if resources is not None:
            event["pdu_session_resources"] = resources
        event.update(fields)
        return event

    def pfcp(self, frame, **fields):
        event = {"frame_number": frame, "timestamp": self._ts(frame), "capture_file": self.CAPTURE,
                 "message_type": "Session Establishment Request", "header": {"seid": 1423, "ipv4": "127.0.0.4"}}
        event.update(fields)
        return event

    def gtpu(self, frame, teid=5001):
        return {"frame_number": frame, "timestamp": self._ts(frame), "capture_file": self.CAPTURE,
                "message_type": "G-PDUTDPPDU", "header": {"teid": teid},
                "outer": {"source_address": "127.0.0.2", "destination_address": "127.0.0.1"}}

    def sbi(self, frame, psi=None, message_type="CreateSmContext"):
        event = {"frame_number": frame, "timestamp": self._ts(frame), "capture_file": self.CAPTURE,
                 "message_type": message_type, "protocol": "3GPP-SBI"}
        if psi is not None:
            event["session_management"] = {"pdu_session_id": psi}
        return event

    def analyze(self, nas=(), ngap=(), pfcp=(), gtpu=(), sbi=(), correlation=()):
        return MODEL.analyze(list(nas), list(ngap), list(pfcp), list(gtpu), list(sbi), list(correlation))

    def assert_no_session(self, document):
        self.assertEqual(document["instances"], [], "no instance may be created without a session identity")
        self.assertNotIn("PARTIAL_CAPTURE", [d["type"] for i in document["instances"] for d in i["deviations"]])

    def test_generic_ue_context_alone_creates_no_instance(self):
        document, _ = self.analyze(ngap=[
            self.ngap(3, "InitialUEMessage", amf=None),
            self.ngap(4, "DownlinkNASTransport"),
            self.ngap(5, "UplinkNASTransport"),
            self.ngap(6, "UEContextReleaseCommand"),
        ])
        self.assertEqual(document["instances"], [])

    def test_registration_only_nas_creates_no_instance(self):
        document, _ = self.analyze(nas=[
            self.nas(1, "Registration request"),
            self.nas(2, "Authentication request"),
            self.nas(3, "Authentication response"),
            self.nas(4, "Security mode command"),
        ], ngap=[self.ngap(5, "InitialContextSetupRequest")])
        self.assertEqual(document["instances"], [])

    def test_ciphered_nas_without_identity_creates_no_instance(self):
        protected = self.nas(7, None, support_status="UNKNOWN", security={
            "ciphered": True, "header_type": 2, "inner_message_available": False})
        document, _ = self.analyze(nas=[protected], ngap=[self.ngap(8, "UplinkNASTransport")])
        self.assertEqual(document["instances"], [])

    def test_initial_ue_to_release_pair_creates_no_instance(self):
        document, _ = self.analyze(ngap=[
            self.ngap(2, "InitialUEMessage", amf=None),
            self.ngap(9, "UEContextReleaseCommand"),
        ])
        self.assertEqual(document["instances"], [])
        self.assertNotIn("PARTIAL_CAPTURE", [
            d["type"] for instance in document["instances"] for d in instance["deviations"]])

    def test_pfcp_transaction_alone_invents_no_session_id(self):
        document, _ = self.analyze(pfcp=[self.pfcp(4)])
        self.assertEqual(document["instances"], [])

    def test_gtpu_traffic_alone_invents_no_session_id(self):
        document, _ = self.analyze(gtpu=[self.gtpu(4)])
        self.assertEqual(document["instances"], [])

    def test_generic_ue_context_plus_pfcp_and_gtpu_still_creates_no_instance(self):
        document, _ = self.analyze(
            ngap=[self.ngap(3, "InitialUEMessage", amf=None), self.ngap(12, "UEContextReleaseCommand")],
            pfcp=[self.pfcp(4)], gtpu=[self.gtpu(14)])
        self.assertEqual(document["instances"], [])

    def test_explicit_ngap_resource_item_creates_instance(self):
        document, _ = self.analyze(ngap=[
            self.ngap(5, "PDUSessionResourceSetupRequest",
                      resources=[{"pdu_session_id": 7, "item_status": "SUCCEEDED", "qfi": 1}]),
            self.ngap(6, "PDUSessionResourceSetupResponse",
                      resources=[{"pdu_session_id": 7, "item_status": "SUCCEEDED"}]),
        ])
        self.assertEqual(len(document["instances"]), 1)
        instance = document["instances"][0]
        self.assertEqual(instance["pdu_session_id"], 7)
        self.assertIsNotNone(instance["observation_window"]["first_frame"])

    def test_explicit_nas_5gsm_identity_creates_bounded_instance(self):
        document, _ = self.analyze(
            nas=[self.nas(2, "PduSessionEstablishmentRequest", session_management={"pdu_session_id": 4, "pti": 1}),
                 self.nas(3, "PduSessionEstablishmentAccept",
                          session_management={"pdu_session_id": 4, "pti": 1})],
            ngap=[self.ngap(1, "InitialUEMessage", amf=None)])
        self.assertEqual(len(document["instances"]), 1)
        instance = document["instances"][0]
        self.assertEqual(instance["pdu_session_id"], 4)
        window = instance["observation_window"]
        self.assertEqual([window["first_frame"], window["last_frame"]], [2, 3])

    def test_explicit_sbi_identity_creates_instance_only_with_unambiguous_context(self):
        single = self.analyze(
            ngap=[self.ngap(2, "InitialUEMessage")], sbi=[self.sbi(6, psi=5)])[0]
        self.assertEqual(len(single["instances"]), 1)
        instance = single["instances"][0]
        self.assertEqual(instance["pdu_session_id"], 5)
        self.assertEqual(instance["ue_context"]["ran_ue_ngap_id"], 1)

        # Two distinct UE contexts share the capture: an equal numeric session id is
        # not a safe association, so the identity stays context-unresolved instead
        # of being bound to whichever context happens to come first.
        ambiguous = self.analyze(
            ngap=[self.ngap(2, "InitialUEMessage", ran=1, amf=1),
                  self.ngap(3, "InitialUEMessage", ran=2, amf=2)],
            sbi=[self.sbi(6, psi=5)])[0]
        self.assertEqual(len(ambiguous["instances"]), 1)
        context = ambiguous["instances"][0]["ue_context"]
        self.assertIsNone(context["ran_ue_ngap_id"])
        self.assertIsNone(context["amf_ue_ngap_id"])
        self.assertIn(":psi5", ambiguous["instances"][0]["instance_id"])

    def test_unbound_sbi_without_identity_creates_no_instance(self):
        document, _ = self.analyze(sbi=[self.sbi(6, psi=None)])
        self.assertEqual(document["instances"], [])

    def test_multi_ue_input_never_merges_sessions(self):
        document, _ = self.analyze(nas=[
            self.nas(3, "PduSessionEstablishmentRequest", session_management={"pdu_session_id": 1, "pti": 1}),
            self.nas(5, "PduSessionEstablishmentRequest", session_management={"pdu_session_id": 1, "pti": 2}),
        ], ngap=[
            self.ngap(3, "UplinkNASTransport", ran=1, amf=1),
            self.ngap(5, "UplinkNASTransport", ran=2, amf=2),
        ])
        instances = document["instances"]
        self.assertEqual(len(instances), 2)
        self.assertEqual({i["pdu_session_id"] for i in instances}, {1})
        self.assertEqual(sorted(i["ue_context"]["ran_ue_ngap_id"] for i in instances), [1, 2])
        self.assertEqual(len({i["instance_id"] for i in instances}), 2)
        self.assertEqual(sorted((i["observation_window"]["first_frame"],
                                 i["observation_window"]["last_frame"]) for i in instances),
                         [(3, 3), (5, 5)], "each session keeps only its own frame provenance")

    def test_identical_psi_in_separate_ue_contexts_stays_separate(self):
        document, _ = self.analyze(ngap=[
            self.ngap(3, "PDUSessionResourceSetupRequest", ran=1, amf=1,
                      resources=[{"pdu_session_id": 1, "item_status": "SUCCEEDED"}]),
            self.ngap(4, "PDUSessionResourceSetupRequest", ran=2, amf=2,
                      resources=[{"pdu_session_id": 1, "item_status": "SUCCEEDED"}]),
        ])
        instances = document["instances"]
        self.assertEqual(len(instances), 2)
        self.assertEqual(len({i["instance_id"] for i in instances}), 2)
        for instance in instances:
            ran = instance["ue_context"]["ran_ue_ngap_id"]
            self.assertEqual(instance["observation_window"],
                             {"first_frame": ran + 2, "last_frame": ran + 2})
            for deviation in instance["deviations"]:
                for ref in deviation["evidence_refs"]:
                    self.assertEqual(ref["window_first_frame"], ran + 2)
                    self.assertEqual(ref["window_last_frame"], ran + 2)

    def test_repeated_psi_in_new_lifecycle_keeps_generation_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis, _ = run_scenario("release-psi-reuse-after-complete", Path(directory))
            instances = analysis["instances"]
            self.assertEqual([i.get("session_generation") for i in instances], [1, 2])
            self.assertEqual(instances[1].get("reuse_status"), "REESTABLISHED_AFTER_RELEASE_COMPLETE")

    def test_valid_partial_capture_keeps_window_and_references(self):
        document, _ = self.analyze(ngap=[
            self.ngap(9, "PDUSessionResourceSetupRequest",
                      resources=[{"pdu_session_id": 2, "item_status": "SUCCEEDED", "qfi": 1}]),
        ])
        self.assertEqual(len(document["instances"]), 1)
        instance = document["instances"][0]
        partials = [d for d in instance["deviations"] if d["type"] == "PARTIAL_CAPTURE"]
        self.assertTrue(partials, "a session without its initiation stage keeps partial-capture visibility")
        for deviation in partials:
            self.assertTrue(deviation["evidence_refs"], "a partial-capture claim must stay anchored")
            self.assertIsNotNone(deviation["evidence_refs"][0]["window_first_frame"])

    def test_removed_instance_takes_its_partial_capture_with_it(self):
        for kwargs in ({"ngap": [self.ngap(3, "InitialUEMessage", amf=None)]},
                       {"pfcp": [self.pfcp(4)]},
                       {"gtpu": [self.gtpu(4)]},
                       {"nas": [self.nas(7, None, support_status="UNKNOWN")]},
                       {"sbi": [self.sbi(6, psi=None)]}):
            with self.subTest(input=sorted(kwargs)):
                self.assert_no_session(self.analyze(**kwargs)[0])

    def test_protected_nas_never_becomes_a_session_reject(self):
        document, _ = self.analyze(
            nas=[self.nas(2, "Registration request"),
                 self.nas(7, None, support_status="UNKNOWN", security={
                     "ciphered": True, "header_type": 2, "inner_message_available": False})],
            ngap=[self.ngap(8, "DownlinkNASTransport", ran=1, amf=1)])
        self.assertEqual(document["instances"], [])
        self.assertNotIn("ESTABLISHMENT_REJECT_OBSERVED", str(document))

    def test_package_runs_standalone_without_repository_root(self):
        scripts = str(SCRIPTS)
        with tempfile.TemporaryDirectory() as directory:
            probe = Path(directory) / "probe.py"
            probe.write_text(
                "import sys\n"
                "import pdu_session_model as model\n"
                "bad = [m for m in sys.modules.values() if getattr(m, '__file__', None)\n"
                "         and str(getattr(m, '__file__')).replace('\\\\', '/')]\n"
                "print('OK', model.ANALYSIS_VERSION)\n",
                encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(probe)],
                cwd=directory, env={"PYTHONPATH": scripts, "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")},
                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr[-300:])
        self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
