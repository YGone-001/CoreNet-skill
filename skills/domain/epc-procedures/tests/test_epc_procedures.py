#!/usr/bin/env python3
"""Standalone tests for the bounded EPC Attach Domain Skill."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
EXAMPLES = PACKAGE / "examples"
ANALYZE = SCRIPTS / "analyze_epc_attach.py"
TIMELINE = SCRIPTS / "epc_attach_timeline.py"

sys.path.insert(0, str(SCRIPTS))
import epc_attach_model as model  # noqa: E402


def run(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True, check=False
    )


def s1ap_event(frame, message, enb, mme, procedure=11, nas_pdu=True):
    return {
        "frame_number": frame,
        "timestamp": f"2025-03-11T19:03:{frame:02d}.000000Z",
        "capture_file": "synthetic.pcap",
        "message_type": message,
        "procedure_code": procedure,
        "procedure_name": message,
        "pdu_type": "initiatingMessage",
        "result": "REQUEST",
        "support_status": "SUPPORTED",
        "sender_role": "mme",
        "enb_ue_s1ap_id": enb,
        "mme_ue_s1ap_id": mme,
        "cause": None,
        "nas_pdu_present": nas_pdu,
        "nas_pdu_length": 20 if nas_pdu else None,
        "evidence": {"level": "OBSERVED", "source": f"capture:synthetic.pcap#frame={frame}"},
        "sctp": {"association_id": 1},
    }


def nas_event(frame, message, code, direction="uplink", **extra):
    event = {
        "frame_number": frame,
        "timestamp": f"2025-03-11T19:03:{frame:02d}.000000Z",
        "capture_file": "synthetic.pcap",
        "message_type": message,
        "message_type_code": code,
        "direction": direction,
        "protection": "PLAIN",
        "security_header_type": 0,
        "emm_cause": None,
        "protected_inner_message_unavailable": False,
        "evidence": {"level": "OBSERVED", "source": f"capture:synthetic.pcap#frame={frame}"},
        "sctp": {"association_id": 1},
    }
    event.update(extra)
    return event


def analyze_events(s1ap, nas, name="synthetic"):
    return model.analyze(s1ap, nas, f"{name}-s1ap.jsonl", f"{name}-nas.jsonl")


class FixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def analyze_fixture(self, case: str) -> dict:
        output = self.base / f"{case}.json"
        completed = run(
            ANALYZE,
            "--s1ap", str(EXAMPLES / "extracted" / f"{case}-s1ap.jsonl"),
            "--nas", str(EXAMPLES / "extracted" / f"{case}-nas.jsonl"),
            "--output", str(output),
        )
        self.assertIn(completed.returncode, (0, 6), completed.stderr)
        return json.loads(output.read_text(encoding="utf-8"))

    # D1 / D7 ---------------------------------------------------------------
    def test_attach_request_opens_instance_and_reject_is_anchored(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        self.assertEqual(analysis["instance_count"], 2)
        for instance in analysis["procedure_instances"]:
            initiation = {s["stage_id"]: s for s in instance["stages"]}["attach-initiation"]
            self.assertEqual(initiation["status"], "OBSERVED")
            rejections = [
                d for d in instance["deviations"] if d["deviation_type"] == "ATTACH_REJECT_OBSERVED"
            ]
            self.assertEqual(len(rejections), 1)
            self.assertEqual(rejections[0]["procedure_stage"], "attach-decision")
            self.assertEqual(rejections[0]["protocol"], "NAS-EPS")
            self.assertEqual(rejections[0]["evidence_refs"][0]["frame_number"], rejections[0]["frame_number"])

    def test_attach_reject_preserves_emm_cause(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        explanations = [
            deviation["explanation"]
            for instance in analysis["procedure_instances"]
            for deviation in instance["deviations"]
            if deviation["deviation_type"] == "ATTACH_REJECT_OBSERVED"
        ]
        self.assertTrue(explanations)
        self.assertIn("19", explanations[0])
        self.assertIn("ESM failure", explanations[0])

    # D3 / D13 --------------------------------------------------------------
    def test_multiple_ues_remain_independent(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        references = {item["procedure_reference"] for item in analysis["procedure_instances"]}
        self.assertEqual(len(references), analysis["instance_count"])
        enb_ids = {item["association"]["enb_ue_s1ap_id"] for item in analysis["procedure_instances"]}
        self.assertEqual(len(enb_ids), analysis["instance_count"])

    def test_authentication_messages_stay_with_their_ue(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        for instance in analysis["procedure_instances"]:
            frames = [
                observation["frame_number"]
                for observation in instance["observations"]
                if observation["observation_type"] == "AUTHENTICATION_RESPONSE_OBSERVED"
            ]
            self.assertEqual(len(frames), 1)
            self.assertGreaterEqual(frames[0], instance["first_frame"])
            self.assertLessEqual(frames[0], instance["last_frame"])

    # D4 / D5 / D6 ----------------------------------------------------------
    def test_authentication_failure_and_reject_are_recorded(self) -> None:
        analysis = self.analyze_fixture("auth-failure")
        instance = analysis["procedure_instances"][0]
        types = [deviation["deviation_type"] for deviation in instance["deviations"]]
        self.assertIn("AUTHENTICATION_FAILURE_OBSERVED", types)
        self.assertIn("AUTHENTICATION_REJECT_OBSERVED", types)
        failure = next(d for d in instance["deviations"] if d["deviation_type"] == "AUTHENTICATION_FAILURE_OBSERVED")
        self.assertEqual(failure["frame_number"], 12)
        self.assertEqual(failure["procedure_stage"], "authentication")
        self.assertEqual(failure["evidence_level"], "OBSERVED")

    def test_security_mode_is_separate_from_authentication(self) -> None:
        analysis = self.analyze_fixture("smc-reject")
        stages = {stage["stage_id"]: stage for stage in analysis["procedure_instances"][0]["stages"]}
        self.assertEqual(stages["authentication"]["status"], "OBSERVED")
        self.assertEqual(stages["security-mode"]["status"], "OBSERVED")
        self.assertNotEqual(stages["authentication"]["messages"], stages["security-mode"]["messages"])
        rejections = [
            deviation
            for deviation in analysis["procedure_instances"][0]["deviations"]
            if deviation["deviation_type"] == "SECURITY_MODE_REJECT_OBSERVED"
        ]
        self.assertEqual(len(rejections), 1)
        self.assertEqual(rejections[0]["frame_number"], 24)

    # D8 / D9 ---------------------------------------------------------------
    def test_attach_accept_and_complete_are_observed_not_service_success(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 3, None, 12),
            s1ap_event(11, "DownlinkNASTransport", 3, 33, 11),
            s1ap_event(12, "UplinkNASTransport", 3, 33, 13),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(11, "Attach accept", 66, "downlink", result="ACCEPT"),
            nas_event(12, "Attach complete", 67, result="COMPLETE"),
        ]
        analysis = analyze_events(s1ap, nas)
        instance = analysis["procedure_instances"][0]
        observations = {item["observation_type"] for item in instance["observations"]}
        self.assertIn("ATTACH_ACCEPT_OBSERVED", observations)
        self.assertIn("ATTACH_COMPLETE_OBSERVED", observations)
        serialised = json.dumps(analysis).lower()
        for forbidden in ("bearer_active", "pdn_connectivity_success", "user_plane_ready", "service_success"):
            self.assertNotIn(forbidden, serialised)
        self.assertIn("default bearer activation is not established", serialised)

    def test_missing_attach_complete_is_a_limitation(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 3, None, 12),
            s1ap_event(11, "DownlinkNASTransport", 3, 33, 11),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(11, "Attach accept", 66, "downlink", result="ACCEPT"),
        ]
        analysis = analyze_events(s1ap, nas)
        instance = analysis["procedure_instances"][0]
        self.assertTrue(
            any("Attach accept was observed without Attach complete" in item for item in instance["evidence_limitations"])
        )
        self.assertNotIn(
            "INSUFFICIENT_TERMINAL_EVIDENCE",
            [deviation["deviation_type"] for deviation in instance["deviations"]],
        )

    # D10 -------------------------------------------------------------------
    def test_protected_nas_does_not_invent_inner_messages(self) -> None:
        analysis = self.analyze_fixture("protected-inner")
        instance = analysis["procedure_instances"][0]
        deviations = [d for d in instance["deviations"] if d["deviation_type"] == "PROTECTED_INNER_MESSAGE_UNAVAILABLE"]
        self.assertEqual(len(deviations), 1)
        self.assertIsNone(deviations[0]["message_type"])
        self.assertIn("INSUFFICIENT_TERMINAL_EVIDENCE", [d["deviation_type"] for d in instance["deviations"]])

    # D11 / D12 -------------------------------------------------------------
    def test_s1_context_setup_failure_is_ue_scoped(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 4, None, 12),
            s1ap_event(11, "InitialContextSetupRequest", 4, 44, 9),
            s1ap_event(12, "InitialContextSetupFailure", 4, 44, 9),
            s1ap_event(20, "InitialUEMessage", 5, None, 12),
            s1ap_event(21, "InitialContextSetupRequest", 5, 55, 9),
            s1ap_event(22, "InitialContextSetupResponse", 5, 55, 9),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(20, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
        ]
        for event in nas[1:]:
            event["sctp"] = {"association_id": 1}
        nas[1]["frame_number"] = 20
        analysis = analyze_events(s1ap, nas)
        self.assertEqual(analysis["instance_count"], 2)
        by_enb = {item["association"]["enb_ue_s1ap_id"]: item for item in analysis["procedure_instances"]}
        failure_types = [d["deviation_type"] for d in by_enb[4]["deviations"]]
        success_types = [d["deviation_type"] for d in by_enb[5]["deviations"]]
        self.assertIn("S1_CONTEXT_SETUP_FAILURE_OBSERVED", failure_types)
        self.assertNotIn("S1_CONTEXT_SETUP_FAILURE_OBSERVED", success_types)
        observations = {item["observation_type"] for item in by_enb[5]["observations"]}
        self.assertIn("S1_CONTEXT_SETUP_RESPONSE_OBSERVED", observations)

    def test_context_release_does_not_invent_a_root_cause(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        instance = analysis["procedure_instances"][0]
        release = [s for s in instance["stages"] if s["stage_id"] == "context-release"][0]
        self.assertEqual(release["status"], "OBSERVED")
        serialised = json.dumps(instance).lower()
        for forbidden in ("caused by", "root cause is", "responsibility", "culprit"):
            self.assertNotIn(forbidden, serialised)

    # D14 / D15 / D16 -------------------------------------------------------
    def test_conflicting_identifiers_stay_ambiguous(self) -> None:
        analysis = self.analyze_fixture("conflicting-ids")
        strengths = {item["association"]["strength"] for item in analysis["procedure_instances"]}
        self.assertIn("AMBIGUOUS", strengths)
        self.assertEqual(analysis["global_first_abnormal_boundary"], None)
        self.assertEqual(analysis["global_boundary_evaluation"], "NOT_EVALUATED")

    def test_identifier_reuse_across_attempts_is_not_merged(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 6, None, 12),
            s1ap_event(11, "DownlinkNASTransport", 6, 66, 11),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(11, "Attach reject", 68, "downlink", result="REJECT",
                      emm_cause={"value": 15, "name": "No suitable cells in tracking area"}),
        ]
        analysis = analyze_events(s1ap, nas)
        instance = analysis["procedure_instances"][0]
        self.assertEqual(instance["attempt_index"], 1)
        self.assertEqual(len(analysis["procedure_instances"]), 1)

    def test_unbound_nas_evidence_stays_unbound(self) -> None:
        output = self.base / "unbound.json"
        completed = run(
            ANALYZE,
            "--s1ap", str(EXAMPLES / "extracted" / "unbound-nas-s1ap.jsonl"),
            "--nas", str(EXAMPLES / "extracted" / "unbound-nas.jsonl"),
            "--output", str(output),
        )
        self.assertEqual(completed.returncode, 6, completed.stderr)
        analysis = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(analysis["instance_count"], 0)
        self.assertEqual(len(analysis["unbound_evidence"]), 2)
        self.assertTrue(any("no enclosing S1AP" in item["reason"] for item in analysis["unbound_evidence"]))

    # D17 / D18 -------------------------------------------------------------
    def test_repeated_attach_request_does_not_duplicate_attempts(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 8, None, 12),
            s1ap_event(11, "UplinkNASTransport", 8, 88, 13),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(11, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
        ]
        analysis = analyze_events(s1ap, nas)
        self.assertEqual(analysis["instance_count"], 1)
        observations = [o["observation_type"] for o in analysis["procedure_instances"][0]["observations"]]
        self.assertEqual(observations.count("ATTACH_REQUEST_OBSERVED"), 2)

    def test_unsupported_messages_do_not_complete_a_stage(self) -> None:
        s1ap = [
            s1ap_event(10, "InitialUEMessage", 12, None, 12),
            s1ap_event(11, "UplinkNASTransport", 12, 121, 13),
        ]
        nas = [
            nas_event(10, "Attach request", 65, procedure="eps-attach", result="REQUEST"),
            nas_event(11, "Tracking area update request", 72, support_status="UNSUPPORTED"),
        ]
        analysis = analyze_events(s1ap, nas)
        stages = {s["stage_id"]: s for s in analysis["procedure_instances"][0]["stages"]}
        self.assertEqual(stages["attach-decision"]["status"], "NOT_OBSERVED")
        self.assertEqual(stages["attach-completion"]["status"], "NOT_OBSERVED")

    # D19 / D20 -------------------------------------------------------------
    def test_malformed_evidence_fails_explicitly(self) -> None:
        completed = run(
            ANALYZE,
            "--s1ap", str(EXAMPLES / "extracted" / "attach-reject-s1ap.jsonl"),
            "--nas", str(EXAMPLES / "extracted" / "malformed-nas.jsonl"),
            "--output", str(self.base / "out.json"),
        )
        self.assertEqual(completed.returncode, 5)
        self.assertIn("input error", completed.stderr)
        self.assertFalse((self.base / "out.json").exists())

    def test_no_subscriber_material_in_analysis(self) -> None:
        analysis = self.analyze_fixture("attach-reject")
        serialised = json.dumps(analysis).lower()
        for forbidden in ("imsi", "imei", "guti", "tmsi", "rand", "autn", "kasme"):
            self.assertNotIn(forbidden, serialised)
        self.assertNotRegex(serialised, r"\\d{14,}")

    # Golden files ----------------------------------------------------------
    def test_expected_analysis_matches_committed_golden_files(self) -> None:
        for case in ("attach-reject", "auth-failure", "smc-reject", "conflicting-ids", "protected-inner"):
            with self.subTest(case=case):
                produced = self.analyze_fixture(case)
                golden = json.loads(
                    (EXAMPLES / "expected" / f"{case}-analysis.json").read_text(encoding="utf-8")
                )
                self.assertEqual(produced, golden)

    def test_stage_timeline_matches_committed_golden_file(self) -> None:
        stages = self.base / "stages.jsonl"
        completed = run(
            ANALYZE,
            "--s1ap", str(EXAMPLES / "extracted" / "attach-reject-s1ap.jsonl"),
            "--nas", str(EXAMPLES / "extracted" / "attach-reject-nas.jsonl"),
            "--output", str(self.base / "analysis.json"),
            "--stage-output", str(stages),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        produced = [json.loads(line) for line in stages.read_text(encoding="utf-8").splitlines()]
        golden = [
            json.loads(line)
            for line in (EXAMPLES / "expected" / "attach-reject-stages.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(produced, golden)

    def test_deterministic_output(self) -> None:
        first = self.base / "a.json"
        second = self.base / "b.json"
        for target in (first, second):
            run(
                ANALYZE,
                "--s1ap", str(EXAMPLES / "extracted" / "attach-reject-s1ap.jsonl"),
                "--nas", str(EXAMPLES / "extracted" / "attach-reject-nas.jsonl"),
                "--output", str(target),
            )
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_existing_output_is_not_overwritten_without_force(self) -> None:
        output = self.base / "analysis.json"
        output.write_text("keep-me\n", encoding="utf-8")
        completed = run(
            ANALYZE,
            "--s1ap", str(EXAMPLES / "extracted" / "attach-reject-s1ap.jsonl"),
            "--nas", str(EXAMPLES / "extracted" / "attach-reject-nas.jsonl"),
            "--output", str(output),
        )
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep-me\n")


class TimelineTests(unittest.TestCase):
    def test_text_timeline_renders_stages_and_deviations(self) -> None:
        completed = run(TIMELINE, str(EXAMPLES / "expected" / "attach-reject-analysis.json"))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("stage attach-initiation", completed.stdout)
        self.assertIn("ATTACH_REJECT_OBSERVED", completed.stdout)
        self.assertIn("Global boundary     : NOT_EVALUATED", completed.stdout)
        self.assertIn("Not confirmed:", completed.stdout)

    def test_timeline_rejects_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broken.json"
            path.write_text("{}", encoding="utf-8")
            completed = run(TIMELINE, str(path))
            self.assertEqual(completed.returncode, 5)


class ModelTests(unittest.TestCase):
    def test_nas_event_without_enclosing_s1ap_is_unbound(self) -> None:
        bound, unbound, ambiguous = model.bind_nas_events(
            [nas_event(5, "Attach request", 65)], {}
        )
        self.assertEqual(bound, [])
        self.assertEqual(len(unbound), 1)
        self.assertEqual(ambiguous, [])

    def test_multiple_nas_carrying_s1ap_messages_are_ambiguous(self) -> None:
        s1ap = [s1ap_event(5, "UplinkNASTransport", 1, 2), s1ap_event(5, "UplinkNASTransport", 3, 4)]
        index = model.index_s1ap_by_frame(s1ap)
        bound, unbound, ambiguous = model.bind_nas_events([nas_event(5, "Attach request", 65)], index)
        self.assertEqual(bound, [])
        self.assertEqual(unbound, [])
        self.assertEqual(len(ambiguous), 1)
        self.assertEqual(len(ambiguous[0]["candidates"]), 2)

    def test_s1ap_event_without_nas_pdu_does_not_bind(self) -> None:
        s1ap = [s1ap_event(5, "UEContextReleaseCommand", 1, 2, 23, nas_pdu=False)]
        index = model.index_s1ap_by_frame(s1ap)
        bound, unbound, _ = model.bind_nas_events([nas_event(5, "Attach reject", 68)], index)
        self.assertEqual(bound, [])
        self.assertEqual(len(unbound), 1)

    def test_procedure_reference_is_pseudonymous(self) -> None:
        context = {
            "capture_file": "capture.pcap",
            "sctp_association": "sctp-assoc-1",
            "enb_ue_s1ap_id": 12345,
            "mme_ue_s1ap_id": 67890,
        }
        reference = model.context_identity(context, 1)
        self.assertRegex(reference, r"^epc-attach-[0-9a-f]{10}$")
        self.assertNotIn("12345", reference)
        self.assertNotIn("67890", reference)

    def test_validate_events_rejects_missing_frame(self) -> None:
        with self.assertRaises(model.InputError):
            model.validate_events([{"timestamp": "t", "capture_file": "c", "message_type": "x"}], "NAS-EPS")


if __name__ == "__main__":
    unittest.main()
