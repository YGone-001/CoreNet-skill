"""Synthetic regression tests for bounded authentication recovery detection.

These tests verify that a recovered 5G NAS Authentication Failure (cause 21,
synchronization failure) followed by a subsequent Authentication request and
Authentication response within the same procedure instance is classified as
RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED rather than UNSUCCESSFUL_OUTCOME_OBSERVED,
and that the recovered deviation is not candidate-eligible for boundary selection.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
RULES = PACKAGE / "rules"
sys.path.insert(0, str(SCRIPTS))

import procedure_model as MODEL


def nas_record(frame: int, message_type: str, cause_code=None, cause_name=None,
               timestamp: str | None = None) -> dict:
    if timestamp is None:
        timestamp = f"2024-01-02T03:04:{frame:02d}.00Z"
    return {
        "capture_file": "reg.pcapng",
        "cause": {"code": cause_code, "name": cause_name},
        "frame_number": frame,
        "identity": {"value": None},
        "message_type": message_type,
        "nas_family": "5GMM",
        "registration": {"type_name": None},
        "security": {"header_type": 2, "inner_message_available": True},
        "security_mode": {"ciphering_algorithm_name": None, "integrity_algorithm_name": None},
        "support_status": "SUPPORTED",
        "timestamp": timestamp,
    }


def ngap_record(frame: int, message_type: str, ran_id: int = 1, amf_id: int | None = 2,
                timestamp: str | None = None) -> dict:
    if timestamp is None:
        timestamp = f"2024-01-02T03:04:{frame:02d}.00Z"
    return {
        "amf_ue_ngap_id": amf_id,
        "capture_file": "reg.pcapng",
        "cause": None,
        "frame_number": frame,
        "message_type": message_type,
        "pdu_type": "initiatingMessage",
        "procedure_name": message_type,
        "protocol": "NGAP",
        "ran_ue_ngap_id": ran_id,
        "sctp": {"association_id": 0, "dstport": 38412, "srcport": 31000, "stream_id": 0},
        "support_status": "SUPPORTED",
        "timestamp": timestamp,
    }


def recovery_nas_events() -> list[dict]:
    """NAS events with Authentication failure followed by full recovery."""
    return [
        nas_record(10, "Registration request"),
        nas_record(11, "Authentication request"),
        nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
        nas_record(13, "Authentication request"),
        nas_record(14, "Authentication response"),
        nas_record(15, "Security mode command"),
        nas_record(16, "Security mode complete"),
        nas_record(17, "Registration accept"),
        nas_record(18, "Registration complete"),
    ]


def recovery_ngap_events() -> list[dict]:
    """NGAP events matching the recovery NAS sequence."""
    return [
        ngap_record(10, "InitialUEMessage", amf_id=None),
        ngap_record(11, "DownlinkNASTransport"),
        ngap_record(12, "UplinkNASTransport"),
        ngap_record(13, "DownlinkNASTransport"),
        ngap_record(14, "UplinkNASTransport"),
        ngap_record(15, "DownlinkNASTransport"),
        ngap_record(16, "UplinkNASTransport"),
        ngap_record(17, "DownlinkNASTransport"),
        ngap_record(18, "UplinkNASTransport"),
    ]


def write_and_load(directory: Path, nas_events: list[dict], ngap_events: list[dict]):
    nas_path = directory / "nas.jsonl"
    ngap_path = directory / "ngap.jsonl"
    nas_path.write_text("".join(json.dumps(r) + "\n" for r in nas_events), encoding="utf-8")
    ngap_path.write_text("".join(json.dumps(r) + "\n" for r in ngap_events), encoding="utf-8")
    return MODEL.analyze(
        MODEL.load_ngap_events(ngap_path),
        MODEL.load_nas_events(nas_path),
        [],
        RULES,
    )


def first_instance(analysis: dict) -> dict:
    return analysis["analyses"][0]


def deviation_types(instance: dict) -> set[str]:
    return {d["type"] for d in instance["deviations"]}


class AuthRecoveryDetectionTests(unittest.TestCase):
    """Verify that recovered Authentication failures are classified correctly."""

    def test_01_full_recovery_classified_as_recovered(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))

    def test_02_no_recovery_stays_unsuccessful(self):
        """Auth failure without subsequent request+response stays UNSUCCESSFUL."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))

    def test_03_only_request_after_failure_no_recovery(self):
        """Auth failure followed by only Auth request (no response) is not recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))

    def test_04_only_response_after_failure_no_recovery(self):
        """Auth failure followed by only Auth response (no request) is not recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))

    def test_05_recovered_deviation_has_three_evidence_refs(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertEqual(len(recovered), 1)
            refs = recovered[0]["evidence_refs"]
            self.assertEqual(len(refs), 3)
            frames = [r.get("frame_number") for r in refs if r.get("kind") == "EVENT"]
            self.assertEqual(sorted(frames), [12, 13, 14])

    def test_06_recovered_deviation_evidence_level_is_observed(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertEqual(recovered[0]["evidence_level"], "OBSERVED")

    def test_07_recovered_type_not_candidate_eligible(self):
        """The recovered deviation type is not in the candidate-eligible set."""
        self.assertEqual(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED")
        self.assertNotEqual(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, MODEL.DEVIATION_UNSUCCESSFUL)

    def test_08_recovered_description_mentions_all_frames(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            desc = recovered[0]["description"]
            self.assertIn("frame 12", desc)
            self.assertIn("frame 13", desc)
            self.assertIn("frame 14", desc)

    def test_09_initial_context_setup_failure_unaffected(self):
        """ICS failure is not subject to recovery detection."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication response"),
            nas_record(13, "Security mode command"),
            nas_record(14, "Security mode complete"),
            nas_record(15, "Registration accept"),
            nas_record(16, "Registration complete"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
            ngap_record(15, "InitialContextSetupFailure", amf_id=2),
        ]
        ngap[-1]["cause"] = "radioNetwork:3"
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))

    def test_10_recovery_strict_frame_ordering(self):
        """Recovery request must appear after the failure frame."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication response"),
            nas_record(14, "Authentication request"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "UplinkNASTransport"),
            ngap_record(14, "DownlinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))

    def test_11_recovery_does_not_cross_instances(self):
        """Recovery in a different UE instance does not reclassify the failure."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(20, "Registration request"),
            nas_record(21, "Authentication request"),
            nas_record(22, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", ran_id=1, amf_id=None),
            ngap_record(11, "DownlinkNASTransport", ran_id=1),
            ngap_record(12, "UplinkNASTransport", ran_id=1),
            ngap_record(20, "InitialUEMessage", ran_id=2, amf_id=None),
            ngap_record(21, "DownlinkNASTransport", ran_id=2, amf_id=3),
            ngap_record(22, "UplinkNASTransport", ran_id=2, amf_id=3),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            self.assertEqual(len(analysis["analyses"]), 2)
            failure_instance = next(
                inst for inst in analysis["analyses"]
                if any(d["type"] == MODEL.DEVIATION_UNSUCCESSFUL for d in inst["deviations"])
            )
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(failure_instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(failure_instance))

    def test_12_multiple_failures_all_recovered(self):
        """Two Auth failures each followed by recovery are both recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
            nas_record(15, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(16, "Authentication request"),
            nas_record(17, "Authentication response"),
            nas_record(18, "Security mode command"),
            nas_record(19, "Security mode complete"),
            nas_record(20, "Registration accept"),
            nas_record(21, "Registration complete"),
        ]
        ngap = [ngap_record(f, "DownlinkNASTransport") for f in range(11, 22)]
        ngap[0] = ngap_record(10, "InitialUEMessage", amf_id=None)
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertEqual(len(recovered), 2)
            self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))

    def test_13_recovery_followed_by_registration_complete(self):
        """Full recovery sequence reaches Registration Complete terminal."""
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            self.assertEqual(instance["terminal"]["observation"], MODEL.TERMINAL_COMPLETE)

    def test_14_recovered_deviation_has_limitation_text(self):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            limitation = recovered[0]["limitation"]
            self.assertIn("not candidate-eligible", limitation)

    def test_15_recovery_no_security_mode_required(self):
        """Recovery is established by Auth request+response alone; no Security Mode needed."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))


class AuthRecoveryCauseBarrierTests(unittest.TestCase):
    """Cause-aware recovery qualification: only cause 21 authorizes recovery."""

    def _assert_not_recovered(self, nas, ngap):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))
            return instance

    def test_16_cause_20_mac_failure_not_recovered(self):
        """Cause 20 (MAC failure) with later request+response is not recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=20, cause_name="Mac failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_17_unknown_cause_not_recovered(self):
        """An unknown/reserved cause code with later request+response is not recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=99, cause_name="Reserved"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_18_missing_cause_not_recovered(self):
        """An Authentication failure with no decoded cause is not recovered."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_19_cause_21_with_none_cause_code_not_recovered(self):
        """A cause dict with code None must not match cause 21."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=None, cause_name=None),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)


class AuthRecoveryTerminationBarrierTests(unittest.TestCase):
    """Termination and re-scoping barriers block retroactive recovery."""

    def _assert_not_recovered(self, nas, ngap):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))
            return instance

    def test_20_auth_reject_before_request_blocks_recovery(self):
        """Authentication reject between failure and later request blocks recovery."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication reject"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "UplinkNASTransport"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_21_registration_reject_blocks_recovery(self):
        """Registration reject between failure and later request blocks recovery."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Registration reject"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_22_ue_context_release_blocks_recovery(self):
        """A terminating UE context release between failure and request blocks recovery."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "UEContextReleaseCommand"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_23_new_registration_request_blocks_recovery(self):
        """A new independent Registration request between failure and re-challenge blocks recovery."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Registration request"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "InitialUEMessage"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)

    def test_24_later_auth_failure_blocks_recovery(self):
        """A later Authentication failure blocks recovery of the earlier failure.

        The first failure (frame 12) must stay UNSUCCESSFUL because a later
        Authentication failure (frame 13) is a re-scoping barrier. The second
        failure is evaluated independently and may recover on its own.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "UplinkNASTransport"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            types = deviation_types(instance)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, types)
            recovered = [dev for dev in instance["deviations"]
                         if dev["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            for dev in recovered:
                refs = dev.get("evidence_refs", [])
                failure_frames = [r.get("frame_number") for r in refs
                                  if r.get("kind") == "EVENT" and r.get("message_type") == "Authentication failure"]
                self.assertNotIn(12, failure_frames,
                                 "the first failure must not be recovered when a later failure intervenes")

    def test_25_barrier_between_request_and_response_blocks_recovery(self):
        """A barrier between the re-challenge request and response blocks recovery."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication reject"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        self._assert_not_recovered(nas, ngap)


class AuthRecoveryEvidencePreservationTests(unittest.TestCase):
    """Recovered outcomes preserve original and recovery evidence references."""

    def test_26_recovered_retains_cause_21_in_description(self):
        """The recovered deviation description records the decoded cause 21."""
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), recovery_nas_events(), recovery_ngap_events())
            instance = first_instance(analysis)
            recovered = [d for d in instance["deviations"]
                         if d["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertIn("cause 21", recovered[0]["description"])

    def test_27_cause_20_failure_remains_unsuccessful_with_cause(self):
        """A cause-20 failure is preserved as UNSUCCESSFUL with its original cause."""
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=20, cause_name="Mac failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))


class AuthRecoveryBindingConflictSuppressionTests(unittest.TestCase):
    """A conflicting UE-context binding suppresses recovery on the integrated path."""

    def test_28_binding_conflict_suppresses_recovery(self):
        """A cause-21 failure with a later challenge and response stays
        UNSUCCESSFUL when the instance carries a conflicting AMF binding.

        The conflict is produced through the integrated ``analyze`` path (a
        later frame binds the same RAN UE NGAP ID to a different AMF UE NGAP
        ID), not by calling the detection helper directly. The original
        unsuccessful outcome remains observable with its own evidence
        reference, the conflict is surfaced as its own deviation, and the
        instance confidence is lowered. The identical frames with a
        consistent binding recover, proving the conflict is what suppressed
        the classification.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        conflicting_ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport", amf_id=2),
            ngap_record(12, "UplinkNASTransport", amf_id=2),
            ngap_record(13, "DownlinkNASTransport", amf_id=9),
            ngap_record(14, "UplinkNASTransport", amf_id=9),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, conflicting_ngap)
            instance = first_instance(analysis)
            types = deviation_types(instance)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, types)
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, types)
            self.assertIn(MODEL.DEVIATION_CORRELATION_CONFLICT, types)
            self.assertEqual(instance["confidence"], "LOW")
            self.assertTrue(analysis["correlation_conflicts"])
            unsuccessful = [dev for dev in instance["deviations"]
                            if dev["type"] == MODEL.DEVIATION_UNSUCCESSFUL]
            self.assertEqual(len(unsuccessful), 1)
            frames = [ref.get("frame_number") for ref in unsuccessful[0]["evidence_refs"]
                      if ref.get("kind") == "EVENT"]
            self.assertEqual(frames, [12])
        consistent_ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport", amf_id=2),
            ngap_record(12, "UplinkNASTransport", amf_id=2),
            ngap_record(13, "DownlinkNASTransport", amf_id=2),
            ngap_record(14, "UplinkNASTransport", amf_id=2),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, consistent_ngap)
            instance = first_instance(analysis)
            types = deviation_types(instance)
            self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, types)
            self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, types)


class AuthRecoveryAssociationIsolationTests(unittest.TestCase):
    """Recovery never combines authentication events across SCTP associations."""

    @staticmethod
    def _assoc_ngap(frame, message_type, association_id, ran_id=1, amf_id=2):
        record = ngap_record(frame, message_type, ran_id=ran_id, amf_id=amf_id)
        record["sctp"]["association_id"] = association_id
        return record

    def test_29_recovery_does_not_cross_associations(self):
        """The same numeric RAN UE NGAP ID on two associations never merges
        into one synthetic recovery sequence.

        The failure lives on association 0 while the re-challenge request
        and response live on association 7 under the same numeric RAN UE
        NGAP ID. Two instances must result, the failure instance must stay
        UNSUCCESSFUL with its own evidence reference, and no instance may
        report a recovered outcome.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            self._assoc_ngap(10, "InitialUEMessage", 0, amf_id=None),
            self._assoc_ngap(11, "DownlinkNASTransport", 0),
            self._assoc_ngap(12, "UplinkNASTransport", 0),
            self._assoc_ngap(13, "DownlinkNASTransport", 7),
            self._assoc_ngap(14, "UplinkNASTransport", 7),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            self.assertEqual(len(analysis["analyses"]), 2)
            for instance in analysis["analyses"]:
                self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE,
                                 deviation_types(instance))
            failure_instance = next(
                inst for inst in analysis["analyses"]
                if any(dev["type"] == MODEL.DEVIATION_UNSUCCESSFUL
                       for dev in inst["deviations"])
            )
            self.assertEqual(failure_instance["instance_id"],
                             "5gc-reg:reg.pcapng:sctp-assoc-0:r1")
            unsuccessful = [dev for dev in failure_instance["deviations"]
                            if dev["type"] == MODEL.DEVIATION_UNSUCCESSFUL]
            self.assertEqual(len(unsuccessful), 1)
            frames = [ref.get("frame_number") for ref in unsuccessful[0]["evidence_refs"]
                      if ref.get("kind") == "EVENT"]
            self.assertEqual(frames, [12])

    def test_30_independent_association_instances_both_recover(self):
        """Isolation never suppresses legitimate recovery in an unaffected
        instance.

        The same numeric RAN UE NGAP ID on two associations each completes
        its own bounded failure, challenge, and response sequence; both
        instances are independently classified as recovered.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
            nas_record(20, "Registration request"),
            nas_record(21, "Authentication request"),
            nas_record(22, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(23, "Authentication request"),
            nas_record(24, "Authentication response"),
        ]
        ngap = [
            self._assoc_ngap(10, "InitialUEMessage", 0, amf_id=None),
            self._assoc_ngap(11, "DownlinkNASTransport", 0),
            self._assoc_ngap(12, "UplinkNASTransport", 0),
            self._assoc_ngap(13, "DownlinkNASTransport", 0),
            self._assoc_ngap(14, "UplinkNASTransport", 0),
            self._assoc_ngap(20, "InitialUEMessage", 7, amf_id=None),
            self._assoc_ngap(21, "DownlinkNASTransport", 7),
            self._assoc_ngap(22, "UplinkNASTransport", 7),
            self._assoc_ngap(23, "DownlinkNASTransport", 7),
            self._assoc_ngap(24, "UplinkNASTransport", 7),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            self.assertEqual(len(analysis["analyses"]), 2)
            self.assertEqual({inst["instance_id"] for inst in analysis["analyses"]}, {
                "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                "5gc-reg:reg.pcapng:sctp-assoc-7:r1",
            })
            for instance in analysis["analyses"]:
                types = deviation_types(instance)
                self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, types)
                self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, types)


class AuthRecoveryBarrierMatrixTests(unittest.TestCase):
    """Every declared barrier message blocks recovery on both window sides."""

    def _assert_not_recovered(self, nas, ngap):
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            self.assertIn(MODEL.DEVIATION_UNSUCCESSFUL, deviation_types(instance))
            self.assertNotIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, deviation_types(instance))
            return instance

    def _barrier_case(self, side, barrier_message, barrier_protocol,
                      ngap_carrier=None, barrier_cause_code=None, barrier_cause_name=None):
        """Deterministic recovery sequence with one barrier insertion.

        ``side="after-failure"`` places the barrier at frame 13 between the
        Authentication failure (frame 12) and the re-challenge request
        (frame 14). ``side="after-request"`` keeps the request at frame 13
        and places the barrier at frame 14 between the request and the
        response (frame 15). A NAS barrier also needs an NGAP carrier
        record on the same frame so the instance frame join retains it.
        """
        if side == "after-failure":
            request_frame, barrier_frame = 14, 13
        else:
            request_frame, barrier_frame = 13, 14
        response_frame = 15
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(request_frame, "Authentication request"),
            nas_record(response_frame, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(request_frame, "DownlinkNASTransport"),
            ngap_record(response_frame, "UplinkNASTransport"),
        ]
        if barrier_protocol == "NGAP":
            ngap.append(ngap_record(barrier_frame, barrier_message))
        else:
            nas.append(nas_record(barrier_frame, barrier_message,
                                  cause_code=barrier_cause_code, cause_name=barrier_cause_name))
            ngap.append(ngap_record(barrier_frame, ngap_carrier))
        return nas, ngap

    def test_31_ue_context_release_request_after_failure_blocks_recovery(self):
        """UEContextReleaseRequest between failure and request blocks recovery."""
        nas, ngap = self._barrier_case("after-failure", "UEContextReleaseRequest", "NGAP")
        self._assert_not_recovered(nas, ngap)

    def test_32_ue_context_release_complete_after_failure_blocks_recovery(self):
        """UEContextReleaseComplete between failure and request blocks recovery."""
        nas, ngap = self._barrier_case("after-failure", "UEContextReleaseComplete", "NGAP")
        self._assert_not_recovered(nas, ngap)

    def test_33_registration_reject_after_request_blocks_recovery(self):
        """Registration reject between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "Registration reject",
                                       "NAS-5GS", ngap_carrier="DownlinkNASTransport")
        self._assert_not_recovered(nas, ngap)

    def test_34_registration_request_after_request_blocks_recovery(self):
        """A new Registration request between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "Registration request",
                                       "NAS-5GS", ngap_carrier="InitialUEMessage")
        self._assert_not_recovered(nas, ngap)

    def test_35_later_auth_failure_after_request_blocks_recovery(self):
        """A later Authentication failure between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "Authentication failure",
                                       "NAS-5GS", ngap_carrier="UplinkNASTransport",
                                       barrier_cause_code=21, barrier_cause_name="Synch failure")
        self._assert_not_recovered(nas, ngap)

    def test_36_ue_context_release_request_after_request_blocks_recovery(self):
        """UEContextReleaseRequest between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "UEContextReleaseRequest", "NGAP")
        self._assert_not_recovered(nas, ngap)

    def test_37_ue_context_release_command_after_request_blocks_recovery(self):
        """UEContextReleaseCommand between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "UEContextReleaseCommand", "NGAP")
        self._assert_not_recovered(nas, ngap)

    def test_38_ue_context_release_complete_after_request_blocks_recovery(self):
        """UEContextReleaseComplete between request and response blocks recovery."""
        nas, ngap = self._barrier_case("after-request", "UEContextReleaseComplete", "NGAP")
        self._assert_not_recovered(nas, ngap)


class AuthRecoveryRechallengeAmbiguityTests(unittest.TestCase):
    """Ambiguous re-challenge sequences stay bounded and deterministic."""

    def test_39_multiple_auth_requests_select_earliest_deterministically(self):
        """Two Authentication requests after the failure keep recovery
        bounded and deterministic.

        Frame evidence cannot distinguish a retransmission of one challenge
        from an independently initiated second challenge, so no distinction
        is invented: the earliest request after the failure and the first
        response after that request are selected, and the recovered claim
        stays non-candidate supporting evidence for procedure progression
        only.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication request"),
            nas_record(15, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "DownlinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            types = deviation_types(instance)
            self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, types)
            self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, types)
            recovered = [dev for dev in instance["deviations"]
                         if dev["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertEqual(len(recovered), 1)
            frames = sorted(ref.get("frame_number") for ref in recovered[0]["evidence_refs"]
                            if ref.get("kind") == "EVENT")
            self.assertEqual(frames, [12, 13, 15])

    def test_40_duplicate_failure_records_stay_bounded(self):
        """Duplicated Authentication failure input records never widen the
        recovery association.

        Each duplicated record is retained and surfaced as
        duplicate-or-retransmitted evidence; every recovered deviation it
        produces references only the same bounded failure, request, and
        response frames, and no unsupported unsuccessful outcome is
        invented or removed.
        """
        failure = nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure")
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            failure,
            dict(failure),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            types = deviation_types(instance)
            self.assertIn(MODEL.DEVIATION_DUPLICATE, types)
            self.assertIn(MODEL.DEVIATION_RECOVERED_INTERMEDIATE, types)
            self.assertNotIn(MODEL.DEVIATION_UNSUCCESSFUL, types)
            recovered = [dev for dev in instance["deviations"]
                         if dev["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            self.assertTrue(recovered)
            for dev in recovered:
                frames = sorted(ref.get("frame_number") for ref in dev["evidence_refs"]
                                if ref.get("kind") == "EVENT")
                self.assertEqual(frames, [12, 13, 14])

    def test_41_recovered_failure_does_not_reclassify_later_unrecovered_failure(self):
        """A recovered first failure never reclassifies a later unrecovered
        failure in the same instance.

        The first synchronization failure is recovered by its own challenge
        and response; a later failure without any subsequent request stays
        UNSUCCESSFUL with its own evidence reference.
        """
        nas = [
            nas_record(10, "Registration request"),
            nas_record(11, "Authentication request"),
            nas_record(12, "Authentication failure", cause_code=21, cause_name="Synch failure"),
            nas_record(13, "Authentication request"),
            nas_record(14, "Authentication response"),
            nas_record(15, "Authentication failure", cause_code=21, cause_name="Synch failure"),
        ]
        ngap = [
            ngap_record(10, "InitialUEMessage", amf_id=None),
            ngap_record(11, "DownlinkNASTransport"),
            ngap_record(12, "UplinkNASTransport"),
            ngap_record(13, "DownlinkNASTransport"),
            ngap_record(14, "UplinkNASTransport"),
            ngap_record(15, "UplinkNASTransport"),
        ]
        with tempfile.TemporaryDirectory() as d:
            analysis = write_and_load(Path(d), nas, ngap)
            instance = first_instance(analysis)
            recovered = [dev for dev in instance["deviations"]
                         if dev["type"] == MODEL.DEVIATION_RECOVERED_INTERMEDIATE]
            unsuccessful = [dev for dev in instance["deviations"]
                            if dev["type"] == MODEL.DEVIATION_UNSUCCESSFUL]
            self.assertEqual(len(recovered), 1)
            self.assertEqual(len(unsuccessful), 1)
            recovered_frames = sorted(ref.get("frame_number") for ref in recovered[0]["evidence_refs"]
                                      if ref.get("kind") == "EVENT")
            self.assertEqual(recovered_frames, [12, 13, 14])
            unsuccessful_frames = [ref.get("frame_number") for ref in unsuccessful[0]["evidence_refs"]
                                   if ref.get("kind") == "EVENT"]
            self.assertEqual(unsuccessful_frames, [15])


if __name__ == "__main__":
    unittest.main()
