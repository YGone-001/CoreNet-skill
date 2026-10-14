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


if __name__ == "__main__":
    unittest.main()
