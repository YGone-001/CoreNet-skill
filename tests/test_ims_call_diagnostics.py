#!/usr/bin/env python3
"""Deterministic tests for per-call IMS media diagnostic consolidation."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ims_call_diagnostics as diagnostics  # noqa: E402

CAP = "synthetic-call.pcapng"
SHA = "f1" * 32
SSRC_A = f"rtp-ssrc:{CAP}:11111111"
SSRC_B = f"rtp-ssrc:{CAP}:22222222"


def sip_event(frame: int, method: str | None = None, status: int | None = None) -> dict:
    return {
        "source_reference": f"sip-event:{CAP}:{frame}.1",
        "capture_file": CAP,
        "frame_number": frame,
        "message_occurrence": 1,
        "message_type": "REQUEST" if method else "RESPONSE",
        "method": method,
        "status_code": status,
        "frame_time_epoch": f"17000000{frame:02d}.000000",
    }


def rtp_event(
    ref: str,
    frame: int,
    *,
    sequence: int,
    udp: int = 10,
    ssrc: str = SSRC_A,
    timestamp: int = 1000,
    payload_type: int = 104,
    length: int = 100,
) -> dict:
    return {
        "event_reference": ref,
        "capture_file": CAP,
        "frame_number": frame,
        "frame_reference": f"frame:{frame}",
        "protocol": "RTP",
        "udp_stream": udp,
        "ssrc_reference": ssrc,
        "sequence_number": sequence,
        "timestamp": timestamp,
        "payload_type": payload_type,
        "packet_length": length,
        "frame_timestamp": f"17000000{frame:02d}.000000",
        "evidence_status": "OBSERVED",
    }


def rtcp_event(
    frame: int,
    *,
    packet_type: int,
    sender_ssrc: str | None = SSRC_A,
    report_blocks: list[dict] | None = None,
    udp: int = 10,
    component_index: int = 0,
) -> dict:
    return {
        "event_reference": f"rtcp-component:{CAP}:{frame}.1.{component_index}",
        "capture_file": CAP,
        "frame_number": frame,
        "frame_reference": f"frame:{frame}",
        "protocol": "RTCP",
        "component_index": component_index,
        "packet_type": packet_type,
        "sender_ssrc_reference": sender_ssrc,
        "udp_stream": udp,
        "report_blocks": report_blocks or [],
        "frame_timestamp": f"17000000{frame:02d}.000000",
        "evidence_status": "OBSERVED",
    }


def sdp_message(frame: int, *, payload_type: int = 104, clock_rate: int = 16000) -> dict:
    return {
        "source_reference": f"sip-event:{CAP}:{frame}.1",
        "capture_file": CAP,
        "frame_number": frame,
        "message_occurrence": 1,
        "evidence_status": "OBSERVED",
        "media_sections": [
            {
                "index": 0,
                "media_type": "audio",
                "direction": "sendrecv",
                "mid": "0",
                "media_type_supported": True,
                "transport_endpoint": {
                    "endpoint_reference": f"endpoint-hmac-sha256:v1:{frame:064x}"
                },
                "rtpmap": [
                    {
                        "payload_type": payload_type,
                        "clock_rate": clock_rate,
                        "encoding_name": "AMR-WB",
                        "channels": 1,
                    }
                ],
            }
        ],
    }


def attempt(
    frame: int,
    *,
    answer_frames: list[int] | None = None,
    ack_frames: list[int] | None = None,
    branches: list[dict] | None = None,
) -> dict:
    answer_frames = answer_frames or []
    ack_frames = ack_frames or []
    return {
        "attempt_reference": f"ims-session:{CAP}:{frame}.1",
        "initial_invite_transaction_reference": f"sip-transaction:{CAP}:request:{frame}.1",
        "initial_invite_event_reference": f"sip-event:{CAP}:{frame}.1",
        "invite_outcome": "ACCEPTED_2XX_OBSERVED" if answer_frames else "PROVISIONAL_ONLY",
        "first_observed_frame": frame,
        "last_observed_frame": max([frame, *answer_frames, *ack_frames]),
        "stage_evidence": {
            "provisional_response_event_references": [],
            "final_response_event_references": [
                f"sip-event:{CAP}:{item}.1" for item in answer_frames
            ],
            "accepted_2xx_event_references": [
                f"sip-event:{CAP}:{item}.1" for item in answer_frames
            ],
        },
        "ack_evidence": {
            "twoxx_ack_event_references": [
                f"sip-event:{CAP}:{item}.1" for item in ack_frames
            ]
        },
        "cancel_evidence": {"outcome": "NO_CANCEL_OBSERVED"},
        "release_evidence": {"outcome": "NO_BYE_OBSERVED"},
        "branch_count": len(branches or []),
        "branches": branches or [],
    }


def branch(
    reference: str,
    *,
    identity: str = "ESTABLISHED",
    answer_frames: list[int] | None = None,
    ack_frames: list[int] | None = None,
    bye_frames: list[int] | None = None,
) -> dict:
    answer_frames = answer_frames or []
    ack_frames = ack_frames or []
    bye_frames = bye_frames or []
    observations = []
    if bye_frames:
        observations.append(
            {
                "bye_transaction_reference": f"sip-transaction:{CAP}:request:{bye_frames[0]}.1",
                "bye_request_event_references": [
                    f"sip-event:{CAP}:{item}.1" for item in bye_frames
                ],
                "bye_final_response_event_references": [],
                "final_response_status_codes": [],
                "outcome": "BYE_RESPONSE_NOT_OBSERVED",
                "termination_supported": False,
                "missing_evidence": ["BYE_FINAL_RESPONSE_NOT_OBSERVED"],
            }
        )
    return {
        "branch_reference": reference,
        "dialog_reference": reference if reference.startswith("sip-dialog:") else None,
        "fork_branch_reference": None,
        "identity_status": identity,
        "dialog_state": "CONFIRMED" if identity == "ESTABLISHED" else "UNKNOWN",
        "observed_lifecycle_status": "CONFIRMATION_OBSERVED",
        "response_event_references": [
            f"sip-event:{CAP}:{item}.1" for item in answer_frames
        ],
        "response_status_codes": [200 for _ in answer_frames],
        "outcome": "ACCEPTED_2XX",
        "ack_event_references": [f"sip-event:{CAP}:{item}.1" for item in ack_frames],
        "ack_status": "OBSERVED_FOR_ALL_ACCEPTED_BRANCHES",
        "release": {
            "outcome": "BYE_REQUEST_OBSERVED" if bye_frames else "NO_BYE_OBSERVED",
            "bye_transaction_count": len(observations),
            "observations": observations,
            "termination_supported_dialog_references": [],
        },
        "missing_evidence": [],
        "conflict_findings": [],
    }


def exchange(
    attempt_frame: int,
    *,
    branch_reference: str | None,
    offer_frame: int,
    answer_frame: int | None,
) -> dict:
    return {
        "exchange_reference": f"ims-media-signaling:{CAP}:{answer_frame or offer_frame}.1",
        "attempt_reference": f"ims-session:{CAP}:{attempt_frame}.1",
        "branch_reference": branch_reference,
        "dialog_reference": branch_reference,
        "branch_identity_status": "ESTABLISHED" if branch_reference else "INSUFFICIENT_EVIDENCE",
        "offer_sdp_reference": f"sip-event:{CAP}:{offer_frame}.1",
        "answer_sdp_reference": (
            f"sip-event:{CAP}:{answer_frame}.1" if answer_frame is not None else None
        ),
        "offer_event_reference": f"sip-event:{CAP}:{offer_frame}.1",
        "answer_event_reference": (
            f"sip-event:{CAP}:{answer_frame}.1" if answer_frame is not None else None
        ),
        "association_status": "ESTABLISHED" if answer_frame is not None else "INSUFFICIENT_EVIDENCE",
        "exchange_type": "INITIAL_INVITE_OFFER_ANSWER",
        "initial_invite_transaction_reference": f"sip-transaction:{CAP}:request:{attempt_frame}.1",
        "initial_sdp_state": "OBSERVED_VALID",
        "missing_evidence": [],
        "conflict_findings": [],
    }


def correlation(
    reference: str,
    *,
    offer_frames: list[int],
    answer_frames: list[int] | None = None,
    udp_streams: list[int] | None = None,
    complete: bool = True,
) -> dict:
    answer_frames = answer_frames or []
    sections = [
        {"message_reference": f"sip-event:{CAP}:{frame}.1", "media_index": 0}
        for frame in [*offer_frames, *answer_frames]
    ]
    return {
        "correlation_reference": reference,
        "association_status": "MATCHED_ENDPOINT",
        "correlation_strength": "STRONG",
        "correlation_type": "SINGLE_MEDIA",
        "sdp_media_sections": sections,
        "sdp_message_references": [item["message_reference"] for item in sections],
        "rtp_udp_stream_references": [
            f"rtp-udp-stream:{CAP}:{udp}" for udp in (udp_streams or [10])
        ],
        "rtp_event_references": [],
        "missing_evidence": [] if complete else ["RTP_ENDPOINT_EVIDENCE_INCOMPLETE"],
        "conflict_findings": [],
        "endpoint_references": [],
        "match_directions": ["RTP_SOURCE_ENDPOINT_MATCH"],
        "bundle_references": [],
    }


def stream(
    udp: int = 10,
    ssrc: str = SSRC_A,
    *,
    payload_types: list[int] | None = None,
) -> dict:
    suffix = ssrc.rsplit(":", 1)[-1]
    return {
        "source_stream_reference": f"rtp-source-stream:{CAP}:{udp}:{suffix}",
        "udp_stream": udp,
        "ssrc_reference": ssrc,
        "capture_file": CAP,
        "observed_payload_types": payload_types or [104],
        "rtp_packet_count": 0,
        "sequence_eligible_packet_count": 0,
        "incomplete_packet_count": 0,
        "invalid_or_excluded_packet_count": 0,
        "event_references": [],
        "sequence_validation_status": "VALIDATED",
        "sequence_wrap_count": 0,
        "duplicate_sequence_observation_count": 0,
        "out_of_order_packet_count": 0,
        "observed_sequence_gap_count": 0,
        "unobserved_sequence_number_slot_count": 0,
        "restart_pattern_count": 0,
        "endpoint_evidence_status": "ESTABLISHED",
        "source_endpoint_references": [],
        "destination_endpoint_references": [],
        "missing_evidence": [],
        "conflict_findings": [],
    }


def run(
    *,
    attempts: list[dict],
    exchanges: list[dict],
    sdp_messages: list[dict],
    correlations: list[dict],
    rtp_events: list[dict],
    rtcp_events: list[dict] | None = None,
    streams: list[dict] | None = None,
    views: dict[int, dict] | None = None,
) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / "sip-events.jsonl").write_text(
            "\n".join(
                json.dumps(item, sort_keys=True)
                for item in [
                    sip_event(1, method="INVITE"),
                    sip_event(2, status=200),
                    sip_event(3, method="ACK"),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        (root / "ims-session.json").write_text(
            json.dumps({"session_attempts": attempts}), encoding="utf-8"
        )
        (root / "media-signaling.json").write_text(
            json.dumps({"exchanges": exchanges}), encoding="utf-8"
        )
        (root / "sdp.json").write_text(
            json.dumps({"messages": sdp_messages}), encoding="utf-8"
        )
        (root / "correlation.json").write_text(
            json.dumps({"correlations": correlations}), encoding="utf-8"
        )
        (root / "rtp-rtcp.json").write_text(
            json.dumps({"events": [*rtp_events, *(rtcp_events or [])]}),
            encoding="utf-8",
        )
        (root / "rtp-stream.json").write_text(
            json.dumps({"source_streams": streams or []}), encoding="utf-8"
        )
        return diagnostics.build_diagnostics(
            capture=root / CAP,
            capture_sha256=SHA,
            sip_events_path=root / "sip-events.jsonl",
            ims_session_path=root / "ims-session.json",
            media_signaling_path=root / "media-signaling.json",
            sdp_path=root / "sdp.json",
            correlation_path=root / "correlation.json",
            rtp_rtcp_path=root / "rtp-rtcp.json",
            rtp_stream_path=root / "rtp-stream.json",
            frame_views=views or {},
        )


def simple_chain(
    *,
    attempt_frame: int = 1,
    offer_frame: int = 1,
    answer_frame: int = 2,
    ack_frame: int = 3,
    rtp_frames: list[int] | None = None,
    udp: int = 10,
    correlation_ref: str = "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
) -> dict:
    rtp_frames = rtp_frames or [4, 5, 6]
    return run(
        attempts=[
            attempt(
                attempt_frame,
                answer_frames=[answer_frame],
                ack_frames=[ack_frame],
                branches=[
                    branch(
                        f"sip-dialog:{CAP}:{answer_frame}.1",
                        answer_frames=[answer_frame],
                        ack_frames=[ack_frame],
                    )
                ],
            )
        ],
        exchanges=[
            exchange(
                attempt_frame,
                branch_reference=f"sip-dialog:{CAP}:{answer_frame}.1",
                offer_frame=offer_frame,
                answer_frame=answer_frame,
            )
        ],
        sdp_messages=[sdp_message(offer_frame), sdp_message(answer_frame)],
        correlations=[
            correlation(
                correlation_ref,
                offer_frames=[offer_frame],
                answer_frames=[answer_frame],
                udp_streams=[udp],
            )
        ],
        rtp_events=[
            rtp_event(f"rtp-packet:{CAP}:{frame}.1", frame, sequence=frame, udp=udp)
            for frame in rtp_frames
        ],
        streams=[stream(udp=udp)],
    )


class PerCallIsolationTests(unittest.TestCase):
    def test_exact_single_call_chain_is_supported(self) -> None:
        document = simple_chain()
        self.assertEqual(document["attempts"][0]["evidence_status"], "EVIDENCE_CHAIN_SUPPORTED")
        self.assertEqual(document["branches"][0]["evidence_status"], "EVIDENCE_CHAIN_SUPPORTED")
        self.assertTrue(document["call_evidence_summary"]["all_attempts_supported"])

    def test_cross_attempt_sdp_answer_is_not_supported(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])]),
                attempt(20, answer_frames=[21], branches=[branch(f"sip-dialog:{CAP}:21.1", answer_frames=[21])]),
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(20, branch_reference=f"sip-dialog:{CAP}:21.1", offer_frame=20, answer_frame=21),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(20), sdp_message(21)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1, 20],
                    answer_frames=[2, 21],
                )
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        self.assertEqual(document["call_evidence_summary"]["supported_attempt_count"], 0)
        self.assertEqual(
            document["call_evidence_summary"]["ambiguous_attempt_count"], 2
        )
        self.assertIn(
            "CAPTURE_WIDE_OR_CROSS_ATTEMPT_OWNERSHIP_REJECTED",
            document["attempts"][0]["conflict_findings"],
        )

    def test_shared_rtp_stream_cannot_support_two_calls(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])]),
                attempt(20, answer_frames=[21], branches=[branch(f"sip-dialog:{CAP}:21.1", answer_frames=[21])]),
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(20, branch_reference=f"sip-dialog:{CAP}:21.1", offer_frame=20, answer_frame=21),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(20), sdp_message(21)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1],
                    answer_frames=[2],
                ),
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:20.1.0",
                    offer_frames=[20],
                    answer_frames=[21],
                ),
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        self.assertEqual(document["call_evidence_summary"]["supported_attempt_count"], 0)
        self.assertEqual(document["call_evidence_summary"]["ambiguous_attempt_count"], 2)

    def test_branch_isolation_keeps_branch_evidence_independent(self) -> None:
        document = run(
            attempts=[
                attempt(
                    1,
                    answer_frames=[2, 12],
                    ack_frames=[3],
                    branches=[
                        branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2], ack_frames=[3]),
                        branch(f"sip-dialog:{CAP}:12.1", answer_frames=[12]),
                    ],
                )
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(1, branch_reference=f"sip-dialog:{CAP}:12.1", offer_frame=1, answer_frame=12),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(12)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1],
                    answer_frames=[2],
                    udp_streams=[10],
                )
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream(udp=10)],
        )
        statuses = {item["branch_reference"]: item["evidence_status"] for item in document["branches"]}
        self.assertEqual(statuses[f"sip-dialog:{CAP}:2.1"], "EVIDENCE_CHAIN_SUPPORTED")
        self.assertEqual(statuses[f"sip-dialog:{CAP}:12.1"], "PARTIAL_EVIDENCE")

    def test_reordering_attempts_does_not_change_ownership(self) -> None:
        attempts = [
            attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])]),
            attempt(20, answer_frames=[21], branches=[branch(f"sip-dialog:{CAP}:21.1", answer_frames=[21])]),
        ]
        exchanges = [
            exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
            exchange(20, branch_reference=f"sip-dialog:{CAP}:21.1", offer_frame=20, answer_frame=21),
        ]
        sdp = [sdp_message(1), sdp_message(2), sdp_message(20), sdp_message(21)]
        corr = [
            correlation(
                "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                offer_frames=[1],
                answer_frames=[2],
            )
        ]
        first = run(
            attempts=attempts,
            exchanges=exchanges,
            sdp_messages=sdp,
            correlations=corr,
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        second = run(
            attempts=list(reversed(attempts)),
            exchanges=list(reversed(exchanges)),
            sdp_messages=list(reversed(sdp)),
            correlations=corr,
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        first_status = {item["attempt_reference"]: item["evidence_status"] for item in first["attempts"]}
        second_status = {item["attempt_reference"]: item["evidence_status"] for item in second["attempts"]}
        self.assertEqual(first_status, second_status)


class TemporalTests(unittest.TestCase):
    def test_rtp_before_invite_2xx(self) -> None:
        document = diagnostics._temporal(
            [1, 2], {"invite": 1, "provisional": [], "final_2xx": [10], "ack": [], "bye": [], "bye_response": [], "first_sip_frame": 1, "last_sip_frame": 10},
            ownership_ambiguous=False,
            missing_identity=False,
        )
        self.assertEqual(document["temporal_association_status"], "RTP_OBSERVED_BEFORE_INVITE_2XX")

    def test_rtp_within_observed_interval(self) -> None:
        document = diagnostics._temporal(
            [6, 7, 8], {"invite": 1, "provisional": [], "final_2xx": [5], "ack": [6], "bye": [10], "bye_response": [], "first_sip_frame": 1, "last_sip_frame": 10},
            ownership_ambiguous=False,
            missing_identity=False,
        )
        self.assertEqual(document["temporal_association_status"], "RTP_WITHIN_OBSERVED_SIGNALING_INTERVAL")
        self.assertIn("RTP_OBSERVED_AFTER_INVITE_2XX", document["boundary_flags"])
        self.assertIn("RTP_OBSERVED_BEFORE_BYE", document["boundary_flags"])

    def test_rtp_after_bye_is_not_automatically_an_error(self) -> None:
        document = diagnostics._temporal(
            [11, 12], {"invite": 1, "provisional": [], "final_2xx": [5], "ack": [6], "bye": [10], "bye_response": [], "first_sip_frame": 1, "last_sip_frame": 10},
            ownership_ambiguous=False,
            missing_identity=False,
        )
        self.assertEqual(document["temporal_association_status"], "RTP_OBSERVED_AFTER_BYE")
        self.assertIn("RTP_OBSERVED_AFTER_BYE", document["boundary_flags"])

    def test_ambiguous_ownership_forces_ambiguous_temporal(self) -> None:
        document = diagnostics._temporal(
            [6, 7], {"invite": 1, "provisional": [], "final_2xx": [5], "ack": [], "bye": [], "bye_response": [], "first_sip_frame": 1, "last_sip_frame": 5},
            ownership_ambiguous=True,
            missing_identity=False,
        )
        self.assertEqual(document["temporal_association_status"], "TEMPORAL_ASSOCIATION_AMBIGUOUS")

    def test_missing_2xx_is_insufficient(self) -> None:
        document = diagnostics._temporal(
            [6], {"invite": 1, "provisional": [], "final_2xx": [], "ack": [], "bye": [], "bye_response": [], "first_sip_frame": 1, "last_sip_frame": 1},
            ownership_ambiguous=False,
            missing_identity=False,
        )
        self.assertEqual(
            document["temporal_association_status"],
            "TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE",
        )


class DuplicateObservationTests(unittest.TestCase):
    def _document(self, views: dict[int, dict]) -> dict:
        events = [
            rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1),
            rtp_event(f"rtp-packet:{CAP}:2.1", 2, sequence=1),
            rtp_event(f"rtp-packet:{CAP}:3.1", 3, sequence=2),
            rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=2),
            rtp_event(f"rtp-packet:{CAP}:5.1", 5, sequence=3, timestamp=3000),
            rtp_event(f"rtp-packet:{CAP}:6.1", 6, sequence=3, timestamp=4000),
        ]
        return diagnostics.duplicate_investigation(
            CAP, events, {"source_streams": [{"duplicate_sequence_observation_count": 3}]}, views
        )

    def test_multi_vantage_duplicate_packet_and_sequence_only_classes(self) -> None:
        views = {
            1: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "1", "gtp_present": True},
            2: {"interface_id": "1", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "0", "gtp_present": True},
            3: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            4: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            5: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            6: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
        }
        document = self._document(views)
        self.assertEqual(document["multi_vantage_event_count"], 1)
        self.assertEqual(document["duplicate_packet_event_count"], 1)
        self.assertEqual(document["sequence_only_duplicate_event_count"], 1)
        self.assertEqual(document["retransmission_not_established_count"], 1)
        self.assertEqual(document["rtp_stream_reported_duplicate_sequence_observation_count"], 3)

    def test_sequence_equality_alone_is_unresolved(self) -> None:
        views = {
            1: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            2: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
        }
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1, timestamp=1000),
                rtp_event(f"rtp-packet:{CAP}:2.1", 2, sequence=1, timestamp=2000),
            ],
            None,
            views,
        )
        self.assertEqual(document["classification_counts"]["DUPLICATE_CAUSE_UNRESOLVED"], 1)
        self.assertEqual(document["classification_counts"]["MULTI_VANTAGE_OBSERVATION_SUPPORTED"], 0)


class RtcpAssociationTests(unittest.TestCase):
    def test_established_sr_report_block_and_jitter_ms(self) -> None:
        streams = [
            stream(udp=10, ssrc=SSRC_A),
            stream(udp=11, ssrc=SSRC_B, payload_types=[104]),
        ]
        event = rtcp_event(
            9,
            packet_type=200,
            sender_ssrc=SSRC_A,
            report_blocks=[
                {
                    "reported_ssrc": 0x22222222,
                    "fraction_lost": 1,
                    "cumulative_packets_lost": 2,
                    "extended_highest_sequence": 100,
                    "interarrival_jitter": 160,
                    "last_sr_timestamp": 0,
                    "delay_since_last_sr": 0,
                }
            ],
        )
        document = diagnostics._rtcp_association(
            CAP,
            [event],
            streams,
            [sdp_message(1, payload_type=104, clock_rate=16000)],
            stream_ownership={},
        )
        self.assertGreaterEqual(
            document["status_counts"]["RTCP_STREAM_ASSOCIATION_ESTABLISHED"], 2
        )
        report = document["receiver_reported_quality"][0]
        self.assertEqual(report["measurement_origin"], "RECEIVER_REPORTED")
        self.assertEqual(report["jitter_ms"], 10.0)
        self.assertEqual(report["jitter_ms_status"], "DERIVED_FROM_UNIQUE_SDP_CLOCK_RATE")

    def test_ambiguous_reportee_source_stream_has_no_jitter_ms(self) -> None:
        streams = [
            stream(udp=11, ssrc=SSRC_B),
            stream(udp=12, ssrc=SSRC_B),
        ]
        event = rtcp_event(
            9,
            packet_type=201,
            sender_ssrc=SSRC_A,
            report_blocks=[
                {
                    "reported_ssrc": 0x22222222,
                    "fraction_lost": 0,
                    "cumulative_packets_lost": 0,
                    "extended_highest_sequence": 10,
                    "interarrival_jitter": 160,
                    "last_sr_timestamp": 0,
                    "delay_since_last_sr": 0,
                }
            ],
            udp=10,
        )
        document = diagnostics._rtcp_association(
            CAP,
            [event],
            streams,
            [sdp_message(1, payload_type=104, clock_rate=16000)],
            stream_ownership={},
        )
        self.assertEqual(
            document["status_counts"]["RTCP_STREAM_ASSOCIATION_AMBIGUOUS"], 1
        )
        report = document["receiver_reported_quality"][0]
        self.assertIsNone(report["jitter_ms"])
        self.assertEqual(report["jitter_ms_status"], "AMBIGUOUS_SOURCE_ASSOCIATION")

    def test_unbound_sdes_is_unsupported(self) -> None:
        document = diagnostics._rtcp_association(
            CAP, [rtcp_event(9, packet_type=202, sender_ssrc=None)], [], [], stream_ownership={}
        )
        self.assertEqual(
            document["status_counts"]["RTCP_STREAM_ASSOCIATION_UNSUPPORTED"], 1
        )
        self.assertEqual(document["unbound_component_count"], 1)


class DiagnosticIntegrityTests(unittest.TestCase):
    def test_last_evidence_is_per_attempt_not_global(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])]),
                attempt(100, answer_frames=[101], branches=[branch(f"sip-dialog:{CAP}:101.1", answer_frames=[101])]),
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(100, branch_reference=f"sip-dialog:{CAP}:101.1", offer_frame=100, answer_frame=101),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(100), sdp_message(101)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1],
                    answer_frames=[2],
                ),
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:100.1.0",
                    offer_frames=[100],
                    answer_frames=[101],
                    udp_streams=[20],
                ),
            ],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1),
                rtp_event(f"rtp-packet:{CAP}:104.1", 104, sequence=1, udp=20),
            ],
            streams=[stream(udp=10), stream(udp=20)],
        )
        first = next(item for item in document["attempts"] if item["attempt_reference"].endswith(":1.1"))
        last = first["diagnostic"]["last_supported_evidence"]
        self.assertLessEqual(last["frame_number"], 101)

    def test_removing_rtcp_does_not_erase_rtp_evidence(self) -> None:
        base = simple_chain()
        with_rtcp = run(
            attempts=base["attempts"] and [attempt(1, answer_frames=[2], ack_frames=[3], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2], ack_frames=[3])])],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            rtcp_events=[rtcp_event(9, packet_type=200)],
            streams=[stream()],
        )
        without = run(
            attempts=[attempt(1, answer_frames=[2], ack_frames=[3], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2], ack_frames=[3])])],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        self.assertEqual(with_rtcp["attempts"][0]["evidence_status"], without["attempts"][0]["evidence_status"])

    def test_removing_answer_does_not_fabricate_success(self) -> None:
        document = run(
            attempts=[attempt(1, branches=[branch(f"sip-event:{CAP}:1.1")])],
            exchanges=[exchange(1, branch_reference=None, offer_frame=1, answer_frame=None)],
            sdp_messages=[sdp_message(1)],
            correlations=[],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        self.assertNotEqual(document["attempts"][0]["evidence_status"], "EVIDENCE_CHAIN_SUPPORTED")
        self.assertIn("SDP_ANSWER_NOT_OBSERVED", document["attempts"][0]["missing_evidence"])

    def test_unrelated_rtp_cannot_upgrade_incomplete_call(self) -> None:
        document = run(
            attempts=[
                attempt(1, branches=[branch(f"sip-event:{CAP}:1.1")]),
                attempt(20, answer_frames=[21], branches=[branch(f"sip-dialog:{CAP}:21.1", answer_frames=[21])]),
            ],
            exchanges=[
                exchange(1, branch_reference=None, offer_frame=1, answer_frame=None),
                exchange(20, branch_reference=f"sip-dialog:{CAP}:21.1", offer_frame=20, answer_frame=21),
            ],
            sdp_messages=[sdp_message(1), sdp_message(20), sdp_message(21)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:20.1.0",
                    offer_frames=[20],
                    answer_frames=[21],
                    udp_streams=[20],
                )
            ],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:22.1", 22, sequence=1, udp=20),
                rtp_event(f"rtp-packet:{CAP}:23.1", 23, sequence=2, udp=20),
            ],
            streams=[stream(udp=20)],
        )
        statuses = {item["attempt_reference"]: item["evidence_status"] for item in document["attempts"]}
        self.assertNotEqual(statuses[f"ims-session:{CAP}:1.1"], "EVIDENCE_CHAIN_SUPPORTED")
        self.assertEqual(statuses[f"ims-session:{CAP}:20.1"], "EVIDENCE_CHAIN_SUPPORTED")

    def test_duplicate_observation_does_not_create_a_second_call(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])])
            ],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2])],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1),
                rtp_event(f"rtp-packet:{CAP}:5.1", 5, sequence=1),
            ],
            streams=[stream()],
            views={
                4: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
                5: {"interface_id": "1", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "1", "gtp_present": True},
            },
        )
        self.assertEqual(document["attempt_count"], 1)
        self.assertEqual(
            document["duplicate_observation_investigation"]["multi_vantage_event_count"], 1
        )

    def test_privacy_no_raw_endpoint_payload_or_key(self) -> None:
        document = simple_chain()
        text = json.dumps(document)
        for token in (
            "source_address",
            "destination_address",
            "source_port",
            "destination_port",
            "rtp_payload",
            "sdp_body",
            "hmac_key",
            "endpoint_key",
        ):
            self.assertNotIn(token, text)
        self.assertNotIn('"ssrc"', text)

    def test_deterministic_replay(self) -> None:
        first = simple_chain()
        second = simple_chain()
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))


if __name__ == "__main__":
    unittest.main()