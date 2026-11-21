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


def sip_event(
    frame: int,
    method: str | None = None,
    status: int | None = None,
    *,
    call_id: str = "call-a",
    from_tag: str = "from-a",
    to_tag: str | None = None,
    cseq: int = 1,
    vias: list[str] | None = None,
    body_present: bool = False,
    content_type: str | None = None,
    authorization_count: int = 0,
    proxy_authorization_count: int = 0,
    integrity_findings: list[str] | None = None,
) -> dict:
    return {
        "source_reference": f"sip-event:{CAP}:{frame}.1",
        "capture_file": CAP,
        "frame_number": frame,
        "message_occurrence": 1,
        "message_type": "REQUEST" if method else "RESPONSE",
        "method": method,
        "status_code": status,
        "frame_time_epoch": f"17000000{frame:02d}.000000",
        "headers": {
            "cseq": {
                "present": True,
                "sequence": cseq,
                "method": "INVITE",
                "count": 1,
            },
            "content_type": content_type,
            "authorization": {"count": authorization_count},
            "proxy_authorization": {"count": proxy_authorization_count},
        },
        "call_id_reference": call_id,
        "from_tag_reference": from_tag,
        "to_tag_reference": to_tag,
        "via_branch_references": vias or [],
        "identity_reference_status": "ESTABLISHED",
        "identity_reference_scope": "CAPTURE_SHA256_SCOPED_HMAC_SHA256",
        "integrity_findings": integrity_findings or [],
        "body_present": body_present,
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
    fingerprint: str | None = None,
    fingerprint_status: str = "ESTABLISHED",
) -> dict:
    if fingerprint is None:
        fingerprint = (
            f"rtp-packet-fingerprint-v1:{sequence * 1_000_003 + timestamp:064x}"
        )
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
        "rtp_packet_byte_count": length - 8,
        "rtp_packet_fingerprint": fingerprint,
        "rtp_packet_fingerprint_status": fingerprint_status,
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
    provisional_frames: list[int] | None = None,
    cancel_evidence: dict | None = None,
) -> dict:
    answer_frames = answer_frames or []
    ack_frames = ack_frames or []
    provisional_frames = provisional_frames or []
    return {
        "attempt_reference": f"ims-session:{CAP}:{frame}.1",
        "initial_invite_transaction_reference": f"sip-transaction:{CAP}:request:{frame}.1",
        "initial_invite_event_reference": f"sip-event:{CAP}:{frame}.1",
        "invite_outcome": "ACCEPTED_2XX_OBSERVED" if answer_frames else "PROVISIONAL_ONLY",
        "first_observed_frame": frame,
        "last_observed_frame": max([frame, *answer_frames, *ack_frames]),
        "stage_evidence": {
            "provisional_response_event_references": [
                f"sip-event:{CAP}:{item}.1" for item in provisional_frames
            ],
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
        "cancel_evidence": cancel_evidence
        or {
            "outcome": "NO_CANCEL_OBSERVED",
            "association_status": "NOT_OBSERVED",
            "cancel_transaction_references": [],
            "cancel_request_event_references": [],
            "cancel_final_response_event_references": [],
            "cancel_final_response_status_codes": [],
            "invite_final_response_status": None,
            "response_sequence_observed": False,
            "missing_evidence": [],
            "conflict_findings": [],
        },
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
    response_status_codes: list[int] | None = None,
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
        "response_status_codes": (
            response_status_codes
            if response_status_codes is not None
            else [200 for _ in answer_frames]
        ),
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
    association_status: str | None = None,
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
        "association_status": (
            association_status
            if association_status is not None
            else "ESTABLISHED"
            if answer_frame is not None
            else "INSUFFICIENT_EVIDENCE"
        ),
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
    response_status_by_frame: dict[int, int] | None = None,
    sip_overrides: dict[int, dict] | None = None,
) -> dict:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        events: dict[int, dict] = {
            1: sip_event(1, method="INVITE", call_id="call-1", from_tag="from-1"),
            2: sip_event(2, status=200, call_id="call-1", from_tag="from-1", to_tag="to-1"),
            3: sip_event(3, method="ACK", call_id="call-1", from_tag="from-1", to_tag="to-1"),
        }
        attempt_frames: dict[str, int] = {}
        for item in attempts:
            reference = item.get("attempt_reference") or ""
            parts = reference.rsplit(":", 1)[-1].split(".")
            try:
                attempt_frame = int(parts[0])
            except (IndexError, ValueError):
                continue
            attempt_frames[reference] = attempt_frame
            identity = {
                "call_id": f"call-{attempt_frame}",
                "from_tag": f"from-{attempt_frame}",
                "to_tag": f"to-{attempt_frame}",
            }
            events.setdefault(
                attempt_frame,
                sip_event(attempt_frame, method="INVITE", **identity),
            )
            for frame in (item.get("stage_evidence") or {}).get(
                "final_response_event_references"
            ) or []:
                match = frame.rsplit(":", 1)[-1].split(".")
                events.setdefault(
                    int(match[0]),
                    sip_event(
                        int(match[0]),
                        status=(response_status_by_frame or {}).get(
                            int(match[0]), 200
                        ),
                        **identity,
                    ),
                )
            for frame in (item.get("ack_evidence") or {}).get(
                "twoxx_ack_event_references"
            ) or []:
                match = frame.rsplit(":", 1)[-1].split(".")
                events.setdefault(
                    int(match[0]),
                    sip_event(int(match[0]), method="ACK", **identity),
                )
        for item in exchanges:
            attempt_frame = attempt_frames.get(item.get("attempt_reference") or "")
            if attempt_frame is None:
                continue
            identity = {
                "call_id": f"call-{attempt_frame}",
                "from_tag": f"from-{attempt_frame}",
                "to_tag": f"to-{attempt_frame}",
            }
            for key, method, status in (
                ("offer_sdp_reference", "INVITE", None),
                ("answer_sdp_reference", None, 200),
            ):
                reference = item.get(key)
                if not isinstance(reference, str):
                    continue
                frame = int(reference.rsplit(":", 1)[-1].split(".")[0])
                events.setdefault(
                    frame,
                    sip_event(
                        frame,
                        method=method,
                        status=(response_status_by_frame or {}).get(frame, status),
                        **identity,
                    ),
                )
        for item in sdp_messages:
            frame = item.get("frame_number")
            if isinstance(frame, int):
                events.setdefault(
                    frame,
                    sip_event(frame, method="INVITE", call_id=f"call-{frame}", from_tag=f"from-{frame}"),
                )
        for frame, status in (response_status_by_frame or {}).items():
            current = events.get(frame)
            if isinstance(current, dict) and current.get("message_type") == "RESPONSE":
                updated = dict(current)
                updated["status_code"] = status
                events[frame] = updated
        for frame, override in (sip_overrides or {}).items():
            events[frame] = override
        (root / "sip-events.jsonl").write_text(
            "\n".join(
                json.dumps(item, sort_keys=True)
                for _, item in sorted(events.items())
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


class LogicalCallGroupingTests(unittest.TestCase):
    def _group(self, events: list[dict], attempts: list[dict]) -> dict:
        return diagnostics.logical_call_grouping(
            CAP, {event["source_reference"]: event for event in events}, attempts
        )

    def test_nested_via_stack_groups_multi_hop_attempts(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", vias=["b1"]),
                sip_event(2, "INVITE", vias=["b2", "b1"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 1)
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"], "MULTI_HOP_PROVEN"
        )
        self.assertEqual(
            len(document["logical_calls"][0]["member_attempt_references"]), 2
        )

    def test_independent_call_id_is_not_merged(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", call_id="call-a", vias=["b1"]),
                sip_event(2, "INVITE", call_id="call-b", vias=["b2"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 2)

    def test_different_to_tag_keeps_dialogs_separate(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", to_tag="to-a", vias=["b1"]),
                sip_event(2, "INVITE", to_tag="to-b", vias=["b2"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 2)

    def test_unproven_via_relation_is_ambiguous(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", vias=["b1"]),
                sip_event(2, "INVITE", vias=["b2"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 1)
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"], "AMBIGUOUS_MULTI_HOP"
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
            1: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "1", "inner_udp_stream": "0", "gtp_present": True},
            2: {"interface_id": "1", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "0", "inner_udp_stream": "0", "gtp_present": True},
            3: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            4: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            5: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            6: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
        }
        document = self._document(views)
        self.assertEqual(document["multi_vantage_supported_event_count"], 1)
        self.assertEqual(document["byte_identical_duplicate_event_count"], 1)
        self.assertEqual(document["duplicate_sequence_event_count"], 1)
        self.assertEqual(document["potential_retransmission_event_count"], 0)
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
        self.assertEqual(document["classification_counts"]["DUPLICATE_SEQUENCE_OBSERVED"], 1)
        self.assertEqual(document["classification_counts"]["MULTI_VANTAGE_SUPPORTED"], 0)
        self.assertEqual(document["packet_identity_unresolved_event_count"], 0)
        self.assertEqual(document["duplicate_cause_unresolved_event_count"], 1)

    def test_same_header_with_different_bytes_is_only_header_signature(self) -> None:
        views = {
            1: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            2: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
        }
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(
                    f"rtp-packet:{CAP}:1.1", 1, sequence=1,
                    fingerprint="rtp-packet-fingerprint-v1:" + "a" * 64,
                ),
                rtp_event(
                    f"rtp-packet:{CAP}:2.1", 2, sequence=1,
                    fingerprint="rtp-packet-fingerprint-v1:" + "b" * 64,
                ),
            ],
            None,
            views,
        )
        self.assertEqual(
            document["classification_counts"]["RTP_HEADER_SIGNATURE_MATCH"], 1
        )
        self.assertEqual(document["byte_identical_duplicate_event_count"], 0)

    def test_unavailable_fingerprint_is_unresolved(self) -> None:
        views = {
            1: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
            2: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "gtp_present": False},
        }
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(
                    f"rtp-packet:{CAP}:1.1", 1, sequence=1,
                    fingerprint=None, fingerprint_status="UNAVAILABLE_NO_KEY",
                ),
                rtp_event(
                    f"rtp-packet:{CAP}:2.1", 2, sequence=1,
                    fingerprint=None, fingerprint_status="UNAVAILABLE_NO_KEY",
                ),
            ],
            None,
            views,
        )
        self.assertEqual(
            document["classification_counts"]["PACKET_IDENTITY_UNRESOLVED"], 1
        )
        self.assertEqual(document["byte_identical_duplicate_event_count"], 0)

    def test_observation_count_conservation(self) -> None:
        views = {
            frame: {"interface_id": str(frame % 2), "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": str(frame % 2), "inner_udp_stream": "0", "gtp_present": False}
            for frame in range(1, 7)
        }
        document = self._document(views)
        classified = (
            document["distinct_byte_identity_count"]
            + document["multi_vantage_supported_event_count"]
            + document["multi_vantage_consistent_byte_event_count"]
            + document["byte_identical_duplicate_event_count"]
            + document["fingerprint_unavailable_observation_count"]
        )
        self.assertEqual(classified, document["raw_rtp_observation_count"])
        self.assertEqual(document["duplicate_sequence_event_count"], 1)


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
                4: {"interface_id": "0", "encap_type": "25", "protocols": "sll:ip:udp:rtp", "outer_udp_stream": "2", "inner_udp_stream": "2", "gtp_present": False},
                5: {"interface_id": "1", "encap_type": "25", "protocols": "sll:ip:udp:gtp:ip:udp:rtp", "outer_udp_stream": "1", "inner_udp_stream": "2", "gtp_present": True},
            },
        )
        self.assertEqual(document["attempt_count"], 1)
        self.assertEqual(
            document["duplicate_observation_investigation"]["multi_vantage_supported_event_count"], 1
        )

    def test_ambiguous_attempt_last_evidence_is_not_candidate_rtp(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])])],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[
                correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2]),
                correlation("sdp-rtp-transport:synthetic-call.pcapng:20.1.0", offer_frames=[20], answer_frames=[21]),
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:200.1", 200, sequence=1)],
            streams=[stream()],
        )
        attempt_record = document["attempts"][0]
        self.assertEqual(attempt_record["evidence_status"], "AMBIGUOUS_OWNERSHIP")
        last = attempt_record["diagnostic"]["last_supported_evidence"]
        self.assertNotEqual(last.get("stage"), "RTP")

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


class LogicalCallIdentityIntegrityTests(unittest.TestCase):
    def _group(
        self,
        events: list[dict],
        attempts: list[dict],
        branches: dict[str, list[dict]] | None = None,
    ) -> dict:
        return diagnostics.logical_call_grouping(
            CAP,
            {event["source_reference"]: event for event in events},
            attempts,
            branches,
        )

    def test_distinct_from_tags_are_not_merged(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", from_tag="from-a", vias=["a"]),
                sip_event(2, "INVITE", from_tag="from-b", vias=["b"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 2)

    def test_differing_cseq_without_dialog_bridge_stays_distinct(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", cseq=1, vias=["a"]),
                sip_event(2, "INVITE", cseq=2, vias=["b"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 2)
        self.assertEqual(
            [group["grouping_status"] for group in document["logical_calls"]],
            ["SINGLE_ATTEMPT", "SINGLE_ATTEMPT"],
        )

    def test_proven_in_dialog_reinvite_joins_through_accepted_dialog(self) -> None:
        initial = attempt(
            1,
            answer_frames=[2],
            branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])],
        )
        document = self._group(
            [
                sip_event(1, "INVITE", cseq=1, vias=["a"]),
                sip_event(2, status=200, to_tag="to-a", cseq=1, vias=["a"]),
                sip_event(10, "INVITE", to_tag="to-a", cseq=2, vias=["b", "a"]),
            ],
            [initial, attempt(10)],
            {"ims-session:%s:1.1" % CAP: initial["branches"]},
        )
        self.assertEqual(document["logical_call_count"], 1)
        group = document["logical_calls"][0]
        self.assertEqual(group["grouping_status"], "IN_DIALOG_SEQUENCE")
        self.assertIn("ACCEPTED_DIALOG_BRIDGE", group["grouping_reason_codes"])
        self.assertTrue(group["grouping_accepted"])

    def test_two_competing_via_chains_sharing_call_id_are_ambiguous(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", vias=["a"]),
                sip_event(2, "INVITE", vias=["b"]),
                sip_event(3, "INVITE", vias=["x", "a"]),
                sip_event(4, "INVITE", vias=["y", "b"]),
            ],
            [attempt(1), attempt(2), attempt(3), attempt(4)],
        )
        self.assertEqual(document["logical_call_count"], 1)
        group = document["logical_calls"][0]
        self.assertEqual(group["grouping_status"], "AMBIGUOUS_MULTI_HOP")
        self.assertIn("COMPETING_VIA_FORWARDING_CHAINS", group["grouping_reason_codes"])
        self.assertFalse(group["grouping_accepted"])

    def test_missing_cseq_is_never_multi_hop_proven(self) -> None:
        event = sip_event(1, "INVITE", vias=["a"])
        event["headers"]["cseq"]["sequence"] = None
        document = self._group([event, sip_event(2, "INVITE", vias=["b", "a"])], [attempt(1), attempt(2)])
        unresolved = [
            group
            for group in document["logical_calls"]
            if group["grouping_status"] == "UNRESOLVED_IDENTITY"
        ]
        self.assertEqual(len(unresolved), 1)
        self.assertIn("CSEQ_NOT_ESTABLISHED", unresolved[0]["grouping_reason_codes"])

    def test_missing_via_branch_identity_is_ambiguous(self) -> None:
        document = self._group(
            [sip_event(1, "INVITE", vias=["a"]), sip_event(2, "INVITE", vias=["b"])],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"], "AMBIGUOUS_MULTI_HOP"
        )

    def test_missing_identity_key_is_unresolved(self) -> None:
        event = sip_event(1, "INVITE")
        event["identity_reference_status"] = "UNAVAILABLE_NO_KEY"
        event["call_id_reference"] = None
        document = self._group([event], [attempt(1)])
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"], "UNRESOLVED_IDENTITY"
        )
        self.assertIn(
            "SIP_IDENTITY_REFERENCE_UNAVAILABLE",
            document["logical_calls"][0]["grouping_reason_codes"],
        )
        self.assertFalse(document["accepted_logical_call"][
            document["logical_calls"][0]["logical_call_reference"]
        ])

    def test_identical_via_stack_is_repeated_observation(self) -> None:
        document = self._group(
            [sip_event(1, "INVITE", vias=["a", "b"]), sip_event(2, "INVITE", vias=["a", "b"])],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"],
            "REPEATED_OBSERVATION_ONLY",
        )
        self.assertTrue(document["logical_calls"][0]["grouping_accepted"])

    def test_b2bua_call_id_change_is_not_merged(self) -> None:
        document = self._group(
            [
                sip_event(1, "INVITE", call_id="leg-a", vias=["a"]),
                sip_event(2, "INVITE", call_id="leg-b", vias=["b", "a"]),
            ],
            [attempt(1), attempt(2)],
        )
        self.assertEqual(document["logical_call_count"], 2)

    def test_shared_transaction_reference_is_ambiguous(self) -> None:
        first = attempt(1)
        second = attempt(2)
        second["initial_invite_transaction_reference"] = first[
            "initial_invite_transaction_reference"
        ]
        document = self._group(
            [sip_event(1, "INVITE", vias=["a"]), sip_event(2, "INVITE", vias=["b", "a"])],
            [first, second],
        )
        self.assertEqual(
            document["logical_calls"][0]["grouping_status"], "AMBIGUOUS_MULTI_HOP"
        )
        self.assertIn(
            "TRANSACTION_OWNERSHIP_NOT_INDEPENDENT",
            document["logical_calls"][0]["grouping_reason_codes"],
        )


class MediaOwnershipGateTests(unittest.TestCase):
    def test_offer_and_answer_without_established_exchange_is_insufficient(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])])],
            exchanges=[
                exchange(
                    1,
                    branch_reference=f"sip-dialog:{CAP}:2.1",
                    offer_frame=1,
                    answer_frame=2,
                    association_status="INSUFFICIENT_EVIDENCE",
                )
            ],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        logical = document["logical_calls"][0]
        self.assertEqual(logical["ownership_status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn(
            "ESTABLISHED_OFFER_ANSWER_EXCHANGE_NOT_OBSERVED", logical["ownership_basis"]
        )

    def test_offer_and_answer_from_different_calls_is_not_owned(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])]),
                attempt(20, answer_frames=[21], branches=[branch(f"sip-dialog:{CAP}:21.1", answer_frames=[21])]),
            ],
            exchanges=[
                exchange(1, branch_reference=None, offer_frame=20, answer_frame=21),
                exchange(20, branch_reference=None, offer_frame=20, answer_frame=21),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(20), sdp_message(21)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:20.1.0", offer_frames=[20], answer_frames=[21])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:24.1", 24, sequence=1)],
            streams=[stream()],
        )
        statuses = {
            item["attempt_reference"]: item["evidence_status"]
            for item in document["attempts"]
        }
        self.assertNotEqual(statuses[f"ims-session:{CAP}:1.1"], "EVIDENCE_CHAIN_SUPPORTED")

    def test_answer_shared_across_distinct_branches_is_rejected(self) -> None:
        document = run(
            attempts=[
                attempt(
                    1,
                    answer_frames=[2],
                    branches=[
                        branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2]),
                        branch(f"sip-dialog:{CAP}:2.2", answer_frames=[2]),
                    ],
                )
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.2", offer_frame=1, answer_frame=2),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        logical = document["logical_calls"][0]
        self.assertIn(
            "COMPETING_BRANCH_ANSWER_CONTAMINATION", logical["ownership_basis"]
        )
        self.assertEqual(logical["ownership_status"], "INSUFFICIENT_EVIDENCE")

    def test_matched_endpoint_without_exchange_is_not_owned(self) -> None:
        document = run(
            attempts=[attempt(1, branches=[branch(f"sip-event:{CAP}:1.1")])],
            exchanges=[],
            sdp_messages=[sdp_message(1)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        logical = document["logical_calls"][0]
        self.assertEqual(logical["ownership_status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(
            logical["diagnostic_review"]["diagnostic_result"]["sdp_association_outcome"],
            "OFFER_ANSWER_NOT_ESTABLISHED",
        )

    def test_rtp_without_sdp_is_not_owned(self) -> None:
        document = run(
            attempts=[attempt(1)],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
        )
        logical = document["logical_calls"][0]
        self.assertEqual(logical["ownership_status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(
            logical["diagnostic_review"]["diagnostic_result"]["rtp_evidence_outcome"],
            "RTP_NOT_OBSERVED",
        )

    def test_multiple_streams_with_competing_ownership_are_ambiguous(self) -> None:
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
                correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2]),
                correlation("sdp-rtp-transport:synthetic-call.pcapng:20.1.0", offer_frames=[20], answer_frames=[21]),
            ],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1, udp=10),
                rtp_event(f"rtp-packet:{CAP}:5.1", 5, sequence=2, udp=11),
            ],
            streams=[stream(udp=10), stream(udp=11)],
        )
        statuses = {item["ownership_status"] for item in document["logical_calls"]}
        self.assertIn("AMBIGUOUS_OWNERSHIP", statuses)

    def test_deleting_one_correlation_downgrades_only_that_call(self) -> None:
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
                correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2], udp_streams=[10]),
            ],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1, udp=10),
                rtp_event(f"rtp-packet:{CAP}:24.1", 24, sequence=1, udp=20),
            ],
            streams=[stream(udp=10), stream(udp=20)],
        )
        by_member = {
            logical["member_ims_attempt_references"][0]: logical["ownership_status"]
            for logical in document["logical_calls"]
        }
        self.assertEqual(by_member[f"ims-session:{CAP}:1.1"], "LOGICAL_CALL_MEDIA_OWNED")
        self.assertEqual(by_member[f"ims-session:{CAP}:20.1"], "INSUFFICIENT_EVIDENCE")


class LogicalRtcpOwnershipTests(unittest.TestCase):
    def _owned_call(self, rtcp_events: list[dict], streams: list[dict] | None = None) -> dict:
        return run(
            attempts=[
                attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])])
            ],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2], udp_streams=[10])],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1, udp=10)],
            rtcp_events=rtcp_events,
            streams=streams or [stream(udp=10)],
        )

    def test_unique_sender_and_reportee_association_is_call_owned(self) -> None:
        event = rtcp_event(
            9,
            packet_type=200,
            sender_ssrc=SSRC_A,
            report_blocks=[
                {
                    "reported_ssrc": 0x11111111,
                    "fraction_lost": 0,
                    "cumulative_packets_lost": 0,
                    "extended_highest_sequence": 20,
                    "interarrival_jitter": 160,
                    "last_sr_timestamp": 0,
                    "delay_since_last_sr": 0,
                }
            ],
        )
        document = self._owned_call([event])
        rtcp = document["logical_calls"][0]["rtcp_evidence"]
        self.assertEqual(rtcp["ownership_status"], "LOGICAL_CALL_RTCP_ASSOCIATED")
        self.assertEqual(rtcp["established_source_association_count"], 2)

    def test_nonempty_ambiguous_association_never_becomes_call_owned(self) -> None:
        event = rtcp_event(9, packet_type=200, sender_ssrc=SSRC_A, udp=99)
        document = self._owned_call(
            [event], streams=[stream(udp=10), stream(udp=11)]
        )
        rtcp = document["logical_calls"][0]["rtcp_evidence"]
        self.assertEqual(rtcp["ownership_status"], "RTCP_CALL_ASSOCIATION_AMBIGUOUS")
        self.assertGreaterEqual(rtcp["association_count"], 1)
        self.assertEqual(rtcp["established_source_association_count"], 0)
        self.assertNotEqual(rtcp["ownership_status"], "LOGICAL_CALL_RTCP_ASSOCIATED")

    def test_unknown_clock_rate_keeps_jitter_ms_null(self) -> None:
        event = rtcp_event(
            9,
            packet_type=200,
            sender_ssrc=SSRC_A,
            report_blocks=[
                {
                    "reported_ssrc": 0x11111111,
                    "fraction_lost": 50,
                    "cumulative_packets_lost": 5,
                    "extended_highest_sequence": 20,
                    "interarrival_jitter": 160,
                    "last_sr_timestamp": 0,
                    "delay_since_last_sr": 0,
                }
            ],
        )
        document = self._owned_call(
            [event], streams=[stream(udp=10, payload_types=[105])]
        )
        reports = document["logical_calls"][0]["rtcp_evidence"]["receiver_reported_quality"]
        self.assertTrue(reports)
        self.assertIsNone(reports[0]["jitter_ms"])
        self.assertEqual(
            reports[0]["jitter_ms_status"], "RTP_CLOCK_RATE_NOT_PROVEN_FOR_ASSOCIATION"
        )
        self.assertEqual(reports[0]["measurement_origin"], "RECEIVER_REPORTED")
        self.assertEqual(reports[0]["fraction_lost"], 50)
        self.assertEqual(reports[0]["cumulative_packets_lost"], 5)
        self.assertIn("CONFIRMED_NETWORK_PACKET_LOSS", document["not_confirmed"])


class NegativeDiagnosticTests(unittest.TestCase):
    def _negative(self, status: int) -> dict:
        return run(
            attempts=[attempt(1, answer_frames=[2])],
            exchanges=[exchange(1, branch_reference=None, offer_frame=1, answer_frame=None)],
            sdp_messages=[sdp_message(1)],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: status},
            sip_overrides={
                2: sip_event(
                    2,
                    status=status,
                    call_id="call-1",
                    from_tag="from-1",
                    to_tag="to-1",
                )
            },
        )

    def test_sip_4xx_outcome_is_negative_not_protocol_violation(self) -> None:
        document = self._negative(486)
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            result["observed_sip_outcome"], "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
        )
        self.assertEqual(
            result["logical_call_outcome"], "NEGATIVE_FINAL_BRANCH_OBSERVED"
        )
        self.assertEqual(
            result["boundary_classification"], "OBSERVED_NEGATIVE_SIP_OUTCOME"
        )
        outcome = document["attempts"][0]["sip_final_outcome"]
        self.assertEqual(outcome["final_status_codes"], [486])
        self.assertEqual(
            outcome["final_response_references"], [f"sip-event:{CAP}:2.1"]
        )
        self.assertFalse(outcome["reason_established"])
        self.assertFalse(outcome["timeout_inferred"])

    def test_sip_5xx_outcome_is_negative_not_protocol_violation(self) -> None:
        document = self._negative(503)
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            document["attempts"][0]["sip_final_outcome"]["final_status_codes"], [503]
        )
        self.assertEqual(
            result["observed_sip_outcome"], "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
        )

    def test_missing_sdp_answer_is_not_network_failure(self) -> None:
        document = run(
            attempts=[attempt(1)],
            exchanges=[exchange(1, branch_reference=None, offer_frame=1, answer_frame=None)],
            sdp_messages=[sdp_message(1)],
            correlations=[],
            rtp_events=[],
            streams=[],
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(result["boundary_classification"], "MISSING_OBSERVATION")
        self.assertIn("SDP_ANSWER_NOT_OBSERVED", document["logical_calls"][0]["missing_and_ambiguous_evidence"])

    def test_missing_rtp_is_not_media_failure(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2], branches=[branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2])])],
            exchanges=[exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)],
            sdp_messages=[sdp_message(1), sdp_message(2)],
            correlations=[],
            rtp_events=[],
            streams=[],
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertEqual(result["rtp_evidence_outcome"], "RTP_NOT_OBSERVED")
        self.assertNotEqual(result["boundary_classification"], "OBSERVED_PROTOCOL_DEVIATION")

    def test_encrypted_or_unavailable_sdp_is_a_visibility_limitation(self) -> None:
        event = sip_event(
            1,
            "INVITE",
            call_id=f"call-1",
            from_tag=f"from-1",
            body_present=True,
            content_type="application/sdp",
        )
        document = run(
            attempts=[attempt(1)],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            sip_overrides={1: event},
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertTrue(document["capture_visibility_limited"])
        self.assertEqual(
            result["boundary_classification"], "CAPTURE_VISIBILITY_LIMITATION"
        )

    def test_valid_call_has_no_abnormal_boundary(self) -> None:
        document = simple_chain()
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertEqual(result["boundary_classification"], "NO_ABNORMAL_EVIDENCE_OBSERVED")
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertIsNone(result["first_missing_evidence_boundary"])
        self.assertEqual(result["diagnostic_completeness_status"], "COMPLETE")

    def test_two_independent_calls_are_both_owned(self) -> None:
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
                correlation("sdp-rtp-transport:synthetic-call.pcapng:1.1.0", offer_frames=[1], answer_frames=[2], udp_streams=[10]),
                correlation("sdp-rtp-transport:synthetic-call.pcapng:20.1.0", offer_frames=[20], answer_frames=[21], udp_streams=[20]),
            ],
            rtp_events=[
                rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1, udp=10),
                rtp_event(f"rtp-packet:{CAP}:24.1", 24, sequence=1, udp=20),
            ],
            streams=[stream(udp=10), stream(udp=20)],
        )
        self.assertEqual(document["logical_call_count"], 2)
        self.assertEqual(
            document["logical_call_ownership_counts"].get("LOGICAL_CALL_MEDIA_OWNED"), 2
        )


class RtpPacketIdentityBoundaryTests(unittest.TestCase):
    HEADER = {
        "interface_id": "0",
        "encap_type": "25",
        "protocols": "sll:ip:udp:rtp",
        "outer_udp_stream": "2",
        "inner_udp_stream": "2",
        "gtp_present": False,
    }

    def test_byte_identical_packets_in_independent_streams_are_not_grouped(self) -> None:
        fingerprint = "rtp-packet-fingerprint-v1:" + "c" * 64
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1, udp=10, fingerprint=fingerprint),
                rtp_event(f"rtp-packet:{CAP}:2.1", 2, sequence=1, udp=11, fingerprint=fingerprint),
            ],
            None,
            {1: self.HEADER, 2: dict(self.HEADER, outer_udp_stream="3", inner_udp_stream="3")},
        )
        self.assertEqual(document["multi_vantage_supported_event_count"], 0)
        self.assertEqual(document["cross_stream_byte_identity_collision_count"], 1)
        self.assertEqual(document["distinct_byte_identity_count"], 2)

    def test_ambiguous_encapsulated_transport_is_unresolved(self) -> None:
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1, fingerprint=None, fingerprint_status="UNAVAILABLE_TRANSPORT_AMBIGUOUS"),
                rtp_event(f"rtp-packet:{CAP}:2.1", 2, sequence=1, fingerprint=None, fingerprint_status="UNAVAILABLE_TRANSPORT_AMBIGUOUS"),
            ],
            None,
            {1: self.HEADER, 2: self.HEADER},
        )
        self.assertEqual(document["rtp_packet_identity_coverage"], "UNAVAILABLE")
        self.assertEqual(
            document["classification_counts"]["PACKET_IDENTITY_UNRESOLVED"], 1
        )

    def test_truncated_rtp_packet_is_incomplete_evidence(self) -> None:
        document = diagnostics.duplicate_investigation(
            CAP,
            [rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1, fingerprint=None, fingerprint_status="UNAVAILABLE_INCOMPLETE_PACKET")],
            None,
            {1: self.HEADER},
        )
        self.assertEqual(document["fingerprint_unavailable_observation_count"], 1)
        self.assertEqual(document["packet_identity_unresolved_event_count"], 0)

    def test_no_retransmission_is_fabricated(self) -> None:
        views = {frame: self.HEADER for frame in (1, 2)}
        document = diagnostics.duplicate_investigation(
            CAP,
            [
                rtp_event(f"rtp-packet:{CAP}:1.1", 1, sequence=1),
                rtp_event(f"rtp-packet:{CAP}:2.1", 2, sequence=1),
            ],
            None,
            views,
        )
        self.assertEqual(document["potential_retransmission_event_count"], 0)
        self.assertTrue(
            all(group.get("retransmission_established") is False for group in document["groups"])
        )


class SipOutcomeSemanticsTests(unittest.TestCase):
    def _cancel(self) -> dict:
        return {
            "outcome": "CANCEL_INVITE_SEQUENCE_OBSERVED",
            "association_status": "ASSOCIATED",
            "cancel_transaction_references": [
                f"sip-transaction:{CAP}:request:3.1"
            ],
            "cancel_request_event_references": [f"sip-event:{CAP}:3.1"],
            "cancel_final_response_event_references": [f"sip-event:{CAP}:4.1"],
            "cancel_final_response_status_codes": [200],
            "invite_final_response_status": 487,
            "response_sequence_observed": True,
            "missing_evidence": [],
            "conflict_findings": [],
        }

    def test_cancel_then_487_is_normal_cancellation_not_violation(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[5], cancel_evidence=self._cancel())
            ],
            exchanges=[],
            sdp_messages=[sdp_message(1)],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={5: 487},
            sip_overrides={
                1: sip_event(1, "INVITE", call_id="call-1", from_tag="from-1"),
                2: sip_event(2, status=100, call_id="call-1", from_tag="from-1"),
                3: sip_event(3, "CANCEL", call_id="call-1", from_tag="from-1"),
                4: sip_event(4, status=200, call_id="call-1", from_tag="from-1"),
                5: sip_event(5, status=487, call_id="call-1", from_tag="from-1"),
            },
        )
        attempt_outcome = document["attempts"][0]["sip_final_outcome"]
        self.assertEqual(
            attempt_outcome["classification"],
            "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED",
        )
        self.assertTrue(attempt_outcome["cancel_relationship_established"])
        self.assertEqual(
            attempt_outcome["cancel_request_event_references"],
            [f"sip-event:{CAP}:3.1"],
        )
        self.assertEqual(
            attempt_outcome["cancel_response_event_references"],
            [f"sip-event:{CAP}:4.1"],
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            result["boundary_classification"],
            "OBSERVED_CANCELLED_SIP_OUTCOME",
        )
        self.assertEqual(
            result["observed_sip_outcome"],
            "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED",
        )

    def test_487_without_established_cancel_is_negative_only(self) -> None:
        document = run(
            attempts=[
                attempt(1, answer_frames=[2], cancel_evidence={
                    "outcome": "CANCEL_ASSOCIATION_NOT_ESTABLISHED",
                    "association_status": "NOT_ESTABLISHED",
                    "cancel_transaction_references": [],
                    "cancel_request_event_references": [],
                    "cancel_final_response_event_references": [],
                    "cancel_final_response_status_codes": [],
                    "invite_final_response_status": 487,
                    "response_sequence_observed": False,
                    "missing_evidence": [],
                    "conflict_findings": [],
                })
            ],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: 487},
        )
        outcome = document["attempts"][0]["sip_final_outcome"]
        self.assertEqual(
            outcome["classification"], "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
        )
        self.assertFalse(outcome["cancel_relationship_established"])
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            result["boundary_classification"], "OBSERVED_NEGATIVE_SIP_OUTCOME"
        )

    def test_487_and_200_in_different_forks_are_mixed_not_failed(self) -> None:
        document = run(
            attempts=[
                attempt(
                    1,
                    answer_frames=[2, 6],
                    branches=[
                        branch(f"sip-dialog:{CAP}:2.1", answer_frames=[2]),
                        branch(
                            f"sip-dialog:{CAP}:6.1",
                            answer_frames=[6],
                            response_status_codes=[487],
                        ),
                    ],
                )
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2),
                exchange(
                    1,
                    branch_reference=f"sip-dialog:{CAP}:6.1",
                    offer_frame=1,
                    answer_frame=6,
                    association_status="INSUFFICIENT_EVIDENCE",
                ),
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(6)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1],
                    answer_frames=[2],
                )
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
            response_status_by_frame={6: 487},
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertEqual(
            result["logical_call_outcome"], "MIXED_FORK_OUTCOMES_OBSERVED"
        )
        self.assertTrue(result["branch_outcomes"])
        classifications = {
            outcome["classification"] for outcome in result["branch_outcomes"]
        }
        self.assertIn("SIP_POSITIVE_FINAL_OUTCOME_OBSERVED", classifications)
        self.assertIn(
            "SIP_FORK_BRANCH_NEGATIVE_OUTCOME_OBSERVED", classifications
        )
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            result["boundary_classification"], "OBSERVED_MIXED_SIP_OUTCOMES"
        )

    def test_conflicting_final_responses_in_one_branch_are_contradiction(self) -> None:
        document = run(
            attempts=[
                attempt(
                    1,
                    answer_frames=[2, 6],
                    branches=[
                        branch(
                            f"sip-dialog:{CAP}:2.1",
                            answer_frames=[2, 6],
                            response_status_codes=[200, 487],
                        )
                    ],
                )
            ],
            exchanges=[
                exchange(1, branch_reference=f"sip-dialog:{CAP}:2.1", offer_frame=1, answer_frame=2)
            ],
            sdp_messages=[sdp_message(1), sdp_message(2), sdp_message(6)],
            correlations=[
                correlation(
                    "sdp-rtp-transport:synthetic-call.pcapng:1.1.0",
                    offer_frames=[1],
                    answer_frames=[2],
                )
            ],
            rtp_events=[rtp_event(f"rtp-packet:{CAP}:4.1", 4, sequence=1)],
            streams=[stream()],
            response_status_by_frame={6: 487},
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNone(result["first_supported_protocol_deviation"])
        self.assertIsNotNone(result["first_observed_procedure_contradiction"])
        self.assertEqual(
            result["boundary_classification"],
            "OBSERVED_SIP_PROCEDURE_CONTRADICTION",
        )
        self.assertEqual(
            result["observed_sip_outcome"], "SIP_PROCEDURE_CONTRADICTION_OBSERVED"
        )

    def test_403_404_486_503_are_negative_outcomes_without_root_cause(self) -> None:
        for status in (403, 404, 486, 503):
            with self.subTest(status=status):
                document = self._negative_status(status)
                outcome = document["attempts"][0]["sip_final_outcome"]
                self.assertEqual(
                    outcome["classification"],
                    "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED",
                )
                self.assertFalse(outcome["reason_established"])
                self.assertFalse(outcome["timeout_inferred"])
                self.assertTrue(outcome["next_checks"])
                result = document["logical_calls"][0]["diagnostic_review"][
                    "diagnostic_result"
                ]
                self.assertIsNone(result["first_supported_protocol_deviation"])
                self.assertEqual(
                    result["boundary_classification"],
                    "OBSERVED_NEGATIVE_SIP_OUTCOME",
                )

    def _negative_status(self, status: int) -> dict:
        return run(
            attempts=[attempt(1, answer_frames=[2])],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: status},
        )

    def test_protocol_violation_requires_malformed_response_evidence(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2])],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: 486},
            sip_overrides={
                2: sip_event(
                    2,
                    status=486,
                    call_id="call-1",
                    from_tag="from-1",
                    integrity_findings=["INVALID_STATUS_CODE"],
                )
            },
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertIsNotNone(result["first_supported_protocol_deviation"])
        self.assertEqual(
            result["boundary_classification"], "OBSERVED_PROTOCOL_VIOLATION"
        )
        self.assertEqual(
            result["observed_sip_outcome"], "SIP_PROTOCOL_VIOLATION_EVIDENCE"
        )

    def test_invite_407_with_authorized_retry_is_associated(self) -> None:
        document = run(
            attempts=[
                attempt(
                    1,
                    answer_frames=[2],
                    branches=[
                        branch(
                            f"sip-event:{CAP}:2.1",
                            identity="INSUFFICIENT_EVIDENCE",
                            answer_frames=[2],
                            response_status_codes=[407],
                        )
                    ],
                ),
                attempt(10, answer_frames=[11]),
            ],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: 407, 11: 200},
            sip_overrides={
                1: sip_event(1, "INVITE", call_id="call-a", from_tag="from-a", cseq=1),
                2: sip_event(2, status=407, call_id="call-a", from_tag="from-a", to_tag="to-a", cseq=1),
                10: sip_event(
                    10,
                    "INVITE",
                    call_id="call-a",
                    from_tag="from-a",
                    to_tag="to-a",
                    cseq=2,
                    authorization_count=1,
                ),
                11: sip_event(11, status=200, call_id="call-a", from_tag="from-a", to_tag="to-a", cseq=2),
            },
        )
        review = next(
            document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"][
                "invite_authentication_review"
            ]
            for record in document["logical_calls"]
            if record["member_ims_attempt_references"][0]
            == f"ims-session:{CAP}:1.1"
        )
        self.assertTrue(review["challenge_observed"])
        self.assertTrue(review["retry_observed"])
        self.assertEqual(review["association_status"], "CHALLENGE_RETRY_ASSOCIATED")
        self.assertEqual(
            review["retry_request_event_references"], [f"sip-event:{CAP}:10.1"]
        )
        self.assertEqual(review["retry_final_status_codes"], [200])
        self.assertFalse(review["authentication_verified"])

    def test_invite_407_without_retry_is_not_authentication_failure(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2])],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={2: 407},
        )
        review = document["logical_calls"][0]["diagnostic_review"][
            "diagnostic_result"
        ]["invite_authentication_review"]
        self.assertTrue(review["challenge_observed"])
        self.assertFalse(review["retry_observed"])
        self.assertEqual(
            review["association_status"], "CHALLENGE_WITHOUT_OBSERVED_RETRY"
        )
        self.assertFalse(review["authentication_verified"])

    def test_observed_408_is_not_a_locally_inferred_timeout(self) -> None:
        observed = self._negative_status(408)
        outcome = observed["attempts"][0]["sip_final_outcome"]
        self.assertEqual(outcome["final_status_codes"], [408])
        self.assertFalse(outcome["timeout_inferred"])
        absent = run(
            attempts=[attempt(1)],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            sip_overrides={
                1: sip_event(1, "INVITE", call_id="call-1", from_tag="from-1"),
                2: sip_event(2, status=100, call_id="call-1", from_tag="from-1"),
            },
        )
        absent_outcome = absent["attempts"][0]["sip_final_outcome"]
        self.assertEqual(
            absent_outcome["classification"], "SIP_FINAL_OUTCOME_NOT_OBSERVED"
        )
        self.assertFalse(absent_outcome["timeout_inferred"])

    def test_180_without_final_is_provisional_only(self) -> None:
        document = run(
            attempts=[attempt(1, provisional_frames=[2])],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            sip_overrides={
                1: sip_event(1, "INVITE", call_id="call-1", from_tag="from-1"),
                2: sip_event(2, status=180, call_id="call-1", from_tag="from-1"),
            },
        )
        result = document["logical_calls"][0]["diagnostic_review"]["diagnostic_result"]
        self.assertEqual(result["logical_call_outcome"], "PROVISIONAL_ONLY")
        self.assertEqual(
            result["observed_sip_outcome"], "SIP_FINAL_OUTCOME_NOT_OBSERVED"
        )
        self.assertEqual(result["boundary_classification"], "MISSING_OBSERVATION")

    def test_multiple_independent_calls_keep_mixed_outcomes_separate(self) -> None:
        document = run(
            attempts=[attempt(1, answer_frames=[2]), attempt(20, answer_frames=[21])],
            exchanges=[],
            sdp_messages=[],
            correlations=[],
            rtp_events=[],
            streams=[],
            response_status_by_frame={21: 486},
        )
        by_member = {
            record["member_ims_attempt_references"][0]: record[
                "diagnostic_review"
            ]["diagnostic_result"]["logical_call_outcome"]
            for record in document["logical_calls"]
        }
        self.assertEqual(
            by_member[f"ims-session:{CAP}:1.1"], "ACCEPTED_INVITE_BRANCH_OBSERVED"
        )
        self.assertEqual(
            by_member[f"ims-session:{CAP}:20.1"], "NEGATIVE_FINAL_BRANCH_OBSERVED"
        )


if __name__ == "__main__":
    unittest.main()