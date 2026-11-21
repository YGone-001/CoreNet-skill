#!/usr/bin/env python3
"""Per-call and per-branch IMS media diagnostic consolidation.

This is application-level orchestration over already-accepted artifacts. It does
not decode SIP or RTP, parse SDP, or reconstruct transactions, dialogs, streams or
SDP/RTP correlations. It preserves exact capture-scoped references, rejects
capture-wide ownership promotion, and publishes evidence-coverage statuses rather
than network, delivery or quality verdicts.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

ANALYSIS_NAME = "ims-call-diagnostics"
ANALYSIS_VERSION = "0.2.0"
CAPABILITY = "bounded per-call and per-branch IMS media evidence consolidation"

MAX_LIST_ITEMS = 32
MAX_GROUPS = 64
MAX_REPORTS = 256
MAX_REPORT_BLOCKS = 32
MAX_RECEIVER_REPORTS = 512
MAX_DIAGNOSTIC_ITEMS = 24

CALL_STATUSES = (
    "EVIDENCE_CHAIN_SUPPORTED",
    "SIGNALING_ONLY",
    "MEDIA_TRANSPORT_OBSERVED",
    "PARTIAL_EVIDENCE",
    "AMBIGUOUS_OWNERSHIP",
    "INSUFFICIENT_EVIDENCE",
    "UNSUPPORTED_PROCEDURE",
)
TEMPORAL_STATUSES = (
    "RTP_OBSERVED_BEFORE_INVITE_2XX",
    "RTP_OBSERVED_AFTER_INVITE_2XX",
    "RTP_OBSERVED_BEFORE_BYE",
    "RTP_OBSERVED_AFTER_BYE",
    "RTP_WITHIN_OBSERVED_SIGNALING_INTERVAL",
    "TEMPORAL_ASSOCIATION_AMBIGUOUS",
    "TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE",
)
RTCP_STATUSES = (
    "RTCP_STREAM_ASSOCIATION_ESTABLISHED",
    "RTCP_STREAM_ASSOCIATION_AMBIGUOUS",
    "RTCP_STREAM_ASSOCIATION_INSUFFICIENT",
    "RTCP_STREAM_ASSOCIATION_UNSUPPORTED",
)
DUPLICATE_CLASSES = (
    "RTP_PACKET_BYTES_IDENTICAL",
    "RTP_HEADER_SIGNATURE_MATCH",
    "MULTI_VANTAGE_SUPPORTED",
    "MULTI_VANTAGE_CONSISTENT",
    "DUPLICATE_SEQUENCE_OBSERVED",
    "PACKET_IDENTITY_UNRESOLVED",
)
REFERENCE_FRAME = re.compile(r":([0-9]+)\.[0-9]+(?:\.[0-9]+)?$")
STREAM_REFERENCE = re.compile(r"^rtp-source-stream:([^:]+):([0-9]+):([0-9a-f]{8})$")
UDP_STREAM_REFERENCE = re.compile(r"^rtp-udp-stream:([^:]+):([0-9]+)$")
SSRC_REFERENCE = re.compile(r"^rtp-ssrc:([^:]+):([0-9a-f]{8})$")


def _load(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return document if isinstance(document, dict) else None


def _load_jsonl(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    result: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            result.append(item)
    return result


def _unique(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _frame_of(reference: Any) -> int | None:
    if not isinstance(reference, str):
        return None
    match = REFERENCE_FRAME.search(reference)
    return int(match.group(1)) if match else None


def _ssrc_reference(capture: str, raw: Any) -> str | None:
    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 0xFFFFFFFF:
        return None
    return f"rtp-ssrc:{capture}:{raw:08x}"


def _udp_stream(reference: Any) -> int | None:
    if not isinstance(reference, str):
        return None
    match = UDP_STREAM_REFERENCE.fullmatch(reference)
    return int(match.group(2)) if match else None


def _frame_views(capture: Path, runner: Callable[..., Any] | None = None) -> dict[int, dict[str, Any]]:
    command = [
        "tshark",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.interface_id",
        "-e",
        "frame.encap_type",
        "-e",
        "frame.protocols",
        "-e",
        "udp.stream",
        "-e",
        "gtp.teid",
    ]
    try:
        completed = (runner or subprocess.run)(
            command, capture_output=True, text=True, check=False
        )
    except OSError:
        return {}
    if completed.returncode != 0:
        return {}
    views: dict[int, dict[str, Any]] = {}
    for line in completed.stdout.splitlines():
        parts = line.split("\t")
        if not parts or not parts[0].isdigit():
            continue
        frame = int(parts[0])
        fields = parts + [""] * (6 - len(parts))
        protocols = fields[3]
        udp_streams = [value for value in fields[4].split(",") if value]
        views[frame] = {
            "interface_id": fields[1] or None,
            "encap_type": fields[2] or None,
            "protocols": protocols or None,
            "gtp_present": "gtp" in protocols.split(":") if protocols else False,
            "udp_streams": udp_streams,
            "outer_udp_stream": udp_streams[0] if udp_streams else None,
            "inner_udp_stream": udp_streams[-1] if udp_streams else None,
            "gtp_teid_present": bool(fields[5]),
        }
    return views


def _view_signature(view: dict[str, Any] | None) -> tuple[Any, ...]:
    if view is None:
        return ("UNAVAILABLE",)
    return (
        view.get("interface_id"),
        view.get("encap_type"),
        view.get("protocols"),
        view.get("outer_udp_stream"),
        view.get("gtp_present"),
    )


def duplicate_investigation(
    capture_file: str,
    rtp_events: list[dict[str, Any]],
    stream_document: dict[str, Any] | None,
    views: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    header_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    byte_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    sequence_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for event in rtp_events:
        base = (
            event.get("udp_stream"),
            event.get("ssrc_reference"),
            event.get("sequence_number"),
        )
        header = base + (
            event.get("timestamp"),
            event.get("payload_type"),
            event.get("packet_length"),
        )
        header_groups[header].append(event)
        if event.get("rtp_packet_fingerprint_status") == "ESTABLISHED":
            fingerprint = event.get("rtp_packet_fingerprint")
            if isinstance(fingerprint, str):
                byte_groups[fingerprint].append(event)
        sequence_groups[base].append(event)

    class_counts = {name: 0 for name in DUPLICATE_CLASSES}
    groups: list[dict[str, Any]] = []
    byte_identical_events = 0
    multi_vantage_supported = 0
    multi_vantage_consistent = 0
    header_signature_events = 0
    sequence_only_events = 0
    unresolved_events = 0
    classified_events: set[str] = set()
    per_stream: dict[tuple[Any, Any], dict[str, int]] = defaultdict(
        lambda: {
            "raw": 0,
            "byte_identical": 0,
            "multi_vantage_supported": 0,
            "multi_vantage_consistent": 0,
            "header_signature": 0,
            "sequence_only": 0,
            "unresolved": 0,
        }
    )
    for event in rtp_events:
        per_stream[(event.get("udp_stream"), event.get("ssrc_reference"))]["raw"] += 1

    for fingerprint, events in byte_groups.items():
        stream_key = (events[0].get("udp_stream"), events[0].get("ssrc_reference"))
        if len(events) <= 1:
            continue
        base_view = _view_signature(views.get(events[0].get("frame_number")))
        for event in events[1:]:
            event_view = _view_signature(views.get(event.get("frame_number")))
            if event_view != base_view:
                classification = "MULTI_VANTAGE_SUPPORTED"
                multi_vantage_supported += 1
                per_stream[stream_key]["multi_vantage_supported"] += 1
            else:
                classification = "RTP_PACKET_BYTES_IDENTICAL"
                byte_identical_events += 1
                per_stream[stream_key]["byte_identical"] += 1
            class_counts[classification] += 1
            reference = event.get("event_reference")
            if isinstance(reference, str):
                classified_events.add(reference)
            if len(groups) < MAX_GROUPS:
                groups.append(
                    {
                        "classification": classification,
                        "packet_identity_basis": "BYTE_IDENTICAL",
                        "rtp_packet_fingerprint": fingerprint,
                        "stream_key": {
                            "udp_stream": event.get("udp_stream"),
                            "ssrc_reference": event.get("ssrc_reference"),
                        },
                        "sequence_number": event.get("sequence_number"),
                        "rtp_timestamp": event.get("timestamp"),
                        "payload_type": event.get("payload_type"),
                        "packet_length": event.get("packet_length"),
                        "rtp_packet_byte_count": event.get("rtp_packet_byte_count"),
                        "event_references": [
                            events[0].get("event_reference"),
                            event.get("event_reference"),
                        ][:MAX_LIST_ITEMS],
                        "frame_numbers": [
                            events[0].get("frame_number"),
                            event.get("frame_number"),
                        ][:MAX_LIST_ITEMS],
                        "capture_views": [
                            views.get(events[0].get("frame_number")) or {},
                            event_view and (views.get(event.get("frame_number")) or {}),
                        ][:MAX_LIST_ITEMS],
                        "evidence_class": "DERIVED",
                    }
                )

    header_signature_group_count = len(header_groups)
    header_signature_repeated_event_count = sum(
        max(0, len(events) - 1) for events in header_groups.values()
    )
    for key, events in header_groups.items():
        remaining = [
            event
            for event in events
            if not (
                isinstance(event.get("event_reference"), str)
                and event.get("event_reference") in classified_events
            )
        ]
        if len(remaining) <= 1:
            continue
        base = remaining[0]
        base_fingerprint = base.get("rtp_packet_fingerprint")
        base_view = _view_signature(views.get(base.get("frame_number")))
        stream_key = (key[0], key[1])
        for event in remaining[1:]:
            event_fingerprint = event.get("rtp_packet_fingerprint")
            event_view = _view_signature(views.get(event.get("frame_number")))
            if (
                isinstance(base_fingerprint, str)
                and isinstance(event_fingerprint, str)
                and base_fingerprint != event_fingerprint
            ):
                classification = "RTP_HEADER_SIGNATURE_MATCH"
                header_signature_events += 1
                per_stream[stream_key]["header_signature"] += 1
                basis = "HEADER_SIGNATURE_ONLY"
            elif base_fingerprint is None or event_fingerprint is None:
                if event_view != base_view:
                    classification = "MULTI_VANTAGE_CONSISTENT"
                    multi_vantage_consistent += 1
                    per_stream[stream_key]["multi_vantage_consistent"] += 1
                    basis = "CAPTURE_VIEW_CONSISTENT_ONLY"
                else:
                    classification = "PACKET_IDENTITY_UNRESOLVED"
                    unresolved_events += 1
                    per_stream[stream_key]["unresolved"] += 1
                    basis = "UNRESOLVED"
            else:
                classification = "PACKET_IDENTITY_UNRESOLVED"
                unresolved_events += 1
                per_stream[stream_key]["unresolved"] += 1
                basis = "UNRESOLVED"
            class_counts[classification] += 1
            reference = event.get("event_reference")
            if isinstance(reference, str):
                classified_events.add(reference)
            if len(groups) < MAX_GROUPS:
                groups.append(
                    {
                        "classification": classification,
                        "packet_identity_basis": basis,
                        "stream_key": {
                            "udp_stream": key[0],
                            "ssrc_reference": key[1],
                        },
                        "sequence_number": key[2],
                        "rtp_timestamp": key[3],
                        "payload_type": key[4],
                        "packet_length": key[5],
                        "event_references": [
                            base.get("event_reference"),
                            event.get("event_reference"),
                        ][:MAX_LIST_ITEMS],
                        "frame_numbers": [
                            base.get("frame_number"),
                            event.get("frame_number"),
                        ][:MAX_LIST_ITEMS],
                        "capture_views": [
                            views.get(base.get("frame_number")) or {},
                            views.get(event.get("frame_number")) or {},
                        ][:MAX_LIST_ITEMS],
                        "evidence_class": "DERIVED",
                    }
                )

    def _header_signature(event: dict[str, Any]) -> tuple[Any, ...]:
        return (
            event.get("timestamp"),
            event.get("payload_type"),
            event.get("packet_length"),
        )

    for key, events in sequence_groups.items():
        remaining = [
            event
            for event in events
            if not (
                isinstance(event.get("event_reference"), str)
                and event.get("event_reference") in classified_events
            )
        ]
        if len(remaining) <= 1:
            continue
        base = remaining[0]
        base_header = _header_signature(base)
        stream_key = (key[0], key[1])
        for event in remaining[1:]:
            if _header_signature(event) == base_header:
                continue
            sequence_only_events += 1
            class_counts["DUPLICATE_SEQUENCE_OBSERVED"] += 1
            per_stream[stream_key]["sequence_only"] += 1
            reference = event.get("event_reference")
            if isinstance(reference, str):
                classified_events.add(reference)
            if len(groups) < MAX_GROUPS:
                groups.append(
                    {
                        "classification": "DUPLICATE_SEQUENCE_OBSERVED",
                        "packet_identity_basis": "UNRESOLVED",
                        "stream_key": {
                            "udp_stream": key[0],
                            "ssrc_reference": key[1],
                        },
                        "sequence_number": key[2],
                        "distinct_header_signature_count": 2,
                        "event_references": [
                            base.get("event_reference"),
                            event.get("event_reference"),
                        ][:MAX_LIST_ITEMS],
                        "frame_numbers": [
                            base.get("frame_number"),
                            event.get("frame_number"),
                        ][:MAX_LIST_ITEMS],
                        "capture_views": [
                            views.get(base.get("frame_number")) or {},
                            views.get(event.get("frame_number")) or {},
                        ][:MAX_LIST_ITEMS],
                        "retransmission_established": False,
                        "evidence_class": "DERIVED",
                    }
                )

    baseline_duplicate_count = None
    if stream_document is not None:
        baseline_duplicate_count = sum(
            int(stream.get("duplicate_sequence_observation_count") or 0)
            for stream in stream_document.get("source_streams") or []
            if isinstance(stream, dict)
        )
    fingerprint_capable = sum(
        1
        for event in rtp_events
        if event.get("rtp_packet_fingerprint_status") == "ESTABLISHED"
    )
    if not rtp_events:
        identity_coverage = "NOT_APPLICABLE"
    elif fingerprint_capable == len(rtp_events):
        identity_coverage = "COMPLETE"
    elif fingerprint_capable == 0:
        identity_coverage = "UNAVAILABLE"
    else:
        identity_coverage = "PARTIAL"
    return {
        "raw_rtp_observation_count": len(rtp_events),
        "fingerprint_capable_observation_count": fingerprint_capable,
        "fingerprint_unavailable_observation_count": len(rtp_events) - fingerprint_capable,
        "rtp_packet_identity_coverage": identity_coverage,
        "distinct_header_signature_count": header_signature_group_count,
        "distinct_byte_identity_count": len(byte_groups),
        "header_signature_repeated_event_count": header_signature_repeated_event_count,
        "header_signature_match_event_count": (
            header_signature_events + multi_vantage_consistent + unresolved_events
        ),
        "byte_identical_duplicate_event_count": byte_identical_events,
        "multi_vantage_supported_event_count": multi_vantage_supported,
        "multi_vantage_consistent_event_count": multi_vantage_consistent,
        "packet_identity_unresolved_event_count": unresolved_events,
        "duplicate_sequence_event_count": sequence_only_events,
        "potential_retransmission_event_count": 0,
        "exact_duplicate_event_count": byte_identical_events + multi_vantage_supported,
        "exact_duplicate_event_count_basis": "RTP_PACKET_BYTES_IDENTICAL",
        "multi_vantage_event_count": multi_vantage_supported,
        "sequence_only_duplicate_event_count": sequence_only_events,
        "duplicate_cause_unresolved_event_count": unresolved_events + sequence_only_events,
        "retransmission_not_established_count": 0,
        "rtp_stream_reported_duplicate_sequence_observation_count": baseline_duplicate_count,
        "classification_counts": class_counts,
        "groups": groups,
        "per_stream": [
            {
                "source_stream_key": {
                    "udp_stream": key[0],
                    "ssrc_reference": key[1],
                },
                **counts,
            }
            for key, counts in sorted(per_stream.items(), key=lambda item: str(item[0]))
        ],
        "capture_view_limitations": [
            "Frame interface, encapsulation and protocol path are local decoder metadata, not network topology",
            "A multi-vantage classification requires matching complete RTP packet bytes and differing capture-view metadata",
            "Different frame views combined with the same header tuple are only header-signature coincidence",
            "Sequence-number equality alone is never promoted to a same-packet or retransmission classification",
        ],
        "not_confirmed": [
            "NETWORK_RETRANSMISSION",
            "NETWORK_PACKET_LOSS",
            "CAPTURE_POINT_TOPOLOGY",
        ],
    }


def _via_sequences_nested(sequences: list[list[str]]) -> bool:
    unique = [sequence for sequence in sequences if sequence]
    if len(unique) < 2:
        return False
    ordered = sorted(unique, key=len)
    longest_length = len(ordered[-1])
    if all(len(sequence) == longest_length for sequence in ordered):
        return False
    return all(
        any(
            len(longer) > len(shorter) and longer[-len(shorter):] == shorter
            for longer in ordered
        )
        for shorter in ordered
        if len(shorter) < longest_length
    )


def logical_call_grouping(
    capture_file: str,
    sip_by_ref: dict[str, dict[str, Any]],
    attempts: list[dict[str, Any]],
    branches_by_attempt: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Group initial INVITE attempts by proven capture-scoped SIP identity."""
    branches_by_attempt = branches_by_attempt or {}
    unresolved: list[dict[str, Any]] = []
    candidates: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for attempt in attempts:
        attempt_reference = attempt.get("attempt_reference")
        if not isinstance(attempt_reference, str):
            continue
        invite_reference = attempt.get("initial_invite_event_reference")
        event = sip_by_ref.get(invite_reference) if isinstance(invite_reference, str) else None
        if not isinstance(event, dict):
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "INITIAL_INVITE_EVENT_NOT_OBSERVED",
                }
            )
            continue
        call_id_reference = event.get("call_id_reference")
        from_tag_reference = event.get("from_tag_reference")
        to_tag_reference = event.get("to_tag_reference")
        cseq = (event.get("headers") or {}).get("cseq", {}).get("sequence")
        if (
            event.get("identity_reference_status") != "ESTABLISHED"
            or not isinstance(call_id_reference, str)
            or not isinstance(from_tag_reference, str)
        ):
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "SIP_IDENTITY_REFERENCE_UNAVAILABLE",
                }
            )
            continue
        key = (call_id_reference, from_tag_reference, to_tag_reference)
        candidates[key].append(
            {
                "attempt_reference": attempt_reference,
                "event_reference": invite_reference,
                "frame_number": event.get("frame_number"),
                "cseq": cseq,
                "via_branches": list(event.get("via_branch_references") or []),
                "transaction_reference": attempt.get(
                    "initial_invite_transaction_reference"
                ),
                "dialog_references": [
                    branch.get("dialog_reference")
                    for branch in branches_by_attempt.get(attempt_reference, [])
                    if isinstance(branch.get("dialog_reference"), str)
                ],
            }
        )

    groups: list[dict[str, Any]] = []
    attempt_to_logical: dict[str, str] = {}
    event_references_by_logical: dict[str, list[str]] = {}
    for index, (key, members) in enumerate(
        sorted(candidates.items(), key=lambda item: min(
            (member.get("frame_number") or 0) for member in item[1]
        )),
        start=1,
    ):
        frames = sorted(
            member.get("frame_number") or 0 for member in members
        )
        first_frame = frames[0] if frames else 0
        reference = f"ims-logical-call:{capture_file}:{first_frame}.{index}"
        cseq_values = sorted(
            {member.get("cseq") for member in members if isinstance(member.get("cseq"), int)}
        )
        via_sequences = [member["via_branches"] for member in members if member["via_branches"]]
        if len(members) == 1:
            status = "SINGLE_ATTEMPT"
            reasons = ["EXACTLY_ONE_INITIAL_INVITE_ATTEMPT"]
        elif len(set(cseq_values)) <= 1 and _via_sequences_nested(via_sequences):
            status = "MULTI_HOP_PROVEN"
            reasons = [
                "SAME_CALL_ID_REFERENCE",
                "SAME_FROM_TAG_REFERENCE",
                "SAME_TO_TAG_STATE",
                "SAME_CSEQ_SEQUENCE",
                "VIA_HOP_STACK_NESTED",
                "DISTINCT_SOURCE_FRAMES",
            ]
        elif len(set(cseq_values)) <= 1 and via_sequences and all(
            sequence == via_sequences[0] for sequence in via_sequences
        ):
            status = "REPEATED_OBSERVATION_ONLY"
            reasons = [
                "SAME_CALL_ID_REFERENCE",
                "SAME_FROM_TAG_REFERENCE",
                "SAME_CSEQ_SEQUENCE",
                "IDENTICAL_VIA_HOP_STACK",
                "DISTINCT_SOURCE_FRAMES",
            ]
        elif len(set(cseq_values)) > 1:
            status = "IN_DIALOG_SEQUENCE"
            reasons = [
                "SAME_CALL_ID_REFERENCE",
                "SAME_FROM_TAG_REFERENCE",
                "SAME_TO_TAG_STATE",
                "DISTINCT_CSEQ_SEQUENCES",
            ]
        else:
            status = "AMBIGUOUS_MULTI_HOP"
            reasons = [
                "SAME_CALL_ID_REFERENCE",
                "SAME_FROM_TAG_REFERENCE",
                "SAME_CSEQ_SEQUENCE",
                "VIA_HOP_RELATION_UNPROVEN",
            ]
        member_attempts = sorted(member["attempt_reference"] for member in members)
        for member in members:
            attempt_to_logical[member["attempt_reference"]] = reference
        call_id_reference, from_tag_reference, to_tag_reference = key
        dialog_tags: set[str] = set()
        if isinstance(to_tag_reference, str):
            dialog_tags.add(to_tag_reference)
        else:
            for event in sip_by_ref.values():
                if (
                    event.get("call_id_reference") == call_id_reference
                    and event.get("from_tag_reference") == from_tag_reference
                    and isinstance(event.get("to_tag_reference"), str)
                ):
                    dialog_tags.add(event["to_tag_reference"])
        member_event_references: set[str] = {
            member["event_reference"] for member in members
        }
        for event_reference, event in sip_by_ref.items():
            if event.get("call_id_reference") != call_id_reference:
                continue
            if event.get("from_tag_reference") != from_tag_reference:
                continue
            event_to = event.get("to_tag_reference")
            if event_to is None or event_to in dialog_tags:
                member_event_references.add(event_reference)
        event_references_by_logical[reference] = sorted(member_event_references)
        groups.append(
            {
                "logical_call_reference": reference,
                "grouping_status": status,
                "grouping_reason_codes": reasons,
                "member_attempt_references": member_attempts[:MAX_LIST_ITEMS],
                "member_sip_event_references": sorted(
                    member_event_references
                )[:MAX_LIST_ITEMS],
                "member_transaction_references": sorted(
                    member["transaction_reference"]
                    for member in members
                    if isinstance(member["transaction_reference"], str)
                )[:MAX_LIST_ITEMS],
                "member_dialog_references": sorted(
                    {
                        dialog
                        for member in members
                        for dialog in member["dialog_references"]
                    }
                )[:MAX_LIST_ITEMS],
                "source_frames": frames[:MAX_LIST_ITEMS],
                "cseq_values": cseq_values,
                "via_hop_counts": sorted(
                    {len(member["via_branches"]) for member in members}
                ),
                "identity_scope": "CAPTURE_SCOPED_HMAC_SHA256",
                "evidence_class": "DERIVED",
            }
        )

    for item in unresolved:
        reference = (
            f"ims-logical-call:{capture_file}:unresolved."
            f"{len(groups) + 1}"
        )
        attempt_to_logical[item["attempt_reference"]] = reference
        groups.append(
            {
                "logical_call_reference": reference,
                "grouping_status": "UNRESOLVED_IDENTITY",
                "grouping_reason_codes": [item["reason_code"]],
                "member_attempt_references": [item["attempt_reference"]],
                "member_sip_event_references": [],
                "member_transaction_references": [],
                "member_dialog_references": [],
                "source_frames": [],
                "cseq_values": [],
                "via_hop_counts": [],
                "identity_scope": None,
                "evidence_class": "DERIVED",
            }
        )

    status_counts: dict[str, int] = defaultdict(int)
    for group in groups:
        status_counts[group["grouping_status"]] += 1
    return {
        "logical_call_count": len(groups),
        "attempt_count": len(attempt_to_logical),
        "grouping_status_counts": dict(status_counts),
        "multi_hop_group_count": sum(
            1 for group in groups if group["grouping_status"] == "MULTI_HOP_PROVEN"
        ),
        "ambiguous_group_count": status_counts["AMBIGUOUS_MULTI_HOP"]
        + status_counts["UNRESOLVED_IDENTITY"],
        "unassigned_attempt_count": status_counts["UNRESOLVED_IDENTITY"],
        "attempt_to_logical_call": dict(sorted(attempt_to_logical.items())),
        "event_references_by_logical_call": {
            key: value
            for key, value in sorted(event_references_by_logical.items())
        },
        "logical_calls": groups,
        "limitations": [
            "Call-ID, From-tag and To-tag values are compared only as capture-scoped keyed HMAC references",
            "A shared Call-ID alone never groups attempts; CSeq, tag and Via-hop evidence must agree",
            "A B2BUA Call-ID change without an independent bridge remains unresolved and is never merged by time or endpoint equality",
        ],
        "not_confirmed": [
            "IMS_CALL_SUCCESS",
            "CALL_ID_VALUE",
            "B2BUA_CROSS_LEG_OWNERSHIP",
        ],
    }


def _boundary_frames(
    attempt: dict[str, Any], branch: dict[str, Any] | None, sip_by_ref: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    stages = attempt.get("stage_evidence") or {}
    ack = attempt.get("ack_evidence") or {}
    frames: dict[str, Any] = {
        "invite": _frame_of(attempt.get("initial_invite_event_reference")),
        "provisional": [],
        "final_2xx": [],
        "ack": [],
        "bye": [],
        "bye_response": [],
    }
    for reference in stages.get("provisional_response_event_references") or []:
        frame = _frame_of(reference)
        if frame is not None:
            frames["provisional"].append(frame)
    for reference in stages.get("accepted_2xx_event_references") or []:
        frame = _frame_of(reference)
        if frame is not None:
            frames["final_2xx"].append(frame)
    for reference in ack.get("twoxx_ack_event_references") or []:
        frame = _frame_of(reference)
        if frame is not None:
            frames["ack"].append(frame)
    if branch:
        for reference in branch.get("response_event_references") or []:
            frame = _frame_of(reference)
            if frame is not None:
                frames["final_2xx"].append(frame)
        for reference in branch.get("ack_event_references") or []:
            frame = _frame_of(reference)
            if frame is not None:
                frames["ack"].append(frame)
        for observation in (branch.get("release") or {}).get("observations") or []:
            for reference in observation.get("bye_request_event_references") or []:
                frame = _frame_of(reference)
                if frame is not None:
                    frames["bye"].append(frame)
            for reference in observation.get(
                "bye_final_response_event_references"
            ) or []:
                frame = _frame_of(reference)
                if frame is not None:
                    frames["bye_response"].append(frame)
    for key in ("provisional", "final_2xx", "ack", "bye", "bye_response"):
        frames[key] = sorted(set(frames[key]))
    frames["first_sip_frame"] = min(
        [frame for frame in (frames["invite"], *frames["provisional"], *frames["final_2xx"], *frames["ack"], *frames["bye"]) if frame is not None]
        or [0]
    ) or None
    frames["last_sip_frame"] = max(
        [frame for frame in (frames["invite"], *frames["provisional"], *frames["final_2xx"], *frames["ack"], *frames["bye"], *frames["bye_response"]) if frame is not None]
        or [0]
    ) or None
    return frames


def _temporal(
    rtp_frames: list[int],
    boundaries: dict[str, Any],
    *,
    ownership_ambiguous: bool,
    missing_identity: bool,
) -> dict[str, Any]:
    first_rtp = min(rtp_frames) if rtp_frames else None
    last_rtp = max(rtp_frames) if rtp_frames else None
    final_2xx = boundaries["final_2xx"][0] if boundaries["final_2xx"] else None
    bye = boundaries["bye"][0] if boundaries["bye"] else None
    flags: list[str] = []
    if first_rtp is not None and final_2xx is not None and first_rtp < final_2xx:
        flags.append("RTP_OBSERVED_BEFORE_INVITE_2XX")
    if last_rtp is not None and final_2xx is not None and last_rtp > final_2xx:
        flags.append("RTP_OBSERVED_AFTER_INVITE_2XX")
    if last_rtp is not None and bye is not None and last_rtp < bye:
        flags.append("RTP_OBSERVED_BEFORE_BYE")
    if first_rtp is not None and bye is not None and first_rtp > bye:
        flags.append("RTP_OBSERVED_AFTER_BYE")
    if ownership_ambiguous:
        status = "TEMPORAL_ASSOCIATION_AMBIGUOUS"
        reason = "AMBIGUOUS_TRANSPORT_OWNERSHIP"
    elif missing_identity or first_rtp is None or final_2xx is None:
        status = "TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE"
        reason = "MISSING_RTP_OR_INVITE_2XX_EVIDENCE"
    elif bye is not None and first_rtp > bye:
        status = "RTP_OBSERVED_AFTER_BYE"
        reason = "RTP_OBSERVED_AFTER_BYE_OBSERVATION_BOUNDARY"
    elif last_rtp is not None and last_rtp < final_2xx:
        status = "RTP_OBSERVED_BEFORE_INVITE_2XX"
        reason = "RTP_OBSERVED_BEFORE_INVITE_2XX_OBSERVATION_BOUNDARY"
    elif (
        first_rtp is not None
        and first_rtp >= final_2xx
        and (bye is None or (last_rtp is not None and last_rtp <= bye))
    ):
        status = "RTP_WITHIN_OBSERVED_SIGNALING_INTERVAL"
        reason = "RTP_WITHIN_OBSERVED_INVITE_2XX_TO_CAPTURE_END_OR_BYE"
    else:
        status = "TEMPORAL_ASSOCIATION_AMBIGUOUS"
        reason = "RTP_STRADDLES_SIGNALING_BOUNDARY"
    if "RTP_OBSERVED_AFTER_INVITE_2XX" not in flags and last_rtp is not None and final_2xx is not None and last_rtp >= final_2xx:
        flags.append("RTP_OBSERVED_AFTER_INVITE_2XX")
    return {
        "temporal_association_status": status,
        "reason_code": reason,
        "boundary_flags": sorted(set(flags)),
        "first_rtp_frame": first_rtp,
        "last_rtp_frame": last_rtp,
        "invite_frame": boundaries["invite"],
        "final_2xx_frames": boundaries["final_2xx"],
        "ack_frames": boundaries["ack"],
        "bye_frames": boundaries["bye"],
        "bye_response_frames": boundaries["bye_response"],
        "first_sip_frame": boundaries["first_sip_frame"],
        "last_sip_frame": boundaries["last_sip_frame"],
        "sip_to_rtp_ordering": (
            "NOT_ESTABLISHED"
            if first_rtp is None or boundaries["last_sip_frame"] is None
            else "RTP_AFTER_SIP"
            if first_rtp > boundaries["last_sip_frame"]
            else "RTP_BEFORE_SIP"
            if last_rtp is not None and last_rtp < (boundaries["first_sip_frame"] or 0)
            else "RTP_STRADDLES_SIP"
        ),
        "ownership_ambiguous": ownership_ambiguous,
        "missing_evidence": (
            ["TEMPORAL_OWNERSHIP_AMBIGUOUS"]
            if ownership_ambiguous
            else ["RTP_OBSERVATION_OR_INVITE_2XX_UNAVAILABLE"]
            if first_rtp is None or final_2xx is None
            else []
        ),
        "capture_boundary_limitations": [
            "SIP boundaries are observation boundaries, not the true start or end of RTP activity",
            "Capture start/end are unknown; no leading or trailing missing RTP is inferred",
            "A packet after BYE is not automatically an error; a missing packet after 2xx is not automatically a media failure",
        ],
        "evidence_class": "DERIVED",
    }


def _clock_rates_for_stream(
    stream: dict[str, Any], sdp_messages: list[dict[str, Any]]
) -> list[int]:
    payload_types = set(stream.get("observed_payload_types") or [])
    rates: set[int] = set()
    for message in sdp_messages:
        for media in message.get("media_sections") or []:
            for mapping in media.get("rtpmap") or []:
                if mapping.get("payload_type") in payload_types:
                    rate = mapping.get("clock_rate")
                    if isinstance(rate, int) and rate > 0:
                        rates.add(rate)
    return sorted(rates)


def _rtcp_association(
    capture_file: str,
    rtcp_events: list[dict[str, Any]],
    streams: list[dict[str, Any]],
    sdp_messages: list[dict[str, Any]],
    *,
    stream_ownership: dict[str, list[str]],
) -> dict[str, Any]:
    streams_by_key: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    streams_by_ssrc: dict[Any, list[dict[str, Any]]] = defaultdict(list)
    for stream in streams:
        streams_by_key[(stream.get("udp_stream"), stream.get("ssrc_reference"))].append(
            stream
        )
        streams_by_ssrc[stream.get("ssrc_reference")].append(stream)
    associations: list[dict[str, Any]] = []
    receiver_reports: list[dict[str, Any]] = []
    status_counts = {status: 0 for status in RTCP_STATUSES}
    unbound: list[dict[str, Any]] = []
    for event in rtcp_events:
        packet_type = event.get("packet_type")
        if packet_type in (200, 201):
            if packet_type == 200:
                sender_reference = event.get("sender_ssrc_reference")
                udp_candidates = streams_by_key.get(
                    (event.get("udp_stream"), sender_reference), []
                )
                ssrc_candidates = streams_by_ssrc.get(sender_reference, [])
                candidates = udp_candidates or ssrc_candidates
                status = (
                    "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
                    if len(udp_candidates) == 1
                    else "RTCP_STREAM_ASSOCIATION_AMBIGUOUS"
                    if len(ssrc_candidates) > 1
                    else "RTCP_STREAM_ASSOCIATION_INSUFFICIENT"
                )
                status_counts[status] += 1
                associations.append(
                    {
                        "rtcp_event_reference": event.get("event_reference"),
                        "packet_type": packet_type,
                        "association_kind": "SR_SENDER_SSRC",
                        "reporter_ssrc_reference": sender_reference,
                        "reportee_ssrc_reference": sender_reference,
                        "association_status": status,
                        "source_stream_references": [
                            item.get("source_stream_reference") for item in candidates
                        ][:MAX_LIST_ITEMS],
                        "ssrc_candidate_source_stream_references": [
                            item.get("source_stream_reference")
                            for item in ssrc_candidates
                        ][:MAX_LIST_ITEMS],
                        "udp_stream_candidate_source_stream_references": [
                            item.get("source_stream_reference")
                            for item in udp_candidates
                        ][:MAX_LIST_ITEMS],
                        "stream_ownership_attempt_references": {
                            item.get("source_stream_reference"): stream_ownership.get(
                                item.get("source_stream_reference"), []
                            )[:MAX_LIST_ITEMS]
                            for item in candidates
                        },
                        "udp_stream": event.get("udp_stream"),
                        "missing_evidence": (
                            ["EXACT_SENDER_STREAM_NOT_UNIQUE"]
                            if status == "RTCP_STREAM_ASSOCIATION_AMBIGUOUS"
                            else ["SENDER_SSRC_NOT_MATCHED_BY_EXACT_UDP_STREAM"]
                            if status == "RTCP_STREAM_ASSOCIATION_INSUFFICIENT"
                            else []
                        ),
                        "evidence_class": "DERIVED",
                    }
                )
            for block_index, block in enumerate(event.get("report_blocks") or []):
                reportee_reference = _ssrc_reference(
                    capture_file, block.get("reported_ssrc")
                )
                block_candidates = streams_by_ssrc.get(reportee_reference, [])
                block_status = (
                    "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
                    if len(block_candidates) == 1
                    else "RTCP_STREAM_ASSOCIATION_AMBIGUOUS"
                    if len(block_candidates) > 1
                    else "RTCP_STREAM_ASSOCIATION_INSUFFICIENT"
                )
                status_counts[block_status] += 1
                associations.append(
                    {
                        "rtcp_event_reference": event.get("event_reference"),
                        "packet_type": packet_type,
                        "association_kind": "REPORT_BLOCK",
                        "reporter_ssrc_reference": event.get("sender_ssrc_reference"),
                        "reportee_ssrc_reference": reportee_reference,
                        "association_status": block_status,
                        "source_stream_references": [
                            item.get("source_stream_reference")
                            for item in block_candidates
                        ][:MAX_LIST_ITEMS],
                        "stream_ownership_attempt_references": {
                            item.get("source_stream_reference"): stream_ownership.get(
                                item.get("source_stream_reference"), []
                            )[:MAX_LIST_ITEMS]
                            for item in block_candidates
                        },
                        "udp_stream": event.get("udp_stream"),
                        "missing_evidence": (
                            ["EXACT_REPORTEE_STREAM_NOT_UNIQUE"]
                            if block_status != "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
                            else []
                        ),
                        "evidence_class": "DERIVED",
                    }
                )
                rate = None
                if block_status == "RTCP_STREAM_ASSOCIATION_ESTABLISHED" and block_candidates:
                    rates = _clock_rates_for_stream(block_candidates[0], sdp_messages)
                    if len(rates) == 1:
                        rate = rates[0]
                jitter = block.get("interarrival_jitter")
                receiver_reports.append(
                    {
                        "source_event_reference": event.get("event_reference"),
                        "component_index": event.get("component_index"),
                        "report_block_index": block_index,
                        "reporter_ssrc_reference": event.get("sender_ssrc_reference"),
                        "reportee_ssrc_reference": reportee_reference,
                        "association_status": block_status,
                        "measurement_origin": "RECEIVER_REPORTED",
                        "fraction_lost": block.get("fraction_lost"),
                        "cumulative_packets_lost": block.get(
                            "cumulative_packets_lost"
                        ),
                        "interarrival_jitter_rtp_units": jitter,
                        "jitter_ms": (
                            round(jitter / rate * 1000, 6)
                            if isinstance(jitter, int) and rate
                            else None
                        ),
                        "jitter_ms_status": (
                            "DERIVED_FROM_UNIQUE_SDP_CLOCK_RATE"
                            if isinstance(jitter, int) and rate
                            else "AMBIGUOUS_SOURCE_ASSOCIATION"
                            if block_status == "RTCP_STREAM_ASSOCIATION_AMBIGUOUS"
                            else "INSUFFICIENT_SOURCE_ASSOCIATION"
                            if block_status == "RTCP_STREAM_ASSOCIATION_INSUFFICIENT"
                            else "RTP_CLOCK_RATE_NOT_PROVEN_FOR_ASSOCIATION"
                        ),
                        "rtp_clock_rate_hz": rate,
                        "extended_highest_sequence": block.get(
                            "extended_highest_sequence"
                        ),
                        "lsr": block.get("last_sr_timestamp"),
                        "dlsr": block.get("delay_since_last_sr"),
                        "source_stream_references": [
                            item.get("source_stream_reference")
                            for item in block_candidates
                        ][:MAX_LIST_ITEMS],
                        "evidence_class": "OBSERVED",
                    }
                )
            continue
        status = "RTCP_STREAM_ASSOCIATION_UNSUPPORTED"
        status_counts[status] += 1
        unbound.append(
            {
                "rtcp_event_reference": event.get("event_reference"),
                "packet_type": packet_type,
                "packet_type_name": event.get("packet_type_name"),
                "evidence_status": event.get("evidence_status"),
                "reason_code": "RTCP_COMPONENT_NOT_STREAM_ASSOCIATED",
                "evidence_class": "OBSERVED",
            }
        )
    return {
        "component_count": len(rtcp_events),
        "association_count": len(associations),
        "status_counts": status_counts,
        "associations": associations[:MAX_REPORTS],
        "unbound_component_count": len(unbound),
        "unbound_components": unbound[:MAX_REPORTS],
        "receiver_reported_quality": receiver_reports[:MAX_RECEIVER_REPORTS],
        "limitations": [
            "RTCP components are associated only by exact capture-scoped UDP stream and SSRC reference",
            "An exact SSRC match is one piece of evidence, not proof of call ownership",
            "Receiver-reported fraction lost, cumulative loss and jitter are not local measurements",
            "RTCP jitter is preserved in RTP timestamp units; milliseconds are derived only with a unique proven SDP clock rate",
            "No MOS, QoS or network-loss verdict is produced",
        ],
        "not_confirmed": [
            "LOCAL_PACKET_LOSS",
            "LOCAL_JITTER",
            "NETWORK_PACKET_LOSS",
            "MEDIA_QUALITY",
            "MOS",
            "RTCP_TO_CALL_OWNERSHIP",
        ],
    }


def build_diagnostics(
    *,
    capture: Path,
    capture_sha256: str,
    sip_events_path: Path,
    ims_session_path: Path,
    media_signaling_path: Path,
    sdp_path: Path,
    correlation_path: Path,
    rtp_rtcp_path: Path,
    rtp_stream_path: Path,
    frame_views: dict[int, dict[str, Any]] | None = None,
    frame_runner: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    sip_events = _load_jsonl(sip_events_path)
    ims_session = _load(ims_session_path) or {}
    media_signaling = _load(media_signaling_path) or {}
    sdp = _load(sdp_path) or {}
    correlation = _load(correlation_path) or {}
    rtp_rtcp = _load(rtp_rtcp_path) or {}
    rtp_stream = _load(rtp_stream_path) or {}
    capture_file = capture.name
    sip_by_ref = {
        event["source_reference"]: event
        for event in sip_events
        if isinstance(event.get("source_reference"), str)
    }
    sdp_by_ref = {
        message["source_reference"]: message
        for message in sdp.get("messages") or []
        if isinstance(message, dict) and isinstance(message.get("source_reference"), str)
    }
    exchanges = [
        item for item in media_signaling.get("exchanges") or [] if isinstance(item, dict)
    ]
    exchanges_by_attempt: dict[str, list[dict[str, Any]]] = defaultdict(list)
    exchanges_by_branch: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for exchange in exchanges:
        if isinstance(exchange.get("attempt_reference"), str):
            exchanges_by_attempt[exchange["attempt_reference"]].append(exchange)
        if isinstance(exchange.get("branch_reference"), str):
            exchanges_by_branch[exchange["branch_reference"]].append(exchange)
    correlations = [
        item for item in correlation.get("correlations") or [] if isinstance(item, dict)
    ]
    rtp_events = [
        event for event in rtp_rtcp.get("events") or []
        if isinstance(event, dict) and event.get("protocol") == "RTP"
    ]
    rtcp_events = [
        event for event in rtp_rtcp.get("events") or []
        if isinstance(event, dict) and event.get("protocol") == "RTCP"
    ]
    streams = [
        item for item in rtp_stream.get("source_streams") or [] if isinstance(item, dict)
    ]
    streams_by_udp: dict[int, list[dict[str, Any]]] = defaultdict(list)
    streams_by_key: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for stream in streams:
        udp = stream.get("udp_stream")
        if isinstance(udp, int):
            streams_by_udp[udp].append(stream)
        streams_by_key[(udp, stream.get("ssrc_reference"))].append(stream)
    rtp_by_key: dict[tuple[Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for event in rtp_events:
        rtp_by_key[(event.get("udp_stream"), event.get("ssrc_reference"))].append(event)
    if frame_views is None:
        frame_views = _frame_views(capture, frame_runner)

    # Build exact per-call correlation views.
    attempts_source = [
        item for item in ims_session.get("session_attempts") or [] if isinstance(item, dict)
    ]
    branches_by_attempt = {
        item["attempt_reference"]: item.get("branches") or []
        for item in attempts_source
        if isinstance(item.get("attempt_reference"), str)
    }
    logical_grouping = logical_call_grouping(
        capture_file, sip_by_ref, attempts_source, branches_by_attempt
    )
    attempt_to_logical = logical_grouping["attempt_to_logical_call"]
    logical_members: dict[str, list[str]] = defaultdict(list)
    for attempt_reference, logical_reference in attempt_to_logical.items():
        logical_members[logical_reference].append(attempt_reference)
    all_exchange_refs_by_attempt: dict[str, set[str]] = {}
    for attempt_reference, attempt_exchanges in exchanges_by_attempt.items():
        refs: set[str] = set()
        for exchange in attempt_exchanges:
            for key in ("offer_sdp_reference", "answer_sdp_reference"):
                if isinstance(exchange.get(key), str):
                    refs.add(exchange[key])
        all_exchange_refs_by_attempt[attempt_reference] = refs

    all_exchange_refs_by_logical: dict[str, set[str]] = {}
    for logical_reference, members in logical_members.items():
        refs: set[str] = set()
        for attempt_reference in members:
            refs.update(all_exchange_refs_by_attempt.get(attempt_reference, set()))
        all_exchange_refs_by_logical[logical_reference] = refs
    for logical_reference, event_references in (
        logical_grouping.get("event_references_by_logical_call") or {}
    ).items():
        event_reference_set = set(event_references)
        sdp_references = {
            reference for reference in sdp_by_ref if reference in event_reference_set
        }
        all_exchange_refs_by_logical.setdefault(logical_reference, set()).update(
            sdp_references
        )

    def correlation_attempt_details(
        corr: dict[str, Any],
    ) -> tuple[list[str], list[str], bool]:
        refs = {
            section.get("message_reference")
            for section in corr.get("sdp_media_sections") or []
            if isinstance(section, dict)
        }
        owners: list[str] = []
        exact: list[str] = []
        covered: set[str] = set()
        for logical_reference, sdp_refs in all_exchange_refs_by_logical.items():
            if refs & sdp_refs:
                owners.append(logical_reference)
            if refs and refs <= sdp_refs:
                exact.append(logical_reference)
                covered.update(sdp_refs)
        unowned = bool(refs - covered)
        if unowned:
            owners.append("UNOWNED_CORRELATION")
        return sorted(set(owners)), sorted(set(exact)), unowned

    stream_owners: dict[str, list[str]] = defaultdict(list)
    for corr in correlations:
        owners, _exact, _unowned = correlation_attempt_details(corr)
        owners = owners or ["UNOWNED_CORRELATION"]
        for stream_ref in corr.get("rtp_udp_stream_references") or []:
            stream_owners[stream_ref].extend(owners)
    stream_owners = {
        key: sorted(set(value)) for key, value in stream_owners.items()
    }
    stream_owner_by_source: dict[str, list[str]] = {}
    for stream in streams:
        udp = stream.get("udp_stream")
        source_ref = stream.get("source_stream_reference")
        if isinstance(source_ref, str) and isinstance(udp, int):
            stream_owner_by_source[source_ref] = stream_owners.get(
                f"rtp-udp-stream:{capture_file}:{udp}", []
            )

    attempt_records: list[dict[str, Any]] = []
    branch_records: list[dict[str, Any]] = []
    for attempt in sorted(
        attempts_source, key=lambda item: str(item.get("attempt_reference"))
    ):
        attempt_reference = attempt.get("attempt_reference")
        if not isinstance(attempt_reference, str):
            continue
        attempt_exchanges = exchanges_by_attempt.get(attempt_reference, [])
        exchange_refs = [exchange.get("exchange_reference") for exchange in attempt_exchanges]
        offer_refs = [exchange.get("offer_sdp_reference") for exchange in attempt_exchanges if isinstance(exchange.get("offer_sdp_reference"), str)]
        answer_refs = [exchange.get("answer_sdp_reference") for exchange in attempt_exchanges if isinstance(exchange.get("answer_sdp_reference"), str)]
        media_sections: list[dict[str, Any]] = []
        for reference in _unique(offer_refs + answer_refs):
            message = sdp_by_ref.get(reference) or {}
            for media in message.get("media_sections") or []:
                if not isinstance(media, dict):
                    continue
                media_sections.append(
                    {
                        "message_reference": reference,
                        "media_index": media.get("index"),
                        "media_type": media.get("media_type"),
                        "direction": media.get("direction"),
                        "mid": media.get("mid"),
                        "media_type_supported": media.get("media_type_supported"),
                        "transport_endpoint_reference": (media.get("transport_endpoint") or {}).get("endpoint_reference"),
                    }
                )
        relevant_correlations: list[dict[str, Any]] = []
        exact_correlations: list[dict[str, Any]] = []
        cross_correlations: list[dict[str, Any]] = []
        attempt_logical = attempt_to_logical.get(attempt_reference)
        for corr in correlations:
            owners, exact_owners, unowned = correlation_attempt_details(corr)
            if attempt_logical not in owners:
                continue
            relevant_correlations.append(corr)
            if exact_owners == [attempt_logical] and not unowned:
                exact_correlations.append(corr)
            if len(owners) > 1 or unowned:
                cross_correlations.append(corr)
        matched = [
            corr for corr in relevant_correlations
            if corr.get("association_status") in ("MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED")
        ]
        ambiguous = [
            corr for corr in relevant_correlations
            if corr.get("association_status") == "AMBIGUOUS"
        ]
        out_of_scope = [
            corr for corr in relevant_correlations
            if corr.get("association_status") == "OUT_OF_SCOPE"
        ]
        candidate_stream_refs = _unique(
            [
                stream.get("source_stream_reference")
                for corr in matched + ambiguous
                for udp in corr.get("rtp_udp_stream_references") or []
                for stream in streams_by_udp.get(_udp_stream(udp) or -1, [])
            ]
        )
        shared_streams = [
            stream_ref for stream_ref in candidate_stream_refs
            if len(stream_owner_by_source.get(stream_ref, [])) > 1
        ]
        rtp_frames = sorted(
            {
                event.get("frame_number")
                for stream_ref in candidate_stream_refs
                for stream in streams
                if stream.get("source_stream_reference") == stream_ref
                for event in rtp_by_key.get(
                    (stream.get("udp_stream"), stream.get("ssrc_reference")), []
                )
                if isinstance(event.get("frame_number"), int)
            }
        )
        ownership_ambiguous = bool(
            cross_correlations or shared_streams or (ambiguous and matched)
        )
        boundaries = _boundary_frames(attempt, None, sip_by_ref)
        temporal = _temporal(
            rtp_frames,
            boundaries,
            ownership_ambiguous=ownership_ambiguous,
            missing_identity=not candidate_stream_refs,
        )
        has_answer = bool(answer_refs)
        has_offer = bool(offer_refs)
        has_matched = bool(matched)
        exchange_established = any(
            exchange.get("association_status") == "ESTABLISHED"
            for exchange in attempt_exchanges
        )
        unsupported_sections = [
            section for section in media_sections
            if section.get("media_type_supported") is False
        ]
        if not attempt.get("initial_invite_event_reference"):
            call_status = "INSUFFICIENT_EVIDENCE"
        elif unsupported_sections and not media_sections:
            call_status = "UNSUPPORTED_PROCEDURE"
        elif ownership_ambiguous:
            call_status = "AMBIGUOUS_OWNERSHIP"
        elif exchange_established and has_offer and has_answer and has_matched and candidate_stream_refs and temporal["temporal_association_status"] not in (
            "TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE",
            "TEMPORAL_ASSOCIATION_AMBIGUOUS",
        ):
            call_status = "EVIDENCE_CHAIN_SUPPORTED"
        elif has_offer and has_answer and not has_matched:
            call_status = "PARTIAL_EVIDENCE"
        elif has_matched and candidate_stream_refs:
            call_status = "MEDIA_TRANSPORT_OBSERVED"
        elif has_offer or has_answer:
            call_status = "PARTIAL_EVIDENCE"
        elif attempt.get("initial_invite_event_reference"):
            call_status = "SIGNALING_ONLY"
        else:
            call_status = "INSUFFICIENT_EVIDENCE"

        missing: list[str] = []
        if not has_offer:
            missing.append("SDP_OFFER_NOT_OBSERVED")
        if not has_answer:
            missing.append("SDP_ANSWER_NOT_OBSERVED")
        if not relevant_correlations:
            missing.append("RTP_TRANSPORT_CORRELATION_NOT_OBSERVED")
        if ownership_ambiguous:
            missing.append("AMBIGUOUS_PER_CALL_TRANSPORT_OWNERSHIP")
        if not candidate_stream_refs:
            missing.append("RTP_SOURCE_STREAM_NOT_OBSERVED")
        if temporal["temporal_association_status"] in (
            "TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE",
            "TEMPORAL_ASSOCIATION_AMBIGUOUS",
        ):
            missing.append("TEMPORAL_ASSOCIATION_NOT_ESTABLISHED")
        if not rtcp_events:
            missing.append("RTCP_ASSOCIATION_NOT_OBSERVED")

        attempt_record = {
            "attempt_reference": attempt_reference,
            "initial_invite_transaction_reference": attempt.get("initial_invite_transaction_reference"),
            "initial_invite_event_reference": attempt.get("initial_invite_event_reference"),
            "invite_outcome": attempt.get("invite_outcome"),
            "signaling": {
                "first_observed_frame": attempt.get("first_observed_frame"),
                "last_observed_frame": attempt.get("last_observed_frame"),
                "provisional_response_event_references": list(
                    (attempt.get("stage_evidence") or {}).get(
                        "provisional_response_event_references"
                    )
                    or []
                )[:MAX_LIST_ITEMS],
                "final_response_event_references": list(
                    (attempt.get("stage_evidence") or {}).get(
                        "final_response_event_references"
                    )
                    or []
                )[:MAX_LIST_ITEMS],
                "ack_event_references": list(
                    (attempt.get("ack_evidence") or {}).get(
                        "twoxx_ack_event_references"
                    )
                    or []
                )[:MAX_LIST_ITEMS],
                "cancel_outcome": (attempt.get("cancel_evidence") or {}).get("outcome"),
                "release_outcome": (attempt.get("release_evidence") or {}).get("outcome"),
                "branch_count": int(attempt.get("branch_count") or 0),
            },
            "sdp": {
                "exchange_references": [ref for ref in exchange_refs if ref][:MAX_LIST_ITEMS],
                "offer_references": _unique(offer_refs)[:MAX_LIST_ITEMS],
                "answer_references": _unique(answer_refs)[:MAX_LIST_ITEMS],
                "offer_answer_status": (
                    "OBSERVED" if has_offer and has_answer else "INCOMPLETE" if has_offer else "NOT_OBSERVED"
                ),
                "media_sections": media_sections[:MAX_LIST_ITEMS],
                "missing_evidence": (
                    ["SDP_ANSWER_NOT_OBSERVED"] if not has_answer else []
                ),
            },
            "transport": {
                "logical_call_reference": attempt_logical,
                "correlation_references": [
                    corr.get("correlation_reference") for corr in relevant_correlations
                ][:MAX_LIST_ITEMS],
                "matched_correlation_references": [
                    corr.get("correlation_reference") for corr in matched
                ][:MAX_LIST_ITEMS],
                "ambiguous_correlation_references": [
                    corr.get("correlation_reference") for corr in ambiguous
                ][:MAX_LIST_ITEMS],
                "cross_attempt_correlation_references": [
                    corr.get("correlation_reference") for corr in cross_correlations
                ][:MAX_LIST_ITEMS],
                "candidate_rtp_udp_stream_references": _unique(
                    [
                        udp for corr in matched + ambiguous
                        for udp in corr.get("rtp_udp_stream_references") or []
                    ]
                )[:MAX_LIST_ITEMS],
                "candidate_source_stream_references": candidate_stream_refs[:MAX_LIST_ITEMS],
                "shared_source_stream_references": shared_streams[:MAX_LIST_ITEMS],
                "ownership_status": (
                    "AMBIGUOUS_OWNERSHIP"
                    if ownership_ambiguous
                    else "EXACT_REFERENCE_OWNED"
                    if exact_correlations
                    else "INSUFFICIENT_EVIDENCE"
                ),
                "missing_evidence": (
                    ["AMBIGUOUS_PER_CALL_TRANSPORT_OWNERSHIP"]
                    if ownership_ambiguous
                    else ["RTP_TRANSPORT_CORRELATION_NOT_OBSERVED"]
                    if not relevant_correlations
                    else []
                ),
            },
            "rtp": {
                "source_stream_references": candidate_stream_refs[:MAX_LIST_ITEMS],
                "rtp_packet_count": len(rtp_frames),
                "first_observed_frame": min(rtp_frames) if rtp_frames else None,
                "last_observed_frame": max(rtp_frames) if rtp_frames else None,
                "sequence_evidence": [
                    {
                        "source_stream_reference": stream.get("source_stream_reference"),
                        "sequence_validation_status": stream.get("sequence_validation_status"),
                        "rtp_packet_count": stream.get("rtp_packet_count"),
                        "sequence_wrap_count": stream.get("sequence_wrap_count"),
                        "duplicate_sequence_observation_count": stream.get(
                            "duplicate_sequence_observation_count"
                        ),
                        "out_of_order_packet_count": stream.get("out_of_order_packet_count"),
                        "observed_sequence_gap_count": stream.get("observed_sequence_gap_count"),
                        "unobserved_sequence_number_slot_count": stream.get(
                            "unobserved_sequence_number_slot_count"
                        ),
                        "restart_pattern_count": stream.get("restart_pattern_count"),
                    }
                    for stream in streams
                    if stream.get("source_stream_reference") in candidate_stream_refs
                ][:MAX_LIST_ITEMS],
                "missing_evidence": (
                    ["RTP_SOURCE_STREAM_NOT_OBSERVED"] if not candidate_stream_refs else []
                ),
            },
            "temporal": temporal,
            "evidence_status": call_status,
            "missing_evidence": _unique(missing)[:MAX_DIAGNOSTIC_ITEMS],
            "conflict_findings": (
                ["CAPTURE_WIDE_OR_CROSS_ATTEMPT_OWNERSHIP_REJECTED"]
                if ownership_ambiguous
                else []
            ),
            "diagnostic": {
                "last_supported_evidence": None,
                "first_missing_or_abnormal_boundary": None,
                "reason_codes": _unique(missing)[:MAX_DIAGNOSTIC_ITEMS],
                "excluded_interpretations": [
                    "CAPTURE_WIDE_AGGREGATE_COUNTS_ARE_NOT_CALL_OWNERSHIP",
                    "SEQUENCE_NUMBER_EQUALITY_IS_NOT_RETRANSMISSION",
                    "MISSING_RTCP_IS_NOT_MEDIA_QUALITY_FAILURE",
                    "ENDPOINT_EQUALITY_IS_NOT_IMS_CALL_IDENTITY",
                ],
                "additional_evidence_needed": (
                    [
                        "Provide per-call SDP/RTP reference ownership that excludes other attempts and branches.",
                        "Provide exact branch-scoped transport correlation rather than capture-wide endpoint correspondence.",
                    ]
                    if ownership_ambiguous
                    else []
                ),
                "evidence_class": "DERIVED",
            },
            "evidence_class": "DERIVED",
        }
        # Last supported evidence is scoped to this attempt, never a global max.
        owned_frames: list[tuple[int, str, str]] = []
        if isinstance(attempt.get("last_observed_frame"), int):
            owned_frames.append(
                (
                    attempt["last_observed_frame"],
                    "SIP",
                    attempt.get("initial_invite_event_reference") or "",
                )
            )
        for reference in _unique(offer_refs + answer_refs):
            frame = _frame_of(reference)
            if frame is not None:
                owned_frames.append((frame, "SDP", reference))
        if not ownership_ambiguous:
            for corr in exact_correlations:
                for reference in corr.get("rtp_event_references") or []:
                    frame = _frame_of(reference)
                    if frame is not None:
                        owned_frames.append((frame, "RTP", reference))
        if owned_frames:
            frame, stage, reference = max(owned_frames, key=lambda item: (item[0], item[2]))
            attempt_record["diagnostic"]["last_supported_evidence"] = {
                "stage": stage,
                "reference": reference,
                "frame_number": frame,
            }
        if missing:
            attempt_record["diagnostic"]["first_missing_or_abnormal_boundary"] = {
                "reason_code": missing[0],
                "evidence_status": "MISSING_OR_AMBIGUOUS_EVIDENCE",
                "last_supported_evidence": attempt_record["diagnostic"]["last_supported_evidence"],
            }
        attempt_records.append(attempt_record)

        for branch in attempt.get("branches") or []:
            if not isinstance(branch, dict):
                continue
            branch_reference = branch.get("branch_reference")
            branch_exchanges = exchanges_by_branch.get(branch_reference, [])
            branch_offer_refs = [
                exchange.get("offer_sdp_reference")
                for exchange in branch_exchanges
                if isinstance(exchange.get("offer_sdp_reference"), str)
            ]
            branch_answer_refs = [
                exchange.get("answer_sdp_reference")
                for exchange in branch_exchanges
                if isinstance(exchange.get("answer_sdp_reference"), str)
            ]
            branch_refs = set(branch_offer_refs + branch_answer_refs)
            branch_exact_corr: list[dict[str, Any]] = []
            branch_shared_corr: list[dict[str, Any]] = []
            for corr in relevant_correlations:
                corr_refs = {
                    section.get("message_reference")
                    for section in corr.get("sdp_media_sections") or []
                    if isinstance(section, dict)
                }
                if not (corr_refs & branch_refs):
                    continue
                if corr_refs <= branch_refs:
                    branch_exact_corr.append(corr)
                else:
                    branch_shared_corr.append(corr)
            branch_matched = [
                corr for corr in branch_exact_corr
                if corr.get("association_status") in ("MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED")
            ]
            branch_candidate_streams = _unique(
                [
                    stream.get("source_stream_reference")
                    for corr in branch_matched
                    for udp in corr.get("rtp_udp_stream_references") or []
                    for stream in streams_by_udp.get(_udp_stream(udp) or -1, [])
                ]
            )
            branch_shared = [
                ref for ref in branch_candidate_streams
                if len(stream_owner_by_source.get(ref, [])) > 1
            ]
            branch_boundaries = _boundary_frames(attempt, branch, sip_by_ref)
            branch_rtp_frames = sorted(
                {
                    event.get("frame_number")
                    for stream_ref in branch_candidate_streams
                    for stream in streams
                    if stream.get("source_stream_reference") == stream_ref
                    for event in rtp_by_key.get(
                        (stream.get("udp_stream"), stream.get("ssrc_reference")), []
                    )
                    if isinstance(event.get("frame_number"), int)
                }
            )
            branch_ambiguous = bool(branch_shared)
            branch_temporal = _temporal(
                branch_rtp_frames,
                branch_boundaries,
                ownership_ambiguous=branch_ambiguous,
                missing_identity=not branch_candidate_streams,
            )
            branch_status = (
                "INSUFFICIENT_EVIDENCE"
                if branch.get("identity_status") != "ESTABLISHED"
                else "AMBIGUOUS_OWNERSHIP"
                if branch_ambiguous
                else "EVIDENCE_CHAIN_SUPPORTED"
                if branch_exchanges
                and branch_answer_refs
                and branch_matched
                and branch_candidate_streams
                and branch_temporal["temporal_association_status"]
                not in ("TEMPORAL_ASSOCIATION_INSUFFICIENT_EVIDENCE", "TEMPORAL_ASSOCIATION_AMBIGUOUS")
                else "PARTIAL_EVIDENCE"
                if branch_offer_refs or branch_answer_refs or branch_shared_corr
                else "SIGNALING_ONLY"
            )
            branch_records.append(
                {
                    "attempt_reference": attempt_reference,
                    "branch_reference": branch_reference,
                    "dialog_reference": branch.get("dialog_reference"),
                    "fork_branch_reference": branch.get("fork_branch_reference"),
                    "identity_status": branch.get("identity_status"),
                    "dialog_state": branch.get("dialog_state"),
                    "invite_outcome": branch.get("outcome"),
                    "release_outcome": (branch.get("release") or {}).get("outcome"),
                    "exchange_references": [
                        exchange.get("exchange_reference") for exchange in branch_exchanges
                    ][:MAX_LIST_ITEMS],
                    "sdp_offer_references": _unique(branch_offer_refs)[:MAX_LIST_ITEMS],
                    "sdp_answer_references": _unique(branch_answer_refs)[:MAX_LIST_ITEMS],
                    "transport_correlation_references": [
                        corr.get("correlation_reference") for corr in branch_exact_corr
                    ][:MAX_LIST_ITEMS],
                    "shared_attempt_correlation_references": [
                        corr.get("correlation_reference") for corr in branch_shared_corr
                    ][:MAX_LIST_ITEMS],
                    "rtp_source_stream_references": branch_candidate_streams[:MAX_LIST_ITEMS],
                    "shared_source_stream_references": branch_shared[:MAX_LIST_ITEMS],
                    "temporal": branch_temporal,
                    "evidence_status": branch_status,
                    "ownership_scope": (
                        "ATTEMPT_SHARED"
                        if branch_shared_corr
                        or (
                            not branch_candidate_streams
                            and attempt_record["rtp"]["source_stream_references"]
                        )
                        else "BRANCH_SPECIFIC"
                        if branch_candidate_streams
                        else "NONE"
                    ),
                    "missing_evidence": [
                        item
                        for item in _unique(
                            [
                                "BRANCH_IDENTITY_NOT_ESTABLISHED"
                                if branch.get("identity_status") != "ESTABLISHED"
                                else None,
                                "BRANCH_SDP_ANSWER_NOT_OBSERVED"
                                if not branch_answer_refs
                                else None,
                                "BRANCH_TRANSPORT_CORRELATION_NOT_OBSERVED"
                                if not branch_matched
                                else None,
                                "AMBIGUOUS_BRANCH_TRANSPORT_OWNERSHIP"
                                if branch_ambiguous
                                else None,
                            ]
                        )
                        if item is not None
                    ][:MAX_DIAGNOSTIC_ITEMS],
                    "diagnostic": {
                        "last_supported_evidence": (
                            {
                                "stage": "SIP",
                                "reference": (branch.get("response_event_references") or [attempt.get("initial_invite_event_reference")])[0],
                                "frame_number": _frame_of((branch.get("response_event_references") or [attempt.get("initial_invite_event_reference")])[0]),
                            }
                            if branch.get("response_event_references")
                            else None
                        ),
                        "first_missing_or_abnormal_boundary": (
                            {
                                "reason_code": "AMBIGUOUS_BRANCH_TRANSPORT_OWNERSHIP"
                                if branch_ambiguous
                                else "BRANCH_MEDIA_EVIDENCE_INCOMPLETE",
                                "evidence_status": "MISSING_OR_AMBIGUOUS_EVIDENCE",
                            }
                            if branch_status != "EVIDENCE_CHAIN_SUPPORTED"
                            else None
                        ),
                        "excluded_interpretations": [
                            "A shared attempt-level stream is not duplicated into a branch-owned observation",
                            "A branch identity mismatch is not a network failure",
                        ],
                        "additional_evidence_needed": (
                            ["Provide branch-specific SDP and transport references that exclude other forks."]
                            if branch_status != "EVIDENCE_CHAIN_SUPPORTED"
                            else []
                        ),
                        "evidence_class": "DERIVED",
                    },
                    "evidence_class": "DERIVED",
                }
            )

    # RTCP association uses exact stream identity; call ownership is published separately.
    rtcp = _rtcp_association(
        capture_file,
        rtcp_events,
        streams,
        sdp.get("messages") or [],
        stream_ownership=stream_owner_by_source,
    )
    for attempt_record in attempt_records:
        attempt_streams = set(attempt_record["rtp"]["source_stream_references"])
        call_associations = [
            association for association in rtcp["associations"]
            if set(association.get("source_stream_references") or []) & attempt_streams
        ]
        call_reports = [
            report for report in rtcp["receiver_reported_quality"]
            if set(report.get("source_stream_references") or []) & attempt_streams
        ]
        attempt_record["rtcp"] = {
            "associations": call_associations[:MAX_LIST_ITEMS],
            "association_count": len(call_associations),
            "receiver_reported_quality": call_reports[:MAX_REPORTS],
            "receiver_report_count": len(call_reports),
            "ownership_status": (
                "AMBIGUOUS_OWNERSHIP"
                if attempt_record["evidence_status"] == "AMBIGUOUS_OWNERSHIP"
                else "EXACT_STREAM_ASSOCIATION"
                if call_associations
                else "INSUFFICIENT_EVIDENCE"
            ),
            "missing_evidence": (
                ["RTCP_STREAM_ASSOCIATION_NOT_OBSERVED"]
                if not call_associations
                else []
            ),
        }

    for branch_record in branch_records:
        branch_streams = set(branch_record.get("rtp_source_stream_references") or [])
        branch_associations = [
            association for association in rtcp["associations"]
            if set(association.get("source_stream_references") or []) & branch_streams
        ]
        branch_reports = [
            report for report in rtcp["receiver_reported_quality"]
            if set(report.get("source_stream_references") or []) & branch_streams
        ]
        branch_record["rtcp"] = {
            "associations": branch_associations[:MAX_LIST_ITEMS],
            "association_count": len(branch_associations),
            "receiver_reported_quality": branch_reports[:MAX_REPORTS],
            "receiver_report_count": len(branch_reports),
            "ownership_status": (
                "AMBIGUOUS_OWNERSHIP"
                if branch_record["evidence_status"] == "AMBIGUOUS_OWNERSHIP"
                else "EXACT_STREAM_ASSOCIATION"
                if branch_associations
                else "INSUFFICIENT_EVIDENCE"
            ),
            "missing_evidence": (
                ["BRANCH_RTCP_STREAM_ASSOCIATION_NOT_OBSERVED"]
                if not branch_associations
                else []
            ),
        }

    attempt_status_counts = {status: 0 for status in CALL_STATUSES}
    for attempt_record in attempt_records:
        attempt_status_counts[attempt_record["evidence_status"]] += 1
    branch_status_counts = {status: 0 for status in CALL_STATUSES}
    for branch_record in branch_records:
        branch_status_counts[branch_record["evidence_status"]] += 1
    temporal_counts: dict[str, int] = defaultdict(int)
    for attempt_record in attempt_records:
        temporal_counts[attempt_record["temporal"]["temporal_association_status"]] += 1
    for branch_record in branch_records:
        temporal_counts[branch_record["temporal"]["temporal_association_status"]] += 1
    duplicates = duplicate_investigation(
        capture_file, rtp_events, rtp_stream, frame_views
    )

    logical_records: list[dict[str, Any]] = []
    for group in logical_grouping["logical_calls"]:
        logical_reference = group["logical_call_reference"]
        members = group["member_attempt_references"]
        member_records = [
            record for record in attempt_records
            if record.get("attempt_reference") in members
        ]
        relevant: list[dict[str, Any]] = []
        exact: list[dict[str, Any]] = []
        competing: list[dict[str, Any]] = []
        for corr in correlations:
            owners, exact_owners, unowned = correlation_attempt_details(corr)
            if logical_reference not in owners:
                continue
            relevant.append(corr)
            if exact_owners == [logical_reference] and not unowned:
                exact.append(corr)
            if len(owners) > 1 or unowned:
                competing.append(corr)
        matched = [
            corr
            for corr in exact
            if corr.get("association_status")
            in ("MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED")
        ]
        candidate_transports = _unique(
            [
                udp
                for corr in matched
                for udp in corr.get("rtp_udp_stream_references") or []
            ]
        )
        source_streams = _unique(
            [
                stream.get("source_stream_reference")
                for udp in candidate_transports
                for stream in streams_by_udp.get(_udp_stream(udp) or -1, [])
            ]
        )
        has_offer = any(
            (record.get("sdp") or {}).get("offer_answer_status")
            in ("OBSERVED", "INCOMPLETE")
            for record in member_records
        )
        has_answer = any(
            (record.get("sdp") or {}).get("offer_answer_status") == "OBSERVED"
            for record in member_records
        )
        temporal_statuses = [
            (record.get("temporal") or {}).get("temporal_association_status")
            for record in member_records
            if (record.get("temporal") or {}).get("temporal_association_status")
        ]
        if temporal_statuses and all(
            status == "RTP_WITHIN_OBSERVED_SIGNALING_INTERVAL"
            for status in temporal_statuses
        ):
            temporal_status = "LOGICAL_CALL_TEMPORAL_CONSTRAINT_SATISFIED"
        elif "TEMPORAL_ASSOCIATION_AMBIGUOUS" in temporal_statuses:
            temporal_status = "LOGICAL_CALL_TEMPORAL_CONSTRAINT_AMBIGUOUS"
        else:
            temporal_status = "LOGICAL_CALL_TEMPORAL_CONSTRAINT_INSUFFICIENT"
        rtcp_associations = list(
            {
                (
                    association.get("rtcp_event_reference"),
                    association.get("association_kind"),
                    association.get("reportee_ssrc_reference"),
                ): association
                for record in member_records
                for association in (record.get("rtcp") or {}).get("associations") or []
            }.values()
        )
        receiver_reports = list(
            {
                (
                    report.get("source_event_reference"),
                    report.get("component_index"),
                    report.get("report_block_index"),
                ): report
                for record in member_records
                for report in (record.get("rtcp") or {}).get("receiver_reported_quality") or []
            }.values()
        )
        grouping_status = group.get("grouping_status")
        if competing:
            ownership_status = "AMBIGUOUS_OWNERSHIP"
        elif grouping_status in ("AMBIGUOUS_MULTI_HOP", "UNRESOLVED_IDENTITY"):
            ownership_status = "INSUFFICIENT_EVIDENCE"
        elif not matched or not has_offer or not has_answer or not source_streams:
            ownership_status = "INSUFFICIENT_EVIDENCE"
        else:
            ownership_status = "LOGICAL_CALL_MEDIA_OWNED"
        last_evidence = None
        for record in member_records:
            candidate = (record.get("diagnostic") or {}).get("last_supported_evidence")
            if isinstance(candidate, dict) and (
                last_evidence is None
                or (candidate.get("frame_number") or 0)
                > (last_evidence.get("frame_number") or 0)
            ):
                last_evidence = candidate
        missing = _unique(
            [
                item
                for record in member_records
                for item in record.get("missing_evidence") or []
            ]
        )
        logical_records.append(
            {
                "logical_call_reference": logical_reference,
                "grouping_status": grouping_status,
                "grouping_reason_codes": group.get("grouping_reason_codes"),
                "member_ims_attempt_references": members[:MAX_LIST_ITEMS],
                "member_sip_transaction_references": group.get(
                    "member_transaction_references"
                ),
                "member_sip_event_references": group.get(
                    "member_sip_event_references"
                ),
                "dialog_branch_references": group.get("member_dialog_references"),
                "offer_answer_exchange_references": _unique(
                    [
                        ref
                        for record in member_records
                        for ref in (record.get("sdp") or {}).get(
                            "exchange_references"
                        )
                        or []
                    ]
                )[:MAX_LIST_ITEMS],
                "accepted_media_sections": _unique(
                    [
                        section.get("message_reference")
                        for record in member_records
                        for section in (record.get("sdp") or {}).get(
                            "media_sections"
                        )
                        or []
                        if isinstance(section, dict)
                    ]
                )[:MAX_LIST_ITEMS],
                "candidate_rtp_transport_references": candidate_transports[
                    :MAX_LIST_ITEMS
                ],
                "source_stream_references": source_streams[:MAX_LIST_ITEMS],
                "temporal_constraints": {
                    "status": temporal_status,
                    "member_attempt_statuses": sorted(set(temporal_statuses)),
                    "capture_boundary_limitations": [
                        "SIP and RTP observations are capture-bound; no true media start or end is claimed",
                        "Temporal evidence narrows an already-supported identity candidate and never replaces identity",
                    ],
                },
                "rtcp_evidence": {
                    "association_count": len(rtcp_associations),
                    "receiver_report_count": len(receiver_reports),
                    "ownership_status": (
                        "AMBIGUOUS_OWNERSHIP"
                        if ownership_status != "LOGICAL_CALL_MEDIA_OWNED"
                        else "LOGICAL_CALL_RTCP_ASSOCIATED"
                        if rtcp_associations
                        else "INSUFFICIENT_EVIDENCE"
                    ),
                    "measurement_origin": (
                        "RECEIVER_REPORTED" if receiver_reports else None
                    ),
                },
                "ownership_status": ownership_status,
                "missing_and_ambiguous_evidence": missing[:MAX_DIAGNOSTIC_ITEMS],
                "last_supported_observation": last_evidence,
                "first_supported_diagnostic_boundary": (
                    None
                    if ownership_status == "LOGICAL_CALL_MEDIA_OWNED"
                    else {
                        "reason_code": (
                            "COMPETING_LOGICAL_CALL_MEDIA_OWNERSHIP"
                            if competing
                            else "LOGICAL_CALL_MEDIA_CHAIN_INCOMPLETE"
                        ),
                        "evidence_status": "MISSING_OR_AMBIGUOUS_EVIDENCE",
                    }
                ),
                "required_additional_evidence": (
                    []
                    if ownership_status == "LOGICAL_CALL_MEDIA_OWNED"
                    else [
                        "Provide SDP/RTP correspondence that excludes every competing logical call",
                        "Provide the missing SDP answer or source-stream evidence for this logical call",
                    ]
                ),
                "evidence_class": "DERIVED",
            }
        )
    logical_ownership_counts: dict[str, int] = defaultdict(int)
    for record in logical_records:
        logical_ownership_counts[record["ownership_status"]] += 1

    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "capability": CAPABILITY,
        "capture": {"file_name": capture_file, "sha256": capture_sha256},
        "input_provenance": {
            "sip_events_sha256": _sha256(sip_events_path),
            "ims_session_sha256": _sha256(ims_session_path),
            "media_signaling_sha256": _sha256(media_signaling_path),
            "sdp_analysis_sha256": _sha256(sdp_path),
            "transport_correlation_sha256": _sha256(correlation_path),
            "rtp_rtcp_analysis_sha256": _sha256(rtp_rtcp_path),
            "rtp_stream_analysis_sha256": _sha256(rtp_stream_path),
        },
        "attempt_count": len(attempt_records),
        "branch_count": len(branch_records),
        "attempts": attempt_records,
        "branches": branch_records,
        "logical_call_count": len(logical_records),
        "logical_calls": logical_records,
        "logical_call_ownership_counts": dict(logical_ownership_counts),
        "logical_call_grouping": {
            key: value
            for key, value in logical_grouping.items()
            if key != "logical_calls"
        },
        "call_evidence_summary": {
            "attempt_count": len(attempt_records),
            "branch_count": len(branch_records),
            "attempt_status_counts": attempt_status_counts,
            "branch_status_counts": branch_status_counts,
            "supported_attempt_count": attempt_status_counts["EVIDENCE_CHAIN_SUPPORTED"],
            "partial_attempt_count": attempt_status_counts["PARTIAL_EVIDENCE"]
            + attempt_status_counts["MEDIA_TRANSPORT_OBSERVED"],
            "ambiguous_attempt_count": attempt_status_counts["AMBIGUOUS_OWNERSHIP"],
            "signaling_only_attempt_count": attempt_status_counts["SIGNALING_ONLY"],
            "insufficient_attempt_count": attempt_status_counts["INSUFFICIENT_EVIDENCE"],
            "unsupported_attempt_count": attempt_status_counts["UNSUPPORTED_PROCEDURE"],
            "all_attempts_supported": (
                len(attempt_records) > 0
                and attempt_status_counts["EVIDENCE_CHAIN_SUPPORTED"] == len(attempt_records)
            ),
            "capture_wide_and_per_call_statuses_are_separate": True,
        },
        "duplicate_observation_investigation": duplicates,
        "temporal_association": {
            "status_counts": dict(sorted(temporal_counts.items())),
            "not_confirmed": [
                "RTP_DELIVERY",
                "TWO_WAY_AUDIO",
                "MEDIA_DELIVERY",
                "NETWORK_PACKET_LOSS",
            ],
            "limitations": [
                "SIP boundaries are observation boundaries, not true RTP start/end",
                "Temporal association does not upgrade transport or call ownership",
                "Capture boundaries remain unknown",
            ],
        },
        "rtcp_association": rtcp,
        "ambiguity_inventory": (
            [
                {
                    "scope": "ATTEMPT",
                    "reference": attempt["attempt_reference"],
                    "reason_code": "AMBIGUOUS_OWNERSHIP",
                    "shared_stream_references": attempt["transport"]["shared_source_stream_references"],
                    "cross_attempt_correlation_references": attempt["transport"]["cross_attempt_correlation_references"],
                }
                for attempt in attempt_records
                if attempt["evidence_status"] == "AMBIGUOUS_OWNERSHIP"
            ]
            + [
                {
                    "scope": "BRANCH",
                    "reference": branch["branch_reference"],
                    "reason_code": "AMBIGUOUS_BRANCH_TRANSPORT_OWNERSHIP",
                    "shared_stream_references": branch["shared_source_stream_references"],
                }
                for branch in branch_records
                if branch["evidence_status"] == "AMBIGUOUS_OWNERSHIP"
            ]
        )[:MAX_LIST_ITEMS],
        "missing_evidence_inventory": (
            [
                {
                    "scope": "ATTEMPT",
                    "reference": attempt["attempt_reference"],
                    "missing_evidence": attempt["missing_evidence"],
                }
                for attempt in attempt_records
                if attempt["missing_evidence"]
            ]
            + [
                {
                    "scope": "BRANCH",
                    "reference": branch["branch_reference"],
                    "missing_evidence": branch["missing_evidence"],
                }
                for branch in branch_records
                if branch["missing_evidence"]
            ]
        )[:MAX_LIST_ITEMS],
        "completeness": {
            "attempt_count": len(attempt_records),
            "branch_count": len(branch_records),
            "attempts_omitted": max(0, len(attempt_records) - MAX_REPORTS),
            "branches_omitted": max(0, len(branch_records) - MAX_REPORTS),
            "rtcp_component_count": len(rtcp_events),
            "rtp_observation_count": len(rtp_events),
        },
        "limitations": [
            "Per-call diagnostics consume accepted SIP, IMS Session, SDP, RTP/RTCP, RTP source-stream and SDP/RTP correlation artifacts; they decode and parse no protocol",
            "A capture-wide correlation is not per-call ownership; shared streams remain ambiguous",
            "A missing observation is not automatically an abnormal protocol boundary",
            "RTCP receiver-reported values are not local measurements",
            "No call success, RTP delivery, two-way audio, packet-loss, QoS or MOS verdict is produced",
        ],
        "not_confirmed": [
            "IMS_CALL_SUCCESS",
            "RTP_DELIVERY",
            "TWO_WAY_AUDIO",
            "CONFIRMED_NETWORK_PACKET_LOSS",
            "MEDIA_QOS",
            "MOS",
            "CALL_OWNED_RTP_STREAM",
            "RTCP_TO_CALL_OWNERSHIP",
            "TEMPORAL_RTP_OWNERSHIP",
        ],
        "evidence_class": "DERIVED",
    }


def _sha256(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()