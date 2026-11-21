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
ANALYSIS_VERSION = "0.5.0"
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


def _vantage_transport(view: dict[str, Any] | None) -> Any:
    if view is None:
        return None
    inner = view.get("inner_udp_stream")
    if inner is None:
        inner = view.get("outer_udp_stream")
    return inner


def _vantage_compatible(
    left: dict[str, Any] | None, right: dict[str, Any] | None
) -> bool:
    """Require a compatible inner transport path before claiming one packet."""
    left_transport = _vantage_transport(left)
    right_transport = _vantage_transport(right)
    if left_transport is None or right_transport is None:
        return False
    if left_transport != right_transport:
        return False
    for view in (left, right):
        protocols = (view or {}).get("protocols") or ""
        if "rtp" not in protocols.split(":"):
            return False
    return True


def duplicate_investigation(
    capture_file: str,
    rtp_events: list[dict[str, Any]],
    stream_document: dict[str, Any] | None,
    views: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    header_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    fingerprint_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    stream_byte_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
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
                fingerprint_groups[fingerprint].append(event)
                stream_byte_groups[
                    (event.get("udp_stream"), event.get("ssrc_reference"), fingerprint)
                ].append(event)
        sequence_groups[base].append(event)

    class_counts = {name: 0 for name in DUPLICATE_CLASSES}
    groups: list[dict[str, Any]] = []
    byte_identical_events = 0
    cross_stream_events = 0
    multi_vantage_supported = 0
    multi_vantage_consistent = 0
    multi_vantage_consistent_byte_events = 0
    header_signature_events = 0
    sequence_only_events = 0
    unresolved_events = 0
    classified_events: set[str] = set()
    byte_accounted_events: set[str] = set()
    vantage_counts: dict[str, int] = defaultdict(int)
    per_stream: dict[tuple[Any, Any], dict[str, int]] = defaultdict(
        lambda: {
            "raw": 0,
            "byte_identical": 0,
            "multi_vantage_supported": 0,
            "multi_vantage_consistent": 0,
            "header_signature": 0,
            "sequence_only": 0,
            "unresolved": 0,
            "cross_stream_collision": 0,
        }
    )
    for event in rtp_events:
        per_stream[(event.get("udp_stream"), event.get("ssrc_reference"))]["raw"] += 1

    # Independent streams may legitimately carry byte-identical packets. Keep
    # that byte identity visible without collapsing them into one observation.
    for fingerprint, events in fingerprint_groups.items():
        stream_keys = {
            (event.get("udp_stream"), event.get("ssrc_reference")) for event in events
        }
        if len(stream_keys) > 1:
            # The same bytes appear in independent streams. Record the
            # relationship; never merge the streams into one observation.
            cross_stream_events += len(stream_keys) - 1
            representatives = [
                min(
                    [
                        event
                        for event in events
                        if (event.get("udp_stream"), event.get("ssrc_reference"))
                        == stream_key
                    ],
                    key=lambda event: event.get("frame_number") or 0,
                )
                for stream_key in sorted(stream_keys, key=str)
            ]
            if len(groups) < MAX_GROUPS:
                groups.append(
                    {
                        "classification": "RTP_PACKET_BYTES_IDENTICAL",
                        "packet_identity_basis": "BYTE_IDENTICAL",
                        "physical_observation_grouped": False,
                        "cross_stream_collision": True,
                        "byte_identity_retained_without_physical_merge": True,
                        "reason_code": "INDEPENDENT_STREAM_BYTE_COLLISION",
                        "rtp_packet_fingerprint": fingerprint,
                        "stream_keys": [
                            {
                                "udp_stream": stream_key[0],
                                "ssrc_reference": stream_key[1],
                            }
                            for stream_key in sorted(stream_keys, key=str)
                        ][:MAX_LIST_ITEMS],
                        "event_references": [
                            event.get("event_reference")
                            for event in representatives
                        ][:MAX_LIST_ITEMS],
                        "frame_numbers": [
                            event.get("frame_number") for event in representatives
                        ][:MAX_LIST_ITEMS],
                        "retransmission_established": False,
                        "evidence_class": "DERIVED",
                    }
                )

    for (udp_stream, ssrc_reference, fingerprint), events in stream_byte_groups.items():
        if len(events) <= 1:
            continue
        stream_key = (udp_stream, ssrc_reference)
        for event in events:
            reference = event.get("event_reference")
            if isinstance(reference, str):
                byte_accounted_events.add(reference)
        base = events[0]
        base_view = views.get(base.get("frame_number"))
        for event in events[1:]:
            event_view = views.get(event.get("frame_number"))
            if base_view is None or event_view is None:
                classification = "RTP_PACKET_BYTES_IDENTICAL"
                vantage_status = "UNAVAILABLE"
                basis = "BYTE_IDENTICAL"
                byte_identical_events += 1
                per_stream[stream_key]["byte_identical"] += 1
            elif _view_signature(base_view) != _view_signature(event_view) and _vantage_compatible(
                base_view, event_view
            ):
                classification = "MULTI_VANTAGE_SUPPORTED"
                vantage_status = "COMPATIBLE_INNER_TRANSPORT"
                basis = "BYTE_IDENTICAL_AND_VIEW_COMPATIBLE"
                multi_vantage_supported += 1
                per_stream[stream_key]["multi_vantage_supported"] += 1
            elif _view_signature(base_view) != _view_signature(event_view):
                classification = "MULTI_VANTAGE_CONSISTENT"
                vantage_status = "VIEW_DIFFERS_TRANSPORT_UNPROVEN"
                basis = "BYTE_IDENTICAL_AND_VIEW_DIFFERS_ONLY"
                multi_vantage_consistent += 1
                multi_vantage_consistent_byte_events += 1
                per_stream[stream_key]["multi_vantage_consistent"] += 1
            else:
                classification = "RTP_PACKET_BYTES_IDENTICAL"
                vantage_status = "SAME_CAPTURE_VIEW"
                basis = "BYTE_IDENTICAL"
                byte_identical_events += 1
                per_stream[stream_key]["byte_identical"] += 1
            vantage_counts[vantage_status] += 1
            class_counts[classification] += 1
            reference = event.get("event_reference")
            if isinstance(reference, str):
                classified_events.add(reference)
            if len(groups) < MAX_GROUPS:
                groups.append(
                    {
                        "classification": classification,
                        "packet_identity_basis": basis,
                        "physical_observation_grouped": classification
                        == "MULTI_VANTAGE_SUPPORTED",
                        "vantage_evidence_status": vantage_status,
                        "rtp_packet_fingerprint": fingerprint,
                        "stream_key": {
                            "udp_stream": udp_stream,
                            "ssrc_reference": ssrc_reference,
                        },
                        "sequence_number": event.get("sequence_number"),
                        "rtp_timestamp": event.get("timestamp"),
                        "payload_type": event.get("payload_type"),
                        "packet_length": event.get("packet_length"),
                        "rtp_packet_byte_count": event.get("rtp_packet_byte_count"),
                        "event_references": [
                            base.get("event_reference"),
                            event.get("event_reference"),
                        ][:MAX_LIST_ITEMS],
                        "frame_numbers": [
                            base.get("frame_number"),
                            event.get("frame_number"),
                        ][:MAX_LIST_ITEMS],
                        "capture_views": [
                            base_view or {},
                            event_view or {},
                        ][:MAX_LIST_ITEMS],
                        "retransmission_established": False,
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
                and (
                    event.get("event_reference") in classified_events
                    or event.get("event_reference") in byte_accounted_events
                )
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
                        "physical_observation_grouped": False,
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
                        "retransmission_established": False,
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
                        "physical_observation_grouped": False,
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
        "distinct_byte_identity_count": len(stream_byte_groups),
        "distinct_fingerprint_value_count": len(fingerprint_groups),
        "header_signature_repeated_event_count": header_signature_repeated_event_count,
        "header_signature_match_event_count": (
            header_signature_events + multi_vantage_consistent + unresolved_events
        ),
        "byte_identical_duplicate_event_count": byte_identical_events,
        "multi_vantage_supported_event_count": multi_vantage_supported,
        "multi_vantage_consistent_event_count": multi_vantage_consistent,
        "multi_vantage_consistent_byte_event_count": multi_vantage_consistent_byte_events,
        "multi_vantage_event_count": multi_vantage_supported,
        "physical_observation_grouped_count": multi_vantage_supported,
        "cross_stream_byte_identity_collision_count": cross_stream_events,
        "vantage_evidence_status_counts": dict(sorted(vantage_counts.items())),
        "packet_identity_unresolved_event_count": unresolved_events,
        "duplicate_sequence_event_count": sequence_only_events,
        "potential_retransmission_event_count": 0,
        "exact_duplicate_event_count": byte_identical_events + multi_vantage_supported,
        "exact_duplicate_event_count_basis": "RTP_PACKET_BYTES_IDENTICAL",
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
            "MULTI_VANTAGE_SUPPORTED requires matching complete RTP packet bytes and a compatible inner transport path",
            "Byte-identical packets in different streams are never collapsed into one physical observation",
            "Different frame views combined with the same header tuple are only header-signature coincidence",
            "Sequence-number equality alone is never promoted to a same-packet or retransmission classification",
        ],
        "not_confirmed": [
            "NETWORK_RETRANSMISSION",
            "NETWORK_PACKET_LOSS",
            "CAPTURE_POINT_TOPOLOGY",
            "SINGLE_PHYSICAL_PACKET_OBSERVED_TWICE",
        ],
    }


def _via_chain_analysis(sequences: list[list[str]]) -> dict[str, Any]:
    """Classify Via-stack nesting into zero, one or several forwarding chains.

    A coherent forwarding chain has exactly one maximal (outermost) stack and
    every shorter stack is its ordered suffix. Two different maximal stacks are
    competing chains, even when they share a common trunk.
    """
    unique: list[list[str]] = []
    for sequence in sequences:
        if not sequence:
            continue
        if sequence not in unique:
            unique.append(sequence)
    result: dict[str, Any] = {
        "unique_stack_count": len(unique),
        "chain_count": len(unique),
        "coherent": False,
        "incompatible": False,
        "maximal_stack_count": 0,
    }
    if len(unique) < 2:
        return result
    maximal = [
        candidate
        for candidate in unique
        if not any(
            len(other) > len(candidate) and other[-len(candidate):] == candidate
            for other in unique
        )
    ]
    result["maximal_stack_count"] = len(maximal)
    orphans = [
        candidate
        for candidate in unique
        if candidate not in maximal
        and not any(
            len(stack) > len(candidate) and stack[-len(candidate):] == candidate
            for stack in maximal
        )
    ]
    if len(maximal) == 1 and not orphans:
        result["coherent"] = True
        result["chain_count"] = 1
        return result
    result["incompatible"] = True
    result["chain_count"] = len(maximal) + len(orphans)
    return result


def _collect_sip_references(value: Any) -> set[str]:
    """Collect every capture-scoped SIP event reference inside an accepted record."""
    found: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, str):
            if item.startswith("sip-event:"):
                found.add(item)
        elif isinstance(item, dict):
            for nested in item.values():
                walk(nested)
        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(value)
    return found


def _cseq_method(event: dict[str, Any]) -> str | None:
    headers = event.get("headers") or {}
    cseq = headers.get("cseq") if isinstance(headers, dict) else None
    if not isinstance(cseq, dict):
        return None
    method = cseq.get("method")
    return method if isinstance(method, str) else None


def _dialog_remote_tag(
    branch: dict[str, Any], sip_by_ref: dict[str, dict[str, Any]]
) -> str | None:
    for reference in branch.get("response_event_references") or []:
        event = sip_by_ref.get(reference)
        if isinstance(event, dict) and isinstance(event.get("to_tag_reference"), str):
            return event["to_tag_reference"]
    return None


def logical_call_grouping(
    capture_file: str,
    sip_by_ref: dict[str, dict[str, Any]],
    attempts: list[dict[str, Any]],
    branches_by_attempt: dict[str, list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Group initial INVITE attempts by proven capture-scoped SIP identity.

    Grouping requires an established identity reference, a confirmed INVITE
    method and CSeq, and for a multi-hop chain an ordered nested Via stack with
    a single coherent forwarding relationship. Differing CSeq values never merge
    without an accepted Dialog bridge.
    """
    branches_by_attempt = branches_by_attempt or {}
    unresolved: list[dict[str, Any]] = []
    families: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
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
        cseq_method = _cseq_method(event)
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
        if event.get("method") != "INVITE" or event.get("message_type") != "REQUEST":
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "INITIAL_INVITE_METHOD_NOT_CONFIRMED",
                }
            )
            continue
        if isinstance(cseq, bool) or not isinstance(cseq, int) or cseq < 0:
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "CSEQ_NOT_ESTABLISHED",
                }
            )
            continue
        if cseq_method != "INVITE":
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "CSEQ_METHOD_MISMATCH",
                }
            )
            continue
        via_meta = (event.get("headers") or {}).get("via") or {}
        declared_via_count = via_meta.get("count")
        if (
            isinstance(declared_via_count, int)
            and declared_via_count > len(event.get("via_branch_references") or [])
        ):
            unresolved.append(
                {
                    "attempt_reference": attempt_reference,
                    "reason_code": "VIA_HOP_IDENTITY_INCOMPLETE",
                }
            )
            continue
        transaction_reference = attempt.get("initial_invite_transaction_reference")
        branches = branches_by_attempt.get(attempt_reference, [])
        dialogs = [
            {
                "dialog_reference": branch.get("dialog_reference"),
                "remote_tag": _dialog_remote_tag(branch, sip_by_ref),
            }
            for branch in branches
            if isinstance(branch, dict)
            and branch.get("identity_status") == "ESTABLISHED"
            and isinstance(branch.get("dialog_reference"), str)
        ]
        families[(call_id_reference, from_tag_reference)].append(
            {
                "attempt_reference": attempt_reference,
                "attempt_object": attempt,
                "event_reference": invite_reference,
                "frame_number": event.get("frame_number"),
                "cseq": cseq,
                "to_tag": to_tag_reference if isinstance(to_tag_reference, str) else None,
                "via_branches": list(event.get("via_branch_references") or []),
                "transaction_reference": transaction_reference,
                "dialogs": dialogs,
                "identity_scope": event.get("identity_reference_scope"),
            }
        )

    group_specs: list[dict[str, Any]] = []

    def add_group(members: list[dict[str, Any]], status: str, reasons: list[str]) -> None:
        group_specs.append(
            {
                "members": members,
                "status": status,
                "reasons": reasons,
                "call_id_reference": family_key[0],
                "from_tag_reference": family_key[1],
            }
        )

    for family_key, family in families.items():
        initial = [member for member in family if member["to_tag"] is None]
        in_dialog = [member for member in family if member["to_tag"] is not None]

        initial_units: list[dict[str, Any]] = []
        by_cseq: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for member in initial:
            by_cseq[member["cseq"]].append(member)
        for cseq_value in sorted(by_cseq):
            members = sorted(by_cseq[cseq_value], key=lambda item: item["frame_number"] or 0)
            if len(members) == 1:
                unit = {
                    "members": members,
                    "status": "SINGLE_ATTEMPT",
                    "reasons": ["EXACTLY_ONE_INITIAL_INVITE_ATTEMPT"],
                    "cseq": cseq_value,
                }
                initial_units.append(unit)
                continue
            if any(not member["via_branches"] for member in members):
                unit = {
                    "members": members,
                    "status": "AMBIGUOUS_MULTI_HOP",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_CSEQ_SEQUENCE",
                        "VIA_HOP_IDENTITY_MISSING",
                    ],
                    "cseq": cseq_value,
                }
                initial_units.append(unit)
                continue
            chains = _via_chain_analysis([member["via_branches"] for member in members])
            transactions = [member["transaction_reference"] for member in members]
            independent_transactions = all(
                isinstance(value, str) for value in transactions
            ) and len(set(transactions)) == len(transactions)
            if not independent_transactions:
                unit = {
                    "members": members,
                    "status": "AMBIGUOUS_MULTI_HOP",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_CSEQ_SEQUENCE",
                        "TRANSACTION_OWNERSHIP_NOT_INDEPENDENT",
                    ],
                    "cseq": cseq_value,
                }
            elif chains["coherent"]:
                unit = {
                    "members": members,
                    "status": "MULTI_HOP_PROVEN",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_TO_TAG_STATE",
                        "SAME_CSEQ_SEQUENCE",
                        "VIA_HOP_STACK_NESTED",
                        "SINGLE_FORWARDING_CHAIN",
                        "DISTINCT_SOURCE_FRAMES",
                    ],
                    "cseq": cseq_value,
                    "via_chain": chains,
                }
            elif chains["unique_stack_count"] == 1:
                unit = {
                    "members": members,
                    "status": "REPEATED_OBSERVATION_ONLY",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_CSEQ_SEQUENCE",
                        "IDENTICAL_VIA_HOP_STACK",
                        "DISTINCT_SOURCE_FRAMES",
                    ],
                    "cseq": cseq_value,
                }
            elif chains["maximal_stack_count"] > 1:
                unit = {
                    "members": members,
                    "status": "AMBIGUOUS_MULTI_HOP",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_CSEQ_SEQUENCE",
                        "COMPETING_VIA_FORWARDING_CHAINS",
                    ],
                    "cseq": cseq_value,
                    "via_chain": chains,
                }
            else:
                unit = {
                    "members": members,
                    "status": "AMBIGUOUS_MULTI_HOP",
                    "reasons": [
                        "SAME_CALL_ID_REFERENCE",
                        "SAME_FROM_TAG_REFERENCE",
                        "SAME_CSEQ_SEQUENCE",
                        "VIA_HOP_RELATION_UNPROVEN",
                    ],
                    "cseq": cseq_value,
                }
            initial_units.append(unit)

        # Proven in-dialog re-INVITEs join an initial unit only through an
        # accepted Dialog bridge whose remote tag matches the request's To-tag.
        for member in in_dialog:
            owners = [
                unit
                for unit in initial_units
                if any(
                    dialog.get("remote_tag") == member["to_tag"]
                    for attempt_member in unit["members"]
                    for dialog in attempt_member["dialogs"]
                )
            ]
            if len(owners) == 1 and member["cseq"] not in {
                attempt_member["cseq"] for attempt_member in owners[0]["members"]
            }:
                owner = owners[0]
                owner["members"].append(member)
                owner["status"] = "IN_DIALOG_SEQUENCE"
                owner["reasons"] = [
                    "SAME_CALL_ID_REFERENCE",
                    "SAME_FROM_TAG_REFERENCE",
                    "ACCEPTED_DIALOG_BRIDGE",
                    "DISTINCT_CSEQ_SEQUENCES",
                ]
            elif len(owners) > 1:
                unresolved.append(
                    {
                        "attempt_reference": member["attempt_reference"],
                        "reason_code": "AMBIGUOUS_DIALOG_BRIDGE",
                    }
                )
            else:
                add_group(
                    [member],
                    "SINGLE_ATTEMPT",
                    [
                        "DISTINCT_DIALOG_IDENTITY",
                        "NO_ACCEPTED_DIALOG_BRIDGE",
                    ],
                )

        for unit in initial_units:
            add_group(unit["members"], unit["status"], unit["reasons"])

    groups: list[dict[str, Any]] = []
    attempt_to_logical: dict[str, str] = {}
    event_references_by_logical: dict[str, list[str]] = {}
    unbound_event_references: dict[str, list[str]] = {}
    excluded_identity_events: dict[str, list[str]] = {}
    accepted_groups: dict[str, bool] = {}
    ordered_specs = sorted(
        group_specs,
        key=lambda spec: (
            min((member["frame_number"] or 0) for member in spec["members"]),
            min(member["attempt_reference"] for member in spec["members"]),
        ),
    )
    for index, spec in enumerate(ordered_specs, start=1):
        members = sorted(spec["members"], key=lambda item: item["attempt_reference"])
        frames = sorted({member["frame_number"] or 0 for member in members})
        first_frame = frames[0] if frames else 0
        reference = f"ims-logical-call:{capture_file}:{first_frame}.{index}"
        call_id_reference = spec["call_id_reference"]
        from_tag_reference = spec["from_tag_reference"]
        accepted_references: set[str] = set()
        for member in members:
            accepted_references.update(_collect_sip_references(member["attempt_object"]))
            accepted_references.add(member["event_reference"])
        member_event_references: set[str] = set()
        mismatched: set[str] = set()
        for event_reference in accepted_references:
            event = sip_by_ref.get(event_reference)
            if not isinstance(event, dict):
                mismatched.add(event_reference)
                continue
            if event.get("call_id_reference") != call_id_reference:
                mismatched.add(event_reference)
                continue
            event_from = event.get("from_tag_reference")
            if isinstance(event_from, str) and event_from != from_tag_reference:
                mismatched.add(event_reference)
                continue
            member_event_references.add(event_reference)
        family_events = {
            event_reference
            for event_reference, event in sip_by_ref.items()
            if event.get("call_id_reference") == call_id_reference
            and event.get("from_tag_reference") == from_tag_reference
        }
        event_references_by_logical[reference] = sorted(member_event_references)
        unbound_event_references[reference] = sorted(family_events - member_event_references)
        excluded_identity_events[reference] = sorted(mismatched)
        status = spec["status"]
        accepted = status in (
            "SINGLE_ATTEMPT",
            "MULTI_HOP_PROVEN",
            "REPEATED_OBSERVATION_ONLY",
        ) or (status == "IN_DIALOG_SEQUENCE" and "ACCEPTED_DIALOG_BRIDGE" in spec["reasons"])
        accepted_groups[reference] = accepted
        for member in members:
            attempt_to_logical[member["attempt_reference"]] = reference
        groups.append(
            {
                "logical_call_reference": reference,
                "grouping_status": status,
                "grouping_accepted": accepted,
                "grouping_reason_codes": spec["reasons"],
                "member_attempt_references": [
                    member["attempt_reference"] for member in members
                ][:MAX_LIST_ITEMS],
                "member_sip_event_references": sorted(member_event_references)[:MAX_LIST_ITEMS],
                "member_transaction_references": sorted(
                    {
                        member["transaction_reference"]
                        for member in members
                        if isinstance(member["transaction_reference"], str)
                    }
                )[:MAX_LIST_ITEMS],
                "member_dialog_references": sorted(
                    {
                        dialog["dialog_reference"]
                        for member in members
                        for dialog in member["dialogs"]
                    }
                )[:MAX_LIST_ITEMS],
                "source_frames": frames[:MAX_LIST_ITEMS],
                "cseq_values": sorted({member["cseq"] for member in members}),
                "via_hop_counts": sorted(
                    {len(member["via_branches"]) for member in members}
                ),
                "via_forwarding_chain_count": (
                    spec.get("via_chain", {}).get("chain_count")
                    if isinstance(spec.get("via_chain"), dict)
                    else 1
                    if len(members) == 1
                    else None
                ),
                "identity_scope": next(
                    (
                        member["identity_scope"]
                        for member in members
                        if isinstance(member["identity_scope"], str)
                    ),
                    None,
                ),
                "unbound_sip_event_reference_count": len(
                    family_events - member_event_references
                ),
                "evidence_class": "DERIVED",
            }
        )

    for item in unresolved:
        reference = (
            f"ims-logical-call:{capture_file}:unresolved."
            f"{len(groups) + 1}"
        )
        attempt_to_logical[item["attempt_reference"]] = reference
        accepted_groups[reference] = False
        groups.append(
            {
                "logical_call_reference": reference,
                "grouping_status": "UNRESOLVED_IDENTITY",
                "grouping_accepted": False,
                "grouping_reason_codes": [item["reason_code"]],
                "member_attempt_references": [item["attempt_reference"]],
                "member_sip_event_references": [],
                "member_transaction_references": [],
                "member_dialog_references": [],
                "source_frames": [],
                "cseq_values": [],
                "via_hop_counts": [],
                "via_forwarding_chain_count": None,
                "identity_scope": None,
                "unbound_sip_event_reference_count": None,
                "evidence_class": "DERIVED",
            }
        )

    status_counts: dict[str, int] = defaultdict(int)
    for group in groups:
        status_counts[group["grouping_status"]] += 1
    return {
        "logical_call_count": len(groups),
        "attempt_count": len(attempt_to_logical),
        "accepted_logical_call_count": sum(1 for value in accepted_groups.values() if value),
        "grouping_status_counts": dict(status_counts),
        "multi_hop_group_count": sum(
            1 for group in groups if group["grouping_status"] == "MULTI_HOP_PROVEN"
        ),
        "ambiguous_group_count": status_counts["AMBIGUOUS_MULTI_HOP"]
        + status_counts["UNRESOLVED_IDENTITY"],
        "unassigned_attempt_count": status_counts["UNRESOLVED_IDENTITY"],
        "attempt_to_logical_call": dict(sorted(attempt_to_logical.items())),
        "accepted_logical_call": dict(sorted(accepted_groups.items())),
        "event_references_by_logical_call": {
            key: value for key, value in sorted(event_references_by_logical.items())
        },
        "unbound_event_references_by_logical_call": {
            key: value for key, value in sorted(unbound_event_references.items())
        },
        "excluded_identity_event_references_by_logical_call": {
            key: value for key, value in sorted(excluded_identity_events.items())
        },
        "logical_calls": groups,
        "limitations": [
            "Call-ID, From-tag and To-tag values are compared only as capture-scoped keyed references",
            "A shared Call-ID alone never groups attempts; CSeq, tag, Via-hop and transaction evidence must agree",
            "Differing CSeq values merge only through an accepted Dialog bridge",
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
    PROTOCOL_VIOLATION_FINDINGS = {
        "MISSING_START_LINE",
        "MISSING_STATUS_CODE",
        "INVALID_STATUS_CODE",
        "HEADER_NOT_TERMINATED",
        "HEADER_NO_COLON",
    }

    def _status_of(reference: Any) -> int | None:
        event = sip_by_ref.get(reference) if isinstance(reference, str) else None
        if not isinstance(event, dict):
            return None
        status = event.get("status_code")
        return status if isinstance(status, int) else None

    def _sip_outcome_record(
        status_codes: list[int],
        response_references: list[str],
        *,
        cancel_evidence: dict[str, Any] | None = None,
        identity_ambiguous: bool = False,
        other_branch_accepted: bool = False,
        allow_contradiction: bool = True,
        provisional_status_codes: list[int] | None = None,
        association_basis: str = "TRANSACTION_OR_BRANCH_CONTEXT",
        transaction_ownership_established: bool = True,
    ) -> dict[str, Any]:
        statuses = sorted(
            {
                status
                for status in status_codes
                if isinstance(status, int) and status >= 200
            }
        )
        positive = any(200 <= status < 300 for status in statuses)
        negative = any(status >= 300 for status in statuses)
        challenge_statuses = sorted(
            status for status in statuses if status in (401, 407)
        )
        authentication_challenge = bool(statuses) and all(
            status in (401, 407) for status in statuses
        )
        violation_findings = sorted(
            {
                finding
                for reference in response_references
                for event in (sip_by_ref.get(reference),)
                if isinstance(event, dict)
                for finding in event.get("integrity_findings") or []
                if finding in PROTOCOL_VIOLATION_FINDINGS
            }
        )
        contradictions: list[str] = []
        if allow_contradiction and positive and negative:
            contradictions.append("CONFLICTING_FINAL_RESPONSES_FOR_ONE_TRANSACTION")
        cancel = cancel_evidence if isinstance(cancel_evidence, dict) else {}
        cancel_conflicts = list(cancel.get("conflict_findings") or [])
        if "CANCEL_AFTER_INVITE_FINAL_RESPONSE" in cancel_conflicts:
            contradictions.append("CANCEL_AFTER_INVITE_FINAL_RESPONSE")
        cancel_statuses = list(cancel.get("cancel_final_response_status_codes") or [])
        cancel_established = bool(
            cancel.get("association_status") == "ASSOCIATED"
            and cancel.get("invite_final_response_status") == 487
            and 487 in statuses
            and cancel.get("cancel_request_event_references")
            and cancel.get("cancel_final_response_event_references")
            and 200 in cancel_statuses
            and cancel.get("outcome")
            in ("CANCEL_INVITE_SEQUENCE_OBSERVED", "CANCEL_RESPONSE_OBSERVED")
        )
        fork_negative = bool(
            other_branch_accepted and negative and not positive
        )
        if violation_findings:
            classification = "SIP_PROTOCOL_VIOLATION_EVIDENCE"
        elif contradictions:
            classification = "SIP_PROCEDURE_CONTRADICTION_OBSERVED"
        elif cancel_established:
            classification = "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED"
        elif positive:
            classification = "SIP_POSITIVE_FINAL_OUTCOME_OBSERVED"
        elif authentication_challenge:
            classification = "SIP_AUTHENTICATION_CHALLENGE_OBSERVED"
        elif fork_negative:
            classification = "SIP_FORK_BRANCH_NEGATIVE_OUTCOME_OBSERVED"
        elif negative:
            classification = "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
        elif identity_ambiguous:
            classification = "SIP_OUTCOME_IDENTITY_AMBIGUOUS"
        else:
            classification = "SIP_FINAL_OUTCOME_NOT_OBSERVED"

        next_checks: list[str] = []
        if classification == "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED":
            next_checks.append(
                "Provide the endpoint or policy event that triggered the CANCEL; this capture does not establish why cancellation occurred."
            )
        elif classification == "SIP_AUTHENTICATION_CHALLENGE_OBSERVED":
            next_checks.append(
                "Provide the authorized retry and its final response; an authentication challenge does not prove an authentication failure."
            )
        elif classification in (
            "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED",
            "SIP_FORK_BRANCH_NEGATIVE_OUTCOME_OBSERVED",
        ):
            next_checks.append(
                "Provide endpoint or service logs covering the rejected branch and any Reason header context."
            )
        elif classification == "SIP_PROTOCOL_VIOLATION_EVIDENCE":
            next_checks.append(
                "Validate the malformed response against RFC 3261 message syntax with a reviewed decoder trace."
            )
        elif classification == "SIP_PROCEDURE_CONTRADICTION_OBSERVED":
            next_checks.append(
                "Provide every final response observed for this transaction with its branch identity."
            )
        elif classification == "SIP_FINAL_OUTCOME_NOT_OBSERVED":
            next_checks.append(
                "Provide a capture view covering the response direction; absence is not evidence of a timeout."
            )

        return {
            "classification": classification,
            "final_status_codes": statuses,
            "final_response_references": sorted(set(response_references))[:MAX_LIST_ITEMS],
            "provisional_status_codes": sorted(
                {
                    status
                    for status in (provisional_status_codes or [])
                    if isinstance(status, int) and 100 <= status < 200
                }
            ),
            "positive_final_response_observed": positive,
            "negative_final_response_observed": negative,
            "authentication_challenge_observed": authentication_challenge,
            "authentication_challenge_status_codes": challenge_statuses,
            "cancel_relationship_established": cancel_established,
            "cancel_transaction_references": list(
                cancel.get("cancel_transaction_references") or []
            )[:MAX_LIST_ITEMS],
            "cancel_request_event_references": list(
                cancel.get("cancel_request_event_references") or []
            )[:MAX_LIST_ITEMS],
            "cancel_response_event_references": list(
                cancel.get("cancel_final_response_event_references") or []
            )[:MAX_LIST_ITEMS],
            "cancel_response_status_codes": cancel_statuses,
            "procedure_contradictions": contradictions,
            "protocol_violation_findings": violation_findings,
            "response_association_basis": association_basis,
            "transaction_ownership_established": transaction_ownership_established,
            "reason_established": False,
            "timeout_inferred": False,
            "scope": "SIP_OUTCOME_ONLY",
            "next_checks": next_checks[:MAX_DIAGNOSTIC_ITEMS],
            "excluded_interpretations": [
                "A SIP negative response is not a network-function root cause",
                "A matching CANCEL and 487 is normal INVITE termination processing",
                "An authentication challenge is not an authentication failure",
                "An absent response is not a locally inferred timeout",
            ],
            "evidence_class": "DERIVED",
        }

    def _unbound_outcome_record(
        observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        statuses = sorted(
            {
                int(observation["status_code"])
                for observation in observations
                if isinstance(observation.get("status_code"), int)
            }
        )
        unique_candidate = bool(observations) and all(
            observation.get("candidate_request_count") == 1
            for observation in observations
        )
        classification = (
            "SIP_UNBOUND_FINAL_RESPONSE_OBSERVED"
            if unique_candidate
            else "SIP_OUTCOME_IDENTITY_AMBIGUOUS"
        )
        return {
            "classification": classification,
            "final_status_codes": [],
            "final_response_references": [],
            "unbound_final_status_codes": statuses,
            "unbound_final_response_observations": observations[:MAX_LIST_ITEMS],
            "unbound_final_response_count": len(observations),
            "provisional_status_codes": [],
            "positive_final_response_observed": False,
            "negative_final_response_observed": False,
            "authentication_challenge_observed": False,
            "authentication_challenge_status_codes": [],
            "cancel_relationship_established": False,
            "cancel_transaction_references": [],
            "cancel_request_event_references": [],
            "cancel_response_event_references": [],
            "cancel_response_status_codes": [],
            "procedure_contradictions": [],
            "protocol_violation_findings": [],
            "response_association_basis": "IDENTITY_AND_CSEQ_ONLY",
            "transaction_ownership_established": False,
            "reason_established": False,
            "timeout_inferred": False,
            "scope": "SIP_RESPONSE_OBSERVATION_ONLY",
            "next_checks": [
                "Provide the peer-facing request frame with a matching Via sent-by and transport, or a capture point before the proxy rewrite.",
                "Do not treat the observed response as an INVITE transaction result until transaction identity is established.",
            ],
            "excluded_interpretations": [
                "An observed SIP response does not establish transaction ownership",
                "A broad Call-ID and CSeq match does not establish a transaction relationship",
                "An unbound response does not establish branch ownership or a call verdict",
            ],
            "evidence_class": "OBSERVED",
        }

    def _logical_call_outcome(
        attempt_outcomes: list[dict[str, Any]],
        branch_outcomes: list[dict[str, Any]],
        *,
        grouping_accepted: bool,
        provisional_observed: bool,
    ) -> dict[str, Any]:
        def _has_outcome_evidence(outcome: dict[str, Any]) -> bool:
            return bool(
                outcome.get("final_status_codes")
                or outcome.get("unbound_final_response_observations")
            )

        outcomes = (
            [outcome for outcome in branch_outcomes if _has_outcome_evidence(outcome)]
            or [outcome for outcome in attempt_outcomes if _has_outcome_evidence(outcome)]
            or attempt_outcomes
        )
        classifications = [
            str(outcome.get("classification")) for outcome in outcomes
        ]
        positive = any(
            outcome.get("positive_final_response_observed") for outcome in outcomes
        )
        negative = any(
            outcome.get("negative_final_response_observed") for outcome in outcomes
        )
        cancelled = any(
            classification == "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED"
            for classification in classifications
        )
        authenticated = any(
            classification == "SIP_AUTHENTICATION_CHALLENGE_OBSERVED"
            for classification in classifications
        )
        violation = any(
            classification == "SIP_PROTOCOL_VIOLATION_EVIDENCE"
            for classification in classifications
        )
        contradiction = any(
            classification == "SIP_PROCEDURE_CONTRADICTION_OBSERVED"
            for classification in classifications
        )
        unbound = any(
            outcome.get("unbound_final_response_observations")
            for outcome in outcomes
        )
        if violation:
            logical_outcome = "UNRESOLVED_LOGICAL_CALL_OUTCOME"
            observed = "SIP_PROTOCOL_VIOLATION_EVIDENCE"
        elif contradiction:
            logical_outcome = "UNRESOLVED_LOGICAL_CALL_OUTCOME"
            observed = "SIP_PROCEDURE_CONTRADICTION_OBSERVED"
        elif not grouping_accepted:
            logical_outcome = "UNRESOLVED_LOGICAL_CALL_OUTCOME"
            observed = "SIP_OUTCOME_IDENTITY_AMBIGUOUS"
        elif unbound and not (positive or negative or cancelled):
            logical_outcome = "UNRESOLVED_LOGICAL_CALL_OUTCOME"
            observed = "SIP_UNBOUND_FINAL_RESPONSE_OBSERVED"
        elif positive and (negative or cancelled):
            logical_outcome = "MIXED_FORK_OUTCOMES_OBSERVED"
            observed = "SIP_FORK_BRANCH_NEGATIVE_OUTCOME_OBSERVED"
        elif positive:
            logical_outcome = "ACCEPTED_INVITE_BRANCH_OBSERVED"
            observed = "SIP_POSITIVE_FINAL_OUTCOME_OBSERVED"
        elif cancelled:
            logical_outcome = "CANCELLATION_OUTCOME_OBSERVED"
            observed = "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED"
        elif authenticated:
            logical_outcome = "NEGATIVE_FINAL_BRANCH_OBSERVED"
            observed = "SIP_AUTHENTICATION_CHALLENGE_OBSERVED"
        elif negative:
            logical_outcome = "NEGATIVE_FINAL_BRANCH_OBSERVED"
            observed = "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
        elif provisional_observed:
            logical_outcome = "PROVISIONAL_ONLY"
            observed = "SIP_FINAL_OUTCOME_NOT_OBSERVED"
        else:
            logical_outcome = "FINAL_RESPONSE_NOT_OBSERVED"
            observed = "SIP_FINAL_OUTCOME_NOT_OBSERVED"
        counts: dict[str, int] = defaultdict(int)
        for classification in classifications:
            counts[classification] += 1
        return {
            "logical_call_outcome": logical_outcome,
            "observed_sip_outcome": observed,
            "component_outcome_counts": dict(sorted(counts.items())),
            "positive_branch_observed": positive,
            "negative_branch_observed": negative,
            "cancelled_branch_observed": cancelled,
            "unbound_response_observed": unbound,
            "authentication_challenge_observed": authenticated,
            "protocol_violation_observed": violation,
            "procedure_contradiction_observed": contradiction,
            "scope": "SIP_OUTCOME_ONLY",
            "evidence_class": "DERIVED",
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
    branch_by_reference: dict[str, dict[str, Any]] = {}
    attempt_by_reference: dict[str, dict[str, Any]] = {}
    for attempt in attempts_source:
        reference = attempt.get("attempt_reference")
        if isinstance(reference, str):
            attempt_by_reference[reference] = attempt
        for branch in attempt.get("branches") or []:
            if isinstance(branch, dict) and isinstance(branch.get("branch_reference"), str):
                branch_by_reference[branch["branch_reference"]] = branch

    def _sdp_shape(message: dict[str, Any]) -> tuple[Any, ...]:
        shape: list[tuple[Any, ...]] = []
        for media in message.get("media_sections") or []:
            if not isinstance(media, dict):
                continue
            payload_types = tuple(
                sorted(
                    mapping.get("payload_type")
                    for mapping in media.get("rtpmap") or []
                    if isinstance(mapping, dict)
                    and isinstance(mapping.get("payload_type"), int)
                )
            )
            shape.append(
                (
                    media.get("media_type"),
                    media.get("direction"),
                    payload_types,
                )
            )
        return tuple(shape)

    sdp_shape_by_ref = {
        reference: _sdp_shape(message) for reference, message in sdp_by_ref.items()
    }
    logical_sdp_context: dict[str, set[str]] = {}
    repeated_sdp_by_logical: dict[str, list[str]] = {}
    unbound_sdp_by_logical: dict[str, list[str]] = {}
    attempt_identity_family: dict[str, tuple[Any, Any]] = {}
    for logical_reference, members in logical_members.items():
        accepted = set(
            (logical_grouping.get("event_references_by_logical_call") or {}).get(
                logical_reference, []
            )
        )
        dialog_tags = {
            event.get("to_tag_reference")
            for reference in accepted
            for event in (sip_by_ref.get(reference),)
            if isinstance(event, dict) and isinstance(event.get("to_tag_reference"), str)
        }
        from_tag = None
        call_id = None
        for attempt_reference in members:
            attempt_object = attempt_by_reference.get(attempt_reference) or {}
            invite = sip_by_ref.get(attempt_object.get("initial_invite_event_reference"))
            if isinstance(invite, dict):
                call_id = invite.get("call_id_reference")
                from_tag = invite.get("from_tag_reference")
                break
        family = {
            reference
            for reference in sdp_by_ref
            for event in (sip_by_ref.get(reference),)
            if isinstance(event, dict)
            and event.get("call_id_reference") == call_id
            and event.get("from_tag_reference") == from_tag
            and (
                event.get("to_tag_reference") is None
                or event.get("to_tag_reference") in dialog_tags
            )
        }
        for attempt_reference in members:
            attempt_identity_family[attempt_reference] = (call_id, from_tag)
        established_exchange_refs = {
            exchange.get(key)
            for attempt_reference in members
            for exchange in exchanges_by_attempt.get(attempt_reference, [])
            if exchange.get("association_status") == "ESTABLISHED"
            for key in ("offer_sdp_reference", "answer_sdp_reference")
            if isinstance(exchange.get(key), str)
        }
        shapes = {
            sdp_shape_by_ref[reference]
            for reference in established_exchange_refs
            if reference in sdp_shape_by_ref
        }
        repeats: set[str] = set()
        unbound: set[str] = set()
        for reference in family - accepted:
            if reference in established_exchange_refs:
                continue
            if shapes and sdp_shape_by_ref.get(reference) in shapes:
                repeats.add(reference)
            else:
                unbound.add(reference)
        logical_sdp_context[logical_reference] = set(accepted & set(sdp_by_ref)) | repeats
        repeated_sdp_by_logical[logical_reference] = sorted(repeats)
        unbound_sdp_by_logical[logical_reference] = sorted(unbound)

    all_exchange_refs_by_logical: dict[str, set[str]] = {
        reference: set(context)
        for reference, context in logical_sdp_context.items()
    }
    unbound_exchange_refs_by_logical: dict[str, list[str]] = {}
    for logical_reference, members in logical_members.items():
        accepted = set(
            (logical_grouping.get("event_references_by_logical_call") or {}).get(
                logical_reference, []
            )
        )
        unbound: set[str] = set()
        for attempt_reference in members:
            for exchange in exchanges_by_attempt.get(attempt_reference, []):
                exchange_refs = {
                    exchange.get(key)
                    for key in ("offer_sdp_reference", "answer_sdp_reference")
                    if isinstance(exchange.get(key), str)
                }
                if exchange_refs and not exchange_refs <= accepted:
                    unbound.update(exchange_refs)
        unbound_exchange_refs_by_logical[logical_reference] = sorted(unbound)

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

    group_by_reference = {
        group["logical_call_reference"]: group
        for group in logical_grouping["logical_calls"]
    }

    def _final_status(reference: Any) -> int | None:
        event = sip_by_ref.get(reference) if isinstance(reference, str) else None
        if isinstance(event, dict) and isinstance(event.get("status_code"), int):
            return event["status_code"]
        return None

    def _response_match_reason(
        request: dict[str, Any], response: dict[str, Any]
    ) -> str:
        request_vias = list(request.get("via_branch_references") or [])
        response_vias = list(response.get("via_branch_references") or [])
        if not request_vias or not response_vias:
            return "VIA_IDENTITY_MISSING"
        if request_vias[0] != response_vias[0]:
            return "VIA_BRANCH_MISMATCH"
        return "VIA_SENT_BY_OR_TRANSPORT_MISMATCH"

    bound_response_references: set[str] = set()
    for attempt_source in attempts_source:
        stage = attempt_source.get("stage_evidence") or {}
        bound_response_references.update(
            stage.get("final_response_event_references") or []
        )
        bound_response_references.update(
            stage.get("provisional_response_event_references") or []
        )
        for source_branch in attempt_source.get("branches") or []:
            if isinstance(source_branch, dict):
                bound_response_references.update(
                    source_branch.get("response_event_references") or []
                )

    unbound_response_inventory: list[dict[str, Any]] = []
    for response_reference, response_event in sip_by_ref.items():
        if not isinstance(response_event, dict):
            continue
        if response_event.get("message_type") != "RESPONSE":
            continue
        status = response_event.get("status_code")
        if not isinstance(status, int) or status < 200:
            continue
        if response_reference in bound_response_references:
            continue
        call_id = response_event.get("call_id_reference")
        from_tag = response_event.get("from_tag_reference")
        headers = response_event.get("headers") or {}
        cseq = (headers.get("cseq") or {}).get("sequence")
        if (headers.get("cseq") or {}).get("method") != "INVITE":
            continue
        response_frame = response_event.get("frame_number")
        compatible_requests: list[dict[str, Any]] = []
        for request_reference, request_event in sip_by_ref.items():
            if not isinstance(request_event, dict):
                continue
            if request_event.get("method") != "INVITE":
                continue
            if request_event.get("call_id_reference") != call_id:
                continue
            if request_event.get("from_tag_reference") != from_tag:
                continue
            request_headers = request_event.get("headers") or {}
            request_cseq = (request_headers.get("cseq") or {}).get("sequence")
            if isinstance(cseq, int) and request_cseq != cseq:
                continue
            if (request_headers.get("cseq") or {}).get("method") != "INVITE":
                continue
            request_frame = request_event.get("frame_number")
            if (
                isinstance(response_frame, int)
                and isinstance(request_frame, int)
                and request_frame >= response_frame
            ):
                continue
            compatible_requests.append(
                {
                    "request_reference": request_reference,
                    "request_event": request_event,
                    "request_frame": request_frame,
                }
            )
        candidate_count = len(compatible_requests)
        if candidate_count == 0:
            ambiguity = "NO_COMPATIBLE_REQUEST"
            reason = "NO_COMPATIBLE_REQUEST"
        elif candidate_count > 1:
            ambiguity = "MULTIPLE_CANDIDATES"
            reason = "MULTIPLE_COMPATIBLE_REQUESTS"
        else:
            ambiguity = "UNIQUE_CANDIDATE"
            reason = _response_match_reason(
                compatible_requests[0]["request_event"], response_event
            )
        unbound_response_inventory.append(
            {
                "response_reference": response_reference,
                "frame_number": response_frame,
                "status_code": status,
                "candidate_request_references": [
                    item["request_reference"] for item in compatible_requests
                ][:MAX_LIST_ITEMS],
                "candidate_request_count": candidate_count,
                "ambiguity_status": ambiguity,
                "response_match_reason": reason,
                "transaction_ownership_established": False,
                "evidence_class": "OBSERVED",
            }
        )
    unbound_response_inventory = sorted(
        unbound_response_inventory,
        key=lambda item: (item.get("frame_number") or 0, item["response_reference"]),
    )

    logical_has_positive: dict[str, bool] = {}
    for group in logical_grouping["logical_calls"]:
        reference = group["logical_call_reference"]
        statuses: list[int] = []
        for member_reference in group["member_attempt_references"]:
            member_object = attempt_by_reference.get(member_reference) or {}
            statuses.extend(
                status
                for status in (
                    _final_status(item)
                    for item in (member_object.get("stage_evidence") or {}).get(
                        "final_response_event_references"
                    )
                    or []
                )
                if status is not None
            )
            for member_branch in member_object.get("branches") or []:
                statuses.extend(
                    status
                    for status in (
                        _final_status(item)
                        for item in member_branch.get("response_event_references")
                        or []
                    )
                    if status is not None
                )
                statuses.extend(
                    status
                    for status in member_branch.get("response_status_codes") or []
                    if isinstance(status, int)
                )
        logical_has_positive[reference] = any(
            200 <= status < 300 for status in statuses
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
        attempt_group = group_by_reference.get(attempt_logical) or {}
        attempt_stage = attempt.get("stage_evidence") or {}
        attempt_final_refs = list(
            attempt_stage.get("final_response_event_references") or []
        )
        attempt_final_statuses = [
            status
            for status in (_final_status(item) for item in attempt_final_refs)
            if status is not None and status >= 200
        ]
        attempt_provisional_statuses = [
            status
            for status in (
                _final_status(item)
                for item in attempt_stage.get("provisional_response_event_references")
                or []
            )
            if status is not None and 100 <= status < 200
        ]
        attempt_has_positive = any(
            200 <= status < 300 for status in attempt_final_statuses
        )
        related_unbound = [
            observation
            for observation in unbound_response_inventory
            if attempt.get("initial_invite_event_reference")
            in (observation.get("candidate_request_references") or [])
        ]
        if related_unbound and not attempt_final_refs:
            attempt_sip_outcome = _unbound_outcome_record(related_unbound)
        else:
            attempt_sip_outcome = _sip_outcome_record(
                attempt_final_statuses,
                attempt_final_refs,
                cancel_evidence=attempt.get("cancel_evidence") or {},
                identity_ambiguous=not bool(attempt_group.get("grouping_accepted")),
                other_branch_accepted=(
                    logical_has_positive.get(attempt_logical, False)
                    and not attempt_has_positive
                ),
                allow_contradiction=int(attempt.get("branch_count") or 0) <= 1,
                provisional_status_codes=attempt_provisional_statuses,
                association_basis="TRANSACTION_OR_BRANCH_CONTEXT",
                transaction_ownership_established=True,
            )
            if related_unbound:
                attempt_sip_outcome = {
                    **attempt_sip_outcome,
                    "unbound_final_status_codes": sorted(
                        {
                            int(observation["status_code"])
                            for observation in related_unbound
                            if isinstance(observation.get("status_code"), int)
                        }
                    ),
                    "unbound_final_response_observations": related_unbound[
                        :MAX_LIST_ITEMS
                    ],
                    "unbound_final_response_count": len(related_unbound),
                }
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
            "sip_final_outcome": attempt_sip_outcome,
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
                "final_outcome_classification": attempt_sip_outcome["classification"],
                "positive_final_outcome_observed": attempt_sip_outcome[
                    "positive_final_response_observed"
                ],
                "negative_final_outcome_observed": attempt_sip_outcome[
                    "negative_final_response_observed"
                ],
                "authentication_challenge_observed": attempt_sip_outcome[
                    "authentication_challenge_observed"
                ],
                "cancel_relationship_established": attempt_sip_outcome[
                    "cancel_relationship_established"
                ],
                "cancel_response_event_references": attempt_sip_outcome[
                    "cancel_response_event_references"
                ],
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
            branch_statuses = [
                status
                for status in (
                    _final_status(item)
                    for item in branch.get("response_event_references") or []
                )
                if status is not None and status >= 200
            ]
            branch_statuses.extend(
                status
                for status in branch.get("response_status_codes") or []
                if isinstance(status, int) and status >= 200
            )
            branch_provisional_statuses = [
                status
                for status in branch.get("response_status_codes") or []
                if isinstance(status, int) and 100 <= status < 200
            ]
            branch_sip_outcome = _sip_outcome_record(
                branch_statuses,
                list(branch.get("response_event_references") or []),
                cancel_evidence=attempt.get("cancel_evidence") or {},
                identity_ambiguous=branch.get("identity_status") != "ESTABLISHED",
                other_branch_accepted=(
                    logical_has_positive.get(attempt_logical, False)
                    and not any(200 <= status < 300 for status in branch_statuses)
                ),
                allow_contradiction=True,
                provisional_status_codes=branch_provisional_statuses,
            )
            branch_records.append(
                {
                    "attempt_reference": attempt_reference,
                    "sip_final_outcome": branch_sip_outcome,
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

    sdp_body_observed = any(
        event.get("body_present")
        and (((event.get("headers") or {}).get("content_type") or "") == "application/sdp")
        for event in sip_by_ref.values()
    )
    capture_visibility_limited = sdp_body_observed and not sdp_by_ref

    def _logical_rtcp_ownership(
        member_records: list[dict[str, Any]],
        source_streams: list[str],
        media_ownership: str,
    ) -> dict[str, Any]:
        associations = list(
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
        reports = list(
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
        stream_set = set(source_streams)
        relevant = [
            association
            for association in associations
            if set(association.get("source_stream_references") or []) & stream_set
        ]
        competing = [
            association
            for association in relevant
            if any(
                len(stream_owner_by_source.get(stream_reference, [])) > 1
                for stream_reference in association.get("source_stream_references") or []
            )
        ]
        accepted = [
            association
            for association in relevant
            if association.get("association_status")
            == "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
            and set(association.get("source_stream_references") or []) <= stream_set
        ]
        sender_counts: dict[str, int] = defaultdict(int)
        reportee_counts: dict[str, int] = defaultdict(int)
        for association in relevant:
            bucket = (
                sender_counts
                if association.get("association_kind") == "SR_SENDER_SSRC"
                else reportee_counts
            )
            bucket[str(association.get("association_status"))] += 1
        if not rtcp_events:
            status = "RTCP_NOT_OBSERVED"
            reason = "RTCP_COMPONENT_NOT_OBSERVED"
        elif competing:
            status = "AMBIGUOUS_OWNERSHIP"
            reason = "COMPETING_RTCP_STREAM_OWNERSHIP"
        elif accepted and media_ownership == "LOGICAL_CALL_MEDIA_OWNED":
            status = "LOGICAL_CALL_RTCP_ASSOCIATED"
            reason = "ACCEPTED_RTCP_SOURCE_AND_CALL_OWNERSHIP"
        elif any(
            association.get("association_status")
            == "RTCP_STREAM_ASSOCIATION_AMBIGUOUS"
            for association in relevant
        ) or not relevant:
            status = "RTCP_CALL_ASSOCIATION_AMBIGUOUS"
            reason = (
                "ALL_RTCP_STREAM_ASSOCIATIONS_AMBIGUOUS"
                if relevant
                else "RTCP_COMPONENT_NOT_OWNED_BY_LOGICAL_CALL"
            )
        else:
            status = "RTCP_CALL_ASSOCIATION_INSUFFICIENT"
            reason = "RTCP_SOURCE_RELATIONSHIP_NOT_ESTABLISHED"
        return {
            "association_count": len(relevant),
            "receiver_report_count": len(reports),
            "established_source_association_count": len(accepted),
            "ambiguous_association_count": sum(
                1
                for association in relevant
                if association.get("association_status")
                != "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
            ),
            "sender_association_status_counts": dict(sorted(sender_counts.items())),
            "reportee_association_status_counts": dict(sorted(reportee_counts.items())),
            "ownership_status": status,
            "ownership_basis": [reason],
            "competing_owner_association_count": len(competing),
            "measurement_origin": "RECEIVER_REPORTED" if reports else None,
            "associations": relevant[:MAX_LIST_ITEMS],
            "receiver_reported_quality": reports[:MAX_REPORTS],
        }

    logical_records: list[dict[str, Any]] = []
    for group in logical_grouping["logical_calls"]:
        logical_reference = group["logical_call_reference"]
        members = group["member_attempt_references"]
        member_records = [
            record for record in attempt_records
            if record.get("attempt_reference") in members
        ]
        accepted_refs = set(
            (logical_grouping.get("event_references_by_logical_call") or {}).get(
                logical_reference, []
            )
        )
        unbound_sip_refs = list(
            (logical_grouping.get("unbound_event_references_by_logical_call") or {}).get(
                logical_reference, []
            )
        )
        unbound_exchange_refs = list(
            unbound_exchange_refs_by_logical.get(logical_reference, [])
        )
        member_branch_records = [
            record
            for record in branch_records
            if record.get("attempt_reference") in members
        ]
        attempt_outcomes = [
            record.get("sip_final_outcome")
            for record in member_records
            if isinstance(record.get("sip_final_outcome"), dict)
        ]
        branch_outcomes = [
            record.get("sip_final_outcome")
            for record in member_branch_records
            if isinstance(record.get("sip_final_outcome"), dict)
        ]
        outcome_records = (
            [
                outcome
                for outcome in branch_outcomes
                if outcome.get("final_status_codes")
                or outcome.get("unbound_final_response_observations")
            ]
            or [
                outcome
                for outcome in attempt_outcomes
                if outcome.get("final_status_codes")
                or outcome.get("unbound_final_response_observations")
            ]
            or attempt_outcomes
        )
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

        member_exchanges: list[dict[str, Any]] = []
        for attempt_reference in members:
            member_exchanges.extend(exchanges_by_attempt.get(attempt_reference, []))

        established = [
            exchange
            for exchange in member_exchanges
            if exchange.get("association_status") == "ESTABLISHED"
            and isinstance(exchange.get("offer_sdp_reference"), str)
            and isinstance(exchange.get("answer_sdp_reference"), str)
        ]
        branch_gate_failures = [
            exchange.get("branch_reference")
            for exchange in established
            if isinstance(exchange.get("branch_reference"), str)
            and (
                exchange.get("branch_reference") not in branch_by_reference
                or branch_by_reference[exchange["branch_reference"]].get("identity_status")
                != "ESTABLISHED"
            )
        ]
        owned_exchanges = [
            exchange
            for exchange in established
            if {
                exchange.get("offer_sdp_reference"),
                exchange.get("answer_sdp_reference"),
            }
            <= accepted_refs
        ]
        answer_branch_owner: dict[str, str] = {}
        contaminated_answers: set[str] = set()
        for exchange in owned_exchanges:
            answer_reference = exchange.get("answer_sdp_reference")
            branch_reference = exchange.get("branch_reference")
            if not isinstance(answer_reference, str) or not isinstance(
                branch_reference, str
            ):
                continue
            previous = answer_branch_owner.get(answer_reference)
            if previous is not None and previous != branch_reference:
                contaminated_answers.add(answer_reference)
            answer_branch_owner[answer_reference] = branch_reference
        contradicted_exchanges = [
            exchange for exchange in established if exchange not in owned_exchanges
        ]
        owned_exchange_refs: set[str] = set()
        accepted_sections: list[dict[str, Any]] = []
        unsupported_section_count = 0
        for exchange in owned_exchanges:
            for key in ("offer_sdp_reference", "answer_sdp_reference"):
                reference = exchange.get(key)
                if not isinstance(reference, str):
                    continue
                owned_exchange_refs.add(reference)
                message = sdp_by_ref.get(reference)
                if not isinstance(message, dict):
                    continue
                for section in message.get("media_sections") or []:
                    if not isinstance(section, dict):
                        continue
                    if section.get("media_type_supported") is False:
                        unsupported_section_count += 1
                        continue
                    accepted_sections.append(
                        {
                            "message_reference": reference,
                            "media_index": section.get("index"),
                            "media_type": section.get("media_type"),
                            "direction": section.get("direction"),
                            "mid": section.get("mid"),
                        }
                    )

        correlation_context_refs = set(
            logical_sdp_context.get(logical_reference, set())
        )
        repeated_sdp_refs = list(
            repeated_sdp_by_logical.get(logical_reference, [])
        )
        unbound_sdp_refs = list(unbound_sdp_by_logical.get(logical_reference, []))

        matched_owned: list[dict[str, Any]] = []
        for corr in exact:
            if corr.get("association_status") not in (
                "MATCHED_ENDPOINT",
                "BUNDLE_TRANSPORT_MATCHED",
            ):
                continue
            if corr.get("missing_evidence") or corr.get("conflict_findings"):
                continue
            section_refs = {
                section.get("message_reference")
                for section in corr.get("sdp_media_sections") or []
                if isinstance(section, dict)
            }
            if section_refs and section_refs <= correlation_context_refs:
                matched_owned.append(corr)
        candidate_transports = _unique(
            [
                udp
                for corr in matched_owned
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
        shared_streams = [
            stream_reference
            for stream_reference in source_streams
            if len(stream_owner_by_source.get(stream_reference, [])) > 1
        ]

        ownership_reasons: list[str] = []
        if not group.get("grouping_accepted"):
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("LOGICAL_CALL_GROUPING_NOT_ACCEPTED")
        elif competing:
            ownership_status = "AMBIGUOUS_OWNERSHIP"
            ownership_reasons.append("COMPETING_LOGICAL_CALL_OWNERSHIP")
        elif branch_gate_failures:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("DIALOG_BRANCH_IDENTITY_NOT_ACCEPTED")
        elif contaminated_answers:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("COMPETING_BRANCH_ANSWER_CONTAMINATION")
        elif contradicted_exchanges:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("EXCHANGE_REFERENCE_NOT_OWNED")
        elif not owned_exchanges:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append(
                "ESTABLISHED_OFFER_ANSWER_EXCHANGE_NOT_OBSERVED"
            )
        elif unsupported_section_count and not accepted_sections:
            ownership_status = "UNSUPPORTED_PROCEDURE"
            ownership_reasons.append("SDP_MEDIA_SECTIONS_UNSUPPORTED")
        elif not accepted_sections:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("SDP_MEDIA_SECTIONS_NOT_RESOLVED")
        elif not matched_owned:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("TRANSPORT_CORRELATION_NOT_OWNED")
        elif not source_streams:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("RTP_SOURCE_STREAM_NOT_OBSERVED")
        elif unbound_sdp_refs:
            ownership_status = "INSUFFICIENT_EVIDENCE"
            ownership_reasons.append("UNBOUND_SDP_OBSERVATION")
        elif shared_streams:
            ownership_status = "AMBIGUOUS_OWNERSHIP"
            ownership_reasons.append("SHARED_RTP_STREAM_OWNERSHIP")
        else:
            ownership_status = "LOGICAL_CALL_MEDIA_OWNED"
            ownership_reasons.append("ESTABLISHED_EXCHANGE_AND_UNIQUE_TRANSPORT_OWNED")

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

        rtcp_evidence = _logical_rtcp_ownership(
            member_records, source_streams, ownership_status
        )

        # Ordered per-call evidence review.
        provisional_refs: list[str] = []
        final_refs: list[str] = []
        ack_refs: list[str] = []
        cancel_refs: set[str] = set()
        release_refs: set[str] = set()
        bye_request_refs: set[str] = set()
        bye_response_refs: set[str] = set()
        initial_invite_refs: list[str] = []
        for attempt_reference in members:
            attempt_object = attempt_by_reference.get(attempt_reference) or {}
            stages = attempt_object.get("stage_evidence") or {}
            provisional_refs.extend(
                stages.get("provisional_response_event_references") or []
            )
            final_refs.extend(stages.get("final_response_event_references") or [])
            ack_refs.extend(
                (attempt_object.get("ack_evidence") or {}).get(
                    "twoxx_ack_event_references"
                )
                or []
            )
            if isinstance(attempt_object.get("initial_invite_event_reference"), str):
                initial_invite_refs.append(
                    attempt_object["initial_invite_event_reference"]
                )
            cancel_refs.update(
                _collect_sip_references(attempt_object.get("cancel_evidence") or {})
            )
            release_refs.update(
                _collect_sip_references(attempt_object.get("release_evidence") or {})
            )
            for branch in attempt_object.get("branches") or []:
                if not isinstance(branch, dict):
                    continue
                final_refs.extend(branch.get("response_event_references") or [])
                ack_refs.extend(branch.get("ack_event_references") or [])
                for observation in (branch.get("release") or {}).get("observations") or []:
                    if not isinstance(observation, dict):
                        continue
                    bye_request_refs.update(
                        observation.get("bye_request_event_references") or []
                    )
                    bye_response_refs.update(
                        observation.get("bye_final_response_event_references") or []
                    )
        provisional_refs = sorted(set(provisional_refs))
        final_refs = sorted(
            set(final_refs)
            | {
                reference
                for outcome in outcome_records
                for reference in outcome.get("final_response_references") or []
            }
        )
        unbound_response_observations = [
            observation
            for outcome in [*outcome_records, *attempt_outcomes]
            for observation in outcome.get("unbound_final_response_observations") or []
        ]
        unbound_response_observations = sorted(
            {
                observation.get("response_reference"): observation
                for observation in unbound_response_observations
                if isinstance(observation, dict)
                and isinstance(observation.get("response_reference"), str)
            }.values(),
            key=lambda item: (item.get("frame_number") or 0, item["response_reference"]),
        )
        unbound_response_refs = [
            observation["response_reference"]
            for observation in unbound_response_observations
        ]
        unbound_response_statuses = sorted(
            {
                int(observation["status_code"])
                for observation in unbound_response_observations
                if isinstance(observation.get("status_code"), int)
            }
        )
        ack_refs = sorted(set(ack_refs))
        observed_provisional_statuses = sorted(
            {
                event.get("status_code")
                for reference in provisional_refs
                for event in (sip_by_ref.get(reference),)
                if isinstance(event, dict)
                and isinstance(event.get("status_code"), int)
                and 100 <= event["status_code"] < 200
            }
            | {
                event.get("status_code")
                for reference in final_refs
                for event in (sip_by_ref.get(reference),)
                if isinstance(event, dict)
                and isinstance(event.get("status_code"), int)
                and 100 <= event["status_code"] < 200
            }
        )
        provisional_statuses = observed_provisional_statuses
        final_statuses = sorted(
            {
                event.get("status_code")
                for reference in final_refs
                for event in (sip_by_ref.get(reference),)
                if isinstance(event, dict)
                and isinstance(event.get("status_code"), int)
                and event["status_code"] >= 200
            }
        )
        logical_outcome = _logical_call_outcome(
            attempt_outcomes,
            branch_outcomes,
            grouping_accepted=bool(group.get("grouping_accepted")),
            provisional_observed=bool(provisional_statuses),
        )
        observed_sip_outcome = logical_outcome["observed_sip_outcome"]
        logical_outcome_classification = logical_outcome["logical_call_outcome"]

        def _outcome_boundary(
            classification: str, reason_code: str
        ) -> dict[str, Any] | None:
            for outcome in outcome_records:
                if outcome.get("classification") != classification:
                    continue
                references = list(outcome.get("final_response_references") or [])
                reference = references[0] if references else None
                frame = _frame_of(reference) if reference else None
                statuses = list(outcome.get("final_status_codes") or [])
                return {
                    "reason_code": reason_code,
                    "status_code": statuses[0] if statuses else None,
                    "event_reference": reference,
                    "frame_number": frame,
                    "scope": "SIP_OUTCOME_ONLY",
                    "network_root_cause_established": False,
                    "evidence_class": "OBSERVED",
                }
            return None

        violation = _outcome_boundary(
            "SIP_PROTOCOL_VIOLATION_EVIDENCE", "SIP_PROTOCOL_VIOLATION_EVIDENCE"
        )
        contradiction = _outcome_boundary(
            "SIP_PROCEDURE_CONTRADICTION_OBSERVED",
            "SIP_PROCEDURE_CONTRADICTION_OBSERVED",
        )
        deviation = violation
        if unbound_response_refs and not final_statuses:
            signaling_outcome = "UNBOUND_FINAL_RESPONSE_OBSERVED"
        elif any(200 <= status < 300 for status in final_statuses) and any(
            status >= 300 for status in final_statuses
        ):
            signaling_outcome = "MIXED_FINAL_RESPONSES_OBSERVED"
        elif any(200 <= status < 300 for status in final_statuses):
            signaling_outcome = "ACCEPTED_2XX_OBSERVED"
        elif final_statuses:
            signaling_outcome = "NON_2XX_FINAL_RESPONSE_OBSERVED"
        elif provisional_statuses:
            signaling_outcome = "PROVISIONAL_ONLY"
        else:
            signaling_outcome = "FINAL_RESPONSE_NOT_OBSERVED"

        family_key = attempt_identity_family.get(members[0]) if members else None
        family_members = [
            reference
            for reference in attempt_to_logical
            if attempt_identity_family.get(reference) == family_key
        ] if family_key is not None else list(members)
        family_records = [
            record
            for record in attempt_records
            if record.get("attempt_reference") in family_members
        ]
        family_outcomes = [
            record.get("sip_final_outcome")
            for record in family_records
            if isinstance(record.get("sip_final_outcome"), dict)
        ]
        challenge_outcomes = [
            outcome
            for outcome in family_outcomes
            if outcome.get("authentication_challenge_observed")
        ]
        challenge_references = sorted(
            {
                reference
                for outcome in challenge_outcomes
                for reference in outcome.get("final_response_references") or []
                if _status_of(reference) in (401, 407)
            }
        )
        challenge_frames = [
            frame
            for frame in (_frame_of(reference) for reference in challenge_references)
            if frame is not None
        ]
        retry_requests: list[str] = []
        retry_final_statuses: list[int] = []
        retry_logical_references: list[str] = []
        for family_attempt in (
            attempt_by_reference.get(reference) or {} for reference in family_members
        ):
            invite_reference = family_attempt.get("initial_invite_event_reference")
            invite_event = sip_by_ref.get(invite_reference)
            if not isinstance(invite_event, dict):
                continue
            invite_frame = invite_event.get("frame_number")
            if (
                not isinstance(invite_frame, int)
                or not challenge_frames
                or invite_frame <= max(challenge_frames)
            ):
                continue
            headers = invite_event.get("headers") or {}
            authorization = (headers.get("authorization") or {}).get("count") or 0
            proxy_authorization = (
                headers.get("proxy_authorization") or {}
            ).get("count") or 0
            if not (authorization or proxy_authorization):
                continue
            retry_outcome = next(
                (
                    record.get("sip_final_outcome")
                    for record in family_records
                    if record.get("attempt_reference")
                    == family_attempt.get("attempt_reference")
                ),
                None,
            )
            if not isinstance(retry_outcome, dict):
                continue
            if not retry_outcome.get("positive_final_response_observed"):
                continue
            if isinstance(invite_reference, str):
                retry_requests.append(invite_reference)
            retry_final_statuses.extend(
                status
                for status in retry_outcome.get("final_status_codes") or []
                if status >= 200
            )
            logical_for_retry = attempt_to_logical.get(
                family_attempt.get("attempt_reference")
            )
            if isinstance(logical_for_retry, str):
                retry_logical_references.append(logical_for_retry)
        if challenge_outcomes:
            invite_authentication_review = {
                "challenge_observed": True,
                "challenge_status_codes": sorted(
                    {_status_of(reference) for reference in challenge_references}
                    - {None}
                ),
                "challenge_event_references": challenge_references[:MAX_LIST_ITEMS],
                "retry_observed": bool(retry_requests),
                "retry_request_event_references": sorted(set(retry_requests))[
                    :MAX_LIST_ITEMS
                ],
                "retry_final_status_codes": sorted(set(retry_final_statuses)),
                "retry_logical_call_references": sorted(
                    set(retry_logical_references)
                )[:MAX_LIST_ITEMS],
                "association_status": (
                    "CHALLENGE_RETRY_ASSOCIATED"
                    if retry_requests
                    else "CHALLENGE_WITHOUT_OBSERVED_RETRY"
                ),
                "authorization_presence_observed": bool(retry_requests),
                "authentication_verified": False,
                "basis": (
                    ["challenge_observed", "later_authorized_request_observed"]
                    if retry_requests
                    else ["challenge_observed", "no_later_authorized_request_observed"]
                ),
                "missing_evidence": (
                    []
                    if retry_requests
                    else ["AUTHORIZED_RETRY_NOT_OBSERVED"]
                ),
                "evidence_class": "DERIVED",
            }
        else:
            invite_authentication_review = {
                "challenge_observed": False,
                "challenge_status_codes": [],
                "challenge_event_references": [],
                "retry_observed": False,
                "retry_request_event_references": [],
                "retry_final_status_codes": [],
                "retry_logical_call_references": [],
                "association_status": "NOT_OBSERVED",
                "authentication_verified": False,
                "basis": ["no_401_or_407_invite_final_response"],
                "missing_evidence": [],
                "evidence_class": "DERIVED",
            }

        branch_outcome_records = [
            {
                "branch_reference": record.get("branch_reference"),
                "dialog_reference": record.get("dialog_reference"),
                "identity_status": record.get("identity_status"),
                "classification": (record.get("sip_final_outcome") or {}).get(
                    "classification"
                ),
                "final_status_codes": (record.get("sip_final_outcome") or {}).get(
                    "final_status_codes"
                ),
                "final_response_references": (
                    record.get("sip_final_outcome") or {}
                ).get("final_response_references"),
                "cancel_relationship_established": (
                    record.get("sip_final_outcome") or {}
                ).get("cancel_relationship_established"),
                "procedure_contradictions": (
                    record.get("sip_final_outcome") or {}
                ).get("procedure_contradictions"),
                "scope": "SIP_OUTCOME_ONLY",
            }
            for record in member_branch_records
        ]

        owned_streams = [
            stream
            for stream in streams
            if stream.get("source_stream_reference") in source_streams
        ]
        owned_rtp_events = [
            event
            for stream in owned_streams
            for event in rtp_by_key.get(
                (stream.get("udp_stream"), stream.get("ssrc_reference")), []
            )
        ]
        owned_rtp_frames = sorted(
            {
                event.get("frame_number")
                for event in owned_rtp_events
                if isinstance(event.get("frame_number"), int)
            }
        )
        rtp_evidence_outcome = (
            "RTP_STREAMS_OWNED"
            if owned_streams and ownership_status == "LOGICAL_CALL_MEDIA_OWNED"
            else "RTP_OBSERVED_NOT_OWNED"
            if candidate_transports or relevant
            else "RTP_NOT_OBSERVED"
        )
        sdp_association_outcome = (
            "ESTABLISHED_OFFER_ANSWER_OWNED"
            if owned_exchanges
            else "OFFER_ANSWER_NOT_ESTABLISHED"
            if not established
            else "EXCHANGE_REFERENCE_NOT_OWNED"
        )

        last_candidates: list[tuple[int, str, str]] = []
        for reference in accepted_refs:
            frame = _frame_of(reference)
            if frame is not None:
                last_candidates.append((frame, "SIP", reference))
        for reference in owned_exchange_refs:
            frame = _frame_of(reference)
            if frame is not None:
                last_candidates.append((frame, "SDP", reference))
        if ownership_status == "LOGICAL_CALL_MEDIA_OWNED":
            for frame in owned_rtp_frames:
                last_candidates.append((frame, "RTP", f"frame:{frame}"))
            for association in rtcp_evidence["associations"]:
                if (
                    association.get("association_status")
                    != "RTCP_STREAM_ASSOCIATION_ESTABLISHED"
                ):
                    continue
                frame = _frame_of(association.get("rtcp_event_reference"))
                if frame is not None:
                    last_candidates.append(
                        (frame, "RTCP", association.get("rtcp_event_reference"))
                    )
        last_supported_observation = (
            {
                "stage": max(last_candidates, key=lambda item: (item[0], item[2]))[1],
                "reference": max(last_candidates, key=lambda item: (item[0], item[2]))[2],
                "frame_number": max(last_candidates, key=lambda item: (item[0], item[2]))[0],
            }
            if last_candidates
            else None
        )

        if violation is not None:
            boundary_classification = "OBSERVED_PROTOCOL_VIOLATION"
        elif contradiction is not None:
            boundary_classification = "OBSERVED_SIP_PROCEDURE_CONTRADICTION"
        elif not group.get("grouping_accepted"):
            boundary_classification = "IDENTITY_AMBIGUITY"
        elif logical_outcome_classification == "NEGATIVE_FINAL_BRANCH_OBSERVED":
            boundary_classification = "OBSERVED_NEGATIVE_SIP_OUTCOME"
        elif logical_outcome_classification == "CANCELLATION_OUTCOME_OBSERVED":
            boundary_classification = "OBSERVED_CANCELLED_SIP_OUTCOME"
        elif logical_outcome_classification == "MIXED_FORK_OUTCOMES_OBSERVED":
            boundary_classification = "OBSERVED_MIXED_SIP_OUTCOMES"
        elif unbound_response_refs and not final_statuses:
            boundary_classification = "UNBOUND_SIP_RESPONSE_OBSERVED"
        elif signaling_outcome in (
            "FINAL_RESPONSE_NOT_OBSERVED",
            "PROVISIONAL_ONLY",
        ):
            boundary_classification = (
                "CAPTURE_VISIBILITY_LIMITATION"
                if capture_visibility_limited
                else "MISSING_OBSERVATION"
            )
        elif ownership_status == "UNSUPPORTED_PROCEDURE":
            boundary_classification = "UNSUPPORTED_PROCEDURE"
        elif capture_visibility_limited and not sdp_by_ref:
            boundary_classification = "CAPTURE_VISIBILITY_LIMITATION"
        elif sdp_body_observed and unbound_sdp_refs:
            boundary_classification = "EXTRACTION_FAILURE"
        elif ownership_status == "AMBIGUOUS_OWNERSHIP":
            boundary_classification = "IDENTITY_AMBIGUITY"
        elif ownership_status != "LOGICAL_CALL_MEDIA_OWNED":
            boundary_classification = "MISSING_OBSERVATION"
        else:
            boundary_classification = "NO_ABNORMAL_EVIDENCE_OBSERVED"

        first_response_ownership_boundary = None
        if unbound_response_observations:
            primary_observation = unbound_response_observations[0]
            first_response_ownership_boundary = {
                "reason_code": "SIP_RESPONSE_TRANSACTION_OWNERSHIP_NOT_ESTABLISHED",
                "response_event_reference": primary_observation.get(
                    "response_reference"
                ),
                "frame_number": primary_observation.get("frame_number"),
                "status_code": primary_observation.get("status_code"),
                "candidate_request_count": primary_observation.get(
                    "candidate_request_count"
                ),
                "candidate_request_references": primary_observation.get(
                    "candidate_request_references"
                ),
                "response_match_reason": primary_observation.get(
                    "response_match_reason"
                ),
                "ambiguity_status": primary_observation.get("ambiguity_status"),
                "transaction_ownership_established": False,
                "evidence_status": "UNBOUND_SIP_RESPONSE_OBSERVED",
            }

        missing_boundary_classes = {
            "MISSING_OBSERVATION",
            "CAPTURE_VISIBILITY_LIMITATION",
            "UNSUPPORTED_PROCEDURE",
            "EXTRACTION_FAILURE",
            "IDENTITY_AMBIGUITY",
        }
        first_missing_boundary = None
        if (
            boundary_classification in missing_boundary_classes
            and violation is None
            and contradiction is None
        ):
            first_missing_boundary = {
                "reason_code": (
                    ownership_reasons[0]
                    if ownership_reasons
                    and ownership_status != "LOGICAL_CALL_MEDIA_OWNED"
                    else "SIP_FINAL_RESPONSE_NOT_OBSERVED"
                    if signaling_outcome
                    in ("FINAL_RESPONSE_NOT_OBSERVED", "PROVISIONAL_ONLY")
                    else "LOGICAL_CALL_MEDIA_CHAIN_INCOMPLETE"
                ),
                "evidence_status": boundary_classification,
                "last_supported_observation": last_supported_observation,
            }

        missing: list[str] = []
        if ownership_status != "LOGICAL_CALL_MEDIA_OWNED":
            missing.extend(ownership_reasons)
        if not owned_exchanges:
            offer_without_answer = any(
                isinstance(exchange.get("offer_sdp_reference"), str)
                and not isinstance(exchange.get("answer_sdp_reference"), str)
                for exchange in member_exchanges
            )
            missing.append(
                "SDP_ANSWER_NOT_OBSERVED"
                if offer_without_answer or established
                else "ESTABLISHED_OFFER_ANSWER_EXCHANGE_NOT_OBSERVED"
            )
        if unbound_sdp_refs:
            missing.append("UNBOUND_SDP_OBSERVATION")
        if ownership_status != "LOGICAL_CALL_MEDIA_OWNED" and unbound_sip_refs:
            missing.append("UNBOUND_SIP_OBSERVATION")
        if rtcp_evidence["ownership_status"] not in (
            "LOGICAL_CALL_RTCP_ASSOCIATED",
            "RTCP_NOT_OBSERVED",
        ):
            missing.append("RTCP_CALL_ASSOCIATION_NOT_ESTABLISHED")
        if unbound_response_refs:
            missing.append("RESPONSE_TRANSACTION_OWNERSHIP_NOT_ESTABLISHED")
        missing = _unique(missing)
        if (
            group.get("grouping_accepted")
            and owned_exchanges
            and matched_owned
            and source_streams
            and not competing
            and not unbound_sdp_refs
        ):
            diagnostic_completeness = "COMPLETE"
        elif group.get("grouping_accepted") and (owned_exchanges or source_streams):
            diagnostic_completeness = "PARTIAL"
        else:
            diagnostic_completeness = "INSUFFICIENT"

        candidate_explanations: list[str] = []
        if logical_outcome_classification == "NEGATIVE_FINAL_BRANCH_OBSERVED":
            candidate_explanations.append(
                "The captured SIP transaction received an explicit negative final response; the reason is not established by the status code alone."
            )
        if logical_outcome_classification == "CANCELLATION_OUTCOME_OBSERVED":
            candidate_explanations.append(
                "A matching CANCEL and 487 indicate normal INVITE termination processing; the cause of the cancellation is not observed."
            )
        if logical_outcome_classification == "MIXED_FORK_OUTCOMES_OBSERVED":
            candidate_explanations.append(
                "Independent fork branches have different final outcomes; the logical call is not collapsed into success or failure."
            )
        if invite_authentication_review["challenge_observed"]:
            candidate_explanations.append(
                "A 401 or 407 is an authentication challenge; it is not proof of an authentication failure."
            )
        if violation is not None:
            candidate_explanations.append(
                "A final response carries message-syntax evidence that contradicts RFC 3261."
            )
        if contradiction is not None:
            candidate_explanations.append(
                "Conflicting final responses were observed for one proven transaction or branch."
            )
        if unbound_response_refs and not final_statuses:
            candidate_explanations.append(
                "A SIP final response was observed but its transaction identity does not match the observed request; it is retained as an unbound response and is not promoted to a branch outcome."
            )
        if capture_visibility_limited:
            candidate_explanations.append(
                "SDP bodies are present but not extractable from the available capture view."
            )
        if (unbound_sdp_refs or unbound_sip_refs) and (
            ownership_status != "LOGICAL_CALL_MEDIA_OWNED"
            or diagnostic_completeness != "COMPLETE"
        ):
            candidate_explanations.append(
                "Some SDP or SIP observations remain outside the accepted transaction context."
            )
        if not candidate_explanations:
            candidate_explanations.append(
                "No evidence-supported abnormality is present within the observed capture scope."
            )
        hypotheses: list[str] = []
        if (
            signaling_outcome in ("FINAL_RESPONSE_NOT_OBSERVED", "PROVISIONAL_ONLY")
            and capture_visibility_limited
        ):
            hypotheses.append(
                "HYPOTHESIS: the response direction may lie outside the capture view; unconfirmed."
            )

        next_checks = _unique(
            [
                item
                for outcome in outcome_records
                for item in outcome.get("next_checks") or []
            ]
        )[:MAX_DIAGNOSTIC_ITEMS]
        if diagnostic_completeness != "COMPLETE":
            next_checks.extend(
                [
                    "Provide SDP/RTP correspondence that excludes every competing logical call and branch.",
                    "Provide the missing SDP answer or RTP source-stream evidence for this logical call.",
                    "Provide a capture view that exposes the encrypted or unobserved signaling leg.",
                ]
            )
        next_checks = _unique(next_checks)[:MAX_DIAGNOSTIC_ITEMS]

        supporting_refs = _unique(
            [
                *sorted(initial_invite_refs)[:4],
                *final_refs[:4],
                *sorted(owned_exchange_refs)[:4],
                *unbound_response_refs[:4],
                *(
                    [f"frame:{frame}" for frame in owned_rtp_frames[:4]]
                    if ownership_status == "LOGICAL_CALL_MEDIA_OWNED"
                    else []
                ),
            ]
        )[:MAX_LIST_ITEMS]

        diagnostic_review = {
            "logical_call_reference": logical_reference,
            "member_attempt_references": members[:MAX_LIST_ITEMS],
            "dialog_branch_references": group.get("member_dialog_references"),
            "sip_signaling": {
                "initial_invite_event_references": sorted(initial_invite_refs)[:MAX_LIST_ITEMS],
                "provisional_response_event_references": provisional_refs[:MAX_LIST_ITEMS],
                "provisional_status_codes": provisional_statuses,
                "final_response_event_references": final_refs[:MAX_LIST_ITEMS],
                "final_response_status_codes": final_statuses,
                "unbound_response_event_references": unbound_response_refs[
                    :MAX_LIST_ITEMS
                ],
                "unbound_response_status_codes": unbound_response_statuses,
                "unbound_response_observations": unbound_response_observations[
                    :MAX_LIST_ITEMS
                ],
                "ack_event_references": ack_refs[:MAX_LIST_ITEMS],
                "cancel_event_references": sorted(cancel_refs)[:MAX_LIST_ITEMS],
                "bye_request_event_references": sorted(bye_request_refs)[:MAX_LIST_ITEMS],
                "bye_final_response_event_references": sorted(bye_response_refs)[:MAX_LIST_ITEMS],
                "release_event_references": sorted(release_refs)[:MAX_LIST_ITEMS],
                "outcome": signaling_outcome,
                "observed_sip_outcome": observed_sip_outcome,
                "logical_call_outcome": logical_outcome_classification,
                "invite_authentication_review": invite_authentication_review,
                "branch_outcomes": branch_outcome_records[:MAX_LIST_ITEMS],
                "fork_branch_references": group.get("member_dialog_references"),
            },
            "sdp_signaling": {
                "offer_references": sorted(
                    {
                        exchange.get("offer_sdp_reference")
                        for exchange in owned_exchanges
                        if isinstance(exchange.get("offer_sdp_reference"), str)
                    }
                )[:MAX_LIST_ITEMS],
                "answer_references": sorted(
                    {
                        exchange.get("answer_sdp_reference")
                        for exchange in owned_exchanges
                        if isinstance(exchange.get("answer_sdp_reference"), str)
                    }
                )[:MAX_LIST_ITEMS],
                "accepted_media_sections": accepted_sections[:MAX_LIST_ITEMS],
                "unsupported_media_section_count": unsupported_section_count,
                "repeated_sdp_observation_references": repeated_sdp_refs[:MAX_LIST_ITEMS],
                "unbound_sdp_message_references": unbound_sdp_refs[:MAX_LIST_ITEMS],
                "unbound_exchange_references": unbound_exchange_refs[:MAX_LIST_ITEMS],
                "association_outcome": sdp_association_outcome,
            },
            "rtp_evidence": {
                "candidate_transport_references": candidate_transports[:MAX_LIST_ITEMS],
                "source_stream_references": source_streams[:MAX_LIST_ITEMS],
                "rtp_packet_count": len(owned_rtp_frames),
                "first_observed_frame": min(owned_rtp_frames) if owned_rtp_frames else None,
                "last_observed_frame": max(owned_rtp_frames) if owned_rtp_frames else None,
                "sequence_validation_statuses": sorted(
                    {
                        stream.get("sequence_validation_status")
                        for stream in owned_streams
                        if stream.get("sequence_validation_status")
                    }
                ),
                "sequence_wrap_count": sum(
                    int(stream.get("sequence_wrap_count") or 0)
                    for stream in owned_streams
                ),
                "duplicate_sequence_observation_count": sum(
                    int(stream.get("duplicate_sequence_observation_count") or 0)
                    for stream in owned_streams
                ),
                "out_of_order_packet_count": sum(
                    int(stream.get("out_of_order_packet_count") or 0)
                    for stream in owned_streams
                ),
                "unobserved_sequence_number_slot_count": sum(
                    int(stream.get("unobserved_sequence_number_slot_count") or 0)
                    for stream in owned_streams
                ),
                "temporal_association_status": temporal_status,
                "outcome": rtp_evidence_outcome,
                "limitations": [
                    "Unobserved RTP sequence slots are not confirmed network packet loss",
                    "RTP observation boundaries are capture boundaries, not true media start or end",
                ],
            },
            "rtcp_evidence": {
                "ownership_status": rtcp_evidence["ownership_status"],
                "ownership_basis": rtcp_evidence["ownership_basis"],
                "sender_association_status_counts": rtcp_evidence[
                    "sender_association_status_counts"
                ],
                "reportee_association_status_counts": rtcp_evidence[
                    "reportee_association_status_counts"
                ],
                "established_source_association_count": rtcp_evidence[
                    "established_source_association_count"
                ],
                "measurement_origin": rtcp_evidence["measurement_origin"],
                "receiver_report_count": rtcp_evidence["receiver_report_count"],
            },
            "diagnostic_result": {
                "signaling_outcome": signaling_outcome,
                "observed_sip_outcome": observed_sip_outcome,
                "logical_call_outcome": logical_outcome_classification,
                "sip_outcome_component_counts": logical_outcome[
                    "component_outcome_counts"
                ],
                "sdp_association_outcome": sdp_association_outcome,
                "media_transport_ownership_outcome": ownership_status,
                "rtp_evidence_outcome": rtp_evidence_outcome,
                "rtcp_evidence_outcome": rtcp_evidence["ownership_status"],
                "first_supported_protocol_deviation": violation,
                "first_observed_procedure_contradiction": contradiction,
                "first_response_ownership_boundary": first_response_ownership_boundary,
                "first_missing_evidence_boundary": first_missing_boundary,
                "boundary_classification": boundary_classification,
                "identity_ambiguity_present": not bool(group.get("grouping_accepted")),
                "first_identity_boundary": (
                    {
                        "reason_code": (group.get("grouping_reason_codes") or [
                            "LOGICAL_CALL_GROUPING_NOT_ACCEPTED"
                        ])[0],
                        "evidence_status": "IDENTITY_AMBIGUITY",
                    }
                    if not group.get("grouping_accepted")
                    else None
                ),
                "last_supported_observation": last_supported_observation,
                "supporting_source_references": supporting_refs,
                "sip_response_ownership": {
                    "bound_final_response_count": len(final_refs),
                    "unbound_final_response_count": len(unbound_response_refs),
                    "unbound_response_event_references": unbound_response_refs[
                        :MAX_LIST_ITEMS
                    ],
                    "unbound_response_status_codes": unbound_response_statuses,
                    "ambiguous_unbound_response_count": sum(
                        1
                        for observation in unbound_response_observations
                        if observation.get("ambiguity_status")
                        == "MULTIPLE_CANDIDATES"
                    ),
                    "transaction_ownership_established": bool(
                        final_refs and not unbound_response_refs
                    ),
                    "evidence_class": "DERIVED",
                },
                "invite_authentication_review": invite_authentication_review,
                "branch_outcomes": branch_outcome_records[:MAX_LIST_ITEMS],
                "hypotheses": hypotheses[:MAX_DIAGNOSTIC_ITEMS],
                "next_checks": next_checks,
                "candidate_explanations": candidate_explanations[:MAX_DIAGNOSTIC_ITEMS],
                "excluded_interpretations": [
                    "A missing observation is not automatically a network failure",
                    "A SIP non-2xx response does not by itself establish a network-function root cause",
                    "An observed SIP response does not establish transaction ownership",
                    "An RTP sequence gap is not automatically network packet loss",
                    "An RTCP receiver report is not a locally measured packet-loss result",
                    "Capture-wide evidence never upgrades an unproven logical call",
                    "Encrypted or IPsec traffic is never decrypted or assumed absent",
                ][:MAX_DIAGNOSTIC_ITEMS],
                "additional_evidence_required": (
                    [
                        "Provide SDP/RTP correspondence that excludes every competing logical call and branch",
                        "Provide the missing SDP answer or RTP source-stream evidence for this logical call",
                        "Provide a capture view that exposes the encrypted or unobserved signaling leg",
                    ]
                    if diagnostic_completeness != "COMPLETE"
                    else []
                )[:MAX_DIAGNOSTIC_ITEMS],
                "diagnostic_completeness_status": diagnostic_completeness,
                "evidence_class": "DERIVED",
            },
            "evidence_class": "DERIVED",
        }

        logical_records.append(
            {
                "logical_call_reference": logical_reference,
                "grouping_status": group.get("grouping_status"),
                "grouping_accepted": bool(group.get("grouping_accepted")),
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
                        exchange.get("exchange_reference")
                        for exchange in owned_exchanges
                        if isinstance(exchange.get("exchange_reference"), str)
                    ]
                )[:MAX_LIST_ITEMS],
                "accepted_media_sections": _unique(
                    [section.get("message_reference") for section in accepted_sections]
                )[:MAX_LIST_ITEMS],
                "candidate_rtp_transport_references": candidate_transports[
                    :MAX_LIST_ITEMS
                ],
                "source_stream_references": source_streams[:MAX_LIST_ITEMS],
                "shared_source_stream_references": shared_streams[:MAX_LIST_ITEMS],
                "temporal_constraints": {
                    "status": temporal_status,
                    "member_attempt_statuses": sorted(set(temporal_statuses)),
                    "capture_boundary_limitations": [
                        "SIP and RTP observations are capture-bound; no true media start or end is claimed",
                        "Temporal evidence narrows an already-supported identity candidate and never replaces identity",
                    ],
                },
                "rtcp_evidence": rtcp_evidence,
                "ownership_status": ownership_status,
                "ownership_basis": ownership_reasons,
                "unbound_sip_event_references": unbound_sip_refs[:MAX_LIST_ITEMS],
                "repeated_sdp_observation_references": repeated_sdp_refs[:MAX_LIST_ITEMS],
                "unbound_sdp_message_references": unbound_sdp_refs[:MAX_LIST_ITEMS],
                "missing_and_ambiguous_evidence": missing[:MAX_DIAGNOSTIC_ITEMS],
                "last_supported_observation": last_supported_observation,
                "first_supported_diagnostic_boundary": (
                    None
                    if boundary_classification == "NO_ABNORMAL_EVIDENCE_OBSERVED"
                    else {
                        "reason_code": (
                            violation.get("reason_code")
                            if violation is not None
                            else contradiction.get("reason_code")
                            if contradiction is not None
                            else "SIP_NEGATIVE_FINAL_OUTCOME_OBSERVED"
                            if logical_outcome_classification
                            == "NEGATIVE_FINAL_BRANCH_OBSERVED"
                            else "SIP_CANCELLED_INVITE_OUTCOME_OBSERVED"
                            if logical_outcome_classification
                            == "CANCELLATION_OUTCOME_OBSERVED"
                            else "SIP_FORK_BRANCH_NEGATIVE_OUTCOME_OBSERVED"
                            if logical_outcome_classification
                            == "MIXED_FORK_OUTCOMES_OBSERVED"
                            else "SIP_RESPONSE_TRANSACTION_OWNERSHIP_NOT_ESTABLISHED"
                            if unbound_response_refs and not final_statuses
                            else first_missing_boundary.get("reason_code")
                            if first_missing_boundary is not None
                            else "LOGICAL_CALL_MEDIA_CHAIN_INCOMPLETE"
                        ),
                        "evidence_status": boundary_classification,
                    }
                ),
                "required_additional_evidence": (
                    []
                    if diagnostic_completeness == "COMPLETE"
                    else [
                        "Provide SDP/RTP correspondence that excludes every competing logical call",
                        "Provide the missing SDP answer or source-stream evidence for this logical call",
                    ]
                ),
                "diagnostic_review": diagnostic_review,
                "evidence_class": "DERIVED",
            }
        )
    logical_ownership_counts: dict[str, int] = defaultdict(int)
    boundary_classification_counts: dict[str, int] = defaultdict(int)
    diagnostic_completeness_counts: dict[str, int] = defaultdict(int)
    logical_call_outcome_counts: dict[str, int] = defaultdict(int)
    sip_outcome_classification_counts: dict[str, int] = defaultdict(int)
    for record in logical_records:
        logical_ownership_counts[record["ownership_status"]] += 1
        review = record.get("diagnostic_review") or {}
        result = review.get("diagnostic_result") or {}
        boundary_classification_counts[
            str(result.get("boundary_classification"))
        ] += 1
        diagnostic_completeness_counts[
            str(result.get("diagnostic_completeness_status"))
        ] += 1
        logical_call_outcome_counts[
            str(result.get("logical_call_outcome"))
        ] += 1
        sip_outcome_classification_counts[
            str(result.get("observed_sip_outcome"))
        ] += 1
    for attempt_record in attempt_records:
        outcome = attempt_record.get("sip_final_outcome") or {}
        if outcome.get("classification"):
            sip_outcome_classification_counts[
                str(outcome["classification"])
            ] += 1
    for branch_record in branch_records:
        outcome = branch_record.get("sip_final_outcome") or {}
        if outcome.get("classification"):
            sip_outcome_classification_counts[
                str(outcome["classification"])
            ] += 1

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
        "accepted_logical_call_count": sum(
            1 for record in logical_records if record["grouping_accepted"]
        ),
        "logical_calls": logical_records,
        "logical_call_ownership_counts": dict(logical_ownership_counts),
        "logical_call_boundary_classification_counts": dict(
            sorted(boundary_classification_counts.items())
        ),
        "logical_call_diagnostic_completeness_counts": dict(
            sorted(diagnostic_completeness_counts.items())
        ),
        "logical_call_outcome_counts": dict(
            sorted(logical_call_outcome_counts.items())
        ),
        "sip_outcome_classification_counts": dict(
            sorted(sip_outcome_classification_counts.items())
        ),
        "capture_visibility_limited": capture_visibility_limited,
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
            "A SIP non-2xx response is a SIP outcome, not a proven network-function root cause",
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
            "MEDIA_DELIVERY",
            "TEMPORAL_RTP_OWNERSHIP",
        ],
        "evidence_class": "DERIVED",
    }


def _sha256(path: Path) -> str | None:
    import hashlib

    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()