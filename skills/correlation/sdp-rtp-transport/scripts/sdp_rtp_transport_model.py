#!/usr/bin/env python3
"""Bounded SDP-to-RTP UDP transport endpoint correlation.

This Correlation-layer model consumes already-accepted SDP Analysis and
RTP/RTCP Analysis artifacts. It parses no SDP body, decodes no RTP packet,
reads no capture and reconstructs no SIP dialog or IMS session. The only
join key is an exact capture-scoped HMAC endpoint reference produced by the
sdp-rtp Protocol Skill with a shared local endpoint key.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SKILLS = HERE.parents[2]
SDP_SCRIPTS = SKILLS / "protocol" / "sdp-rtp" / "scripts"
for path in (SDP_SCRIPTS, HERE):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402
from endpoint_reference import (  # noqa: E402
    is_context_reference,
    is_endpoint_reference,
)

ANALYSIS_NAME = "sdp-rtp-transport"
ANALYSIS_VERSION = "0.1.0"
CAPABILITY = "bounded SDP-to-RTP UDP transport endpoint correlation"
DOMAIN = "sdp-rtp-transport"
SDP_ANALYSIS_VERSION = sdp_model.ANALYSIS_VERSION
SDP_EVENT_SCHEMA_VERSION = sdp_model.EVENT_SCHEMA_VERSION
RTP_ANALYSIS_VERSION = rtp_rtcp_model.ANALYSIS_VERSION
RTP_EVENT_SCHEMA_VERSION = rtp_rtcp_model.EVENT_SCHEMA_VERSION
RTP_PARSER_VERSION = rtp_rtcp_model.PARSER_VERSION

CAPTURE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ +-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STREAM_REFERENCE_PATTERN = re.compile(r"^rtp-udp-stream:.+:[0-9]+$")
CORRELATION_REFERENCE_PATTERN = re.compile(
    r"^sdp-rtp-transport:.+:[0-9]+\.[0-9]+\.[0-9]+$"
)

MAX_CORRELATIONS = 512
MAX_STREAMS = 1024
MAX_EVENT_REFERENCES = 64
MAX_LIST_ITEMS = 64

ASSOCIATION_STATUSES = (
    "MATCHED_ENDPOINT",
    "BUNDLE_TRANSPORT_MATCHED",
    "AMBIGUOUS",
    "INSUFFICIENT_EVIDENCE",
    "UNMATCHED",
    "OUT_OF_SCOPE",
)
CORRELATION_STRENGTHS = ("STRONG", "MEDIUM", "WEAK")
CORRELATION_TYPES = ("SINGLE_MEDIA", "BUNDLE_MEDIA", "UNAVAILABLE_MEDIA")
ENDPOINT_EVIDENCE_STATUSES = (
    "ESTABLISHED",
    "INCOMPLETE",
    "AMBIGUOUS",
    "CONFLICT",
    "UNAVAILABLE",
)
MATCH_DIRECTIONS = (
    "RTP_SOURCE_ENDPOINT_MATCH",
    "RTP_DESTINATION_ENDPOINT_MATCH",
)


class InputError(ValueError):
    """Raised when an accepted input artifact is contradictory or malformed."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"{label} could not be read: {exc}") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise InputError(f"{label} must be an object")
    return document


def _unique(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _reference_suffix(reference: str) -> str:
    return reference.split(":", 1)[1] if ":" in reference else reference


def _capture(document: dict[str, Any], label: str) -> tuple[str, str]:
    provenance = document.get("input_provenance")
    if not isinstance(provenance, dict):
        raise InputError(f"{label} input_provenance is missing")
    captures = provenance.get("capture_files")
    if (
        not isinstance(captures, list)
        or len(captures) != 1
        or not isinstance(captures[0], str)
        or not CAPTURE_NAME_PATTERN.fullmatch(captures[0])
    ):
        raise InputError(f"{label} must publish exactly one privacy-safe capture")
    sha = provenance.get("capture_sha256")
    if not isinstance(sha, str) or not SHA256_PATTERN.fullmatch(sha):
        raise InputError(f"{label} capture_sha256 is malformed")
    return captures[0], sha


def load_sdp_analysis(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SDP analysis")
    try:
        sdp_model.validate_analysis(document)
    except sdp_model.InputError as exc:
        raise InputError(f"SDP analysis is not accepted: {exc}") from None
    if document.get("analysis_name") != sdp_model.ANALYSIS_NAME:
        raise InputError("SDP analysis_name is not accepted")
    if document.get("analysis_version") != SDP_ANALYSIS_VERSION:
        raise InputError("SDP analysis_version is not accepted")
    if document.get("event_schema_version") != SDP_EVENT_SCHEMA_VERSION:
        raise InputError("SDP event_schema_version is not accepted")
    provenance = document.get("input_provenance") or {}
    if provenance.get("parser_version") != sdp_model.PARSER_VERSION:
        raise InputError("SDP parser_version is not accepted")
    if provenance.get("message_count") != document.get("message_count"):
        raise InputError("SDP input_provenance message count disagrees")
    capture, sha = _capture(document, "SDP")
    for message in document.get("messages") or []:
        if message.get("capture_file") != capture or message.get("capture_sha256") != sha:
            raise InputError("an SDP message disagrees with the SDP capture provenance")
        reference = message.get("source_reference")
        if (
            not isinstance(reference, str)
            or reference.split(":", 2)[1:2] != [capture]
        ):
            raise InputError("an SDP source reference disagrees with the capture")
        if message.get("parser_version") != sdp_model.PARSER_VERSION:
            raise InputError("an SDP message parser_version is not accepted")
        if message.get("media_section_count") != len(message.get("media_sections") or []):
            raise InputError("an SDP media section count disagrees with its array")
        for media in message.get("media_sections") or []:
            index = media.get("index")
            if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < 64:
                raise InputError("an SDP media section index is invalid")
    context = provenance.get("endpoint_context_reference")
    if context is not None and not is_context_reference(context):
        raise InputError("SDP endpoint context reference is malformed")
    return document


def load_rtp_analysis(path: Path) -> dict[str, Any]:
    document = _load_json(path, "RTP/RTCP analysis")
    try:
        rtp_rtcp_model.validate_analysis(document)
    except rtp_rtcp_model.InputError as exc:
        raise InputError(f"RTP/RTCP analysis is not accepted: {exc}") from None
    if document.get("analysis_name") != rtp_rtcp_model.ANALYSIS_NAME:
        raise InputError("RTP/RTCP analysis_name is not accepted")
    if document.get("analysis_version") != RTP_ANALYSIS_VERSION:
        raise InputError("RTP/RTCP analysis_version is not accepted")
    if document.get("event_schema_version") != RTP_EVENT_SCHEMA_VERSION:
        raise InputError("RTP/RTCP event_schema_version is not accepted")
    provenance = document.get("input_provenance") or {}
    if provenance.get("parser_version") != RTP_PARSER_VERSION:
        raise InputError("RTP/RTCP parser_version is not accepted")
    message_count = provenance.get("input_message_count")
    if (
        isinstance(message_count, bool)
        or not isinstance(message_count, int)
        or message_count < 0
        or message_count > int(document.get("event_count") or 0)
    ):
        raise InputError("RTP/RTCP input_provenance count disagrees")
    capture, sha = _capture(document, "RTP/RTCP")
    references: set[str] = set()
    for event in document.get("events") or []:
        reference = event.get("event_reference")
        if not isinstance(reference, str) or reference in references:
            raise InputError("an RTP/RTCP event reference is invalid or duplicated")
        references.add(reference)
        if event.get("capture_file") != capture or event.get("capture_sha256") != sha:
            raise InputError("an RTP/RTCP event disagrees with the capture provenance")
        parts = reference.split(":", 2)
        if len(parts) < 3 or parts[1] != capture:
            raise InputError("an RTP/RTCP source reference disagrees with the capture")
        if event.get("protocol") == "RTP":
            if event.get("parser_version") != RTP_PARSER_VERSION:
                raise InputError("an RTP event parser_version is not accepted")
        elif event.get("parser_version") not in (None, RTP_PARSER_VERSION):
            raise InputError("an RTCP event parser_version is not accepted")
        if event.get("protocol") == "RTP":
            for key in (
                "source_transport_endpoint_reference",
                "destination_transport_endpoint_reference",
            ):
                value = event.get(key)
                if value is not None and not is_endpoint_reference(value):
                    raise InputError("an RTP event endpoint reference is malformed")
            status = event.get("transport_endpoint_status")
            if status is not None and status not in {
                "ESTABLISHED",
                "INCOMPLETE",
                "AMBIGUOUS",
                "UNAVAILABLE",
            }:
                raise InputError("an RTP event endpoint status is invalid")
    context = provenance.get("endpoint_context_reference")
    if context is not None and not is_context_reference(context):
        raise InputError("RTP/RTCP endpoint context reference is malformed")
    if context != document.get("endpoint_context_reference"):
        raise InputError("RTP/RTCP endpoint context references disagree")
    return document


def verify_provenance(
    sdp: dict[str, Any],
    rtp: dict[str, Any],
    *,
    sdp_path: Path,
    rtp_path: Path,
) -> dict[str, Any]:
    sdp_capture, sdp_sha = _capture(sdp, "SDP")
    rtp_capture, rtp_sha = _capture(rtp, "RTP/RTCP")
    if sdp_capture != rtp_capture:
        raise InputError("SDP and RTP/RTCP artifacts describe different captures")
    if sdp_sha != rtp_sha:
        raise InputError("SDP and RTP/RTCP artifacts publish different capture SHA-256 values")
    sdp_context = (sdp.get("input_provenance") or {}).get(
        "endpoint_context_reference"
    )
    rtp_context = (rtp.get("input_provenance") or {}).get(
        "endpoint_context_reference"
    )
    if sdp_context is not None and rtp_context is not None and sdp_context != rtp_context:
        raise InputError("SDP and RTP/RTCP endpoint contexts differ")
    return {
        "sdp_analysis_source_name": sdp_path.name,
        "sdp_analysis_sha256": _sha256(sdp_path),
        "sdp_analysis_version": sdp.get("analysis_version"),
        "sdp_event_schema_version": sdp.get("event_schema_version"),
        "rtp_rtcp_analysis_source_name": rtp_path.name,
        "rtp_rtcp_analysis_sha256": _sha256(rtp_path),
        "rtp_rtcp_analysis_version": rtp.get("analysis_version"),
        "rtp_rtcp_event_schema_version": rtp.get("event_schema_version"),
        "capture_files": [sdp_capture],
        "capture_sha256": sdp_sha,
        "endpoint_context_reference": sdp_context or rtp_context,
        "input_status": "ACCEPTED",
    }


def _bundle_reference(
    message: dict[str, Any], group_index: int
) -> str:
    return f"sdp-bundle:{message['source_reference']}:{group_index}"


def _bundle_membership(
    message: dict[str, Any], media: dict[str, Any]
) -> tuple[list[int], bool]:
    mid = media.get("mid")
    if not isinstance(mid, str) or not mid or mid == "AMBIGUOUS":
        return ([], False)
    groups = [
        index
        for index, group in enumerate(message["session"].get("groups") or [])
        if group.get("semantics") == "BUNDLE"
        and group.get("reference_status") == "RESOLVED"
        and mid in (group.get("mids") or [])
    ]
    if len(groups) > 1:
        return (groups, True)
    return (groups, False)


def _media_entry(message: dict[str, Any], media: dict[str, Any]) -> dict[str, Any]:
    endpoint = media.get("transport_endpoint")
    endpoint_status = None
    endpoint_reference = None
    reasons: list[str] = []
    if isinstance(endpoint, dict):
        endpoint_status = endpoint.get("endpoint_status")
        endpoint_reference = endpoint.get("endpoint_reference")
        reasons = [
            item for item in endpoint.get("reason_codes") or [] if isinstance(item, str)
        ]
    groups, membership_ambiguous = _bundle_membership(message, media)
    eligible = (
        message.get("evidence_status") == "OBSERVED"
        and media.get("evidence_status") == "OBSERVED"
        and endpoint_status == "ESTABLISHED"
        and is_endpoint_reference(endpoint_reference)
    )
    return {
        "message": message,
        "media": media,
        "message_reference": message["source_reference"],
        "media_index": media["index"],
        "mid": media.get("mid") if isinstance(media.get("mid"), str) else None,
        "endpoint_status": endpoint_status,
        "endpoint_reference": endpoint_reference if is_endpoint_reference(endpoint_reference) else None,
        "reason_codes": reasons,
        "bundle_group_indexes": groups,
        "bundle_membership_ambiguous": membership_ambiguous,
        "eligible": eligible,
    }


def _media_observed(entry: dict[str, Any]) -> bool:
    return entry["message"].get("evidence_status") == "OBSERVED" and entry["media"].get(
        "evidence_status"
    ) == "OBSERVED"


def _streams(rtp: dict[str, Any], capture: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    counts = {
        "rtp_packet_count": 0,
        "correlatable_rtp_packet_count": 0,
        "non_observed_rtp_packet_count": 0,
        "ungrouped_rtp_packet_count": 0,
    }
    grouped: dict[int, dict[str, Any]] = {}
    for event in rtp.get("events") or []:
        if event.get("protocol") != "RTP":
            continue
        counts["rtp_packet_count"] += 1
        if event.get("evidence_status") != "OBSERVED":
            counts["non_observed_rtp_packet_count"] += 1
            continue
        counts["correlatable_rtp_packet_count"] += 1
        stream_id = event.get("udp_stream")
        if isinstance(stream_id, bool) or not isinstance(stream_id, int) or stream_id < 0:
            counts["ungrouped_rtp_packet_count"] += 1
            continue
        stream = grouped.setdefault(
            stream_id,
            {
                "stream_id": stream_id,
                "reference": f"rtp-udp-stream:{capture}:{stream_id}",
                "event_references": [],
                "source_references": [],
                "destination_references": [],
                "ssrc_references": [],
                "frame_numbers": [],
                "endpoint_statuses": [],
            },
        )
        stream["event_references"].append(event["event_reference"])
        source = event.get("source_transport_endpoint_reference")
        destination = event.get("destination_transport_endpoint_reference")
        if is_endpoint_reference(source):
            stream["source_references"].append(source)
        if is_endpoint_reference(destination):
            stream["destination_references"].append(destination)
        ssrc = event.get("ssrc_reference")
        if isinstance(ssrc, str):
            stream["ssrc_references"].append(ssrc)
        frame = event.get("frame_number")
        if isinstance(frame, int) and not isinstance(frame, bool):
            stream["frame_numbers"].append(frame)
        status = event.get("transport_endpoint_status")
        stream["endpoint_statuses"].append(
            status if status in {"ESTABLISHED", "INCOMPLETE", "AMBIGUOUS", "UNAVAILABLE"} else "UNAVAILABLE"
        )
    streams: list[dict[str, Any]] = []
    for stream_id in sorted(grouped):
        raw = grouped[stream_id]
        sources = _unique(raw["source_references"])
        destinations = _unique(raw["destination_references"])
        statuses = raw["endpoint_statuses"]
        missing: list[str] = []
        if len(sources) > 1 or len(destinations) > 1:
            status = "CONFLICT"
        elif "CONFLICT" in statuses:
            status = "CONFLICT"
        elif sources and destinations:
            # Use the unambiguous endpoint subset. Encapsulated duplicate
            # observations may lack endpoint evidence without contradicting the
            # established pair; the coverage limitation is preserved.
            status = "ESTABLISHED"
            if any(item != "ESTABLISHED" for item in statuses):
                missing.append("ENDPOINT_EVIDENCE_INCOMPLETE_FOR_SOME_PACKETS")
        elif "AMBIGUOUS" in statuses:
            status = "AMBIGUOUS"
        elif any(item != "ESTABLISHED" for item in statuses):
            status = "INCOMPLETE"
        elif not sources or not destinations:
            status = "UNAVAILABLE"
        else:
            status = "ESTABLISHED"
        frames = sorted(raw["frame_numbers"])
        streams.append(
            {
                "stream_id": stream_id,
                "reference": raw["reference"],
                "event_references": _unique(raw["event_references"]),
                "source_references": sources,
                "destination_references": destinations,
                "ssrc_references": _unique(raw["ssrc_references"]),
                "packet_count": len(raw["event_references"]),
                "first_frame_number": frames[0] if frames else None,
                "last_frame_number": frames[-1] if frames else None,
                "endpoint_evidence_status": status,
                "missing_evidence": (
                    ["RTP_STREAM_ENDPOINT_EVIDENCE_INCOMPLETE"]
                    if status in {"INCOMPLETE", "UNAVAILABLE"}
                    else missing
                ),
                "conflict_findings": (
                    ["UDP_STREAM_ENDPOINT_SET_CONFLICT"]
                    if status in {"CONFLICT", "AMBIGUOUS"}
                    else []
                ),
                "used": False,
            }
        )
    return (streams, counts)


def _directions(stream: dict[str, Any], endpoint_reference: str) -> list[str]:
    directions: list[str] = []
    if endpoint_reference in stream["source_references"]:
        directions.append("RTP_SOURCE_ENDPOINT_MATCH")
    if endpoint_reference in stream["destination_references"]:
        directions.append("RTP_DESTINATION_ENDPOINT_MATCH")
    return directions


def _correlation(
    reference: str,
    correlation_type: str,
    entries: list[dict[str, Any]],
    *,
    endpoint_reference: str | None,
    bundle_reference: str | None,
    stream: dict[str, Any] | None,
    status: str,
    strength: str,
    missing: list[str],
    conflicts: list[str],
    streams: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    selected = streams if streams is not None else ([stream] if stream is not None else [])
    directions = (
        _unique(
            [
                direction
                for selected_stream in selected
                for direction in _directions(selected_stream, endpoint_reference)
            ]
        )
        if endpoint_reference
        else []
    )
    return {
        "correlation_reference": reference,
        "correlation_type": correlation_type,
        "sdp_message_references": _unique(
            [entry["message_reference"] for entry in entries]
        )[:MAX_LIST_ITEMS],
        "sdp_media_sections": [
            {
                "message_reference": entry["message_reference"],
                "media_index": entry["media_index"],
                "mid": entry["mid"],
            }
            for entry in entries[:MAX_LIST_ITEMS]
        ],
        "bundle_references": [bundle_reference] if bundle_reference else [],
        "endpoint_references": [endpoint_reference] if endpoint_reference else [],
        "rtp_udp_stream_references": [
            selected_stream["reference"] for selected_stream in selected
        ],
        "rtp_event_references": _unique(
            [
                event_reference
                for selected_stream in selected
                for event_reference in selected_stream["event_references"]
            ]
        )[:MAX_EVENT_REFERENCES],
        "match_directions": directions,
        "association_status": status,
        "correlation_strength": strength,
        "missing_evidence": _unique(missing)[:16],
        "conflict_findings": _unique(conflicts)[:16],
        "evidence_class": "DERIVED",
    }


def _unavailable_correlation(entry: dict[str, Any]) -> dict[str, Any]:
    reference = (
        f"{ANALYSIS_NAME}:{_reference_suffix(entry['message_reference'])}."
        f"{entry['media_index']}"
    )
    if not _media_observed(entry):
        status = "INSUFFICIENT_EVIDENCE"
        missing = ["SDP_EVIDENCE_NOT_OBSERVED"]
        conflicts: list[str] = []
    elif entry["endpoint_status"] == "OUT_OF_SCOPE":
        status = "OUT_OF_SCOPE"
        missing = entry["reason_codes"] or ["ENDPOINT_OUT_OF_SCOPE"]
        conflicts = []
    elif entry["endpoint_status"] == "UNAVAILABLE":
        status = "INSUFFICIENT_EVIDENCE"
        missing = entry["reason_codes"] or ["ENDPOINT_REFERENCE_UNAVAILABLE"]
        conflicts = []
    else:
        status = "INSUFFICIENT_EVIDENCE"
        missing = ["ENDPOINT_REFERENCE_UNAVAILABLE"]
        conflicts = entry["reason_codes"]
    return _correlation(
        reference,
        "UNAVAILABLE_MEDIA",
        [entry],
        endpoint_reference=entry["endpoint_reference"],
        bundle_reference=None,
        stream=None,
        status=status,
        strength="WEAK",
        missing=missing,
        conflicts=conflicts,
    )


def _mirror_pair(
    left: dict[str, Any], right: dict[str, Any]
) -> bool:
    """Two UDP streams are one bidirectional pair when their endpoint sets mirror."""
    return (
        left["reference"] != right["reference"]
        and len(left["source_references"]) == 1
        and len(left["destination_references"]) == 1
        and len(right["source_references"]) == 1
        and len(right["destination_references"]) == 1
        and left["source_references"] == right["destination_references"]
        and left["destination_references"] == right["source_references"]
    )


def _match_unit(
    entries: list[dict[str, Any]],
    endpoint_reference: str,
    streams: list[dict[str, Any]],
    bundle_reference: str | None,
) -> dict[str, Any]:
    entries = sorted(
        entries, key=lambda item: (item["message_reference"], item["media_index"])
    )
    first = entries[0]
    reference = (
        f"{ANALYSIS_NAME}:{_reference_suffix(first['message_reference'])}."
        f"{first['media_index']}"
    )
    if not entries:
        raise InputError("a correlation unit must contain at least one media section")
    matching = [
        stream for stream in streams if endpoint_reference in (
            stream["source_references"] + stream["destination_references"]
        )
    ]
    candidates = [
        stream for stream in matching if stream["endpoint_evidence_status"] == "ESTABLISHED"
    ]
    non_established = [
        stream for stream in matching if stream["endpoint_evidence_status"] != "ESTABLISHED"
    ]
    if candidates and non_established:
        candidate_endpoints: set[str] = set()
        for stream in candidates:
            candidate_endpoints.update(stream["source_references"])
            candidate_endpoints.update(stream["destination_references"])
        unrelated = [
            stream
            for stream in non_established
            if not (
                set(stream["source_references"])
                | set(stream["destination_references"])
            ) <= candidate_endpoints
        ]
        if unrelated:
            for stream in candidates:
                stream["used"] = True
            return _correlation(
                reference,
                "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
                entries,
                endpoint_reference=endpoint_reference,
                bundle_reference=bundle_reference,
                stream=None,
                status="AMBIGUOUS",
                strength="MEDIUM",
                missing=["RTP_STREAM_NOT_UNIQUE"],
                conflicts=["UNRELATED_AMBIGUOUS_RTP_STREAM"],
            )
    if len(candidates) == 2 and _mirror_pair(candidates[0], candidates[1]):
        for stream in candidates:
            stream["used"] = True
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=None,
            streams=candidates,
            status="MATCHED_ENDPOINT",
            strength="STRONG",
            missing=_unique(
                [
                    item
                    for stream in candidates
                    for item in stream["missing_evidence"]
                ]
            ),
            conflicts=[
                "DUPLICATE_RTP_STREAM_GROUPING_IGNORED"
            ] if non_established else [],
        )
    if not candidates and matching:
        ambiguous_candidate = any(
            stream["endpoint_evidence_status"] in {"AMBIGUOUS", "CONFLICT"}
            for stream in matching
        )
        conflicts: list[str] = []
        if any(
            stream["endpoint_evidence_status"] == "CONFLICT" for stream in matching
        ):
            conflicts.append("UDP_STREAM_ENDPOINT_SET_CONFLICT")
        if len(matching) > 1:
            conflicts.append("MULTIPLE_RTP_STREAMS")
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=None,
            status="AMBIGUOUS" if ambiguous_candidate else "INSUFFICIENT_EVIDENCE",
            strength="MEDIUM" if ambiguous_candidate else "WEAK",
            missing=(
                ["RTP_STREAM_NOT_UNIQUE"]
                if ambiguous_candidate
                else ["RTP_STREAM_ENDPOINT_EVIDENCE_INCOMPLETE"]
            ),
            conflicts=conflicts,
        )
    if not candidates:
        if len(entries) > 1 and bundle_reference is None:
            return _correlation(
                reference,
                "SINGLE_MEDIA",
                entries,
                endpoint_reference=endpoint_reference,
                bundle_reference=None,
                stream=None,
                status="AMBIGUOUS",
                strength="MEDIUM",
                missing=["NO_OBSERVED_RTP_STREAM_FOR_ENDPOINT"],
                conflicts=["UNRELATED_MEDIA_SHARE_ENDPOINT"],
            )
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=None,
            status="UNMATCHED",
            strength="WEAK",
            missing=["NO_OBSERVED_RTP_STREAM_FOR_ENDPOINT"],
            conflicts=[],
        )
    if len(candidates) > 1:
        for stream in candidates:
            stream["used"] = True
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=None,
            status="AMBIGUOUS",
            strength="MEDIUM",
            missing=["RTP_STREAM_NOT_UNIQUE"],
            conflicts=["MULTIPLE_RTP_STREAMS"],
        )
    stream = candidates[0]
    stream["used"] = True
    if stream["endpoint_evidence_status"] in {"CONFLICT", "AMBIGUOUS"}:
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=stream,
            status="AMBIGUOUS",
            strength="MEDIUM",
            missing=["RTP_ENDPOINT_EVIDENCE_AMBIGUOUS"],
            conflicts=["UDP_STREAM_ENDPOINT_SET_CONFLICT"],
        )
    if stream["endpoint_evidence_status"] != "ESTABLISHED":
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=stream,
            status="INSUFFICIENT_EVIDENCE",
            strength="WEAK",
            missing=["RTP_STREAM_ENDPOINT_EVIDENCE_INCOMPLETE"],
            conflicts=[],
        )
    if len(entries) > 1 and bundle_reference is None:
        return _correlation(
            reference,
            "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=None,
            stream=stream,
            status="AMBIGUOUS",
            strength="MEDIUM",
            missing=[],
            conflicts=["UNRELATED_MEDIA_SHARE_ENDPOINT"],
        )
    directions = _directions(stream, endpoint_reference)
    if len(directions) > 1:
        return _correlation(
            reference,
            "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
            entries,
            endpoint_reference=endpoint_reference,
            bundle_reference=bundle_reference,
            stream=stream,
            status="AMBIGUOUS",
            strength="MEDIUM",
            missing=["TRANSPORT_DIRECTION_NOT_UNIQUE"],
            conflicts=["SOURCE_AND_DESTINATION_ENDPOINT_SHARED"],
        )
    return _correlation(
        reference,
        "BUNDLE_MEDIA" if bundle_reference else "SINGLE_MEDIA",
        entries,
        endpoint_reference=endpoint_reference,
        bundle_reference=bundle_reference,
        stream=stream,
        status="BUNDLE_TRANSPORT_MATCHED" if bundle_reference else "MATCHED_ENDPOINT",
        strength="STRONG",
        missing=list(stream["missing_evidence"]),
        conflicts=[],
    )


def _bundle_unit_key(entry: dict[str, Any]) -> tuple[str, int] | None:
    if entry["bundle_membership_ambiguous"]:
        return None
    if len(entry["bundle_group_indexes"]) != 1:
        return None
    return (entry["message_reference"], entry["bundle_group_indexes"][0])


def _stream_inventory(
    stream: dict[str, Any],
) -> dict[str, Any]:
    return {
        "rtp_udp_stream_reference": stream["reference"],
        "rtp_event_references": stream["event_references"][:MAX_EVENT_REFERENCES],
        "packet_count": stream["packet_count"],
        "first_frame_number": stream["first_frame_number"],
        "last_frame_number": stream["last_frame_number"],
        "observed_ssrc_references": stream["ssrc_references"][:MAX_LIST_ITEMS],
        "source_endpoint_references": stream["source_references"][:MAX_LIST_ITEMS],
        "destination_endpoint_references": stream["destination_references"][:MAX_LIST_ITEMS],
        "endpoint_evidence_status": stream["endpoint_evidence_status"],
        "missing_evidence": stream["missing_evidence"],
        "conflict_findings": stream["conflict_findings"],
        "evidence_class": "DERIVED",
    }


def build_analysis(
    sdp: dict[str, Any],
    rtp: dict[str, Any],
    *,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    capture = provenance["capture_files"][0]
    media_entries: list[dict[str, Any]] = []
    for message in sdp.get("messages") or []:
        for media in message.get("media_sections") or []:
            media_entries.append(_media_entry(message, media))
    media_entries.sort(
        key=lambda item: (item["message_reference"], item["media_index"])
    )
    streams, stream_counts = _streams(rtp, capture)

    eligible = [entry for entry in media_entries if entry["eligible"]]
    by_endpoint: dict[str, list[dict[str, Any]]] = {}
    for entry in eligible:
        by_endpoint.setdefault(entry["endpoint_reference"], []).append(entry)

    correlations: list[dict[str, Any]] = []
    for endpoint_reference in sorted(by_endpoint):
        owners = sorted(
            by_endpoint[endpoint_reference],
            key=lambda item: (item["message_reference"], item["media_index"]),
        )
        bundle_keys = [_bundle_unit_key(entry) for entry in owners]
        if (
            len(owners) > 1
            and all(key is not None for key in bundle_keys)
            and len(set(bundle_keys)) == 1
        ):
            key = bundle_keys[0]
            bundle_reference = _bundle_reference(owners[0]["message"], key[1])
            correlations.append(
                _match_unit(owners, endpoint_reference, streams, bundle_reference)
            )
            continue
        if len(owners) > 1:
            correlations.append(
                _match_unit(owners, endpoint_reference, streams, None)
            )
        else:
            correlations.append(
                _match_unit([owners[0]], endpoint_reference, streams, None)
            )

    for entry in media_entries:
        if entry["eligible"]:
            continue
        correlations.append(_unavailable_correlation(entry))

    correlation_sort_key = {
        status: index for index, status in enumerate(ASSOCIATION_STATUSES)
    }
    correlations.sort(
        key=lambda item: (
            item["correlation_reference"],
            correlation_sort_key[item["association_status"]],
        )
    )
    published = correlations[:MAX_CORRELATIONS]
    unmatched_streams = [
        _stream_inventory(stream)
        for stream in sorted(streams, key=lambda item: item["stream_id"])
        if not stream["used"]
        and (
            stream["source_references"]
            or stream["destination_references"]
        )
    ][:MAX_STREAMS]

    status_counts = {
        status: sum(1 for item in published if item["association_status"] == status)
        for status in ASSOCIATION_STATUSES
    }
    with_endpoint = sum(1 for entry in media_entries if entry["endpoint_reference"])
    streams_with_endpoint = sum(
        1
        for stream in streams
        if stream["source_references"] or stream["destination_references"]
    )
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "capability": CAPABILITY,
        "input_provenance": provenance,
        "correlation_count": len(published),
        "correlations": published,
        "unmatched_stream_count": len(unmatched_streams),
        "unmatched_streams": unmatched_streams,
        "completeness": {
            "sdp_message_count": len(sdp.get("messages") or []),
            "sdp_media_section_count": len(media_entries),
            "sdp_media_with_endpoint_count": with_endpoint,
            "sdp_media_without_endpoint_count": len(media_entries) - with_endpoint,
            "sdp_media_correlatable_count": len(eligible),
            "rtp_packet_count": stream_counts["rtp_packet_count"],
            "correlatable_rtp_packet_count": stream_counts[
                "correlatable_rtp_packet_count"
            ],
            "non_observed_rtp_packet_count": stream_counts[
                "non_observed_rtp_packet_count"
            ],
            "ungrouped_rtp_packet_count": stream_counts[
                "ungrouped_rtp_packet_count"
            ],
            "rtp_stream_count": len(streams),
            "rtp_stream_with_endpoint_count": streams_with_endpoint,
            "rtp_stream_without_endpoint_count": len(streams) - streams_with_endpoint,
            "correlation_count": len(published),
            "correlations_omitted": max(0, len(correlations) - len(published)),
            "matched_correlation_count": status_counts["MATCHED_ENDPOINT"],
            "bundle_matched_correlation_count": status_counts[
                "BUNDLE_TRANSPORT_MATCHED"
            ],
            "ambiguous_correlation_count": status_counts["AMBIGUOUS"],
            "insufficient_correlation_count": status_counts[
                "INSUFFICIENT_EVIDENCE"
            ],
            "unmatched_correlation_count": status_counts["UNMATCHED"],
            "out_of_scope_correlation_count": status_counts["OUT_OF_SCOPE"],
            "unmatched_stream_count": len(unmatched_streams),
        },
        "limitations": [
            "Correlation is limited to exact capture-scoped HMAC endpoint equality from accepted SDP and RTP/RTCP artifacts",
            "No SDP body is parsed, no RTP packet is decoded and no PCAP is read here",
            "An endpoint match is transport correspondence only; it is not an IMS session identity, call identity or media-delivery proof",
            "BUNDLE shared transport is grouped from resolved SDP BUNDLE groups; RTP header-extension MID demultiplexing is not implemented",
            "ICE candidate selection, STUN, TURN, NAT rewriting, DTLS and SRTP decryption are not interpreted",
            "RTP stream reconstruction, sequence analysis, packet loss, jitter, MOS, QoS and RTCP stream correlation are not implemented",
            "When the advertised SDP endpoint differs from the observed packet endpoint, the result is unmatched or insufficient evidence; no NAT mapping is invented",
            "No timestamp proximity is used to create or select an association",
        ],
        "not_confirmed": [
            "IMS_SESSION_IDENTITY",
            "MEDIA_DELIVERY",
            "TWO_WAY_AUDIO",
            "MEDIA_QOS",
            "CALL_SUCCESS",
            "CODEC_NEGOTIATION",
            "NAT_MAPPING",
            "ICE_CONNECTIVITY",
        ],
    }


def validate_analysis(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise InputError("SDP/RTP transport correlation must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("correlation analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("correlation analysis_version is not accepted")
    if document.get("domain") != DOMAIN:
        raise InputError("correlation domain is not accepted")
    correlations = document.get("correlations")
    if not isinstance(correlations, list):
        raise InputError("correlations must be an array")
    if document.get("correlation_count") != len(correlations):
        raise InputError("correlation_count does not match the correlation array")
    references: set[str] = set()
    for correlation in correlations:
        reference = correlation.get("correlation_reference")
        if not isinstance(reference, str) or not CORRELATION_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("a correlation reference is invalid")
        if reference in references:
            raise InputError("correlation references are not unique")
        references.add(reference)
        if correlation.get("association_status") not in ASSOCIATION_STATUSES:
            raise InputError("a correlation association status is invalid")
        if correlation.get("correlation_strength") not in CORRELATION_STRENGTHS:
            raise InputError("a correlation strength is invalid")
        if correlation.get("correlation_type") not in CORRELATION_TYPES:
            raise InputError("a correlation type is invalid")
        if correlation.get("evidence_class") != "DERIVED":
            raise InputError("a correlation evidence class is invalid")
        if not correlation.get("sdp_media_sections"):
            raise InputError("a correlation has no SDP media section")
        status = correlation["association_status"]
        if status in {"MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED"}:
            if correlation.get("correlation_strength") != "STRONG":
                raise InputError("an established correlation is not STRONG")
            if not correlation.get("rtp_udp_stream_references"):
                raise InputError("an established correlation has no RTP stream")
            if not correlation.get("endpoint_references"):
                raise InputError("an established correlation has no endpoint")
            if status == "BUNDLE_TRANSPORT_MATCHED" and not correlation.get(
                "bundle_references"
            ):
                raise InputError("a BUNDLE correlation has no bundle reference")
        if status == "AMBIGUOUS" and correlation.get("correlation_strength") == "STRONG":
            raise InputError("an ambiguous correlation cannot be STRONG")
        for value in correlation.get("endpoint_references") or []:
            if not is_endpoint_reference(value):
                raise InputError("a correlation endpoint reference is malformed")
        for value in correlation.get("rtp_udp_stream_references") or []:
            if not isinstance(value, str) or not STREAM_REFERENCE_PATTERN.fullmatch(value):
                raise InputError("a correlation RTP stream reference is invalid")
        if status in {"MATCHED_ENDPOINT", "BUNDLE_TRANSPORT_MATCHED"}:
            if not correlation.get("match_directions"):
                raise InputError("an established correlation has no match direction")
        for direction in correlation.get("match_directions") or []:
            if direction not in MATCH_DIRECTIONS:
                raise InputError("a correlation match direction is invalid")
    completeness = document.get("completeness") or {}
    status_counts = (
        completeness.get("matched_correlation_count", 0)
        + completeness.get("bundle_matched_correlation_count", 0)
        + completeness.get("ambiguous_correlation_count", 0)
        + completeness.get("insufficient_correlation_count", 0)
        + completeness.get("unmatched_correlation_count", 0)
        + completeness.get("out_of_scope_correlation_count", 0)
    )
    if status_counts != completeness.get("correlation_count", 0):
        raise InputError("correlation status counts do not sum to published correlations")
    if completeness.get("sdp_media_with_endpoint_count", 0) + completeness.get(
        "sdp_media_without_endpoint_count", 0
    ) != completeness.get("sdp_media_section_count", 0):
        raise InputError("SDP media endpoint counts do not conserve media sections")
    if completeness.get("rtp_stream_with_endpoint_count", 0) + completeness.get(
        "rtp_stream_without_endpoint_count", 0
    ) != completeness.get("rtp_stream_count", 0):
        raise InputError("RTP stream endpoint counts do not conserve streams")
    if completeness.get("rtp_packet_count", 0) != (
        completeness.get("correlatable_rtp_packet_count", 0)
        + completeness.get("non_observed_rtp_packet_count", 0)
    ):
        raise InputError("RTP packet count conservation failed")
    if document.get("unmatched_stream_count") != len(
        document.get("unmatched_streams") or []
    ):
        raise InputError("unmatched_stream_count does not match the array")
    for forbidden in (
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "sdp_body",
        "rtp_payload",
        "call_id",
        "sip_uri",
        "hmac_key",
        "endpoint_key",
    ):
        if forbidden in document:
            raise InputError(f"forbidden raw field published: {forbidden}")