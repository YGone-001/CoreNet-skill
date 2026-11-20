#!/usr/bin/env python3
"""Bounded RTP source-stream and sequence-integrity reconstruction.

This Protocol-layer model consumes an already-accepted RTP/RTCP Analysis
artifact produced by the ``sdp-rtp`` Protocol Skill (analysis ``rtp-rtcp``
version ``0.4.0``, event schema ``1.2.0``). It never decodes an RTP packet,
reads a capture, executes TShark, parses SDP, associates an RTCP component
with an RTP stream, or produces a media, QoS, packet-loss or call verdict.

It reconstructs capture-scoped RTP source streams from the accepted packet
observations and applies the bounded RFC 3550 Appendix A.1 sequence-number
validation algorithm with the documented constants ``RTP_SEQ_MOD = 65536``,
``MIN_SEQUENTIAL = 2``, ``MAX_DROPOUT = 3000`` and ``MAX_MISORDER = 100``.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent

ANALYSIS_NAME = "rtp-stream"
ANALYSIS_VERSION = "0.1.0"
EVENT_SCHEMA_VERSION = "1.0.0"
CAPABILITY = "bounded RTP source-stream, sequence-integrity and capture-boundary evidence"

SOURCE_ANALYSIS_NAME = "rtp-rtcp"
SOURCE_ANALYSIS_VERSION = "0.4.0"
SOURCE_EVENT_SCHEMA_VERSION = "1.2.0"
SOURCE_PARSER_VERSION = "0.4.0"

RTCP_OBSERVATION_STATUS = "NOT_INTERPRETED_FOR_RTP_STREAM_ASSOCIATION"

RTP_SEQ_MOD = 65536
MIN_SEQUENTIAL = 2
MAX_DROPOUT = 3000
MAX_MISORDER = 100

MAX_INPUT_EVENTS = 65536
MAX_SOURCE_STREAMS = 512
MAX_UNASSIGNED_PACKETS = 1024
MAX_STREAM_EVENT_REFERENCES = 256
MAX_EPOCHS_PER_STREAM = 32
MAX_GAPS_PER_STREAM = 256
MAX_GAP_SLOTS = 256
MAX_RESTART_PATTERNS = 32
MAX_LIST_ITEMS = 64

SEQUENCE_STATUSES = (
    "PROBATION",
    "VALIDATED",
    "INSUFFICIENT_EVIDENCE",
    "AMBIGUOUS",
)
SOURCE_ENDPOINT_IDENTITY_STATUSES = ("ESTABLISHED", "AMBIGUOUS", "UNAVAILABLE")
ENDPOINT_EVIDENCE_STATUSES = (
    "ESTABLISHED",
    "INCOMPLETE",
    "AMBIGUOUS",
    "UNAVAILABLE",
)
EVENT_EVIDENCE_STATUSES = ("OBSERVED", "INCOMPLETE", "AMBIGUOUS", "UNSUPPORTED", "INVALID")
EXCLUDING_EVIDENCE_STATUSES = ("AMBIGUOUS", "UNSUPPORTED", "INVALID")

CAPTURE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ +-]{0,127}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
EVENT_REFERENCE_PATTERN = re.compile(r"^[a-z][a-z0-9-]*:.+:[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
SSRC_REFERENCE_PATTERN = re.compile(r"^rtp-ssrc:([^:]+):([0-9a-f]{8})$")
STREAM_REFERENCE_PATTERN = re.compile(
    r"^rtp-source-stream:[^:]+:[0-9]+:[0-9a-f]{8}$"
)
GAP_REFERENCE_PATTERN = re.compile(
    r"^rtp-sequence-gap:[^:]+:[0-9]+:[0-9a-f]{8}:[0-9]+$"
)
RESTART_REFERENCE_PATTERN = re.compile(
    r"^rtp-sequence-restart:[^:]+:[0-9]+:[0-9a-f]{8}:[0-9]+$"
)

FORBIDDEN_RAW_KEYS = frozenset(
    {
        "ssrc",
        "source_address",
        "destination_address",
        "source_port",
        "destination_port",
        "source_transport_endpoint",
        "destination_transport_endpoint",
        "rtp_payload",
        "payload",
        "payload_hex",
        "srtp_key",
        "srtp_auth_tag",
        "hmac_key",
        "endpoint_key",
        "call_id",
        "sip_uri",
        "imsi",
        "msisdn",
        "supi",
        "gpsi",
        "source_ip",
        "destination_ip",
    }
)


class InputError(ValueError):
    """Raised when an accepted input artifact is malformed or contradictory."""


_UPSTREAM_MODULE: Any = None
_UPSTREAM_SKILL: Path | None = None


def _candidate_sdp_rtp_dirs() -> list[Path]:
    candidates: list[Path] = [HERE.parent.parent / "sdp-rtp"]
    environment = os.environ.get("CORENET_SKILLS_ROOT")
    if environment:
        root = Path(environment)
        candidates.append(root / "protocol" / "sdp-rtp")
        candidates.append(root / "skills" / "protocol" / "sdp-rtp")
    for parent in HERE.parents:
        candidates.append(parent / "skills" / "protocol" / "sdp-rtp")
    result: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        result.append(resolved)
    return result


def _locate_upstream_skill() -> Path:
    global _UPSTREAM_SKILL
    if _UPSTREAM_SKILL is not None:
        return _UPSTREAM_SKILL
    for candidate in _candidate_sdp_rtp_dirs():
        if (candidate / "scripts" / "rtp_rtcp_model.py").is_file():
            _UPSTREAM_SKILL = candidate
            return candidate
    raise InputError(
        "the sdp-rtp Protocol Skill is required but was not found; "
        "rtp-stream consumes its accepted rtp-rtcp Analysis artifact"
    )


def _upstream_model() -> Any:
    global _UPSTREAM_MODULE
    if _UPSTREAM_MODULE is not None:
        return _UPSTREAM_MODULE
    skill = _locate_upstream_skill()
    scripts = str(skill / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import rtp_rtcp_model as module  # noqa: PLC0415

    _UPSTREAM_MODULE = module
    return module


def _upstream_schema_path() -> Path:
    return _locate_upstream_skill() / "schemas" / "rtp-rtcp-events.schema.json"


def _endpoint_helpers() -> Any:
    _upstream_model()
    import endpoint_reference as helpers  # noqa: PLC0415

    return helpers


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def _strict_int(value: Any, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < minimum or value > maximum:
        return None
    return value


def _safe_capture_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not CAPTURE_NAME_PATTERN.fullmatch(value):
        raise InputError(f"{label} must be a privacy-safe capture basename")
    if value in (".", "..") or "/" in value or "\\" in value or ":" in value:
        raise InputError(f"{label} must be a privacy-safe capture basename")
    return value


def _safe_source_name(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise InputError("input artifact name must be a non-empty basename")
    if "/" in value or "\\" in value or ":" in value or "\x00" in value:
        raise InputError("input artifact name must be a privacy-safe basename")
    if len(value) > 512:
        raise InputError("input artifact name is unreasonably long")
    return value


def _load_json_bytes(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{label} could not be read: {exc}") from None
    try:
        document = json.loads(payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InputError(f"{label} is not UTF-8 JSON: {exc}") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from None
    if not isinstance(document, dict):
        raise InputError(f"{label} must be a JSON object")
    return document, _sha256_bytes(payload)


def _validate_against_accepted_schema(document: dict[str, Any]) -> str:
    """Validate against the authoritative sdp-rtp schema; fail closed."""
    schema_path = _upstream_schema_path()
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"the accepted RTP/RTCP event schema is unusable: {exc}") from None
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        return "STRUCTURAL_FALLBACK"
    try:
        jsonschema.validate(document, schema)
    except jsonschema.ValidationError as exc:
        raise InputError(
            "RTP/RTCP analysis does not conform to the accepted event schema: "
            f"{exc.message}"
        ) from None
    return "JSON_SCHEMA"


def _event_reference_parts(reference: str) -> list[str]:
    return reference.split(":", 2)


def _check_event_identity(event: dict[str, Any], capture: str, capture_sha: str) -> None:
    reference = event.get("event_reference")
    if not isinstance(reference, str) or not EVENT_REFERENCE_PATTERN.fullmatch(reference):
        raise InputError("an RTP/RTCP event reference is invalid")
    if event.get("capture_file") != capture:
        raise InputError("an RTP/RTCP event disagrees with the capture provenance")
    if event.get("capture_sha256") != capture_sha:
        raise InputError("an RTP/RTCP event disagrees with the capture SHA-256")
    if event.get("protocol") == "RTP":
        if event.get("parser_version") != SOURCE_PARSER_VERSION:
            raise InputError("an RTP event parser_version is not accepted")
    elif event.get("parser_version") not in (None, SOURCE_PARSER_VERSION):
        raise InputError("an RTCP event parser_version is not accepted")
    if event.get("evidence_status") not in EVENT_EVIDENCE_STATUSES:
        raise InputError("an RTP/RTCP event evidence_status is invalid")
    frame = event.get("frame_number")
    occurrence = event.get("message_occurrence")
    if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
        raise InputError("an RTP/RTCP event frame_number is invalid")
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 1:
        raise InputError("an RTP/RTCP event message_occurrence is invalid")
    if not isinstance(event.get("frame_timestamp"), str) or not event.get("frame_timestamp"):
        raise InputError("an RTP/RTCP event frame_timestamp is missing")
    if event.get("frame_reference") != f"frame:{frame}":
        raise InputError(
            "an RTP/RTCP event frame_reference is inconsistent with its frame_number"
        )
    parts = _event_reference_parts(reference)
    if len(parts) != 3 or parts[1] != capture:
        raise InputError("an RTP/RTCP event reference disagrees with the capture")
    numeric = parts[2].split(".")
    if len(numeric) < 2:
        raise InputError("an RTP/RTCP event reference lacks a frame identity")
    try:
        reference_frame = int(numeric[0])
        reference_occurrence = int(numeric[1])
    except ValueError:
        raise InputError("an RTP/RTCP event reference has an invalid frame identity") from None
    if reference_frame != frame or reference_occurrence != occurrence:
        raise InputError(
            "an RTP/RTCP event reference disagrees with its frame identity"
        )


def load_source_provenance(
    document: dict[str, Any],
    *,
    source_name: str,
    source_sha256: str,
    schema_validation: str,
) -> dict[str, Any]:
    """Validate accepted RTP/RTCP provenance and return rtp-stream provenance."""
    if document.get("analysis_name") != SOURCE_ANALYSIS_NAME:
        raise InputError("RTP/RTCP analysis_name is not accepted")
    if document.get("analysis_version") != SOURCE_ANALYSIS_VERSION:
        raise InputError("RTP/RTCP analysis_version is not accepted")
    if document.get("event_schema_version") != SOURCE_EVENT_SCHEMA_VERSION:
        raise InputError("RTP/RTCP event_schema_version is not accepted")
    events = document.get("events")
    if not isinstance(events, list):
        raise InputError("RTP/RTCP events must be an array")
    if not all(isinstance(event, dict) for event in events):
        raise InputError("every RTP/RTCP event must be an object")
    if document.get("event_count") != len(events):
        raise InputError("RTP/RTCP event_count does not match the event array")
    provenance = document.get("input_provenance")
    if not isinstance(provenance, dict):
        raise InputError("RTP/RTCP input_provenance is missing")
    if provenance.get("parser_version") != SOURCE_PARSER_VERSION:
        raise InputError("RTP/RTCP parser_version is not accepted")
    if provenance.get("mode") not in {"STRUCTURED_JSONL", "PCAP"}:
        raise InputError("RTP/RTCP provenance mode is not accepted")
    captures = provenance.get("capture_files")
    if not isinstance(captures, list) or len(captures) != 1:
        raise InputError("RTP/RTCP provenance must publish exactly one capture")
    capture = _safe_capture_name(captures[0], "RTP/RTCP capture_files entry")
    capture_sha = provenance.get("capture_sha256")
    if not isinstance(capture_sha, str) or not SHA256_PATTERN.fullmatch(capture_sha):
        raise InputError("RTP/RTCP capture_sha256 is malformed")
    input_name = _safe_source_name(provenance.get("input_name"))
    message_count = provenance.get("input_message_count")
    if (
        isinstance(message_count, bool)
        or not isinstance(message_count, int)
        or message_count < 1
        or message_count > document.get("event_count")
    ):
        raise InputError("RTP/RTCP input_message_count is inconsistent with its events")

    references: set[str] = set()
    for event in events:
        reference = event.get("event_reference")
        if not isinstance(reference, str) or reference in references:
            raise InputError("RTP/RTCP event references are not unique")
        references.add(reference)
        _check_event_identity(event, capture, capture_sha)

    completeness = document.get("completeness")
    if not isinstance(completeness, dict):
        raise InputError("RTP/RTCP completeness block is missing")
    rtp_events = [event for event in events if event.get("protocol") == "RTP"]
    rtcp_events = [event for event in events if event.get("protocol") == "RTCP"]
    if completeness.get("rtp_packet_count") != len(rtp_events):
        raise InputError("RTP/RTCP completeness rtp_packet_count disagrees with events")
    if completeness.get("rtcp_component_count") != len(rtcp_events):
        raise InputError("RTP/RTCP completeness rtcp_component_count disagrees with events")
    for key, expected in (
        ("sr_component_count", sum(1 for event in rtcp_events if event.get("packet_type") == 200)),
        ("rr_component_count", sum(1 for event in rtcp_events if event.get("packet_type") == 201)),
        ("sdes_component_count", sum(1 for event in rtcp_events if event.get("packet_type") == 202)),
        ("bye_component_count", sum(1 for event in rtcp_events if event.get("packet_type") == 203)),
    ):
        if completeness.get(key) != expected:
            raise InputError(f"RTP/RTCP completeness {key} disagrees with events")
    for status in EVENT_EVIDENCE_STATUSES:
        key = f"{status.lower()}_event_count"
        expected = sum(1 for event in events if event.get("evidence_status") == status)
        if completeness.get(key) != expected:
            raise InputError(f"RTP/RTCP completeness {key} disagrees with events")

    document_context = document.get("endpoint_context_reference")
    provenance_context = provenance.get("endpoint_context_reference")
    if document_context is not None and provenance_context is not None:
        if document_context != provenance_context:
            raise InputError("RTP/RTCP endpoint context references disagree")
    if document_context is not None or provenance_context is not None:
        context_reference = document_context or provenance_context
        if not _endpoint_helpers().is_context_reference(context_reference):
            raise InputError("RTP/RTCP endpoint context reference is malformed")

    upstream = _upstream_model()
    try:
        upstream.validate_analysis(document)
    except upstream.InputError as exc:
        raise InputError(f"RTP/RTCP analysis is not accepted: {exc}") from None

    return {
        "source_analysis_name": SOURCE_ANALYSIS_NAME,
        "source_analysis_version": SOURCE_ANALYSIS_VERSION,
        "source_event_schema_version": SOURCE_EVENT_SCHEMA_VERSION,
        "source_parser_version": SOURCE_PARSER_VERSION,
        "source_analysis_source_name": source_name,
        "source_analysis_sha256": source_sha256,
        "source_analysis_schema_validation": schema_validation,
        "capture_files": [capture],
        "capture_sha256": capture_sha,
        "source_input_name": input_name,
        "source_provenance_mode": provenance.get("mode"),
        "input_event_count": len(events),
        "input_rtp_event_count": len(rtp_events),
        "input_rtcp_event_count": len(rtcp_events),
        "endpoint_context_reference": document_context or provenance_context,
        "input_status": "VERIFIED",
    }


def load_rtp_rtcp_analysis(
    path: Path, *, expected_source_sha256: str | None = None
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Load and strictly verify an accepted RTP/RTCP Analysis artifact."""
    document, actual_sha = _load_json_bytes(path, "RTP/RTCP analysis")
    if expected_source_sha256 is not None:
        if (
            not isinstance(expected_source_sha256, str)
            or not SHA256_PATTERN.fullmatch(expected_source_sha256)
            or expected_source_sha256 != actual_sha
        ):
            raise InputError(
                "the supplied RTP/RTCP analysis SHA-256 does not match the expectation"
            )
    schema_validation = _validate_against_accepted_schema(document)
    provenance = load_source_provenance(
        document,
        source_name=path.name,
        source_sha256=actual_sha,
        schema_validation=schema_validation,
    )
    return document, provenance, actual_sha


def _ssrc_identity(event: dict[str, Any], capture: str) -> tuple[str | None, str | None]:
    """Return (ssrc_reference, reason) for the capture-scoped SSRC identity."""
    reference = event.get("ssrc_reference")
    if reference is None:
        return None, "SSRC_REFERENCE_UNAVAILABLE"
    if not isinstance(reference, str):
        return None, "SSRC_REFERENCE_INVALID"
    match = SSRC_REFERENCE_PATTERN.fullmatch(reference)
    if match is None or match.group(1) != capture:
        return None, "SSRC_REFERENCE_INVALID"
    raw_ssrc = event.get("ssrc")
    if raw_ssrc is not None:
        parsed = _strict_int(raw_ssrc, 0, 0xFFFFFFFF)
        if parsed is None or f"{parsed:08x}" != match.group(2):
            return None, "SSRC_REFERENCE_CONFLICT"
    return reference, None


def _stream_key(event: dict[str, Any], capture: str, capture_sha: str) -> tuple[str, Any]:
    """Classify one RTP event as assigned or unassigned.

    Returns either ("ASSIGNED", (udp_stream, ssrc_reference, reason_codes,
    missing_evidence)) or ("UNASSIGNED", (reason_codes, missing_evidence)).
    """
    reference = event.get("event_reference")
    if not isinstance(reference, str) or not reference:
        return "UNASSIGNED", (["EVENT_REFERENCE_INVALID"], ["EVENT_REFERENCE_UNAVAILABLE"])
    if (
        event.get("capture_file") != capture
        or event.get("capture_sha256") != capture_sha
    ):
        return "UNASSIGNED", (
            ["CAPTURE_IDENTITY_INVALID"],
            ["CAPTURE_IDENTITY_UNAVAILABLE"],
        )
    frame = event.get("frame_number")
    occurrence = event.get("message_occurrence")
    if (
        isinstance(frame, bool)
        or not isinstance(frame, int)
        or frame < 1
        or isinstance(occurrence, bool)
        or not isinstance(occurrence, int)
        or occurrence < 1
    ):
        return "UNASSIGNED", (
            ["FRAME_IDENTITY_INVALID"],
            ["FRAME_IDENTITY_UNAVAILABLE"],
        )
    udp_stream = _strict_int(event.get("udp_stream"), 0, 0xFFFFFFFF)
    ssrc_reference, ssrc_reason = _ssrc_identity(event, capture)
    reasons: list[str] = []
    missing: list[str] = []
    if udp_stream is None:
        reasons.append("UDP_STREAM_UNAVAILABLE")
        missing.append("UDP_STREAM_ID_UNAVAILABLE")
    if ssrc_reference is None:
        reasons.append(ssrc_reason or "SSRC_REFERENCE_UNAVAILABLE")
        missing.append("SSRC_REFERENCE_UNAVAILABLE")
    if reasons:
        return "UNASSIGNED", (sorted(set(reasons)), sorted(set(missing)))
    return "ASSIGNED", (udp_stream, ssrc_reference, [], [])


def _payload_type_inventory(events: list[dict[str, Any]]) -> list[int]:
    values: list[int] = []
    for event in events:
        payload_type = _strict_int(event.get("payload_type"), 0, 127)
        if payload_type is not None:
            values.append(payload_type)
    return sorted(set(values))


def _endpoint_scope(event: dict[str, Any]) -> tuple[str | None, str | None, str]:
    """Return (source reference, destination reference, endpoint status)."""
    helper = _endpoint_helpers()
    source = event.get("source_transport_endpoint_reference")
    destination = event.get("destination_transport_endpoint_reference")
    source_value = source if helper.is_endpoint_reference(source) else None
    destination_value = destination if helper.is_endpoint_reference(destination) else None
    status = event.get("transport_endpoint_status")
    if status not in ENDPOINT_EVIDENCE_STATUSES:
        status = "UNAVAILABLE"
    return source_value, destination_value, status


def _endpoint_summary(events: list[dict[str, Any]], context: str | None) -> dict[str, Any]:
    sources: list[str] = []
    destinations: list[str] = []
    statuses: list[str] = []
    malformed = False
    for event in events:
        source, destination, status = _endpoint_scope(event)
        raw_source = event.get("source_transport_endpoint_reference")
        raw_destination = event.get("destination_transport_endpoint_reference")
        if raw_source is not None and source is None:
            malformed = True
        if raw_destination is not None and destination is None:
            malformed = True
        if source is not None:
            sources.append(source)
        if destination is not None:
            destinations.append(destination)
        statuses.append(status)
    sources = _unique(sources)
    destinations = _unique(destinations)
    missing: list[str] = []
    conflicts: list[str] = []
    if not sources:
        identity = "UNAVAILABLE"
        missing.append("SOURCE_ENDPOINT_REFERENCE_UNAVAILABLE")
    elif len(sources) > 1:
        identity = "AMBIGUOUS"
        conflicts.append("MULTIPLE_SOURCE_ENDPOINT_REFERENCES")
    else:
        identity = "ESTABLISHED"
    if not destinations:
        missing.append("DESTINATION_ENDPOINT_REFERENCE_UNAVAILABLE")
    if len(destinations) > 1:
        conflicts.append("MULTIPLE_DESTINATION_ENDPOINT_REFERENCES")
    if malformed:
        conflicts.append("ENDPOINT_REFERENCE_MALFORMED")
    if "AMBIGUOUS" in statuses or len(sources) > 1 or len(destinations) > 1:
        evidence_status = "AMBIGUOUS"
        conflicts.append("ENDPOINT_EVIDENCE_AMBIGUOUS")
    elif context is None or not sources or not destinations:
        evidence_status = "UNAVAILABLE"
    elif any(status != "ESTABLISHED" for status in statuses):
        evidence_status = "INCOMPLETE"
        missing.append("ENDPOINT_EVIDENCE_INCOMPLETE")
    else:
        evidence_status = "ESTABLISHED"
    return {
        "source_endpoint_references": sources[:MAX_LIST_ITEMS],
        "destination_endpoint_references": destinations[:MAX_LIST_ITEMS],
        "source_endpoint_identity_status": identity,
        "destination_endpoint_identity_status": (
            "UNAVAILABLE"
            if not destinations
            else "AMBIGUOUS"
            if len(destinations) > 1
            else "ESTABLISHED"
        ),
        "endpoint_evidence_status": evidence_status,
        "endpoint_context_reference": context,
        "missing_evidence": sorted(set(missing)),
        "conflict_findings": sorted(set(conflicts)),
    }


def _init_seq(state: dict[str, Any], sequence_number: int) -> None:
    state["base_seq"] = sequence_number
    state["max_seq"] = sequence_number
    state["bad_seq"] = RTP_SEQ_MOD + 1
    state["cycles"] = 0
    state["received"] = 0


class _Epoch:
    """One sequence-state epoch, starting at the first observation or a resync."""

    def __init__(self, index: int) -> None:
        self.index = index
        self.validated = False
        self.probation_count = 0
        self.accepted_count = 0
        self.duplicate_count = 0
        self.out_of_order_count = 0
        self.wrap_count = 0
        self.observed_ext: set[int] = set()
        self.probation_ext: set[int] = set()
        self.observed_reference_by_ext: dict[int, str] = {}
        self.first_sequence: int | None = None
        self.last_sequence: int | None = None
        self.highest_ext: int | None = None
        self.highest_reference: str | None = None
        self.gaps: list[dict[str, Any]] = []
        self.restart_references: list[str] = []
        self.missing_evidence: list[str] = []
        self.conflict_findings: list[str] = []

    def note_sequence(self, sequence_number: int) -> None:
        if self.first_sequence is None:
            self.first_sequence = sequence_number
        self.last_sequence = sequence_number

    def range_values(self) -> tuple[int | None, int | None, int]:
        if self.observed_ext:
            return (min(self.observed_ext), max(self.observed_ext), len(self.observed_ext))
        if self.probation_ext:
            return (
                min(self.probation_ext),
                max(self.probation_ext),
                len(self.probation_ext),
            )
        return (None, None, 0)

    def accept(self, extended: int, reference: str, *, duplicate: bool, reorder: bool) -> None:
        self.observed_ext.add(extended)
        self.observed_reference_by_ext.setdefault(extended, reference)
        self.accepted_count += 1
        if duplicate:
            self.duplicate_count += 1
        if reorder:
            self.out_of_order_count += 1
        if self.highest_ext is None or extended > self.highest_ext:
            self.highest_ext = extended
            self.highest_reference = reference


def _new_gap(
    epoch: _Epoch,
    *,
    capture: str,
    udp_stream: int,
    ssrc_hex: str,
    gap_index: int,
    end_extended: int,
    end_reference: str,
) -> dict[str, Any]:
    start = epoch.highest_ext
    missing = set(range(start + 1, end_extended)) if start is not None else set()
    return {
        "gap_reference": (
            f"rtp-sequence-gap:{capture}:{udp_stream}:{ssrc_hex}:{gap_index}"
        ),
        "epoch_index": epoch.index,
        "start_event_reference": epoch.highest_reference,
        "start_extended_sequence_position": start,
        "end_event_reference": end_reference,
        "end_extended_sequence_position": end_extended,
        "missing_extended_positions": missing,
        "filled_extended_positions": set(),
        "missing_evidence": [],
        "conflict_findings": [],
    }


def _fill_gaps(epoch: _Epoch, extended: int, reference: str) -> None:
    for gap in epoch.gaps:
        if extended in gap["missing_extended_positions"]:
            gap["missing_extended_positions"].discard(extended)
            gap["filled_extended_positions"].add(extended)
            gap.setdefault("filled_event_references", []).append(reference)


def _bounded_sequence_numbers(extended_positions: set[int]) -> tuple[list[int], int]:
    values = sorted(extended_positions)
    sequence_numbers = _unique([position % RTP_SEQ_MOD for position in values])
    return sequence_numbers[:MAX_GAP_SLOTS], max(0, len(sequence_numbers) - MAX_GAP_SLOTS)


def _publish_gap(gap: dict[str, Any]) -> dict[str, Any]:
    remaining = set(gap["missing_extended_positions"])
    filled = set(gap["filled_extended_positions"])
    remaining_numbers, remaining_omitted = _bounded_sequence_numbers(remaining)
    filled_numbers, filled_omitted = _bounded_sequence_numbers(filled)
    conflicts = sorted(set(gap["conflict_findings"]))
    if filled and remaining:
        conflicts.append("SEQUENCE_GAP_PARTIALLY_FILLED_BY_REORDERED_PACKET")
    elif filled:
        conflicts.append("SEQUENCE_GAP_FILLED_BY_REORDERED_PACKET")
    missing: list[str] = []
    if remaining:
        missing.append("UNOBSERVED_SEQUENCE_NUMBERS")
    return {
        "gap_reference": gap["gap_reference"],
        "epoch_index": gap["epoch_index"],
        "start_event_reference": gap["start_event_reference"],
        "start_extended_sequence_position": gap["start_extended_sequence_position"],
        "end_event_reference": gap["end_event_reference"],
        "end_extended_sequence_position": gap["end_extended_sequence_position"],
        "unobserved_sequence_number_count": len(remaining_numbers) + remaining_omitted,
        "unobserved_sequence_numbers": remaining_numbers,
        "unobserved_sequence_numbers_omitted": remaining_omitted,
        "filled_by_later_observation": bool(filled),
        "filled_sequence_number_count": len(filled_numbers) + filled_omitted,
        "filled_sequence_numbers": filled_numbers,
        "filled_sequence_numbers_omitted": filled_omitted,
        "missing_evidence": sorted(set(missing)),
        "conflict_findings": sorted(set(conflicts)),
        "evidence_class": "DERIVED",
    }


def _publish_restart(pattern: dict[str, Any]) -> dict[str, Any]:
    return {
        "restart_reference": pattern["restart_reference"],
        "restart_confirmation": pattern["restart_confirmation"],
        "candidate_event_reference": pattern["candidate_event_reference"],
        "candidate_frame_number": pattern["candidate_frame_number"],
        "candidate_sequence_number": pattern["candidate_sequence_number"],
        "confirmation_event_reference": pattern.get("confirmation_event_reference"),
        "confirmation_frame_number": pattern.get("confirmation_frame_number"),
        "confirmation_sequence_number": pattern.get("confirmation_sequence_number"),
        "previous_epoch_index": pattern["previous_epoch_index"],
        "new_epoch_index": pattern.get("new_epoch_index"),
        "supporting_event_references": _unique(
            pattern.get("supporting_event_references", [])
        )[:MAX_LIST_ITEMS],
        "missing_evidence": sorted(set(pattern.get("missing_evidence", []))),
        "conflict_findings": sorted(set(pattern.get("conflict_findings", []))),
        "evidence_class": "DERIVED",
    }


def _reconstruct_sequence(
    events: list[dict[str, Any]],
    *,
    capture: str,
    udp_stream: int,
    ssrc_hex: str,
) -> dict[str, Any]:
    """Run the bounded RFC 3550 Appendix A.1 sequence algorithm."""
    epochs: list[_Epoch] = []
    restarts: list[dict[str, Any]] = []
    state: dict[str, Any] = {
        "max_seq": None,
        "cycles": 0,
        "base_seq": None,
        "bad_seq": RTP_SEQ_MOD + 1,
        "probation": 0,
        "received": 0,
    }
    epoch: _Epoch | None = None
    pending: dict[str, Any] | None = None
    open_candidate_at_end = False

    for event in events:
        sequence = event["sequence_number"]
        reference = event["event_reference"]
        if state["max_seq"] is None:
            epoch = _Epoch(0)
            epochs.append(epoch)
            _init_seq(state, sequence)
            state["max_seq"] = (sequence - 1) % RTP_SEQ_MOD
            state["probation"] = MIN_SEQUENTIAL

        assert epoch is not None
        max_seq = state["max_seq"]
        delta = (sequence - max_seq) % RTP_SEQ_MOD

        if state["probation"]:
            if sequence == (max_seq + 1) % RTP_SEQ_MOD:
                state["probation"] -= 1
                state["max_seq"] = sequence
                epoch.note_sequence(sequence)
                if state["probation"] == 0:
                    if sequence < max_seq:
                        epoch.wrap_count += 1
                    _init_seq(state, sequence)
                    state["received"] += 1
                    epoch.validated = True
                    epoch.accept(sequence, reference, duplicate=False, reorder=False)
                else:
                    epoch.probation_count += 1
                    epoch.probation_ext.add(sequence)
            else:
                state["probation"] = MIN_SEQUENTIAL - 1
                state["max_seq"] = sequence
                epoch.note_sequence(sequence)
                epoch.probation_count += 1
                epoch.probation_ext.add(sequence)
            continue

        if delta < MAX_DROPOUT:
            if pending is not None:
                pending["restart_confirmation"] = "UNCONFIRMED"
                pending["conflict_findings"] = ["RESTART_CANDIDATE_NOT_CONFIRMED"]
                restarts.append(pending)
                pending = None
            if sequence < max_seq:
                state["cycles"] += RTP_SEQ_MOD
                epoch.wrap_count += 1
            extended = state["cycles"] + sequence
            duplicate = extended in epoch.observed_ext
            state["max_seq"] = sequence
            state["received"] += 1
            epoch.note_sequence(sequence)
            if (
                not duplicate
                and epoch.highest_ext is not None
                and extended > epoch.highest_ext + 1
            ):
                gap = _new_gap(
                    epoch,
                    capture=capture,
                    udp_stream=udp_stream,
                    ssrc_hex=ssrc_hex,
                    gap_index=len(epoch.gaps),
                    end_extended=extended,
                    end_reference=reference,
                )
                epoch.gaps.append(gap)
            epoch.accept(extended, reference, duplicate=duplicate, reorder=False)
            continue

        if delta <= RTP_SEQ_MOD - MAX_MISORDER:
            if sequence == state["bad_seq"]:
                if pending is not None:
                    pending["restart_confirmation"] = "CONFIRMED"
                    pending["confirmation_event_reference"] = reference
                    pending["confirmation_frame_number"] = event["frame_number"]
                    pending["confirmation_sequence_number"] = sequence
                    pending.setdefault("supporting_event_references", []).append(reference)
                    pending["new_epoch_index"] = len(epochs)
                else:
                    pending = {
                        "restart_reference": (
                            f"rtp-sequence-restart:{capture}:{udp_stream}:"
                            f"{ssrc_hex}:{len(restarts)}"
                        ),
                        "restart_confirmation": "CONFIRMED",
                        "candidate_event_reference": reference,
                        "candidate_frame_number": event["frame_number"],
                        "candidate_sequence_number": sequence,
                        "confirmation_event_reference": reference,
                        "confirmation_frame_number": event["frame_number"],
                        "confirmation_sequence_number": sequence,
                        "previous_epoch_index": epoch.index,
                        "new_epoch_index": len(epochs),
                        "supporting_event_references": [reference],
                        "missing_evidence": [
                            "RESTART_CANDIDATE_PACKET_NOT_SEQUENCE_VALIDATED"
                        ],
                        "conflict_findings": [],
                    }
                restarts.append(pending)
                epoch.restart_references.append(pending["restart_reference"])
                pending = None
                new_epoch = _Epoch(len(epochs))
                epochs.append(new_epoch)
                _init_seq(state, sequence)
                state["received"] += 1
                new_epoch.validated = True
                new_epoch.note_sequence(sequence)
                new_epoch.accept(sequence, reference, duplicate=False, reorder=False)
                new_epoch.restart_references.append(restarts[-1]["restart_reference"])
                epoch = new_epoch
            else:
                if pending is not None:
                    pending["restart_confirmation"] = "UNCONFIRMED"
                    pending["conflict_findings"] = ["RESTART_CANDIDATE_SUPERSEDED"]
                    restarts.append(pending)
                    pending = None
                pending = {
                    "restart_reference": (
                        f"rtp-sequence-restart:{capture}:{udp_stream}:"
                        f"{ssrc_hex}:{len(restarts)}"
                    ),
                    "restart_confirmation": "UNCONFIRMED",
                    "candidate_event_reference": reference,
                    "candidate_frame_number": event["frame_number"],
                    "candidate_sequence_number": sequence,
                    "previous_epoch_index": epoch.index,
                    "supporting_event_references": [reference],
                    "missing_evidence": ["RESTART_CONFIRMATION_NOT_OBSERVED"],
                    "conflict_findings": [],
                }
                state["bad_seq"] = (sequence + 1) % RTP_SEQ_MOD
            continue

        if pending is not None:
            pending["restart_confirmation"] = "UNCONFIRMED"
            pending["conflict_findings"] = ["RESTART_CANDIDATE_NOT_CONFIRMED"]
            restarts.append(pending)
            pending = None
        extended = state["cycles"] + sequence
        if epoch.highest_ext is not None and extended > epoch.highest_ext + RTP_SEQ_MOD // 2:
            extended -= RTP_SEQ_MOD
        epoch.note_sequence(sequence)
        duplicate = extended in epoch.observed_ext
        reorder = (not duplicate) and (
            epoch.highest_ext is not None and extended < epoch.highest_ext
        )
        state["received"] += 1
        if not duplicate and epoch.validated:
            _fill_gaps(epoch, extended, reference)
        epoch.accept(extended, reference, duplicate=duplicate, reorder=reorder)

    open_candidate_at_end = pending is not None
    if pending is not None:
        pending["restart_confirmation"] = "UNCONFIRMED"
        pending["conflict_findings"] = [
            "RESTART_CONFIRMATION_NOT_OBSERVED_AT_CAPTURE_END"
        ]
        restarts.append(pending)

    if epoch is not None and open_candidate_at_end:
        epoch.conflict_findings.append("SEQUENCE_CONTINUITY_AMBIGUOUS_AT_CAPTURE_END")

    published_epochs: list[dict[str, Any]] = []
    total_unobserved = 0
    total_gaps = 0
    total_wraps = 0
    total_duplicates = 0
    total_out_of_order = 0
    gaps_omitted = 0
    for item in epochs:
        start, end, unique = item.range_values()
        published_gaps = item.gaps[:MAX_GAPS_PER_STREAM]
        gaps_omitted += max(0, len(item.gaps) - len(published_gaps))
        gap_unobserved = 0
        for gap in published_gaps:
            gap_unobserved += len(gap["missing_extended_positions"])
        total_unobserved += sum(
            len(gap["missing_extended_positions"]) for gap in item.gaps
        )
        total_gaps += len(item.gaps)
        total_wraps += item.wrap_count
        total_duplicates += item.duplicate_count
        total_out_of_order += item.out_of_order_count
        if not item.validated:
            status = (
                "PROBATION"
                if item.probation_count
                else "INSUFFICIENT_EVIDENCE"
            )
        else:
            status = "VALIDATED"
        if open_candidate_at_end and item is epochs[-1] and item.validated:
            status = "AMBIGUOUS"
        missing: list[str] = []
        conflicts: list[str] = list(item.conflict_findings)
        if status == "PROBATION":
            missing.append("SEQUENTIAL_VALIDATION_INCOMPLETE")
        if status == "INSUFFICIENT_EVIDENCE":
            missing.append("SEQUENCE_EVIDENCE_UNAVAILABLE")
        if gap_unobserved:
            missing.append("UNOBSERVED_SEQUENCE_NUMBERS")
        if item.duplicate_count:
            conflicts.append("DUPLICATE_SEQUENCE_NUMBER_OBSERVED")
        if item.out_of_order_count:
            conflicts.append("OUT_OF_ORDER_SEQUENCE_OBSERVED")
        published_epochs.append(
            {
                "epoch_index": item.index,
                "sequence_validation_status": status,
                "first_observed_sequence_number": item.first_sequence,
                "last_observed_sequence_number": item.last_sequence,
                "extended_sequence_start": start,
                "extended_sequence_end": end,
                "unique_sequence_count": unique,
                "accepted_observation_count": item.accepted_count,
                "probation_observation_count": item.probation_count,
                "duplicate_observation_count": item.duplicate_count,
                "out_of_order_observation_count": item.out_of_order_count,
                "sequence_wrap_count": item.wrap_count,
                "observed_gap_count": len(item.gaps),
                "unobserved_sequence_number_slot_count": sum(
                    len(gap["missing_extended_positions"]) for gap in item.gaps
                ),
                "restart_pattern_evidence_references": _unique(
                    item.restart_references
                )[:MAX_LIST_ITEMS],
                "missing_evidence": sorted(set(missing)),
                "conflict_findings": sorted(set(conflicts)),
                "evidence_class": "DERIVED",
            }
        )

    all_gap_records: list[dict[str, Any]] = []
    for item in epochs:
        all_gap_records.extend(_publish_gap(gap) for gap in item.gaps)
    gaps_omitted = max(0, len(all_gap_records) - MAX_GAPS_PER_STREAM)
    published_gaps_all = all_gap_records[:MAX_GAPS_PER_STREAM]

    published_restarts = [_publish_restart(pattern) for pattern in restarts][
        :MAX_RESTART_PATTERNS
    ]
    restarts_omitted = max(0, len(restarts) - len(published_restarts))
    gaps_omitted = max(0, len(published_gaps_all) - MAX_GAPS_PER_STREAM)

    if epochs:
        last = epochs[-1]
        if open_candidate_at_end and last.validated:
            stream_status = "AMBIGUOUS"
        elif last.validated:
            stream_status = "VALIDATED"
        elif last.probation_count:
            stream_status = "PROBATION"
        else:
            stream_status = "INSUFFICIENT_EVIDENCE"
    else:
        stream_status = "INSUFFICIENT_EVIDENCE"

    published_epochs = published_epochs[:MAX_EPOCHS_PER_STREAM]
    epochs_omitted = max(0, len(epochs) - len(published_epochs))

    return {
        "sequence_validation_status": stream_status,
        "sequence_epoch_count": len(epochs),
        "sequence_epochs": published_epochs,
        "sequence_epochs_omitted": epochs_omitted,
        "sequence_wrap_count": total_wraps,
        "duplicate_sequence_observation_count": total_duplicates,
        "out_of_order_packet_count": total_out_of_order,
        "observed_sequence_gap_count": total_gaps,
        "sequence_gaps": published_gaps_all,
        "sequence_gaps_omitted": gaps_omitted,
        "unobserved_sequence_number_slot_count": total_unobserved,
        "restart_pattern_count": len(restarts),
        "restart_patterns": published_restarts,
        "restart_patterns_omitted": restarts_omitted,
    }


def _categorize_assigned_event(
    event: dict[str, Any], reason_codes: list[str], missing: list[str]
) -> tuple[str, list[str], list[str]]:
    """Return (category, reason_codes, missing_evidence) for an assigned event."""
    status = event.get("evidence_status")
    version = _strict_int(event.get("version"), 0, 3)
    sequence = _strict_int(event.get("sequence_number"), 0, 0xFFFF)
    if status in EXCLUDING_EVIDENCE_STATUSES:
        reason_codes.append(f"UPSTREAM_EVIDENCE_{status}")
    if event.get("version") is None:
        reason_codes.append("RTP_VERSION_MISSING")
        missing.append("RTP_VERSION_UNAVAILABLE")
    elif version is None or version != 2:
        reason_codes.append(
            "RTP_VERSION_INVALID" if version is None else "UNSUPPORTED_RTP_VERSION"
        )
    if event.get("sequence_number") is None:
        reason_codes.append("RTP_SEQUENCE_NUMBER_MISSING")
        missing.append("RTP_SEQUENCE_NUMBER_UNAVAILABLE")
    elif sequence is None:
        reason_codes.append("RTP_SEQUENCE_NUMBER_INVALID")

    invalid = any(
        reason
        in {
            "UPSTREAM_EVIDENCE_AMBIGUOUS",
            "UPSTREAM_EVIDENCE_UNSUPPORTED",
            "UPSTREAM_EVIDENCE_INVALID",
            "RTP_VERSION_INVALID",
            "UNSUPPORTED_RTP_VERSION",
            "RTP_SEQUENCE_NUMBER_INVALID",
        }
        for reason in reason_codes
    )
    incomplete = any(
        reason in {"RTP_VERSION_MISSING", "RTP_SEQUENCE_NUMBER_MISSING"}
        for reason in reason_codes
    )
    if invalid:
        return "EXCLUDED", reason_codes, missing
    if incomplete:
        return "INCOMPLETE", reason_codes, missing
    return "ELIGIBLE", reason_codes, missing


def _reconstruct_stream(
    key: tuple[str, int, str],
    events: list[dict[str, Any]],
    *,
    capture: str,
    context: str | None,
) -> dict[str, Any]:
    capture_sha, udp_stream, ssrc_reference = key
    ssrc_hex = ssrc_reference.rsplit(":", 1)[1]
    ordered = sorted(
        events,
        key=lambda event: (
            event["frame_number"],
            event["message_occurrence"],
            event["event_reference"],
        ),
    )
    endpoint = _endpoint_summary(ordered, context)
    eligible: list[dict[str, Any]] = []
    incomplete_count = 0
    excluded_count = 0
    for event in ordered:
        category, _reasons, _missing = _categorize_assigned_event(
            event, [], []
        )
        if category == "ELIGIBLE":
            eligible.append(event)
        elif category == "INCOMPLETE":
            incomplete_count += 1
        else:
            excluded_count += 1
    sequence = _reconstruct_sequence(
        eligible, capture=capture, udp_stream=udp_stream, ssrc_hex=ssrc_hex
    )
    references = [event["event_reference"] for event in ordered]
    frames = [event["frame_number"] for event in ordered]
    missing = list(endpoint["missing_evidence"]) + [
        "CAPTURE_BOUNDARY_COMPLETENESS_UNKNOWN"
    ]
    conflicts = list(endpoint["conflict_findings"])
    if sequence["sequence_validation_status"] == "PROBATION":
        missing.append("SEQUENTIAL_VALIDATION_INCOMPLETE")
    if sequence["sequence_validation_status"] == "INSUFFICIENT_EVIDENCE":
        missing.append("SEQUENCE_EVIDENCE_UNAVAILABLE")
    if sequence["unobserved_sequence_number_slot_count"]:
        missing.append("UNOBSERVED_SEQUENCE_NUMBERS")
    if sequence["duplicate_sequence_observation_count"]:
        conflicts.append("DUPLICATE_SEQUENCE_NUMBER_OBSERVED")
    if sequence["out_of_order_packet_count"]:
        conflicts.append("OUT_OF_ORDER_SEQUENCE_OBSERVED")
    if sequence["sequence_validation_status"] == "AMBIGUOUS":
        conflicts.append("RESTART_CANDIDATE_UNCONFIRMED")
    published_references = references[:MAX_STREAM_EVENT_REFERENCES]
    return {
        "source_stream_reference": (
            f"rtp-source-stream:{capture}:{udp_stream}:{ssrc_hex}"
        ),
        "capture_file": capture,
        "udp_stream": udp_stream,
        "ssrc_reference": ssrc_reference,
        "source_endpoint_references": endpoint["source_endpoint_references"],
        "destination_endpoint_references": endpoint[
            "destination_endpoint_references"
        ],
        "source_endpoint_identity_status": endpoint[
            "source_endpoint_identity_status"
        ],
        "destination_endpoint_identity_status": endpoint[
            "destination_endpoint_identity_status"
        ],
        "endpoint_evidence_status": endpoint["endpoint_evidence_status"],
        "endpoint_context_reference": context,
        "observed_payload_types": _payload_type_inventory(ordered),
        "first_frame_number": min(frames) if frames else None,
        "last_frame_number": max(frames) if frames else None,
        "rtp_packet_count": len(ordered),
        "sequence_eligible_packet_count": len(eligible),
        "incomplete_packet_count": incomplete_count,
        "invalid_or_excluded_packet_count": excluded_count,
        "event_reference_count": len(references),
        "event_references": published_references,
        "event_references_omitted": max(0, len(references) - len(published_references)),
        "sequence_validation_status": sequence["sequence_validation_status"],
        "sequence_epoch_count": sequence["sequence_epoch_count"],
        "sequence_epochs": sequence["sequence_epochs"],
        "sequence_epochs_omitted": sequence["sequence_epochs_omitted"],
        "sequence_wrap_count": sequence["sequence_wrap_count"],
        "duplicate_sequence_observation_count": sequence[
            "duplicate_sequence_observation_count"
        ],
        "out_of_order_packet_count": sequence["out_of_order_packet_count"],
        "observed_sequence_gap_count": sequence["observed_sequence_gap_count"],
        "sequence_gaps": sequence["sequence_gaps"],
        "sequence_gaps_omitted": sequence["sequence_gaps_omitted"],
        "unobserved_sequence_number_slot_count": sequence[
            "unobserved_sequence_number_slot_count"
        ],
        "restart_pattern_count": sequence["restart_pattern_count"],
        "restart_patterns": sequence["restart_patterns"],
        "restart_patterns_omitted": sequence["restart_patterns_omitted"],
        "missing_evidence": sorted(set(missing)),
        "conflict_findings": sorted(set(conflicts)),
        "evidence_class": "DERIVED",
    }


def _unassigned_record(
    event: dict[str, Any], reason_codes: list[str], missing: list[str]
) -> dict[str, Any]:
    return {
        "event_reference": event.get("event_reference"),
        "frame_number": event.get("frame_number"),
        "message_occurrence": event.get("message_occurrence"),
        "original_evidence_status": event.get("evidence_status"),
        "reason_codes": sorted(set(reason_codes)),
        "missing_evidence": sorted(set(missing)),
    }


def build_analysis(
    document: dict[str, Any], *, provenance: dict[str, Any]
) -> dict[str, Any]:
    capture = provenance["capture_files"][0]
    capture_sha = provenance["capture_sha256"]
    context = provenance.get("endpoint_context_reference")
    events = document["events"]
    rtp_events = [event for event in events if event.get("protocol") == "RTP"]
    rtcp_events = [event for event in events if event.get("protocol") == "RTCP"]

    assigned: dict[tuple[str, int, str], list[dict[str, Any]]] = {}
    unassigned_events: list[tuple[dict[str, Any], list[str], list[str]]] = []
    eligible_count = 0
    for event in rtp_events:
        kind, payload = _stream_key(event, capture, capture_sha)
        if kind == "UNASSIGNED":
            reasons, missing = payload
            unassigned_events.append((event, list(reasons), list(missing)))
            continue
        udp_stream, ssrc_reference, _r, _m = payload
        key = (capture_sha, udp_stream, ssrc_reference)
        assigned.setdefault(key, []).append(event)
        category, _reasons, _missing = _categorize_assigned_event(event, [], [])
        if category == "ELIGIBLE":
            eligible_count += 1

    unassigned_events.sort(
        key=lambda item: (
            item[0].get("frame_number") if isinstance(item[0].get("frame_number"), int) else 0,
            item[0].get("message_occurrence")
            if isinstance(item[0].get("message_occurrence"), int)
            else 0,
            item[0].get("event_reference") or "",
        )
    )

    streams: list[dict[str, Any]] = []
    for key in sorted(assigned, key=lambda item: (item[1], item[2])):
        streams.append(
            _reconstruct_stream(
                key, assigned[key], capture=capture, context=context
            )
        )

    published_streams = streams[:MAX_SOURCE_STREAMS]
    streams_omitted = max(0, len(streams) - len(published_streams))
    published_unassigned = unassigned_events[:MAX_UNASSIGNED_PACKETS]
    unassigned_omitted = max(0, len(unassigned_events) - len(published_unassigned))
    unassigned_records = [
        _unassigned_record(event, reasons, missing)
        for event, reasons, missing in published_unassigned
    ]

    assigned_event_count = sum(stream["rtp_packet_count"] for stream in streams)
    unassigned_event_count = len(unassigned_events)
    total_rtp = len(rtp_events)
    if total_rtp != assigned_event_count + unassigned_event_count:
        raise InputError("RTP event conservation failed during reconstruction")

    stream_status_counts = {status: 0 for status in SEQUENCE_STATUSES}
    for stream in streams:
        stream_status_counts[stream["sequence_validation_status"]] += 1

    published_assigned_references = sum(
        len(stream["event_references"]) for stream in published_streams
    )
    event_references_omitted = assigned_event_count - published_assigned_references
    omitted_record_count = (
        streams_omitted + unassigned_omitted + event_references_omitted
    )

    rtcp_type_counts: dict[str, int] = {}
    for event in rtcp_events:
        name = event.get("packet_type_name")
        if not isinstance(name, str) or not name:
            name = "UNKNOWN"
        rtcp_type_counts[name] = rtcp_type_counts.get(name, 0) + 1

    limitations = [
        "Sequence gaps are unobserved sequence-number slots inside the observed validated range and never prove network packet loss",
        "RTP stream reconstruction is limited to the observed capture interval; leading and trailing missing packets are never inferred",
        "The first and last observed sequence numbers are not stream origin or stream termination evidence",
        "Extended sequence numbers are epoch-local deterministic reconstructions from the 16-bit RTP Sequence Number field",
        "Duplicate and out-of-order observations are reported without any retransmission, loss or attack interpretation",
        "An observed restart pattern is only the RFC 3550 Appendix A.1 bad-sequence resynchronization behaviour and never a physical cause",
        "RTCP events are counted but never associated with an RTP source stream, and a BYE never proves RTP teardown",
        "HMAC endpoint references are optional; a missing endpoint key does not block sequence reconstruction",
        "A unique source endpoint reference is a capture-scoped pseudonym, not a UE, IMS, access-side or caller/recipient identity",
        "No RTP payload, SDP body, codec, jitter, MOS, QoS, ICE, STUN, TURN, NAT, DTLS or SRTP content is interpreted",
        "No timestamp proximity is used to group packets, order sequence state or associate RTCP with RTP",
    ]
    if provenance.get("source_analysis_schema_validation") == "STRUCTURAL_FALLBACK":
        limitations.insert(
            0,
            "The jsonschema dependency was unavailable; input validation used the accepted structural and semantic checks",
        )

    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "capability": CAPABILITY,
        "input_provenance": provenance,
        "sequence_validation_parameters": {
            "algorithm": "RFC 3550 Appendix A.1",
            "RTP_SEQ_MOD": RTP_SEQ_MOD,
            "MIN_SEQUENTIAL": MIN_SEQUENTIAL,
            "MAX_DROPOUT": MAX_DROPOUT,
            "MAX_MISORDER": MAX_MISORDER,
        },
        "source_stream_count": len(streams),
        "source_streams": published_streams,
        "source_streams_omitted": streams_omitted,
        "unassigned_packet_count": len(unassigned_events),
        "unassigned_packets": unassigned_records,
        "unassigned_packets_omitted": unassigned_omitted,
        "rtcp_event_count": len(rtcp_events),
        "rtcp_observation_status": RTCP_OBSERVATION_STATUS,
        "rtcp_component_counts_by_type": rtcp_type_counts,
        "completeness": {
            "total_input_rtp_packet_count": total_rtp,
            "sequence_eligible_rtp_packet_count": eligible_count,
            "excluded_rtp_packet_count": total_rtp - eligible_count,
            "assigned_rtp_packet_count": assigned_event_count,
            "unassigned_rtp_packet_count": unassigned_event_count,
            "source_stream_count": len(streams),
            "sequence_validated_stream_count": stream_status_counts["VALIDATED"],
            "probation_stream_count": stream_status_counts["PROBATION"],
            "ambiguous_stream_count": stream_status_counts["AMBIGUOUS"],
            "incomplete_stream_count": stream_status_counts["INSUFFICIENT_EVIDENCE"],
            "duplicate_observation_count": sum(
                stream["duplicate_sequence_observation_count"] for stream in streams
            ),
            "out_of_order_observation_count": sum(
                stream["out_of_order_packet_count"] for stream in streams
            ),
            "sequence_gap_count": sum(
                stream["observed_sequence_gap_count"] for stream in streams
            ),
            "restart_pattern_count": sum(
                stream["restart_pattern_count"] for stream in streams
            ),
            "rtcp_event_count": len(rtcp_events),
            "omitted_record_count": omitted_record_count,
            "published_source_stream_count": len(published_streams),
            "published_unassigned_packet_count": len(unassigned_records),
            "event_references_omitted": event_references_omitted,
        },
        "limitations": limitations,
        "not_confirmed": [
            "NETWORK_PACKET_LOSS",
            "RTP_RECEIVER_PACKET_LOSS",
            "PACKET_RETRANSMISSION_CAUSE",
            "DUPLICATE_SEQUENCE_CAUSE",
            "SEQUENCE_RESTART_CAUSE",
            "SSRC_COLLISION",
            "RTP_SENDER_REPLACEMENT",
            "RTP_DELIVERY",
            "TWO_WAY_AUDIO",
            "MEDIA_QOS",
            "LOCAL_JITTER",
            "MOS",
            "RTCP_TO_RTP_STREAM_ASSOCIATION",
            "RTP_TEARDOWN_FROM_RTCP_BYE",
            "IMS_MEDIA_SESSION_IDENTITY",
            "SUBSCRIBER_IDENTITY",
            "IMS_IDENTITY",
            "UE_IDENTITY",
            "CALL_SUCCESS",
        ],
    }


def _walk_keys(value: Any) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def validate_analysis(document: dict[str, Any]) -> None:
    """Enforce the rtp-stream semantic output contract."""
    if not isinstance(document, dict):
        raise InputError("rtp-stream analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("rtp-stream analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("rtp-stream analysis_version is not accepted")
    if document.get("event_schema_version") != EVENT_SCHEMA_VERSION:
        raise InputError("rtp-stream event_schema_version is not accepted")
    if document.get("capability") != CAPABILITY:
        raise InputError("rtp-stream capability is not accepted")
    if document.get("rtcp_observation_status") != RTCP_OBSERVATION_STATUS:
        raise InputError("rtp-stream RTCP observation status is not accepted")
    parameters = document.get("sequence_validation_parameters") or {}
    if parameters != {
        "algorithm": "RFC 3550 Appendix A.1",
        "RTP_SEQ_MOD": RTP_SEQ_MOD,
        "MIN_SEQUENTIAL": MIN_SEQUENTIAL,
        "MAX_DROPOUT": MAX_DROPOUT,
        "MAX_MISORDER": MAX_MISORDER,
    }:
        raise InputError("sequence validation parameters diverge from RFC 3550 A.1")

    forbidden = sorted(set(_walk_keys(document)) & FORBIDDEN_RAW_KEYS)
    if forbidden:
        raise InputError(f"forbidden raw field published: {forbidden[0]}")

    streams = document.get("source_streams")
    if not isinstance(streams, list):
        raise InputError("source_streams must be an array")
    if document.get("source_stream_count") != len(streams) + document.get(
        "source_streams_omitted", 0
    ):
        raise InputError("source_stream_count does not conserve published streams")
    if document.get("unassigned_packet_count") != len(
        document.get("unassigned_packets") or []
    ) + document.get("unassigned_packets_omitted", 0):
        raise InputError("unassigned_packet_count does not conserve published packets")

    stream_references: set[str] = set()
    event_references: set[str] = set()
    published_event_reference_count = 0
    totals = {
        "rtp_packet_count": 0,
        "sequence_eligible_packet_count": 0,
        "duplicate_sequence_observation_count": 0,
        "out_of_order_packet_count": 0,
        "observed_sequence_gap_count": 0,
        "restart_pattern_count": 0,
        "event_references_omitted": 0,
        "sequence_epochs_omitted": 0,
        "sequence_gaps_omitted": 0,
        "restart_patterns_omitted": 0,
    }
    status_counts = {status: 0 for status in SEQUENCE_STATUSES}
    for stream in streams:
        reference = stream.get("source_stream_reference")
        if not isinstance(reference, str) or not STREAM_REFERENCE_PATTERN.fullmatch(
            reference
        ):
            raise InputError("a source-stream reference is invalid")
        if reference in stream_references:
            raise InputError("source-stream references are not unique")
        stream_references.add(reference)
        expected_reference = "rtp-source-stream:{}:{}:{}".format(
            stream.get("capture_file"),
            stream.get("udp_stream"),
            str(stream.get("ssrc_reference", "")).rsplit(":", 1)[-1],
        )
        if reference != expected_reference:
            raise InputError(
                "a source-stream reference disagrees with its capture, UDP stream or SSRC reference"
            )
        if stream.get("sequence_validation_status") not in SEQUENCE_STATUSES:
            raise InputError("a source-stream sequence status is invalid")
        status_counts[stream["sequence_validation_status"]] += 1
        if stream.get("source_endpoint_identity_status") not in (
            SOURCE_ENDPOINT_IDENTITY_STATUSES
        ):
            raise InputError("a source endpoint identity status is invalid")
        if stream.get("destination_endpoint_identity_status") not in (
            SOURCE_ENDPOINT_IDENTITY_STATUSES
        ):
            raise InputError("a destination endpoint identity status is invalid")
        if stream.get("endpoint_evidence_status") not in ENDPOINT_EVIDENCE_STATUSES:
            raise InputError("an endpoint evidence status is invalid")
        if stream.get("evidence_class") != "DERIVED":
            raise InputError("a source stream has an invalid evidence class")
        if stream.get("rtp_packet_count") != (
            stream.get("sequence_eligible_packet_count", 0)
            + stream.get("incomplete_packet_count", 0)
            + stream.get("invalid_or_excluded_packet_count", 0)
        ):
            raise InputError("a source stream packet categories do not conserve")
        last = None
        for epoch in stream.get("sequence_epochs") or []:
            index = epoch.get("epoch_index")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise InputError("a sequence epoch index is invalid")
            if last is not None and index != last + 1:
                raise InputError("sequence epoch indexes are not contiguous")
            last = index
            if epoch.get("sequence_validation_status") not in SEQUENCE_STATUSES:
                raise InputError("a sequence epoch status is invalid")
            if epoch.get("evidence_class") != "DERIVED":
                raise InputError("a sequence epoch has an invalid evidence class")
            if index >= stream.get("sequence_epoch_count", 0):
                raise InputError("a sequence epoch index exceeds the epoch count")
        if (last is None) != (stream.get("sequence_epoch_count") == 0):
            raise InputError("sequence epoch publication disagrees with the count")
        epochs_published = len(stream.get("sequence_epochs") or [])
        if stream.get("sequence_epoch_count") != epochs_published + stream.get(
            "sequence_epochs_omitted", 0
        ):
            raise InputError("sequence epoch counts do not conserve")
        for gap in stream.get("sequence_gaps") or []:
            if not isinstance(gap.get("gap_reference"), str) or not GAP_REFERENCE_PATTERN.fullmatch(
                gap["gap_reference"]
            ):
                raise InputError("a sequence gap reference is invalid")
            if gap.get("evidence_class") != "DERIVED":
                raise InputError("a sequence gap has an invalid evidence class")
            if gap.get("epoch_index", 0) >= stream.get("sequence_epoch_count", 0):
                raise InputError("a sequence gap epoch index exceeds the epoch count")
            if gap.get("start_extended_sequence_position") >= gap.get(
                "end_extended_sequence_position"
            ):
                raise InputError("a sequence gap has an invalid extended-position range")
            if gap.get("unobserved_sequence_number_count") != len(
                gap.get("unobserved_sequence_numbers") or []
            ) + gap.get("unobserved_sequence_numbers_omitted", 0):
                raise InputError("sequence gap conservation failed")
            if gap.get("filled_sequence_number_count") != len(
                gap.get("filled_sequence_numbers") or []
            ) + gap.get("filled_sequence_numbers_omitted", 0):
                raise InputError("sequence gap fill conservation failed")
        gaps_published = len(stream.get("sequence_gaps") or [])
        if stream.get("observed_sequence_gap_count", 0) != gaps_published + stream.get(
            "sequence_gaps_omitted", 0
        ):
            raise InputError("sequence gap counts do not conserve")
        for pattern in stream.get("restart_patterns") or []:
            if not isinstance(
                pattern.get("restart_reference"), str
            ) or not RESTART_REFERENCE_PATTERN.fullmatch(pattern["restart_reference"]):
                raise InputError("a restart-pattern reference is invalid")
            if pattern.get("restart_confirmation") not in {"CONFIRMED", "UNCONFIRMED"}:
                raise InputError("a restart confirmation status is invalid")
            if pattern.get("evidence_class") != "DERIVED":
                raise InputError("a restart pattern has an invalid evidence class")
            if pattern.get("previous_epoch_index", 0) >= stream.get(
                "sequence_epoch_count", 0
            ):
                raise InputError("a restart pattern epoch index exceeds the epoch count")
            if pattern.get("new_epoch_index") is not None and pattern.get(
                "new_epoch_index"
            ) >= stream.get("sequence_epoch_count", 0):
                raise InputError("a restart pattern new epoch exceeds the epoch count")
        restarts_published = len(stream.get("restart_patterns") or [])
        if stream.get("restart_pattern_count", 0) != restarts_published + stream.get(
            "restart_patterns_omitted", 0
        ):
            raise InputError("restart pattern counts do not conserve")
        published = stream.get("event_references") or []
        for item in published:
            if not isinstance(item, str) or item in event_references:
                raise InputError("published source event references are not unique")
            event_references.add(item)
        published_event_reference_count += len(published)
        if stream.get("event_reference_count") != len(published) + stream.get(
            "event_references_omitted", 0
        ):
            raise InputError("source event reference conservation failed")
        for key in totals:
            totals[key] += stream.get(key, 0)

    for packet in document.get("unassigned_packets") or []:
        reference = packet.get("event_reference")
        if not isinstance(reference, str) or reference in event_references:
            raise InputError("published unassigned event references are not unique")
        event_references.add(reference)
        published_event_reference_count += 1
        if packet.get("original_evidence_status") not in EVENT_EVIDENCE_STATUSES:
            raise InputError("an unassigned packet evidence status is invalid")
        if not packet.get("reason_codes"):
            raise InputError("an unassigned packet has no reason code")

    completeness = document.get("completeness")
    if not isinstance(completeness, dict):
        raise InputError("completeness is missing")
    total = completeness.get("total_input_rtp_packet_count", 0)
    assigned = completeness.get("assigned_rtp_packet_count", 0)
    unassigned = completeness.get("unassigned_rtp_packet_count", 0)
    if total != assigned + unassigned:
        raise InputError("RTP input packet conservation failed")
    if total != completeness.get("sequence_eligible_rtp_packet_count", 0) + completeness.get(
        "excluded_rtp_packet_count", 0
    ):
        raise InputError("RTP eligibility conservation failed")
    if document.get("source_streams_omitted", 0) == 0:
        if assigned != totals["rtp_packet_count"]:
            raise InputError("assigned packet count disagrees with source streams")
        if completeness.get("sequence_eligible_rtp_packet_count") != totals[
            "sequence_eligible_packet_count"
        ]:
            raise InputError("eligible packet count disagrees with source streams")
        if completeness.get("duplicate_observation_count") != totals[
            "duplicate_sequence_observation_count"
        ]:
            raise InputError("duplicate observation count disagrees")
        if completeness.get("out_of_order_observation_count") != totals[
            "out_of_order_packet_count"
        ]:
            raise InputError("out-of-order observation count disagrees")
        if completeness.get("sequence_gap_count") != totals[
            "observed_sequence_gap_count"
        ]:
            raise InputError("sequence gap count disagrees")
        if completeness.get("restart_pattern_count") != totals[
            "restart_pattern_count"
        ]:
            raise InputError("restart pattern count disagrees")
        if sum(status_counts.values()) != completeness.get("source_stream_count"):
            raise InputError("source stream status counts do not sum")
        if status_counts["VALIDATED"] != completeness.get(
            "sequence_validated_stream_count"
        ):
            raise InputError("validated stream count disagrees")
        if status_counts["PROBATION"] != completeness.get("probation_stream_count"):
            raise InputError("probation stream count disagrees")
        if status_counts["AMBIGUOUS"] != completeness.get("ambiguous_stream_count"):
            raise InputError("ambiguous stream count disagrees")
        if status_counts["INSUFFICIENT_EVIDENCE"] != completeness.get(
            "incomplete_stream_count"
        ):
            raise InputError("incomplete stream count disagrees")
    if completeness.get("published_source_stream_count") != len(streams):
        raise InputError("published stream count disagrees")
    expected_omitted = (
        document.get("source_streams_omitted", 0)
        + document.get("unassigned_packets_omitted", 0)
        + completeness.get("event_references_omitted", 0)
    )
    if completeness.get("omitted_record_count") != expected_omitted:
        raise InputError("omitted record count does not account for all truncation")
    if published_event_reference_count + completeness.get(
        "event_references_omitted", 0
    ) + document.get("unassigned_packets_omitted", 0) != total:
        raise InputError("event reference inventory conservation failed")
    if completeness.get("rtcp_event_count") != document.get("rtcp_event_count"):
        raise InputError("RTCP event count disagrees")
    if not document.get("limitations"):
        raise InputError("limitations must not be empty")
    if not document.get("not_confirmed"):
        raise InputError("not_confirmed must not be empty")