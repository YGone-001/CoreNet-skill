#!/usr/bin/env python3
"""Bounded RTP version 2 and RTCP subset evidence extraction.

Structured JSONL is the deterministic offline contract. Authorized PCAP input
uses an installed TShark dissector through a reviewed field allowlist. No manual
RTP/RTCP binary parser is implemented here.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import shutil
import subprocess
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from typing import Any, Callable

from endpoint_reference import (
    EndpointError,
    EndpointKeyError,
    endpoint_context_reference,
    endpoint_reference,
    is_context_reference,
    is_endpoint_reference,
)

ANALYSIS_NAME = "rtp-rtcp"
ANALYSIS_VERSION = "0.5.0"
EVENT_SCHEMA_VERSION = "1.3.0"
PARSER_VERSION = "0.5.0"
CAPABILITY = "bounded RTP and RTCP packet evidence with optional endpoint references"

MAX_RECORDS = 1024
MAX_COMPONENTS = 16
MAX_REPORT_BLOCKS = 31
MAX_SDES_CHUNKS = 16
MAX_SDES_ITEMS = 16
MAX_SOURCES = 16
MAX_LIST_ITEMS = 64
MAX_PACKET_LENGTH = 262144

REFERENCE_PATTERN = re.compile(r"^[a-z][a-z0-9-]*:.+:[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
CAPTURE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ +-]{0,127}$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._/-]{1,64}$")

RTCP_TYPE_NAMES = {
    200: "SR",
    201: "RR",
    202: "SDES",
    203: "BYE",
    204: "APP",
    205: "RTPFB",
    206: "PSFB",
    207: "XR",
    208: "AVB",
    209: "RSI",
}
SUPPORTED_RTCP_TYPES = {200, 201, 202, 203}
SDES_ITEM_NAMES = {
    1: "CNAME",
    2: "NAME",
    3: "EMAIL",
    4: "PHONE",
    5: "LOC",
    6: "TOOL",
    7: "NOTE",
    8: "PRIV",
}
REQUIRED_TSHARK_FIELDS = (
    "rtp.version",
    "rtp.padding",
    "rtp.ext",
    "rtp.cc",
    "rtp.marker",
    "rtp.p_type",
    "rtp.seq",
    "rtp.timestamp",
    "rtp.ssrc",
    "rtcp.version",
    "rtcp.pt",
    "rtcp.length",
    "rtcp.senderssrc",
    "udp.stream",
)
OPTIONAL_TSHARK_FIELDS = (
    "udp.stream.pnum",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
)
ENDPOINT_FIELDS = ("source_address", "destination_address", "source_port", "destination_port")
PACKET_FINGERPRINT_PREFIX = "rtp-packet-fingerprint-v1:"
PACKET_FINGERPRINT_DOMAIN = b"corenet-rtp-packet-v1\x00"


class InputError(ValueError):
    """Raised when a structured or capture input contract is malformed."""


class ToolError(RuntimeError):
    """Raised when the accepted dissector is unavailable or incomplete."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _unique(values: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for value in values:
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else value
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _int(value: Any, minimum: int, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < minimum or value > maximum:
        return None
    return value


def _bool(value: Any, default: bool = False) -> bool:
    return value if isinstance(value, bool) else default


def _timestamp(value: Any) -> str | None:
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def _validate_capture_name(value: Any, line_number: int | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise InputError("capture_file must be a non-empty safe basename")
    if (
        not CAPTURE_NAME_PATTERN.fullmatch(value)
        or value in (".", "..")
        or "/" in value
        or "\\" in value
        or ":" in value
    ):
        location = f"input line {line_number} " if line_number is not None else ""
        raise InputError(f"{location}capture_file must be a privacy-safe basename")
    return value


def _ssrc_reference(capture: str, ssrc: int) -> str:
    return f"rtp-ssrc:{capture}:{ssrc:08x}"


def _component_reference(capture: str, frame: int, occurrence: int, index: int) -> str:
    return f"rtcp-component:{capture}:{frame}.{occurrence}.{index}"


def _escalate(current: str, candidate: str) -> str:
    severity = {
        "OBSERVED": 0,
        "UNSUPPORTED": 1,
        "AMBIGUOUS": 2,
        "INCOMPLETE": 3,
        "INVALID": 4,
    }
    return candidate if severity[candidate] > severity[current] else current


def _tri_flag(fields: dict[str, Any], key: str) -> tuple[bool | None, bool, bool]:
    """Return (value, present, invalid) without defaulting a missing flag to false."""
    if key not in fields or fields[key] is None:
        return None, False, False
    value = fields[key]
    if isinstance(value, bool):
        return value, True, False
    return None, True, True


def _version_value(value: Any) -> tuple[int | None, str]:
    if value is None:
        return None, "MISSING"
    if isinstance(value, bool) or not isinstance(value, int):
        return None, "INVALID"
    if value < 0 or value > 3:
        return None, "INVALID"
    return value, "VALID"


def _rtp_endpoint_evidence(
    record: dict[str, Any], fields: dict[str, Any], endpoint_key: bytes | None
) -> dict[str, Any]:
    if endpoint_key is None:
        return {}
    evidence: dict[str, Any] = {
        "source_transport_endpoint_reference": None,
        "destination_transport_endpoint_reference": None,
        "transport_endpoint_status": "UNAVAILABLE",
        "transport_endpoint_reason_codes": [],
    }
    if fields.get("endpoint_transport_ambiguous"):
        evidence["transport_endpoint_status"] = "AMBIGUOUS"
        evidence["transport_endpoint_reason_codes"] = [
            "MULTIPLE_TRANSPORT_CANDIDATES"
        ]
        return evidence
    raw_values = [fields.get(name) for name in ENDPOINT_FIELDS]
    if any(isinstance(value, list) for value in raw_values):
        evidence["transport_endpoint_status"] = "AMBIGUOUS"
        evidence["transport_endpoint_reason_codes"] = [
            "MULTIPLE_TRANSPORT_CANDIDATES"
        ]
        return evidence
    present = [value is not None for value in raw_values]
    if not any(present):
        evidence["transport_endpoint_reason_codes"] = [
            "UDP_ENDPOINT_FIELDS_UNAVAILABLE"
        ]
        return evidence
    if not all(present):
        evidence["transport_endpoint_status"] = "INCOMPLETE"
        evidence["transport_endpoint_reason_codes"] = ["UDP_ENDPOINT_FIELDS_INCOMPLETE"]
        return evidence
    source_address, destination_address, source_port, destination_port = raw_values
    try:
        source_reference = endpoint_reference(
            endpoint_key,
            record["capture_sha256"],
            source_address,
            source_port,
            "UDP",
        )
        destination_reference = endpoint_reference(
            endpoint_key,
            record["capture_sha256"],
            destination_address,
            destination_port,
            "UDP",
        )
    except (EndpointError, EndpointKeyError):
        evidence["transport_endpoint_reason_codes"] = ["UDP_ENDPOINT_INVALID"]
        return evidence
    evidence.update(
        {
            "source_transport_endpoint_reference": source_reference,
            "destination_transport_endpoint_reference": destination_reference,
            "transport_endpoint_status": "ESTABLISHED",
        }
    )
    return evidence


def _rtp_event(
    record: dict[str, Any],
    fields: dict[str, Any],
    endpoint_key: bytes | None = None,
) -> dict[str, Any]:
    capture = record["capture_file"]
    frame = record["frame_number"]
    occurrence = record["message_occurrence"]
    reasons: list[str] = []
    limitations = [
        "RTP payload bytes are never published",
        "SSRC is a capture-scoped protocol observation, not a subscriber or session identity",
        "RTP packet observation does not prove media delivery or two-way audio",
    ]
    status = "OBSERVED"
    version, version_state = _version_value(fields.get("version"))
    if version_state == "MISSING":
        reasons.append("RTP_VERSION_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif version_state == "INVALID":
        reasons.append("RTP_VERSION_INVALID")
        status = _escalate(status, "INVALID")
    elif version != 2:
        reasons.append("UNSUPPORTED_RTP_VERSION")
        status = _escalate(status, "UNSUPPORTED")
    padding, padding_present, padding_invalid = _tri_flag(fields, "padding")
    if not padding_present:
        reasons.append("RTP_PADDING_FLAG_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif padding_invalid:
        reasons.append("RTP_PADDING_FLAG_INVALID")
        status = _escalate(status, "INVALID")
    if padding is True:
        raw_padding_count = fields.get("padding_count")
        parsed_padding = _int(raw_padding_count, 1, MAX_PACKET_LENGTH)
        if raw_padding_count is None:
            reasons.append("PADDING_COUNT_MISSING")
            status = _escalate(status, "INCOMPLETE")
            padding_count = None
        elif parsed_padding is None:
            reasons.append("PADDING_COUNT_INVALID")
            status = _escalate(status, "INVALID")
            padding_count = None
        else:
            padding_count = parsed_padding
    else:
        raw_padding_count = fields.get("padding_count")
        if raw_padding_count is None:
            padding_count = 0
        else:
            padding_count = _int(raw_padding_count, 0, MAX_PACKET_LENGTH)
            if padding_count is None:
                reasons.append("PADDING_COUNT_INVALID")
                status = _escalate(status, "INVALID")
    extension, extension_present, extension_invalid = _tri_flag(fields, "extension")
    if not extension_present:
        reasons.append("RTP_EXTENSION_FLAG_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif extension_invalid:
        reasons.append("RTP_EXTENSION_FLAG_INVALID")
        status = _escalate(status, "INVALID")
    extension_profile = None
    extension_length = None
    if extension is True:
        if fields.get("extension_profile") is None:
            reasons.append("EXTENSION_PROFILE_MISSING")
            status = _escalate(status, "INCOMPLETE")
        else:
            extension_profile = _int(fields.get("extension_profile"), 0, 65535)
            if extension_profile is None:
                reasons.append("EXTENSION_PROFILE_INVALID")
                status = _escalate(status, "INVALID")
        if fields.get("extension_length") is None:
            reasons.append("EXTENSION_LENGTH_MISSING")
            status = _escalate(status, "INCOMPLETE")
        else:
            extension_length = _int(fields.get("extension_length"), 0, 65535)
            if extension_length is None:
                reasons.append("EXTENSION_LENGTH_INVALID")
                status = _escalate(status, "INVALID")
    csrc_count = _int(fields.get("csrc_count"), 0, 15)
    csrc = fields.get("csrc", [])
    if not isinstance(csrc, list):
        csrc = []
        reasons.append("CSRC_LIST_INVALID")
        status = "INVALID" if status == "OBSERVED" else status
    parsed_csrc = [
        _int(value, 0, 0xFFFFFFFF) for value in csrc[:15]
    ]
    if any(value is None for value in parsed_csrc):
        reasons.append("CSRC_IDENTIFIER_INVALID")
        status = "INVALID" if status == "OBSERVED" else status
    parsed_csrc = [value for value in parsed_csrc if value is not None]
    if csrc_count is None:
        reasons.append("CSRC_COUNT_INVALID")
        status = "INVALID" if status == "OBSERVED" else status
    elif csrc_count != len(parsed_csrc):
        reasons.append("CSRC_COUNT_MISMATCH")
        status = "AMBIGUOUS" if status == "OBSERVED" else status
    marker, marker_present, marker_invalid = _tri_flag(fields, "marker")
    if not marker_present:
        reasons.append("RTP_MARKER_FLAG_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif marker_invalid:
        reasons.append("RTP_MARKER_FLAG_INVALID")
        status = _escalate(status, "INVALID")
    payload_type = _int(fields.get("payload_type"), 0, 127)
    sequence = _int(fields.get("sequence_number"), 0, 65535)
    timestamp = _int(fields.get("timestamp"), 0, 0xFFFFFFFF)
    ssrc = _int(fields.get("ssrc"), 0, 0xFFFFFFFF)
    packet_length = _int(fields.get("packet_length"), 12, MAX_PACKET_LENGTH)
    required = (
        ("RTP_PAYLOAD_TYPE", fields.get("payload_type"), payload_type),
        ("RTP_SEQUENCE", fields.get("sequence_number"), sequence),
        ("RTP_TIMESTAMP", fields.get("timestamp"), timestamp),
        ("RTP_SSRC", fields.get("ssrc"), ssrc),
        ("RTP_PACKET_LENGTH", fields.get("packet_length"), packet_length),
    )
    for label, raw_value, parsed_value in required:
        if raw_value is None:
            reasons.append(f"{label}_MISSING")
            status = "INCOMPLETE" if status == "OBSERVED" else status
        elif parsed_value is None:
            reasons.append(f"{label}_INVALID")
            status = "INVALID"
    if "payload" in fields or "payload_hex" in fields:
        limitations.append("RTP payload field ignored and not published")
    if fields.get("truncated"):
        reasons.append("TRUNCATED_RTP_PACKET")
        status = "INCOMPLETE" if status in ("OBSERVED", "UNSUPPORTED") else status
    packet_bytes = fields.get("packet_bytes")
    packet_payload_error = fields.get("packet_payload_error")
    packet_byte_count = len(packet_bytes) if isinstance(packet_bytes, (bytes, bytearray)) else None
    packet_fingerprint = None
    if endpoint_key is None:
        fingerprint_status = "UNAVAILABLE_NO_KEY"
    elif not isinstance(packet_bytes, (bytes, bytearray)) or not packet_bytes:
        fingerprint_status = packet_payload_error or "PACKET_PAYLOAD_UNAVAILABLE"
    elif fields.get("truncated"):
        fingerprint_status = "TRUNCATED_RTP_PACKET"
    elif status == "INVALID":
        fingerprint_status = "RTP_HEADER_EVIDENCE_INVALID"
    else:
        packet_fingerprint = _rtp_packet_fingerprint(
            endpoint_key, record["capture_sha256"], bytes(packet_bytes)
        )
        fingerprint_status = "ESTABLISHED"
    if packet_fingerprint is not None:
        limitations.append(
            "RTP packet identity is a capture-scoped keyed HMAC over complete RTP packet bytes; raw bytes are never published"
        )
    event = {
        "event_reference": record["source_reference"],
        "capture_file": capture,
        "capture_sha256": record["capture_sha256"],
        "frame_number": frame,
        "frame_timestamp": record["frame_timestamp"],
        "frame_reference": record["frame_reference"],
        "message_occurrence": occurrence,
        "protocol": "RTP",
        "parser_version": PARSER_VERSION,
        "evidence_status": status,
        "version": version,
        "padding": padding,
        "padding_count": padding_count,
        "extension": extension,
        "extension_profile": extension_profile if extension else None,
        "extension_length": extension_length if extension else None,
        "csrc_count": csrc_count,
        "csrc": parsed_csrc,
        "marker": marker,
        "payload_type": payload_type,
        "sequence_number": sequence,
        "timestamp": timestamp,
        "ssrc": ssrc,
        "ssrc_reference": _ssrc_reference(capture, ssrc) if ssrc is not None else None,
        "packet_length": packet_length,
        "rtp_packet_byte_count": packet_byte_count,
        "rtp_packet_fingerprint": packet_fingerprint,
        "rtp_packet_fingerprint_status": fingerprint_status,
        "rtp_packet_identity_scope": (
            "CAPTURE_SCOPED_HMAC_SHA256" if packet_fingerprint is not None else None
        ),
        "udp_stream": _int(fields.get("udp_stream"), 0, 0xFFFFFFFF),
        "udp_stream_packet": _int(fields.get("udp_stream_packet"), 0, 0xFFFFFFFF),
        "invalid_reasons": sorted(set(reasons)),
        "limitations": limitations,
        "not_confirmed": [
            "RTP_DELIVERY",
            "MEDIA_QUALITY",
            "TWO_WAY_AUDIO",
            "CODEC_FROM_DYNAMIC_PAYLOAD_TYPE",
        ],
    }
    event.update(_rtp_endpoint_evidence(record, fields, endpoint_key))
    return event


def _report_block(block: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(block, dict):
        return None, [f"REPORT_BLOCK_{index}_NOT_AN_OBJECT"]
    reasons: list[str] = []
    reported = _int(block.get("reported_ssrc"), 0, 0xFFFFFFFF)
    fraction = _int(block.get("fraction_lost"), 0, 255)
    cumulative = block.get("cumulative_packets_lost")
    if isinstance(cumulative, bool) or not isinstance(cumulative, int) or not (-8388608 <= cumulative <= 8388607):
        cumulative = None
        reasons.append(f"REPORT_BLOCK_{index}_CUMULATIVE_LOSS_INVALID")
    extended = _int(block.get("extended_highest_sequence"), 0, 0xFFFFFFFF)
    jitter = _int(block.get("interarrival_jitter"), 0, 0xFFFFFFFF)
    lsr = _int(block.get("last_sr_timestamp"), 0, 0xFFFFFFFF)
    dlsr = _int(block.get("delay_since_last_sr"), 0, 0xFFFFFFFF)
    if reported is None:
        reasons.append(f"REPORT_BLOCK_{index}_SSRC_MISSING")
    if fraction is None:
        reasons.append(f"REPORT_BLOCK_{index}_FRACTION_LOST_MISSING")
    if extended is None:
        reasons.append(f"REPORT_BLOCK_{index}_EXTENDED_SEQUENCE_MISSING")
    if jitter is None:
        reasons.append(f"REPORT_BLOCK_{index}_JITTER_MISSING")
    if lsr is None:
        reasons.append(f"REPORT_BLOCK_{index}_LSR_MISSING")
    if dlsr is None:
        reasons.append(f"REPORT_BLOCK_{index}_DLSR_MISSING")
    if reasons:
        return None, reasons
    return {
        "reported_ssrc": reported,
        "fraction_lost": fraction,
        "cumulative_packets_lost": cumulative,
        "extended_highest_sequence": extended,
        "interarrival_jitter": jitter,
        "last_sr_timestamp": lsr,
        "delay_since_last_sr": dlsr,
        "binding_status": "OBSERVED",
        "reported_value_class": "RECEIVER_REPORTED",
    }, []


def _sdes_chunk(chunk: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(chunk, dict):
        return None, [f"SDES_CHUNK_{index}_NOT_AN_OBJECT"]
    source = _int(chunk.get("source_ssrc"), 0, 0xFFFFFFFF)
    items = chunk.get("items", [])
    if source is None or not isinstance(items, list):
        return None, [f"SDES_CHUNK_{index}_INVALID"]
    parsed = []
    reasons = []
    for item in items[:MAX_SDES_ITEMS]:
        if not isinstance(item, dict):
            reasons.append(f"SDES_CHUNK_{index}_ITEM_INVALID")
            continue
        item_type = _int(item.get("item_type"), 0, 255)
        value_present = _bool(item.get("value_present"))
        value_length = item.get("value_length")
        if item_type is None or (value_present and _int(value_length, 0, 65535) is None):
            reasons.append(f"SDES_CHUNK_{index}_ITEM_INVALID")
            continue
        parsed.append(
            {
                "item_type": item_type,
                "item_name": SDES_ITEM_NAMES.get(item_type, "UNKNOWN"),
                "value_present": value_present,
                "value_length": value_length if value_present else 0,
                "value_redacted": True,
            }
        )
    return {
        "source_ssrc": source,
        "items": parsed,
        "items_omitted": max(0, len(items) - len(parsed)),
    }, reasons


def _rtcp_component(
    record: dict[str, Any], component: dict[str, Any], index: int
) -> dict[str, Any]:
    capture = record["capture_file"]
    frame = record["frame_number"]
    occurrence = record["message_occurrence"]
    reasons: list[str] = []
    packet_type = _int(component.get("packet_type"), 0, 255)
    packet_type_name = RTCP_TYPE_NAMES.get(packet_type, "UNKNOWN") if packet_type is not None else "UNKNOWN"
    version = None
    length = _int(component.get("length"), 0, 65535)
    status = "OBSERVED"
    limitations = [
        "RTCP report values are remote-reported protocol values, not local measurements",
        "RTCP BYE does not prove media delivery or teardown",
        "RTCP payload, SDES text, APP data and feedback payload are never published",
    ]
    version_state = "VALID"
    if version is None:
        raw_version = component.get("version")
        version, version_state = _version_value(raw_version)
    if version_state == "MISSING":
        reasons.append("RTCP_VERSION_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif version_state == "INVALID":
        reasons.append("RTCP_VERSION_INVALID")
        status = _escalate(status, "INVALID")
    elif version != 2:
        reasons.append("UNSUPPORTED_RTCP_VERSION")
        status = _escalate(status, "UNSUPPORTED")
    if packet_type is None:
        reasons.append("RTCP_PACKET_TYPE_MISSING")
        status = _escalate(status, "INCOMPLETE")
    elif packet_type not in SUPPORTED_RTCP_TYPES:
        reasons.append("UNSUPPORTED_RTCP_PACKET_TYPE")
        status = _escalate(status, "UNSUPPORTED")
        limitations.append(f"RTCP packet type {packet_type} is outside the implemented SR/RR/SDES/BYE subset")
    if length is None:
        reasons.append("RTCP_LENGTH_MISSING")
        status = _escalate(status, "INCOMPLETE")
    report_count = _int(component.get("report_count"), 0, 31)
    report_blocks: list[dict[str, Any]] = []
    if packet_type in (200, 201):
        blocks = component.get("report_blocks", [])
        if not isinstance(blocks, list):
            reasons.append("REPORT_BLOCKS_NOT_AN_ARRAY")
            status = "INVALID"
            blocks = []
        for block_index, block in enumerate(blocks[:MAX_REPORT_BLOCKS]):
            parsed, block_reasons = _report_block(block, block_index)
            reasons.extend(block_reasons)
            if parsed:
                report_blocks.append(parsed)
        if report_count is not None and report_count != len(blocks):
            reasons.append("REPORT_COUNT_MISMATCH")
            if status in ("OBSERVED", "UNSUPPORTED"):
                status = "AMBIGUOUS"
        if report_count is None:
            reasons.append("REPORT_COUNT_MISSING")
            if status == "OBSERVED":
                status = "INCOMPLETE"
        if any("REPORT_BLOCK" in reason for reason in reasons) and status == "OBSERVED":
            status = "INCOMPLETE"
    sdes_chunks: list[dict[str, Any]] = []
    declared_source_count = None
    observed_source_count = 0
    source_count_status = "NOT_APPLICABLE"
    if packet_type == 202:
        declared_source_count = _int(component.get("source_count"), 0, 31)
        if "sdes_chunks" not in component or component.get("sdes_chunks") is None:
            reasons.append("SDES_CHUNKS_UNAVAILABLE")
            status = _escalate(status, "INCOMPLETE")
            chunks = []
        else:
            chunks = component.get("sdes_chunks")
            if not isinstance(chunks, list):
                reasons.append("SDES_CHUNKS_NOT_AN_ARRAY")
                status = _escalate(status, "INVALID")
                chunks = []
        for chunk_index, chunk in enumerate(chunks[:MAX_SDES_CHUNKS]):
            parsed, chunk_reasons = _sdes_chunk(chunk, chunk_index)
            reasons.extend(chunk_reasons)
            if parsed:
                sdes_chunks.append(parsed)
        observed_source_count = len(sdes_chunks)
        if declared_source_count is None:
            reasons.append("SDES_SOURCE_COUNT_MISSING")
            status = _escalate(status, "INCOMPLETE")
            source_count_status = "INCOMPLETE"
        elif declared_source_count != observed_source_count:
            reasons.append("SDES_SOURCE_COUNT_MISMATCH")
            status = _escalate(status, "AMBIGUOUS")
            source_count_status = "AMBIGUOUS"
        else:
            source_count_status = "OBSERVED"
        if any("SDES" in reason and "SOURCE_COUNT" not in reason and "CHUNKS" not in reason for reason in reasons):
            status = _escalate(status, "INCOMPLETE")
    sender_info = None
    if packet_type == 200:
        source = component.get("sender_report")
        if not isinstance(source, dict):
            reasons.append("SENDER_REPORT_INFO_MISSING")
            status = "INCOMPLETE"
        else:
            sender_info = {
                "ntp_msw": _int(source.get("ntp_msw"), 0, 0xFFFFFFFF),
                "ntp_lsw": _int(source.get("ntp_lsw"), 0, 0xFFFFFFFF),
                "ntp_present": _bool(source.get("ntp_present")),
                "rtp_timestamp": _int(source.get("rtp_timestamp"), 0, 0xFFFFFFFF),
                "packet_count": _int(source.get("packet_count"), 0, 0xFFFFFFFF),
                "octet_count": _int(source.get("octet_count"), 0, 0xFFFFFFFF),
            }
            if any(sender_info[key] is None for key in ("ntp_msw", "ntp_lsw", "rtp_timestamp", "packet_count", "octet_count")):
                reasons.append("SENDER_REPORT_FIELD_INCOMPLETE")
                status = "INCOMPLETE" if status == "OBSERVED" else status
    bye_reason_present = _bool(component.get("bye_reason_present"))
    bye_reason_length = _int(component.get("bye_reason_length"), 0, 65535) if bye_reason_present else 0
    if bye_reason_present and bye_reason_length is None:
        reasons.append("BYE_REASON_LENGTH_INVALID")
        bye_reason_length = 0
        status = "INCOMPLETE" if status == "OBSERVED" else status
    if component.get("hierarchy_unavailable"):
        reasons.append("RTCP_NESTED_HIERARCHY_UNAVAILABLE")
        status = "INCOMPLETE" if status == "OBSERVED" else status
        limitations.append("The source representation did not prove nested RTCP component/report-block binding")
    bye_sources: list[int] = []
    if packet_type == 203:
        declared_source_count = _int(component.get("source_count"), 0, 31)
        if "bye_sources" not in component or component.get("bye_sources") is None:
            reasons.append("BYE_SOURCES_UNAVAILABLE")
            status = _escalate(status, "INCOMPLETE")
            raw_sources = []
        else:
            raw_sources = component.get("bye_sources")
            if not isinstance(raw_sources, list):
                reasons.append("BYE_SOURCES_NOT_AN_ARRAY")
                status = _escalate(status, "INVALID")
                raw_sources = []
        for source in raw_sources[:MAX_SOURCES]:
            parsed = _int(source, 0, 0xFFFFFFFF)
            if parsed is None:
                reasons.append("BYE_SOURCE_INVALID")
                status = "INVALID"
            else:
                bye_sources.append(parsed)
        observed_source_count = len(bye_sources)
        if declared_source_count is None:
            reasons.append("BYE_SOURCE_COUNT_MISSING")
            status = _escalate(status, "INCOMPLETE")
            source_count_status = "INCOMPLETE"
        elif declared_source_count != observed_source_count:
            reasons.append("BYE_SOURCE_COUNT_MISMATCH")
            status = _escalate(status, "AMBIGUOUS")
            source_count_status = "AMBIGUOUS"
        elif declared_source_count == 0:
            source_count_status = "OBSERVED"
            limitations.append("A zero-source BYE packet is valid per RFC 3550 but conveys no source identifier; no more is inferred")
        else:
            source_count_status = "OBSERVED"
    sender_ssrc = _int(component.get("sender_ssrc"), 0, 0xFFFFFFFF)
    if packet_type in (200, 201, 202, 203) and sender_ssrc is None and packet_type != 203:
        reasons.append("SENDER_SSRC_MISSING")
        status = "INCOMPLETE" if status == "OBSERVED" else status
    if component.get("truncated"):
        reasons.append("TRUNCATED_RTCP_COMPONENT")
        status = "INCOMPLETE" if status in ("OBSERVED", "UNSUPPORTED") else status
    if component.get("malformed_length"):
        reasons.append("RTCP_LENGTH_INVALID")
        status = "INVALID"
    return {
        "event_reference": _component_reference(capture, frame, occurrence, index),
        "packet_reference": record["source_reference"],
        "capture_file": capture,
        "capture_sha256": record["capture_sha256"],
        "frame_number": frame,
        "frame_timestamp": record["frame_timestamp"],
        "frame_reference": record["frame_reference"],
        "message_occurrence": occurrence,
        "protocol": "RTCP",
        "component_index": index,
        "packet_type": packet_type,
        "packet_type_name": packet_type_name,
        "version": version,
        "length": length,
        "report_count": report_count,
        "declared_source_count": declared_source_count,
        "observed_source_count": observed_source_count,
        "source_count_status": source_count_status,
        "sender_ssrc": sender_ssrc,
        "sender_ssrc_reference": _ssrc_reference(capture, sender_ssrc) if sender_ssrc is not None else None,
        "sender_report": sender_info,
        "report_blocks": report_blocks,
        "sdes_chunks": sdes_chunks,
        "bye_sources": bye_sources,
        "bye_source_count": len(bye_sources),
        "bye_reason_present": bye_reason_present,
        "bye_reason_length": bye_reason_length,
        "udp_stream": _int(component.get("udp_stream"), 0, 0xFFFFFFFF),
        "udp_stream_packet": _int(component.get("udp_stream_packet"), 0, 0xFFFFFFFF),
        "evidence_status": status,
        "invalid_reasons": sorted(set(reasons)),
        "limitations": limitations,
        "not_confirmed": [
            "LOCAL_PACKET_LOSS",
            "LOCAL_JITTER",
            "MOS",
            "MEDIA_QUALITY",
            "TWO_WAY_MEDIA",
            "MEDIA_DELIVERY",
        ],
    }


def _parse_record(
    record: dict[str, Any], endpoint_key: bytes | None = None
) -> list[dict[str, Any]]:
    protocol = record["protocol"]
    fields = record["fields"]
    if protocol == "RTP":
        return [_rtp_event(record, fields, endpoint_key)]
    if protocol != "RTCP":
        raise InputError("protocol must be RTP or RTCP")
    components = fields.get("components")
    if not isinstance(components, list) or not components:
        raise InputError("RTCP fields must contain a non-empty components array")
    if len(components) > MAX_COMPONENTS:
        raise InputError(f"RTCP compound packet exceeds {MAX_COMPONENTS} components")
    return [
        _rtcp_component(record, component, index)
        for index, component in enumerate(components)
    ]


def _validate_record(record: Any, line_number: int) -> None:
    if not isinstance(record, dict):
        raise InputError(f"input line {line_number} is not an object")
    for key in (
        "source_reference",
        "capture_file",
        "capture_sha256",
        "frame_number",
        "frame_timestamp",
        "frame_reference",
        "message_occurrence",
        "protocol",
        "fields",
    ):
        if key not in record:
            raise InputError(f"input line {line_number} is missing {key}")
    if not isinstance(record["source_reference"], str) or not REFERENCE_PATTERN.fullmatch(record["source_reference"]):
        raise InputError(f"input line {line_number} has an invalid source_reference")
    _validate_capture_name(record["capture_file"], line_number)
    if not isinstance(record["capture_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["capture_sha256"]):
        raise InputError(f"input line {line_number} has an invalid capture_sha256")
    if isinstance(record["frame_number"], bool) or not isinstance(record["frame_number"], int) or record["frame_number"] < 1:
        raise InputError(f"input line {line_number} has an invalid frame_number")
    if not isinstance(record["frame_timestamp"], str) or not record["frame_timestamp"]:
        raise InputError(f"input line {line_number} has no frame_timestamp")
    if not isinstance(record["frame_reference"], str) or not record["frame_reference"]:
        raise InputError(f"input line {line_number} has no frame_reference")
    if isinstance(record["message_occurrence"], bool) or not isinstance(record["message_occurrence"], int) or record["message_occurrence"] < 1:
        raise InputError(f"input line {line_number} has an invalid message_occurrence")
    if record["protocol"] not in {"RTP", "RTCP"}:
        raise InputError(f"input line {line_number} has an unsupported protocol")
    if not isinstance(record["fields"], dict):
        raise InputError(f"input line {line_number} fields must be an object")
    if record["protocol"] == "RTP":
        fields = record["fields"]
        for key in ("source_address", "destination_address"):
            if key not in fields:
                continue
            value = fields[key]
            if not isinstance(value, str):
                raise InputError(f"input line {line_number} {key} must be a string")
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise InputError(
                    f"input line {line_number} {key} is not a valid IP address"
                ) from None
        for key in ("source_port", "destination_port"):
            if key not in fields:
                continue
            value = fields[key]
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
                raise InputError(
                    f"input line {line_number} {key} is not a valid UDP port"
                )
        if "endpoint_transport_ambiguous" in fields and not isinstance(
            fields["endpoint_transport_ambiguous"], bool
        ):
            raise InputError(
                f"input line {line_number} endpoint_transport_ambiguous must be a boolean"
            )


def load_structured_messages(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InputError(f"input could not be read: {exc}") from exc
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"input line {line_number} is not valid JSON: {exc}") from exc
        _validate_record(record, line_number)
        records.append(record)
    if not records:
        raise InputError("input contains no RTP or RTCP messages")
    if len(records) > MAX_RECORDS:
        raise InputError(f"input exceeds the {MAX_RECORDS}-record bound")
    if len({record["source_reference"] for record in records}) != len(records):
        raise InputError("RTP/RTCP source references are not unique")
    captures = {(record["capture_file"], record["capture_sha256"]) for record in records}
    if len(captures) != 1:
        raise InputError("RTP/RTCP input mixes capture provenance")
    return records


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def probe_tshark(tshark: str = "tshark") -> list[str]:
    if shutil.which(tshark) is None:
        raise ToolError("TSHARK_UNAVAILABLE", "TShark is not installed; capture extraction was not run")
    completed = subprocess.run(
        [tshark, "-G", "fields"], capture_output=True, text=True, check=False
    )
    if completed.returncode != 0:
        raise ToolError("TSHARK_PROBE_FAILED", "TShark field probe failed")
    available = {
        line.split("\t")[2]
        for line in completed.stdout.splitlines()
        if line.startswith("F\t") and len(line.split("\t")) > 2
    }
    missing = [field for field in REQUIRED_TSHARK_FIELDS if field not in available]
    if missing:
        raise ToolError(
            "UNSUPPORTED_TSHARK_FIELD",
            "TShark lacks required reviewed fields: " + ", ".join(missing),
        )
    return [field for field in OPTIONAL_TSHARK_FIELDS if field not in available]


def _tshark_run(
    capture: Path, decode_as: list[str], tshark: str = "tshark"
) -> dict[str, Any]:
    command = [
        tshark,
        "-r",
        str(capture),
        "-T",
        "json",
        "-Y",
        "rtp or rtcp",
        "-n",
    ]
    for mapping in decode_as:
        command.extend(["-d", mapping])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise ToolError(
            "TSHARK_EXTRACTION_FAILED",
            "TShark extraction failed with exit code " + str(completed.returncode),
        )
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ToolError("TSHARK_OUTPUT_INVALID", "TShark JSON output is not valid") from exc
    if not isinstance(payload, list):
        raise ToolError("TSHARK_OUTPUT_INVALID", "TShark JSON output is not an array")
    return {"packets": payload}


def _layer(packet: dict[str, Any], name: str) -> dict[str, Any] | None:
    source = packet.get("_source")
    if not isinstance(source, dict):
        return None
    layers = source.get("layers")
    if not isinstance(layers, dict):
        return None
    value = layers.get(name)
    return value if isinstance(value, dict) else None


def _layer_candidates(packet: dict[str, Any], name: str) -> list[dict[str, Any]]:
    source = packet.get("_source")
    if not isinstance(source, dict):
        return []
    layers = source.get("layers")
    if not isinstance(layers, dict):
        return []
    value = layers.get(name)
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def _endpoint_fields(packet: dict[str, Any]) -> dict[str, Any]:
    source = packet.get("_source")
    layers = source.get("layers") if isinstance(source, dict) else None
    layer_names = set(layers) if isinstance(layers, dict) else set()
    ip_layers = _layer_candidates(packet, "ip") + _layer_candidates(packet, "ipv6")
    udp_layers = _layer_candidates(packet, "udp")
    encapsulated = any(
        name == "gtp" or name.startswith("gtp.") or name.startswith("gtpv")
        for name in layer_names
    )
    if encapsulated:
        # TShark collapses duplicate layer names in JSON. For a GTP-encapsulated
        # RTP/RTCP packet the accepted single IP/UDP pair is usable only when it
        # is the inner transport pair: exactly one pair, an RTP/RTCP layer is
        # present, and the pair is not the GTP-U port 2152. Anything else stays
        # ambiguous rather than guessing between outer and inner endpoints.
        if len(ip_layers) != 1 or len(udp_layers) != 1:
            return {"endpoint_transport_ambiguous": True}
        udp_layer = udp_layers[0]
        source_port = _numeric(_first(udp_layer.get("udp.srcport")))
        destination_port = _numeric(_first(udp_layer.get("udp.dstport")))
        if 2152 in (source_port, destination_port):
            return {"endpoint_transport_ambiguous": True}
        if _layer(packet, "rtp") is None and _layer(packet, "rtcp") is None:
            return {"endpoint_transport_ambiguous": True}
    elif len(ip_layers) > 1 or len(udp_layers) > 1:
        return {"endpoint_transport_ambiguous": True}
    elif len(ip_layers) != 1 or len(udp_layers) != 1:
        return {}
    ip_layer = ip_layers[0]
    raw_addresses = [
        ip_layer.get("ip.src"),
        ip_layer.get("ip.dst"),
        ip_layer.get("ipv6.src"),
        ip_layer.get("ipv6.dst"),
    ]
    if any(isinstance(value, list) for value in raw_addresses):
        return {"endpoint_transport_ambiguous": True}
    source_v4 = ip_layer.get("ip.src")
    source_v6 = ip_layer.get("ipv6.src")
    destination_v4 = ip_layer.get("ip.dst")
    destination_v6 = ip_layer.get("ipv6.dst")
    if (source_v4 and source_v6) or (destination_v4 and destination_v6):
        return {"endpoint_transport_ambiguous": True}
    udp_layer = udp_layers[0]
    fields: dict[str, Any] = {}
    source_address = source_v4 or source_v6
    destination_address = destination_v4 or destination_v6
    source_port = _numeric(_first(udp_layer.get("udp.srcport")))
    destination_port = _numeric(_first(udp_layer.get("udp.dstport")))
    if isinstance(source_address, str) and source_address:
        fields["source_address"] = source_address
    if isinstance(destination_address, str) and destination_address:
        fields["destination_address"] = destination_address
    if source_port is not None:
        fields["source_port"] = source_port
    if destination_port is not None:
        fields["destination_port"] = destination_port
    return fields


def _numeric(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _first(value: Any) -> Any:
    return value[0] if isinstance(value, list) and value else value


def _rtp_payload_bytes(packet: dict[str, Any]) -> tuple[bytes | None, str | None]:
    """Return the complete inner RTP packet bytes, never the enclosing headers."""
    source = packet.get("_source")
    layers = source.get("layers") if isinstance(source, dict) else None
    layer_names = set(layers) if isinstance(layers, dict) else set()
    udp_layers = _layer_candidates(packet, "udp")
    encapsulated = any(
        name == "gtp" or name.startswith("gtp.") or name.startswith("gtpv")
        for name in layer_names
    )
    if encapsulated:
        if len(udp_layers) != 1:
            return None, "PACKET_TRANSPORT_AMBIGUOUS"
        udp_layer = udp_layers[0]
        ports = {
            _numeric(_first(udp_layer.get("udp.srcport"))),
            _numeric(_first(udp_layer.get("udp.dstport"))),
        }
        if 2152 in ports:
            return None, "PACKET_TRANSPORT_AMBIGUOUS"
        if _layer(packet, "rtp") is None and _layer(packet, "rtcp") is None:
            return None, "PACKET_TRANSPORT_AMBIGUOUS"
    elif len(udp_layers) != 1:
        return None, "PACKET_TRANSPORT_AMBIGUOUS"
    else:
        udp_layer = udp_layers[0]
    raw = _first(udp_layer.get("udp.payload"))
    if not isinstance(raw, str) or not raw:
        return None, "PACKET_PAYLOAD_UNAVAILABLE"
    try:
        data = bytes.fromhex(raw.replace(":", ""))
    except ValueError:
        return None, "PACKET_PAYLOAD_ENCODING_INVALID"
    if not data:
        return None, "PACKET_PAYLOAD_UNAVAILABLE"
    declared = _numeric(_first(udp_layer.get("udp.length")))
    if declared is not None and declared >= 8 and len(data) != declared - 8:
        return None, "PACKET_BOUNDARY_INCONSISTENT"
    return data, None


def _rtp_packet_fingerprint(
    key: bytes | None, capture_sha256: str, data: bytes
) -> str | None:
    if key is None:
        return None
    payload = (
        PACKET_FINGERPRINT_DOMAIN
        + capture_sha256.encode("ascii", "strict")
        + b"\x00"
        + data
    )
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return PACKET_FINGERPRINT_PREFIX + digest


def _pdml_run(
    capture: Path, decode_as: list[str], tshark: str = "tshark"
) -> str:
    command = [tshark, "-r", str(capture), "-T", "pdml", "-Y", "rtcp", "-n"]
    for mapping in decode_as:
        command.extend(["-d", mapping])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise ToolError(
            "TSHARK_RTCP_EXTRACTION_FAILED",
            "TShark RTCP PDML extraction failed with exit code " + str(completed.returncode),
        )
    return completed.stdout


def _pdml_show(node: ElementTree.Element, name: str) -> str | None:
    for field in node.iter("field"):
        if field.get("name") == name:
            value = field.get("show")
            return value if isinstance(value, str) else None
    return None


def _pdml_number(node: ElementTree.Element, name: str) -> int | None:
    raw = _pdml_show(node, name)
    if raw is None:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return None


def _pdml_direct(node: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [
        field
        for field in node.findall("field")
        if field.get("name") == name
    ]


def _pdml_udp_ancestor(packet: ElementTree.Element) -> dict[str, Any]:
    # TShark PDML flattens encapsulated protocols into sibling proto elements,
    # so the usable RTP/RTCP transport is the last UDP proto before RTCP.
    current: dict[str, Any] = {}
    for child in packet.findall("proto"):
        name = child.get("name")
        if name == "udp":
            current = {
                "udp.stream": _pdml_show(child, "udp.stream"),
                "udp.stream.pnum": _pdml_show(child, "udp.stream.pnum"),
            }
        elif name == "rtcp":
            return dict(current)
    return {}


def _pdml_rtcp_components(proto: ElementTree.Element) -> dict[str, Any]:
    packet_type = _pdml_number(proto, "rtcp.pt")
    wrappers = [
        field
        for field in proto.iter("field")
        if field.get("name") == ""
        and any(
            child.get("name") == "rtcp.ssrc.identifier"
            for child in field.findall("field")
        )
    ]
    report_blocks: list[dict[str, Any]] = []
    if packet_type in (200, 201):
        for wrapper in wrappers:
            report_blocks.append(
                {
                    "reported_ssrc": _pdml_number(wrapper, "rtcp.ssrc.identifier"),
                    "fraction_lost": _pdml_number(wrapper, "rtcp.ssrc.fraction"),
                    "cumulative_packets_lost": _pdml_number(wrapper, "rtcp.ssrc.cum_nr"),
                    "extended_highest_sequence": _pdml_number(wrapper, "rtcp.ssrc.ext_high"),
                    "interarrival_jitter": _pdml_number(wrapper, "rtcp.ssrc.jitter"),
                    "last_sr_timestamp": _pdml_number(wrapper, "rtcp.ssrc.lsr"),
                    "delay_since_last_sr": _pdml_number(wrapper, "rtcp.ssrc.dlsr"),
                }
            )
    sdes_chunks: list[dict[str, Any]] = []
    if packet_type == 202:
        for wrapper in wrappers:
            items: list[dict[str, Any]] = []
            pending_type: int | None = None
            for field in wrapper.iter("field"):
                name = field.get("name")
                if name == "rtcp.sdes.type":
                    parsed = _pdml_number(wrapper, "rtcp.sdes.type") if pending_type is None else None
                    try:
                        parsed = int(field.get("show") or "", 0)
                    except ValueError:
                        parsed = None
                    if parsed is None:
                        continue
                    if parsed == 0:
                        break
                    pending_type = parsed
                elif name == "rtcp.sdes.length" and pending_type is not None:
                    try:
                        length = int(field.get("show") or "", 0)
                    except ValueError:
                        length = 0
                    items.append(
                        {
                            "item_type": pending_type,
                            "value_present": bool(length > 0),
                            "value_length": length,
                        }
                    )
                    pending_type = None
            sdes_chunks.append(
                {
                    "source_ssrc": _pdml_number(wrapper, "rtcp.ssrc.identifier"),
                    "items": items,
                }
            )
    bye_sources: list[int] = []
    if packet_type == 203:
        for name in ("rtcp.bye.ssrc", "rtcp.ssrc.identifier"):
            for child in _pdml_direct(proto, name):
                value = _pdml_number(child, name)
                if value is not None:
                    bye_sources.append(value)
    bye_reason = _pdml_show(proto, "rtcp.bye.reason")
    return {
        "packet_type": packet_type,
        "version": _pdml_number(proto, "rtcp.version"),
        "length": _pdml_number(proto, "rtcp.length"),
        "report_count": _pdml_number(proto, "rtcp.rc"),
        "source_count": _pdml_number(proto, "rtcp.sc")
        if packet_type in (202, 203)
        else None,
        "sender_ssrc": _pdml_number(proto, "rtcp.senderssrc"),
        "sender_report": {
            "ntp_msw": _pdml_number(proto, "rtcp.timestamp.ntp.msw"),
            "ntp_lsw": _pdml_number(proto, "rtcp.timestamp.ntp.lsw"),
            "ntp_present": _pdml_show(proto, "rtcp.timestamp.ntp") is not None,
            "rtp_timestamp": _pdml_number(proto, "rtcp.timestamp.rtp"),
            "packet_count": _pdml_number(proto, "rtcp.sender.packetcount"),
            "octet_count": _pdml_number(proto, "rtcp.sender.octetcount"),
        }
        if packet_type == 200
        else None,
        "report_blocks": report_blocks,
        "sdes_chunks": sdes_chunks,
        "bye_sources": bye_sources,
        "bye_reason_present": bye_reason is not None,
        "bye_reason_length": len(bye_reason.encode("utf-8")) if bye_reason else 0,
        "hierarchy_unavailable": False,
    }


def _pdml_rtcp_records(capture: Path, text: str) -> list[dict[str, Any]]:
    if not text.strip():
        return []
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ToolError("TSHARK_OUTPUT_INVALID", "TShark RTCP PDML output is not valid") from exc
    capture_name = capture.name
    capture_sha = _sha256(capture)
    records: list[dict[str, Any]] = []
    for packet in root.iter("packet"):
        frame = _pdml_number(packet, "frame.number")
        if frame is None:
            continue
        timestamp = _pdml_show(packet, "frame.time_epoch") or ""
        udp = _pdml_udp_ancestor(packet)
        components = [
            _pdml_rtcp_components(proto)
            for proto in packet.iter("proto")
            if proto.get("name") == "rtcp"
        ]
        if not components:
            continue
        for component in components:
            component["udp_stream"] = _numeric(udp.get("udp.stream"))
            component["udp_stream_packet"] = _numeric(udp.get("udp.stream.pnum"))
        records.append(
            {
                "source_reference": f"rtcp-packet:{capture_name}:{frame}.1",
                "capture_file": capture_name,
                "capture_sha256": capture_sha,
                "frame_number": frame,
                "frame_timestamp": timestamp,
                "frame_reference": f"frame:{frame}",
                "message_occurrence": 1,
                "protocol": "RTCP",
                "fields": {
                    "components": components,
                    "udp_stream": _numeric(udp.get("udp.stream")),
                    "udp_stream_packet": _numeric(udp.get("udp.stream.pnum")),
                },
            }
        )
    return records


def _capture_records(capture: Path, decode_as: list[str], tshark: str, runner: Callable | None = None, pdml_runner: Callable | None = None) -> list[dict[str, Any]]:
    payload = (runner or _tshark_run)(capture, decode_as, tshark)
    capture_name = capture.name
    capture_sha = _sha256(capture)
    pdml_text: str | None = None
    if pdml_runner is not None:
        pdml_text = pdml_runner(capture, decode_as, tshark)
    elif runner is None:
        pdml_text = _pdml_run(capture, decode_as, tshark)
    pdml_records = _pdml_rtcp_records(capture, pdml_text) if pdml_text else []
    pdml_by_reference = {record["source_reference"]: record for record in pdml_records}
    records: list[dict[str, Any]] = []
    emitted_rtcp: set[str] = set()
    for packet in payload.get("packets", []):
        frame = _layer(packet, "frame")
        if not frame:
            continue
        frame_number = _numeric(_first(frame.get("frame.number")))
        if frame_number is None:
            continue
        timestamp = _first(frame.get("frame.time_epoch")) or ""
        occurrence = 1
        udp = _layer(packet, "udp") or {}
        udp_stream = _numeric(_first(udp.get("udp.stream")))
        udp_stream_packet = _numeric(_first(udp.get("udp.stream.pnum")))
        endpoint_fields = _endpoint_fields(packet)
        rtp = _layer(packet, "rtp")
        payload_bytes: bytes | None = None
        payload_error: str | None = None
        if rtp:
            payload_bytes, payload_error = _rtp_payload_bytes(packet)
        if rtp:
            fields = {
                "version": _numeric(_first(rtp.get("rtp.version"))),
                "csrc_count": _numeric(_first(rtp.get("rtp.cc"))),
                "csrc": [_numeric(v) for v in (rtp.get("rtp.csrc.item") or [])] if isinstance(rtp.get("rtp.csrc.item"), list) else [_numeric(rtp.get("rtp.csrc.item"))] if rtp.get("rtp.csrc.item") is not None else [],
                "payload_type": _numeric(_first(rtp.get("rtp.p_type"))),
                "sequence_number": _numeric(_first(rtp.get("rtp.seq"))),
                "timestamp": _numeric(_first(rtp.get("rtp.timestamp"))),
                "ssrc": _numeric(_first(rtp.get("rtp.ssrc"))),
                "packet_length": _numeric(_first(frame.get("frame.len"))),
                "udp_stream": udp_stream,
                "udp_stream_packet": udp_stream_packet,
            }
            fields.update(endpoint_fields)
            fields["packet_bytes"] = payload_bytes
            fields["packet_payload_error"] = payload_error
            for field_name, tshark_name in (
                ("padding", "rtp.padding"),
                ("extension", "rtp.ext"),
                ("marker", "rtp.marker"),
            ):
                raw_flag = _first(rtp.get(tshark_name))
                if raw_flag is None:
                    continue
                parsed_flag = _numeric(raw_flag)
                fields[field_name] = bool(parsed_flag) if parsed_flag in (0, 1) else "INVALID"
            for field_name, tshark_name in (
                ("padding_count", "rtp.padding.count"),
                ("extension_profile", "rtp.ext.profile"),
                ("extension_length", "rtp.ext.len"),
            ):
                raw_value = _first(rtp.get(tshark_name))
                if raw_value is None:
                    continue
                parsed_value = _numeric(raw_value)
                fields[field_name] = parsed_value if parsed_value is not None else "INVALID"
            fields["csrc"] = [value for value in fields["csrc"] if value is not None]
            records.append(
                {
                    "source_reference": f"rtp-packet:{capture_name}:{frame_number}.{occurrence}",
                    "capture_file": capture_name,
                    "capture_sha256": capture_sha,
                    "frame_number": frame_number,
                    "frame_timestamp": str(timestamp),
                    "frame_reference": f"frame:{frame_number}",
                    "message_occurrence": occurrence,
                    "protocol": "RTP",
                    "fields": fields,
                }
            )
        rtcp = _layer(packet, "rtcp")
        if rtcp:
            json_rtcp_reference = f"rtcp-packet:{capture_name}:{frame_number}.1"
            if json_rtcp_reference in pdml_by_reference:
                continue
            packet_type = _numeric(_first(rtcp.get("rtcp.pt")))
            report_blocks = []
            for key, value in rtcp.items():
                if isinstance(value, dict) and value.get("rtcp.ssrc.identifier") is not None:
                    block = {
                        "reported_ssrc": _numeric(_first(value.get("rtcp.ssrc.identifier"))),
                        "fraction_lost": _numeric(_first(value.get("rtcp.ssrc.fraction"))),
                        "cumulative_packets_lost": _numeric(_first(value.get("rtcp.ssrc.cum_nr"))),
                        "extended_highest_sequence": _numeric(_first(value.get("rtcp.ssrc.ext_high"))),
                        "interarrival_jitter": _numeric(_first(value.get("rtcp.ssrc.jitter"))),
                        "last_sr_timestamp": _numeric(_first(value.get("rtcp.ssrc.lsr"))),
                        "delay_since_last_sr": _numeric(_first(value.get("rtcp.ssrc.dlsr"))),
                    }
                    report_blocks.append(block)
            component = {
                "packet_type": packet_type,
                "packet_type_name": RTCP_TYPE_NAMES.get(packet_type, "UNKNOWN") if packet_type is not None else "UNKNOWN",
                "version": _numeric(_first(rtcp.get("rtcp.version"))),
                "length": _numeric(_first(rtcp.get("rtcp.length"))),
                "report_count": _numeric(_first(rtcp.get("rtcp.rc"))),
                "source_count": _numeric(_first(rtcp.get("rtcp.sc"))) if packet_type in (202, 203) else None,
                "sender_ssrc": _numeric(_first(rtcp.get("rtcp.senderssrc"))),
                "sender_report": {
                    "ntp_msw": _numeric(_first(rtcp.get("rtcp.timestamp.ntp.msw"))),
                    "ntp_lsw": _numeric(_first(rtcp.get("rtcp.timestamp.ntp.lsw"))),
                    "ntp_present": "rtcp.timestamp.ntp" in rtcp,
                    "rtp_timestamp": _numeric(_first(rtcp.get("rtcp.timestamp.rtp"))),
                    "packet_count": _numeric(_first(rtcp.get("rtcp.sender.packetcount"))),
                    "octet_count": _numeric(_first(rtcp.get("rtcp.sender.octetcount"))),
                } if packet_type == 200 else None,
                "report_blocks": report_blocks,
                "sdes_chunks": [],
                "bye_sources": [],
                "bye_reason_present": False,
                "bye_reason_length": 0,
                "hierarchy_unavailable": packet_type in (202, 203),
                "udp_stream": udp_stream,
                "udp_stream_packet": udp_stream_packet,
            }
            emitted_rtcp.add(f"rtcp-packet:{capture_name}:{frame_number}.{occurrence}")
            records.append(
                {
                    "source_reference": f"rtcp-packet:{capture_name}:{frame_number}.{occurrence}",
                    "capture_file": capture_name,
                    "capture_sha256": capture_sha,
                    "frame_number": frame_number,
                    "frame_timestamp": str(timestamp),
                    "frame_reference": f"frame:{frame_number}",
                    "message_occurrence": occurrence,
                    "protocol": "RTCP",
                    "fields": {"components": [component]},
                }
            )
    for record in pdml_records:
        if record["source_reference"] in emitted_rtcp:
            continue
        record["fields"]["udp_stream"] = _numeric(
            (record["fields"].get("udp_stream"))
        )
        record["fields"]["udp_stream_packet"] = _numeric(
            (record["fields"].get("udp_stream_packet"))
        )
        records.append(record)
    return records


def build_analysis(events: list[dict[str, Any]], provenance: dict[str, Any]) -> dict[str, Any]:
    references = [event["event_reference"] for event in events]
    if len(references) != len(set(references)):
        raise InputError("RTP/RTCP event references are not unique")
    rtp_events = [event for event in events if event["protocol"] == "RTP"]
    rtcp_events = [event for event in events if event["protocol"] == "RTCP"]
    unsupported = [event for event in events if event["evidence_status"] == "UNSUPPORTED"]
    limitations = [
        "RTP payload, SRTP keys/tags, SDES text, APP data and feedback payload are never published",
        "SSRC is a capture-scoped protocol observation, not a subscriber or media-session identity",
        "RTCP sender/receiver report values are remote-reported values, not locally measured loss or jitter",
        "No local packet-loss, jitter, MOS, QoS, media-delivery or two-way-audio calculation is performed",
        "RTP/RTCP packet presence does not prove successful media delivery",
        "SDP-to-RTP endpoint association is owned by the sdp-rtp-transport Correlation Skill and is not performed here; stream reconstruction is not implemented",
    ]
    if provenance.get("optional_fields_unavailable"):
        limitations.insert(
            0,
            "TShark optional transport fields unavailable: "
            + ", ".join(provenance.get("optional_fields_unavailable") or []),
        )
    if provenance.get("mode") == "PCAP":
        limitations.append(
            "TShark JSON may expose only one RTCP compound component; compound component binding is not assumed"
        )
    if provenance.get("endpoint_context_reference"):
        limitations.append(
            "UDP endpoint references are keyed HMAC-SHA-256 values scoped to the original capture; they do not prove SDP transport correspondence, media delivery or direction of an IMS role"
        )
    document = {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "capability": CAPABILITY,
        "input_provenance": provenance,
        "event_count": len(events),
        "events": events,
        "completeness": {
            "rtp_packet_count": len(rtp_events),
            "rtcp_component_count": len(rtcp_events),
            "sr_component_count": sum(1 for event in rtcp_events if event["packet_type"] == 200),
            "rr_component_count": sum(1 for event in rtcp_events if event["packet_type"] == 201),
            "sdes_component_count": sum(1 for event in rtcp_events if event["packet_type"] == 202),
            "bye_component_count": sum(1 for event in rtcp_events if event["packet_type"] == 203),
            "unsupported_component_count": len(unsupported),
            "observed_event_count": sum(1 for event in events if event["evidence_status"] == "OBSERVED"),
            "incomplete_event_count": sum(1 for event in events if event["evidence_status"] == "INCOMPLETE"),
            "ambiguous_event_count": sum(1 for event in events if event["evidence_status"] == "AMBIGUOUS"),
            "unsupported_event_count": len(unsupported),
            "invalid_event_count": sum(1 for event in events if event["evidence_status"] == "INVALID"),
        },
        "limitations": limitations,
        "not_confirmed": [
            "RTP_DELIVERY",
            "TWO_WAY_AUDIO",
            "MEDIA_QOS",
            "MOS",
            "LOCAL_PACKET_LOSS",
            "LOCAL_JITTER",
            "SDP_TO_RTP_ASSOCIATION",
            "IMS_MEDIA_SESSION",
        ],
    }
    if provenance.get("endpoint_context_reference"):
        document["endpoint_context_reference"] = provenance["endpoint_context_reference"]
    return document


def validate_analysis(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise InputError("RTP/RTCP analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("RTP/RTCP analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("RTP/RTCP analysis_version is not accepted")
    events = document.get("events")
    if not isinstance(events, list):
        raise InputError("RTP/RTCP events must be an array")
    if document.get("event_count") != len(events):
        raise InputError("RTP/RTCP event_count does not match the event array")
    references: set[str] = set()
    for event in events:
        reference = event.get("event_reference")
        if not isinstance(reference, str) or not REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("an RTP/RTCP event reference is invalid")
        if reference in references:
            raise InputError("RTP/RTCP event references are not unique")
        references.add(reference)
        if event.get("evidence_status") not in {"OBSERVED", "INCOMPLETE", "AMBIGUOUS", "UNSUPPORTED", "INVALID"}:
            raise InputError("an RTP/RTCP event has an invalid evidence status")
        if event.get("protocol") not in {"RTP", "RTCP"}:
            raise InputError("an event has an invalid protocol")
        for forbidden in ENDPOINT_FIELDS + ("source_transport_endpoint",):
            if forbidden in event:
                raise InputError("an RTP/RTCP event published a raw endpoint field")
        if "transport_endpoint_status" in event:
            if event.get("protocol") != "RTP":
                raise InputError("a non-RTP event published an endpoint status")
            status = event["transport_endpoint_status"]
            if status not in {"ESTABLISHED", "INCOMPLETE", "AMBIGUOUS", "UNAVAILABLE"}:
                raise InputError("an RTP event has an invalid endpoint status")
            source = event.get("source_transport_endpoint_reference")
            destination = event.get("destination_transport_endpoint_reference")
            if status == "ESTABLISHED":
                if not is_endpoint_reference(source) or not is_endpoint_reference(
                    destination
                ):
                    raise InputError("an established RTP endpoint lacks a valid reference")
            elif source is not None or destination is not None:
                raise InputError("an unavailable RTP endpoint published a reference")
    if document.get("endpoint_context_reference") is not None:
        if not is_context_reference(document["endpoint_context_reference"]):
            raise InputError("RTP/RTCP endpoint context reference is malformed")
    has_endpoint = any("transport_endpoint_status" in event for event in events)
    if has_endpoint and document.get("endpoint_context_reference") is None:
        raise InputError("RTP/RTCP endpoint evidence lacks a context reference")
    completeness = document.get("completeness") or {}
    if sum(
        completeness.get(key, 0)
        for key in (
            "observed_event_count",
            "incomplete_event_count",
            "ambiguous_event_count",
            "unsupported_event_count",
            "invalid_event_count",
        )
    ) != completeness.get("rtp_packet_count", 0) + completeness.get("rtcp_component_count", 0):
        raise InputError("RTP/RTCP status counts do not sum to the published events")


def extract_structured(
    path: Path, endpoint_key: bytes | None = None
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records = load_structured_messages(path)
    events: list[dict[str, Any]] = []
    for record in records:
        events.extend(_parse_record(record, endpoint_key))
    provenance = {
        "mode": "STRUCTURED_JSONL",
        "input_name": path.name,
        "capture_files": [records[0]["capture_file"]],
        "capture_sha256": records[0]["capture_sha256"],
        "input_message_count": len(records),
        "parser_version": PARSER_VERSION,
        "tool": None,
        "decode_as": [],
    }
    if endpoint_key is not None:
        provenance["endpoint_context_reference"] = endpoint_context_reference(
            endpoint_key, records[0]["capture_sha256"]
        )
    return events, provenance


def extract_capture(
    capture: Path,
    decode_as: list[str] | None = None,
    tshark: str = "tshark",
    *,
    runner: Callable | None = None,
    prober: Callable | None = None,
    endpoint_key: bytes | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    decode_as = decode_as or []
    _validate_capture_name(capture.name)
    optional_unavailable = (prober or probe_tshark)(tshark) or []
    records = _capture_records(capture, decode_as, tshark, runner)
    events: list[dict[str, Any]] = []
    for record in records:
        events.extend(_parse_record(record, endpoint_key))
    provenance = {
        "mode": "PCAP",
        "input_name": capture.name,
        "capture_files": [capture.name],
        "capture_sha256": _sha256(capture),
        "input_message_count": len(records),
        "parser_version": PARSER_VERSION,
        "tool": "tshark",
        "decode_as": decode_as,
        "optional_fields_unavailable": list(optional_unavailable),
    }
    if endpoint_key is not None:
        provenance["endpoint_context_reference"] = endpoint_context_reference(
            endpoint_key, provenance["capture_sha256"]
        )
    return events, provenance