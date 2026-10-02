#!/usr/bin/env python3
"""Shared, standalone helpers for bounded GTP-U (N3) evidence extraction.

Reviewed basis: 3GPP TS 29.281 version 19.2.0 Release 19 (GPRS Tunnelling
Protocol User Plane, GTPv1-U) for the GTP-U header, message types, TEID
rules and extension header types, and 3GPP TS 38.415 version 19.1.0
Release 19 (PDU Session User Plane protocol) for the PDU Session Container
content. Message types come from TS 29.281 table 6.1-1, extension header
types from the reviewed extension header type table in clause 5.2.1.

Field names follow the GTP dissector of Wireshark/TShark as published in
the Wireshark display-filter reference. The reviewed environment had no
local tshark installation, so field names are published-reference verified
rather than locally re-dumped; that verification debt is recorded in
references/field-reference.md. No field name is invented: the reviewed
reference exposes no dedicated field for the encapsulated inner packet, so
inner packet metadata is accepted from structured input only.

Bounded semantics: G-PDU, Echo Request, Echo Response, Error Indication,
End Marker and Supported Extension Headers Notification are SUPPORTED.
Tunnel Status is recognized and UNSUPPORTED; message types outside the
reviewed table are UNKNOWN. This module never implements a byte-level GTP-U
decoder, never correlates to PFCP/NGAP/NAS, never interprets application
payloads, and never concludes that a tunnel delivered traffic, that a
packet was lost, or that a network function is defective.

Timestamp normalization matches the core-network-pcap convention; the code
is duplicated here on purpose so this package stays standalone when the
core-network-pcap Skill is not installed.
"""

from __future__ import annotations

import csv
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN
from pathlib import Path
from typing import Iterable, Iterator


EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "gtpu-event"

PROTOCOL_NAME = "GTP-U"
INTERFACE_NAME = "N3"

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "gtp.flags.version",
    "gtp.flags.payload",
    "gtp.flags.e",
    "gtp.flags.s",
    "gtp.flags.pn",
    "gtp.message",
    "gtp.length",
    "gtp.teid",
    "gtp.seq_number",
    "gtp.npdu_number",
    "gtp.next",
    "gtp.ext_hdr_type",
    "gtp.ext_hdr.length",
    "gtp.ext_hdr.next",
    "gtp.ext_hdr.pdu_ses_con.pdu_type",
    "gtp.ext_hdr.pdu_ses_con.qos_flow_id",
    "gtp.ext_hdr.pdu_ses_con.rqi",
    "gtp.ext_hdr.pdu_ses_con.ppi",
    "gtp.ext_hdr.pdu_ses_con.ppp",
    "gtp.unknown_extension_header",
    "gtp.recovery",
    "gtp.teid_data",
    "gtp.num_ext_hdr_types",
)

# Reviewed GTP-U message types (TS 29.281 19.2.0 table 6.1-1).
# code -> (reviewed name, class)
MESSAGE_TYPES = {
    1: ("Echo Request", "path-management"),
    2: ("Echo Response", "path-management"),
    26: ("Error Indication", "path-management"),
    31: ("Supported Extension Headers Notification", "path-management"),
    253: ("Tunnel Status", "path-management"),
    254: ("End Marker", "tunnel-management"),
    255: ("G-PDU", "user-plane"),
}

SUPPORTED_MESSAGE_TYPES = frozenset({1, 2, 26, 31, 254, 255})

# TS 29.281 19.2.0 clause 5.1: the Echo Request/Response, the Supported
# Extension Headers Notification and the Error Indication messages carry a
# TEID of all zeroes. A G-PDU and an End Marker carry the tunnel TEID.
TEID_ZERO_MESSAGE_TYPES = frozenset({1, 2, 26, 31})

# Reviewed extension header types (TS 29.281 19.2.0 clause 5.2.1).
EXTENSION_HEADER_TYPES = {
    0x00: "No more extension headers",
    0x01: "Reserved - Control Plane only",
    0x02: "Reserved - Control Plane only",
    0x03: "Long PDCP PDU Number",
    0x04: "PDU Set Information Container",
    0x20: "Service Class Indicator",
    0x40: "UDP Port",
    0x81: "RAN Container",
    0x82: "Long PDCP PDU Number",
    0x83: "Xw RAN Container",
    0x84: "NR RAN Container",
    0x85: "PDU Session Container",
    0x86: "PDU Set Information Container",
    0xC0: "PDCP PDU Number",
    0xC1: "Reserved - Control Plane only",
    0xC2: "Reserved - Control Plane only",
}

PDU_SESSION_CONTAINER_TYPE = 0x85

# Reviewed PDU Session Container PDU types (TS 38.415 19.1.0 clause 5.5.2).
PDU_SESSION_CONTAINER_PDU_TYPES = {
    0: "DL PDU SESSION INFORMATION",
    1: "UL PDU SESSION INFORMATION",
}

# Local normalized message-role labels (NOT wire values). Only the Echo pair
# has a reviewed request/response relationship; every other supported message
# carries null rather than an invented role.
RESULT_LABELS = {1: "REQUEST", 2: "RESPONSE"}

BINDING_STRUCTURED = "structured-input"
BINDING_SINGLE = "single-source-order"
BINDING_UNBOUND = "unbound"


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested GTP-U fields."""


@dataclass(frozen=True)
class MessageIdentity:
    """Normalized GTP-U identity for one observed datagram."""

    message_type_code: int
    message_type: str | None
    message_class: str | None
    support_status: str
    teid_expected_zero: bool
    derivations: tuple[str, ...]


def safe_capture_name(path: Path) -> str:
    """Return a basename so outputs do not disclose workstation paths."""
    return path.name


def clean(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def parse_int(value: object, field: str) -> int:
    text = clean(value)
    if text is None:
        raise InputError(f"{field} is required")
    try:
        return int(text, 0)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


def optional_int(value: object) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes"}:
        return True
    if text in {"0", "false", "no"}:
        return False
    raise InputError("boolean field must be true/false or 0/1")


def parse_port(value: object, field: str) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        port = int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer port") from exc
    if not 0 <= port <= 65535:
        raise InputError(f"{field} is outside the valid port range")
    return port


def repeated_tokens(value: object) -> list[str]:
    """Ordered tokens from a repeated field (comma-joined text or JSON array)."""
    if value is None:
        return []
    items = [str(item) for item in value] if isinstance(value, (list, tuple)) else str(value).split(",")
    return [token.strip() for token in items if token.strip()]


def repeated_ints(value: object) -> list[int]:
    result: list[int] = []
    for token in repeated_tokens(value):
        try:
            result.append(int(token, 0))
        except ValueError as exc:
            raise InputError("repeated numeric field must contain integers") from exc
    return result


def first_token(value: object) -> str | None:
    """First comma-separated token of a scalar field.

    The GTP dissector re-dissects the encapsulated inner packet, so a plain
    ``ip.src`` export can contain both the outer and the inner address. The
    outer header is parsed first, so the first token is the outer address;
    inner packet metadata is therefore taken from structured input only.
    """
    text = clean(value)
    if text is None:
        return None
    return text.split(",")[0].strip() or None


def normalize_timestamp(value: object) -> str:
    """Convert tshark epoch seconds to UTC ISO-8601 with microsecond precision."""
    text = clean(value)
    if text is None:
        raise InputError("frame.time_epoch is required")
    try:
        epoch = Decimal(text)
    except InvalidOperation as exc:
        raise InputError("frame.time_epoch is not a valid epoch timestamp") from exc
    if not epoch.is_finite():
        raise InputError("frame.time_epoch must be finite")
    microseconds = int((epoch * Decimal("1000000")).to_integral_value(rounding=ROUND_HALF_EVEN))
    try:
        instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    except OverflowError as exc:
        raise InputError("frame.time_epoch is outside the supported UTC range") from exc
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def resolve_message(code: int) -> MessageIdentity:
    """Normalize GTP-U message identity from the reviewed message-type table."""
    known = MESSAGE_TYPES.get(code)
    if known is None:
        return MessageIdentity(
            message_type_code=code,
            message_type=None,
            message_class=None,
            support_status="UNKNOWN",
            teid_expected_zero=False,
            derivations=(),
        )
    name, message_class = known
    derivations = ["message_type", "message_class"]
    return MessageIdentity(
        message_type_code=code,
        message_type=name,
        message_class=message_class,
        support_status="SUPPORTED" if code in SUPPORTED_MESSAGE_TYPES else "UNSUPPORTED",
        teid_expected_zero=code in TEID_ZERO_MESSAGE_TYPES,
        derivations=tuple(sorted(derivations)),
    )


def parse_header(record: dict[str, object], identity: MessageIdentity) -> dict[str, object]:
    """Preserve directly observed GTP-U header fields."""
    version = optional_int(record.get("gtp.flags.version"))
    if version is not None and not 0 <= version <= 7:
        raise InputError("gtp.flags.version must be within 0..7")
    teid = optional_int(record.get("gtp.teid"))
    if teid is not None and not 0 <= teid <= 4294967295:
        raise InputError("gtp.teid must be within the 32-bit unsigned range")
    sequence_number = optional_int(record.get("gtp.seq_number"))
    if sequence_number is not None and not 0 <= sequence_number <= 65535:
        raise InputError("gtp.seq_number must be within the 16-bit range")
    npdu = optional_int(record.get("gtp.npdu_number"))
    if npdu is not None and not 0 <= npdu <= 255:
        raise InputError("gtp.npdu_number must be within 0..255")
    next_header = optional_int(record.get("gtp.next"))
    if next_header is not None and not 0 <= next_header <= 255:
        raise InputError("gtp.next must be within 0..255")
    length = optional_int(record.get("gtp.length"))
    if length is not None and length < 0:
        raise InputError("gtp.length must not be negative")
    return {
        "version": version,
        "protocol_type": optional_int(record.get("gtp.flags.payload")),
        "e_flag": optional_bool(record.get("gtp.flags.e")),
        "s_flag": optional_bool(record.get("gtp.flags.s")),
        "pn_flag": optional_bool(record.get("gtp.flags.pn")),
        "message_type_code": identity.message_type_code,
        "message_type": identity.message_type,
        "message_length": length,
        "teid": teid,
        "sequence_number": sequence_number,
        "n_pdu_number": npdu,
        "next_extension_header": next_header,
        "teid_expected_zero": identity.teid_expected_zero,
    }


def resolve_extension_headers(record: dict[str, object]) -> tuple[list[dict[str, object]], list[str]]:
    """Return (extension_headers, limitations).

    Structured input may declare the extension header chain explicitly, which
    preserves the parent-child structure. Flattened dissector output exposes
    the type chain in packet order but does not prove which length belongs to
    which header, so a multi-header chain keeps the types and leaves the
    lengths unbound.
    """
    limitations: list[str] = []
    structured = record.get("extension_headers")
    if structured is not None:
        if not isinstance(structured, list):
            raise InputError("extension_headers must be an array")
        items: list[dict[str, object]] = []
        for entry in structured:
            if not isinstance(entry, dict):
                raise InputError("each extension_headers entry must be an object")
            type_code = optional_int(entry.get("type"))
            if type_code is None:
                raise InputError("extension header entry requires a type")
            if not 0 <= type_code <= 255:
                raise InputError("extension header type must be within 0..255")
            items.append({
                "type": type_code,
                "name": EXTENSION_HEADER_TYPES.get(type_code),
                "length": optional_int(entry.get("length")),
                "next": optional_int(entry.get("next")),
                "binding_basis": BINDING_STRUCTURED,
            })
        return items, limitations

    types = repeated_ints(record.get("gtp.ext_hdr_type"))
    lengths = repeated_ints(record.get("gtp.ext_hdr.length"))
    nexts = repeated_ints(record.get("gtp.ext_hdr.next"))
    unknown = clean(record.get("gtp.unknown_extension_header")) is not None
    if not types and not unknown:
        return [], limitations
    if len(types) == 1:
        return [{
            "type": types[0],
            "name": EXTENSION_HEADER_TYPES.get(types[0]),
            "length": lengths[0] if lengths else None,
            "next": nexts[0] if nexts else None,
            "binding_basis": BINDING_SINGLE,
        }], limitations
    if not types:
        limitations.append("an unknown extension header was flagged but no extension header type was exported")
        return [], limitations
    items = [{
        "type": type_code,
        "name": EXTENSION_HEADER_TYPES.get(type_code),
        "length": None,
        "next": None,
        "binding_basis": BINDING_UNBOUND,
    } for type_code in types]
    if lengths:
        limitations.append("extension header lengths were observed but are not safely attributable to individual extension headers")
    if nexts:
        limitations.append("next-extension-header values were observed but are not safely attributable to individual extension headers")
    return items, limitations


def resolve_pdu_session_container(record: dict[str, object], headers: list[dict[str, object]]) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Return (pdu_session_container, unbound_metadata).

    The container is bound when structured input declares it, or when exactly
    one container is observed in the message. A repeated container leaves the
    QFI/RQI/PPI values unbound rather than selecting one arbitrarily.
    """
    structured = record.get("pdu_session_container")
    if structured is not None:
        if not isinstance(structured, dict):
            raise InputError("pdu_session_container must be an object")
        pdu_type = optional_int(structured.get("pdu_type"))
        if pdu_type is not None and not 0 <= pdu_type <= 15:
            raise InputError("pdu_session_container.pdu_type must be within 0..15")
        qfi = optional_int(structured.get("qfi"))
        if qfi is not None and not 0 <= qfi <= 63:
            raise InputError("pdu_session_container.qfi must be within 0..63")
        return {
            "present": True,
            "pdu_type": pdu_type,
            "pdu_type_name": PDU_SESSION_CONTAINER_PDU_TYPES.get(pdu_type) if pdu_type is not None else None,
            "qfi": qfi,
            "rqi": optional_bool(structured.get("rqi")),
            "ppi": optional_int(structured.get("ppi")),
            "binding_basis": BINDING_STRUCTURED,
        }, None

    pdu_types = repeated_ints(record.get("gtp.ext_hdr.pdu_ses_con.pdu_type"))
    qfis = repeated_ints(record.get("gtp.ext_hdr.pdu_ses_con.qos_flow_id"))
    rqi_raw = optional_bool(record.get("gtp.ext_hdr.pdu_ses_con.rqi"))
    ppi_raw = optional_int(record.get("gtp.ext_hdr.pdu_ses_con.ppi"))
    container_declared = any(item.get("type") == PDU_SESSION_CONTAINER_TYPE for item in headers)
    if not pdu_types and not qfis and rqi_raw is None and ppi_raw is None and not container_declared:
        return None, None

    if len(pdu_types) <= 1 and len(qfis) <= 1:
        pdu_type = pdu_types[0] if pdu_types else (0 if container_declared else None)
        qfi = qfis[0] if qfis else None
        if qfi is not None and not 0 <= qfi <= 63:
            raise InputError("gtp.ext_hdr.pdu_ses_con.qos_flow_id must be within 0..63")
        return {
            "present": True,
            "pdu_type": pdu_type,
            "pdu_type_name": PDU_SESSION_CONTAINER_PDU_TYPES.get(pdu_type) if pdu_type is not None else None,
            "qfi": qfi,
            "rqi": rqi_raw,
            "ppi": ppi_raw,
            "binding_basis": BINDING_SINGLE,
        }, None

    limitations = ["multiple PDU Session Container values were observed and are not safely attributable to a single container"]
    unbound = {
        "pdu_session_container_values": [
            {"pdu_type": pdu_types[index] if index < len(pdu_types) else None,
             "qfi": qfis[index] if index < len(qfis) else None}
            for index in range(max(len(pdu_types), len(qfis)))
        ],
        "limitations": limitations,
    }
    return None, unbound


def resolve_inner_packet(record: dict[str, object]) -> dict[str, object] | None:
    """Bounded inner packet metadata from structured input only.

    The reviewed dissector reference exposes no dedicated field for the
    encapsulated packet, and the flattened export cannot separate the outer
    header from the re-dissected inner header. Inner metadata is therefore
    accepted only from the explicit structured ``inner_packet`` object, and
    application payload bytes are never accepted.
    """
    raw = record.get("inner_packet")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise InputError("inner_packet must be an object")
    forbidden = [key for key in raw if key in {"payload", "payload_bytes", "application_payload", "data"}]
    if forbidden:
        raise InputError("inner_packet must not carry application payload bytes")
    ip_version = optional_int(raw.get("ip_version"))
    if ip_version is not None and ip_version not in (4, 6):
        raise InputError("inner_packet.ip_version must be 4 or 6")
    return {
        "present": True,
        "ip_version": ip_version,
        "source_address": clean(raw.get("source_address")),
        "destination_address": clean(raw.get("destination_address")),
        "protocol": optional_int(raw.get("protocol")),
        "source_port": parse_port(raw.get("source_port"), "inner_packet.source_port"),
        "destination_port": parse_port(raw.get("destination_port"), "inner_packet.destination_port"),
        "length": optional_int(raw.get("length")),
        "opaque": bool(optional_bool(raw.get("opaque"))),
        "binding_basis": BINDING_STRUCTURED,
    }


def _outer_endpoint(record: dict[str, object], direction: str) -> dict[str, object] | None:
    address = first_token(record.get(f"ip.{direction}")) or first_token(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"udp.{direction}port"), f"udp.{direction}port")
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def directed_path_key(event: dict[str, object]) -> str:
    """Derived directed tunnel context key.

    Scoped by capture, outer source endpoint, outer destination endpoint and
    TEID. A TEID alone is never a global tunnel identity, and the key is
    explicitly not a standardized GTP-U identifier.
    """
    capture = str(event.get("capture_file") or "unknown-capture")
    outer = event.get("outer") if isinstance(event.get("outer"), dict) else {}
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    source = f"{outer.get('source_address')}:{outer.get('source_port')}"
    destination = f"{outer.get('destination_address')}:{outer.get('destination_port')}"
    return f"gtpu-path:{capture}:{source}:{destination}:teid{header.get('teid')}"


def normalize_record(record: object, capture_file: str) -> dict[str, object]:
    """Project one structured GTP-U observation into the detailed event."""
    if not isinstance(record, dict):
        raise InputError("structured GTP-U record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    message_type_code = parse_int(record.get("gtp.message"), "gtp.message")
    if not 0 <= message_type_code <= 255:
        raise InputError("gtp.message must be within 0..255")
    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    identity = resolve_message(message_type_code)
    header = parse_header(record, identity)
    extension_headers, header_limitations = resolve_extension_headers(record)
    container, container_unbound = resolve_pdu_session_container(record, extension_headers)
    inner_packet = resolve_inner_packet(record)

    source = _outer_endpoint(record, "src")
    destination = _outer_endpoint(record, "dst")
    outer = {
        "source_address": source["address"] if source else None,
        "destination_address": destination["address"] if destination else None,
        "source_port": source["port"] if source else None,
        "destination_port": destination["port"] if destination else None,
    }

    recovery = optional_int(record.get("gtp.recovery"))
    if recovery is not None and not 0 <= recovery <= 255:
        raise InputError("gtp.recovery must be within 0..255")

    error_indication = None
    if identity.message_type_code == 26:
        affected = optional_int(record.get("gtp.teid_data"))
        if affected is not None and not 0 <= affected <= 4294967295:
            raise InputError("gtp.teid_data must be within the 32-bit unsigned range")
        error_indication = {
            "affected_teid": affected,
            "peer_address": clean(record.get("peer_address")),
            "header_teid": header["teid"],
        }

    end_marker = None
    if identity.message_type_code == 254:
        end_marker = {"teid": header["teid"]}

    advertised = repeated_ints(record.get("gtp.num_ext_hdr_types")) if identity.message_type_code == 31 else []
    advertised_types = []
    if identity.message_type_code == 31:
        advertised_types = [
            {"type": type_code, "name": EXTENSION_HEADER_TYPES.get(type_code)}
            for type_code in repeated_ints(record.get("advertised_extension_header_types"))
        ]

    external_source_role = clean(record.get("outer_source_role"))
    external_destination_role = clean(record.get("outer_destination_role"))

    limitations = list(header_limitations)
    if header["teid"] == 0 and not identity.teid_expected_zero and identity.message_type_code in (254, 255):
        limitations.append("header TEID is zero although the reviewed message definition expects a tunnel TEID")

    source_ref = f"capture:{capture_file}#frame={frame_number}; message-type={message_type_code}"
    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "header": header,
        "support_status": identity.support_status,
        "result": RESULT_LABELS.get(identity.message_type_code),
        "outer": outer,
        "extension_headers": extension_headers,
        "pdu_session_container": container,
        "inner_packet": inner_packet,
        "error_indication": error_indication,
        "end_marker": end_marker,
        "recovery": recovery,
        "advertised_extension_header_count": advertised[0] if advertised else None,
        "advertised_extension_headers": advertised_types,
        "unbound_metadata": container_unbound,
        "limitations": limitations,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": list(identity.derivations),
    }
    if external_source_role is not None:
        event["external_source_role"] = external_source_role
    if external_destination_role is not None:
        event["external_destination_role"] = external_destination_role
    return event


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed GTP-U event into the shared trace-event contract.

    The generic TEID is populated only from a G-PDU or End Marker header TEID
    that identifies the observed tunnel; for messages whose header TEID is
    the reviewed all-zeroes placeholder the field is omitted. QFI is
    projected only when exactly one is unambiguously associated. SEID, PDU
    session ID, DNN, APN, bearer ID and subscriber fields are never populated
    from GTP-U.
    """
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL_NAME,
        "interface": INTERFACE_NAME,
        "procedure": header.get("message_type"),
        "message_type": header.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"gtpu-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    outer = event.get("outer") if isinstance(event.get("outer"), dict) else {}
    if outer.get("source_address") is not None:
        projected["source"] = {"address": outer.get("source_address"), "port": outer.get("source_port")}
    if outer.get("destination_address") is not None:
        projected["destination"] = {"address": outer.get("destination_address"), "port": outer.get("destination_port")}

    session: dict[str, object] = {}
    teid = header.get("teid")
    if teid is not None and not (header.get("teid_expected_zero") and teid == 0):
        session["teid"] = str(teid)
    container = event.get("pdu_session_container") if isinstance(event.get("pdu_session_container"), dict) else {}
    qfi = container.get("qfi")
    if qfi is not None:
        session["qfi"] = int(qfi)
    if session:
        projected["session"] = session
    return projected


def read_jsonl(path: Path) -> Iterator[dict[str, object]]:
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON Lines record at line {line_number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"JSON Lines record at line {line_number} is not an object")
            yield record


def tshark_version() -> str:
    try:
        completed = subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(capture: Path) -> list[str]:
    """Build the bounded field-extraction command.

    ``occurrence=a`` exports every occurrence of a repeated field
    comma-joined, so a multi-header extension chain and repeated container
    values are never truncated to the first occurrence. The flattened export
    still does not prove which value belongs to which header; that is handled
    by the explicit binding rules in the model, never by positional zipping.
    """
    command = ["tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-Y", "gtp"]
    for field in FIELDS:
        command.extend(["-e", field])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    command = build_tshark_fields_command(capture)
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
    if tuple(header) != FIELDS:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark did not expose the required GTP-U fields: {stderr or header}")
    for row in reader:
        if len(row) > len(FIELDS):
            raise TsharkError("tshark returned more columns than the requested GTP-U field set")
        padded = row + [""] * (len(FIELDS) - len(row))
        yield dict(zip(FIELDS, padded, strict=True))
    stderr = process.stderr.read().strip() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise TsharkError(f"tshark capture parsing failed: {stderr or f'exit {return_code}'}")


def input_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    if path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
        return "capture"
    if path.suffix.lower() in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    raise InputError("cannot infer input format; use --input-format capture or fields-jsonl")


def records_for_input(path: Path, requested: str) -> tuple[Iterable[dict[str, object]], str | None]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    kind = input_kind(path, requested)
    if kind == "fields-jsonl":
        return read_jsonl(path), None
    if kind == "capture":
        return tshark_records(path), tshark_version()
    raise InputError(f"unsupported extracted format: {kind}")
