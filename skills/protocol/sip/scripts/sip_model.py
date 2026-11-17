#!/usr/bin/env python3
"""Bounded SIP message observation model.

The model consumes a verified TShark PDML dissection or sanitized dissector
records. It never decodes packet bytes itself, never reassembles TCP streams,
and never assigns IMS procedure, transaction or dialog semantics.

Privacy is a publication contract: subscriber identities, SIP URIs, dialog
tags, Call-ID values, credentials and message bodies are reduced to presence
and bounded length metadata. Only the request method, status code, a reviewed
standard reason phrase and a safe media type may be published verbatim.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

PROTOCOL = "SIP"
EVENT_SCHEMA_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 2
EXIT_NO_EVENTS = 3
EXIT_TOOL_UNAVAILABLE = 4
EXIT_TSHARK_FAILURE = 5
EXIT_OUTPUT_FAILURE = 6

MAX_LIMITATIONS = 12
MAX_INTEGRITY_FINDINGS = 8
MAX_METHOD_LENGTH = 32
MAX_REASON_PHRASE_LENGTH = 64
MAX_CONTENT_TYPE_LENGTH = 64

CAPTURE_MAGIC = (
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
    b"\x0a\x0d\x0d\x0a",
)

CORE_METHODS = {
    "ACK",
    "BYE",
    "CANCEL",
    "INFO",
    "INVITE",
    "MESSAGE",
    "NOTIFY",
    "OPTIONS",
    "PRACK",
    "PUBLISH",
    "REFER",
    "REGISTER",
    "SUBSCRIBE",
    "UPDATE",
}

STANDARD_REASON_PHRASES = {
    100: "Trying",
    180: "Ringing",
    181: "Call Is Being Forwarded",
    182: "Queued",
    183: "Session Progress",
    200: "OK",
    202: "Accepted",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    305: "Use Proxy",
    380: "Alternative Service",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Conditional Request Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    416: "Unsupported URI Scheme",
    420: "Bad Extension",
    421: "Extension Required",
    423: "Interval Too Brief",
    480: "Temporarily Unavailable",
    481: "Call/Transaction Does Not Exist",
    482: "Loop Detected",
    483: "Too Many Hops",
    484: "Address Incomplete",
    485: "Ambiguous",
    486: "Busy Here",
    487: "Request Terminated",
    488: "Not Acceptable Here",
    491: "Request Pending",
    493: "Undecipherable",
    500: "Server Internal Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Server Time-out",
    505: "Version Not Supported",
    513: "Message Too Large",
    600: "Busy Everywhere",
    603: "Decline",
    604: "Does Not Exist Anywhere",
    606: "Not Acceptable",
}

METHOD_PATTERN = re.compile(r"^[A-Za-z0-9.!%*_+\-]{1,32}$")
MEDIA_TYPE_PATTERN = re.compile(r"^[A-Za-z0-9!#$&^_.+\-]+/[A-Za-z0-9!#$&^_.+\-]+$")
STATUS_LINE_PATTERN = re.compile(r"^SIP/2\.0\s+([0-9]{3})(?:\s+(.*))?$")

INTEGRITY_MARKERS = {
    "sip.header_not_terminated": "HEADER_NOT_TERMINATED",
    "sip.header_no_colon": "HEADER_NO_COLON",
    "sip.Status-Code.invalid": "INVALID_STATUS_CODE",
    "sip.Call-ID.invalid": "MISSING_CALL_ID",
    "sip.content_length.invalid": "INVALID_CONTENT_LENGTH",
    "sip.sec_mechanism.malformed": "MALFORMED_SECURITY_MECHANISM",
    "sip.unrecognized_header": "UNRECOGNIZED_HEADER",
}

HEADER_COUNT_FIELDS = {
    "route": "sip.Route",
    "record_route": "sip.Record-Route",
    "contact": "sip.Contact",
    "authorization": "sip.Authorization",
    "proxy_authorization": "sip.Proxy-Authorization",
    "www_authenticate": "sip.WWW-Authenticate",
    "proxy_authenticate": "sip.Proxy-Authenticate",
    "p_asserted_identity": "sip.P-Asserted-Identity",
    "p_preferred_identity": "sip.P-Preferred-Identity",
}

KNOWN_VIA_TRANSPORTS = {"UDP", "TCP", "TLS", "SCTP"}


class InputError(Exception):
    pass


class TsharkError(Exception):
    pass


class ToolUnavailable(Exception):
    pass


# ---------------------------------------------------------------------------
# Dissector helpers
# ---------------------------------------------------------------------------


def _field(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.findall("field"):
        if child.get("name") == name:
            return child
    return None


def _fields(node: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in node.findall("field") if child.get("name") == name]


def _descendant_field(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.iter("field"):
        if child.get("name") == name:
            return child
    return None


def _descendant_fields(node: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in node.iter("field") if child.get("name") == name]


def _show(node: ElementTree.Element | None, name: str) -> str | None:
    if node is None:
        return None
    child = _field(node, name)
    return None if child is None else child.get("show")


def _node_show(node: ElementTree.Element | None) -> str | None:
    return None if node is None else node.get("show")


def _int_text(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _proto(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.findall("proto"):
        if child.get("name") == name:
            return child
    return None


def _protos(node: ElementTree.Element, name: str) -> list[ElementTree.Element]:
    return [child for child in node.findall("proto") if child.get("name") == name]


def _packet_field(packet: ElementTree.Element, name: str) -> str | None:
    for proto in packet.findall("proto"):
        for field in proto.findall("field"):
            if field.get("name") == name:
                return field.get("show")
    return None


def _addresses(packet: ElementTree.Element) -> tuple[str | None, str | None]:
    for prefix in ("ip", "ipv6"):
        source = _packet_field(packet, f"{prefix}.src")
        destination = _packet_field(packet, f"{prefix}.dst")
        if source and destination:
            return source, destination
    return None, None


def _tcp_reassembly(packet: ElementTree.Element) -> tuple[str, int | None, int | None]:
    reassembled = _descendant_field(packet, "tcp.reassembled.length")
    segment_count = _descendant_field(packet, "tcp.segment.count")
    length = _int_text(reassembled.get("show")) if reassembled is not None else None
    count = _int_text(segment_count.get("show")) if segment_count is not None else None
    if length is not None:
        return "REASSEMBLED", length, count
    payload = _int_text(_show(_proto(packet, "tcp"), "tcp.len"))
    if payload is not None and payload > 0:
        return "SINGLE_SEGMENT", None, count
    return "INCOMPLETE", None, count


def _transport(packet: ElementTree.Element) -> dict[str, Any]:
    source_address, destination_address = _addresses(packet)
    tcp = _proto(packet, "tcp")
    udp = _proto(packet, "udp")
    if tcp is not None:
        stream_id = _int_text(_show(tcp, "tcp.stream"))
        reassembly, reassembled_length, segment_count = _tcp_reassembly(packet)
        return {
            "protocol": "TCP",
            "source_address": source_address,
            "source_port": _int_text(_show(tcp, "tcp.srcport")),
            "destination_address": destination_address,
            "destination_port": _int_text(_show(tcp, "tcp.dstport")),
            "stream_id": stream_id,
            "reassembly": reassembly,
            "reassembled_length": reassembled_length,
            "segment_count": segment_count,
            "encrypted": False,
        }
    if udp is not None:
        return {
            "protocol": "UDP",
            "source_address": source_address,
            "source_port": _int_text(_show(udp, "udp.srcport")),
            "destination_address": destination_address,
            "destination_port": _int_text(_show(udp, "udp.dstport")),
            "stream_id": None,
            "reassembly": "NOT_APPLICABLE",
            "reassembled_length": None,
            "segment_count": None,
            "encrypted": False,
        }
    return {
        "protocol": "UNKNOWN",
        "source_address": source_address,
        "source_port": None,
        "destination_address": destination_address,
        "destination_port": None,
        "stream_id": None,
        "reassembly": "UNKNOWN",
        "reassembled_length": None,
        "segment_count": None,
        "encrypted": False,
    }


def _frame_truncated(packet: ElementTree.Element) -> bool:
    captured = _int_text(_packet_field(packet, "frame.cap_len"))
    original = _int_text(_packet_field(packet, "frame.len"))
    return captured is not None and original is not None and captured < original


def _tag_metadata(nodes: list[ElementTree.Element], tag_name: str) -> dict[str, Any]:
    tag: str | None = None
    for node in nodes:
        child = _field(node, tag_name)
        if child is not None:
            tag = child.get("show")
            break
    return {
        "count": len(nodes),
        "tag_present": bool(tag),
        "tag_length": len(tag) if tag else None,
    }


def _tag_from_values(count: int, tag: Any) -> dict[str, Any]:
    value = _text(tag)
    return {
        "count": count,
        "tag_present": bool(value),
        "tag_length": len(value) if value else None,
    }


def _via_metadata(nodes: list[ElementTree.Element]) -> dict[str, Any]:
    branch: str | None = None
    transports: set[str] = set()
    for node in nodes:
        child = _field(node, "sip.Via.branch")
        if branch is None and child is not None:
            branch = child.get("show")
        transport = _show(node, "sip.Via.transport")
        if transport:
            normalized = transport.upper()
            transports.add(normalized if normalized in KNOWN_VIA_TRANSPORTS else "OTHER")
    return {
        "count": len(nodes),
        "branch_present": bool(branch),
        "branch_length": len(branch) if branch else None,
        "transports": sorted(transports),
    }


def _via_from_values(entries: list[dict[str, Any]]) -> dict[str, Any]:
    branch: str | None = None
    transports: set[str] = set()
    for entry in entries:
        value = _text(entry.get("branch"))
        if branch is None and value:
            branch = value
        transport = _text(entry.get("transport"))
        if transport:
            normalized = transport.upper()
            transports.add(normalized if normalized in KNOWN_VIA_TRANSPORTS else "OTHER")
    return {
        "count": len(entries),
        "branch_present": bool(branch),
        "branch_length": len(branch) if branch else None,
        "transports": sorted(transports),
    }


def _safe_media_type(value: str | None) -> str | None:
    if not value:
        return None
    base = value.split(";", 1)[0].strip().lower()
    if len(base) > MAX_CONTENT_TYPE_LENGTH or not MEDIA_TYPE_PATTERN.fullmatch(base):
        return None
    return base


def _safe_reason_phrase(status_code: int | None, raw: str | None) -> str | None:
    if status_code is None or not raw:
        return None
    expected = STANDARD_REASON_PHRASES.get(status_code)
    if expected is None:
        return None
    text = raw.strip()
    if len(text) > MAX_REASON_PHRASE_LENGTH:
        return None
    return expected if text.casefold() == expected.casefold() else None


# ---------------------------------------------------------------------------
# Event construction
# ---------------------------------------------------------------------------


def _relative_time(value: str | None) -> str | None:
    text = _text(value)
    if text is None:
        return None
    match = re.fullmatch(r"([0-9]+)(?:\.([0-9]+))?", text)
    if match is None:
        return None
    fraction = (match.group(2) or "").ljust(9, "0")[:9]
    return f"{int(match.group(1))}.{fraction}"


def _timestamp(epoch: str | None) -> str | None:
    if not epoch:
        return None
    text = str(epoch).strip()
    if not text:
        return None
    whole, _, fraction = text.partition(".")
    try:
        seconds = int(whole)
    except ValueError:
        return None
    micro = 0
    if fraction:
        digits = re.sub(r"[^0-9]", "", fraction)
        micro = int((digits + "000000")[:6]) if digits else 0
    try:
        moment = datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=micro)
    except (OverflowError, OSError, ValueError):
        return None
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{micro:06d}Z"


def _build_event(
    *,
    capture: str,
    frame: int,
    frame_time_epoch: str | None,
    frame_time_relative: str | None,
    occurrence: int,
    transport: dict[str, Any],
    headers: dict[str, Any],
    integrity_findings: list[str],
    capture_truncated: bool,
) -> dict[str, Any]:
    raw_method = _text(headers.get("method"))
    method_valid = bool(raw_method and METHOD_PATTERN.fullmatch(raw_method))
    method = raw_method if method_valid else None
    if raw_method and not method_valid:
        integrity_findings.append("INVALID_METHOD")
    method_scope = (
        "CORE" if method in CORE_METHODS
        else "EXTENSION" if method is not None
        else None
    )
    raw_status = headers.get("status_code")
    status_code = _int_text(raw_status)
    status_present = bool(
        headers.get("status_present")
        or headers.get("status_line_present")
        or raw_status is not None
    )
    status_code_valid = True
    if status_present:
        status_code_valid = status_code is not None and 100 <= status_code <= 699
        if not status_code_valid:
            integrity_findings.append("INVALID_STATUS_CODE")
            status_code = None

    request_uri = _text(headers.get("request_uri"))
    call_id = _text(headers.get("call_id"))
    cseq_sequence = _int_text(headers.get("cseq_sequence"))
    cseq_method = _text(headers.get("cseq_method"))
    cseq_method = cseq_method if cseq_method and METHOD_PATTERN.fullmatch(cseq_method) else None
    cseq_present = bool(
        headers.get("cseq_present")
        or cseq_sequence is not None
        or cseq_method is not None
    )
    if headers.get("cseq_sequence") is not None and cseq_sequence is None:
        integrity_findings.append("INVALID_CSEQ")

    reason_raw = _text(headers.get("reason_phrase"))
    reason_phrase = _safe_reason_phrase(status_code, reason_raw) if status_code is not None else None
    reason_present = bool(reason_raw)

    content_type = _safe_media_type(_text(headers.get("content_type")))
    raw_content_length = headers.get("content_length")
    content_length = _int_text(raw_content_length)
    if raw_content_length is not None and content_length is None:
        integrity_findings.append("INVALID_CONTENT_LENGTH")
    if content_length is not None and content_length < 0:
        content_length = None
        integrity_findings.append("INVALID_CONTENT_LENGTH")
    max_forwards = _int_text(headers.get("max_forwards"))
    if max_forwards is not None and not 0 <= max_forwards <= 255:
        max_forwards = None

    via = headers.get("via")
    if not isinstance(via, dict):
        via = {
            "count": 0,
            "branch_present": False,
            "branch_length": None,
            "transports": [],
        }
    from_meta = headers.get("from")
    if not isinstance(from_meta, dict):
        from_meta = {"count": 0, "tag_present": False, "tag_length": None}
    to_meta = headers.get("to")
    if not isinstance(to_meta, dict):
        to_meta = {"count": 0, "tag_present": False, "tag_length": None}

    body_length = _int_text(headers.get("body_length"))
    if body_length is not None and body_length < 0:
        body_length = None
    body_present = bool(body_length and body_length > 0)

    if method is not None:
        message_type = "REQUEST"
    elif status_code is not None or headers.get("status_present") or headers.get("status_line_present"):
        message_type = "RESPONSE"
    else:
        message_type = "UNKNOWN"

    findings: list[str] = []
    for finding in integrity_findings:
        if finding not in findings:
            findings.append(finding)
    if method is None and message_type == "REQUEST":
        findings.append("MISSING_METHOD")
    if message_type == "RESPONSE" and status_code is None:
        findings.append("MISSING_STATUS_CODE")
    if message_type == "UNKNOWN":
        findings.append("MISSING_START_LINE")
    if not cseq_present:
        findings.append("MISSING_CSEQ")
    if not call_id:
        findings.append("MISSING_CALL_ID")
    if capture_truncated:
        findings.append("CAPTURE_TRUNCATED")
    findings = list(dict.fromkeys(findings))[:MAX_INTEGRITY_FINDINGS]

    malformed_findings = {
        "HEADER_NOT_TERMINATED",
        "HEADER_NO_COLON",
        "INVALID_STATUS_CODE",
        "INVALID_CSEQ",
        "INVALID_METHOD",
        "MISSING_START_LINE",
        "MISSING_STATUS_CODE",
        "INVALID_CONTENT_LENGTH",
    }
    if capture_truncated:
        completeness = "TRUNCATED"
    elif message_type == "UNKNOWN" or malformed_findings & set(findings):
        completeness = "MALFORMED"
    elif message_type == "RESPONSE" and status_code is None:
        completeness = "MALFORMED"
    elif not cseq_present or not call_id:
        completeness = "INCOMPLETE"
    else:
        completeness = "COMPLETE"

    extraction_status = {
        "COMPLETE": "OBSERVED",
        "INCOMPLETE": "PARTIAL",
        "MALFORMED": "MALFORMED",
        "TRUNCATED": "MALFORMED",
        "UNKNOWN": "MALFORMED",
    }[completeness]

    limitations: list[str] = [
        "SIP headers that may carry subscriber identities, URIs, dialog tags or credentials are published as presence and bounded length metadata only",
    ]
    if message_type == "REQUEST":
        limitations.append(
            "an unanswered request is a valid observed message; no transaction, timeout or IMS procedure outcome is inferred"
        )
    elif message_type == "RESPONSE":
        limitations.append(
            "a response without its request may be a mid-capture observation; no transaction or IMS procedure outcome is inferred"
        )
    if method_scope == "EXTENSION":
        limitations.append(
            "the request method is an extension method; no IMS procedure semantics are attached"
        )
    if status_code is not None:
        limitations.append(
            "a SIP status code is protocol-local evidence; it does not prove IMS registration or call success"
        )
    if transport.get("protocol") == "TCP" and transport.get("reassembly") != "REASSEMBLED":
        limitations.append(
            "TCP continuity is not independently reconstructed; the decoder-delivered SIP message is the observation boundary"
        )
    if body_present:
        limitations.append(
            "a message body is present but is never published; SDP and other body semantics are outside this phase"
        )
    if any(field in findings for field in ("MISSING_CSEQ", "MISSING_METHOD", "MISSING_STATUS_CODE")):
        limitations.append(
            "a mandatory SIP start-line or CSeq observation is missing; the message is retained as incomplete evidence"
        )
    limitations = list(dict.fromkeys(limitations))[:MAX_LIMITATIONS]

    return {
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "capture_file": capture,
        "frame_number": frame,
        "frame_time_epoch": frame_time_epoch,
        "frame_time_relative": _relative_time(frame_time_relative),
        "timestamp": _timestamp(frame_time_epoch),
        "message_occurrence": occurrence,
        "source_reference": f"sip-event:{capture}:{frame}.{occurrence}",
        "message_type": message_type,
        "method": method,
        "method_scope": method_scope,
        "status_code": status_code,
        "status_code_valid": status_code_valid,
        "reason_phrase": reason_phrase,
        "reason_phrase_present": reason_present,
        "reason_phrase_length": len(reason_raw) if reason_raw else None,
        "request_uri_present": bool(request_uri),
        "request_uri_length": len(request_uri) if request_uri else None,
        "headers": {
            "call_id": {
                "present": bool(call_id),
                "length": len(call_id) if call_id else None,
                "count": int(headers.get("call_id_count") or (1 if call_id else 0)),
            },
            "cseq": {
                "present": cseq_present,
                "sequence": cseq_sequence,
                "method": cseq_method,
                "count": int(headers.get("cseq_count") or (1 if cseq_present else 0)),
            },
            "via": via,
            "from": from_meta,
            "to": to_meta,
            "max_forwards": max_forwards,
            "content_type": content_type,
            "content_length": content_length,
            "route": {"count": int(headers.get("route_count") or 0)},
            "record_route": {"count": int(headers.get("record_route_count") or 0)},
            "contact": {"count": int(headers.get("contact_count") or 0)},
            "authorization": {"count": int(headers.get("authorization_count") or 0)},
            "proxy_authorization": {"count": int(headers.get("proxy_authorization_count") or 0)},
            "www_authenticate": {"count": int(headers.get("www_authenticate_count") or 0)},
            "proxy_authenticate": {"count": int(headers.get("proxy_authenticate_count") or 0)},
            "p_asserted_identity": {"count": int(headers.get("p_asserted_identity_count") or 0)},
            "p_preferred_identity": {"count": int(headers.get("p_preferred_identity_count") or 0)},
        },
        "transport": transport,
        "body_present": body_present,
        "body_length": body_length,
        "integrity_findings": findings,
        "message_completeness": completeness,
        "extraction_status": extraction_status,
        "evidence_class": "OBSERVED",
        "limitations": limitations,
    }


def _pdml_headers(proto: ElementTree.Element) -> dict[str, Any]:
    method = _node_show(_descendant_field(proto, "sip.Method"))
    status_code = _int_text(_node_show(_descendant_field(proto, "sip.Status-Code")))
    status_line = _node_show(_descendant_field(proto, "sip.Status-Line"))
    status_line_present = status_line is not None
    reason_phrase: str | None = None
    if status_line:
        match = STATUS_LINE_PATTERN.match(status_line.strip())
        if match:
            status_code = int(match.group(1))
            reason_phrase = match.group(2)
    request_uri = _node_show(_descendant_field(proto, "sip.r-uri"))
    call_ids = _descendant_fields(proto, "sip.Call-ID")
    cseq_nodes = _descendant_fields(proto, "sip.CSeq")
    cseq_sequence = None
    cseq_method = None
    if cseq_nodes:
        cseq_sequence = _int_text(_show(cseq_nodes[0], "sip.CSeq.seq"))
        cseq_method = _show(cseq_nodes[0], "sip.CSeq.method")
    else:
        cseq_sequence = _int_text(_node_show(_descendant_field(proto, "sip.CSeq.seq")))
        cseq_method = _node_show(_descendant_field(proto, "sip.CSeq.method"))
    via_nodes = _descendant_fields(proto, "sip.Via")
    from_nodes = _descendant_fields(proto, "sip.From")
    to_nodes = _descendant_fields(proto, "sip.To")
    content_type = _node_show(_descendant_field(proto, "sip.Content-Type"))
    content_length = _int_text(_node_show(_descendant_field(proto, "sip.Content-Length")))
    max_forwards = _int_text(_node_show(_descendant_field(proto, "sip.Max-Forwards")))
    body = _descendant_field(proto, "sip.msg_body")
    body_length = _int_text(body.get("size")) if body is not None else 0
    headers: dict[str, Any] = {
        "method": method,
        "status_code": status_code,
        "status_present": status_code is not None,
        "status_line_present": status_line_present,
        "reason_phrase": reason_phrase,
        "request_uri": request_uri,
        "call_id": _node_show(call_ids[0]) if call_ids else None,
        "call_id_count": len(call_ids),
        "cseq_sequence": cseq_sequence,
        "cseq_method": cseq_method,
        "cseq_present": bool(cseq_nodes or cseq_sequence is not None or cseq_method is not None),
        "cseq_count": len(cseq_nodes),
        "via": _via_metadata(via_nodes),
        "from": _tag_metadata(from_nodes, "sip.from.tag"),
        "to": _tag_metadata(to_nodes, "sip.to.tag"),
        "max_forwards": max_forwards,
        "content_type": content_type,
        "content_length": content_length,
        "body_length": body_length,
        "route_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["route"])),
        "record_route_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["record_route"])),
        "contact_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["contact"])),
        "authorization_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["authorization"])),
        "proxy_authorization_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["proxy_authorization"])),
        "www_authenticate_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["www_authenticate"])),
        "proxy_authenticate_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["proxy_authenticate"])),
        "p_asserted_identity_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["p_asserted_identity"])),
        "p_preferred_identity_count": len(_descendant_fields(proto, HEADER_COUNT_FIELDS["p_preferred_identity"])),
    }
    return headers


def _pdml_integrity(proto: ElementTree.Element) -> list[str]:
    findings: list[str] = []
    for name, label in INTEGRITY_MARKERS.items():
        if _descendant_field(proto, name) is not None:
            findings.append(label)
    return findings


def parse_pdml(text: str, capture_file: str | None = None) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise InputError(f"PDML is not valid XML: {exc}") from exc
    capture = capture_file or Path(root.get("capture_file") or "capture.pcap").name
    events: list[dict[str, Any]] = []
    for packet in root.iter("packet"):
        frame = _int_text(_packet_field(packet, "frame.number"))
        sip_protos = _protos(packet, "sip")
        if not sip_protos:
            continue
        if frame is None:
            raise InputError("a SIP observation has no source frame number")
        frame_time_epoch = _text(_packet_field(packet, "frame.time_epoch"))
        frame_time_relative = _text(_packet_field(packet, "frame.time_relative"))
        transport = _transport(packet)
        truncated = _frame_truncated(packet)
        for occurrence, proto in enumerate(sip_protos, start=1):
            headers = _pdml_headers(proto)
            events.append(
                _build_event(
                    capture=capture,
                    frame=frame,
                    frame_time_epoch=frame_time_epoch,
                    frame_time_relative=frame_time_relative,
                    occurrence=occurrence,
                    transport=dict(transport),
                    headers=headers,
                    integrity_findings=_pdml_integrity(proto),
                    capture_truncated=truncated,
                )
            )
    return _ordered(events)


def _ordered(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(events, key=lambda event: (event["capture_file"], event["frame_number"], event["message_occurrence"]))


# ---------------------------------------------------------------------------
# Sanitized dissector-record input
# ---------------------------------------------------------------------------


_RECORD_KEYS = {
    "capture_file",
    "frame_number",
    "frame_time_epoch",
    "frame_time_relative",
    "message_occurrence",
    "transport",
    "headers",
    "integrity_findings",
    "capture_truncated",
}
_TRANSPORT_KEYS = {
    "protocol",
    "source_address",
    "source_port",
    "destination_address",
    "destination_port",
    "stream_id",
    "reassembly",
    "reassembled_length",
    "segment_count",
}
_HEADER_KEYS = {
    "method",
    "status_code",
    "reason_phrase",
    "request_uri",
    "call_id",
    "cseq_sequence",
    "cseq_method",
    "via",
    "from",
    "to",
    "max_forwards",
    "content_type",
    "content_length",
    "body_length",
    "route_count",
    "record_route_count",
    "contact_count",
    "authorization_count",
    "proxy_authorization_count",
    "www_authenticate_count",
    "proxy_authenticate_count",
    "p_asserted_identity_count",
    "p_preferred_identity_count",
}
_REASSEMBLY_STATUSES = {"NOT_APPLICABLE", "SINGLE_SEGMENT", "REASSEMBLED", "INCOMPLETE", "UNKNOWN"}
_INTEGRITY_VALUES = set(INTEGRITY_MARKERS.values()) | {
    "INVALID_CSEQ",
    "INVALID_METHOD",
    "MISSING_METHOD",
    "MISSING_STATUS_CODE",
    "MISSING_START_LINE",
    "MISSING_CSEQ",
    "CAPTURE_TRUNCATED",
}


def _record_count(entry: Any, label: str) -> int:
    if not isinstance(entry, dict):
        return 0
    count = _int_text(entry.get("count", 1))
    if count is None or count < 0:
        raise InputError(f"{label}.count must be a non-negative integer")
    return count


def _reject_unknown(record: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(record) - allowed)
    if unknown:
        raise InputError(f"{label} contains unsupported field(s): {', '.join(unknown)}")


def _jsonl_transport(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InputError("each record needs a transport object")
    _reject_unknown(raw, _TRANSPORT_KEYS, "transport")
    protocol = raw.get("protocol")
    if protocol not in {"UDP", "TCP"}:
        raise InputError(
            "transport.protocol must be UDP or TCP; encrypted or unsupported transports cannot carry plaintext SIP events"
        )
    source_port = _int_text(raw.get("source_port"))
    destination_port = _int_text(raw.get("destination_port"))
    for port in (source_port, destination_port):
        if port is not None and not 0 <= port <= 65535:
            raise InputError("transport ports must be between 0 and 65535")
    stream_id = _int_text(raw.get("stream_id"))
    if stream_id is not None and stream_id < 0:
        raise InputError("transport.stream_id must be a non-negative integer or null")
    reassembly = raw.get("reassembly", "NOT_APPLICABLE" if protocol == "UDP" else "UNKNOWN")
    if reassembly not in _REASSEMBLY_STATUSES:
        raise InputError("transport.reassembly is not an accepted status")
    if protocol == "UDP" and reassembly != "NOT_APPLICABLE":
        raise InputError("UDP records must declare NOT_APPLICABLE reassembly")
    reassembled_length = _int_text(raw.get("reassembled_length"))
    segment_count = _int_text(raw.get("segment_count"))
    for count in (reassembled_length, segment_count):
        if count is not None and count < 0:
            raise InputError("transport reassembly counts must be non-negative or null")
    return {
        "protocol": protocol,
        "source_address": _text(raw.get("source_address")),
        "source_port": source_port,
        "destination_address": _text(raw.get("destination_address")),
        "destination_port": destination_port,
        "stream_id": stream_id,
        "reassembly": reassembly,
        "reassembled_length": reassembled_length,
        "segment_count": segment_count,
        "encrypted": False,
    }


def _jsonl_headers(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise InputError("each record needs a headers object")
    _reject_unknown(raw, _HEADER_KEYS, "headers")
    via = raw.get("via") or []
    if not isinstance(via, list):
        raise InputError("headers.via must be an array when present")
    normalized_via: list[dict[str, Any]] = []
    for item in via:
        if not isinstance(item, dict):
            raise InputError("each headers.via entry must be an object")
        _reject_unknown(item, {"branch", "transport"}, "headers.via entry")
        normalized_via.append(
            {
                "branch": _text(item.get("branch")),
                "transport": _text(item.get("transport")),
            }
        )
    from_entry = raw.get("from")
    to_entry = raw.get("to")
    for label, entry in (("headers.from", from_entry), ("headers.to", to_entry)):
        if entry is not None and not isinstance(entry, dict):
            raise InputError(f"{label} must be an object when present")
        if isinstance(entry, dict):
            _reject_unknown(entry, {"count", "tag"}, label)
    from_count = _record_count(from_entry, "headers.from")
    to_count = _record_count(to_entry, "headers.to")
    count_values = {
        "route_count": raw.get("route_count", 0),
        "record_route_count": raw.get("record_route_count", 0),
        "contact_count": raw.get("contact_count", 0),
        "authorization_count": raw.get("authorization_count", 0),
        "proxy_authorization_count": raw.get("proxy_authorization_count", 0),
        "www_authenticate_count": raw.get("www_authenticate_count", 0),
        "proxy_authenticate_count": raw.get("proxy_authenticate_count", 0),
        "p_asserted_identity_count": raw.get("p_asserted_identity_count", 0),
        "p_preferred_identity_count": raw.get("p_preferred_identity_count", 0),
    }
    for label, value in count_values.items():
        count = _int_text(value)
        if count is None or count < 0:
            raise InputError(f"headers.{label} must be a non-negative integer")
        count_values[label] = count
    return {
        "method": raw.get("method"),
        "status_code": raw.get("status_code"),
        "status_present": raw.get("status_code") is not None,
        "reason_phrase": raw.get("reason_phrase"),
        "request_uri": raw.get("request_uri"),
        "call_id": raw.get("call_id"),
        "cseq_sequence": raw.get("cseq_sequence"),
        "cseq_method": raw.get("cseq_method"),
        "cseq_present": raw.get("cseq_sequence") is not None or raw.get("cseq_method") is not None,
        "cseq_count": 1 if raw.get("cseq_sequence") is not None or raw.get("cseq_method") is not None else 0,
        "via": _via_from_values(normalized_via),
        "from": _tag_from_values(from_count, from_entry.get("tag") if isinstance(from_entry, dict) else None),
        "to": _tag_from_values(to_count, to_entry.get("tag") if isinstance(to_entry, dict) else None),
        "max_forwards": raw.get("max_forwards"),
        "content_type": raw.get("content_type"),
        "content_length": raw.get("content_length"),
        "body_length": raw.get("body_length", 0),
        **count_values,
    }


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InputError("each JSONL record must be an object")
    _reject_unknown(record, _RECORD_KEYS, "record")
    frame = record.get("frame_number")
    if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
        raise InputError("frame_number must be a positive integer")
    occurrence = record.get("message_occurrence", 1)
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 1:
        raise InputError("message_occurrence must be a positive integer")
    capture = _text(record.get("capture_file")) or "capture.pcap"
    epoch = _text(record.get("frame_time_epoch"))
    relative = _text(record.get("frame_time_relative"))
    if relative is not None and _relative_time(relative) is None:
        raise InputError("frame_time_relative must be a non-negative seconds value or null")
    transport = _jsonl_transport(record.get("transport"))
    headers = _jsonl_headers(record.get("headers"))
    findings_raw = record.get("integrity_findings") or []
    if not isinstance(findings_raw, list):
        raise InputError("integrity_findings must be an array")
    findings: list[str] = []
    for finding in findings_raw:
        if not isinstance(finding, str) or finding not in _INTEGRITY_VALUES:
            raise InputError("integrity_findings contains an unsupported value")
        findings.append(finding)
    truncated = record.get("capture_truncated", False)
    if not isinstance(truncated, bool):
        raise InputError("capture_truncated must be a boolean")
    return _build_event(
        capture=capture,
        frame=frame,
        frame_time_epoch=epoch,
        frame_time_relative=relative,
        occurrence=occurrence,
        transport=transport,
        headers=headers,
        integrity_findings=findings,
        capture_truncated=truncated,
    )


def records_from_jsonl(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(record, dict):
                raise InputError(f"line {line_number} is not a JSON object")
            events.append(normalize_record(record))
    return _ordered(events)


# ---------------------------------------------------------------------------
# TShark boundary
# ---------------------------------------------------------------------------


def _validate_capture_input(path: Path) -> None:
    if not path.is_file():
        raise InputError(f"input does not exist: {path}")
    if path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise InputError("capture input must be a .pcap, .pcapng or .cap file")
    try:
        head = path.read_bytes()[:4]
    except OSError as exc:
        raise InputError(f"capture input could not be read: {exc}") from exc
    if head not in CAPTURE_MAGIC:
        raise InputError("input is not a recognizable PCAP or PCAPNG capture")


def tshark_version(tshark_bin: str | None = None) -> str:
    executable = tshark_bin or shutil.which("tshark") or "tshark"
    try:
        completed = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc
    except OSError as exc:
        raise ToolUnavailable(f"tshark could not start: {exc}") from exc
    if completed.returncode != 0:
        raise TsharkError(_bounded_diagnostic(completed.stderr) or "tshark --version failed")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def _bounded_diagnostic(text: str | None) -> str:
    if not text:
        return ""
    return " ".join(text.strip().splitlines()[:1])[:240]


def pdml_for_capture(capture: Path, tshark_bin: str | None = None) -> str:
    _validate_capture_input(capture)
    executable = tshark_bin or shutil.which("tshark") or "tshark"
    try:
        completed = subprocess.run(
            [executable, "-r", str(capture), "-Y", "sip || tcp.segments", "-T", "pdml"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc
    except OSError as exc:
        raise ToolUnavailable(f"tshark could not start: {exc}") from exc
    if completed.returncode != 0:
        raise TsharkError(_bounded_diagnostic(completed.stderr) or "tshark failed")
    return completed.stdout


def events_for_input(path: Path, input_format: str = "auto") -> tuple[list[dict[str, Any]], str | None]:
    if not path.is_file():
        raise InputError(f"input does not exist: {path}")
    fmt = input_format
    if fmt == "auto":
        suffix = path.suffix.lower()
        if suffix in {".pcap", ".pcapng", ".cap"}:
            fmt = "capture"
        elif suffix in {".pdml", ".xml"}:
            fmt = "pdml"
        elif suffix in {".jsonl", ".json"}:
            fmt = "fields-jsonl"
        else:
            raise InputError(f"cannot infer input format from {path.suffix}")
    if fmt == "capture":
        _validate_capture_input(path)
        decoder = tshark_version()
        return parse_pdml(pdml_for_capture(path), path.name), decoder
    if fmt == "pdml":
        return parse_pdml(path.read_text(encoding="utf-8"), path.name), None
    if fmt == "fields-jsonl":
        return records_from_jsonl(path), None
    raise InputError(f"unsupported input format: {fmt}")


# ---------------------------------------------------------------------------
# Trace-event projection
# ---------------------------------------------------------------------------


def project_trace_event(event: dict[str, Any]) -> dict[str, Any]:
    message_type = (
        event["method"]
        if event["message_type"] == "REQUEST"
        else f"status-{event['status_code']}" if event["status_code"] is not None
        else None
    )
    projected: dict[str, Any] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL,
        "interface": None,
        "procedure": None,
        "message_type": message_type,
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "OBSERVED",
            "source": f"sip-event:{event['capture_file']}#frame={event['frame_number']}.{event['message_occurrence']}",
        },
        "source": {
            "address": event["transport"].get("source_address"),
            "port": event["transport"].get("source_port"),
            "network_function": None,
        },
        "destination": {
            "address": event["transport"].get("destination_address"),
            "port": event["transport"].get("destination_port"),
            "network_function": None,
        },
    }
    if event["status_code"] is not None:
        projected["result"] = {
            "status": None,
            "cause": f"sip:{event['status_code']}",
            "code": event["status_code"],
        }
    return projected