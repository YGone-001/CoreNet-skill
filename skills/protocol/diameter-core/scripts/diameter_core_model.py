#!/usr/bin/env python3
"""Bounded Diameter base-protocol event model.

The model consumes a verified TShark PDML dissection or sanitized dissector
records. It never decodes packet bytes itself and never infers application or
telecom procedure semantics.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree

PROTOCOL = "Diameter"

EXIT_MALFORMED_INPUT = 2
EXIT_NO_EVENTS = 3
EXIT_TOOL_UNAVAILABLE = 4
EXIT_TSHARK_FAILURE = 5
EXIT_OUTPUT_FAILURE = 6

MAX_AVPS = 128
MAX_AVP_DEPTH = 4

BASE_COMMANDS = {
    257: "Capabilities-Exchange",
    258: "Re-Auth",
    271: "Accounting",
    274: "Abort-Session",
    275: "Session-Termination",
    280: "Device-Watchdog",
    282: "Disconnect-Peer",
}

BASE_RESULT_NAMES = {
    1001: "DIAMETER_MULTI_ROUND_AUTH",
    2001: "DIAMETER_SUCCESS",
    2002: "DIAMETER_LIMITED_SUCCESS",
    3001: "DIAMETER_COMMAND_UNSUPPORTED",
    3002: "DIAMETER_UNABLE_TO_DELIVER",
    3003: "DIAMETER_REALM_NOT_SERVED",
    3004: "DIAMETER_TOO_BUSY",
    3005: "DIAMETER_LOOP_DETECTED",
    3006: "DIAMETER_REDIRECT_INDICATION",
    3007: "DIAMETER_APPLICATION_UNSUPPORTED",
    3008: "DIAMETER_INVALID_HDR_BITS",
    3009: "DIAMETER_INVALID_AVP_BITS",
    3010: "DIAMETER_UNKNOWN_PEER",
    4001: "DIAMETER_AUTHENTICATION_REJECTED",
    4002: "DIAMETER_OUT_OF_SPACE",
    4003: "DIAMETER_ELECTION_LOST",
    5001: "DIAMETER_AVP_UNSUPPORTED",
    5002: "DIAMETER_UNKNOWN_SESSION_ID",
    5003: "DIAMETER_AUTHORIZATION_REJECTED",
    5004: "DIAMETER_INVALID_AVP_VALUE",
    5005: "DIAMETER_MISSING_AVP",
    5006: "DIAMETER_RESOURCES_EXCEEDED",
    5007: "DIAMETER_CONTRADICTING_AVPS",
    5008: "DIAMETER_AVP_NOT_ALLOWED",
    5009: "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES",
    5010: "DIAMETER_NO_COMMON_APPLICATION",
    5011: "DIAMETER_UNSUPPORTED_VERSION",
    5012: "DIAMETER_UNABLE_TO_COMPLY",
    5013: "DIAMETER_INVALID_BIT_IN_HEADER",
    5014: "DIAMETER_INVALID_AVP_LENGTH",
    5015: "DIAMETER_INVALID_MESSAGE_LENGTH",
    5016: "DIAMETER_INVALID_AVP_BIT_COMBO",
    5017: "DIAMETER_NO_COMMON_SECURITY",
}

AVP_NAMES = {
    1: "User-Name",
    260: "Vendor-Specific-Application-Id",
    263: "Session-Id",
    264: "Origin-Host",
    265: "Supported-Vendor-Id",
    266: "Vendor-Id",
    268: "Result-Code",
    277: "Auth-Session-State",
    278: "Origin-State-Id",
    279: "Failed-AVP",
    283: "Destination-Realm",
    284: "Proxy-Info",
    293: "Destination-Host",
    296: "Origin-Realm",
    297: "Experimental-Result",
    298: "Experimental-Result-Code",
    443: "Subscription-Id",
    444: "Subscription-Id-Data",
    1408: "Requested-EUTRAN-Authentication-Info",
    1409: "Requested-UTRAN-GERAN-Authentication-Info",
    1413: "E-UTRAN-Authentication-Info",
    1414: "UTRAN-GERAN-Authentication-Info",
}

GROUPED_AVP_CODES = {260, 279, 284, 297, 443, 1408, 1409, 1413, 1414}

SENSITIVE_AVP_CODES = {1, 2, 3, 27, 28, 29, 79, 102, 443, 444, 1408, 1409, 1413, 1414}
SENSITIVE_NAME_MARKERS = (
    "user-name",
    "user-password",
    "chap-password",
    "subscription-id",
    "authentication-info",
    "authentication-vector",
    "eap-payload",
    "eap-key-name",
    "rand",
    "autn",
    "xres",
    "kasme",
)

SAFE_VALUE_CODES = {264, 265, 266, 268, 277, 278, 283, 293, 296, 298}
INTEGER_VALUE_CODES = {266, 268, 277, 278, 298}

SENSITIVE_VALUE_PATTERN = re.compile(r"^(?:[0-9]{10,16}|[0-9a-fA-F]{16,})$")


class InputError(Exception):
    pass


class TsharkError(Exception):
    pass


class ToolUnavailable(Exception):
    pass


def _field(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.findall("field"):
        if child.get("name") == name:
            return child
    return None


def _show(node: ElementTree.Element, name: str) -> str | None:
    child = _field(node, name)
    return None if child is None else child.get("show")


def _int_text(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _bool_text(value: str | None) -> bool:
    return value == "True"


def _proto(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.findall("proto"):
        if child.get("name") == name:
            return child
    return None


def _diameter_protos(packet: ElementTree.Element) -> list[ElementTree.Element]:
    return [child for child in packet.findall("proto") if child.get("name") == "diameter"]


def _packet_field(packet: ElementTree.Element, name: str) -> str | None:
    for proto in packet.findall("proto"):
        for field in proto.findall("field"):
            if field.get("name") == name:
                return field.get("show")
    return None


def _addresses(packet: ElementTree.Element) -> tuple[str | None, str | None]:
    for prefix in ("ip", "ipv6"):
        src = _packet_field(packet, f"{prefix}.src")
        dst = _packet_field(packet, f"{prefix}.dst")
        if src and dst:
            return src, dst
    return None, None


def _transport(packet: ElementTree.Element) -> dict[str, Any]:
    sctp = _proto(packet, "sctp")
    tcp = _proto(packet, "tcp")
    source_address, destination_address = _addresses(packet)
    if sctp is not None:
        tag = _show(sctp, "sctp.verification_tag")
        tag_value = _int_text(tag)
        tag_text = None if tag_value is None else f"0x{tag_value:08x}"
        return {
            "protocol": "SCTP",
            "source_address": source_address,
            "source_port": _int_text(_show(sctp, "sctp.srcport")),
            "destination_address": destination_address,
            "destination_port": _int_text(_show(sctp, "sctp.dstport")),
            "verification_tag": tag_text,
            "stream_id": None,
        }
    if tcp is not None:
        return {
            "protocol": "TCP",
            "source_address": source_address,
            "source_port": _int_text(_show(tcp, "tcp.srcport")),
            "destination_address": destination_address,
            "destination_port": _int_text(_show(tcp, "tcp.dstport")),
            "verification_tag": None,
            "stream_id": _int_text(_show(tcp, "tcp.stream")),
        }
    return {
        "protocol": "UNKNOWN",
        "source_address": source_address,
        "source_port": None,
        "destination_address": destination_address,
        "destination_port": None,
        "verification_tag": None,
        "stream_id": None,
    }


def _endpoint(transport: dict[str, Any], side: str) -> str:
    address = transport.get(f"{side}_address")
    port = transport.get(f"{side}_port")
    return f"{address}:{port}" if address is not None and port is not None else "unknown"


def _association_reference(capture: str, transport: dict[str, Any]) -> str:
    protocol = transport.get("protocol")
    left = _endpoint(transport, "source")
    right = _endpoint(transport, "destination")
    endpoints = "|".join(sorted((left, right)))
    if transport.get("protocol") == "TCP" and transport.get("stream_id") is not None:
        key = f"tcp-stream-{transport['stream_id']}"
    else:
        key = f"{protocol}-{endpoints}"
    return f"diameter-assoc:{capture}:{key}"


def _sensitive_name(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SENSITIVE_NAME_MARKERS)


def _count_avps(node: ElementTree.Element) -> int:
    total = 0
    for child in node.findall("field"):
        if child.get("name") == "diameter.avp":
            total += 1 + _count_avps(child)
    return total


def _avp_value(code: int, name: str | None, semantic: ElementTree.Element | None) -> tuple[Any, str]:
    if code in SENSITIVE_AVP_CODES or (name and _sensitive_name(name)):
        return None, "SENSITIVE_REDACTED"
    if code in GROUPED_AVP_CODES:
        return None, "GROUPED"
    if code not in SAFE_VALUE_CODES:
        return None, "OPAQUE"
    if semantic is None:
        return None, "OPAQUE"
    raw = semantic.get("show")
    if raw is None or raw == "":
        return None, "OPAQUE"
    if code in INTEGER_VALUE_CODES:
        number = _int_text(raw)
        return (number, "INTEGER") if number is not None else (None, "OPAQUE")
    if SENSITIVE_VALUE_PATTERN.match(raw):
        return None, "SENSITIVE_REDACTED"
    return raw, "STRING"


def _parse_avp(
    node: ElementTree.Element,
    *,
    capture: str,
    frame: int,
    occurrence: int,
    path: str,
    depth: int,
    budget: list[int],
) -> dict[str, Any] | None:
    if budget[0] <= 0:
        return None
    budget[0] -= 1
    code = _int_text(_show(node, "diameter.avp.code"))
    flags = _int_text(_show(node, "diameter.avp.flags"))
    length = _int_text(_show(node, "diameter.avp.len"))
    vendor_id = _int_text(_show(node, "diameter.avp.vendorId"))
    semantic = None
    for child in node.findall("field"):
        name = child.get("name") or ""
        if name == "diameter.avp" or name.startswith("diameter.avp."):
            continue
        semantic = child
        break
    decoded_name = None
    if semantic is not None:
        prefix = "diameter."
        decoded_name = semantic.get("name")[len(prefix):] if semantic.get("name", "").startswith(prefix) else semantic.get("name")
    name = AVP_NAMES.get(code) if code in AVP_NAMES else (decoded_name if code is not None else None)
    sensitive = bool(code in SENSITIVE_AVP_CODES or (name and _sensitive_name(name)))
    value, value_kind = _avp_value(code, name, semantic)
    child_nodes = [child for child in node.findall("field") if child.get("name") == "diameter.avp"]
    children: list[dict[str, Any]] = []
    omitted = 0
    if sensitive and child_nodes:
        omitted = sum(1 + _count_avps(child) for child in child_nodes)
        grouping_status = "REDACTED"
    elif child_nodes and depth < MAX_AVP_DEPTH:
        for index, child in enumerate(child_nodes, start=1):
            parsed = _parse_avp(
                child,
                capture=capture,
                frame=frame,
                occurrence=occurrence,
                path=f"{path}.{index}",
                depth=depth + 1,
                budget=budget,
            )
            if parsed is None:
                omitted += 1 + _count_avps(child)
            else:
                children.append(parsed)
        grouping_status = "DECODED" if children else "DEPTH_LIMITED"
    elif child_nodes:
        omitted = sum(1 + _count_avps(child) for child in child_nodes)
        grouping_status = "DEPTH_LIMITED"
    elif code in GROUPED_AVP_CODES:
        grouping_status = "NOT_DECODED"
    else:
        grouping_status = "NOT_GROUPED"
    projection = {
        "avp_reference": f"diameter-avp:{capture}:{frame}.{occurrence}:{path}",
        "code": code,
        "name": name,
        "name_reviewed": bool(code in AVP_NAMES),
        "occurrence_index": int(path.rsplit(".", 1)[-1]),
        "depth": depth,
        "vendor_specific": bool((flags or 0) & 0x80),
        "mandatory": bool((flags or 0) & 0x40),
        "protected": bool((flags or 0) & 0x20),
        "vendor_id": vendor_id,
        "length": length,
        "data_present": bool(length is not None and length > 8),
        "sensitive": sensitive,
        "value": value,
        "value_kind": value_kind,
        "grouping_status": grouping_status,
        "children_omitted": omitted,
        "children": children,
    }
    return projection


def _parse_avps(proto: ElementTree.Element, capture: str, frame: int, occurrence: int) -> tuple[list[dict[str, Any]], int]:
    nodes = [child for child in proto.findall("field") if child.get("name") == "diameter.avp"]
    total = sum(1 + _count_avps(node) for node in nodes)
    budget = [MAX_AVPS]
    avps: list[dict[str, Any]] = []
    for index, node in enumerate(nodes, start=1):
        parsed = _parse_avp(
            node,
            capture=capture,
            frame=frame,
            occurrence=occurrence,
            path=str(index),
            depth=1,
            budget=budget,
        )
        if parsed is not None:
            avps.append(parsed)
    return avps, max(0, total - MAX_AVPS)


def _find_avp(avps: Iterable[dict[str, Any]], code: int) -> dict[str, Any] | None:
    for avp in avps:
        if avp.get("code") == code:
            return avp
        found = _find_avp(avp.get("children") or [], code)
        if found is not None:
            return found
    return None


def _result(avps: list[dict[str, Any]], limitations: list[str]) -> dict[str, Any]:
    base = _find_avp(avps, 268)
    grouped = _find_avp(avps, 297)
    experimental = _find_avp(grouped.get("children") or [], 298) if grouped else None
    vendor = _find_avp(grouped.get("children") or [], 266) if grouped else None
    result_code = None if base is None else base.get("value")
    experimental_code = None if experimental is None else experimental.get("value")
    vendor_id = None if vendor is None else vendor.get("value")
    result_name = BASE_RESULT_NAMES.get(result_code) if isinstance(result_code, int) else None
    if experimental is not None or grouped is not None:
        limitations.append(
            "Experimental-Result-Code is a vendor-specific namespace and is never mapped to a base Result-Code name"
        )
    return {
        "result_code": result_code if isinstance(result_code, int) else None,
        "result_code_name": result_name,
        "result_namespace": "BASE" if base is not None else ("VENDOR_SPECIFIC" if grouped is not None else None),
        "experimental_result_present": grouped is not None,
        "experimental_result_code": experimental_code if isinstance(experimental_code, int) else None,
        "experimental_vendor_id": vendor_id if isinstance(vendor_id, int) else None,
    }


def _base_event(
    *,
    capture: str,
    frame: int,
    frame_time_epoch: str | None,
    occurrence: int,
    transport: dict[str, Any],
    version: int | None,
    declared_length: int | None,
    observed_length: int | None,
    flags: int | None,
    command_code: int | None,
    application_id: int | None,
    hop_by_hop_id: int | None,
    end_to_end_id: int | None,
    avps: list[dict[str, Any]],
    avps_omitted: int,
) -> dict[str, Any]:
    limitations: list[str] = []
    request = bool((flags or 0) & 0x80)
    direction = "REQUEST" if request else "ANSWER"
    if version != 1:
        limitations.append("the Diameter version is not the reviewed base version 1; no application semantics are inferred")
    length_status = "VALID"
    if declared_length is None or observed_length is None:
        length_status = "UNVERIFIED"
        limitations.append("the declared message length or observed dissection length is unavailable")
    elif declared_length != observed_length:
        length_status = "MISMATCH"
        limitations.append("the declared Diameter message length disagrees with the dissected message length")
    elif declared_length < 20:
        length_status = "INVALID"
        limitations.append("the declared Diameter message length is shorter than the 20-octet base header")
    if command_code is None:
        limitations.append("the command code is unavailable")
    command_name = BASE_COMMANDS.get(command_code) if isinstance(command_code, int) else None
    if command_name is None:
        limitations.append("the command code is not a reviewed base command; application semantics remain unsupported")
    application_semantics = "BASE_COMMON_MESSAGES" if application_id == 0 else "UNSUPPORTED"
    if application_id != 0:
        limitations.append("the Application-ID is outside the base common-message scope; application semantics remain unsupported")
    if avps_omitted:
        limitations.append("AVP publication is bounded; the omitted count is published and no ownership is inferred for omitted AVPs")
    if _find_avp(avps, 263) is not None:
        limitations.append(
            "Session-Id values are withheld as opaque presence and length metadata because they may embed a subscription identifier"
        )
    if any(_contains_sensitive(avp) for avp in avps):
        limitations.append("sensitive Diameter AVP values are redacted to structural metadata only")
    result = _result(avps, limitations)
    return {
        "capture_file": capture,
        "frame_number": frame,
        "frame_time_epoch": frame_time_epoch,
        "message_occurrence": occurrence,
        "protocol_version": version,
        "version_status": "SUPPORTED" if version == 1 else "UNSUPPORTED",
        "message_length": declared_length,
        "observed_message_length": observed_length,
        "message_length_status": length_status,
        "command_code": command_code,
        "command_name": command_name,
        "command_scope": "BASE" if command_name is not None else "APPLICATION_OR_UNKNOWN",
        "application_id": application_id,
        "application_semantics": application_semantics,
        "flags": {
            "request": request,
            "proxyable": bool((flags or 0) & 0x40),
            "error": bool((flags or 0) & 0x20),
            "retransmitted": bool((flags or 0) & 0x10),
        },
        "direction": direction,
        "hop_by_hop_id": hop_by_hop_id,
        "end_to_end_id": end_to_end_id,
        "transport": {**transport, "association_reference": _association_reference(capture, transport)},
        "avps": avps,
        "avp_count": sum(1 + _count_projected(avp) for avp in avps),
        "avps_omitted": avps_omitted,
        "result": result,
        "evidence_class": "OBSERVED",
        "limitations": limitations,
    }


def _count_projected(avp: dict[str, Any]) -> int:
    return sum(1 + _count_projected(child) for child in (avp.get("children") or []))


def _contains_sensitive(avp: dict[str, Any]) -> bool:
    if avp.get("sensitive"):
        return True
    return any(_contains_sensitive(child) for child in (avp.get("children") or []))


def parse_pdml(text: str, capture_file: str | None = None) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise InputError(f"PDML is not valid XML: {exc}") from exc
    capture = capture_file or Path(root.get("capture_file") or "capture.pcap").name
    events: list[dict[str, Any]] = []
    for packet in root.iter("packet"):
        frame = _int_text(_packet_field(packet, "frame.number"))
        if frame is None:
            continue
        frame_time = _packet_field(packet, "frame.time_epoch")
        transport = _transport(packet)
        for occurrence, proto in enumerate(_diameter_protos(packet), start=1):
            flags_show = _show(proto, "diameter.flags")
            flags = _int_text(flags_show)
            if _show(proto, "diameter.flags.request") is not None:
                request = _bool_text(_show(proto, "diameter.flags.request"))
                flags = (flags or 0) | (0x80 if request else 0)
                if _bool_text(_show(proto, "diameter.flags.proxyable")):
                    flags |= 0x40
                if _bool_text(_show(proto, "diameter.flags.error")):
                    flags |= 0x20
                if _bool_text(_show(proto, "diameter.flags.T")):
                    flags |= 0x10
            version = _int_text(_show(proto, "diameter.version"))
            declared_length = _int_text(_show(proto, "diameter.length"))
            observed_length = _int_text(proto.get("size"))
            avps, omitted = _parse_avps(proto, capture, frame, occurrence)
            events.append(
                _base_event(
                    capture=capture,
                    frame=frame,
                    frame_time_epoch=frame_time,
                    occurrence=occurrence,
                    transport=transport,
                    version=version,
                    declared_length=declared_length,
                    observed_length=observed_length,
                    flags=flags,
                    command_code=_int_text(_show(proto, "diameter.cmd.code")),
                    application_id=_int_text(_show(proto, "diameter.applicationId")),
                    hop_by_hop_id=_int_text(_show(proto, "diameter.hopbyhopid")),
                    end_to_end_id=_int_text(_show(proto, "diameter.endtoendid")),
                    avps=avps,
                    avps_omitted=omitted,
                )
            )
    return events


def _normalize_avp(raw: dict[str, Any], path: str, depth: int) -> dict[str, Any]:
    code = raw.get("code")
    if isinstance(code, bool) or not isinstance(code, int) or code < 0:
        raise InputError("AVP code must be a non-negative integer")
    name = AVP_NAMES.get(code, raw.get("name"))
    sensitive = bool(code in SENSITIVE_AVP_CODES or (isinstance(name, str) and _sensitive_name(name)))
    raw_value = raw.get("value")
    if sensitive:
        value, value_kind = None, "SENSITIVE_REDACTED"
    elif code in GROUPED_AVP_CODES:
        value, value_kind = None, "GROUPED"
    elif code in SAFE_VALUE_CODES and raw_value is not None:
        if code in INTEGER_VALUE_CODES and not isinstance(raw_value, bool) and isinstance(raw_value, int):
            value, value_kind = raw_value, "INTEGER"
        elif isinstance(raw_value, str):
            if SENSITIVE_VALUE_PATTERN.match(raw_value):
                value, value_kind = None, "SENSITIVE_REDACTED"
            else:
                value, value_kind = raw_value, "STRING"
        else:
            value, value_kind = None, "OPAQUE"
    else:
        value, value_kind = None, "OPAQUE"
    children_raw = raw.get("children") or []
    children = [_normalize_avp(child, f"{path}.{index}", depth + 1) for index, child in enumerate(children_raw, start=1)]
    grouping_status = "DECODED" if children else ("NOT_DECODED" if code in GROUPED_AVP_CODES else "NOT_GROUPED")
    return {
        "avp_reference": raw.get("avp_reference") or f"diameter-avp:record:{path}",
        "code": code,
        "name": name,
        "name_reviewed": code in AVP_NAMES,
        "occurrence_index": int(path.rsplit(".", 1)[-1]),
        "depth": depth,
        "vendor_specific": bool(raw.get("vendor_specific")),
        "mandatory": bool(raw.get("mandatory")),
        "protected": bool(raw.get("protected")),
        "vendor_id": raw.get("vendor_id"),
        "length": raw.get("length"),
        "data_present": bool(raw.get("length") and raw.get("length") > 8),
        "sensitive": sensitive,
        "value": value,
        "value_kind": value_kind,
        "grouping_status": grouping_status,
        "children_omitted": raw.get("children_omitted", 0),
        "children": children,
    }


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InputError("each JSONL record must be an object")
    header = record.get("header")
    transport = record.get("transport")
    if not isinstance(header, dict) or not isinstance(transport, dict):
        raise InputError("each record needs header and transport objects")
    frame = record.get("frame_number")
    if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
        raise InputError("frame_number must be a positive integer")
    occurrence = record.get("message_occurrence", 1)
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 1:
        raise InputError("message_occurrence must be a positive integer")
    raw_avps = record.get("avps") or []
    if not isinstance(raw_avps, list):
        raise InputError("avps must be an array")
    avps = [_normalize_avp(raw, str(index), 1) for index, raw in enumerate(raw_avps, start=1)]
    flags = header.get("flags") or {}
    flag_value = 0
    if flags.get("request"):
        flag_value |= 0x80
    if flags.get("proxyable"):
        flag_value |= 0x40
    if flags.get("error"):
        flag_value |= 0x20
    if flags.get("retransmitted"):
        flag_value |= 0x10
    capture = str(record.get("capture_file") or "capture.pcap")
    return _base_event(
        capture=capture,
        frame=frame,
        frame_time_epoch=str(record.get("frame_time_epoch") or ""),
        occurrence=occurrence,
        transport={
            "protocol": transport.get("protocol", "UNKNOWN"),
            "source_address": transport.get("source_address"),
            "source_port": transport.get("source_port"),
            "destination_address": transport.get("destination_address"),
            "destination_port": transport.get("destination_port"),
            "verification_tag": transport.get("verification_tag"),
            "stream_id": transport.get("stream_id"),
        },
        version=header.get("version"),
        declared_length=header.get("length"),
        observed_length=header.get("observed_length", header.get("length")),
        flags=flag_value,
        command_code=header.get("command_code"),
        application_id=header.get("application_id"),
        hop_by_hop_id=header.get("hop_by_hop_id"),
        end_to_end_id=header.get("end_to_end_id"),
        avps=avps,
        avps_omitted=max(0, int(record.get("avps_omitted") or 0)),
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
    return events


def tshark_version(tshark_bin: str | None = None) -> str:
    exe = tshark_bin or shutil.which("tshark") or "tshark"
    try:
        completed = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc
    if completed.returncode != 0:
        raise TsharkError(completed.stderr.strip() or "tshark --version failed")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def pdml_for_capture(capture: Path, tshark_bin: str | None = None) -> str:
    exe = tshark_bin or shutil.which("tshark") or "tshark"
    try:
        completed = subprocess.run(
            [exe, "-r", str(capture), "-Y", "diameter", "-T", "pdml"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc
    if completed.returncode != 0:
        raise TsharkError(completed.stderr.strip() or "tshark failed")
    return completed.stdout


def events_for_input(path: Path, input_format: str = "auto") -> tuple[list[dict[str, Any]], str | None]:
    if not path.is_file():
        raise InputError(f"input does not exist: {path}")
    fmt = input_format
    if fmt == "auto":
        suffix = path.suffix.lower()
        if suffix in (".pcap", ".pcapng"):
            fmt = "capture"
        elif suffix in (".pdml", ".xml"):
            fmt = "pdml"
        elif suffix in (".jsonl", ".json"):
            fmt = "fields-jsonl"
        else:
            raise InputError(f"cannot infer input format from {path.suffix}")
    if fmt == "capture":
        decoder = tshark_version()
        events = parse_pdml(pdml_for_capture(path), path.name)
        return events, decoder
    if fmt == "pdml":
        return parse_pdml(path.read_text(encoding="utf-8"), path.name), None
    if fmt == "fields-jsonl":
        return records_from_jsonl(path), None
    raise InputError(f"unsupported input format: {fmt}")


def _reference(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "frame_number": event["frame_number"],
        "message_occurrence": event["message_occurrence"],
        "frame_time_epoch": event["frame_time_epoch"],
        "command_code": event["command_code"],
        "command_name": event["command_name"],
        "application_id": event["application_id"],
        "direction": event["direction"],
        "hop_by_hop_id": event["hop_by_hop_id"],
        "end_to_end_id": event["end_to_end_id"],
        "source_endpoint": _endpoint(event["transport"], "source"),
        "destination_endpoint": _endpoint(event["transport"], "destination"),
    }


def _event_sort_key(event: dict[str, Any]) -> tuple[Any, ...]:
    return (event["capture_file"], event["frame_number"], event["message_occurrence"])


def correlate(events: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(events, key=_event_sort_key)
    requests = [event for event in ordered if event["direction"] == "REQUEST"]
    answers = [event for event in ordered if event["direction"] == "ANSWER"]
    duplicate_groups: dict[tuple[Any, ...], int] = {}
    for event in requests:
        transport = event["transport"]
        key = (
            transport["association_reference"],
            event["command_code"],
            event["application_id"],
            event["hop_by_hop_id"],
            event["end_to_end_id"],
        )
        duplicate_groups[key] = duplicate_groups.get(key, 0) + 1
    retransmissions = sum(count - 1 for count in duplicate_groups.values() if count > 1)

    assigned: set[tuple[Any, ...]] = set()
    transactions: list[dict[str, Any]] = []
    for answer in answers:
        answer_transport = answer["transport"]
        candidates = []
        for request in requests:
            request_id = (request["capture_file"], request["frame_number"], request["message_occurrence"])
            if request_id in assigned:
                continue
            if request["frame_number"] >= answer["frame_number"]:
                continue
            if request_transport_key(request) != answer_transport["association_reference"]:
                continue
            if request["command_code"] != answer["command_code"] or request["application_id"] != answer["application_id"]:
                continue
            if request["hop_by_hop_id"] != answer["hop_by_hop_id"]:
                continue
            if request["transport"]["source_address"] != answer_transport["destination_address"]:
                continue
            if request["transport"]["destination_address"] != answer_transport["source_address"]:
                continue
            candidates.append(request)
        same_hop = [
            request
            for request in requests
            if request_transport_key(request) == answer_transport["association_reference"]
            and request["command_code"] == answer["command_code"]
            and request["application_id"] == answer["application_id"]
            and request["hop_by_hop_id"] == answer["hop_by_hop_id"]
            and request["frame_number"] < answer["frame_number"]
        ]
        matched = None
        basis: list[str] = []
        limitations: list[str] = []
        if len(candidates) == 1:
            matched = candidates[0]
            matched_id = (matched["capture_file"], matched["frame_number"], matched["message_occurrence"])
            if matched["end_to_end_id"] == answer["end_to_end_id"]:
                assigned.add(matched_id)
                basis.extend(
                    [
                        "same_transport_association",
                        "opposite_endpoint_direction",
                        "command_code_match",
                        "application_id_match",
                        "hop_by_hop_match",
                        "end_to_end_match",
                        "unique_open_request",
                    ]
                )
                status, strength = "MATCHED", "STRONG"
            else:
                limitations.append(
                    "a request with the same hop-by-hop identifier publishes a different end-to-end identifier; no pairing is claimed"
                )
                status, strength = "RESPONSE_ONLY", "NONE"
        elif len(candidates) > 1:
            status, strength = "AMBIGUOUS", "NONE"
            limitations.append("several open requests share the same command, application, hop-by-hop and end-to-end identifiers")
        else:
            status, strength = "RESPONSE_ONLY", "NONE"
            if same_hop:
                limitations.append(
                    "an earlier request shares the hop-by-hop identifier but its end-to-end identifier differs or it was already answered"
                )
            else:
                limitations.append("no observed request matches this answer within the capture")
        request_ref = None if matched is None else _reference(matched)
        latency = None
        if matched is not None:
            try:
                latency = f"{float(answer['frame_time_epoch']) - float(matched['frame_time_epoch']):.6f}"
            except (TypeError, ValueError):
                latency = None
                limitations.append("frame timestamps are unavailable, so no latency is calculated")
        transactions.append(
            _transaction(
                status=status,
                strength=strength,
                request=request_ref,
                answer=_reference(answer),
                candidates=[_reference(item) for item in candidates],
                basis=basis,
                limitations=limitations,
                latency=latency,
                anchor=answer,
            )
        )

    for request in requests:
        request_id = (request["capture_file"], request["frame_number"], request["message_occurrence"])
        if request_id in assigned:
            continue
        limitations = ["an unanswered request within the capture does not prove a timeout or a peer failure"]
        transport = request["transport"]
        duplicate_key = (
            transport["association_reference"],
            request["command_code"],
            request["application_id"],
            request["hop_by_hop_id"],
            request["end_to_end_id"],
        )
        if duplicate_groups.get(duplicate_key, 0) > 1:
            limitations.append("the same request identifier is observed more than once; no successful transaction is inferred")
        transactions.append(
            _transaction(
                status="OPEN_REQUEST",
                strength="NONE",
                request=_reference(request),
                answer=None,
                candidates=[],
                basis=[],
                limitations=limitations,
                latency=None,
                anchor=request,
            )
        )

    transactions.sort(
        key=lambda item: (
            item["request"]["frame_number"] if item["request"] else item["answer"]["frame_number"],
            item["request"]["message_occurrence"] if item["request"] else item["answer"]["message_occurrence"],
            item["transaction_reference"],
        )
    )
    counts = {
        "MATCHED": sum(1 for item in transactions if item["correlation_status"] == "MATCHED"),
        "OPEN_REQUEST": sum(1 for item in transactions if item["correlation_status"] == "OPEN_REQUEST"),
        "RESPONSE_ONLY": sum(1 for item in transactions if item["correlation_status"] == "RESPONSE_ONLY"),
        "AMBIGUOUS": sum(1 for item in transactions if item["correlation_status"] == "AMBIGUOUS"),
    }
    limitations = [
        "an open request at the capture boundary does not prove a timeout, retransmission or peer failure",
        "a matched answer proves protocol-local request/answer evidence only, not application, subscriber or procedure success",
        "unavailable End-to-End Identifier evidence limits correlation strength; frame proximity is never used",
        "Application-specific and vendor-specific semantics remain outside this base-protocol Skill",
    ]
    return {
        "protocol": PROTOCOL,
        "capture_files": sorted({event["capture_file"] for event in ordered}),
        "transaction_count": len(transactions),
        "matched_count": counts["MATCHED"],
        "open_request_count": counts["OPEN_REQUEST"],
        "response_only_count": counts["RESPONSE_ONLY"],
        "ambiguous_count": counts["AMBIGUOUS"],
        "retransmission_count": retransmissions,
        "transactions": transactions,
        "limitations": limitations,
    }


def request_transport_key(request: dict[str, Any]) -> str:
    return request["transport"]["association_reference"]


def _transaction(
    *,
    status: str,
    strength: str,
    request: dict[str, Any] | None,
    answer: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
    basis: list[str],
    limitations: list[str],
    latency: str | None,
    anchor: dict[str, Any],
) -> dict[str, Any]:
    frame = (request or answer or anchor)["frame_number"]
    occurrence = (request or answer or anchor)["message_occurrence"]
    command_code = anchor["command_code"]
    transport = anchor["transport"]["association_reference"]
    reference = f"diameter-tx:{anchor['capture_file']}:{command_code}:{frame}.{occurrence}"
    result = anchor.get("result") or {}
    command_name = anchor.get("command_name")
    command_scope = anchor.get("command_scope") or (
        "BASE" if command_name in BASE_COMMANDS.values() else "APPLICATION_OR_UNKNOWN"
    )
    application_semantics = anchor.get("application_semantics") or (
        "BASE_COMMON_MESSAGES" if anchor.get("application_id") == 0 else "UNSUPPORTED"
    )
    return {
        "transaction_reference": reference,
        "command_code": command_code,
        "command_name": command_name,
        "command_scope": command_scope,
        "application_id": anchor["application_id"],
        "application_semantics": application_semantics,
        "transport_association_reference": transport,
        "request": request,
        "answer": answer,
        "response_candidates": candidates,
        "correlation_status": status,
        "correlation_strength": strength,
        "correlation_basis": basis,
        "latency_seconds": latency,
        "result_code": result.get("result_code"),
        "result_code_name": result.get("result_code_name"),
        "result_namespace": result.get("result_namespace"),
        "experimental_result_code": result.get("experimental_result_code"),
        "experimental_vendor_id": result.get("experimental_vendor_id"),
        "limitations": limitations,
    }


def render_timeline(transaction_document: dict[str, Any]) -> str:
    lines = [
        "frame  direction  command  application  result  status  latency",
        "-----  ---------  -------  -----------  ------  ------  -------",
    ]
    for transaction in transaction_document["transactions"]:
        request = transaction["request"]
        answer = transaction["answer"]
        if request is not None:
            frame = request["frame_number"]
            direction = "REQUEST"
        else:
            frame = answer["frame_number"]
            direction = "ANSWER"
        command = f"{transaction['command_code']} {transaction['command_name'] or 'UNREVIEWED'}"
        result = transaction["result_code"]
        if result is None and transaction["experimental_result_code"] is not None:
            result = f"exp:{transaction['experimental_result_code']}"
        latency = transaction["latency_seconds"] or "-"
        lines.append(
            f"{frame:<6} {direction:<9} {command:<7} {transaction['application_id']:<11} "
            f"{str(result if result is not None else '-'):<6} {transaction['correlation_status']:<6} {latency}"
        )
    return "\n".join(lines) + "\n"


def trace_timestamp(epoch: str | None) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (TypeError, ValueError, OverflowError):
        return "1970-01-01T00:00:00.000000Z"


def project_trace_event(event: dict[str, Any]) -> dict[str, Any]:
    command = event["command_name"] or f"Command-{event['command_code']}"
    projected: dict[str, Any] = {
        "timestamp": trace_timestamp(event.get("frame_time_epoch")),
        "protocol": PROTOCOL,
        "interface": None,
        "procedure": None,
        "message_type": command,
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "OBSERVED",
            "source": f"diameter-event:{event['capture_file']}#frame={event['frame_number']}.{event['message_occurrence']}",
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
    result = event["result"]
    if result["result_code"] is not None:
        code = result["result_code"]
        status = "SUCCESS" if code in (2001, 2002) else "FAILURE" if code >= 3000 else None
        projected["result"] = {"status": status, "cause": f"diameter:{code}", "code": code}
    elif result["experimental_result_code"] is not None:
        projected["result"] = {
            "status": None,
            "cause": f"diameter-experimental:{result['experimental_result_code']}",
            "code": result["experimental_result_code"],
        }
    return projected