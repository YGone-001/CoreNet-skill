#!/usr/bin/env python3
"""Shared standalone helpers for bounded 3GPP SBI and HTTP/2 extraction on N11.

Reviewed basis:
- 3GPP TS 29.500 version 19.7.0 Release 19 (Technical Realization of SBA)
- 3GPP TS 29.501 version 19.5.0 Release 19 (Principles and Guidelines for Services Definition)
- 3GPP TS 29.502 version 19.8.0 Release 19 (Session Management Services, Release 19 lineage)
- 3GPP TS 29.518 version 19.8.0 Release 19 (Access and Mobility Management Services; Stage 3)
- 3GPP TS 29.571 version 19.4.0 / 19.8.0 Release 19 (Common Data Types for SBI)
- RFC 9113 (HTTP/2)
- RFC 9110 (HTTP Semantics)

Bounded semantics: Nsmf_PDUSession (Create SM Context, Update SM Context, and Release SM Context)
and Namf_Communication (N1N2MessageTransfer and N1N2Transfer Failure Notification) are
SUPPORTED. Other operations or services are UNSUPPORTED or UNKNOWN. Raw HTTP/2 parsing,
HPACK decoding, TLS decryption, NAS decoding, and NGAP decoding are strictly forbidden.
Stream IDs are always scoped by connection context.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any
from urllib.parse import unquote

EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "sbi-http2-event"

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "http2.streamid",
    "http2.type",
    "http2.headers.method",
    "http2.headers.path",
    "http2.headers.status",
    "http2.headers.scheme",
    "http2.headers.authority",
    "http2.header.name",
    "http2.header.value",
    "http2.data.length",
    "http2.rst_stream.error",
    "http2.goaway.last_streamid",
    "http2.goaway.error",
    "mime_multipart.part",
    "mime_multipart.header.name",
    "mime_multipart.header.value",
    "json.member_name",
    "json.value.string",
)

SERVICE_NSMF_PDUSESSION = "Nsmf_PDUSession"
OP_CREATE_SM_CONTEXT = "CreateSMContext"
OP_UPDATE_SM_CONTEXT = "UpdateSMContext"
OP_RELEASE_SM_CONTEXT = "ReleaseSMContext"

SERVICE_NAMF_COMMUNICATION = "Namf_Communication"
OP_N1N2_MESSAGE_TRANSFER = "N1N2MessageTransfer"
OP_N1N2_TRANSFER_FAILURE_NOTIFICATION = "N1N2TransferFailureNotification"

NAMF_TRANSFER_CAUSES = {
    "N1_N2_TRANSFER_INITIATED",
    "WAITING_FOR_ASYNCHRONOUS_TRANSFER",
    "ATTEMPTING_TO_REACH_UE",
    "N1_MSG_NOT_TRANSFERRED",
    "N2_MSG_NOT_TRANSFERRED",
}

NAMF_FAILURE_CAUSES = {
    "UE_NOT_RESPONDING",
    "UE_NOT_REACHABLE_FOR_SESSION",
    "TEMPORARY_REJECT_REGISTRATION_ONGOING",
    "TEMPORARY_REJECT_HANDOVER_ONGOING",
    "AN_NOT_RESPONDING",
    "FAILURE_CAUSE_UNSPECIFIED",
}

MEDIA_TYPE_5GNAS = "application/vnd.3gpp.5gnas"
MEDIA_TYPE_NGAP = "application/vnd.3gpp.ngap"
MEDIA_TYPE_JSON = "application/json"
MEDIA_TYPE_PROBLEM_JSON = "application/problem+json"
MEDIA_TYPE_MULTIPART = "multipart/related"

SAFE_HEADERS = {
    "content-type",
    "content-length",
    "accept",
    "location",
    "user-agent",
    "3gpp-sbi-target-apiroot",
    "3gpp-sbi-routing-binding",
    "3gpp-sbi-message-priority",
    "3gpp-sbi-sender-timestamp",
    "3gpp-sbi-max-rsp-time",
    "3gpp-sbi-correlation-id",
}

FORBIDDEN_HEADERS = {
    "authorization",
    "proxy-authorization",
}


class InputError(Exception):
    """Raised when input records or files are malformed."""


class TsharkError(Exception):
    """Raised when TShark fails during capture processing."""


class ToolUnavailable(Exception):
    """Raised when an external tool is required but not installed."""


def clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def parse_int(value: Any, name: str | None = None, minimum: int | None = None, maximum: int | None = None) -> int | None:
    text = clean(value)
    if text is None:
        return None
    try:
        result = int(text, 0)
    except ValueError as exc:
        raise InputError(f"invalid integer for {name or 'field'}: {value!r}") from exc
    if minimum is not None and result < minimum:
        raise InputError(f"{name or 'field'} must be >= {minimum}: {result}")
    if maximum is not None and result > maximum:
        raise InputError(f"{name or 'field'} must be <= {maximum}: {result}")
    return result


def parse_port(value: Any, name: str) -> int | None:
    return parse_int(value, name=name, minimum=0, maximum=65535)


def safe_capture_name(path: Path | str) -> str:
    cleaned = Path(path).name.strip()
    return cleaned if cleaned else "unknown-capture"


def normalize_timestamp(raw: Any) -> str:
    text = clean(raw)
    if text is None:
        raise InputError("record timestamp is missing")
    if text.endswith("Z") or ("+" in text and "T" in text):
        cleaned = text[:-1] + "+00:00" if text.endswith("Z") else text
        try:
            parsed = datetime.fromisoformat(cleaned)
            utc = parsed.astimezone(timezone.utc)
            return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            pass
    try:
        epoch = Decimal(text)
        seconds = int(epoch)
        micros = int((epoch - Decimal(seconds)) * Decimal(1_000_000))
        utc = datetime.fromtimestamp(seconds, tz=timezone.utc)
        utc = utc.replace(microsecond=micros)
        return utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except (InvalidOperation, ValueError, OverflowError) as exc:
        raise InputError(f"unparseable timestamp: {raw!r}") from exc


def filter_safe_headers(headers: dict[str, Any] | None) -> dict[str, str]:
    """Filter headers to the safe allowlist; unconditionally strip Authorization."""
    if not isinstance(headers, dict):
        return {}
    filtered: dict[str, str] = {}
    for key, val in headers.items():
        if val is None:
            continue
        key_lower = str(key).strip().lower()
        if key_lower in FORBIDDEN_HEADERS:
            continue
        if key_lower in SAFE_HEADERS:
            filtered[key_lower] = str(val).strip()
    return filtered


def sanitize_sbi_uri(uri: Any) -> tuple[str | None, bool, str | None, str | None]:
    """Central URI sanitizer for identity-bearing SBI paths.

    Strips query parameters containing sensitive tokens/secrets.
    Detects and replaces /ue-contexts/{raw_id} with /ue-contexts/{ueContextId}.
    Returns (sanitized_path, ue_context_id_present, ue_context_id_type, n1n2_transfer_ref).
    """
    if uri is None:
        return None, False, None, None
    raw_text = str(uri).strip()
    if not raw_text:
        return None, False, None, None

    # Strip any query string
    path_part = raw_text.split("?")[0].strip()

    # Match /namf-comm/vX/ue-contexts/<id>/n1-n2-messages[/<msg-id>]
    namf_match = re.search(
        r"(?:https?://[^/]+)?(/namf-comm/(v[0-9]+)/ue-contexts/([^/]+)/n1-n2-messages(?:/([^/?#]+))?)",
        path_part,
    )
    if namf_match:
        api_ver = namf_match.group(2)
        raw_id = namf_match.group(3)
        msg_id = namf_match.group(4)

        decoded_id = unquote(raw_id).strip()
        lower_id = decoded_id.lower()

        if lower_id.startswith(("imsi-", "supi-")) or (re.fullmatch(r"[0-9]{14,16}", decoded_id)):
            id_type = "SUPI"
        elif lower_id.startswith(("pei-", "imei-", "imeisv-")) or ("pei" in lower_id):
            id_type = "PEI"
        elif lower_id.startswith("guti-"):
            id_type = "GUTI"
        elif re.fullmatch(r"[a-zA-Z0-9_\-\.~%]+", decoded_id):
            id_type = "GENERIC"
        else:
            id_type = "UNKNOWN"

        sanitized_path = f"/namf-comm/{api_ver}/ue-contexts/{{ueContextId}}/n1-n2-messages"
        transfer_ref = None
        if msg_id:
            sanitized_path += f"/{msg_id}"
            transfer_ref = sanitized_path

        return sanitized_path, True, id_type, transfer_ref

    # Match generic /ue-contexts/<id>
    generic_ue_match = re.search(r"(?:https?://[^/]+)?(/namf-comm/(v[0-9]+)/ue-contexts/([^/]+)(?:/.*)?)", path_part)
    if generic_ue_match:
        api_ver = generic_ue_match.group(2)
        raw_id = generic_ue_match.group(3)
        decoded_id = unquote(raw_id).strip()
        lower_id = decoded_id.lower()
        if lower_id.startswith(("imsi-", "supi-")) or (re.fullmatch(r"[0-9]{14,16}", decoded_id)):
            id_type = "SUPI"
        elif lower_id.startswith(("pei-", "imei-", "imeisv-")) or ("pei" in lower_id):
            id_type = "PEI"
        elif lower_id.startswith("guti-"):
            id_type = "GUTI"
        else:
            id_type = "GENERIC"
        sanitized = re.sub(r"/ue-contexts/[^/]+", "/ue-contexts/{ueContextId}", path_part)
        return sanitized, True, id_type, None

    return path_part, False, None, None


def parse_sbi_uri(
    path: str | None,
    method: str | None,
    json_body: dict[str, Any] | None = None,
) -> tuple[str | None, str | None, str | None, str | None, str | None, str]:
    """Analyze HTTP path, method, and optional body to determine SBI service, version, operation, and ref."""
    if not path:
        return None, None, None, None, None, "UNSUPPORTED"

    clean_path = path.split("?")[0].strip()
    method_upper = method.upper() if method else ""

    nsmf_match = re.search(r"/nsmf-pdusession/(v[0-9]+)/sm-contexts(?:/([a-zA-Z0-9_\-\.~%]+))?(?:/(modify|release|send-mo-data))?", clean_path)
    if nsmf_match:
        api_version = nsmf_match.group(1)
        sm_context_ref = nsmf_match.group(2)
        custom_op = nsmf_match.group(3)

        if sm_context_ref is None and custom_op is None:
            if method_upper == "POST":
                return SERVICE_NSMF_PDUSESSION, api_version, OP_CREATE_SM_CONTEXT, "sm-contexts", None, "SUPPORTED"
            return SERVICE_NSMF_PDUSESSION, api_version, "UNKNOWN", "sm-contexts", None, "UNKNOWN"

        if sm_context_ref is not None and custom_op == "modify":
            if method_upper == "POST":
                return SERVICE_NSMF_PDUSESSION, api_version, OP_UPDATE_SM_CONTEXT, f"sm-contexts/{sm_context_ref}/modify", sm_context_ref, "SUPPORTED"
            return SERVICE_NSMF_PDUSESSION, api_version, "UNKNOWN", f"sm-contexts/{sm_context_ref}/modify", sm_context_ref, "UNKNOWN"

        if sm_context_ref is not None and custom_op == "release":
            if method_upper == "POST":
                return SERVICE_NSMF_PDUSESSION, api_version, OP_RELEASE_SM_CONTEXT, f"sm-contexts/{sm_context_ref}/release", sm_context_ref, "SUPPORTED"
            return SERVICE_NSMF_PDUSESSION, api_version, "UNKNOWN", f"sm-contexts/{sm_context_ref}/release", sm_context_ref, "UNKNOWN"

        if sm_context_ref is not None and custom_op is None:
            if method_upper == "GET":
                return SERVICE_NSMF_PDUSESSION, api_version, "RetrieveSMContext", f"sm-contexts/{sm_context_ref}", sm_context_ref, "UNSUPPORTED"
            return SERVICE_NSMF_PDUSESSION, api_version, "UNKNOWN", f"sm-contexts/{sm_context_ref}", sm_context_ref, "UNKNOWN"

        if custom_op == "send-mo-data":
            return SERVICE_NSMF_PDUSESSION, api_version, "SendMoData", f"sm-contexts/{sm_context_ref}/send-mo-data", sm_context_ref, "UNSUPPORTED"

        return SERVICE_NSMF_PDUSESSION, api_version, "UNKNOWN", clean_path, sm_context_ref, "UNKNOWN"

    if "/nsmf-pdusession/" in clean_path:
        pdu_session_match = re.search(r"/nsmf-pdusession/(v[0-9]+)/pdu-sessions", clean_path)
        ver = pdu_session_match.group(1) if pdu_session_match else None
        return SERVICE_NSMF_PDUSESSION, ver, "PduSessionService", clean_path, None, "UNSUPPORTED"

    # Namf_Communication N1N2MessageTransfer
    namf_n1n2_match = re.search(r"/namf-comm/(v[0-9]+)/ue-contexts/(?:\{ueContextId\}|[^/]+)/n1-n2-messages", clean_path)
    if namf_n1n2_match:
        api_version = namf_n1n2_match.group(1)
        if method_upper == "POST":
            return SERVICE_NAMF_COMMUNICATION, api_version, OP_N1N2_MESSAGE_TRANSFER, "ue-contexts/{ueContextId}/n1-n2-messages", None, "SUPPORTED"
        return SERVICE_NAMF_COMMUNICATION, api_version, "UNKNOWN", "ue-contexts/{ueContextId}/n1-n2-messages", None, "UNSUPPORTED"

    # Namf_Communication N1N2Transfer Failure Notification callback
    is_failure_notif = False
    if isinstance(json_body, dict):
        if ("n1n2MsgDataUri" in json_body or "n1n2_msg_data_uri" in json_body) and "cause" in json_body:
            is_failure_notif = True
    if any(k in clean_path for k in ("n1-n2-failure-notify", "n1n2-failure-notify", "n1-n2-message-transfers/notify", "n1-n2-messages/notify")):
        is_failure_notif = True

    if is_failure_notif:
        api_ver_match = re.search(r"/(v[0-9]+)/", clean_path)
        api_version = api_ver_match.group(1) if api_ver_match else "v1"
        if method_upper == "POST" or not method_upper:
            return SERVICE_NAMF_COMMUNICATION, api_version, OP_N1N2_TRANSFER_FAILURE_NOTIFICATION, clean_path, None, "SUPPORTED"
        return SERVICE_NAMF_COMMUNICATION, api_version, "UNKNOWN", clean_path, None, "UNSUPPORTED"

    # Other Namf_Communication paths (unsupported operations)
    if "/namf-comm/" in clean_path:
        api_ver_match = re.search(r"/namf-comm/(v[0-9]+)/", clean_path)
        api_version = api_ver_match.group(1) if api_ver_match else None
        return SERVICE_NAMF_COMMUNICATION, api_version, None, clean_path, None, "UNSUPPORTED"

    known_services = {
        "/namf-evts/": "Namf_EventExposure",
        "/nausf-auth/": "Nausf_UEAuthentication",
        "/nudm-sdm/": "Nudm_SDM",
        "/nudm-uecm/": "Nudm_UECM",
        "/npcf-smpolicycontrol/": "Npcf_SMPolicyControl",
        "/nnrf-disc/": "Nnrf_NFDiscovery",
        "/nnrf-nfm/": "Nnrf_NFManagement",
    }
    for prefix, svc_name in known_services.items():
        if prefix in clean_path:
            return svc_name, None, None, clean_path, None, "UNSUPPORTED"

    return None, None, None, clean_path, None, "UNSUPPORTED"


def extract_sm_context_ref_from_location(location: str | None) -> str | None:
    if not location:
        return None
    path_part = location.split("?")[0].strip()
    match = re.search(r"/sm-contexts/([a-zA-Z0-9_\-\.~%]+)$", path_part)
    return match.group(1) if match else None


def normalize_content_id(raw_cid: str | None) -> str | None:
    if not raw_cid:
        return None
    cleaned = str(raw_cid).strip()
    if cleaned.startswith("<") and cleaned.endswith(">"):
        cleaned = cleaned[1:-1].strip()
    return cleaned if cleaned else None


def bind_multipart_parts(
    raw_parts: list[Any],
    n1_content_id: str | None,
    n2_content_id: str | None,
    limitations: list[str],
    n1_message_class: str | None = None,
    n2_info_class: str | None = None,
) -> list[dict[str, Any]]:
    """Bind multipart body parts by Content-ID. Never bind by position."""
    if not raw_parts:
        return []

    norm_n1 = normalize_content_id(n1_content_id)
    norm_n2 = normalize_content_id(n2_content_id)

    processed_parts: list[dict[str, Any]] = []
    cid_counts: dict[str, int] = {}

    for item in raw_parts:
        if not isinstance(item, dict):
            continue
        cid = normalize_content_id(item.get("content_id") or item.get("contentId") or item.get("id"))
        ctype = clean(item.get("content_type") or item.get("contentType") or item.get("type"))
        length = parse_int(item.get("length") or item.get("size") or item.get("content_length"))
        if cid:
            cid_counts[cid] = cid_counts.get(cid, 0) + 1
        processed_parts.append({
            "content_id": cid,
            "content_type": ctype,
            "length": length if length is not None else 0,
            "semantic_role": None,
            "reference_basis": None,
        })

    # Check for missing Content-IDs
    if norm_n1 and cid_counts.get(norm_n1, 0) == 0:
        limitations.append(f"referenced Content-ID '{norm_n1}' has no matching multipart part")
    if norm_n2 and cid_counts.get(norm_n2, 0) == 0:
        limitations.append(f"referenced Content-ID '{norm_n2}' has no matching multipart part")

    # Check for duplicate Content-IDs
    for cid, count in cid_counts.items():
        if count > 1 and (cid == norm_n1 or cid == norm_n2):
            limitations.append(f"duplicate Content-ID '{cid}' observed in multipart parts")

    # Match each part deterministically by Content-ID, never positional zip!
    for part in processed_parts:
        cid = part["content_id"]
        ctype = part["content_type"] or ""

        if cid and cid_counts.get(cid, 0) > 1 and (cid == norm_n1 or cid == norm_n2):
            part["semantic_role"] = "UNRESOLVED"
            part["reference_basis"] = "AMBIGUOUS_CONTENT_ID"
            continue

        if norm_n1 and cid == norm_n1:
            part["semantic_role"] = "N1_SM_INFO" if (n1_message_class is None or n1_message_class == "SM") else "N1_MESSAGE"
            part["reference_basis"] = "EXPLICIT_CONTENT_ID"
        elif norm_n2 and cid == norm_n2:
            part["semantic_role"] = "N2_SM_INFO" if (n2_info_class is None or n2_info_class == "SM") else "N2_INFO"
            part["reference_basis"] = "EXPLICIT_CONTENT_ID"
        elif "application/json" in ctype or cid == "jsonData":
            part["semantic_role"] = "JSON_METADATA"
            part["reference_basis"] = "ROOT_JSON"
        else:
            part["semantic_role"] = "UNRESOLVED"
            part["reference_basis"] = "UNREFERENCED"

    return processed_parts


def normalize_record(record: dict[str, Any], capture_file: str) -> dict[str, Any]:
    """Normalize a raw or structured record into a detailed SBI HTTP/2 event."""
    if not isinstance(record, dict):
        raise InputError("record must be a JSON object")

    frame_number = parse_int(record.get("frame_number") or record.get("frame.number"), "frame_number", minimum=1)
    if frame_number is None:
        raise InputError("record requires a positive integer frame_number")

    timestamp = normalize_timestamp(record.get("timestamp") or record.get("frame.time_epoch"))

    # Connection context
    raw_tcp_stream = record.get("tcp_stream") if record.get("tcp_stream") is not None else record.get("tcp.stream")
    tcp_stream = parse_int(raw_tcp_stream, "tcp_stream", minimum=0)
    connection_id = clean(record.get("connection_id"))
    src_addr = clean(record.get("source_address") or record.get("ip.src") or record.get("ipv6.src"))
    dst_addr = clean(record.get("destination_address") or record.get("ip.dst") or record.get("ipv6.dst"))
    raw_sport = record.get("source_port") if record.get("source_port") is not None else record.get("tcp.srcport")
    src_port = parse_port(raw_sport, "source_port")
    raw_dport = record.get("destination_port") if record.get("destination_port") is not None else record.get("tcp.dstport")
    dst_port = parse_port(raw_dport, "destination_port")

    connection = {
        "tcp_stream": tcp_stream,
        "connection_id": connection_id,
        "source_address": src_addr,
        "source_port": src_port,
        "destination_address": dst_addr,
        "destination_port": dst_port,
    }

    # HTTP/2 fields
    raw_stream_id = record.get("stream_id") if record.get("stream_id") is not None else record.get("http2.streamid")
    stream_id = parse_int(raw_stream_id, "stream_id", minimum=0)
    raw_ftype = clean(record.get("frame_type") or record.get("http2.type"))
    frame_type = raw_ftype.upper() if raw_ftype else None

    method = clean(record.get("method") or record.get("http2.headers.method"))
    method_upper = method.upper() if method else None

    scheme = clean(record.get("scheme") or record.get("http2.headers.scheme"))
    authority = clean(record.get("authority") or record.get("http2.headers.authority"))
    raw_path = clean(record.get("path") or record.get("http2.headers.path"))
    sanitized_path, ue_ctx_present, ue_ctx_type, path_transfer_ref = sanitize_sbi_uri(raw_path)
    path = sanitized_path

    raw_status = record.get("status") if record.get("status") is not None else record.get("http2.headers.status")
    status = parse_int(raw_status, "status", minimum=100, maximum=599)
    content_type = clean(record.get("content_type"))
    raw_content_length = record.get("content_length") if record.get("content_length") is not None else record.get("http2.data.length")
    content_length = parse_int(raw_content_length, "content_length", minimum=0)

    # Headers dictionary
    raw_headers = record.get("headers")
    if isinstance(raw_headers, dict):
        selected_headers = filter_safe_headers(raw_headers)
        if not content_type:
            content_type = clean(selected_headers.get("content-type"))
        if content_length is None and selected_headers.get("content-length"):
            content_length = parse_int(selected_headers.get("content-length"))
    else:
        selected_headers = {}

    loc_header = selected_headers.get("location") or clean(record.get("location"))
    loc_transfer_ref = None
    if loc_header:
        sanitized_loc, loc_ue_present, loc_ue_type, loc_transfer_ref = sanitize_sbi_uri(loc_header)
        if sanitized_loc:
            selected_headers["location"] = sanitized_loc
        if loc_ue_present:
            ue_ctx_present = True
            if not ue_ctx_type:
                ue_ctx_type = loc_ue_type

    http2 = {
        "stream_id": stream_id,
        "frame_type": frame_type,
        "method": method_upper,
        "scheme": scheme,
        "authority": authority,
        "path": path,
        "status": status,
        "content_type": content_type,
        "content_length": content_length,
    }

    limitations: list[str] = []
    derivations: list[str] = []

    # Check TLS unavailable flag
    tls_encrypted = bool(record.get("tls_encrypted") or record.get("encrypted_payload"))
    if tls_encrypted:
        limitations.append("HTTP/2/SBI payload unavailable due to encrypted/unavailable application data")

    json_body = record.get("json_body") if isinstance(record.get("json_body"), dict) else {}

    # SBI operation parsing
    service_name, api_version, operation, resource, sm_context_ref, support_status = parse_sbi_uri(path, method_upper, json_body)
    n1n2_transfer_ref = path_transfer_ref

    if record.get("service_name"):
        service_name = clean(record.get("service_name"))
    if record.get("operation"):
        operation = clean(record.get("operation"))

    # If Location header is present on a response, extract smContextRef or n1n2_transfer_ref
    if loc_header and not sm_context_ref:
        loc_ref = extract_sm_context_ref_from_location(loc_header)
        if loc_ref:
            sm_context_ref = loc_ref
            derivations.append("sm_context_ref_from_location")
    if loc_transfer_ref and not n1n2_transfer_ref:
        n1n2_transfer_ref = loc_transfer_ref
        derivations.append("n1n2_transfer_ref_from_location")

    # If Failure Notification, extract n1n2_transfer_ref from n1n2MsgDataUri
    notif_data_uri = clean(json_body.get("n1n2MsgDataUri") or json_body.get("n1n2_msg_data_uri") or record.get("n1n2MsgDataUri"))
    if notif_data_uri:
        sanitized_data_uri, notif_ue_present, notif_ue_type, notif_ref = sanitize_sbi_uri(notif_data_uri)
        if notif_ref:
            n1n2_transfer_ref = notif_ref
        elif sanitized_data_uri:
            n1n2_transfer_ref = sanitized_data_uri
        derivations.append("n1n2_transfer_ref_from_notification_data_uri")
        if notif_ue_present:
            ue_ctx_present = True
            if not ue_ctx_type:
                ue_ctx_type = notif_ue_type

    # Privacy: Check for SUPI, GPSI, PEI in body/record or path
    subscriber_identity_present = False
    subscriber_identity_type: str | None = None
    for id_key, id_type in (("supi", "SUPI"), ("gpsi", "GPSI"), ("pei", "PEI")):
        if id_key in json_body or id_key in record:
            subscriber_identity_present = True
            subscriber_identity_type = id_type
            derivations.append(f"privacy_redaction_{id_key}")
            break

    if ue_ctx_present:
        subscriber_identity_present = True
        if not subscriber_identity_type:
            subscriber_identity_type = ue_ctx_type
        derivations.append("privacy_redaction_ue_context_id")

    privacy = {
        "subscriber_identity_present": subscriber_identity_present,
        "subscriber_identity_type": subscriber_identity_type,
    }

    # Bounded Session Management Metadata
    raw_psi = json_body.get("pduSessionId") or json_body.get("pdu_session_id") or record.get("pdu_session_id")
    pdu_session_id = parse_int(raw_psi, "pdu_session_id", minimum=1, maximum=255)

    dnn = clean(json_body.get("dnn") or record.get("dnn"))

    raw_snssai = json_body.get("sNssai") or json_body.get("snssai") or record.get("snssai")
    snssai = None
    if isinstance(raw_snssai, dict):
        sst = parse_int(raw_snssai.get("sst"), "sst", minimum=0, maximum=255)
        sd = clean(raw_snssai.get("sd"))
        if sst is not None:
            snssai = {"sst": sst, "sd": sd}

    request_type = clean(json_body.get("requestType") or json_body.get("request_type") or record.get("request_type"))
    access_type = clean(json_body.get("anType") or json_body.get("accessType") or json_body.get("access_type") or record.get("access_type"))
    rat_type = clean(json_body.get("ratType") or json_body.get("rat_type") or record.get("rat_type"))
    up_connection_state = clean(json_body.get("upCnxState") or json_body.get("up_connection_state") or record.get("up_connection_state"))
    n2_sm_info_type = clean(json_body.get("n2SmInfoType") or json_body.get("n2_sm_info_type") or record.get("n2_sm_info_type"))

    # If response body has smContextRef directly
    if not sm_context_ref:
        body_ref = clean(json_body.get("smContextRef") or json_body.get("sm_context_ref"))
        if body_ref:
            sm_context_ref = body_ref
            derivations.append("sm_context_ref_from_body")

    # Bounded Namf_Communication Metadata
    n1_class = None
    n1_cid = None
    n1_container = json_body.get("n1MessageContainer") or record.get("n1MessageContainer")
    if isinstance(n1_container, dict):
        n1_class = clean(n1_container.get("n1MessageClass") or record.get("n1MessageClass"))
        content_obj = n1_container.get("n1MessageContent")
        if isinstance(content_obj, dict):
            n1_cid = clean(content_obj.get("contentId") or content_obj.get("content_id"))
        elif clean(n1_container.get("contentId")):
            n1_cid = clean(n1_container.get("contentId"))

    n2_class = None
    n2_cid = None
    n2_container = json_body.get("n2InfoContainer") or record.get("n2InfoContainer")
    if isinstance(n2_container, dict):
        n2_class = clean(n2_container.get("n2InformationClass") or record.get("n2InformationClass"))
        sm_info = n2_container.get("smInfo")
        if isinstance(sm_info, dict):
            if pdu_session_id is None:
                pdu_session_id = parse_int(sm_info.get("pduSessionId") or sm_info.get("pdu_session_id"))
            if not n2_sm_info_type:
                n2_sm_info_type = clean(sm_info.get("n2SmInfoType") or sm_info.get("n2_sm_info_type"))
            n2_content_obj = sm_info.get("n2InfoContent")
            if isinstance(n2_content_obj, dict):
                n2_cid = clean(n2_content_obj.get("contentId") or n2_content_obj.get("content_id"))
        elif clean(n2_container.get("contentId")):
            n2_cid = clean(n2_container.get("contentId"))

    notif_uri = clean(json_body.get("n1n2FailureTxfNotifURI") or json_body.get("n1n2_failure_txf_notif_uri") or record.get("n1n2FailureTxfNotifURI"))
    transfer_cause = None
    failure_cause = None

    if operation == OP_N1N2_MESSAGE_TRANSFER or (status is not None and (service_name == SERVICE_NAMF_COMMUNICATION or loc_transfer_ref)):
        transfer_cause = clean(json_body.get("cause") or record.get("cause"))
        if transfer_cause:
            derivations.append(f"transfer_cause_{transfer_cause}")
    elif operation == OP_N1N2_TRANSFER_FAILURE_NOTIFICATION:
        failure_cause = clean(json_body.get("cause") or record.get("cause"))
        if failure_cause:
            derivations.append(f"failure_cause_{failure_cause}")

    namf_communication = None
    if service_name == SERVICE_NAMF_COMMUNICATION or operation in (OP_N1N2_MESSAGE_TRANSFER, OP_N1N2_TRANSFER_FAILURE_NOTIFICATION) or ue_ctx_present:
        namf_communication = {
            "ue_context_id_present": ue_ctx_present,
            "ue_context_id_type": ue_ctx_type,
            "n1_message_class": n1_class,
            "n2_information_class": n2_class,
            "n2_sm_info_type": n2_sm_info_type,
            "n1_content_id": n1_cid,
            "n2_content_id": n2_cid,
            "failure_notification_uri_present": bool(notif_uri),
            "transfer_cause": transfer_cause,
            "failure_cause": failure_cause,
        }

    session_management = {
        "pdu_session_id": pdu_session_id,
        "dnn": dnn,
        "snssai": snssai,
        "request_type": request_type,
        "access_type": access_type,
        "rat_type": rat_type,
        "up_connection_state": up_connection_state,
        "n2_sm_info_type": n2_sm_info_type,
    }

    # Multipart Content-ID binding
    n1_ref = None
    n1_obj = json_body.get("n1SmMsg") or record.get("n1SmMsg")
    if isinstance(n1_obj, dict):
        n1_ref = clean(n1_obj.get("contentId") or n1_obj.get("content_id"))
    if not n1_ref and n1_cid:
        n1_ref = n1_cid

    n2_ref = None
    n2_obj = json_body.get("n2SmInfo") or record.get("n2SmInfo")
    if isinstance(n2_obj, dict):
        n2_ref = clean(n2_obj.get("contentId") or n2_obj.get("content_id"))
    if not n2_ref and n2_cid:
        n2_ref = n2_cid

    raw_multipart = record.get("multipart_parts") or []
    if not isinstance(raw_multipart, list):
        raw_multipart = []

    multipart_parts = bind_multipart_parts(raw_multipart, n1_ref, n2_ref, limitations, n1_message_class=n1_class, n2_info_class=n2_class)
    if multipart_parts:
        derivations.append("multipart_content_id_binding")

    # ProblemDetails and service errors
    problem_details = None
    prob_src = record.get("problem_details")
    if not prob_src and isinstance(json_body.get("error"), dict):
        prob_src = json_body["error"]
        service_error_type = clean(record.get("service_error_type") or "SmContextCreateError" if operation == OP_CREATE_SM_CONTEXT else "SmContextUpdateError")
    elif not prob_src and (status is not None and status >= 400):
        prob_src = json_body if json_body else None
        service_error_type = clean(record.get("service_error_type") or "ProblemDetails")
    else:
        service_error_type = clean(record.get("service_error_type") or "ProblemDetails") if prob_src else None

    if isinstance(prob_src, dict):
        prob_status = parse_int(prob_src.get("status") or status, "problem_status", minimum=100, maximum=599)
        prob_cause = clean(prob_src.get("cause"))
        prob_title = clean(prob_src.get("title"))
        raw_invalid = prob_src.get("invalidParams") or prob_src.get("invalid_params")
        invalid_params = None
        if isinstance(raw_invalid, list):
            invalid_params = []
            for item in raw_invalid:
                if isinstance(item, dict) and item.get("param"):
                    invalid_params.append({"param": str(item["param"]).strip(), "reason": clean(item.get("reason"))})
        problem_details = {
            "status": prob_status,
            "cause": prob_cause,
            "title": prob_title,
            "invalid_params": invalid_params,
            "service_error_type": service_error_type,
        }
        derivations.append("problem_details_extracted")

    # Transport errors
    transport_error = None
    raw_rst = record.get("rst_stream_error") if record.get("rst_stream_error") is not None else record.get("http2.rst_stream.error")
    raw_goaway = record.get("goaway_error") if record.get("goaway_error") is not None else record.get("http2.goaway.error")
    if frame_type == "RST_STREAM" or raw_rst is not None:
        err_code = raw_rst if raw_rst is not None else clean(record.get("error_code"))
        transport_error = {
            "type": "RST_STREAM",
            "error_code": err_code,
            "last_stream_id": None,
            "debug_data_present": None,
        }
    elif frame_type == "GOAWAY" or raw_goaway is not None:
        raw_last_sid = record.get("last_stream_id") if record.get("last_stream_id") is not None else record.get("http2.goaway.last_streamid")
        last_sid = parse_int(raw_last_sid, "last_stream_id")
        debug_present = bool(record.get("debug_data_present"))
        err_code = raw_goaway if raw_goaway is not None else clean(record.get("error_code"))
        transport_error = {
            "type": "GOAWAY",
            "error_code": err_code,
            "last_stream_id": last_sid,
            "debug_data_present": debug_present,
        }

    # Result labeling
    if tls_encrypted:
        result = "PAYLOAD_UNAVAILABLE"
    elif frame_type == "RST_STREAM" or (transport_error and transport_error["type"] == "RST_STREAM"):
        result = "RESET"
    elif frame_type == "GOAWAY" or (transport_error and transport_error["type"] == "GOAWAY"):
        result = "GOAWAY"
    elif frame_type in ("SETTINGS", "PING", "WINDOW_UPDATE"):
        result = "CONTROL"
    elif status == 202 and (operation == OP_N1N2_MESSAGE_TRANSFER or service_name == SERVICE_NAMF_COMMUNICATION or transfer_cause):
        result = "N1N2_TRANSFER_ACCEPTED_PENDING"
        derivations.append("n1n2_transfer_accepted_pending")
    elif operation == OP_N1N2_TRANSFER_FAILURE_NOTIFICATION and method_upper == "POST":
        result = "FAILURE_NOTIFICATION"
    elif status is not None:
        if status >= 400:
            result = "HTTP_ERROR"
        else:
            result = "RESPONSE"
            if operation == OP_N1N2_TRANSFER_FAILURE_NOTIFICATION and status == 204:
                derivations.append("failure_notification_acknowledged")
    elif method_upper is not None:
        result = "REQUEST"
    else:
        result = None

    if operation:
        derivations.append(f"sbi_operation_{operation}")
    if status is not None:
        derivations.append(f"http_status_{status}")

    sbi = {
        "service_name": service_name,
        "api_version": api_version,
        "operation": operation,
        "resource": resource,
        "sm_context_ref": sm_context_ref,
        "selected_headers": selected_headers,
    }
    if n1n2_transfer_ref is not None:
        sbi["n1n2_transfer_ref"] = n1n2_transfer_ref

    evidence = {
        "level": "OBSERVED",
        "source": f"capture:{capture_file}#frame={frame_number}; stream={stream_id}",
    }

    event: dict[str, Any] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "connection": connection,
        "http2": http2,
        "sbi": sbi,
        "session_management": session_management,
        "privacy": privacy,
        "multipart_parts": multipart_parts,
        "problem_details": problem_details,
        "transport_error": transport_error,
        "support_status": support_status,
        "result": result,
        "evidence": evidence,
        "derivations": sorted(set(derivations)),
        "limitations": sorted(set(limitations)),
    }
    if namf_communication is not None:
        event["namf_communication"] = namf_communication

    return event


def connection_context(event: dict[str, Any]) -> str:
    """Derive connection context string from an event; never rely on stream ID alone."""
    conn = event.get("connection") or {}
    if conn.get("tcp_stream") is not None:
        return f"tcp-stream:{conn['tcp_stream']}"
    if conn.get("connection_id") is not None:
        return f"conn:{conn['connection_id']}"
    src = conn.get("source_address") or "unknown-src"
    dst = conn.get("destination_address") or "unknown-dst"
    sport = conn.get("source_port") or 0
    dport = conn.get("destination_port") or 0
    endpoints = sorted([f"{src}:{sport}", f"{dst}:{dport}"])
    return f"endpoints:{endpoints[0]}-{endpoints[1]}"


def transaction_key(event: dict[str, Any]) -> str:
    """DERIVED transaction key scoped by connection context and stream ID."""
    capture = event.get("capture_file") or "unknown-capture"
    conn_ctx = connection_context(event)
    stream_id = event.get("http2", {}).get("stream_id")
    sid_str = f"stream{stream_id}" if stream_id is not None else "stream-none"
    return f"sbi-tx:{capture}:{conn_ctx}:{sid_str}"


def correlate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Correlate detailed SBI HTTP/2 events into transactions scoped by connection and stream ID."""
    capture_file = events[0].get("capture_file") if events else None

    groups: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    unbound_events: list[dict[str, Any]] = []

    for event in events:
        sid = event.get("http2", {}).get("stream_id")
        ftype = event.get("http2", {}).get("frame_type")

        # Control frames or stream 0 cannot be request/response transactions
        if sid is None or sid == 0 or ftype in ("SETTINGS", "PING", "WINDOW_UPDATE") or event.get("result") == "CONTROL":
            unbound_events.append({
                "frame_number": event.get("frame_number"),
                "timestamp": event.get("timestamp"),
                "stream_id": sid,
                "support_status": event.get("support_status"),
                "limitation": "HTTP/2 control frame or connection-level signaling outside multiplexed stream transactions",
            })
            continue

        c_file = str(event.get("capture_file") or "unknown-capture")
        conn_ctx = connection_context(event)
        groups.setdefault((c_file, conn_ctx, sid), []).append(event)

    completed_transactions: list[dict[str, Any]] = []
    open_transactions: list[dict[str, Any]] = []

    for (c_file, conn_ctx, sid), stream_events in sorted(groups.items(), key=lambda x: (x[0][0], x[0][1], x[0][2])):
        # Sort events by frame number to handle out-of-order input deterministically
        sorted_stream = sorted(stream_events, key=lambda e: e.get("frame_number") or 0)

        request_frames: list[int] = []
        response_frames: list[int] = []
        service: str | None = None
        operation: str | None = None
        method: str | None = None
        path: str | None = None
        status: int | None = None
        sm_context_ref: str | None = None
        n1n2_transfer_ref: str | None = None
        transport_error: dict[str, Any] | None = None
        tx_limitations: list[str] = []

        for ev in sorted_stream:
            fn = ev.get("frame_number")
            h2 = ev.get("http2") or {}
            sb = ev.get("sbi") or {}

            if ev.get("result") in ("REQUEST", "FAILURE_NOTIFICATION") or (h2.get("method") and not h2.get("status")):
                if fn is not None:
                    request_frames.append(fn)
                if not method:
                    method = h2.get("method")
                if not path:
                    path = h2.get("path")
                if not service:
                    service = sb.get("service_name")
                if not operation:
                    operation = sb.get("operation")
                if not sm_context_ref:
                    sm_context_ref = sb.get("sm_context_ref")
                if not n1n2_transfer_ref:
                    n1n2_transfer_ref = sb.get("n1n2_transfer_ref")

            elif ev.get("result") in ("RESPONSE", "HTTP_ERROR", "N1N2_TRANSFER_ACCEPTED_PENDING") or h2.get("status"):
                if fn is not None:
                    response_frames.append(fn)
                if status is None:
                    status = h2.get("status")
                # Transition: response Location header can provide the newly assigned sm_context_ref or n1n2_transfer_ref
                if not sm_context_ref and sb.get("sm_context_ref"):
                    sm_context_ref = sb.get("sm_context_ref")
                if not n1n2_transfer_ref and sb.get("n1n2_transfer_ref"):
                    n1n2_transfer_ref = sb.get("n1n2_transfer_ref")
                if not service and sb.get("service_name"):
                    service = sb.get("service_name")
                if not operation and sb.get("operation"):
                    operation = sb.get("operation")

            if ev.get("transport_error"):
                transport_error = ev["transport_error"]

            for lim in ev.get("limitations") or []:
                if lim not in tx_limitations:
                    tx_limitations.append(lim)

        tx_key = f"sbi-tx:{c_file}:{conn_ctx}:stream{sid}"

        tx_record = {
            "transaction_key": tx_key,
            "capture_file": c_file,
            "connection_context": conn_ctx,
            "stream_id": sid,
            "service": service,
            "operation": operation,
            "method": method,
            "path": path,
            "status": status,
            "sm_context_ref": sm_context_ref,
            "request_frames": request_frames,
            "response_frames": response_frames,
            "correlation_strength": "STRONG" if (request_frames and response_frames) else "PARTIAL",
            "transport_error": transport_error,
            "limitations": tx_limitations,
        }
        if n1n2_transfer_ref is not None:
            tx_record["n1n2_transfer_ref"] = n1n2_transfer_ref

        if request_frames and response_frames:
            completed_transactions.append(tx_record)
        else:
            if request_frames and not response_frames:
                tx_limitations.append("request observed without matching response frame in capture")
            elif response_frames and not request_frames:
                tx_limitations.append("response observed without preceding request frame in capture")
            open_transactions.append(tx_record)

    all_transactions = completed_transactions + open_transactions
    unbound_callbacks: list[dict[str, Any]] = []

    # Identify failure notification request events
    for event in events:
        sb = event.get("sbi") or {}
        if sb.get("operation") == OP_N1N2_TRANSFER_FAILURE_NOTIFICATION and event.get("result") == "FAILURE_NOTIFICATION":
            cb_fn = event.get("frame_number")
            cb_ts = event.get("timestamp")
            cb_ref = sb.get("n1n2_transfer_ref")
            namf_obj = event.get("namf_communication") or {}
            cb_cause = namf_obj.get("failure_cause")

            cb_sid = event.get("http2", {}).get("stream_id")
            cb_conn = connection_context(event)
            cb_cfile = str(event.get("capture_file") or "unknown-capture")
            stream_evs = groups.get((cb_cfile, cb_conn, cb_sid), [])
            acknowledged = any(e.get("http2", {}).get("status") == 204 for e in stream_evs)

            matched_tx = None
            if cb_ref:
                for tx in all_transactions:
                    if tx.get("operation") == OP_N1N2_MESSAGE_TRANSFER:
                        t_ref = tx.get("n1n2_transfer_ref")
                        if t_ref and (t_ref == cb_ref or t_ref.endswith(f"/{cb_ref}") or cb_ref.endswith(f"/{t_ref}")):
                            matched_tx = tx
                            break

            if matched_tx is not None:
                matched_tx["failure_notification"] = {
                    "frame_number": cb_fn,
                    "timestamp": cb_ts,
                    "cause": cb_cause or "FAILURE_CAUSE_UNSPECIFIED",
                    "transfer_ref": cb_ref,
                    "acknowledged": acknowledged,
                }
            else:
                lim = (
                    "failure notification has no matching prior transfer transaction reference in capture"
                    if cb_ref
                    else "failure notification lacks transfer resource reference"
                )
                unbound_callbacks.append({
                    "frame_number": cb_fn,
                    "timestamp": cb_ts,
                    "cause": cb_cause,
                    "transfer_ref": cb_ref,
                    "limitation": lim,
                })

    summary_limitations: list[str] = []
    if open_transactions:
        summary_limitations.append(f"{len(open_transactions)} open or partial transaction(s) observed")

    summary: dict[str, Any] = {
        "capture_file": capture_file,
        "transactions": completed_transactions,
        "open_transactions": open_transactions,
        "unbound_events": unbound_events,
        "limitations": summary_limitations,
    }
    if unbound_callbacks:
        summary["unbound_callbacks"] = unbound_callbacks

    return summary


def project_trace_event(event: dict[str, Any]) -> dict[str, Any]:
    """Project a detailed SBI HTTP/2 event into the shared trace-event contract."""
    h2 = event.get("http2") or {}
    sb = event.get("sbi") or {}
    sm = event.get("session_management") or {}
    conn = event.get("connection") or {}
    prob = event.get("problem_details") or {}
    namf = event.get("namf_communication") or {}

    operation = sb.get("operation")
    method = h2.get("method")
    status = h2.get("status")

    if operation == OP_N1N2_TRANSFER_FAILURE_NOTIFICATION:
        if method:
            msg_type = "N1N2Transfer Failure Notification"
        elif status == 204:
            msg_type = "N1N2Transfer Failure Notification Acknowledged"
        elif status:
            msg_type = f"N1N2Transfer Failure Notification HTTP {status}"
        else:
            msg_type = "N1N2Transfer Failure Notification"
    elif operation == OP_N1N2_MESSAGE_TRANSFER:
        if method:
            msg_type = "N1N2MessageTransfer Request"
        elif status == 200:
            msg_type = "N1N2MessageTransfer 200 OK"
        elif status == 202:
            msg_type = "N1N2MessageTransfer 202 Accepted"
        elif status and status >= 400:
            msg_type = f"N1N2MessageTransfer HTTP {status}"
        elif status:
            msg_type = "N1N2MessageTransfer Response"
        else:
            msg_type = "N1N2MessageTransfer"
    elif operation:
        if method:
            msg_type = f"{operation} Request"
        elif status:
            msg_type = f"{operation} Response"
        else:
            msg_type = operation
    elif method and h2.get("path"):
        msg_type = f"{method} {h2.get('path')}"
    elif status:
        msg_type = f"HTTP {status}"
    else:
        msg_type = h2.get("frame_type") or "HTTP2"

    session: dict[str, Any] = {}
    # PDU Session ID is projected only when directly and unambiguously present
    if sm.get("pdu_session_id") is not None:
        session["pdu_session_id"] = sm["pdu_session_id"]
    if sm.get("dnn") is not None:
        session["dnn"] = sm["dnn"]

    cause_val = prob.get("cause") or namf.get("transfer_cause") or namf.get("failure_cause")
    result: dict[str, Any] = {
        "status": event.get("result"),
        "cause": cause_val,
        "code": prob.get("status") or status,
    }

    projected: dict[str, Any] = {
        "timestamp": event["timestamp"],
        "protocol": "3GPP-SBI",
        "interface": "N11",
        "procedure": operation,
        "message_type": msg_type,
        "packet": {
            "frame_number": event.get("frame_number"),
            "capture_file": event.get("capture_file"),
        },
        "evidence": {
            "level": "DERIVED",
            "source": f"sbi-http2-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }

    if conn.get("source_address") or conn.get("source_port") is not None:
        projected["source"] = {
            "address": conn.get("source_address"),
            "port": conn.get("source_port"),
            "network_function": None,
        }
    if conn.get("destination_address") or conn.get("destination_port") is not None:
        projected["destination"] = {
            "address": conn.get("destination_address"),
            "port": conn.get("destination_port"),
            "network_function": None,
        }

    if session:
        projected["session"] = session

    if result["status"] or result["cause"] or result["code"]:
        projected["result"] = result

    if h2.get("stream_id") is not None:
        projected["correlation"] = {
            "stream_id": str(h2["stream_id"]),
            "transaction_id": transaction_key(event),
        }

    return projected


def records_for_input(input_path: Path, input_format: str = "auto") -> tuple[list[dict[str, Any]], str | None]:
    """Load records from structured fields JSONL or run TShark extraction."""
    if not input_path.is_file():
        raise InputError(f"input file does not exist: {input_path}")

    # Determine format
    suffix = input_path.suffix.lower()
    is_capture = suffix in (".pcap", ".pcapng", ".cap")
    if input_format == "capture" or (input_format == "auto" and is_capture):
        return run_tshark_extraction(input_path)

    # Fields JSONL
    records: list[dict[str, Any]] = []
    try:
        text = input_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InputError(f"unable to read input file: {input_path}: {exc}") from exc

    for line_idx, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise InputError(f"malformed JSON on line {line_idx} of {input_path}: {exc}") from exc
        if not isinstance(item, dict):
            raise InputError(f"record on line {line_idx} of {input_path} is not a JSON object")
        records.append(item)

    if not records:
        raise InputError(f"input file contains no records: {input_path}")
    return records, None


def run_tshark_extraction(capture_path: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Execute TShark to extract HTTP/2, multipart, JSON, and TCP fields."""
    cmd = ["tshark", "-r", str(capture_path), "-T", "fields", "-E", "separator=\t", "-E", "header=y", "-E", "occurrence=a"]
    for field in FIELDS:
        cmd.extend(["-e", field])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable(f"tshark is not installed or not in PATH: {exc}") from exc

    if proc.returncode != 0:
        raise TsharkError(f"tshark execution failed (exit code {proc.returncode}): {proc.stderr}")

    lines = proc.stdout.splitlines()
    if not lines:
        return [], None

    reader = csv.DictReader(lines, delimiter="\t")
    records: list[dict[str, Any]] = []
    for row in reader:
        records.append(dict(row))

    return records, "tshark-extracted"
