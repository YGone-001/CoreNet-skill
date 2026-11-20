#!/usr/bin/env python3
"""Bounded RFC 8866 SDP structural evidence parser.

The parser consumes explicitly supplied SDP message bodies and provenance
metadata. It publishes structural observations only: no offer/answer pairing,
no RTP or media outcome, no IMS session verdict and no raw subscriber, address,
credential or key material.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from endpoint_reference import (
    EndpointError,
    EndpointKeyError,
    endpoint_context_reference,
    endpoint_reference,
    is_context_reference,
    is_endpoint_reference,
)

ANALYSIS_NAME = "sdp-rtp"
ANALYSIS_VERSION = "0.2.0"
CAPABILITY = "bounded SDP structural evidence with optional endpoint references"
PARSER_VERSION = "0.2.0"
EVENT_SCHEMA_VERSION = "1.1.0"

MAX_BODY_BYTES = 65536
MAX_RECORDS = 512
MAX_MEDIA_SECTIONS = 64
MAX_LINE_LENGTH = 8192
MAX_ATTRIBUTES = 256
MAX_FORMATS = 64
MAX_LIST_ITEMS = 32
MAX_PARAMETER_ITEMS = 32

REFERENCE_PATTERN = re.compile(r"^[a-z][a-z0-9-]*:.+:[0-9]+\.[0-9]+$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._/-]{1,64}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
DOMAIN_NAME = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
LINE_PATTERN = re.compile(r"^([a-z])=(.*)$", re.DOTALL)

DIRECTION_VALUES = ("sendrecv", "sendonly", "recvonly", "inactive")
KNOWN_MEDIA = {"audio", "video", "text", "application", "message", "image"}
SENSITIVE_ATTRIBUTES = {
    "ice-ufrag",
    "ice-pwd",
    "candidate",
    "remote-candidates",
    "fingerprint",
    "crypto",
    "identity",
    "ice-pwd",
}
SAFE_METADATA_ATTRIBUTES = {
    "rtpmap",
    "fmtp",
    "mid",
    "rtcp",
    "rtcp-mux",
    "group",
    "ptime",
    "maxptime",
    "framerate",
    "quality",
    "tool",
    "type",
    "charset",
    "sdplang",
    "lang",
    "setup",
    "ice-options",
    "ice-lite",
    "end-of-candidates",
    "bundle-only",
}
SAFE_FMTP_PARAMETERS = {
    "packetization-mode",
    "profile-level-id",
    "level-asymmetry-allowed",
    "max-fs",
    "max-cpb",
    "max-dpb",
    "max-br",
    "max-fr",
    "mode",
    "width",
    "height",
    "framerate",
    "profile",
    "level",
    "streams",
    "sprop-parameter-sets",
}
SAFE_VALUE = re.compile(r"^[A-Za-z0-9._+,/-]{1,128}$")


class InputError(ValueError):
    """Raised when the supplied SDP input contract is malformed."""


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


def _safe_token(value: str) -> str | None:
    return value if SAFE_TOKEN.fullmatch(value) else None


def _safe_name(value: str) -> str | None:
    return value if SAFE_NAME.fullmatch(value) else None


def _parse_int(value: str, minimum: int = 0, maximum: int | None = None) -> int | None:
    if not re.fullmatch(r"[0-9]+", value):
        return None
    number = int(value)
    if number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def _address_info(value: str, address_type: str) -> dict[str, Any]:
    """Classify an address without publishing it."""
    result: dict[str, Any] = {
        "address_present": bool(value),
        "address_redacted": True,
        "address_family": "UNKNOWN",
        "address_class": "UNKNOWN",
        "multicast": False,
        "ttl": None,
        "address_count": None,
        "valid": False,
    }
    if not value:
        return result
    base = value.split("/", 1)[0]
    suffixes = value.split("/")[1:]
    family = {"IP4": "IPv4", "IP6": "IPv6"}.get(address_type, "UNKNOWN")
    result["address_family"] = family
    if suffixes:
        if address_type == "IP4" and len(suffixes) >= 1 and re.fullmatch(r"[0-9]+", suffixes[0]):
            ttl = _parse_int(suffixes[0], 0, 255)
            result["ttl"] = ttl
            if ttl is None:
                result["address_class"] = "INVALID"
                return result
        if len(suffixes) >= 2 and re.fullmatch(r"[0-9]+", suffixes[-1]):
            count = _parse_int(suffixes[-1], 1, 4096)
            result["address_count"] = count
            if count is None:
                result["address_class"] = "INVALID"
                return result
    try:
        address = ipaddress.ip_address(base)
    except ValueError:
        if DOMAIN_NAME.fullmatch(base):
            result["address_class"] = "DOMAIN_NAME"
            result["valid"] = True
            return result
        result["address_class"] = "INVALID"
        return result
    actual_family = "IPv4" if address.version == 4 else "IPv6"
    if family not in ("UNKNOWN", actual_family):
        result["address_class"] = "FAMILY_MISMATCH"
        return result
    result["address_family"] = actual_family
    result["multicast"] = address.is_multicast
    result["valid"] = True
    if address.is_multicast:
        result["address_class"] = "MULTICAST"
    elif address.is_loopback:
        result["address_class"] = "LOOPBACK"
    elif address.is_link_local:
        result["address_class"] = "LINK_LOCAL"
    elif address.is_unspecified:
        result["address_class"] = "UNSPECIFIED"
    elif address.is_private:
        result["address_class"] = "PRIVATE"
    else:
        result["address_class"] = "GLOBAL_UNICAST"
    if address_type == "IP4" and address.is_multicast and result["ttl"] is None:
        result["address_class"] = "MULTICAST_TTL_MISSING"
        result["valid"] = False
    if address_type == "IP6" and address.is_multicast and suffixes:
        result["address_class"] = "MULTICAST_IPV6_TTL_NOT_ALLOWED"
        result["valid"] = False
    if not address.is_multicast and suffixes:
        result["address_class"] = "UNICAST_MULTIPLE_ADDRESSES_INVALID"
        result["valid"] = False
    return result


def _connection(value: str) -> tuple[dict[str, Any] | None, list[str]]:
    parts = value.split()
    if len(parts) < 3:
        return None, ["CONNECTION_FIELD_MALFORMED"]
    net_type, address_type = parts[0], parts[1]
    base_address = parts[2].split("/", 1)[0]
    address = _address_info(parts[2], address_type)
    reasons: list[str] = []
    if not address["valid"]:
        reasons.append("CONNECTION_ADDRESS_INVALID")
    return {
        "net_type": _safe_token(net_type) or "UNKNOWN",
        "address_type": address_type if address_type in ("IP4", "IP6") else "UNKNOWN",
        "address_family": address["address_family"],
        "address_class": address["address_class"],
        "multicast": address["multicast"],
        "ttl": address["ttl"],
        "address_count": address["address_count"],
        "address_present": address["address_present"],
        "address_redacted": True,
        "_raw_address": base_address,
    }, reasons


def _origin(value: str) -> tuple[dict[str, Any] | None, list[str]]:
    parts = value.split()
    if len(parts) != 6:
        return None, ["ORIGIN_FIELD_MALFORMED"]
    username, session_id, session_version, net_type, address_type, address = parts
    version = _parse_int(session_version)
    address_info = _address_info(address, address_type)
    reasons: list[str] = []
    if version is None:
        reasons.append("ORIGIN_SESSION_VERSION_INVALID")
    if not address_info["valid"]:
        reasons.append("ORIGIN_ADDRESS_INVALID")
    return {
        "username_present": bool(username),
        "username_length": len(username),
        "username_is_dash": username == "-",
        "username_redacted": True,
        "session_id_present": bool(session_id),
        "session_id_length": len(session_id),
        "session_id_numeric": bool(re.fullmatch(r"[0-9]+", session_id)),
        "session_id_redacted": True,
        "session_version": version,
        "net_type": _safe_token(net_type) or "UNKNOWN",
        "address_type": address_type if address_type in ("IP4", "IP6") else "UNKNOWN",
        "address_family": address_info["address_family"],
        "address_class": address_info["address_class"],
        "address_redacted": True,
    }, reasons


def _time(value: str) -> tuple[dict[str, Any] | None, list[str]]:
    parts = value.split()
    if len(parts) != 2:
        return None, ["TIME_FIELD_MALFORMED"]
    start = _parse_int(parts[0])
    stop = _parse_int(parts[1])
    if start is None or stop is None:
        return None, ["TIME_VALUE_INVALID"]
    return {"start": start, "stop": stop, "unbounded": stop == 0}, []


def _bandwidth(value: str) -> tuple[dict[str, Any] | None, list[str]]:
    if ":" not in value:
        return None, ["BANDWIDTH_FIELD_MALFORMED"]
    name, _, number = value.partition(":")
    safe = _safe_token(name)
    parsed = _parse_int(number)
    if safe is None or parsed is None:
        return None, ["BANDWIDTH_VALUE_INVALID"]
    return {"type": safe, "value": parsed}, []


def _attribute(value: str) -> tuple[str, str | None, bool]:
    name, separator, attribute_value = value.partition(":")
    return name, attribute_value if separator else None, bool(separator)


def _attribute_descriptor(
    name: str,
    value: str | None,
    classification: str,
) -> dict[str, Any]:
    safe = _safe_name(name)
    return {
        "name": safe or "UNNAMED",
        "value_present": value is not None,
        "value_length": len(value or ""),
        "classification": classification,
    }


def _rtpmap(value: str | None) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, ["RTPMAP_VALUE_MISSING"]
    parts = value.split(None, 1)
    if len(parts) != 2:
        return None, ["RTPMAP_FIELD_MALFORMED"]
    payload = _parse_int(parts[0], 0, 127)
    encoding_parts = parts[1].split("/")
    if payload is None or len(encoding_parts) not in (2, 3):
        return None, ["RTPMAP_FIELD_MALFORMED"]
    name = _safe_token(encoding_parts[0])
    clock = _parse_int(encoding_parts[1], 1)
    channels = _parse_int(encoding_parts[2], 1) if len(encoding_parts) == 3 else None
    if name is None or clock is None or (len(encoding_parts) == 3 and channels is None):
        return None, ["RTPMAP_VALUE_INVALID"]
    return {
        "payload_type": payload,
        "encoding_name": name,
        "clock_rate": clock,
        "channels": channels,
    }, []


def _fmtp(value: str | None) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, ["FMTP_VALUE_MISSING"]
    parts = value.split(None, 1)
    if len(parts) != 2:
        return None, ["FMTP_FIELD_MALFORMED"]
    payload = _parse_int(parts[0], 0, 127)
    if payload is None:
        return None, ["FMTP_PAYLOAD_INVALID"]
    parameters: list[dict[str, Any]] = []
    for item in parts[1].split(";"):
        item = item.strip()
        if not item:
            continue
        key, separator, parameter_value = item.partition("=")
        safe_key = _safe_name(key)
        if safe_key is None:
            return None, ["FMTP_PARAMETER_NAME_INVALID"]
        parameter = {
            "name": safe_key,
            "value_present": bool(separator),
            "value_length": len(parameter_value),
            "value_classification": "UNINTERPRETED",
            "safe_value": None,
        }
        if (
            separator
            and safe_key in SAFE_FMTP_PARAMETERS
            and SAFE_VALUE.fullmatch(parameter_value)
        ):
            parameter["value_classification"] = "SAFE_METADATA"
            parameter["safe_value"] = parameter_value
        parameters.append(parameter)
    return {
        "payload_type": payload,
        "parameter_count": len(parameters),
        "parameters": parameters[:MAX_PARAMETER_ITEMS],
        "parameters_omitted": max(0, len(parameters) - MAX_PARAMETER_ITEMS),
        "value_redacted": True,
    }, []


def _rtcp(value: str | None) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, ["RTCP_VALUE_MISSING"]
    parts = value.split()
    port = _parse_int(parts[0], 1, 65535)
    if port is None:
        return None, ["RTCP_PORT_INVALID"]
    address_family = "UNKNOWN"
    address_class = "UNKNOWN"
    if len(parts) >= 4:
        address = _address_info(parts[3], parts[2])
        address_family = address["address_family"]
        address_class = address["address_class"]
    return {
        "port": port,
        "address_family": address_family,
        "address_class": address_class,
        "address_redacted": True,
    }, []


def _group(value: str | None) -> tuple[dict[str, Any] | None, list[str]]:
    if value is None:
        return None, ["GROUP_VALUE_MISSING"]
    parts = value.split()
    if len(parts) < 2:
        return None, ["GROUP_FIELD_MALFORMED"]
    semantics = _safe_token(parts[0])
    mids = [_safe_token(item) for item in parts[1:]]
    if semantics is None or any(item is None for item in mids):
        return None, ["GROUP_VALUE_INVALID"]
    return {
        "semantics": semantics,
        "mids": mids[:MAX_LIST_ITEMS],
        "mids_omitted": max(0, len(mids) - MAX_LIST_ITEMS),
        "reference_status": "PENDING",
    }, []


def _parse_attribute(
    value: str,
    scope: str,
    target: dict[str, Any],
) -> list[str]:
    name, attribute_value, value_present = _attribute(value)
    safe_name = _safe_name(name)
    reasons: list[str] = []
    if safe_name is None:
        reasons.append("ATTRIBUTE_NAME_INVALID")
        descriptor = _attribute_descriptor("UNNAMED", attribute_value, "UNINTERPRETED")
    elif safe_name in DIRECTION_VALUES:
        if attribute_value is None:
            target.setdefault("_directions", []).append(safe_name)
        else:
            reasons.append("DIRECTION_ATTRIBUTE_HAS_VALUE")
            descriptor = _attribute_descriptor(safe_name, attribute_value, "UNINTERPRETED")
            target.setdefault("attributes", []).append(descriptor)
            return reasons
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "rtpmap":
        parsed, item_reasons = _rtpmap(attribute_value)
        reasons.extend(item_reasons)
        if parsed:
            target.setdefault("rtpmap", []).append(parsed)
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "fmtp":
        parsed, item_reasons = _fmtp(attribute_value)
        reasons.extend(item_reasons)
        if parsed:
            target.setdefault("fmtp", []).append(parsed)
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "mid":
        token = _safe_token((attribute_value or "").strip())
        if token is None:
            reasons.append("MID_VALUE_INVALID")
        else:
            target.setdefault("_mids", []).append(token)
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "rtcp":
        parsed, item_reasons = _rtcp(attribute_value)
        reasons.extend(item_reasons)
        if parsed:
            target["rtcp"] = parsed
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "rtcp-mux":
        if value_present:
            reasons.append("RTCP_MUX_HAS_VALUE")
        target["rtcp_mux"] = True
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "group":
        parsed, item_reasons = _group(attribute_value)
        reasons.extend(item_reasons)
        if parsed:
            target.setdefault("groups", []).append(parsed)
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "ptime":
        parsed = _parse_int(attribute_value or "", 1)
        if parsed is None:
            reasons.append("PTIME_VALUE_INVALID")
        else:
            target["ptime"] = parsed
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "maxptime":
        parsed = _parse_int(attribute_value or "", 1)
        if parsed is None:
            reasons.append("MAXPTIME_VALUE_INVALID")
        else:
            target["maxptime"] = parsed
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "setup":
        value_token = _safe_token((attribute_value or "").strip())
        if value_token not in {"active", "passive", "actpass", "holdconn"}:
            reasons.append("SETUP_VALUE_INVALID")
        else:
            target["setup"] = value_token
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "ice-options":
        options = [_safe_token(item) for item in (attribute_value or "").split()]
        if any(item is None for item in options):
            reasons.append("ICE_OPTIONS_VALUE_INVALID")
        target["ice_options"] = [item for item in options if item][:MAX_LIST_ITEMS]
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name == "ice-lite":
        if value_present:
            reasons.append("ICE_LITE_HAS_VALUE")
        target["ice_lite"] = True
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    elif safe_name in SENSITIVE_ATTRIBUTES:
        detail: dict[str, Any] = {
            "sensitive": True,
            "redacted": True,
            "value_length": len(attribute_value or ""),
        }
        if safe_name == "fingerprint":
            parts = (attribute_value or "").split(None, 1)
            if parts and _safe_token(parts[0]):
                detail["hash_function"] = parts[0]
                detail["digest_length"] = len(parts[1]) if len(parts) > 1 else 0
            else:
                reasons.append("FINGERPRINT_VALUE_MALFORMED")
        elif safe_name == "crypto":
            parts = (attribute_value or "").split()
            if parts and _parse_int(parts[0], 1) is not None:
                detail["tag"] = int(parts[0])
            else:
                reasons.append("CRYPTO_TAG_INVALID")
            if len(parts) >= 2 and _safe_token(parts[1]):
                detail["crypto_suite"] = parts[1]
            else:
                reasons.append("CRYPTO_SUITE_INVALID")
            detail["key_material_present"] = len(parts) >= 3
        elif safe_name in {"ice-ufrag", "ice-pwd"}:
            if not (attribute_value or ""):
                reasons.append("ICE_CREDENTIAL_EMPTY")
        elif safe_name == "candidate":
            parts = (attribute_value or "").split()
            if len(parts) < 8:
                reasons.append("ICE_CANDIDATE_MALFORMED")
            detail["candidate_count"] = 1
        target.setdefault("sensitive_attributes", []).append(detail)
        descriptor = _attribute_descriptor(safe_name, attribute_value, "SENSITIVE_REDACTED")
    elif safe_name in SAFE_METADATA_ATTRIBUTES:
        descriptor = _attribute_descriptor(safe_name, attribute_value, "KNOWN_SAFE")
    else:
        target.setdefault("unknown_attributes", []).append(
            _attribute_descriptor(safe_name or "UNNAMED", attribute_value, "UNINTERPRETED")
        )
        descriptor = _attribute_descriptor(safe_name or "UNNAMED", attribute_value, "UNINTERPRETED")
    target.setdefault("attributes", []).append(descriptor)
    if len(target["attributes"]) > MAX_ATTRIBUTES:
        reasons.append("TOO_MANY_ATTRIBUTES")
    return reasons


def _finish_directions(target: dict[str, Any]) -> None:
    directions = _unique(target.pop("_directions", []))
    if len(directions) == 1:
        target["direction"] = directions[0]
    elif len(directions) > 1:
        target["direction"] = "AMBIGUOUS"
        target.setdefault("invalid_reasons", []).append("CONFLICTING_DIRECTION_ATTRIBUTES")
    else:
        target["direction"] = None


def _finish_mids(target: dict[str, Any]) -> list[str]:
    mids = _unique(target.pop("_mids", []))
    if len(mids) > 1:
        target.setdefault("invalid_reasons", []).append("CONFLICTING_MID_ATTRIBUTES")
        target["mid"] = "AMBIGUOUS"
    elif mids:
        target["mid"] = mids[0]
    else:
        target["mid"] = None
    return mids


ICE_ATTRIBUTE_NAMES = frozenset(
    {
        "ice-ufrag",
        "ice-pwd",
        "candidate",
        "remote-candidates",
        "ice-options",
        "ice-lite",
        "end-of-candidates",
    }
)
SUPPORTED_RTP_PROTOCOLS = frozenset({"RTP/AVP", "RTP/AVPF"})
SUPPORTED_ADDRESS_CLASSES = frozenset({"GLOBAL_UNICAST", "PRIVATE", "LOOPBACK"})


def _attribute_names(target: dict[str, Any]) -> set[str]:
    return {
        item.get("name")
        for item in target.get("attributes") or []
        if isinstance(item.get("name"), str)
    }


def _ice_present(session: dict[str, Any], media: dict[str, Any]) -> bool:
    if session.get("ice_options") or session.get("ice_lite"):
        return True
    if media.get("ice_options") or media.get("ice_lite"):
        return True
    return bool(
        (_attribute_names(session) | _attribute_names(media)) & ICE_ATTRIBUTE_NAMES
    )


def _transport_endpoint(
    media: dict[str, Any],
    session: dict[str, Any],
    endpoint_key: bytes,
    capture_sha256: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "endpoint_status": "UNAVAILABLE",
        "endpoint_reference": None,
        "transport": None,
        "address_family": None,
        "reason_codes": [],
    }

    def unavailable(status: str, reason: str) -> dict[str, Any]:
        result["endpoint_status"] = status
        result["reason_codes"].append(reason)
        return result

    if media.get("media_type_supported") is False:
        return unavailable("OUT_OF_SCOPE", "UNSUPPORTED_MEDIA_TYPE")
    protocol = str(media.get("protocol") or "").upper()
    if protocol not in SUPPORTED_RTP_PROTOCOLS:
        return unavailable("OUT_OF_SCOPE", "UNSUPPORTED_TRANSPORT_PROTOCOL")
    if media.get("port_count") != 1:
        return unavailable("OUT_OF_SCOPE", "UNSUPPORTED_PORT_COUNT")
    port = media.get("port")
    if port == 0:
        return unavailable("OUT_OF_SCOPE", "MEDIA_DISABLED")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return unavailable("UNAVAILABLE", "RTP_PORT_INVALID")
    if "bundle-only" in _attribute_names(media):
        return unavailable("OUT_OF_SCOPE", "BUNDLE_ONLY_ENDPOINT_UNSUPPORTED")
    if _ice_present(session, media):
        return unavailable("UNAVAILABLE", "ICE_SELECTED_TRANSPORT_NOT_ESTABLISHED")

    media_connection = media.get("connection")
    if media_connection is not None:
        connection = media_connection
        secondary_count = media.get("secondary_connection_count", 0)
        invalid_reasons = media.get("invalid_reasons") or []
    else:
        connection = session.get("connection")
        secondary_count = session.get("secondary_connection_count", 0)
        invalid_reasons = session.get("invalid_reasons") or []
    if connection is None:
        return unavailable("UNAVAILABLE", "CONNECTION_NOT_OBSERVED")
    if secondary_count or "MULTIPLE_CONNECTION_LINES" in invalid_reasons:
        return unavailable("UNAVAILABLE", "AMBIGUOUS_CONNECTION")
    if connection.get("net_type") != "IN":
        return unavailable("OUT_OF_SCOPE", "UNSUPPORTED_NETWORK_TYPE")
    address_type = connection.get("address_type")
    if address_type not in {"IP4", "IP6"}:
        return unavailable("OUT_OF_SCOPE", "UNSUPPORTED_ADDRESS_TYPE")
    address_class = connection.get("address_class")
    if address_class == "DOMAIN_NAME":
        return unavailable("OUT_OF_SCOPE", "DOMAIN_NAME_UNRESOLVED")
    if address_class == "MULTICAST" or str(address_class).startswith("MULTICAST"):
        return unavailable("OUT_OF_SCOPE", "MULTICAST_ADDRESS_UNSUPPORTED")
    if address_class == "UNSPECIFIED":
        return unavailable("OUT_OF_SCOPE", "UNSPECIFIED_ADDRESS_UNSUPPORTED")
    if address_class == "LINK_LOCAL":
        return unavailable("OUT_OF_SCOPE", "LINK_LOCAL_ADDRESS_UNSUPPORTED")
    if address_class not in SUPPORTED_ADDRESS_CLASSES:
        return unavailable("UNAVAILABLE", "CONNECTION_ADDRESS_INVALID")
    raw_address = connection.get("_raw_address")
    if not isinstance(raw_address, str) or not raw_address:
        return unavailable("UNAVAILABLE", "CONNECTION_ADDRESS_INVALID")
    try:
        reference = endpoint_reference(
            endpoint_key, capture_sha256, raw_address, port, "UDP"
        )
    except (EndpointError, EndpointKeyError):
        return unavailable("UNAVAILABLE", "CONNECTION_ADDRESS_INVALID")
    result.update(
        {
            "endpoint_status": "ESTABLISHED",
            "endpoint_reference": reference,
            "transport": "UDP",
            "address_family": address_type.replace("IP4", "IPv4").replace("IP6", "IPv6"),
        }
    )
    return result


def _media_line(value: str) -> tuple[dict[str, Any] | None, list[str]]:
    parts = value.split()
    if len(parts) < 4:
        return None, ["MEDIA_FIELD_MALFORMED"]
    media_type = _safe_token(parts[0].lower())
    port_part = parts[1]
    port_text, separator, count_text = port_part.partition("/")
    port = _parse_int(port_text, 0, 65535)
    port_count = _parse_int(count_text, 1, 65535) if separator else 1
    protocol = _safe_token(parts[2])
    formats = parts[3:]
    if media_type is None or port is None or port_count is None or protocol is None:
        return None, ["MEDIA_FIELD_MALFORMED"]
    if len(formats) > MAX_FORMATS:
        return None, ["TOO_MANY_FORMATS"]
    parsed_formats: list[dict[str, Any]] = []
    reasons: list[str] = []
    rtp_protocol = protocol.upper().startswith("RTP/")
    for token in formats:
        if _safe_token(token) is None:
            reasons.append("FORMAT_TOKEN_INVALID")
            continue
        payload = _parse_int(token, 0, 127) if rtp_protocol else None
        if rtp_protocol and payload is None:
            reasons.append("RTP_PAYLOAD_TYPE_INVALID")
        classification = "NOT_RTP"
        if payload is not None:
            classification = "STATIC" if payload <= 95 else "DYNAMIC"
        parsed_formats.append(
            {
                "format": token,
                "payload_type": payload,
                "classification": classification,
            }
        )
    if len({item["payload_type"] for item in parsed_formats if item["payload_type"] is not None}) != len(
        [item for item in parsed_formats if item["payload_type"] is not None]
    ):
        reasons.append("DUPLICATE_PAYLOAD_TYPE")
    return {
        "media_type": media_type,
        "media_type_supported": media_type in KNOWN_MEDIA,
        "port": port,
        "port_count": port_count,
        "protocol": protocol,
        "formats": parsed_formats,
        "formats_omitted": 0,
    }, reasons


def _media_object(index: int, parsed: dict[str, Any]) -> dict[str, Any]:
    parsed.update(
        {
            "index": index,
            "connection": None,
            "secondary_connection_count": 0,
            "bandwidth": [],
            "attributes": [],
            "unknown_attributes": [],
            "sensitive_attributes": [],
            "rtpmap": [],
            "fmtp": [],
            "groups": [],
            "mid": None,
            "rtcp": None,
            "rtcp_mux": False,
            "ptime": None,
            "maxptime": None,
            "setup": None,
            "ice_options": [],
            "ice_lite": False,
            "direction": None,
            "invalid_reasons": [],
            "evidence_status": "OBSERVED",
            "media_title_present": False,
            "media_title_length": 0,
            "obsolete_key_present": False,
        }
    )
    return parsed


def _line_ending_style(body: str) -> str:
    crlf = body.count("\r\n")
    stripped = body.replace("\r\n", "")
    lf = stripped.count("\n")
    cr = stripped.count("\r")
    styles = []
    if crlf:
        styles.append("CRLF")
    if lf:
        styles.append("LF")
    if cr:
        styles.append("CR")
    if not styles:
        return "NONE"
    return styles[0] if len(styles) == 1 else "MIXED"


def parse_message(
    record: dict[str, Any], *, endpoint_key: bytes | None = None
) -> dict[str, Any]:
    body = record["sdp_body"]
    body_bytes = body.encode("utf-8", errors="surrogatepass")
    base = {
        "source_reference": record["source_reference"],
        "capture_file": record["capture_file"],
        "capture_sha256": record["capture_sha256"],
        "frame_number": record["frame_number"],
        "frame_reference": record["frame_reference"],
        "message_occurrence": record["message_occurrence"],
        "parser_version": PARSER_VERSION,
        "sdp_version": None,
        "line_count": 0,
        "line_ending_style": _line_ending_style(body),
        "session": {
            "origin": None,
            "session_name": None,
            "connection": None,
            "secondary_connection_count": 0,
            "timing": [],
            "bandwidth": [],
            "attributes": [],
            "unknown_attributes": [],
            "sensitive_attributes": [],
            "rtpmap": [],
            "fmtp": [],
            "groups": [],
            "mid": None,
            "rtcp": None,
            "rtcp_mux": False,
            "ptime": None,
            "maxptime": None,
            "setup": None,
            "ice_options": [],
            "ice_lite": False,
            "direction": None,
            "obsolete_key_present": False,
            "unknown_lines": [],
            "malformed_lines": [],
            "invalid_reasons": [],
            "evidence_status": "INVALID",
        },
        "media_sections": [],
        "media_section_count": 0,
        "media_sections_omitted": 0,
        "invalid_reasons": [],
        "limitations": [
            "raw SDP body is never published",
            "network addresses, identities, ICE credentials and key material are redacted",
            "SDP structural evidence does not establish offer/answer agreement, RTP delivery, media quality or IMS call success",
        ],
        "not_confirmed": [
            "SDP_OFFER_ANSWER",
            "RTP_DELIVERY",
            "IMS_MEDIA_SESSION",
            "CALL_SUCCESS",
            "MEDIA_QOS",
        ],
        "evidence_status": "OBSERVED",
    }
    if len(body_bytes) > MAX_BODY_BYTES:
        base["evidence_status"] = "INVALID"
        base["invalid_reasons"] = ["OVERSIZED_INPUT"]
        return base
    try:
        text = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        base["evidence_status"] = "INVALID"
        base["invalid_reasons"] = ["INVALID_UTF8"]
        return base

    truncated = bool(text) and not text.endswith(("\n", "\r"))
    lines = re.split(r"\r\n|\n|\r", text)
    if lines and lines[-1] == "":
        lines = lines[:-1]
    base["line_count"] = len(lines)
    session = base["session"]
    current: dict[str, Any] | None = None
    seen_session: set[str] = set()
    total_reasons: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            total_reasons.append("LINE_TOO_LONG")
            session["malformed_lines"].append(
                {"line_number": line_number, "length": len(line), "reason": "LINE_TOO_LONG"}
            )
            continue
        if not line:
            continue
        match = LINE_PATTERN.fullmatch(line)
        if match is None:
            total_reasons.append("MALFORMED_LINE")
            session["malformed_lines"].append(
                {"line_number": line_number, "length": len(line), "reason": "MALFORMED_LINE"}
            )
            continue
        field_type, value = match.group(1), match.group(2)
        if field_type in {"v", "o", "s", "i", "u", "e", "p", "t", "r", "z", "c", "b", "k", "a", "m"}:
            pass
        else:
            total_reasons.append("UNKNOWN_LINE_TYPE")
            session["unknown_lines"].append(
                {"field_type": field_type, "value_length": len(value), "line_number": line_number}
            )
            base["evidence_status"] = "UNSUPPORTED"
            continue

        if field_type == "m":
            parsed_media, reasons = _media_line(value)
            if parsed_media is None:
                total_reasons.extend(reasons)
                continue
            current = _media_object(len(base["media_sections"]), parsed_media)
            current["invalid_reasons"].extend(reasons)
            base["media_sections"].append(current)
            continue

        if current is None:
            target = session
            scope = "SESSION"
        else:
            target = current
            scope = "MEDIA"

        if field_type in {"v", "o", "s", "t"} and scope == "MEDIA":
            total_reasons.append("SESSION_FIELD_IN_MEDIA_SECTION")
            continue

        if field_type == "v":
            if "v" in seen_session:
                total_reasons.append("DUPLICATE_VERSION")
                continue
            seen_session.add("v")
            if value != "0":
                total_reasons.append("UNSUPPORTED_SDP_VERSION")
                base["sdp_version"] = value if re.fullmatch(r"[0-9]+", value) else None
            else:
                base["sdp_version"] = 0
        elif field_type == "o":
            if "o" in seen_session:
                total_reasons.append("DUPLICATE_ORIGIN")
                continue
            seen_session.add("o")
            parsed, reasons = _origin(value)
            total_reasons.extend(reasons)
            session["origin"] = parsed
        elif field_type == "s":
            if "s" in seen_session:
                total_reasons.append("DUPLICATE_SESSION_NAME")
                continue
            seen_session.add("s")
            if not value:
                total_reasons.append("SESSION_NAME_EMPTY")
            session["session_name"] = {
                "present": True,
                "length": len(value),
                "redacted": True,
            }
        elif field_type == "i":
            if scope == "SESSION":
                if "i" in seen_session:
                    total_reasons.append("DUPLICATE_SESSION_INFORMATION")
                seen_session.add("i")
            target["media_title_present" if scope == "MEDIA" else "session_information_present"] = True
            if scope == "MEDIA":
                target["media_title_length"] = len(value)
            else:
                session["session_information_length"] = len(value)
        elif field_type in {"u", "e", "p"}:
            if field_type == "u" and "u" in seen_session:
                total_reasons.append("DUPLICATE_URI")
            seen_session.add(field_type)
            session[f"{field_type}_present"] = True
            session[f"{field_type}_length"] = len(value)
        elif field_type == "c":
            parsed, reasons = _connection(value)
            total_reasons.extend(reasons)
            if parsed:
                if target.get("connection") is None:
                    target["connection"] = parsed
                else:
                    target["secondary_connection_count"] += 1
                    target.setdefault("invalid_reasons", []).append("MULTIPLE_CONNECTION_LINES")
        elif field_type == "b":
            parsed, reasons = _bandwidth(value)
            total_reasons.extend(reasons)
            if parsed:
                target["bandwidth"].append(parsed)
        elif field_type == "t":
            parsed, reasons = _time(value)
            total_reasons.extend(reasons)
            if parsed:
                session["timing"].append(parsed)
        elif field_type in {"r", "z"}:
            session.setdefault("repeat_timing_line_count", 0)
            session["repeat_timing_line_count"] += 1
        elif field_type == "k":
            target["obsolete_key_present"] = True
            total_reasons.append("OBSOLETE_ENCRYPTION_KEY")
        elif field_type == "a":
            reasons = _parse_attribute(value, scope, target)
            total_reasons.extend(reasons)
            target.setdefault("invalid_reasons", []).extend(reasons)

    _finish_directions(session)
    for media in base["media_sections"]:
        _finish_directions(media)
    session_mids = _finish_mids(session)
    media_mids = [_finish_mids(media) for media in base["media_sections"]]
    base["media_sections_omitted"] = max(0, len(base["media_sections"]) - MAX_MEDIA_SECTIONS)
    base["media_sections"] = base["media_sections"][:MAX_MEDIA_SECTIONS]
    base["media_section_count"] = len(base["media_sections"])
    all_mids = {mid for mids in media_mids for mid in mids}
    for target in [session] + base["media_sections"]:
        for group in target.get("groups", []):
            missing = [mid for mid in group["mids"] if mid not in all_mids]
            group["reference_status"] = "RESOLVED" if not missing else "UNRESOLVED"
            if missing:
                total_reasons.append("BUNDLE_REFERENCE_UNRESOLVED")
    if "v" not in seen_session:
        total_reasons.append("MISSING_VERSION")
    if "o" not in seen_session or session["origin"] is None:
        total_reasons.append("MISSING_ORIGIN")
    if "s" not in seen_session or session["session_name"] is None:
        total_reasons.append("MISSING_SESSION_NAME")
    if not session["timing"]:
        total_reasons.append("MISSING_TIME_DESCRIPTION")
    for media in base["media_sections"]:
        if media["connection"] is None and session["connection"] is None:
            media["invalid_reasons"].append("MISSING_CONNECTION")
        for name in ("rtpmap", "fmtp"):
            payloads = [item["payload_type"] for item in media[name]]
            if len(payloads) != len(set(payloads)):
                media["invalid_reasons"].append(f"DUPLICATE_{name.upper()}")
        if not media["media_type_supported"]:
            media["invalid_reasons"].append("UNSUPPORTED_MEDIA_TYPE")
        if media["invalid_reasons"]:
            media["evidence_status"] = (
                "AMBIGUOUS"
                if any("CONFLICT" in item or "MULTIPLE" in item or "DUPLICATE" in item for item in media["invalid_reasons"])
                else "INCOMPLETE"
                if "MISSING_CONNECTION" in media["invalid_reasons"]
                else "UNSUPPORTED"
                if "UNSUPPORTED_MEDIA_TYPE" in media["invalid_reasons"]
                else "INVALID"
            )
    if session["invalid_reasons"]:
        total_reasons.extend(session["invalid_reasons"])
    session["evidence_status"] = (
        "INVALID" if session["invalid_reasons"] else "OBSERVED"
    )
    if session["origin"] is None or not session["timing"]:
        session["evidence_status"] = "INCOMPLETE"
    if truncated:
        total_reasons.append("TRUNCATED_INPUT")
    for media in base["media_sections"]:
        total_reasons.extend(media["invalid_reasons"])
    total_reasons = sorted(set(total_reasons))
    incomplete_reasons = {
        "MISSING_VERSION",
        "MISSING_ORIGIN",
        "MISSING_SESSION_NAME",
        "MISSING_TIME_DESCRIPTION",
        "MISSING_CONNECTION",
        "TRUNCATED_INPUT",
    }
    ambiguous_reasons = {
        "CONFLICTING_DIRECTION_ATTRIBUTES",
        "CONFLICTING_MID_ATTRIBUTES",
        "MULTIPLE_CONNECTION_LINES",
        "DUPLICATE_RTPMAP",
        "DUPLICATE_FMTP",
        "BUNDLE_REFERENCE_UNRESOLVED",
    }
    unsupported_reasons = {
        "UNKNOWN_LINE_TYPE",
        "UNSUPPORTED_MEDIA_TYPE",
        "UNSUPPORTED_SDP_VERSION",
        "OBSOLETE_ENCRYPTION_KEY",
    }
    if any(reason not in incomplete_reasons and reason not in ambiguous_reasons and reason not in unsupported_reasons for reason in total_reasons):
        base["evidence_status"] = "INVALID"
    elif any(reason in total_reasons for reason in incomplete_reasons):
        base["evidence_status"] = "INCOMPLETE"
    elif any(reason in total_reasons for reason in ambiguous_reasons):
        base["evidence_status"] = "AMBIGUOUS"
    elif any(reason in total_reasons for reason in unsupported_reasons) or any(
        media["evidence_status"] == "UNSUPPORTED" for media in base["media_sections"]
    ):
        base["evidence_status"] = "UNSUPPORTED"
    else:
        base["evidence_status"] = "OBSERVED"
    if endpoint_key is not None:
        for media in base["media_sections"]:
            media["transport_endpoint"] = _transport_endpoint(
                media, session, endpoint_key, base["capture_sha256"]
            )
    if isinstance(session.get("connection"), dict):
        session["connection"].pop("_raw_address", None)
    for media in base["media_sections"]:
        if isinstance(media.get("connection"), dict):
            media["connection"].pop("_raw_address", None)
    base["invalid_reasons"] = sorted(set(total_reasons))
    return base


def _validate_record(record: dict[str, Any], line_number: int) -> None:
    for key in (
        "source_reference",
        "capture_file",
        "capture_sha256",
        "frame_number",
        "frame_reference",
        "message_occurrence",
        "sdp_body",
    ):
        if key not in record:
            raise InputError(f"input line {line_number} is missing {key}")
    if not isinstance(record["source_reference"], str) or not REFERENCE_PATTERN.fullmatch(record["source_reference"]):
        raise InputError(f"input line {line_number} has an invalid source_reference")
    if not isinstance(record["capture_file"], str) or not record["capture_file"]:
        raise InputError(f"input line {line_number} has no capture_file")
    if not isinstance(record["capture_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["capture_sha256"]):
        raise InputError(f"input line {line_number} has an invalid capture_sha256")
    if isinstance(record["frame_number"], bool) or not isinstance(record["frame_number"], int) or record["frame_number"] < 1:
        raise InputError(f"input line {line_number} has an invalid frame_number")
    if not isinstance(record["frame_reference"], str) or not record["frame_reference"]:
        raise InputError(f"input line {line_number} has no frame_reference")
    if isinstance(record["message_occurrence"], bool) or not isinstance(record["message_occurrence"], int) or record["message_occurrence"] < 1:
        raise InputError(f"input line {line_number} has an invalid message_occurrence")
    if not isinstance(record["sdp_body"], str):
        raise InputError(f"input line {line_number} has a non-string sdp_body")


def load_messages(path: Path) -> list[dict[str, Any]]:
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
        if not isinstance(record, dict):
            raise InputError(f"input line {line_number} is not an object")
        _validate_record(record, line_number)
        records.append(record)
    if not records:
        raise InputError("input contains no SDP messages")
    if len(records) > MAX_RECORDS:
        raise InputError(f"input exceeds the {MAX_RECORDS}-message bound")
    if len({record["source_reference"] for record in records}) != len(records):
        raise InputError("SDP source references are not unique")
    captures = {(record["capture_file"], record["capture_sha256"]) for record in records}
    if len(captures) != 1:
        raise InputError("SDP input mixes capture provenance")
    return records


def build_analysis(
    records: list[dict[str, Any]],
    *,
    input_name: str = "sdp-input.jsonl",
    endpoint_key: bytes | None = None,
) -> dict[str, Any]:
    messages = [parse_message(record, endpoint_key=endpoint_key) for record in records]
    capture_file = records[0]["capture_file"]
    capture_sha256 = records[0]["capture_sha256"]
    endpoint_context = (
        endpoint_context_reference(endpoint_key, capture_sha256)
        if endpoint_key is not None
        else None
    )
    document = {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "event_schema_version": EVENT_SCHEMA_VERSION,
        "capability": CAPABILITY,
        "input_provenance": {
            "input_name": input_name,
            "capture_files": [capture_file],
            "capture_sha256": capture_sha256,
            "message_count": len(records),
            "parser_version": PARSER_VERSION,
        },
        "message_count": len(messages),
        "messages": messages,
        "completeness": {
            "supplied_message_count": len(records),
            "published_message_count": len(messages),
            "messages_omitted": max(0, len(records) - len(messages)),
            "observed_message_count": sum(1 for item in messages if item["evidence_status"] == "OBSERVED"),
            "incomplete_message_count": sum(1 for item in messages if item["evidence_status"] == "INCOMPLETE"),
            "ambiguous_message_count": sum(1 for item in messages if item["evidence_status"] == "AMBIGUOUS"),
            "unsupported_message_count": sum(1 for item in messages if item["evidence_status"] == "UNSUPPORTED"),
            "invalid_message_count": sum(1 for item in messages if item["evidence_status"] == "INVALID"),
        },
        "limitations": [
            "The parser consumes explicitly supplied SDP bodies and provenance; capture extraction is not implemented here.",
            "Raw SDP bodies, addresses, identities, ICE credentials, fingerprints and key material are not published.",
            "No SDP Offer/Answer pairing, SIP dialog association, RTP endpoint correlation, media quality or IMS media verdict is produced.",
        ],
        "not_confirmed": [
            "SDP_OFFER_ANSWER",
            "SIP_TO_SDP_ASSOCIATION",
            "SDP_TO_RTP_ENDPOINT_CORRELATION",
            "RTP_DELIVERY",
            "MEDIA_QOS",
            "IMS_MEDIA_SESSION",
            "CALL_SUCCESS",
        ],
    }
    if endpoint_context is not None:
        document["input_provenance"]["endpoint_context_reference"] = endpoint_context
        document["limitations"] = list(document["limitations"]) + [
            "Endpoint references are keyed HMAC-SHA-256 values scoped to the original capture and are absent without an endpoint key",
            "Endpoint references are not emitted for ICE-selected, disabled, multicast, unspecified, link-local, unresolved-name or unsupported-transport media sections",
        ]
    return document


def validate_analysis(document: dict[str, Any]) -> None:
    if not isinstance(document, dict):
        raise InputError("SDP analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("SDP analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("SDP analysis_version is not accepted")
    messages = document.get("messages")
    if not isinstance(messages, list):
        raise InputError("SDP messages must be an array")
    if document.get("message_count") != len(messages):
        raise InputError("SDP message_count does not match the message array")
    references: set[str] = set()
    for message in messages:
        reference = message.get("source_reference")
        if not isinstance(reference, str) or not REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("an SDP source reference is invalid")
        if reference in references:
            raise InputError("SDP source references are not unique")
        references.add(reference)
        if message.get("evidence_status") not in {
            "OBSERVED",
            "INCOMPLETE",
            "AMBIGUOUS",
            "UNSUPPORTED",
            "INVALID",
        }:
            raise InputError("an SDP message has an invalid evidence status")
        if message.get("media_section_count") != len(message.get("media_sections") or []):
            raise InputError("SDP media section count does not match the media array")
        for media in message.get("media_sections") or []:
            if media.get("evidence_status") not in {
                "OBSERVED",
                "INCOMPLETE",
                "AMBIGUOUS",
                "UNSUPPORTED",
                "INVALID",
            }:
                raise InputError("an SDP media section has an invalid evidence status")
            if media.get("media_type_supported") is False and media.get("evidence_status") == "OBSERVED":
                raise InputError("an unsupported media type cannot be marked observed")
            if isinstance(media.get("connection"), dict) and "_raw_address" in media["connection"]:
                raise InputError("an SDP media connection published a raw address")
            endpoint = media.get("transport_endpoint")
            if endpoint is not None:
                if not isinstance(endpoint, dict):
                    raise InputError("an SDP transport endpoint is not an object")
                if endpoint.get("endpoint_status") not in {
                    "ESTABLISHED",
                    "UNAVAILABLE",
                    "OUT_OF_SCOPE",
                }:
                    raise InputError("an SDP transport endpoint has an invalid status")
                reference = endpoint.get("endpoint_reference")
                if endpoint.get("endpoint_status") == "ESTABLISHED":
                    if not is_endpoint_reference(reference):
                        raise InputError("an established SDP transport endpoint has no valid reference")
                    if endpoint.get("transport") != "UDP":
                        raise InputError("an established SDP transport endpoint is not UDP")
                    if endpoint.get("address_family") not in {"IPv4", "IPv6"}:
                        raise InputError("an established SDP transport endpoint has no address family")
                elif reference is not None:
                    raise InputError("an unavailable SDP transport endpoint published a reference")
    provenance = document.get("input_provenance") or {}
    if isinstance(provenance.get("capture_files"), list) and provenance.get("capture_files"):
        message_capture = messages[0].get("capture_file") if messages else None
        if message_capture is not None and provenance["capture_files"][0] != message_capture:
            raise InputError("SDP input_provenance capture identity disagrees with the messages")
    context = provenance.get("endpoint_context_reference")
    has_endpoint = any(
        "transport_endpoint" in media
        for message in messages
        for media in message.get("media_sections") or []
    )
    if context is not None and not is_context_reference(context):
        raise InputError("SDP endpoint context reference is malformed")
    if has_endpoint and context is None:
        raise InputError("SDP endpoint evidence lacks a context reference")
    completeness = document.get("completeness") or {}
    if completeness.get("supplied_message_count") != completeness.get("published_message_count", 0) + completeness.get("messages_omitted", 0):
        raise InputError("SDP message count conservation failed")
    for forbidden in ("sdp_body", "raw_sdp", "call_id", "sip_uri", "ice_password", "fingerprint_value"):
        if forbidden in document:
            raise InputError(f"forbidden raw field published: {forbidden}")