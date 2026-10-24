#!/usr/bin/env python3
"""Shared model for bounded GTPv2-C session-control evidence.

Message identities, IE types, cause values and F-TEID interface types were
reviewed against 3GPP TS 29.274 and cross-checked against the value tables of
the TShark 4.7.1 GTPv2 dissector. Header semantics, information-element scope
and grouped Bearer Context boundaries are taken from the dissector's PDML tree
rather than from flattened field lists, because flat `-T fields` output does not
preserve grouped-IE item boundaries.

Two extraction inputs are supported:

* PDML (produced by the installed `tshark`, or stored as a deterministic
  offline artifact). Grouped Bearer Context items are provable in this mode.
* Flat fields JSONL. Grouped-IE boundaries are unavailable in this mode, so
  bearer-level binding is never claimed; the decoded values are published as
  explicitly unbound metadata instead.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterator

EXIT_TOOL_UNAVAILABLE = 3
EXIT_TSHARK_FAILURE = 4
EXIT_MALFORMED_INPUT = 5
EXIT_NO_EVENTS = 6
EXIT_OUTPUT_FAILURE = 7

SCHEMA_NAME = "gtpv2-event"
PROTOCOL = "GTPv2-C"
TRANSPORT = "UDP"
PORT = 2123

MODEL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Reviewed TS 29.274 identities
# ---------------------------------------------------------------------------

# TS 29.274 Table 6.1-1, bounded to the session-control set plus the messages
# this Skill classifies as known-but-unsupported. Values were cross-checked
# against `tshark -G values` for gtpv2.message_type.
MESSAGE_TYPES: dict[int, str] = {
    1: "Echo Request",
    2: "Echo Response",
    3: "Version Not Supported Indication",
    32: "Create Session Request",
    33: "Create Session Response",
    34: "Modify Bearer Request",
    35: "Modify Bearer Response",
    36: "Delete Session Request",
    37: "Delete Session Response",
    95: "Create Bearer Request",
    96: "Create Bearer Response",
    97: "Update Bearer Request",
    98: "Update Bearer Response",
    99: "Delete Bearer Request",
    100: "Delete Bearer Response",
    101: "Delete PDN Connection Set Request",
    102: "Delete PDN Connection Set Response",
    128: "Identification Request",
    129: "Identification Response",
    130: "Context Request",
    131: "Context Response",
    132: "Context Acknowledge",
    149: "Detach Notification",
    150: "Detach Acknowledge",
    170: "Release Access Bearers Request",
    171: "Release Access Bearers Response",
    176: "Downlink Data Notification",
    177: "Downlink Data Notification Acknowledgement",
    179: "PGW Restart Notification",
    180: "PGW Restart Notification Acknowledge",
}

# Procedure families that this bounded Skill analyses end to end.
PROCEDURES: dict[int, str] = {
    1: "echo",
    2: "echo",
    32: "create-session",
    33: "create-session",
    34: "modify-bearer",
    35: "modify-bearer",
    36: "delete-session",
    37: "delete-session",
    170: "release-access-bearers",
    171: "release-access-bearers",
}

SUPPORTED_CODES = frozenset(PROCEDURES)

REQUEST_CODES: dict[int, int] = {
    1: 2,
    32: 33,
    34: 35,
    36: 37,
    170: 171,
}
RESPONSE_CODES: dict[int, int] = {value: key for key, value in REQUEST_CODES.items()}

# TS 29.274 Table 6.1-1 message families for correlation grouping.
MESSAGE_FAMILY: dict[int, str] = {
    1: "echo",
    2: "echo",
    32: "create-session",
    33: "create-session",
    34: "modify-bearer",
    35: "modify-bearer",
    36: "delete-session",
    37: "delete-session",
    170: "release-access-bearers",
    171: "release-access-bearers",
}

# Bounded cause subset. Names follow TS 29.274 Table 8.4-1 and were checked
# against `tshark -G values` for gtpv2.cause.
CAUSES: dict[int, str] = {
    16: "Request accepted",
    17: "Request accepted partially",
    64: "Context Not Found",
    65: "Invalid Message Format",
    66: "Version not supported by next peer",
    67: "Invalid length",
    68: "Service not supported",
    69: "Mandatory IE incorrect",
    70: "Mandatory IE missing",
    72: "System failure",
    73: "No resources available",
    78: "Missing or unknown APN",
    80: "GRE key not found",
    83: "Preferred PDN type not supported",
    84: "All dynamic addresses are occupied",
    87: "UE not responding",
    88: "UE refuses",
    89: "Service denied",
    90: "Unable to page UE",
    91: "No memory available",
    92: "User authentication failed",
    93: "APN access denied - no subscription",
    94: "Request rejected(reason not specified)",
    100: "Remote peer not responding",
    101: "Collision with network initiated request",
    102: "Unable to page UE due to Suspension",
    103: "Conditional IE missing",
    107: "Invalid reply from remote peer",
    108: "Fallback to GTPv1",
    109: "Invalid peer",
    110: "Temporarily rejected due to handover/TAU/RAU procedure in progress",
    114: "Bearer handling not supported",
    115: "UE already re-attached",
    116: "Multiple PDN connections for a given APN not allowed",
    117: "Target access restricted for the subscriber",
    119: "MME/SGSN refuses due to VPLMN Policy",
    120: "GTP-C Entity Congestion",
    121: "Late Overlapping Request",
    122: "Timed out Request",
    123: "UE is temporarily not reachable due to power saving",
    127: "Request rejected due to UE capability",
    128: "S1-U Path Failure",
}

# TS 29.274 Table 8.22-1 interface types. The value table was cross-checked
# against `tshark -G values` for gtpv2.f_teid_interface_type.
INTERFACE_TYPES: dict[int, str] = {
    0: "S1-U eNodeB GTP-U interface",
    1: "S1-U SGW GTP-U interface",
    2: "S12 RNC GTP-U interface",
    3: "S12 SGW GTP-U interface",
    4: "S5/S8 SGW GTP-U interface",
    5: "S5/S8 PGW GTP-U interface",
    6: "S5/S8 SGW GTP-C interface",
    7: "S5/S8 PGW GTP-C interface",
    8: "S5/S8 SGW PMIPv6 interface",
    9: "S5/S8 PGW PMIPv6 interface",
    10: "S11 MME GTP-C interface",
    11: "S11/S4 SGW GTP-C interface",
    12: "S10 MME GTP-C interface",
    13: "S3 MME GTP-C interface",
    14: "S3 SGSN GTP-C interface",
    15: "S4 SGSN GTP-U interface",
    16: "S4 SGW GTP-U interface",
    17: "S4 SGSN GTP-C interface",
    18: "S16 SGSN GTP-C interface",
    19: "eNodeB/gNodeB GTP-U interface for DL data forwarding",
    20: "eNodeB GTP-U interface for UL data forwarding",
    21: "RNC GTP-U interface for data forwarding",
    22: "SGSN GTP-U interface for data forwarding",
    23: "SGW GTP-U interface for data forwarding",
    24: "Sm MBMS GW GTP-C interface",
    25: "Sn MBMS GW GTP-C interface",
    26: "Sm MME GTP-C interface",
    27: "Sn SGSN GTP-C interface",
    28: "SGW GTP-U interface for UL data forwarding",
}

PDN_TYPES: dict[int, str] = {
    1: "IPv4",
    2: "IPv6",
    3: "IPv4/IPv6",
    4: "Non-IP",
    5: "Ethernet",
}

RAT_TYPES: dict[int, str] = {
    0: "Reserved",
    1: "UTRAN",
    2: "GERAN",
    3: "WLAN",
    4: "GAN",
    5: "HSPA Evolution",
    6: "EUTRAN",
    7: "Virtual",
    8: "EUTRAN-NB-IoT",
    9: "LTE-M",
    10: "NR",
}

# Bounded IE type table (TS 29.274 Table 6.1-1 of IE types), cross-checked
# against `tshark -G values` for gtpv2.ie_type.
IE_TYPES: dict[int, str] = {
    1: "IMSI",
    2: "Cause",
    3: "Recovery",
    71: "APN",
    72: "AMBR",
    73: "EBI",
    74: "IP Address",
    75: "MEI",
    76: "MSISDN",
    77: "Indication",
    78: "PCO",
    79: "PAA",
    80: "Bearer QoS",
    82: "RAT Type",
    83: "Serving Network",
    86: "ULI",
    87: "F-TEID",
    88: "TMSI",
    93: "Bearer Context",
    94: "Charging ID",
    99: "PDN Type",
    114: "UE Time Zone",
    127: "APN Restriction",
    128: "Selection Mode",
    135: "Protocol Configuration Options",
}

BEARER_CONTEXT_IE = 93
CAUSE_IE = 2
EBI_IE = 73
F_TEID_IE = 87
APN_IE = 71
AMBR_IE = 72
PAA_IE = 79
RAT_TYPE_IE = 82
PDN_TYPE_IE = 99
CHARGING_ID_IE = 94

# IE types whose values are subscriber identities. Only presence is published.
IDENTITY_IE_TYPES = {
    1: "imsi",
    75: "mei",
    76: "msisdn",
    88: "tmsi",
}

SUPPORT_STATUSES = ("SUPPORTED", "UNSUPPORTED", "UNKNOWN")

HEADER_TEID_ABSENT = "ABSENT"
HEADER_TEID_ZERO = "ZERO"
HEADER_TEID_PRESENT = "PRESENT"

HIERARCHY_PDML = "pdml_grouped_ie"
HIERARCHY_FLAT = "flat_fields"

MAX_IE_SUMMARY = 40
MAX_LIST_ITEMS = 16
MAX_EVIDENCE_REFERENCES = 10


class InputError(ValueError):
    """Raised when an accepted input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested dissection."""


# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


def safe_capture_name(path: Path) -> str:
    """Capture identity used in evidence references: file name only."""
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


def to_int(value: object) -> int | None:
    text = clean(value)
    if text is None:
        return None
    # Flat field exports repeat a field as a comma-separated list; the first
    # occurrence is the one that belongs to the message-scope IE order.
    if "," in text:
        text = text.split(",", 1)[0].strip()
    if not text:
        return None
    if text.lower().startswith(("0x", "-0x")):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        return int(text, 10)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def parse_int(value: object, field: str) -> int:
    text = clean(value)
    if text is None:
        raise InputError(f"{field} is required")
    parsed = to_int(text)
    if parsed is None:
        raise InputError(f"{field} must be an integer")
    return parsed


def repeated(value: object) -> list[str]:
    text = clean(value)
    if text is None:
        return []
    return [item.strip() for item in str(text).split(",") if item.strip()]


def normalize_timestamp(value: object) -> str:
    text = clean(value)
    if text is None:
        raise InputError("frame.time_epoch is required")
    try:
        epoch = Decimal(text)
    except InvalidOperation as exc:
        raise InputError("frame.time_epoch is not a valid epoch timestamp") from exc
    microseconds = int((epoch * Decimal("1000000")).to_integral_value(rounding=ROUND_HALF_EVEN))
    instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=microseconds)
    return instant.isoformat(timespec="microseconds").replace("+00:00", "Z")


def bounded(items: list[Any], limit: int = MAX_LIST_ITEMS) -> list[Any]:
    return items[:limit]


# ---------------------------------------------------------------------------
# PDML access helpers
# ---------------------------------------------------------------------------


def _direct_field(node: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in node.findall("field"):
        if child.get("name") == name:
            return child
    return None


def _show(node: ElementTree.Element, name: str) -> str | None:
    field = _direct_field(node, name)
    if field is None:
        return None
    return field.get("show")


def _flag_show(layer: ElementTree.Element, name: str) -> str | None:
    """Header flag fields are nested inside the dissector's flags field.

    The lookup is deliberately restricted to the flags subtree: a generic deep
    search would also reach IE-scoped values such as a bearer-level Cause.
    """
    direct = _show(layer, name)
    if direct is not None:
        return direct
    flags = _direct_field(layer, "gtpv2.flags")
    if flags is None:
        return None
    return _show(flags, name)


def _ie_containers(node: ElementTree.Element) -> list[ElementTree.Element]:
    """Grouped-IE boundaries as exposed by the dissector tree.

    A grouped IE is rendered as a field element without a field name whose
    first child is the IE type. Its nested IE elements are the direct children
    that are themselves IE containers.
    """
    containers: list[ElementTree.Element] = []
    for child in node.findall("field"):
        if child.get("name") in ("", None) and _direct_field(child, "gtpv2.ie_type") is not None:
            containers.append(child)
    return containers


def _ie_fields(node: ElementTree.Element, names: tuple[str, ...]) -> dict[str, str]:
    payload: dict[str, str] = {}
    for name in names:
        value = _show(node, name)
        if value is not None:
            payload[name] = value
    return payload


# ---------------------------------------------------------------------------
# IE normalization
# ---------------------------------------------------------------------------


def _parse_ie(node: ElementTree.Element) -> dict[str, Any]:
    ie_type = to_int(_show(node, "gtpv2.ie_type"))
    ie: dict[str, Any] = {
        "ie_type": ie_type,
        "ie_name": IE_TYPES.get(ie_type) if ie_type is not None else None,
        "instance": to_int(_show(node, "gtpv2.instance")),
        "cr_flag": to_int(_show(node, "gtpv2.cr")),
        "fields": {},
        "children": [],
    }
    if ie_type == CAUSE_IE:
        ie["fields"] = _ie_fields(node, ("gtpv2.cause", "gtpv2.pce", "gtpv2.bce", "gtpv2.cs"))
    elif ie_type == F_TEID_IE:
        ie["fields"] = _ie_fields(
            node,
            (
                "gtpv2.f_teid_interface_type",
                "gtpv2.f_teid_gre_key",
                "gtpv2.f_teid_ipv4",
                "gtpv2.f_teid_ipv6",
                "gtpv2.f_teid_v4",
                "gtpv2.f_teid_v6",
            ),
        )
    elif ie_type == EBI_IE:
        ie["fields"] = _ie_fields(node, ("gtpv2.ebi",))
    elif ie_type == APN_IE:
        apn = _show(node, "gtpv2.apn")
        if apn is not None:
            # The network name itself is never published; only its length.
            ie["fields"] = {"apn_length": str(len(apn))}
    elif ie_type == AMBR_IE:
        ie["fields"] = _ie_fields(node, ("gtpv2.ambr_up", "gtpv2.ambr_down"))
    elif ie_type == PAA_IE:
        ie["fields"] = _ie_fields(
            node, ("gtpv2.pdn_type", "gtpv2.pdn_addr_and_prefix.ipv4", "gtpv2.pdn_addr_and_prefix.ipv6")
        )
    elif ie_type == RAT_TYPE_IE:
        ie["fields"] = _ie_fields(node, ("gtpv2.rat_type",))
    elif ie_type == PDN_TYPE_IE:
        ie["fields"] = _ie_fields(node, ("gtpv2.pdn_type",))
    elif ie_type in IDENTITY_IE_TYPES:
        # Presence only: the value is deliberately dropped here.
        ie["fields"] = {"present": "True"}
    elif ie_type == CHARGING_ID_IE:
        ie["fields"] = {"present": "True"}
    ie["children"] = [_parse_ie(child) for child in _ie_containers(node)]
    return ie


def _cause_from_ie(ie: dict[str, Any], scope: str) -> dict[str, Any] | None:
    code = to_int(ie["fields"].get("gtpv2.cause"))
    if code is None:
        return None
    payload: dict[str, Any] = {
        "cause_code": code,
        "cause_name": CAUSES.get(code),
        "scope": scope,
    }
    for flag, name in (("gtpv2.pce", "pdn_connection_ie_error"), ("gtpv2.bce", "bearer_context_ie_error")):
        raw = ie["fields"].get(flag)
        if raw is not None:
            payload[name] = raw.lower() == "true"
    source_flag = ie["fields"].get("gtpv2.cs")
    if source_flag is not None:
        # Raw CS bit only; no interpretation of which node originated the cause.
        payload["cause_source_flag"] = source_flag.lower() == "true"
    return payload


def _f_teid_from_ie(ie: dict[str, Any], scope: str) -> dict[str, Any]:
    interface_type = to_int(ie["fields"].get("gtpv2.f_teid_interface_type"))
    return {
        "scope": scope,
        "interface_type": interface_type,
        "interface_type_name": INTERFACE_TYPES.get(interface_type) if interface_type is not None else None,
        "teid": to_int(ie["fields"].get("gtpv2.f_teid_gre_key")),
        "ipv4": ie["fields"].get("gtpv2.f_teid_ipv4"),
        "ipv6": ie["fields"].get("gtpv2.f_teid_ipv6"),
        "ipv4_present": (ie["fields"].get("gtpv2.f_teid_v4") or "").lower() == "true",
        "ipv6_present": (ie["fields"].get("gtpv2.f_teid_v6") or "").lower() == "true",
    }


def _bearer_context(ie: dict[str, Any], index: int) -> dict[str, Any]:
    ebi = None
    cause = None
    f_teids: list[dict[str, Any]] = []
    charging_present = False
    other_ies: list[str] = []
    for child in ie["children"]:
        child_type = child["ie_type"]
        if child_type == EBI_IE:
            ebi = to_int(child["fields"].get("gtpv2.ebi"))
        elif child_type == CAUSE_IE:
            cause = _cause_from_ie(child, "bearer")
        elif child_type == F_TEID_IE:
            f_teids.append(_f_teid_from_ie(child, "bearer"))
        elif child_type == CHARGING_ID_IE:
            charging_present = True
        else:
            name = child["ie_name"]
            if name is not None and name not in other_ies:
                other_ies.append(name)
    context: dict[str, Any] = {
        "item_index": index,
        "ebi": ebi,
        "cause": cause,
        "f_teids": bounded(f_teids),
        "charging_id_present": charging_present,
        "binding_basis": HIERARCHY_PDML,
    }
    if other_ies:
        context["other_ie_names"] = bounded(other_ies)
    return context


# ---------------------------------------------------------------------------
# Message-level assembly
# ---------------------------------------------------------------------------


def resolve_message(code: int) -> tuple[str | None, str, str | None, str | None]:
    name = MESSAGE_TYPES.get(code)
    if name is None:
        return None, "UNKNOWN", None, None
    family = MESSAGE_FAMILY.get(code)
    if code in SUPPORTED_CODES:
        return name, "SUPPORTED", PROCEDURES[code], family
    return name, "UNSUPPORTED", None, family


def _header_from_layer(layer: ElementTree.Element) -> dict[str, Any]:
    raw_teid = _show(layer, "gtpv2.teid")
    if raw_teid is None:
        teid_state, teid = HEADER_TEID_ABSENT, None
    else:
        teid_value = to_int(raw_teid)
        teid = teid_value
        teid_state = HEADER_TEID_ZERO if teid_value == 0 else HEADER_TEID_PRESENT
    return {
        "version": to_int(_flag_show(layer, "gtpv2.version")),
        "flags": to_int(_show(layer, "gtpv2.flags")),
        "teid_flag": (lambda value: None if value is None else value == 1)(
            to_int(_flag_show(layer, "gtpv2.t"))
        ),
        "piggybacking_flag": (lambda value: None if value is None else value == 1)(
            to_int(_flag_show(layer, "gtpv2.p"))
        ),
        "message_length": to_int(_show(layer, "gtpv2.msg_length")),
        "teid": teid,
        "teid_state": teid_state,
        "sequence_number": to_int(_show(layer, "gtpv2.seq")),
    }


def _information_elements(top_level: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    elements: dict[str, Any] = {}
    identities: dict[str, Any] = {}
    paa_type: int | None = None
    for ie in top_level:
        ie_type = ie["ie_type"]
        if ie_type == APN_IE and "apn_length" in ie["fields"]:
            elements["apn_present"] = True
            elements["apn_length"] = to_int(ie["fields"]["apn_length"])
        elif ie_type == PDN_TYPE_IE:
            value = to_int(ie["fields"].get("gtpv2.pdn_type"))
            elements["pdn_type"] = {"value": value, "name": PDN_TYPES.get(value) if value is not None else None}
        elif ie_type == PAA_IE:
            family = None
            if ie["fields"].get("gtpv2.pdn_addr_and_prefix.ipv4") is not None:
                family = "IPv4"
            elif ie["fields"].get("gtpv2.pdn_addr_and_prefix.ipv6") is not None:
                family = "IPv6"
            paa_type = to_int(ie["fields"].get("gtpv2.pdn_type"))
            elements["paa_present"] = True
            elements["paa_address_family"] = family
        elif ie_type == RAT_TYPE_IE:
            value = to_int(ie["fields"].get("gtpv2.rat_type"))
            elements["rat_type"] = {"value": value, "name": RAT_TYPES.get(value) if value is not None else None}
        elif ie_type == AMBR_IE:
            elements["ambr_present"] = True
            elements["ambr_uplink"] = to_int(ie["fields"].get("gtpv2.ambr_up"))
            elements["ambr_downlink"] = to_int(ie["fields"].get("gtpv2.ambr_down"))
        elif ie_type in IDENTITY_IE_TYPES:
            identities[f"{IDENTITY_IE_TYPES[ie_type]}_present"] = True
        elif ie_type == CHARGING_ID_IE:
            elements["charging_id_present"] = True
    if "pdn_type" not in elements and paa_type is not None:
        # The PDN Type IE is absent: the PDN type carried by the PAA IE is the
        # only decoded statement of the allocated address family's type.
        elements["pdn_type"] = {"value": paa_type, "name": PDN_TYPES.get(paa_type)}
    return elements, identities


def _ie_summary(top_level: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summary: list[dict[str, Any]] = []
    for ie in top_level:
        summary.append({"ie_type": ie["ie_type"], "ie_name": ie["ie_name"], "instance": ie["instance"]})
    return bounded(summary, MAX_IE_SUMMARY)


def layer_event(
    layer: ElementTree.Element,
    frame: dict[str, Any],
    capture_file: str,
    occurrence: int,
) -> dict[str, Any]:
    message_code = to_int(_show(layer, "gtpv2.message_type"))
    if message_code is None:
        raise InputError("gtpv2.message_type is required")
    if not 0 <= message_code <= 255:
        raise InputError("gtpv2.message_type must be within 0..255")

    name, support_status, procedure, family = resolve_message(message_code)
    header = _header_from_layer(layer)
    top_level = [_parse_ie(child) for child in _ie_containers(layer)]

    message_cause = None
    message_teids: list[dict[str, Any]] = []
    bearer_contexts: list[dict[str, Any]] = []
    top_level_ebis: list[int] = []
    causes: list[dict[str, Any]] = []
    for ie in top_level:
        ie_type = ie["ie_type"]
        if ie_type == CAUSE_IE:
            cause = _cause_from_ie(ie, "message")
            if cause is not None:
                causes.append(cause)
                if message_cause is None:
                    message_cause = cause
        elif ie_type == F_TEID_IE:
            message_teids.append(_f_teid_from_ie(ie, "message"))
        elif ie_type == BEARER_CONTEXT_IE:
            bearer_contexts.append(_bearer_context(ie, len(bearer_contexts)))
        elif ie_type == EBI_IE:
            value = to_int(ie["fields"].get("gtpv2.ebi"))
            if value is not None:
                top_level_ebis.append(value)

    elements, identities = _information_elements(top_level)

    limitations: list[str] = []
    if len(causes) > 1:
        limitations.append(
            "several message-scope Cause IEs are present; the first is published as message_cause "
            "and the remainder stay in unbound_ie_metadata"
        )
    if len(message_teids) > 1:
        limitations.append(
            "several message-scope F-TEID IEs are present; each keeps its own interface type and none "
            "is attributed to a bearer context"
        )

    unbound: dict[str, Any] | None = None
    if len(causes) > 1 or top_level_ebis:
        unbound = {
            "binding_basis": HIERARCHY_PDML,
            "limitations": ["values listed here are message-scope IE values without a bearer binding"],
        }
        if len(causes) > 1:
            unbound["additional_causes"] = bounded(causes[1:])
        if top_level_ebis:
            unbound["ebi_values"] = bounded(top_level_ebis)

    decoder_link: dict[str, Any] = {}
    response_to = to_int(_show(layer, "gtpv2.response_to"))
    if response_to is not None:
        decoder_link["response_to_frame"] = response_to
        response_time = _show(layer, "gtpv2.response_time")
        if response_time is not None:
            decoder_link["response_time_seconds"] = response_time

    source_ref = f"capture:{capture_file}#frame={frame['frame_number']}"
    if occurrence:
        source_ref += f"; occurrence={occurrence}"
    source_ref += f"; message-type={message_code}"

    event: dict[str, Any] = {
        "timestamp": frame["timestamp"],
        "frame_number": frame["frame_number"],
        "message_occurrence": occurrence,
        "capture_file": capture_file,
        "protocol": PROTOCOL,
        "transport": TRANSPORT,
        "message_type_code": message_code,
        "message_type": name,
        "procedure_family": procedure,
        "message_family": family,
        "support_status": support_status,
        "hierarchy_basis": HIERARCHY_PDML,
        "header": header,
        "message_cause": message_cause,
        "information_elements": elements,
        "identity_ies": identities,
        "f_teids": bounded(message_teids),
        "bearer_contexts": bounded(bearer_contexts),
        "unbound_ie_metadata": unbound,
        "ie_summary": _ie_summary(top_level),
        "extraction_limitations": limitations,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": [],
    }
    if frame.get("source") is not None:
        event["source"] = frame["source"]
    if frame.get("destination") is not None:
        event["destination"] = frame["destination"]
    if decoder_link:
        event["decoder_link"] = decoder_link
    return event


# ---------------------------------------------------------------------------
# PDML document handling
# ---------------------------------------------------------------------------


def _endpoint_from_proto(packet: ElementTree.Element, direction: str) -> dict[str, Any] | None:
    address = None
    port = None
    for proto_name, field_name in (
        ("ip", f"ip.{direction}"),
        ("ipv6", f"ipv6.{direction}"),
        ("udp", f"udp.{direction}port"),
    ):
        proto = packet.find(f"proto[@name='{proto_name}']")
        if proto is None:
            continue
        value = _show(proto, field_name)
        if value is None:
            continue
        if field_name.endswith("port"):
            port = to_int(value)
        else:
            address = value
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def _frame_metadata(packet: ElementTree.Element) -> dict[str, Any]:
    frame_proto = packet.find("proto[@name='frame']")
    if frame_proto is None:
        raise InputError("PDML packet lacks a frame layer")
    number = to_int(_show(frame_proto, "frame.number"))
    if number is None:
        raise InputError("PDML packet lacks frame.number")
    epoch = _show(frame_proto, "frame.time_epoch")
    if epoch is None:
        raise InputError("PDML packet lacks frame.time_epoch")
    return {
        "frame_number": number,
        "timestamp": normalize_timestamp(epoch),
        "source": _endpoint_from_proto(packet, "src"),
        "destination": _endpoint_from_proto(packet, "dst"),
    }


def pdml_events(stream, capture_file: str) -> Iterator[dict[str, Any]]:
    """Yield events from a PDML document, one per GTPv2-C message.

    A single frame may carry more than one GTPv2-C message (piggybacking); each
    dissector layer becomes its own event with an explicit occurrence index.
    """
    try:
        context = ElementTree.iterparse(stream, events=("end",))
        for _, element in context:
            if element.tag != "packet":
                continue
            frame = _frame_metadata(element)
            occurrence = 0
            for proto in element.findall("proto[@name='gtpv2']"):
                yield layer_event(proto, frame, capture_file, occurrence)
                occurrence += 1
            element.clear()
    except ElementTree.ParseError as exc:
        raise InputError(f"PDML document is not well formed: {exc}") from exc


# ---------------------------------------------------------------------------
# Flat fields JSONL input
# ---------------------------------------------------------------------------

FLAT_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "gtpv2.version",
    "gtpv2.flags",
    "gtpv2.t",
    "gtpv2.p",
    "gtpv2.message_type",
    "gtpv2.msg_length",
    "gtpv2.teid",
    "gtpv2.seq",
    "gtpv2.cause",
    "gtpv2.ebi",
    "gtpv2.apn",
    "gtpv2.pdn_type",
    "gtpv2.pdn_addr_and_prefix.ipv4",
    "gtpv2.pdn_addr_and_prefix.ipv6",
    "gtpv2.rat_type",
    "gtpv2.ambr_up",
    "gtpv2.ambr_down",
    "gtpv2.f_teid_interface_type",
    "gtpv2.f_teid_gre_key",
    "gtpv2.f_teid_ipv4",
    "gtpv2.f_teid_ipv6",
)


def _flat_endpoint(record: dict[str, Any], direction: str) -> dict[str, Any] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = to_int(clean(record.get(f"udp.{direction}port")))
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def normalize_flat_record(record: object, capture_file: str, occurrence: int = 0) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise InputError("structured GTPv2-C record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    message_code = parse_int(record.get("gtpv2.message_type"), "gtpv2.message_type")
    if not 0 <= message_code <= 255:
        raise InputError("gtpv2.message_type must be within 0..255")

    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    name, support_status, procedure, family = resolve_message(message_code)

    raw_teid = clean(record.get("gtpv2.teid"))
    if raw_teid is None:
        teid_state, teid = HEADER_TEID_ABSENT, None
    else:
        teid = to_int(raw_teid)
        teid_state = HEADER_TEID_ZERO if teid == 0 else HEADER_TEID_PRESENT

    header = {
        "version": to_int(clean(record.get("gtpv2.version"))),
        "flags": to_int(clean(record.get("gtpv2.flags"))),
        "teid_flag": (lambda value: None if value is None else value == 1)(to_int(clean(record.get("gtpv2.t")))),
        "piggybacking_flag": (lambda value: None if value is None else value == 1)(
            to_int(clean(record.get("gtpv2.p")))
        ),
        "message_length": to_int(clean(record.get("gtpv2.msg_length"))),
        "teid": teid,
        "teid_state": teid_state,
        "sequence_number": to_int(clean(record.get("gtpv2.seq"))),
    }

    causes = [to_int(item) for item in repeated(record.get("gtpv2.cause"))]
    causes = [item for item in causes if item is not None]
    message_cause = None
    if causes:
        message_cause = {"cause_code": causes[0], "cause_name": CAUSES.get(causes[0]), "scope": "message"}

    interface_types = repeated(record.get("gtpv2.f_teid_interface_type"))
    gre_keys = repeated(record.get("gtpv2.f_teid_gre_key"))
    ipv4 = repeated(record.get("gtpv2.f_teid_ipv4"))
    ipv6 = repeated(record.get("gtpv2.f_teid_ipv6"))
    f_teids: list[dict[str, Any]] = []
    if any((interface_types, gre_keys, ipv4, ipv6)):
        count = max(len(interface_types), len(gre_keys), len(ipv4), len(ipv6))
        for index in range(count):
            interface_type = to_int(interface_types[index]) if index < len(interface_types) else None
            f_teids.append(
                {
                    # Flat input cannot tell a message-scope F-TEID from one
                    # nested inside a Bearer Context, so the scope stays unbound.
                    "scope": "unbound",
                    "interface_type": interface_type,
                    "interface_type_name": INTERFACE_TYPES.get(interface_type)
                    if interface_type is not None
                    else None,
                    "teid": to_int(gre_keys[index]) if index < len(gre_keys) else None,
                    "ipv4": ipv4[index] if index < len(ipv4) else None,
                    "ipv6": ipv6[index] if index < len(ipv6) else None,
                    "ipv4_present": index < len(ipv4),
                    "ipv6_present": index < len(ipv6),
                }
            )

    elements: dict[str, Any] = {}
    apn = clean(record.get("gtpv2.apn"))
    if apn is not None:
        elements["apn_present"] = True
        elements["apn_length"] = len(apn)
    pdn_type = to_int(clean(record.get("gtpv2.pdn_type")))
    if pdn_type is not None:
        elements["pdn_type"] = {"value": pdn_type, "name": PDN_TYPES.get(pdn_type)}
    if clean(record.get("gtpv2.pdn_addr_and_prefix.ipv4")) is not None:
        elements["paa_present"] = True
        elements["paa_address_family"] = "IPv4"
    elif clean(record.get("gtpv2.pdn_addr_and_prefix.ipv6")) is not None:
        elements["paa_present"] = True
        elements["paa_address_family"] = "IPv6"
    rat_type = to_int(clean(record.get("gtpv2.rat_type")))
    if rat_type is not None:
        elements["rat_type"] = {"value": rat_type, "name": RAT_TYPES.get(rat_type)}
    ambr_up = to_int(clean(record.get("gtpv2.ambr_up")))
    ambr_down = to_int(clean(record.get("gtpv2.ambr_down")))
    if ambr_up is not None or ambr_down is not None:
        elements["ambr_present"] = True
        elements["ambr_uplink"] = ambr_up
        elements["ambr_downlink"] = ambr_down

    ebis = [item for item in (to_int(value) for value in repeated(record.get("gtpv2.ebi"))) if item is not None]

    limitations = [
        "flat field input does not preserve grouped-IE item boundaries, so no bearer context is published"
    ]
    unbound: dict[str, Any] = {
        "binding_basis": HIERARCHY_FLAT,
        "limitations": [
            "values are decoded IE values without a provable bearer-context binding",
            "a flat field list cannot separate message-scope from bearer-scope values",
        ],
    }
    if ebis:
        unbound["ebi_values"] = bounded(ebis)
    if len(causes) > 1:
        unbound["additional_causes"] = bounded(
            [
                {"cause_code": code, "cause_name": CAUSES.get(code), "scope": "message"}
                for code in causes[1:]
            ]
        )
    if f_teids:
        unbound["f_teid_values"] = bounded(
            [
                {
                    "interface_type": item["interface_type"],
                    "interface_type_name": item["interface_type_name"],
                    "teid": item["teid"],
                }
                for item in f_teids
            ]
        )

    source_ref = f"capture:{capture_file}#frame={frame_number}"
    if occurrence:
        source_ref += f"; occurrence={occurrence}"
    source_ref += f"; message-type={message_code}"

    event: dict[str, Any] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "message_occurrence": occurrence,
        "capture_file": capture_file,
        "protocol": PROTOCOL,
        "transport": TRANSPORT,
        "message_type_code": message_code,
        "message_type": name,
        "procedure_family": procedure,
        "message_family": family,
        "support_status": support_status,
        "hierarchy_basis": HIERARCHY_FLAT,
        "header": header,
        "message_cause": message_cause,
        "information_elements": elements,
        "identity_ies": {},
        "f_teids": bounded(f_teids),
        "bearer_contexts": [],
        "unbound_ie_metadata": unbound,
        "ie_summary": [],
        "extraction_limitations": limitations,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": [],
    }
    source = _flat_endpoint(record, "src")
    destination = _flat_endpoint(record, "dst")
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    return event


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"invalid JSON Lines record at line {number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"JSON Lines record at line {number} is not an object")
            yield record


def project_trace_event(event: dict[str, Any]) -> dict[str, Any]:
    projected: dict[str, Any] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL,
        "interface": None,
        "procedure": event.get("procedure_family"),
        "message_type": event.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"gtpv2-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    for role in ("source", "destination"):
        if event.get(role) is not None:
            projected[role] = event[role]
    cause = event.get("message_cause")
    if isinstance(cause, dict):
        projected["result"] = {"status": None, "cause": f"gtpv2:{cause['cause_code']}", "code": cause["cause_code"]}
    return projected


# ---------------------------------------------------------------------------
# TShark invocation
# ---------------------------------------------------------------------------


def resolve_tshark_executable() -> str:
    return shutil.which("tshark") or "tshark"


def tshark_version(tshark_bin: str | None = None) -> str:
    exe = tshark_bin or resolve_tshark_executable()
    try:
        completed = subprocess.run(
            [exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def tshark_pdml_stream(capture: Path, tshark_bin: str | None = None) -> subprocess.Popen:
    exe = tshark_bin or resolve_tshark_executable()
    command = [exe, "-n", "-r", str(capture), "-T", "pdml", "-Y", "gtpv2"]
    try:
        return subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark and retry") from exc


def input_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    suffix = path.suffix.lower()
    if suffix in {".pcap", ".pcapng", ".cap"}:
        return "capture"
    if suffix in {".pdml", ".xml"}:
        return "pdml"
    if suffix in {".jsonl", ".ndjson"}:
        return "fields-jsonl"
    raise InputError("cannot infer input format; use --input-format capture, pdml or fields-jsonl")


def events_from_capture(capture: Path, capture_file: str) -> Iterator[dict[str, Any]]:
    process = tshark_pdml_stream(capture)
    try:
        assert process.stdout is not None
        yield from pdml_events(process.stdout, capture_file)
    finally:
        stderr = b""
        if process.stderr is not None:
            stderr = process.stderr.read() or b""
        code = process.wait()
        if code != 0:
            detail = stderr.decode("utf-8", errors="replace").strip() or f"exit {code}"
            raise TsharkError(f"tshark capture dissection failed: {detail}")


def events_for_input(path: Path, requested: str) -> tuple[Iterator[dict[str, Any]], str | None]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path}")
    kind = input_kind(path, requested)
    capture_file = safe_capture_name(path)
    if kind == "fields-jsonl":
        def flat() -> Iterator[dict[str, Any]]:
            per_frame: dict[int, int] = {}
            for record in read_jsonl(path):
                frame = parse_int(record.get("frame.number"), "frame.number")
                occurrence = per_frame.get(frame, 0)
                per_frame[frame] = occurrence + 1
                yield normalize_flat_record(record, capture_file, occurrence)

        return flat(), None
    if kind == "pdml":
        def from_document() -> Iterator[dict[str, Any]]:
            with path.open("rb") as handle:
                yield from pdml_events(handle, capture_file)

        return from_document(), None
    if kind == "capture":
        return events_from_capture(path, capture_file), tshark_version()
    raise InputError(f"unsupported input format: {kind}")
