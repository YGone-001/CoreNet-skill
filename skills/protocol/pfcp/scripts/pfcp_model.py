#!/usr/bin/env python3
"""Shared, standalone helpers for bounded PFCP (N4) session-control extraction.

Reviewed basis: 3GPP TS 29.244 version 19.6.0 Release 19 (Interface between
the Control Plane and the User Plane nodes). Message type codes come from
table 7.3-1, cause values from table 8.2.1-1, and the source-interface
values from table 8.2.2-1. Header semantics follow clause 7.2.2, including
clause 7.2.2.4.2 ("Conditions for Sending SEID=0 in PFCP Header").

Field names follow the PFCP dissector of Wireshark/TShark as published in
the Wireshark display-filter reference. The reviewed environment had no
local tshark installation, so field names are published-reference verified
rather than locally re-dumped; that verification debt is recorded in
references/field-reference.md. No field name is invented: where the
reference exposes no field (the F-SEID's own 64-bit SEID value, and the
PFCP version), the value is accepted from structured input only.

Bounded semantics: Heartbeat, Association Setup, Session Establishment,
Session Modification, and Session Deletion are SUPPORTED. Other reviewed
message types are recognized by name and reported UNSUPPORTED; codes
outside the reviewed table are UNKNOWN. This module never implements a raw
PFCP byte parser, never decodes GTP-U traffic, never interprets SBI, and
never decides whether a PDU session or a user-plane path works.

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

SCHEMA_NAME = "pfcp-event"

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "pfcp.msg_type",
    "pfcp.length",
    "pfcp.s",
    "pfcp.mp_flag",
    "pfcp.seid",
    "pfcp.seqno",
    "pfcp.mp",
    "pfcp.cause",
    "pfcp.node_id_ipv4",
    "pfcp.node_id_ipv6",
    "pfcp.node_id_fqdn",
    "pfcp.recovery_time_stamp",
    "pfcp.f_seid.ipv4",
    "pfcp.f_seid.ipv6",
    "pfcp.f_seid_flags.v4",
    "pfcp.f_seid_flags.v6",
    "pfcp.pdr_id",
    "pfcp.far_id",
    "pfcp.qer_id",
    "pfcp.urr_id",
    "pfcp.precedence",
    "pfcp.apply_action.drop",
    "pfcp.apply_action.forw",
    "pfcp.apply_action.buff",
    "pfcp.apply_action.nocp",
    "pfcp.apply_action.dupl",
    "pfcp.source_interface",
    "pfcp.dst_interface",
    "pfcp.f_teid.teid",
    "pfcp.f_teid.ipv4_addr",
    "pfcp.f_teid.ipv6_addr",
    "pfcp.f_teid.choose_id",
    "pfcp.f_teid_flags.ch",
    "pfcp.f_teid_flags.ch_id",
    "pfcp.outer_hdr_creation.teid",
    "pfcp.outer_hdr_creation.ipv4",
    "pfcp.outer_hdr_creation.ipv6",
    "pfcp.outer_hdr_desc",
    "pfcp.network_instance",
    "pfcp.ue_ip_addr_ipv4",
    "pfcp.ue_ip_addr_ipv6",
    "pfcp.qfi_value",
    "pfcp.gate_status.ulgate",
    "pfcp.gate_status.dlgate",
    "pfcp.ul_mbr",
    "pfcp.dl_mbr",
    "pfcp.ul_gbr",
    "pfcp.dl_gbr",
)

@dataclass(frozen=True)
class FieldSpec:
    """Bounded field specification for direct-capture compatibility."""

    canonical_name: str
    tshark_candidates: tuple[str, ...]
    required: bool = False


FIELD_SPECS: tuple[FieldSpec, ...] = (
    FieldSpec("frame.number", ("frame.number",), required=True),
    FieldSpec("frame.time_epoch", ("frame.time_epoch",), required=True),
    FieldSpec("pfcp.msg_type", ("pfcp.msg_type",), required=True),
    FieldSpec("pfcp.outer_hdr_desc", ("pfcp.outer_hdr_desc", "pfcp.out_hdr_desc"), required=False),
    *(
        FieldSpec(field, (field,), required=False)
        for field in FIELDS
        if field not in ("frame.number", "frame.time_epoch", "pfcp.msg_type", "pfcp.outer_hdr_desc")
    ),
)

FILTER_CANDIDATES = ("pfcp",)

KIND_NODE = "node"
KIND_SESSION = "session"

ROLE_REQUEST = "request"
ROLE_RESPONSE = "response"

# Reviewed message types (TS 29.244 19.6.0 table 7.3-1):
# code -> (reviewed name, kind, procedure family, transaction role).
MESSAGE_TYPES = {
    1: ("PFCP Heartbeat Request", KIND_NODE, "Heartbeat", ROLE_REQUEST),
    2: ("PFCP Heartbeat Response", KIND_NODE, "Heartbeat", ROLE_RESPONSE),
    3: ("PFCP PFD Management Request", KIND_NODE, "PFDManagement", ROLE_REQUEST),
    4: ("PFCP PFD Management Response", KIND_NODE, "PFDManagement", ROLE_RESPONSE),
    5: ("PFCP Association Setup Request", KIND_NODE, "AssociationSetup", ROLE_REQUEST),
    6: ("PFCP Association Setup Response", KIND_NODE, "AssociationSetup", ROLE_RESPONSE),
    7: ("PFCP Association Update Request", KIND_NODE, "AssociationUpdate", ROLE_REQUEST),
    8: ("PFCP Association Update Response", KIND_NODE, "AssociationUpdate", ROLE_RESPONSE),
    9: ("PFCP Association Release Request", KIND_NODE, "AssociationRelease", ROLE_REQUEST),
    10: ("PFCP Association Release Response", KIND_NODE, "AssociationRelease", ROLE_RESPONSE),
    11: ("PFCP Version Not Supported Response", KIND_NODE, "VersionNotSupported", ROLE_RESPONSE),
    12: ("PFCP Node Report Request", KIND_NODE, "NodeReport", ROLE_REQUEST),
    13: ("PFCP Node Report Response", KIND_NODE, "NodeReport", ROLE_RESPONSE),
    14: ("PFCP Session Set Deletion Request", KIND_NODE, "SessionSetDeletion", ROLE_REQUEST),
    15: ("PFCP Session Set Deletion Response", KIND_NODE, "SessionSetDeletion", ROLE_RESPONSE),
    16: ("PFCP Session Set Modification Request", KIND_NODE, "SessionSetModification", ROLE_REQUEST),
    17: ("PFCP Session Set Modification Response", KIND_NODE, "SessionSetModification", ROLE_RESPONSE),
    50: ("PFCP Session Establishment Request", KIND_SESSION, "SessionEstablishment", ROLE_REQUEST),
    51: ("PFCP Session Establishment Response", KIND_SESSION, "SessionEstablishment", ROLE_RESPONSE),
    52: ("PFCP Session Modification Request", KIND_SESSION, "SessionModification", ROLE_REQUEST),
    53: ("PFCP Session Modification Response", KIND_SESSION, "SessionModification", ROLE_RESPONSE),
    54: ("PFCP Session Deletion Request", KIND_SESSION, "SessionDeletion", ROLE_REQUEST),
    55: ("PFCP Session Deletion Response", KIND_SESSION, "SessionDeletion", ROLE_RESPONSE),
    56: ("PFCP Session Report Request", KIND_SESSION, "SessionReport", ROLE_REQUEST),
    57: ("PFCP Session Report Response", KIND_SESSION, "SessionReport", ROLE_RESPONSE),
}

# Semantically supported bounded subset for this version.
SUPPORTED_MESSAGE_TYPES = frozenset({1, 2, 5, 6, 50, 51, 52, 53, 54, 55})

# Reviewed cause values (TS 29.244 19.6.0 table 8.2.1-1). Only reviewed
# values carry names; anything else keeps its numeric code with a null name.
CAUSE_NAMES = {
    0: "Reserved",
    1: "Request accepted (success)",
    2: "More Usage Report to send",
    3: "Request partially accepted",
    64: "Request rejected (reason not specified)",
    65: "Session context not found",
    66: "Mandatory IE missing",
    67: "Conditional IE missing",
    68: "Invalid length",
    69: "Mandatory IE incorrect",
    70: "Invalid Forwarding Policy",
    71: "Invalid F-TEID allocation option",
    72: "No established PFCP Association",
    73: "Rule creation/modification Failure",
    74: "PFCP entity in congestion",
    75: "No resources available",
    76: "Service not supported",
    77: "System failure",
    78: "Redirection Requested",
    79: "All dynamic addresses are occupied",
    80: "Unknown Pre-defined Rule",
    81: "Unknown Application ID",
    82: "L2TP tunnel Establishment failure",
    83: "L2TP session Establishment failure",
    84: "L2TP tunnel release",
    85: "L2TP session release",
    86: "PFCP session restoration failure due to requested resource not available",
    87: "L2TP tunnel Establishment failure - Tunnel Auth Failure",
    88: "L2TP Session Establishment failure - Session Auth Failure",
    89: "L2TP tunnel Establishment failure - LNS not reachable",
    90: "PFD Contents Syntax Error",
    91: "PFD Contents Semantics Error",
    92: "PFD Application Id Unknown",
}

# TS 29.244 19.6.0 table 8.2.2-1 interface values.
SOURCE_INTERFACE_VALUES = {
    0: "Access",
    1: "Core",
    2: "SGi-LAN/N6-LAN",
    3: "CP-function",
    4: "5G VN Internal",
}

# Procedures initiated by the CP function over N4. Heartbeat may be
# initiated by either node, so its direction stays null.
CP_INITIATED_FAMILIES = frozenset({"AssociationSetup", "SessionEstablishment", "SessionModification", "SessionDeletion"})
UP_INITIATED_FAMILIES = frozenset({"SessionReport"})

RULE_OPERATIONS = ("CREATE", "UPDATE", "REMOVE")

# Rule-group operations that are fixed by the message definition: a Session
# Establishment Request only carries Create groups, and a Session Deletion
# Request carries none. Modification requests mix operations, so their
# operation is never derived from the message type.
FIXED_RULE_OPERATION = {50: "CREATE"}

BINDING_STRUCTURED = "structured-input"
BINDING_SINGLE_RULE = "single-rule-message"
BINDING_UNBOUND = "unbound"

# Message types whose reviewed header requires the SEID field to be zero
# (TS 29.244 19.6.0 clause 7.2.2.4.2).
SEID_ZERO_MESSAGE_TYPES = frozenset({50})

RULE_TYPES = ("pdrs", "fars", "qers", "urrs")


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested PFCP fields."""


@dataclass(frozen=True)
class MessageIdentity:
    """Normalized PFCP identity for one observed datagram."""

    message_type_code: int
    message_type: str | None
    message_kind: str | None
    family: str | None
    transaction_role: str | None
    support_status: str
    direction: str | None
    direction_basis: str | None
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


def first_token(value: object) -> str | None:
    """Return the first comma-separated token of a scalar field.

    A dissector field that occurs more than once is exported comma-joined;
    a scalar field keeps only its first token so a repeated field never
    corrupts a single-valued property.
    """
    text = clean(value)
    if text is None:
        return None
    return text.split(",")[0].strip() or None


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
        port = int(text, 0)
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
    """Normalize PFCP message identity from the reviewed message-type table."""
    derivations: list[str] = []
    known = MESSAGE_TYPES.get(code)
    if known is None:
        return MessageIdentity(
            message_type_code=code,
            message_type=None,
            message_kind=None,
            family=None,
            transaction_role=None,
            support_status="UNKNOWN",
            direction=None,
            direction_basis=None,
            derivations=(),
        )
    name, kind, family, role = known
    derivations.extend(["message_type", "message_kind", "family"])
    direction = None
    if family in CP_INITIATED_FAMILIES:
        direction = "control-plane-to-user-plane" if role == ROLE_REQUEST else "user-plane-to-control-plane"
    elif family in UP_INITIATED_FAMILIES:
        direction = "user-plane-to-control-plane" if role == ROLE_REQUEST else "control-plane-to-user-plane"
    if direction is not None:
        derivations.append("direction")
    return MessageIdentity(
        message_type_code=code,
        message_type=name,
        message_kind=kind,
        family=family,
        transaction_role=role,
        support_status="SUPPORTED" if code in SUPPORTED_MESSAGE_TYPES else "UNSUPPORTED",
        direction=direction,
        direction_basis="message-definition" if direction is not None else None,
        derivations=tuple(sorted(derivations)),
    )


def parse_header(record: dict[str, object], identity: MessageIdentity) -> dict[str, object]:
    """Preserve directly observed PFCP header fields.

    The header SEID and the F-SEID are separate observations and are never
    substituted for each other. ``seid_expected_zero`` records whether the
    reviewed message definition requires a zero SEID (TS 29.244 clause
    7.2.2.4.2) so a non-zero value stays visible rather than being corrected.
    """
    version = optional_int(record.get("pfcp.version"))
    if version is None:
        version = optional_int(record.get("version"))
    if version is not None and not 0 <= version <= 7:
        raise InputError("pfcp.version must be within 0..7")
    s_flag = optional_bool(record.get("pfcp.s"))
    if s_flag is None:
        s_flag = optional_bool(record.get("pfcp.s_flag"))
    seid = optional_int(record.get("pfcp.seid"))
    if seid is not None and not 0 <= seid <= 18446744073709551615:
        raise InputError("pfcp.seid must be within the 64-bit unsigned range")
    sequence_number = optional_int(record.get("pfcp.seqno"))
    if sequence_number is None:
        sequence_number = optional_int(record.get("pfcp.sequence_number"))
    if sequence_number is not None and not 0 <= sequence_number <= 16777215:
        raise InputError("pfcp.seqno must be within the 24-bit sequence range")
    priority = optional_int(record.get("pfcp.mp"))
    if priority is not None and not 0 <= priority <= 15:
        raise InputError("pfcp.mp must be within 0..15")
    return {
        "version": version,
        "s_flag": s_flag,
        "mp_flag": optional_bool(record.get("pfcp.mp_flag")),
        "message_type_code": identity.message_type_code,
        "message_type": identity.message_type,
        "message_length": optional_int(record.get("pfcp.length")),
        "seid": seid,
        "sequence_number": sequence_number,
        "priority": priority,
        "seid_expected_zero": identity.message_type_code in SEID_ZERO_MESSAGE_TYPES,
    }


def _empty_f_seid() -> dict[str, object]:
    return {"seid": None, "ipv4": None, "ipv6": None}


def parse_structured_f_seid(value: object, label: str) -> dict[str, object] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise InputError(f"{label} must be an object")
    seid = optional_int(value.get("seid"))
    if seid is not None and not 0 <= seid <= 18446744073709551615:
        raise InputError(f"{label}.seid must be within the 64-bit unsigned range")
    return {"seid": seid, "ipv4": clean(value.get("ipv4")), "ipv6": clean(value.get("ipv6"))}


def resolve_f_seids(record: dict[str, object], identity: MessageIdentity) -> tuple[dict[str, object] | None, dict[str, object] | None, list[str]]:
    """Return (cp_f_seid, up_f_seid, limitations).

    The reviewed dissector reference exposes only ``pfcp.f_seid.ipv4`` /
    ``pfcp.f_seid.ipv6`` / ``pfcp.f_seid_flags.*`` — there is no filterable
    field for the F-SEID's own 64-bit SEID value. The role is therefore
    taken from an explicit structured field when present, or derived from
    the message definition (an Establishment Request carries the CP F-SEID;
    an Establishment Response carries the UP F-SEID).
    """
    limitations: list[str] = []
    cp = parse_structured_f_seid(record.get("cp_f_seid"), "cp_f_seid")
    up = parse_structured_f_seid(record.get("up_f_seid"), "up_f_seid")
    flat_ipv4 = clean(record.get("pfcp.f_seid.ipv4"))
    flat_ipv6 = clean(record.get("pfcp.f_seid.ipv6"))
    if flat_ipv4 is None and flat_ipv6 is None:
        return cp, up, limitations
    if cp is not None or up is not None:
        limitations.append("both explicit F-SEID roles and flattened F-SEID fields were present; explicit roles were used")
        return cp, up, limitations
    derived = _empty_f_seid()
    derived["ipv4"] = flat_ipv4
    derived["ipv6"] = flat_ipv6
    if identity.message_type_code == 50:
        return derived, None, limitations
    if identity.message_type_code == 51:
        return None, derived, limitations
    limitations.append("F-SEID observed but the CP/UP role is not derivable from this message type")
    return None, None, limitations


def _empty_rule(rule_type: str, rule_id: int, operation: str | None, basis: str) -> dict[str, object]:
    if rule_type == "pdrs":
        return {
            "id": rule_id,
            "operation": operation,
            "binding_basis": basis,
            "precedence": None,
            "pdi_present": False,
            "source_interface": None,
            "f_teid": None,
            "ue_ip": {"ipv4": None, "ipv6": None},
            "network_instance": None,
            "qfi_values": [],
            "far_ids": [],
            "qer_ids": [],
            "urr_ids": [],
        }
    if rule_type == "fars":
        return {
            "id": rule_id,
            "operation": operation,
            "binding_basis": basis,
            "apply_action": {"drop": None, "forward": None, "buffer": None, "notify_cp": None, "duplicate": None},
            "forwarding_parameters_present": False,
            "destination_interface": None,
            "network_instance": None,
            "outer_header_creation": {"present": False, "description": None, "teid": None, "ipv4": None, "ipv6": None},
        }
    if rule_type == "qers":
        return {
            "id": rule_id,
            "operation": operation,
            "binding_basis": basis,
            "gate_status": {"ul": None, "dl": None},
            "qfi": None,
            "ul_mbr": None,
            "dl_mbr": None,
            "ul_gbr": None,
            "dl_gbr": None,
        }
    return {"id": rule_id, "operation": operation, "binding_basis": basis, "measurement_present": False}


def _structured_rules(record: dict[str, object]) -> dict[str, list[dict[str, object]]] | None:
    """Parse the explicit structured rule groups (hierarchy preserved)."""
    raw = record.get("rule_groups")
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise InputError("rule_groups must be an object")
    result: dict[str, list[dict[str, object]]] = {}
    for rule_type in RULE_TYPES:
        entries = raw.get(rule_type, [])
        if entries is None:
            entries = []
        if not isinstance(entries, list):
            raise InputError(f"rule_groups.{rule_type} must be an array")
        items: list[dict[str, object]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise InputError(f"each rule_groups.{rule_type} entry must be an object")
            rule_id = optional_int(entry.get("id"))
            if rule_id is None:
                raise InputError(f"rule_groups.{rule_type} entry requires an id")
            if not 0 <= rule_id <= 4294967295:
                raise InputError(f"rule_groups.{rule_type} id must be within the unsigned range")
            operation = clean(entry.get("operation"))
            if operation is not None and operation not in RULE_OPERATIONS:
                raise InputError("rule operation must be CREATE, UPDATE or REMOVE")
            item = _empty_rule(rule_type, rule_id, operation, BINDING_STRUCTURED)
            if rule_type == "pdrs":
                item["precedence"] = optional_int(entry.get("precedence"))
                item["pdi_present"] = bool(optional_bool(entry.get("pdi_present")))
                item["source_interface"] = clean(entry.get("source_interface"))
                f_teid = entry.get("f_teid")
                if isinstance(f_teid, dict):
                    item["f_teid"] = {
                        "teid": optional_int(f_teid.get("teid")),
                        "ipv4": clean(f_teid.get("ipv4")),
                        "ipv6": clean(f_teid.get("ipv6")),
                        "choose": optional_bool(f_teid.get("choose")),
                        "choose_id": clean(f_teid.get("choose_id")),
                    }
                item["ue_ip"] = {"ipv4": clean(entry.get("ue_ipv4")), "ipv6": clean(entry.get("ue_ipv6"))}
                item["network_instance"] = clean(entry.get("network_instance"))
                item["qfi_values"] = repeated_ints(entry.get("qfi_values"))
                item["far_ids"] = repeated_ints(entry.get("far_ids"))
                item["qer_ids"] = repeated_ints(entry.get("qer_ids"))
                item["urr_ids"] = repeated_ints(entry.get("urr_ids"))
            elif rule_type == "fars":
                action = entry.get("apply_action")
                if isinstance(action, dict):
                    item["apply_action"] = {
                        "drop": optional_bool(action.get("drop")),
                        "forward": optional_bool(action.get("forward")),
                        "buffer": optional_bool(action.get("buffer")),
                        "notify_cp": optional_bool(action.get("notify_cp")),
                        "duplicate": optional_bool(action.get("duplicate")),
                    }
                item["forwarding_parameters_present"] = bool(optional_bool(entry.get("forwarding_parameters_present")))
                item["destination_interface"] = clean(entry.get("destination_interface"))
                item["network_instance"] = clean(entry.get("network_instance"))
                outer = entry.get("outer_header_creation")
                if isinstance(outer, dict):
                    item["outer_header_creation"] = {
                        "present": bool(optional_bool(outer.get("present"))),
                        "description": clean(outer.get("description")),
                        "teid": optional_int(outer.get("teid")),
                        "ipv4": clean(outer.get("ipv4")),
                        "ipv6": clean(outer.get("ipv6")),
                    }
            elif rule_type == "qers":
                gate = entry.get("gate_status")
                if isinstance(gate, dict):
                    item["gate_status"] = {"ul": optional_int(gate.get("ul")), "dl": optional_int(gate.get("dl"))}
                item["qfi"] = optional_int(entry.get("qfi"))
                item["ul_mbr"] = optional_int(entry.get("ul_mbr"))
                item["dl_mbr"] = optional_int(entry.get("dl_mbr"))
                item["ul_gbr"] = optional_int(entry.get("ul_gbr"))
                item["dl_gbr"] = optional_int(entry.get("dl_gbr"))
            else:
                item["measurement_present"] = bool(optional_bool(entry.get("measurement_present")))
            items.append(item)
        result[rule_type] = items
    return result


def _flattened_rules(record: dict[str, object], identity: MessageIdentity) -> dict[str, list[dict[str, object]]]:
    """Build rule items from flattened dissector fields, conservatively.

    A repeated flattened field carries no parent-child structure, so a
    per-type item is created from the observed identifiers, and nested
    scalar values attach only when that type has exactly one item. QFI binds
    only when the message holds exactly one rule item in total. Anything
    else is preserved as unbound evidence instead of being zipped by
    position.
    """
    default_operation = FIXED_RULE_OPERATION.get(identity.message_type_code)
    id_fields = {"pdrs": "pfcp.pdr_id", "fars": "pfcp.far_id", "qers": "pfcp.qer_id", "urrs": "pfcp.urr_id"}
    groups: dict[str, list[dict[str, object]]] = {}
    for rule_type, field in id_fields.items():
        ids: list[int] = []
        for value in repeated_ints(record.get(field)):
            if value not in ids:
                ids.append(value)
        basis = BINDING_SINGLE_RULE if len(ids) == 1 else BINDING_UNBOUND
        groups[rule_type] = [_empty_rule(rule_type, rule_id, default_operation, basis) for rule_id in ids]

    total_items = sum(len(items) for items in groups.values())

    pdrs = groups["pdrs"]
    if len(pdrs) == 1:
        item = pdrs[0]
        item["precedence"] = optional_int(record.get("pfcp.precedence"))
        item["pdi_present"] = any(
            clean(record.get(field)) is not None
            for field in ("pfcp.source_interface", "pfcp.f_teid.teid", "pfcp.ue_ip_addr_ipv4", "pfcp.ue_ip_addr_ipv6")
        )
        source_interface = optional_int(record.get("pfcp.source_interface"))
        item["source_interface"] = SOURCE_INTERFACE_VALUES.get(source_interface, f"unknown-{source_interface}") if source_interface is not None else None
        teid = optional_int(record.get("pfcp.f_teid.teid"))
        if teid is not None or clean(record.get("pfcp.f_teid.ipv4_addr")) or clean(record.get("pfcp.f_teid.ipv6_addr")):
            item["f_teid"] = {
                "teid": teid,
                "ipv4": clean(record.get("pfcp.f_teid.ipv4_addr")),
                "ipv6": clean(record.get("pfcp.f_teid.ipv6_addr")),
                "choose": optional_bool(record.get("pfcp.f_teid_flags.ch")),
                "choose_id": clean(record.get("pfcp.f_teid.choose_id")),
            }
        item["ue_ip"] = {"ipv4": clean(record.get("pfcp.ue_ip_addr_ipv4")), "ipv6": clean(record.get("pfcp.ue_ip_addr_ipv6"))}
        item["network_instance"] = clean(record.get("pfcp.network_instance"))
        if total_items == 1:
            item["qfi_values"] = repeated_ints(record.get("pfcp.qfi_value"))

    fars = groups["fars"]
    if len(fars) == 1:
        item = fars[0]
        item["apply_action"] = {
            "drop": optional_bool(record.get("pfcp.apply_action.drop")),
            "forward": optional_bool(record.get("pfcp.apply_action.forw")),
            "buffer": optional_bool(record.get("pfcp.apply_action.buff")),
            "notify_cp": optional_bool(record.get("pfcp.apply_action.nocp")),
            "duplicate": optional_bool(record.get("pfcp.apply_action.dupl")),
        }
        outer_teid = optional_int(record.get("pfcp.outer_hdr_creation.teid"))
        outer_ipv4 = clean(record.get("pfcp.outer_hdr_creation.ipv4"))
        outer_ipv6 = clean(record.get("pfcp.outer_hdr_creation.ipv6"))
        description = clean(record.get("pfcp.outer_hdr_desc"))
        if outer_teid is not None or outer_ipv4 or outer_ipv6 or description:
            item["outer_header_creation"] = {
                "present": True,
                "description": description,
                "teid": outer_teid,
                "ipv4": outer_ipv4,
                "ipv6": outer_ipv6,
            }
            item["forwarding_parameters_present"] = True
        destination = optional_int(record.get("pfcp.dst_interface"))
        item["destination_interface"] = SOURCE_INTERFACE_VALUES.get(destination, f"unknown-{destination}") if destination is not None else None
        item["network_instance"] = clean(record.get("pfcp.network_instance"))

    qers = groups["qers"]
    if len(qers) == 1:
        item = qers[0]
        item["gate_status"] = {
            "ul": optional_int(record.get("pfcp.gate_status.ulgate")),
            "dl": optional_int(record.get("pfcp.gate_status.dlgate")),
        }
        item["qfi"] = optional_int(record.get("pfcp.qfi_value")) if total_items == 1 else None
        item["ul_mbr"] = optional_int(record.get("pfcp.ul_mbr"))
        item["dl_mbr"] = optional_int(record.get("pfcp.dl_mbr"))
        item["ul_gbr"] = optional_int(record.get("pfcp.ul_gbr"))
        item["dl_gbr"] = optional_int(record.get("pfcp.dl_gbr"))

    urrs = groups["urrs"]
    if len(urrs) == 1:
        urrs[0]["measurement_present"] = clean(record.get("pfcp.urr_id")) is not None
    return groups


def resolve_rule_operations(record: dict[str, object], identity: MessageIdentity) -> tuple[dict[str, object] | None, dict[str, object] | None]:
    """Return (rule_operations, unbound_ie_metadata)."""
    structured = _structured_rules(record)
    flattened_present = any(clean(record.get(field)) is not None for field in ("pfcp.pdr_id", "pfcp.far_id", "pfcp.qer_id", "pfcp.urr_id"))
    if structured is None and not flattened_present:
        extra_unbound = _unbound_from_record(record)
        return None, extra_unbound

    limitations: list[str] = []
    if structured is not None:
        groups = structured
        for items in groups.values():
            for item in items:
                if item["operation"] is None:
                    item["operation"] = FIXED_RULE_OPERATION.get(identity.message_type_code)
        flat_ids = {
            "pdrs": repeated_ints(record.get("pfcp.pdr_id")),
            "fars": repeated_ints(record.get("pfcp.far_id")),
            "qers": repeated_ints(record.get("pfcp.qer_id")),
            "urrs": repeated_ints(record.get("pfcp.urr_id")),
        }
        for rule_type, ids in flat_ids.items():
            covered = {item["id"] for item in groups[rule_type]}
            if any(rule_id not in covered for rule_id in ids):
                limitations.append(f"structured {rule_type} do not cover every observed identifier")
    else:
        groups = _flattened_rules(record, identity)
        total_items = sum(len(items) for items in groups.values())
        if total_items > 1:
            limitations.append("multiple rule items observed in flattened output; nested values were not bound by position")

    unbound = _unbound_from_record(record)
    teids = repeated_ints(record.get("pfcp.f_teid.teid")) if structured is None else []
    outer_teids = repeated_ints(record.get("pfcp.outer_hdr_creation.teid")) if structured is None else []
    qfis = repeated_ints(record.get("pfcp.qfi_value")) if structured is None else []
    bound_qfis = {value for items in groups.values() for item in items for value in item.get("qfi_values", []) if isinstance(item.get("qfi_values"), list)}
    if structured is None:
        if len(teids) > 1 or (teids and len(groups["pdrs"]) != 1):
            unbound["teids"].extend(teids)
            limitations.append("F-TEID TEID values observed but not safely bound to a single PDR")
        if len(outer_teids) > 1 or (outer_teids and len(groups["fars"]) != 1):
            unbound["teids"].extend(outer_teids)
            limitations.append("Outer Header Creation TEID values observed but not safely bound to a single FAR")
        if qfis and len(groups["qers"]) != 1 and not bound_qfis:
            unbound["qfis"].extend(qfis)
            limitations.append("QFI values observed but not safely bound to a single QER or PDR")

    if unbound["limitations"]:
        limitations.extend(unbound["limitations"])
    unbound["limitations"] = list(dict.fromkeys(limitations))

    rule_operations = {
        "pdrs": groups["pdrs"],
        "fars": groups["fars"],
        "qers": groups["qers"],
        "urrs": groups["urrs"],
    }
    if not any(rule_operations.values()) and not any(unbound[key] for key in ("pdr_ids", "far_ids", "qer_ids", "urr_ids", "teids", "qfis", "causes")) and not unbound["limitations"]:
        return None, None
    return rule_operations, unbound


def _unbound_from_record(record: dict[str, object]) -> dict[str, object]:
    """Build the unbound-IE container from explicit structured hints."""
    unbound = {
        "pdr_ids": repeated_ints(record.get("unbound_pdr_ids")),
        "far_ids": repeated_ints(record.get("unbound_far_ids")),
        "qer_ids": repeated_ints(record.get("unbound_qer_ids")),
        "urr_ids": repeated_ints(record.get("unbound_urr_ids")),
        "teids": repeated_ints(record.get("unbound_teids")),
        "qfis": repeated_ints(record.get("unbound_qfis")),
        "causes": [],
        "limitations": [],
    }
    for entry in repeated_tokens(record.get("unbound_limitations")):
        unbound["limitations"].append(entry)
    return unbound


def normalize_record(record: object, capture_file: str) -> dict[str, object]:
    """Project one structured PFCP observation into the detailed event."""
    if not isinstance(record, dict):
        raise InputError("structured PFCP record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    message_type_code = parse_int(record.get("pfcp.msg_type"), "pfcp.msg_type")
    if not 0 <= message_type_code <= 255:
        raise InputError("pfcp.msg_type must be within 0..255")
    timestamp = normalize_timestamp(record.get("frame.time_epoch"))
    identity = resolve_message(message_type_code)
    header = parse_header(record, identity)
    cp_f_seid, up_f_seid, f_seid_limitations = resolve_f_seids(record, identity)

    cause_code = optional_int(record.get("pfcp.cause"))
    if cause_code is not None and not 0 <= cause_code <= 255:
        raise InputError("pfcp.cause must be within 0..255")
    cause = None
    if cause_code is not None:
        cause = {"code": cause_code, "name": CAUSE_NAMES.get(cause_code)}

    node_id = None
    node_ipv4 = clean(record.get("pfcp.node_id_ipv4"))
    node_ipv6 = clean(record.get("pfcp.node_id_ipv6"))
    node_fqdn = clean(record.get("pfcp.node_id_fqdn"))
    if node_ipv4 or node_ipv6 or node_fqdn:
        node_id = {"ipv4": node_ipv4, "ipv6": node_ipv6, "fqdn": node_fqdn}

    rule_operations, unbound = resolve_rule_operations(record, identity)
    if unbound is not None:
        for limitation in f_seid_limitations:
            if limitation not in unbound["limitations"]:
                unbound["limitations"].append(limitation)
    elif f_seid_limitations:
        unbound = {
            "pdr_ids": [], "far_ids": [], "qer_ids": [], "urr_ids": [],
            "teids": [], "qfis": [], "causes": [], "limitations": list(f_seid_limitations),
        }

    explicit_direction = clean(record.get("carrier_direction"))
    if explicit_direction is not None and explicit_direction not in {
        "control-plane-to-user-plane", "user-plane-to-control-plane",
    }:
        raise InputError("carrier_direction must be a documented PFCP logical direction")
    direction = explicit_direction if explicit_direction is not None else identity.direction
    direction_basis = "observed-carrier" if explicit_direction is not None else identity.direction_basis

    source = _endpoint(record, "src")
    destination = _endpoint(record, "dst")

    source_ref = f"capture:{capture_file}#frame={frame_number}; message-type={message_type_code}"
    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "header": header,
        "support_status": identity.support_status,
        "result": _result_label(identity),
        "direction": direction,
        "direction_basis": direction_basis,
        "node": {
            "node_id": node_id,
            "recovery_time_stamp": clean(record.get("pfcp.recovery_time_stamp")),
        },
        "session": {"cp_f_seid": cp_f_seid, "up_f_seid": up_f_seid},
        "cause": cause,
        "rule_operations": rule_operations,
        "unbound_ie_metadata": unbound,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": list(identity.derivations),
    }
    if source is not None:
        event["source"] = source
    if destination is not None:
        event["destination"] = destination
    return event


def _result_label(identity: MessageIdentity) -> str | None:
    """Message-level normalized label; never a session verdict."""
    if identity.message_type is None:
        return None
    if identity.transaction_role == ROLE_REQUEST:
        return "REQUEST"
    if identity.transaction_role == ROLE_RESPONSE:
        return "RESPONSE"
    return None


def _endpoint(record: dict[str, object], direction: str) -> dict[str, object] | None:
    address = clean(record.get(f"ip.{direction}")) or clean(record.get(f"ipv6.{direction}"))
    port = parse_port(record.get(f"udp.{direction}port"), f"udp.{direction}port")
    if address is None and port is None:
        return None
    return {"address": address, "port": port}


def endpoint_pair(event: dict[str, object]) -> str:
    """Order-normalized endpoint pair used to scope a PFCP transaction.

    Port 8805 is the registered PFCP port but never determines a
    network-function role; roles are never assigned from addresses or ports.
    """
    parts = []
    for role in ("source", "destination"):
        endpoint_data = event.get(role)
        if isinstance(endpoint_data, dict):
            parts.append(f"{endpoint_data.get('address')}:{endpoint_data.get('port')}")
    return "<->".join(sorted(parts)) if parts else "no-endpoints"


def transaction_key(event: dict[str, object]) -> str:
    """Derived transaction key; explicitly not a standardized PFCP identifier."""
    capture = str(event.get("capture_file") or "unknown-capture")
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    sequence = header.get("sequence_number")
    identity = resolve_message(int(header.get("message_type_code") or 0)) if header.get("message_type_code") is not None else None
    family = identity.family if identity is not None and identity.family is not None else "unknown"
    return f"pfcp-tx:{capture}:{endpoint_pair(event)}:seq{sequence}:{family}"


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed PFCP event into the shared trace-event contract.

    The generic session SEID is populated only when exactly one SEID is
    unambiguously meaningful for this event; the CP F-SEID and UP F-SEID are
    never collapsed together to fill it. TEID and QFI are projected only
    when a single unambiguous value exists. Subscriber fields, PDU session
    ID, DNN, APN and bearer ID are never populated from PFCP.
    """
    header = event.get("header") if isinstance(event.get("header"), dict) else {}
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": "PFCP",
        "interface": "N4",
        "procedure": None,
        "message_type": header.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"pfcp-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    code = header.get("message_type_code")
    if code is not None:
        identity = resolve_message(int(code))
        projected["procedure"] = identity.family
        projected["result"] = {
            "status": event.get("result"),
            "cause": (event.get("cause") or {}).get("name") if isinstance(event.get("cause"), dict) else None,
            "code": (event.get("cause") or {}).get("code") if isinstance(event.get("cause"), dict) else None,
        }
    for role in ("source", "destination"):
        if event.get(role) is not None:
            projected[role] = event[role]

    session: dict[str, object] = {}
    candidates: list[int] = []
    session_data = event.get("session") if isinstance(event.get("session"), dict) else {}
    for role in ("cp_f_seid", "up_f_seid"):
        f_seid = session_data.get(role)
        if isinstance(f_seid, dict) and f_seid.get("seid") is not None:
            candidates.append(int(f_seid["seid"]))
    # A header SEID of 0 is the reviewed "peer SEID not available" placeholder
    # (TS 29.244 clause 7.2.2.4.2), not a session identity, so it is not a
    # candidate for the generic projection.
    if header.get("seid") not in (None, 0):
        candidates.append(int(header["seid"]))
    distinct = sorted(set(candidates))
    if len(distinct) == 1:
        # The shared trace schema types session.seid as a string.
        session["seid"] = str(distinct[0])

    teids: list[int] = []
    qfis: list[int] = []
    rules = event.get("rule_operations") if isinstance(event.get("rule_operations"), dict) else {}
    for item in rules.get("pdrs", []) or []:
        f_teid = item.get("f_teid") if isinstance(item, dict) else None
        if isinstance(f_teid, dict) and f_teid.get("teid") is not None:
            teids.append(int(f_teid["teid"]))
        if isinstance(item, dict) and isinstance(item.get("qfi_values"), list):
            qfis.extend(int(value) for value in item["qfi_values"])
    for item in rules.get("fars", []) or []:
        outer = item.get("outer_header_creation") if isinstance(item, dict) else None
        if isinstance(outer, dict) and outer.get("teid") is not None:
            teids.append(int(outer["teid"]))
    for item in rules.get("qers", []) or []:
        if isinstance(item, dict) and item.get("qfi") is not None:
            qfis.append(int(item["qfi"]))
    if len(set(teids)) == 1:
        # The shared trace schema types session.teid as a string.
        session["teid"] = str(sorted(set(teids))[0])
    if len(set(qfis)) == 1:
        session["qfi"] = sorted(set(qfis))[0]
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


_AVAILABLE_FIELDS_CACHE: set[str] | None = None
_AVAILABLE_PROTOCOLS_CACHE: set[str] | None = None
_AVAILABLE_FIELDS_OVERRIDE: set[str] | None = None
_AVAILABLE_PROTOCOLS_OVERRIDE: set[str] | None = None


def set_discovery_overrides(fields: set[str] | None = None, protocols: set[str] | None = None) -> None:
    global _AVAILABLE_FIELDS_OVERRIDE, _AVAILABLE_PROTOCOLS_OVERRIDE
    _AVAILABLE_FIELDS_OVERRIDE = fields
    _AVAILABLE_PROTOCOLS_OVERRIDE = protocols


def resolve_tshark_executable() -> str:
    """Locate the tshark executable across PATH and known platform install paths."""
    import shutil

    found = shutil.which("tshark")
    if found:
        return found
    candidates = [
        Path(r"D:\Wireshark\tshark.exe"),
        Path(r"C:\Program Files\Wireshark\tshark.exe"),
        Path(r"C:\Program Files (x86)\Wireshark\tshark.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return "tshark"


def get_available_fields(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_FIELDS_OVERRIDE is not None:
        return _AVAILABLE_FIELDS_OVERRIDE
    global _AVAILABLE_FIELDS_CACHE
    if _AVAILABLE_FIELDS_CACHE is not None:
        return _AVAILABLE_FIELDS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run([exe, "-G", "fields"], capture_output=True, encoding="utf-8", errors="replace", check=False)
        if proc.returncode == 0 and proc.stdout:
            fields = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2].strip():
                    fields.add(parts[2].strip())
            _AVAILABLE_FIELDS_CACHE = fields
            return fields
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def get_available_protocols(tshark_bin: str | None = None) -> set[str] | None:
    if _AVAILABLE_PROTOCOLS_OVERRIDE is not None:
        return _AVAILABLE_PROTOCOLS_OVERRIDE
    global _AVAILABLE_PROTOCOLS_CACHE
    if _AVAILABLE_PROTOCOLS_CACHE is not None:
        return _AVAILABLE_PROTOCOLS_CACHE
    exe = tshark_bin or resolve_tshark_executable()
    try:
        proc = subprocess.run([exe, "-G", "protocols"], capture_output=True, encoding="utf-8", errors="replace", check=False)
        if proc.returncode == 0 and proc.stdout:
            protos = set()
            for line in proc.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 3 and parts[2].strip():
                    protos.add(parts[2].strip().lower())
            _AVAILABLE_PROTOCOLS_CACHE = protos
            return protos
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def resolve_filter(candidates: tuple[str, ...], available_protocols: set[str] | None) -> str:
    if available_protocols is not None:
        for cand in candidates:
            if cand.lower() in available_protocols:
                return cand
        raise TsharkError(f"tshark compatibility error: none of the protocol filter candidates {candidates} are supported by installed TShark")
    return candidates[0]


def resolve_field_specs(
    specs: tuple[FieldSpec, ...],
    available_fields: set[str] | None,
    tshark_ver: str,
) -> tuple[list[tuple[str, str]], list[str]]:
    resolved_mappings: list[tuple[str, str]] = []
    unresolved_optional: list[str] = []
    for spec in specs:
        resolved_field: str | None = None
        if available_fields is not None:
            for cand in spec.tshark_candidates:
                if cand in available_fields:
                    resolved_field = cand
                    break
        else:
            resolved_field = spec.tshark_candidates[0]

        if resolved_field is not None:
            resolved_mappings.append((resolved_field, spec.canonical_name))
        elif spec.required:
            raise TsharkError(
                f"tshark compatibility error: required field '{spec.canonical_name}' "
                f"(candidates: {spec.tshark_candidates}) is not available in installed TShark {tshark_ver}"
            )
        else:
            unresolved_optional.append(spec.canonical_name)
    return resolved_mappings, unresolved_optional


def tshark_version() -> str:
    exe = resolve_tshark_executable()
    try:
        completed = subprocess.run([exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "unknown tshark failure"
        raise TsharkError(f"tshark --version failed: {detail}")
    return completed.stdout.splitlines()[0].strip() if completed.stdout else "tshark (version unavailable)"


def build_tshark_fields_command(
    capture: Path,
    mappings: list[tuple[str, str]] | None = None,
    display_filter: str = "pfcp",
) -> list[str]:
    """Build the bounded field-extraction command.

    ``occurrence=a`` exports every occurrence of a repeated field
    comma-joined, so multiple PDR/FAR/QER/URR identifiers, F-TEIDs and QFIs
    are never truncated to the first occurrence. The flattened export still
    does not prove which rule an identifier belongs to; that is handled by
    the explicit binding rules in the model, never by positional zipping.
    """
    exe = resolve_tshark_executable()
    command = [
        exe,
        "-n",
        "-r",
        str(capture),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=a",
        "-Y",
        display_filter,
    ]
    if mappings is None:
        mappings = [(s.tshark_candidates[0], s.canonical_name) for s in FIELD_SPECS]
    for actual, _ in mappings:
        command.extend(["-e", actual])
    return command


def tshark_records(capture: Path) -> Iterator[dict[str, object]]:
    exe = resolve_tshark_executable()
    ver = tshark_version()
    avail_fields = get_available_fields(exe)
    avail_protos = get_available_protocols(exe)
    resolved_filter = resolve_filter(FILTER_CANDIDATES, avail_protos)
    mappings, unresolved_optional = resolve_field_specs(FIELD_SPECS, avail_fields, ver)
    command = build_tshark_fields_command(capture, mappings, resolved_filter)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise ToolUnavailable("tshark is unavailable; install Wireshark/tshark manually and retry") from exc
    assert process.stdout is not None
    reader = csv.reader(process.stdout, delimiter="\t")
    header = next(reader, None)
    if header is None:
        stderr = process.stderr.read().strip() if process.stderr else ""
        return_code = process.wait()
        if return_code != 0:
            raise TsharkError(f"tshark returned no field header: {stderr or 'no output'}")
        return
    expected_headers = [actual for actual, _ in mappings]
    if list(header) != expected_headers:
        stderr = process.stderr.read().strip() if process.stderr else ""
        process.wait()
        raise TsharkError(f"tshark returned unexpected field header: expected {expected_headers}, got {header}: {stderr}")
    for row in reader:
        if len(row) > len(mappings):
            raise TsharkError("tshark returned more columns than the requested PFCP field set")
        padded = row + [""] * (len(mappings) - len(row))
        record = {canonical: padded[i] for i, (_, canonical) in enumerate(mappings)}
        for opt in unresolved_optional:
            record[opt] = ""
        yield record
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
