#!/usr/bin/env python3
"""Shared, standalone helpers for bounded NAS-5GS semantic extraction.

Semantic support covers two bounded families of TS 24.501:

- 5GMM registration / identity / authentication / security-mode /
  service / status (unchanged from the earlier bounded subset); and
- 5GSM PDU session establishment / modification / release and 5GSM
  status, added as a bounded, backward-compatible expansion.

Reviewed tables were cross-checked against the NAS-5GS dissector of
Wireshark/TShark 4.7.1 (v4.7.1-0-g667ab240e6de) and against the
normative specifications. Message types, 5GSM causes, Request type, PDU
session type, and SSC mode are taken from 3GPP TS 24.501 version 19.8.0
Release 19 (tables 9.7.2, 9.11.4.2.1, 9.11.3.47.1, 9.11.4.11.1, and
9.11.4.16.1). The extended protocol discriminator values are taken from
3GPP TS 24.007 version 18.2.0 Release 18, table 11.2.3.1.1A.1: 5GMM uses
0x7E and 5GSM uses 0x2E. Dissector output is tooling evidence, not
normative truth; where a specification edition and the dissector
disagree, the reviewed specification value is preserved and the tool
version is recorded rather than reconciled.

Bounded semantics only: supported 5GSM messages are SUPPORTED with
message-local field handling; known out-of-scope 5GSM messages are
UNSUPPORTED with name only; unknown values stay UNKNOWN. This module
never performs key derivation, MAC verification, ciphering, identity
conversions, or identity-value emission by default, and it never
determines PDU session success, failure, or a root cause.
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

PROTOCOL = "NAS-5GS"
INTERFACE = "N1"
FAMILY_MM = "5GMM"
FAMILY_SM = "5GSM"

# Extended protocol discriminator (TS 24.007 table 11.2.3.1.1A.1). The two
# 5GS NAS protocols use distinct octet values: 5GMM 0x7E, 5GSM 0x2E.
EPD_5GMM = 0x7E
EPD_5GSM = 0x2E
# Retained name for the 5GMM discriminator; existing 5GMM records keep it.
EXTENDED_PROTOCOL_DISCRIMINATOR = EPD_5GMM

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "nas-5gs.security_header_type",
    "nas-5gs.security_parameter_index",
    "nas-5gs.seq_no",
    "nas-5gs.msg_auth_code",
    "nas-5gs.mm.message_type",
    "nas-5gs.sm.message_type",
    "nas-5gs.pdu_session_id",
    "nas-5gs.proc_trans_id",
    "nas-5gs.mm.req_type",
    "nas-5gs.sm.pdu_ses_type",
    "nas-5gs.sm.sc_mode",
    "nas-5gs.sm.sel_sc_mode",
    "nas-5gs.cmn.dnn",
    "nas-5gs.mm.sst",
    "nas-5gs.mm.mm_sd",
    "nas-5gs.sm.5gsm_cause",
    "nas-5gs.sm.pdu_addr_inf_ipv4",
    "nas-5gs.sm.pdu_addr_inf_ipv6",
    "nas-5gs.sm.qos_rule_id",
    "nas-5gs.sm.qfi",
    "nas-5gs.sm.5qi",
    "nas-5gs.sm.apsi",
    "nas-5gs.sm.apsr",
    "nas-5gs.mm.5gs_reg_type",
    "nas-5gs.mm.for",
    "nas-5gs.mm.nas_key_set_id",
    "nas-5gs.mm.type_id",
    "nas-5gs.mm.5gmm_cause",
    "nas-5gs.mm.nas_sec_algo_enc",
    "nas-5gs.mm.nas_sec_algo_ip",
    "nas-5gs.mm.serv_type",
    "nas-5gs.mm.imei",
    "nas-5gs.mm.imeisv",
)

# Structured-input-only optional field (never produced by tshark): an
# explicit sensitive-identity value. It is dropped unless the caller
# explicitly enables sensitive identifier output.
SENSITIVE_INPUT_FIELD = "identity_value"

SUPPORTED = "SUPPORTED"
UNSUPPORTED = "UNSUPPORTED"
UNKNOWN = "UNKNOWN"
DEFERRED = "DEFERRED"

SECURITY_HEADER_NAMES = {
    0: "plain NAS message, not security protected",
    1: "integrity protected",
    2: "integrity protected and ciphered",
    3: "integrity protected with new 5GS security context",
    4: "integrity protected and ciphered with new 5GS security context",
}

# 5GMM message types with bounded semantic support (TS 24.501 message
# identity, direction, and bounded IE handling only; no procedure state).
# direction: the single valid protocol direction for the message, or None
# when either side may send it (5GMM status).
SUPPORTED_MESSAGES = {
    65: ("Registration request", FAMILY_MM, "ue-to-amf", "REGISTRATION"),
    66: ("Registration accept", FAMILY_MM, "amf-to-ue", "REGISTRATION"),
    67: ("Registration complete", FAMILY_MM, "ue-to-amf", "REGISTRATION"),
    68: ("Registration reject", FAMILY_MM, "amf-to-ue", "REGISTRATION"),
    91: ("Identity request", FAMILY_MM, "amf-to-ue", "IDENTITY"),
    92: ("Identity response", FAMILY_MM, "ue-to-amf", "IDENTITY"),
    86: ("Authentication request", FAMILY_MM, "amf-to-ue", "AUTHENTICATION"),
    87: ("Authentication response", FAMILY_MM, "ue-to-amf", "AUTHENTICATION"),
    88: ("Authentication reject", FAMILY_MM, "amf-to-ue", "AUTHENTICATION"),
    89: ("Authentication failure", FAMILY_MM, "ue-to-amf", "AUTHENTICATION"),
    90: ("Authentication result", FAMILY_MM, "amf-to-ue", "AUTHENTICATION"),
    93: ("Security mode command", FAMILY_MM, "amf-to-ue", "SECURITY_MODE"),
    94: ("Security mode complete", FAMILY_MM, "ue-to-amf", "SECURITY_MODE"),
    95: ("Security mode reject", FAMILY_MM, "ue-to-amf", "SECURITY_MODE"),
    76: ("Service request", FAMILY_MM, "ue-to-amf", "SERVICE"),
    77: ("Service reject", FAMILY_MM, "amf-to-ue", "SERVICE"),
    78: ("Service accept", FAMILY_MM, "amf-to-ue", "SERVICE"),
    100: ("5GMM status", FAMILY_MM, None, "STATUS"),
}

# Known 5GMM message types outside the bounded subset: identity only,
# recognized by reviewed name, never semantically expanded.
KNOWN_UNSUPPORTED_MESSAGES = {
    69: "Deregistration request (UE originating)",
    70: "Deregistration accept (UE originating)",
    71: "Deregistration request (UE terminated)",
    72: "Deregistration accept (UE terminated)",
    79: "Control plane service request",
    80: "Network slice-specific authentication command",
    81: "Network slice-specific authentication complete",
    82: "Network slice-specific authentication result",
    84: "Configuration update command",
    85: "Configuration update complete",
    101: "Notification",
    102: "Notification response",
    103: "UL NAS transport",
    104: "DL NAS transport",
    105: "Relay key request",
    106: "Relay key accept",
    107: "Relay key reject",
    108: "Relay authentication request",
    109: "Relay authentication response",
}

# Local normalized result labels derived from reviewed message identity;
# they are not 3GPP wire values.
MESSAGE_RESULTS = {
    "Registration request": "REQUEST",
    "Registration accept": "ACCEPT",
    "Registration complete": "COMPLETE",
    "Registration reject": "REJECT",
    "Identity request": "REQUEST",
    "Identity response": "RESPONSE",
    "Authentication request": "REQUEST",
    "Authentication response": "RESPONSE",
    "Authentication reject": "REJECT",
    "Authentication failure": "FAILURE",
    "Authentication result": "RESULT",
    "Security mode command": "COMMAND",
    "Security mode complete": "COMPLETE",
    "Security mode reject": "REJECT",
    "Service request": "REQUEST",
    "Service accept": "ACCEPT",
    "Service reject": "REJECT",
    "5GMM status": "STATUS",
}

# Bounded 5GSM message types with semantic support (TS 24.501 19.8.0 table
# 9.7.2 message identity, logical UE<->SMF direction, and bounded IE
# handling only; no PDU session state). Direction is the single valid
# logical direction for the message, or None when either side may send it
# (5GSM status). 5GSM logical peers are UE and SMF even though N1 transport
# passes through the AMF.
SUPPORTED_SM_MESSAGES = {
    193: ("PDU session establishment request", "ue-to-smf", "PDU_SESSION_ESTABLISHMENT"),
    194: ("PDU session establishment accept", "smf-to-ue", "PDU_SESSION_ESTABLISHMENT"),
    195: ("PDU session establishment reject", "smf-to-ue", "PDU_SESSION_ESTABLISHMENT"),
    201: ("PDU session modification request", "ue-to-smf", "PDU_SESSION_MODIFICATION"),
    202: ("PDU session modification reject", "smf-to-ue", "PDU_SESSION_MODIFICATION"),
    203: ("PDU session modification command", "smf-to-ue", "PDU_SESSION_MODIFICATION"),
    204: ("PDU session modification complete", "ue-to-smf", "PDU_SESSION_MODIFICATION"),
    205: ("PDU session modification command reject", "ue-to-smf", "PDU_SESSION_MODIFICATION"),
    209: ("PDU session release request", "ue-to-smf", "PDU_SESSION_RELEASE"),
    210: ("PDU session release reject", "smf-to-ue", "PDU_SESSION_RELEASE"),
    211: ("PDU session release command", "smf-to-ue", "PDU_SESSION_RELEASE"),
    212: ("PDU session release complete", "ue-to-smf", "PDU_SESSION_RELEASE"),
    214: ("5GSM status", None, "SESSION_MANAGEMENT_STATUS"),
}

# Known 5GSM message types outside the bounded subset: identity only,
# recognized by reviewed name, never semantically expanded.
KNOWN_UNSUPPORTED_SM_MESSAGES = {
    197: "PDU session authentication command",
    198: "PDU session authentication complete",
    199: "PDU session authentication result",
    216: "Service-level authentication command",
    217: "Service-level authentication complete",
    218: "Remote UE report",
    219: "Remote UE report response",
}

# Local normalized result labels derived from reviewed 5GSM message
# identity; they are not 3GPP wire values and not procedure verdicts.
SM_MESSAGE_RESULTS = {
    "PDU session establishment request": "REQUEST",
    "PDU session establishment accept": "ACCEPT",
    "PDU session establishment reject": "REJECT",
    "PDU session modification request": "REQUEST",
    "PDU session modification reject": "REJECT",
    "PDU session modification command": "COMMAND",
    "PDU session modification complete": "COMPLETE",
    "PDU session modification command reject": "REJECT",
    "PDU session release request": "REQUEST",
    "PDU session release reject": "REJECT",
    "PDU session release command": "COMMAND",
    "PDU session release complete": "COMPLETE",
    "5GSM status": "STATUS",
}

# Reviewed 5GSM cause values (TS 24.501 19.8.0 table 9.11.4.2.1). Only
# reviewed values carry names; anything else stays UNKNOWN with its numeric
# code preserved. A 5GSM cause is protocol evidence, never a root cause.
SM_CAUSE_NAMES = {
    8: "Operator determined barring",
    26: "Insufficient resources",
    27: "Missing or unknown DNN",
    28: "Unknown PDU session type",
    29: "User authentication or authorization failed",
    31: "Request rejected, unspecified",
    32: "Service option not supported",
    33: "Requested service option not subscribed",
    35: "PTI already in use",
    36: "Regular deactivation",
    37: "5GS QoS not accepted",
    38: "Network failure",
    39: "Reactivation requested",
    41: "Semantic error in the TFT operation",
    42: "Syntactical error in the TFT operation",
    43: "Invalid PDU session identity",
    44: "Semantic errors in packet filter(s)",
    45: "Syntactical error in packet filter(s)",
    46: "Out of LADN service area",
    47: "PTI mismatch",
    50: "PDU session type IPv4 only allowed",
    51: "PDU session type IPv6 only allowed",
    54: "PDU session does not exist",
    57: "PDU session type IPv4v6 only allowed",
    58: "PDU session type Unstructured only allowed",
    61: "Unsupported 5QI value",
    67: "PDU session type Ethernet only allowed",
    68: "Insufficient resources for specific slice and DNN",
    69: "Not supported SSC mode",
    70: "Insufficient resources for specific slice",
    81: "Missing or unknown DNN in a slice",
    82: "Invalid PTI value",
    83: "Maximum data rate per UE for user-plane integrity protection is too low",
    84: "Semantic error in the QoS operation",
    85: "Syntactical error in the QoS operation",
    86: "Invalid mapped EPS bearer identity",
    87: "UAS services not allowed",
    95: "QoS differentiation for non-3GPP device identifier(s) not available",
    96: "Semantically incorrect message",
    97: "Invalid mandatory information",
    98: "Message type non-existent or not implemented",
    99: "Message type not compatible with the protocol state",
    100: "Information element non-existent or not implemented",
    101: "Conditional IE error",
    111: "Message not compatible with the protocol state",
    127: "Protocol error, unspecified",
}

# TS 24.501 19.8.0 table 9.11.3.47.1 (Request type value).
REQUEST_TYPES = {
    1: "initial request",
    2: "existing PDU session",
    3: "initial emergency request",
    4: "existing emergency PDU session",
    5: "modification request",
    6: "MA PDU request",
}

# TS 24.501 19.8.0 table 9.11.4.11.1 (PDU session type value).
PDU_SESSION_TYPES = {
    1: "IPv4",
    2: "IPv6",
    3: "IPv4v6",
    4: "Unstructured",
    5: "Ethernet",
}

# TS 24.501 19.8.0 table 9.11.4.16.1 (SSC mode value).
SSC_MODES = {
    1: "SSC mode 1",
    2: "SSC mode 2",
    3: "SSC mode 3",
}

REGISTRATION_TYPES = {
    1: "initial registration",
    2: "mobility registration updating",
    3: "periodic registration updating",
    4: "emergency registration",
}

IDENTITY_TYPES = {
    0: "no identity",
    1: "SUCI",
    2: "5G-GUTI",
    3: "IMEI",
    4: "5G-S-TMSI",
    5: "IMEISV",
    6: "MAC address",
    7: "EUI-64",
}

# Reviewed 5GMM cause values (TS 24.501 5GMM cause; tool table of
# TShark 4.7.1, dumped via `tshark -G values`). Only table-verified values
# carry names; anything else stays UNKNOWN with its numeric code preserved.
CAUSE_NAMES = {
    3: "Illegal UE",
    5: "PEI not accepted",
    6: "Illegal ME",
    7: "5GS services not allowed",
    9: "UE identity cannot be derived by the network",
    10: "Implicitly deregistered",
    11: "PLMN not allowed",
    12: "Tracking area not allowed",
    13: "Roaming not allowed in this tracking area",
    15: "No suitable cells in tracking area",
    20: "MAC failure",
    21: "Synch failure",
    22: "Congestion",
    23: "UE security capabilities mismatch",
    24: "Security mode rejected, unspecified",
    26: "Non-5G authentication unacceptable",
    27: "N1 mode not allowed",
    28: "Restricted service area",
    31: "Redirection to EPC required",
    36: "IAB-node operation not authorized",
    43: "LADN not available",
    62: "No network slices available",
    65: "Maximum number of PDU sessions reached",
    67: "Insufficient resources for specific slice and DNN",
    69: "Insufficient resources for specific slice",
    71: "ngKSI already in use",
    72: "Non-3GPP access to 5GCN not allowed",
    73: "Serving network not authorized",
    74: "Temporarily not authorized for this SNPN",
    75: "Permanently not authorized for this SNPN",
    76: "Not authorized for this CAG or authorized for CAG cells only",
    77: "Wireline access area not allowed",
    78: "PLMN not allowed to operate at the present UE location",
    79: "UAS services not allowed",
    80: "Disaster roaming for the determined PLMN with disaster condition not allowed",
    81: "Selected N3IWF is not compatible with the allowed NSSAI",
    82: "Selected TNGF is not compatible with the allowed NSSAI",
    90: "Payload was not forwarded",
    91: "DNN not supported or not subscribed in the slice",
    92: "Insufficient user-plane resources for the PDU session",
}

CIPHERING_ALGORITHMS = {
    0: "5G-EA0",
    1: "128-5G-EA1",
    2: "128-5G-EA2",
    3: "128-5G-EA3",
    4: "5G-EA4",
    5: "5G-EA5",
    6: "5G-EA6",
    7: "5G-EA7",
}

INTEGRITY_ALGORITHMS = {
    0: "5G-IA0",
    1: "128-5G-IA1",
    2: "128-5G-IA2",
    3: "128-5G-IA3",
    4: "5G-IA4",
    5: "5G-IA5",
    6: "5G-IA6",
    7: "5G-IA7",
}

SERVICE_TYPES = {
    0: "signalling",
    1: "data",
    2: "mobile terminated services",
    3: "emergency services",
    4: "emergency services fallback",
    5: "high priority access",
    6: "elevated signalling",
}


class InputError(ValueError):
    """Raised when a supported structured input cannot be normalized."""


class ToolUnavailable(RuntimeError):
    """Raised when tshark is required but unavailable."""


class TsharkError(RuntimeError):
    """Raised when tshark cannot produce the requested NAS-5GS fields."""


@dataclass(frozen=True)
class MessageIdentity:
    """Normalized NAS-5GS identity for one observed frame."""

    nas_family: str | None
    message_type: str | None
    support_status: str
    procedure_family: str | None
    direction: str | None
    direction_basis: str | None
    result: str | None
    derivations: tuple[str, ...]


def safe_capture_name(path: Path) -> str:
    """Return a basename so outputs never disclose workstation paths."""
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
        return int(text)
    except ValueError as exc:
        raise InputError(f"{field} must be an integer") from exc


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


def optional_int(value: object) -> int | None:
    text = first_token(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def int_list(value: object) -> list[int]:
    """Parse a scalar or repeated field into an ordered integer list.

    Repeated dissector output arrives comma-joined; structured input may
    pass a JSON array instead. Order and duplicates are preserved so a
    repeated field is never collapsed into one arbitrary value.
    """
    if value is None:
        return []
    items = [str(item) for item in value] if isinstance(value, (list, tuple)) else str(value).split(",")
    result: list[int] = []
    for item in items:
        token = item.strip()
        if not token:
            continue
        try:
            result.append(int(token))
        except ValueError as exc:
            raise InputError("repeated numeric field must contain integers") from exc
    return result


def optional_bool(value: object) -> bool | None:
    text = clean(value)
    if text is None:
        return None
    if text in {"1", "true", "True", "yes"}:
        return True
    if text in {"0", "false", "False", "no"}:
        return False
    raise InputError("boolean field must be 0/1 or true/false")


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


def resolve_security_header(value: int | None) -> dict[str, object]:
    """Preserve the observed header code and derive the protection state."""
    if value is None:
        return {
            "header_type": None,
            "header_name": None,
            "integrity_protected": None,
            "ciphered": None,
            "new_security_context": None,
            "sequence_number": None,
            "message_authentication_code_present": None,
            "security_parameter_index": None,
            "inner_message_available": None,
            "decode_basis": None,
        }
    if not 0 <= value <= 4:
        raise InputError("nas-5gs.security_header_type must be within 0..4")
    protected = value in {1, 2, 3, 4}
    ciphered = value in {2, 4}
    new_context = value in {3, 4}
    return {
        "header_type": value,
        "header_name": SECURITY_HEADER_NAMES[value],
        "integrity_protected": protected,
        "ciphered": ciphered,
        "new_security_context": new_context,
        "sequence_number": None,
        "message_authentication_code_present": None,
        "security_parameter_index": None,
        "inner_message_available": None,
        "decode_basis": None,
    }


def resolve_message(mm_code: int | None, sm_code: int | None) -> MessageIdentity:
    """Normalize 5GMM/5GSM identity from reviewed tables.

    The 5GMM bounded subset and the 5GSM bounded subset are SUPPORTED with
    bounded semantics; known out-of-scope messages of either family are
    UNSUPPORTED (name only); unknown values stay UNKNOWN. Both message
    types at once is an ambiguous, invalid record.
    """
    derivations: list[str] = []
    if mm_code is not None and sm_code is not None:
        raise InputError("both 5GMM and 5GSM message types observed; ambiguous record")
    if sm_code is not None:
        derivations.append("nas_family")
        if sm_code in SUPPORTED_SM_MESSAGES:
            name, direction, procedure = SUPPORTED_SM_MESSAGES[sm_code]
            derivations.extend(["message_type", "direction", "procedure_family", "result"])
            return MessageIdentity(
                nas_family=FAMILY_SM,
                message_type=name,
                support_status=SUPPORTED,
                procedure_family=procedure,
                direction=direction,
                direction_basis="message-definition",
                result=SM_MESSAGE_RESULTS[name],
                derivations=tuple(sorted(derivations)),
            )
        known = KNOWN_UNSUPPORTED_SM_MESSAGES.get(sm_code)
        if known is not None:
            derivations.append("message_type")
            return MessageIdentity(
                nas_family=FAMILY_SM,
                message_type=known,
                support_status=UNSUPPORTED,
                procedure_family=None,
                direction=None,
                direction_basis=None,
                result=None,
                derivations=tuple(sorted(derivations)),
            )
        return MessageIdentity(
            nas_family=FAMILY_SM,
            message_type=None,
            support_status=UNKNOWN,
            procedure_family=None,
            direction=None,
            direction_basis=None,
            result=None,
            derivations=tuple(sorted(derivations)),
        )
    if mm_code is None:
        return MessageIdentity(
            nas_family=None,
            message_type=None,
            support_status=UNKNOWN,
            procedure_family=None,
            direction=None,
            direction_basis=None,
            result=None,
            derivations=(),
        )
    if mm_code in SUPPORTED_MESSAGES:
        name, family, direction, procedure = SUPPORTED_MESSAGES[mm_code]
        derivations.extend(["nas_family", "message_type", "direction", "procedure_family", "result"])
        return MessageIdentity(
            nas_family=family,
            message_type=name,
            support_status=SUPPORTED,
            procedure_family=procedure,
            direction=direction,
            direction_basis="message-definition",
            result=MESSAGE_RESULTS[name],
            derivations=tuple(sorted(derivations)),
        )
    known = KNOWN_UNSUPPORTED_MESSAGES.get(mm_code)
    if known is not None:
        derivations.extend(["nas_family", "message_type"])
        return MessageIdentity(
            nas_family=FAMILY_MM,
            message_type=known,
            support_status=UNSUPPORTED,
            procedure_family=None,
            direction=None,
            direction_basis=None,
            result=None,
            derivations=tuple(sorted(derivations)),
        )
    derivations.append("nas_family")
    return MessageIdentity(
        nas_family=FAMILY_MM,
        message_type=None,
        support_status=UNKNOWN,
        procedure_family=None,
        direction=None,
        direction_basis=None,
        result=None,
        derivations=tuple(sorted(derivations)),
    )


def normalize_session_management(record: dict[str, object]) -> dict[str, object]:
    """Normalize bounded 5GSM session-management fields from one record.

    Only fields TS 24.501 defines and the reviewed dissector exposes are
    read; absent values stay null and nothing is inferred. A repeated QFI
    or 5QI field is preserved as an ordered list rather than collapsed into
    one arbitrary value. The PDU session identity and the procedure
    transaction identity stay distinct fields.
    """
    request_code = optional_int(record.get("nas-5gs.mm.req_type"))
    session_type_code = optional_int(record.get("nas-5gs.sm.pdu_ses_type"))
    if session_type_code is None:
        session_type_code = optional_int(record.get("nas-5gs.sm.pdu_session_type"))
    ssc_code = optional_int(record.get("nas-5gs.sm.sc_mode"))
    if ssc_code is None:
        ssc_code = optional_int(record.get("nas-5gs.sm.sel_sc_mode"))

    pdu_session_id = optional_int(record.get("nas-5gs.pdu_session_id"))
    if pdu_session_id is not None and not 0 <= pdu_session_id <= 255:
        raise InputError("nas-5gs.pdu_session_id must be within 0..255")
    pti = optional_int(record.get("nas-5gs.proc_trans_id"))
    if pti is not None and not 0 <= pti <= 255:
        raise InputError("nas-5gs.proc_trans_id must be within 0..255")

    qfi_values = int_list(record.get("nas-5gs.sm.qfi"))
    five_qi_values = int_list(record.get("nas-5gs.sm.5qi"))
    rule_ids = int_list(record.get("nas-5gs.sm.qos_rule_id"))

    qos_rules_present = optional_bool(record.get("qos_rules_present"))
    if qos_rules_present is None:
        qos_rules_present = bool(rule_ids)
    flow_descriptions_present = optional_bool(record.get("qos_flow_descriptions_present"))
    if flow_descriptions_present is None:
        flow_descriptions_present = bool(qfi_values or five_qi_values)

    pdu_address = first_token(record.get("nas-5gs.sm.pdu_addr_inf_ipv4"))
    if pdu_address is None:
        pdu_address = first_token(record.get("pdu_address"))

    return {
        "pdu_session_id": pdu_session_id,
        "pti": pti,
        "request_type": {"code": request_code, "name": REQUEST_TYPES.get(request_code) if request_code is not None else None},
        "pdu_session_type": {"code": session_type_code, "name": PDU_SESSION_TYPES.get(session_type_code) if session_type_code is not None else None},
        "ssc_mode": {"code": ssc_code, "name": SSC_MODES.get(ssc_code) if ssc_code is not None else None},
        "dnn": first_token(record.get("nas-5gs.cmn.dnn")),
        "snssai": {"sst": optional_int(record.get("nas-5gs.mm.sst")), "sd": optional_int(record.get("nas-5gs.mm.mm_sd"))},
        "pdu_address": pdu_address,
        "always_on": {
            "requested": optional_bool(record.get("nas-5gs.sm.apsr")),
            "indicated": optional_bool(record.get("nas-5gs.sm.apsi")),
        },
        "authorized_qos_rules": {"present": bool(qos_rules_present), "rule_ids": rule_ids},
        "qos_flow_descriptions": {"present": bool(flow_descriptions_present), "qfi_values": qfi_values, "five_qi_values": five_qi_values},
        "epco_present": optional_bool(record.get("epco_present")),
    }


def normalize_record(record: object, capture_file: str, include_sensitive: bool = False) -> dict[str, object]:
    """Project one structured NAS-5GS observation into the detailed event.

    Sensitive identity values are dropped unless ``include_sensitive`` is
    explicitly enabled; authentication secret material is never emitted in
    any mode. Every emitted event carries all keys, with null for values
    the frame does not contain.
    """
    if not isinstance(record, dict):
        raise InputError("structured NAS-5GS record must be a JSON object")
    frame_number = parse_int(record.get("frame.number"), "frame.number")
    if frame_number < 1:
        raise InputError("frame.number must be at least 1")
    timestamp = normalize_timestamp(record.get("frame.time_epoch"))

    mm_code = optional_int(record.get("nas-5gs.mm.message_type"))
    sm_code = optional_int(record.get("nas-5gs.sm.message_type"))
    for code, field in ((mm_code, "nas-5gs.mm.message_type"), (sm_code, "nas-5gs.sm.message_type")):
        if code is not None and not 0 <= code <= 255:
            raise InputError(f"{field} must be within 0..255")
    identity = resolve_message(mm_code, sm_code)

    header_code = optional_int(record.get("nas-5gs.security_header_type"))
    if clean(record.get("nas-5gs.security_header_type")) is not None and header_code is None:
        raise InputError("nas-5gs.security_header_type must be an integer")
    security = resolve_security_header(header_code)
    security["sequence_number"] = optional_int(record.get("nas-5gs.seq_no"))
    mac_code = optional_int(record.get("nas-5gs.msg_auth_code"))
    if clean(record.get("nas-5gs.msg_auth_code")) is not None and mac_code is None:
        raise InputError("nas-5gs.msg_auth_code must be an integer")
    security["message_authentication_code_present"] = mac_code is not None
    security["security_parameter_index"] = optional_int(record.get("nas-5gs.security_parameter_index"))
    if security["header_type"] == 0:
        security["inner_message_available"] = True
        security["decode_basis"] = "plain-message"
    elif identity.message_type is not None:
        security["inner_message_available"] = True
        security["decode_basis"] = "dissector-decoded"
    else:
        security["inner_message_available"] = False
        security["decode_basis"] = None

    reg_code = optional_int(record.get("nas-5gs.mm.5gs_reg_type"))
    if reg_code is not None and reg_code not in REGISTRATION_TYPES:
        reg_name = "UNKNOWN"
    else:
        reg_name = REGISTRATION_TYPES.get(reg_code) if reg_code is not None else None

    if identity.nas_family == FAMILY_SM:
        cause_code = optional_int(record.get("nas-5gs.sm.5gsm_cause"))
        cause_name = SM_CAUSE_NAMES.get(cause_code) if cause_code is not None else None
        cause_family = FAMILY_SM
    else:
        cause_code = optional_int(record.get("nas-5gs.mm.5gmm_cause"))
        cause_name = CAUSE_NAMES.get(cause_code) if cause_code is not None else None
        cause_family = FAMILY_MM
    extra_derivations: list[str] = []
    if cause_name is not None:
        extra_derivations.append("cause_name")

    identity_type_code = optional_int(record.get("nas-5gs.mm.type_id"))
    if identity_type_code is not None and identity_type_code not in IDENTITY_TYPES:
        identity_type_name = "UNKNOWN"
    else:
        identity_type_name = IDENTITY_TYPES.get(identity_type_code) if identity_type_code is not None else None
    imei_present = clean(record.get("nas-5gs.mm.imei")) is not None
    imeisv_present = clean(record.get("nas-5gs.mm.imeisv")) is not None
    identity_present = identity_type_code is not None or imei_present or imeisv_present

    sensitive_value = clean(record.get(SENSITIVE_INPUT_FIELD))
    if sensitive_value is not None and not include_sensitive:
        sensitive_value = None

    ksi = optional_int(record.get("nas-5gs.mm.nas_key_set_id"))
    if ksi is not None and not 0 <= ksi <= 7:
        raise InputError("nas-5gs.mm.nas_key_set_id must be within 0..7")

    auth_meta = {
        "rand_present": optional_bool(record.get("auth_rand_present")),
        "autn_present": optional_bool(record.get("auth_autn_present")),
        "res_present": optional_bool(record.get("auth_res_present")),
        "auts_present": optional_bool(record.get("auth_auts_present")),
    }

    cipher_code = optional_int(record.get("nas-5gs.mm.nas_sec_algo_enc"))
    integrity_code = optional_int(record.get("nas-5gs.mm.nas_sec_algo_ip"))
    security_mode_meta = {
        "ciphering_algorithm_code": cipher_code,
        "ciphering_algorithm_name": CIPHERING_ALGORITHMS.get(cipher_code) if cipher_code is not None else None,
        "integrity_algorithm_code": integrity_code,
        "integrity_algorithm_name": INTEGRITY_ALGORITHMS.get(integrity_code) if integrity_code is not None else None,
    }
    if security_mode_meta["ciphering_algorithm_name"] is not None or security_mode_meta["integrity_algorithm_name"] is not None:
        extra_derivations.append("algorithm_names")

    service_code = optional_int(record.get("nas-5gs.mm.serv_type"))
    service_meta = {
        "type_code": service_code,
        "type_name": SERVICE_TYPES.get(service_code) if service_code is not None else None,
    }

    carrier_direction = clean(record.get("carrier_direction"))
    if carrier_direction is not None and carrier_direction not in {"ue-to-amf", "amf-to-ue", "ue-to-smf", "smf-to-ue"}:
        raise InputError("carrier_direction must be a documented logical direction")
    direction = carrier_direction if carrier_direction is not None else identity.direction
    direction_basis = "observed-carrier" if carrier_direction is not None else identity.direction_basis

    observed_epd = optional_int(record.get("nas-5gs.epd"))
    if observed_epd is not None and not 0 <= observed_epd <= 255:
        raise InputError("nas-5gs.epd must be within 0..255")
    derived_epd = EPD_5GSM if identity.nas_family == FAMILY_SM else EPD_5GMM
    if observed_epd is not None and identity.nas_family in (FAMILY_MM, FAMILY_SM) and observed_epd != derived_epd:
        raise InputError("observed extended protocol discriminator conflicts with the observed NAS family")
    protocol_discriminator = observed_epd if observed_epd is not None else derived_epd

    source_ref = f"capture:{capture_file}#frame={frame_number}; message-type={mm_code if mm_code is not None else sm_code}"
    event: dict[str, object] = {
        "timestamp": timestamp,
        "frame_number": frame_number,
        "capture_file": capture_file,
        "nas_family": identity.nas_family,
        "protocol_discriminator": protocol_discriminator,
        "security": security,
        "message_type_code": mm_code if mm_code is not None else sm_code,
        "message_type": identity.message_type,
        "support_status": identity.support_status,
        "result": identity.result,
        "direction": direction,
        "direction_basis": direction_basis,
        "procedure_family": identity.procedure_family,
        "registration": {
            "type_code": reg_code,
            "type_name": reg_name,
            "follow_on_request": optional_bool(record.get("nas-5gs.mm.for")),
        },
        "ngksi": {"key_set_id": ksi},
        "identity": {
            "present": identity_present,
            "type_code": identity_type_code,
            "type_name": identity_type_name,
            "value": sensitive_value,
        },
        "cause": {"code": cause_code, "name": cause_name, "family": cause_family},
        "authentication": auth_meta,
        "security_mode": security_mode_meta,
        "service": service_meta,
        "evidence": {"level": "OBSERVED", "source": source_ref},
        "derivations": tuple(sorted(set(identity.derivations) | set(extra_derivations))),
    }
    if identity.nas_family == FAMILY_SM:
        event["session_management"] = normalize_session_management(record)
    return event


def project_trace_event(event: dict[str, object]) -> dict[str, object]:
    """Project a detailed NAS event into the shared trace-event contract.

    Subscriber fields are never populated (identity privacy). Session
    fields are populated only from directly observed 5GSM evidence and only
    when unambiguous: ``pdu_session_id`` from the observed PDU session
    identity, ``dnn`` from an observed DNN, and ``qfi`` only when exactly
    one QFI is represented. SEID and TEID are never derived from NAS, and
    APN is never fabricated from DNN.
    """
    projected: dict[str, object] = {
        "timestamp": event["timestamp"],
        "protocol": PROTOCOL,
        "interface": INTERFACE,
        "procedure": event.get("procedure_family"),
        "message_type": event.get("message_type"),
        "packet": {"frame_number": event["frame_number"], "capture_file": event["capture_file"]},
        "evidence": {
            "level": "DERIVED",
            "source": f"nas5gs-event:{event['capture_file']}#frame={event['frame_number']}",
        },
    }
    cause = event.get("cause") if isinstance(event.get("cause"), dict) else {}
    status = event.get("result")
    if status is not None or cause.get("code") is not None:
        projected["result"] = {
            "status": status,
            "cause": cause.get("name") if cause.get("name") is not None else cause.get("code"),
            "code": cause.get("code"),
        }
    session_management = event.get("session_management")
    if isinstance(session_management, dict):
        session: dict[str, object] = {}
        pdu_session_id = session_management.get("pdu_session_id")
        if pdu_session_id is not None:
            session["pdu_session_id"] = pdu_session_id
        dnn = session_management.get("dnn")
        if dnn is not None:
            session["dnn"] = dnn
        flow_descriptions = session_management.get("qos_flow_descriptions")
        qfi_values = flow_descriptions.get("qfi_values") if isinstance(flow_descriptions, dict) else None
        if isinstance(qfi_values, list) and len(qfi_values) == 1:
            session["qfi"] = qfi_values[0]
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
    comma-joined, so a PDU session with several QFIs is never collapsed
    into one arbitrary value; single-occurrence fields are unaffected.
    """
    command = ["tshark", "-n", "-r", str(capture), "-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a", "-Y", "nas-5gs"]
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
        raise TsharkError(f"tshark did not expose the required NAS-5GS fields: {stderr or header}")
    for row in reader:
        if len(row) > len(FIELDS):
            raise TsharkError("tshark returned more columns than the requested NAS-5GS field set")
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
