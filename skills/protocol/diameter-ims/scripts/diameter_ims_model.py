#!/usr/bin/env python3
"""Bounded Diameter IMS Cx/Dx application evidence model.

The model consumes accepted Diameter Core events and transactions. It never
parses packet bytes, never re-correlates Request/Answer pairs, never infers a
Cx versus Dx interface identity, and never emits an IMS registration,
authentication or service-authorization verdict.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

ANALYSIS_NAME = "diameter-ims"
ANALYSIS_VERSION = "1.1.0"

CX_APPLICATION_ID = 16777216
THREEGPP_VENDOR_ID = 10415
MAX_OBSERVATIONS = 256
MAX_REVIEWED_VALUES = 16
MAX_GROUP_CHILDREN = 32

TRANSACTION_REFERENCE_PATTERN = re.compile(
    r"^diameter-tx:.+:[0-9]+:[0-9]+\.[0-9]+$"
)

COMMANDS = {
    300: ("User-Authorization", "UAR", "UAA"),
    301: ("Server-Assignment", "SAR", "SAA"),
    302: ("Location-Info", "LIR", "LIA"),
    303: ("Multimedia-Auth", "MAR", "MAA"),
    304: ("Registration-Termination", "RTR", "RTA"),
    305: ("Push-Profile", "PPR", "PPA"),
}
SUPPORTED_COMMAND_CODES = tuple(sorted(COMMANDS))

# Reviewed Cx/Dx AVP vocabulary: (code, reviewed decoder name, vendor_id, grouped).
AVP_VOCABULARY = (
    (1, "User-Name", None, False),
    (263, "Session-Id", None, False),
    (264, "Origin-Host", None, False),
    (268, "Result-Code", None, False),
    (277, "Auth-Session-State", None, False),
    (283, "Destination-Realm", None, False),
    (296, "Origin-Realm", None, False),
    (297, "Experimental-Result", None, True),
    (266, "Vendor-Id", None, False),
    (600, "Visited-Network-Identifier", THREEGPP_VENDOR_ID, False),
    (601, "Public-Identity", THREEGPP_VENDOR_ID, False),
    (602, "Server-Name", THREEGPP_VENDOR_ID, False),
    (603, "Server-Capabilities", THREEGPP_VENDOR_ID, True),
    (604, "Mandatory-Capability", THREEGPP_VENDOR_ID, False),
    (605, "Optional-Capability", THREEGPP_VENDOR_ID, False),
    (606, "Cx-User-Data", THREEGPP_VENDOR_ID, False),
    (607, "3GPP-SIP-Number-Auth-Items", THREEGPP_VENDOR_ID, False),
    (608, "3GPP-SIP-Authentication-Scheme", THREEGPP_VENDOR_ID, False),
    (609, "3GPP-SIP-Authenticate", THREEGPP_VENDOR_ID, False),
    (610, "3GPP-SIP-Authorization", THREEGPP_VENDOR_ID, False),
    (611, "SIP-Authentication-Context", THREEGPP_VENDOR_ID, False),
    (612, "3GPP-SIP-Auth-Data-Item", THREEGPP_VENDOR_ID, True),
    (613, "3GPP-SIP-Item-Number", THREEGPP_VENDOR_ID, False),
    (614, "Server-Assignment-Type", THREEGPP_VENDOR_ID, False),
    (615, "Deregistration-Reason", THREEGPP_VENDOR_ID, True),
    (616, "Reason-Code", THREEGPP_VENDOR_ID, False),
    (617, "Reason-Info", THREEGPP_VENDOR_ID, False),
    (623, "User-Authorization-Type", THREEGPP_VENDOR_ID, False),
    (624, "User-Data-Already-Available", THREEGPP_VENDOR_ID, False),
    (625, "Confidentiality-Key", THREEGPP_VENDOR_ID, False),
    (626, "Integrity-Key", THREEGPP_VENDOR_ID, False),
    (628, "Supported-Features", THREEGPP_VENDOR_ID, True),
    (629, "Feature-List-ID", THREEGPP_VENDOR_ID, False),
    (630, "Feature-List", THREEGPP_VENDOR_ID, False),
)
AVP_NAMES = {code: name for code, name, _, _ in AVP_VOCABULARY}
GROUPED_CODES = {code for code, _, _, grouped in AVP_VOCABULARY if grouped}
AVP_VENDORS = {code: vendor for code, _, vendor, _ in AVP_VOCABULARY}

# TS 29.229 clause 6.3 uses the normative 3GPP AVP names below. The installed
# Wireshark dictionary exposes the "3GPP-" prefixed aliases for several of them.
CANONICAL_AVP_NAMES = {
    606: "User-Data",
    607: "SIP-Number-Auth-Items",
    608: "SIP-Authentication-Scheme",
    609: "SIP-Authenticate",
    610: "SIP-Authorization",
    612: "SIP-Auth-Data-Item",
    613: "SIP-Item-Number",
}


def canonical_avp_name(code: int) -> str | None:
    return CANONICAL_AVP_NAMES.get(code, AVP_NAMES.get(code))


# AVPs whose contents are never published, regardless of Diameter Core marking.
PROTECTED_CODES = {
    1,  # User-Name
    601,  # Public-Identity
    606,  # Cx-User-Data
    609,  # 3GPP-SIP-Authenticate
    610,  # 3GPP-SIP-Authorization
    611,  # SIP-Authentication-Context
    617,  # Reason-Info
    625,  # Confidentiality-Key
    626,  # Integrity-Key
}

REVIEWED_ENUMS = {
    614: {
        0: "NO_ASSIGNMENT",
        1: "REGISTRATION",
        2: "RE_REGISTRATION",
        3: "UNREGISTERED_USER",
        4: "TIMEOUT_DEREGISTRATION",
        5: "USER_DEREGISTRATION",
        6: "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME",
        7: "USER_DEREGISTRATION_STORE_SERVER_NAME",
        8: "ADMINISTRATIVE_DEREGISTRATION",
        9: "AUTHENTICATION_FAILURE",
        10: "AUTHENTICATION_TIMEOUT",
        11: "DEREGISTRATION_TOO_MUCH_DATA",
        12: "AAA_USER_DATA_REQUEST",
        13: "PGW_UPDATE",
        14: "RESTORATION",
    },
    616: {
        0: "PERMANENT_TERMINATION",
        1: "NEW_SERVER_ASSIGNED",
        2: "SERVER_CHANGE",
        3: "REMOVE_S-CSCF",
    },
    623: {
        0: "REGISTRATION",
        1: "DE_REGISTRATION",
        2: "REGISTRATION_AND_CAPABILITIES",
    },
    624: {
        0: "USER_DATA_NOT_AVAILABLE",
        1: "USER_DATA_ALREADY_AVAILABLE",
    },
}

THREEGPP_CX_SUCCESS_RESULT_NAMES = {
    2001: "DIAMETER_FIRST_REGISTRATION",
    2002: "DIAMETER_SUBSEQUENT_REGISTRATION",
    2003: "DIAMETER_UNREGISTERED_SERVICE",
    2004: "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED",
}

THREEGPP_CX_FAILURE_RESULT_NAMES = {
    5001: "DIAMETER_ERROR_USER_UNKNOWN",
    5002: "DIAMETER_ERROR_IDENTITIES_DONT_MATCH",
    5003: "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED",
    5004: "DIAMETER_ERROR_ROAMING_NOT_ALLOWED",
    5005: "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED",
    5006: "DIAMETER_ERROR_AUTH_SCHEME_NOT_SUPPORTED",
    5007: "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE",
    5008: "DIAMETER_ERROR_TOO_MUCH_DATA",
    5009: "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA",
    5011: "DIAMETER_ERROR_FEATURE_UNSUPPORTED",
    5012: "DIAMETER_ERROR_SERVING_NODE_FEATURE_UNSUPPORTED",
}

# Combined view retained for callers that need all reviewed Cx result names.
THREEGPP_CX_RESULT_NAMES = {
    **THREEGPP_CX_SUCCESS_RESULT_NAMES,
    **THREEGPP_CX_FAILURE_RESULT_NAMES,
}

# TS 29.229 V19.1.0 clause 6.2.1.5 and clause 6.2.2.10 define these as Void.
THREEGPP_CX_VOID_RESULT_CODES = {2005, 5010}

# TS 29.230 V19.3.0 registry ranges. Success and permanent-failure reserved
# ranges are intentionally separate.
THREEGPP_CX_RESERVED_SUCCESS_RESULT_CODES = frozenset(range(2006, 2021))
THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES = frozenset(range(5013, 5021))
# Reserved for TS 32.299, not owned by the Cx/Dx application.
THREEGPP_OTHER_SPEC_RESERVED_RESULT_CODES = frozenset(range(5021, 5041))
# Backward-compatible alias for the permanent-failure reserved range only.
THREEGPP_CX_RESERVED_RESULT_CODES = THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES

BASE_SUCCESS = {2001, 2002}

# Reviewed top-level AVP vocabulary per command and direction.
COMMAND_AVPS = {
    (300, "REQUEST"): (263, 601, 600, 623, 277, 264, 296, 283),
    (300, "ANSWER"): (268, 297, 603, 277, 264, 296),
    (301, "REQUEST"): (263, 601, 602, 614, 628, 277, 264, 296, 283),
    (301, "ANSWER"): (268, 297, 606, 628, 264, 296),
    (302, "REQUEST"): (263, 601, 277, 264, 296, 283),
    (302, "ANSWER"): (268, 297, 602, 264, 296),
    (303, "REQUEST"): (263, 601, 607, 612, 277, 264, 296, 283),
    (303, "ANSWER"): (268, 297, 607, 612, 264, 296),
    (304, "REQUEST"): (263, 601, 615, 277, 264, 296, 283),
    (304, "ANSWER"): (268, 297, 264, 296),
    (305, "REQUEST"): (263, 606, 628, 277, 264, 296, 283),
    (305, "ANSWER"): (268, 297, 264, 296),
}

LIMITATIONS = [
    "the Cx/Dx Application-ID does not prove whether an observed message crossed the Cx or the Dx interface",
    "a Diameter Result-Code or 3GPP Experimental-Result is protocol evidence only; it is not an IMS registration, authentication or service-authorization verdict",
    "subscriber identities, public identities, authentication vectors, Cx user data and raw grouped payloads are never published",
    "the analysis consumes accepted Diameter Core correlation and never constructs a new Request/Answer pair",
]

NOT_CONFIRMED = [
    "IMS registration success or failure is not proven",
    "IMS subscriber authentication is not proven",
    "HSS authorization beyond the reported Diameter result is not proven",
    "S-CSCF assignment or profile installation is not proven",
    "Cx versus Dx interface identity is not proven",
    "SIP-level IMS identity or registration state is not established",
]


class InputError(Exception):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name} is not valid JSON: {exc}") from exc


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name} line {line_number} is not valid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise InputError(f"{path.name} line {line_number} is not an object")
            rows.append(row)
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_event(event: dict[str, Any]) -> None:
    for field in (
        "capture_file",
        "frame_number",
        "message_occurrence",
        "command_code",
        "application_id",
        "direction",
        "transport",
        "avps",
        "result",
    ):
        if field not in event:
            raise InputError(f"missing required event field: {field}")
        if event[field] is None:
            raise InputError(f"event {field} must not be null")
    if not isinstance(event["frame_number"], int) or isinstance(event["frame_number"], bool) or event["frame_number"] < 1:
        raise InputError("event frame_number must be a positive integer")
    if not isinstance(event["message_occurrence"], int) or isinstance(event["message_occurrence"], bool) or event["message_occurrence"] < 1:
        raise InputError("event message_occurrence must be a positive integer")
    if event["direction"] not in ("REQUEST", "ANSWER"):
        raise InputError("event direction must be REQUEST or ANSWER")
    if not isinstance(event["avps"], list):
        raise InputError("event avps must be an array")
    if not isinstance(event["transport"], dict):
        raise InputError("event transport must be an object")
    if not isinstance(event["result"], dict):
        raise InputError("event result must be an object")


def _validate_transaction(transaction: dict[str, Any]) -> None:
    for field in (
        "transaction_reference",
        "command_code",
        "application_id",
        "correlation_status",
        "request",
        "answer",
    ):
        if field not in transaction:
            raise InputError(f"missing required transaction field: {field}")
    if transaction["transaction_reference"] is None or transaction["command_code"] is None or transaction["application_id"] is None:
        raise InputError("transaction identity fields must not be null")
    if not isinstance(transaction["transaction_reference"], str) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(
        transaction["transaction_reference"]
    ):
        raise InputError("transaction_reference is not a valid Diameter Core transaction reference")
    if transaction["correlation_status"] not in (
        "MATCHED",
        "OPEN_REQUEST",
        "RESPONSE_ONLY",
        "AMBIGUOUS",
    ):
        raise InputError("transaction has an unsupported correlation_status")
    if transaction["correlation_status"] == "MATCHED":
        if transaction["request"] is None or transaction["answer"] is None:
            raise InputError("MATCHED transaction must publish request and answer")
    if transaction["correlation_status"] == "OPEN_REQUEST":
        if transaction["request"] is None or transaction["answer"] is not None:
            raise InputError("OPEN_REQUEST transaction must publish only a request")
        if transaction.get("latency_seconds") is not None:
            raise InputError("OPEN_REQUEST transaction must not publish latency")
    if transaction["correlation_status"] == "RESPONSE_ONLY":
        if transaction["request"] is not None or transaction["answer"] is None:
            raise InputError("RESPONSE_ONLY transaction must publish only an answer")
        if transaction.get("latency_seconds") is not None:
            raise InputError("RESPONSE_ONLY transaction must not publish latency")
    if transaction["correlation_status"] == "AMBIGUOUS":
        if transaction["request"] is not None or transaction["answer"] is None:
            raise InputError("AMBIGUOUS transaction must publish an answer and no selected request")
        if transaction.get("latency_seconds") is not None:
            raise InputError("AMBIGUOUS transaction must not publish latency")
        if not transaction.get("response_candidates"):
            raise InputError("AMBIGUOUS transaction must retain candidate references")


def event_reference(event: dict[str, Any]) -> str:
    return f"diameter-event:{event['capture_file']}:{event['frame_number']}.{event['message_occurrence']}"


def _reference_endpoint(reference: dict[str, Any], side: str) -> str:
    explicit = reference.get(f"{side}_endpoint")
    if explicit is not None:
        return explicit
    transport = reference.get("transport") or {}
    address = transport.get(f"{side}_address")
    port = transport.get(f"{side}_port")
    return f"{address}:{port}" if address is not None and port is not None else "unknown"


def _message_name(command_code: int, direction: str) -> str | None:
    command = COMMANDS.get(command_code)
    if command is None:
        return None
    return command[1] if direction == "REQUEST" else command[2]


def _reference_projection(reference: dict[str, Any] | None, *, interpreted: bool) -> dict[str, Any] | None:
    if reference is None:
        return None
    command_code = reference["command_code"]
    return {
        "event_reference": f"diameter-event:{reference['frame_number']}.{reference['message_occurrence']}",
        "frame_number": reference["frame_number"],
        "message_occurrence": reference["message_occurrence"],
        "direction": reference["direction"],
        "application_id": reference["application_id"],
        "command_code": command_code,
        "command_name": AVP_COMMAND_NAME(command_code) if interpreted else None,
        "message_name": _message_name(command_code, reference["direction"]) if interpreted else None,
        "hop_by_hop_id": reference["hop_by_hop_id"],
        "end_to_end_id": reference["end_to_end_id"],
        "source_endpoint": _reference_endpoint(reference, "source"),
        "destination_endpoint": _reference_endpoint(reference, "destination"),
    }


def AVP_COMMAND_NAME(command_code: int) -> str | None:
    command = COMMANDS.get(command_code)
    return command[0] if command is not None else None


def _resolve(index: dict[tuple[int, int], dict[str, Any]], reference: dict[str, Any], label: str) -> dict[str, Any]:
    key = (reference["frame_number"], reference["message_occurrence"])
    event = index.get(key)
    if event is None:
        raise InputError(f"{label} reference does not resolve to a Diameter Core event")
    for field in ("direction", "command_code", "application_id", "hop_by_hop_id", "end_to_end_id"):
        if reference.get(field) != event.get(field):
            raise InputError(f"{label} reference disagrees with the event on {field}")
    return event


def validate_core(
    events: list[dict[str, Any]], transaction_document: dict[str, Any]
) -> tuple[dict[tuple[int, int], dict[str, Any]], list[dict[str, Any]]]:
    if not isinstance(transaction_document, dict):
        raise InputError("transaction input must be a JSON object")
    if not events:
        raise InputError("event input contains no Diameter records")
    for event in events:
        _validate_event(event)
    captures = {event["capture_file"] for event in events}
    if len(captures) != 1:
        raise InputError("application analysis requires events from exactly one capture")
    capture = next(iter(captures))
    transactions = transaction_document.get("transactions")
    if not isinstance(transactions, list):
        raise InputError("transaction input must contain a transactions array")
    declared_captures = transaction_document.get("capture_files")
    if declared_captures != [capture]:
        raise InputError("transaction capture_files do not match the event capture")
    index: dict[tuple[int, int], dict[str, Any]] = {}
    for event in events:
        key = (event["frame_number"], event["message_occurrence"])
        if key in index:
            raise InputError("duplicate event frame and message occurrence")
        index[key] = event
    seen: set[str] = set()
    for transaction in transactions:
        _validate_transaction(transaction)
        reference = transaction["transaction_reference"]
        if reference in seen:
            raise InputError(f"duplicate transaction reference: {reference}")
        seen.add(reference)
        request = transaction["request"]
        answer = transaction["answer"]
        if request is not None:
            request_event = _resolve(index, request, "request")
            if request_event["direction"] != "REQUEST":
                raise InputError("transaction request reference does not point to a REQUEST")
        if answer is not None:
            answer_event = _resolve(index, answer, "answer")
            if answer_event["direction"] != "ANSWER":
                raise InputError("transaction answer reference does not point to an ANSWER")
        if request is not None and answer is not None:
            request_event = _resolve(index, request, "request")
            answer_event = _resolve(index, answer, "answer")
            for field in ("command_code", "application_id", "hop_by_hop_id", "end_to_end_id"):
                if request_event.get(field) != answer_event.get(field):
                    raise InputError(f"MATCHED transaction disagrees on {field}")
        for candidate in transaction.get("response_candidates") or []:
            _resolve(index, candidate, "ambiguous candidate")
    referenced: set[tuple[int, int]] = set()
    for transaction in transactions:
        references = []
        if transaction["request"] is not None:
            references.append(transaction["request"])
        if transaction["answer"] is not None:
            references.append(transaction["answer"])
        references.extend(transaction.get("response_candidates") or [])
        for reference in references:
            referenced.add((reference["frame_number"], reference["message_occurrence"]))
    for event in events:
        if event["application_id"] != CX_APPLICATION_ID:
            continue
        key = (event["frame_number"], event["message_occurrence"])
        if key not in referenced:
            raise InputError(
                "supplied Core transactions do not cover every Cx/Dx event: "
                f"frame {event['frame_number']} occurrence {event['message_occurrence']}"
            )
    return index, transactions


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _avp_namespace(avp: dict[str, Any]) -> str:
    namespace = avp.get("namespace")
    if isinstance(namespace, str):
        return namespace
    vendor_id = avp.get("vendor_id")
    vendor_specific = bool(avp.get("vendor_specific"))
    if vendor_specific and vendor_id == THREEGPP_VENDOR_ID:
        return "3GPP"
    if not vendor_specific and vendor_id in (None, 0):
        return "BASE"
    return "UNKNOWN_VENDOR"


def _namespace_for_code(code: int) -> str:
    vendor = AVP_VENDORS.get(code)
    return "3GPP" if vendor == THREEGPP_VENDOR_ID else "BASE"


def _reviewed_values(avps: list[dict[str, Any]], code: int) -> list[str]:
    if code in PROTECTED_CODES:
        return []
    enum = REVIEWED_ENUMS.get(code)
    if enum is None:
        return []
    values: set[str] = set()
    for avp in avps:
        if avp.get("sensitive"):
            continue
        value = avp.get("value")
        if isinstance(value, int) and not isinstance(value, bool) and value in enum:
            values.add(enum[value])
    return sorted(values)[:MAX_REVIEWED_VALUES]


def _grouped_children(avp: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    groups: dict[tuple[int, str, int | None], dict[str, Any]] = {}
    for child in avp.get("children") or []:
        code = child.get("code")
        if not isinstance(code, int) or isinstance(code, bool):
            continue
        key = (code, _avp_namespace(child), child.get("vendor_id"))
        entry = groups.get(key)
        if entry is None:
            entry = {
                "code": code,
                "name": AVP_NAMES.get(code) or child.get("name"),
                "canonical_name": canonical_avp_name(code) or child.get("name"),
                "vendor_id": child.get("vendor_id"),
                "occurrence_count": 0,
                "sensitive": bool(child.get("sensitive")) or code in PROTECTED_CODES,
            }
            groups[key] = entry
        entry["occurrence_count"] += 1
    published = list(groups.values())[:MAX_GROUP_CHILDREN]
    for entry in published:
        entry["reviewed_values"] = _reviewed_values(
            [
                child
                for child in avp.get("children") or []
                if child.get("code") == entry["code"]
            ],
            entry["code"],
        )
        entry["value_published"] = bool(entry["reviewed_values"])
    omitted = int(avp.get("children_omitted") or 0) + max(0, len(groups) - len(published))
    return published, omitted


def _presence(
    event: dict[str, Any] | None,
    code: int,
    omitted: int,
) -> dict[str, Any]:
    grouped = code in GROUPED_CODES
    if event is None:
        matches: list[dict[str, Any]] = []
    else:
        matches = [
            avp
            for avp in event["avps"]
            if avp.get("code") == code
            and _avp_namespace(avp) == _namespace_for_code(code)
            and (_namespace_for_code(code) != "3GPP" or avp.get("vendor_id") == THREEGPP_VENDOR_ID)
        ]
    if matches:
        first = matches[0]
        sensitive = code in PROTECTED_CODES or any(bool(avp.get("sensitive")) for avp in matches)
        grouping_status = first.get("grouping_status")
        structure_proven = grouped and grouping_status == "DECODED"
        children: list[dict[str, Any]] = []
        children_omitted = 0
        if grouped and structure_proven:
            children, children_omitted = _grouped_children(first)
        if sensitive:
            status = "PRESENT_REDACTED"
        elif grouped:
            status = "PRESENT_STRUCTURE_ONLY"
        else:
            status = "PRESENT"
        reviewed_values = _reviewed_values(matches, code)
        return {
            "code": code,
            "name": AVP_NAMES[code],
            "canonical_name": canonical_avp_name(code),
            "vendor_id": AVP_VENDORS[code],
            "occurrence_count": len(matches),
            "status": status,
            "sensitive": sensitive,
            "grouped": grouped,
            "grouping_status": grouping_status,
            "structure_proven": structure_proven,
            "reviewed_values": reviewed_values,
            "value_published": bool(reviewed_values) and not sensitive,
            "children": children,
            "children_omitted": children_omitted,
        }
    return {
        "code": code,
        "name": AVP_NAMES[code],
        "canonical_name": canonical_avp_name(code),
        "vendor_id": AVP_VENDORS[code],
        "occurrence_count": 0,
        "status": "NOT_OBSERVED_IN_PUBLISHED_SUBSET" if omitted else "NOT_OBSERVED",
        "sensitive": code in PROTECTED_CODES,
        "grouped": grouped,
        "grouping_status": None,
        "structure_proven": False,
        "reviewed_values": [],
        "value_published": False,
        "children": [],
        "children_omitted": 0,
    }


def _unproven_grouping(presence: dict[str, Any]) -> bool:
    return (
        presence["grouped"]
        and presence["status"] == "PRESENT_STRUCTURE_ONLY"
        and not presence["structure_proven"]
    )


def _presence_set(event: dict[str, Any] | None, command_code: int) -> list[dict[str, Any]]:
    if event is None:
        return []
    definitions = COMMAND_AVPS.get((command_code, event["direction"]), ())
    omitted = int(event.get("avps_omitted") or 0)
    return [_presence(event, code, omitted) for code in definitions]


def _core_result_evidence(result: dict[str, Any]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    base = result.get("base_result_codes")
    experimental = result.get("experimental_results")
    status = result.get("result_status")
    if isinstance(base, list) and isinstance(experimental, list):
        if status is None:
            if base and experimental:
                status = "CONFLICTING"
            elif len(base) > 1 or len(experimental) > 1:
                status = "DUPLICATE"
            elif base:
                status = "SINGLE_BASE"
            elif experimental:
                status = "SINGLE_EXPERIMENTAL"
            else:
                status = "MISSING"
        return status, base, experimental
    base_entries = []
    experimental_entries = []
    if result.get("result_code") is not None:
        base_entries.append(
            {
                "code": result["result_code"],
                "name": result.get("result_code_name"),
                "avp_reference": None,
            }
        )
    if result.get("experimental_result_present"):
        experimental_entries.append(
            {
                "vendor_id": result.get("experimental_vendor_id"),
                "code": result.get("experimental_result_code"),
                "group_reference": None,
                "code_reference": None,
                "vendor_reference": None,
            }
        )
    if base_entries and experimental_entries:
        status = "CONFLICTING"
    elif len(base_entries) > 1 or len(experimental_entries) > 1:
        status = "DUPLICATE"
    elif base_entries:
        status = "SINGLE_BASE"
    elif experimental_entries:
        status = "SINGLE_EXPERIMENTAL"
    else:
        status = "MISSING"
    return status, base_entries, experimental_entries


def _base_outcome(code: Any) -> str:
    if code in BASE_SUCCESS:
        return "SUCCESS_REPORTED"
    if isinstance(code, int) and not isinstance(code, bool) and (
        1000 <= code < 2000 or code >= 3000
    ):
        return "FAILURE_REPORTED"
    return "UNRESOLVED"


def classify_result(answer: dict[str, Any] | None) -> dict[str, Any]:
    if answer is None:
        return {
            "core_result_status": "MISSING",
            "namespace_status": "MISSING",
            "application_result": "NOT_APPLICABLE",
            "base_result_code": None,
            "base_result_code_name": None,
            "experimental_result_code": None,
            "experimental_result_code_name": None,
            "experimental_vendor_id": None,
            "base_results": [],
            "experimental_results": [],
            "limitations": [],
        }
    result = answer.get("result") or {}
    status, base_entries, experimental_entries = _core_result_evidence(result)
    limitations: list[str] = []
    if status in ("CONFLICTING", "DUPLICATE"):
        limitations.append(
            "the supplied Core result evidence is conflicting or duplicated; no single result is selected"
        )
        return {
            "core_result_status": status,
            "namespace_status": "CONFLICTING",
            "application_result": "UNRESOLVED",
            "base_result_code": None,
            "base_result_code_name": None,
            "experimental_result_code": None,
            "experimental_result_code_name": None,
            "experimental_vendor_id": None,
            "base_results": base_entries,
            "experimental_results": experimental_entries,
            "limitations": limitations,
        }
    if status == "SINGLE_BASE" and base_entries:
        entry = base_entries[0]
        base_code = entry.get("code")
        base_name = entry.get("name")
        return {
            "core_result_status": status,
            "namespace_status": "BASE_RFC6733",
            "application_result": _base_outcome(base_code),
            "base_result_code": base_code,
            "base_result_code_name": base_name,
            "experimental_result_code": None,
            "experimental_result_code_name": None,
            "experimental_vendor_id": None,
            "base_results": base_entries,
            "experimental_results": [],
            "limitations": [] if base_name else ["the base Result-Code has no reviewed name and remains numeric"],
        }
    if status == "SINGLE_EXPERIMENTAL" and experimental_entries:
        entry = experimental_entries[0]
        vendor_id = entry.get("vendor_id")
        experimental_code = entry.get("code")
        if vendor_id == THREEGPP_VENDOR_ID and experimental_code in THREEGPP_CX_SUCCESS_RESULT_NAMES:
            return {
                "core_result_status": status,
                "namespace_status": "3GPP_TS_29_229_EXPERIMENTAL",
                "application_result": "SUCCESS_REPORTED",
                "base_result_code": None,
                "base_result_code_name": None,
                "experimental_result_code": experimental_code,
                "experimental_result_code_name": THREEGPP_CX_SUCCESS_RESULT_NAMES[experimental_code],
                "experimental_vendor_id": vendor_id,
                "base_results": [],
                "experimental_results": experimental_entries,
                "limitations": [],
            }
        if vendor_id == THREEGPP_VENDOR_ID and experimental_code in THREEGPP_CX_FAILURE_RESULT_NAMES:
            return {
                "core_result_status": status,
                "namespace_status": "3GPP_TS_29_229_EXPERIMENTAL",
                "application_result": "FAILURE_REPORTED",
                "base_result_code": None,
                "base_result_code_name": None,
                "experimental_result_code": experimental_code,
                "experimental_result_code_name": THREEGPP_CX_FAILURE_RESULT_NAMES[experimental_code],
                "experimental_vendor_id": vendor_id,
                "base_results": [],
                "experimental_results": experimental_entries,
                "limitations": [],
            }
        if vendor_id == THREEGPP_VENDOR_ID:
            if experimental_code in THREEGPP_CX_VOID_RESULT_CODES:
                clause = "6.2.1.5" if experimental_code == 2005 else "6.2.2.10"
                limitations.append(
                    "the Experimental-Result-Code is Void in TS 29.229 V19.1.0 clause "
                    f"{clause}; no semantic name is assigned and the numeric value is preserved"
                )
                if experimental_code == 2005:
                    limitations.append(
                        "TS 29.230 V19.3.0 table 8.1.2 classifies 2005 as a Deprecated value; it is not a valid Cx success result"
                    )
                else:
                    limitations.append(
                        "TS 29.230 V19.3.0 table 8.1.4 classifies 5010 as unassigned"
                    )
            elif experimental_code in THREEGPP_CX_RESERVED_SUCCESS_RESULT_CODES:
                limitations.append(
                    "the Experimental-Result-Code is in the TS 29.230 V19.3.0 table 8.1.2 reserved success range 2006-2020; numeric identity is preserved without a semantic name"
                )
            elif experimental_code in THREEGPP_CX_RESERVED_PERMANENT_FAILURE_RESULT_CODES:
                limitations.append(
                    "the Experimental-Result-Code is in the TS 29.230 V19.3.0 table 8.1.4 reserved permanent-failure range 5013-5020; numeric identity is preserved without a semantic name"
                )
            elif experimental_code in THREEGPP_OTHER_SPEC_RESERVED_RESULT_CODES:
                limitations.append(
                    "the Experimental-Result-Code is reserved for TS 32.299 (5021-5040) in TS 29.230 V19.3.0 and is not a Cx/Dx result code; no Cx/Dx semantics are assigned"
                )
            else:
                limitations.append(
                    "the 3GPP Vendor-ID is present but the Experimental-Result-Code is not reviewed; no semantic name is assigned"
                )
            namespace = "3GPP_TS_29_229_EXPERIMENTAL"
        elif vendor_id is None:
            limitations.append(
                "the Experimental-Result has no Vendor-ID; no 3GPP meaning is assigned"
            )
            namespace = "UNKNOWN_VENDOR_EXPERIMENTAL"
        else:
            limitations.append(
                "the Experimental-Result Vendor-ID is not 3GPP; no 3GPP meaning is assigned"
            )
            namespace = "UNKNOWN_VENDOR_EXPERIMENTAL"
        return {
            "core_result_status": status,
            "namespace_status": namespace,
            "application_result": "UNRESOLVED",
            "base_result_code": None,
            "base_result_code_name": None,
            "experimental_result_code": experimental_code,
            "experimental_result_code_name": None,
            "experimental_vendor_id": vendor_id,
            "base_results": [],
            "experimental_results": experimental_entries,
            "limitations": limitations,
        }
    return {
        "core_result_status": "MISSING",
        "namespace_status": "MISSING",
        "application_result": "UNRESOLVED",
        "base_result_code": None,
        "base_result_code_name": None,
        "experimental_result_code": None,
        "experimental_result_code_name": None,
        "experimental_vendor_id": None,
        "base_results": base_entries,
        "experimental_results": experimental_entries,
        "limitations": ["no base Result-Code or Experimental-Result is published"],
    }


def _observation_reference(capture: str, event: dict[str, Any], suffix: str = "") -> str:
    base = f"diameter-ims-observation:{capture}:{event['frame_number']}.{event['message_occurrence']}"
    return f"{base}{suffix}"


def _not_confirmed(procedure_family: str | None, application_result: str) -> list[str]:
    items = [
        "a Diameter Cx/Dx result does not prove IMS registration, authentication or service authorization"
    ]
    if procedure_family == "USER_AUTHORIZATION":
        items.append("the I-CSCF or HSS user-authorization decision beyond the observed result is not proven")
    if procedure_family == "SERVER_ASSIGNMENT":
        items.append("S-CSCF assignment, user-profile installation and registration success are not proven")
    if procedure_family == "LOCATION_INFO":
        items.append("the serving S-CSCF location beyond the observed answer is not proven")
    if procedure_family == "MULTIMEDIA_AUTH":
        items.append("usable authentication vectors and UE authentication success are not proven")
        if application_result == "SUCCESS_REPORTED":
            items.append("MAA success does not prove that the UE later authenticated successfully")
    if procedure_family == "REGISTRATION_TERMINATION":
        items.append("the subscriber is not proven to have been deregistered or to have lost service")
    if procedure_family == "PUSH_PROFILE":
        items.append("profile-update delivery to the S-CSCF is not proven")
    return items


def _observation(
    *,
    capture: str,
    transaction: dict[str, Any],
    request: dict[str, Any] | None,
    answer: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
    message_status: str,
) -> dict[str, Any]:
    anchor = request if request is not None else answer
    command_code = int(transaction["command_code"])
    interpreted = message_status == "OBSERVED"
    procedure_family = (
        COMMANDS[command_code][0].upper().replace("-", "_") if interpreted else None
    )
    procedure = (
        _message_name(command_code, anchor["direction"]) if interpreted else None
    )
    result = classify_result(answer) if interpreted else {
        "core_result_status": "MISSING",
        "namespace_status": "MISSING",
        "application_result": "NOT_APPLICABLE",
        "base_result_code": None,
        "base_result_code_name": None,
        "experimental_result_code": None,
        "experimental_result_code_name": None,
        "experimental_vendor_id": None,
        "base_results": [],
        "experimental_results": [],
        "limitations": [],
    }
    limitations: list[str] = []
    if transaction["correlation_status"] != "MATCHED":
        limitations.append(
            "the Diameter Core transaction is not MATCHED; no application Request/Answer pairing is claimed"
        )
    if message_status == "KNOWN_UNSUPPORTED":
        limitations.append(
            "the command code is outside the reviewed Cx/Dx command set; its numeric identity is preserved without application semantics"
        )
    if message_status == "CONFLICTING":
        limitations.append(
            "the command code is a reviewed Cx/Dx command but the Application-ID is not 16777216; no Cx/Dx semantics are assigned"
        )
    limitations.extend(result["limitations"])
    if request is not None:
        limitations.extend(request.get("limitations") or [])
    if answer is not None:
        limitations.extend(answer.get("limitations") or [])
    if transaction.get("limitations"):
        limitations.extend(transaction["limitations"])
    request_presence = _presence_set(request, command_code) if interpreted else []
    answer_presence = _presence_set(answer, command_code) if interpreted else []
    for presence in request_presence + answer_presence:
        if _unproven_grouping(presence):
            limitations.append(
                "a reviewed grouped AVP is present without decoder-proven child structure; child relationships are not inferred"
            )
            break
    return {
        "observation_reference": _observation_reference(capture, anchor),
        "procedure": procedure,
        "procedure_family": procedure_family,
        "command_code": command_code,
        "command_name": AVP_COMMAND_NAME(command_code) if interpreted else None,
        "message_status": message_status,
        "transaction_status": transaction["correlation_status"],
        "application_result": result["application_result"],
        "request": _reference_projection(request, interpreted=interpreted),
        "answer": _reference_projection(answer, interpreted=interpreted),
        "response_candidates": [
            _reference_projection(item, interpreted=interpreted) for item in candidates
        ],
        "latency_seconds": transaction.get("latency_seconds") if transaction["correlation_status"] == "MATCHED" else None,
        "transaction_reference": transaction["transaction_reference"],
        "result": result,
        "request_avp_presence": request_presence,
        "answer_avp_presence": answer_presence,
        "limitations": sorted({item for item in limitations if item}),
        "not_confirmed": _not_confirmed(procedure_family, result["application_result"]),
    }


def analyze(
    events: list[dict[str, Any]],
    transaction_document: dict[str, Any],
    *,
    input_provenance: dict[str, Any],
) -> dict[str, Any]:
    index, transactions = validate_core(events, transaction_document)
    capture = events[0]["capture_file"]
    observations: list[dict[str, Any]] = []

    for transaction in transactions:
        application_id = transaction["application_id"]
        command_code = int(transaction["command_code"])
        if application_id != CX_APPLICATION_ID and command_code not in SUPPORTED_COMMAND_CODES:
            continue
        request = transaction["request"]
        answer = transaction["answer"]
        request_event = _resolve(index, request, "request") if request is not None else None
        answer_event = _resolve(index, answer, "answer") if answer is not None else None
        candidates = [
            _resolve(index, candidate, "ambiguous candidate")
            for candidate in transaction.get("response_candidates") or []
        ]
        if application_id != CX_APPLICATION_ID:
            message_status = "CONFLICTING"
        elif command_code in SUPPORTED_COMMAND_CODES:
            message_status = "OBSERVED"
        else:
            message_status = "KNOWN_UNSUPPORTED"
        observations.append(
            _observation(
                capture=capture,
                transaction=transaction,
                request=request_event,
                answer=answer_event,
                candidates=candidates,
                message_status=message_status,
            )
        )

    observations.sort(
        key=lambda item: (
            (item["request"] or item["answer"])["frame_number"],
            (item["request"] or item["answer"])["message_occurrence"],
            item["observation_reference"],
        )
    )
    omitted = max(0, len(observations) - MAX_OBSERVATIONS)
    published = observations[:MAX_OBSERVATIONS]
    inventory = _inventory(events, transactions)
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": "protocol",
        "capability": {
            "supported_commands": [
                f"{code} {COMMANDS[code][1]}/{COMMANDS[code][2]}" for code in SUPPORTED_COMMAND_CODES
            ],
            "recognized_unsupported_commands": [],
            "application_id": CX_APPLICATION_ID,
            "application_name": "Cx/Dx",
            "interface_identity": "UNPROVED",
            "interface_identity_basis": [],
            "unreviewed_command_policy": "KNOWN_UNSUPPORTED_WITH_NUMERIC_IDENTITY",
        },
        "input_provenance": input_provenance,
        "command_inventory": inventory,
        "observations": published,
        "completeness": {
            "observation_count": len(published),
            "observations_omitted": omitted,
            "cx_event_count": sum(1 for event in events if event["application_id"] == CX_APPLICATION_ID),
            "cx_transaction_count": sum(1 for transaction in transactions if transaction["application_id"] == CX_APPLICATION_ID),
            "events_with_avp_omissions": sum(1 for event in events if int(event.get("avps_omitted") or 0) > 0),
            "truncated_observations": sum(
                1
                for observation in published
                if any(
                    presence["status"] == "NOT_OBSERVED_IN_PUBLISHED_SUBSET"
                    for presence in observation["request_avp_presence"] + observation["answer_avp_presence"]
                )
            ),
            "unsupported_observations": sum(
                1 for observation in published if observation["message_status"] == "KNOWN_UNSUPPORTED"
            ),
            "conflicting_observations": sum(
                1 for observation in published if observation["message_status"] == "CONFLICTING"
            ),
            "observations_with_unproven_grouping": sum(
                1
                for observation in published
                if any(
                    _unproven_grouping(presence)
                    for presence in observation["request_avp_presence"] + observation["answer_avp_presence"]
                )
            ),
        },
        "not_confirmed": NOT_CONFIRMED,
        "limitations": LIMITATIONS,
    }


def _inventory(events: list[dict[str, Any]], transactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[int, int, str], int] = {}
    transaction_counts: dict[tuple[int, int], int] = {}
    for event in events:
        key = (event["application_id"], event["command_code"], event["direction"])
        counts[key] = counts.get(key, 0) + 1
    for transaction in transactions:
        key = (transaction["application_id"], transaction["command_code"])
        transaction_counts[key] = transaction_counts.get(key, 0) + 1
    inventory = []
    for (application_id, command_code, direction), count in sorted(counts.items(), key=str):
        if application_id == CX_APPLICATION_ID and command_code in SUPPORTED_COMMAND_CODES:
            scope = "SUPPORTED"
        elif application_id == CX_APPLICATION_ID:
            scope = "KNOWN_UNSUPPORTED"
        elif command_code in SUPPORTED_COMMAND_CODES:
            scope = "CONFLICTING_APPLICATION"
        elif application_id == 0:
            scope = "BASE_OR_UNKNOWN"
        else:
            scope = "NON_CX_APPLICATION"
        inventory.append(
            {
                "application_id": application_id,
                "command_code": command_code,
                "command_name": AVP_COMMAND_NAME(command_code) if application_id == CX_APPLICATION_ID else None,
                "direction": direction,
                "event_count": count,
                "transaction_count": transaction_counts.get((application_id, command_code), 0),
                "scope": scope,
            }
        )
    return inventory


def render_timeline(document: dict[str, Any]) -> str:
    lines = [
        "frame       command  core-status    result                    app-result        interface",
        "----------  -------  -------------  ------------------------  ----------------  ---------",
    ]
    for observation in document["observations"]:
        request = observation["request"]
        answer = observation["answer"]
        request_frame = None if request is None else f"{request['frame_number']}.{request['message_occurrence']}"
        answer_frame = None if answer is None else f"{answer['frame_number']}.{answer['message_occurrence']}"
        if request_frame and answer_frame:
            frame = f"{request_frame}->{answer_frame}"
        else:
            frame = request_frame or answer_frame
        command = observation["procedure"] or f"CMD-{observation['command_code']}"
        result = observation["result"]
        if result["base_result_code"] is not None:
            result_text = f"base:{result['base_result_code']}({result['base_result_code_name'] or 'UNNAMED'})"
        elif result["experimental_result_code"] is not None:
            prefix = "3gpp" if result["namespace_status"] == "3GPP_TS_29_229_EXPERIMENTAL" else "exp"
            result_text = f"{prefix}:{result['experimental_result_code']}({result['experimental_result_code_name'] or 'UNREVIEWED'})"
        else:
            result_text = "unresolved"
        lines.append(
            f"{frame:<11} {command:<7} {observation['transaction_status']:<13} "
            f"{result_text:<24} {observation['application_result']:<16} "
            f"{document['capability']['interface_identity']}"
        )
    return "\n".join(lines) + "\n"