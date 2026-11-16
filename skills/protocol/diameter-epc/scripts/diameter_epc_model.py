#!/usr/bin/env python3
"""Bounded Diameter EPC S6a/S6d application evidence model.

The model consumes accepted Diameter Core events and transactions. It never
parses packet bytes, never re-correlates Request/Answer pairs, and never emits a
subscriber, authentication-vector or EPC procedure verdict.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ANALYSIS_NAME = "diameter-epc"
ANALYSIS_VERSION = "1.0.0"

S6A_APPLICATION_ID = 16777251
THREEGPP_VENDOR_ID = 10415
MAX_OBSERVATIONS = 256

COMMANDS = {
    316: ("Update-Location", "ULR", "ULA"),
    317: ("Cancel-Location", "CLR", "CLA"),
    318: ("Authentication-Information", "AIR", "AIA"),
    319: ("Insert-Subscriber-Data", "IDR", "IDA"),
    320: ("Delete-Subscriber-Data", "DSR", "DSA"),
    321: ("Notify", "NOR", "NOA"),
    322: ("Purge-UE", "PUR", "PUA"),
    323: ("Reset", "RSR", "RSA"),
}
SUPPORTED_COMMANDS = {316, 318}
REVIEWED_UNSUPPORTED_COMMANDS = {317, 319, 320, 321, 322, 323}

THREEGPP_RESULT_NAMES = {
    5001: "DIAMETER_ERROR_USER_UNKNOWN",
    5420: "DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION",
    5421: "DIAMETER_ERROR_RAT_NOT_ALLOWED",
}

BASE_SUCCESS = {2001, 2002}

AIR_PRESENCE = (
    (1408, "Requested-EUTRAN-Authentication-Info", THREEGPP_VENDOR_ID),
    (1409, "Requested-UTRAN-GERAN-Authentication-Info", THREEGPP_VENDOR_ID),
    (1407, "Visited-PLMN-Id", THREEGPP_VENDOR_ID),
    (1, "User-Name", None),
    (263, "Session-Id", None),
    (264, "Origin-Host", None),
    (296, "Origin-Realm", None),
    (283, "Destination-Realm", None),
    (293, "Destination-Host", None),
    (277, "Auth-Session-State", None),
)

AIA_AUTHENTICATION = (
    (1413, "E-UTRAN-Authentication-Info", THREEGPP_VENDOR_ID),
    (1414, "UTRAN-GERAN-Authentication-Info", THREEGPP_VENDOR_ID),
)

ULR_PRESENCE = (
    (1032, "RAT-Type", THREEGPP_VENDOR_ID),
    (1405, "ULR-Flags", THREEGPP_VENDOR_ID),
    (1407, "Visited-PLMN-Id", THREEGPP_VENDOR_ID),
    (628, "Supported-Features", THREEGPP_VENDOR_ID),
    (1, "User-Name", None),
    (263, "Session-Id", None),
    (264, "Origin-Host", None),
    (296, "Origin-Realm", None),
    (283, "Destination-Realm", None),
    (293, "Destination-Host", None),
)

ULA_PRESENCE = (
    (1400, "Subscription-Data", THREEGPP_VENDOR_ID),
    (1407, "Visited-PLMN-Id", THREEGPP_VENDOR_ID),
    (628, "Supported-Features", THREEGPP_VENDOR_ID),
    (263, "Session-Id", None),
    (264, "Origin-Host", None),
    (296, "Origin-Realm", None),
)

LIMITATIONS = [
    "the S6a/S6d Application-ID does not distinguish an MME from an SGSN interface",
    "a Diameter Result-Code or 3GPP Experimental-Result is protocol evidence only; it is not an EPS Attach, UE authentication, registration or network-access verdict",
    "subscriber identity, authentication vectors and subscription profiles are never published",
    "the analysis consumes accepted Diameter Core correlation and never constructs a new Request/Answer pair",
]

NOT_CONFIRMED = [
    "UE authentication success is not proven",
    "EPS Attach success or failure is not proven",
    "HSS subscriber authorization beyond the reported Diameter result is not proven",
    "MME or SGSN context installation is not proven",
    "usable authentication-vector correctness is not proven",
    "S6a versus S6d interface identity is not proven",
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


def _reference_projection(reference: dict[str, Any] | None) -> dict[str, Any] | None:
    if reference is None:
        return None
    return {
        "event_reference": f"diameter-event:{reference['frame_number']}.{reference['message_occurrence']}",
        "frame_number": reference["frame_number"],
        "message_occurrence": reference["message_occurrence"],
        "direction": reference["direction"],
        "command_code": reference["command_code"],
        "command_name": reference.get("command_name"),
        "application_id": reference["application_id"],
        "hop_by_hop_id": reference["hop_by_hop_id"],
        "end_to_end_id": reference["end_to_end_id"],
        "source_endpoint": _reference_endpoint(reference, "source"),
        "destination_endpoint": _reference_endpoint(reference, "destination"),
    }


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
    return index, transactions


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def _presence(
    avps: list[dict[str, Any]], code: int, name: str, vendor_id: int | None, omitted: int
) -> dict[str, Any]:
    matches = [
        avp for avp in avps
        if avp.get("code") == code and (vendor_id is None or avp.get("vendor_id") == vendor_id)
    ]
    if matches:
        avp = matches[0]
        if avp.get("sensitive"):
            status = "PRESENT_REDACTED"
        elif avp.get("grouping_status") in ("DECODED", "NOT_DECODED", "REDACTED", "DEPTH_LIMITED"):
            status = "PRESENT_STRUCTURE_ONLY"
        else:
            status = "PRESENT"
        return {
            "code": code,
            "name": name,
            "vendor_id": vendor_id,
            "status": status,
            "value_kind": avp.get("value_kind"),
            "sensitive": bool(avp.get("sensitive")),
            "grouping_status": avp.get("grouping_status"),
            "children_omitted": avp.get("children_omitted", 0),
            "value_published": False,
        }
    return {
        "code": code,
        "name": name,
        "vendor_id": vendor_id,
        "status": "NOT_OBSERVED_IN_PUBLISHED_SUBSET" if omitted else "NOT_OBSERVED",
        "value_kind": None,
        "sensitive": False,
        "grouping_status": None,
        "children_omitted": 0,
        "value_published": False,
    }


def _presence_set(
    event: dict[str, Any] | None, definitions: tuple[tuple[int, str, int | None], ...]
) -> list[dict[str, Any]]:
    if event is None:
        return []
    omitted = int(event.get("avps_omitted") or 0)
    return [_presence(event["avps"], code, name, vendor, omitted) for code, name, vendor in definitions]


def classify_result(answer: dict[str, Any] | None) -> dict[str, Any]:
    if answer is None:
        return {
            "namespace_status": "MISSING",
            "application_result": "NOT_APPLICABLE",
            "base_result_code": None,
            "base_result_code_name": None,
            "experimental_result_code": None,
            "experimental_result_code_name": None,
            "experimental_vendor_id": None,
            "limitations": [],
        }
    result = answer.get("result") or {}
    base_code = result.get("result_code")
    experimental_present = bool(result.get("experimental_result_present"))
    experimental_code = result.get("experimental_result_code")
    vendor_id = result.get("experimental_vendor_id")
    base_name = result.get("result_code_name")
    limitations: list[str] = []
    if base_code is not None and experimental_present:
        return {
            "namespace_status": "CONFLICTING",
            "application_result": "UNRESOLVED",
            "base_result_code": base_code,
            "base_result_code_name": base_name,
            "experimental_result_code": experimental_code,
            "experimental_result_code_name": None,
            "experimental_vendor_id": vendor_id,
            "limitations": [
                "both base Result-Code and Experimental-Result are present; the result is unresolved rather than merged"
            ],
        }
    if base_code is not None:
        if base_code in BASE_SUCCESS:
            application_result = "SUCCESS_REPORTED"
        elif isinstance(base_code, int) and base_code >= 3000:
            application_result = "FAILURE_REPORTED"
        else:
            application_result = "UNRESOLVED"
        return {
            "namespace_status": "BASE_RFC6733",
            "application_result": application_result,
            "base_result_code": base_code,
            "base_result_code_name": base_name,
            "experimental_result_code": None,
            "experimental_result_code_name": None,
            "experimental_vendor_id": None,
            "limitations": [] if base_name else ["the base Result-Code has no reviewed name and remains numeric"],
        }
    if experimental_present:
        if vendor_id == THREEGPP_VENDOR_ID and experimental_code in THREEGPP_RESULT_NAMES:
            return {
                "namespace_status": "3GPP_TS_29_272_EXPERIMENTAL",
                "application_result": "FAILURE_REPORTED",
                "base_result_code": None,
                "base_result_code_name": None,
                "experimental_result_code": experimental_code,
                "experimental_result_code_name": THREEGPP_RESULT_NAMES[experimental_code],
                "experimental_vendor_id": vendor_id,
                "limitations": [],
            }
        if vendor_id == THREEGPP_VENDOR_ID:
            limitations.append(
                "the 3GPP Vendor-ID is present but the Experimental-Result-Code is not reviewed; no semantic name is assigned"
            )
            namespace = "3GPP_TS_29_272_EXPERIMENTAL"
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
            "namespace_status": namespace,
            "application_result": "UNRESOLVED",
            "base_result_code": None,
            "base_result_code_name": None,
            "experimental_result_code": experimental_code,
            "experimental_result_code_name": None,
            "experimental_vendor_id": vendor_id,
            "limitations": limitations,
        }
    return {
        "namespace_status": "MISSING",
        "application_result": "UNRESOLVED",
        "base_result_code": None,
        "base_result_code_name": None,
        "experimental_result_code": None,
        "experimental_result_code_name": None,
        "experimental_vendor_id": None,
        "limitations": ["no base Result-Code or Experimental-Result is published"],
    }


def _auth_information(expected_name: str, answer: dict[str, Any] | None) -> str:
    if answer is None:
        return "NOT_APPLICABLE"
    omitted = int(answer.get("avps_omitted") or 0)
    matches = [
        avp for avp in answer["avps"]
        if (avp.get("code"), avp.get("vendor_id")) in {
            (1413, THREEGPP_VENDOR_ID),
            (1414, THREEGPP_VENDOR_ID),
        }
    ]
    if matches:
        if all(avp.get("sensitive") for avp in matches):
            return "PRESENT_REDACTED"
        return "INCOMPLETE"
    if omitted:
        return "NOT_OBSERVED_IN_PUBLISHED_SUBSET"
    return "NOT_OBSERVED"


def _observation_reference(capture: str, event: dict[str, Any], suffix: str = "") -> str:
    base = f"diameter-epc-observation:{capture}:{event['frame_number']}.{event['message_occurrence']}"
    return f"{base}{suffix}"


def _procedure_name(command_code: int, direction: str) -> str | None:
    command = COMMANDS.get(command_code)
    if command is None:
        return None
    return command[1] if direction == "REQUEST" else command[2]


def _observation(
    *,
    capture: str,
    transaction: dict[str, Any],
    request: dict[str, Any] | None,
    answer: dict[str, Any] | None,
    candidates: list[dict[str, Any]],
    message_status: str,
    procedure_family: str | None,
) -> dict[str, Any]:
    anchor = request if request is not None else answer
    command_code = int(transaction["command_code"])
    procedure = _procedure_name(command_code, (request or answer)["direction"])
    result = classify_result(answer)
    effective_result = result["application_result"]
    if message_status == "UNSUPPORTED":
        effective_result = "NOT_APPLICABLE"
    limitations: list[str] = []
    if transaction["correlation_status"] != "MATCHED":
        limitations.append(
            "the Diameter Core transaction is not MATCHED; no application Request/Answer pairing is claimed"
        )
    if message_status == "UNSUPPORTED":
        limitations.append(
            "the command is recognized as S6a/S6d but detailed semantics are outside this capability"
        )
    limitations.extend(result["limitations"])
    if request is not None:
        limitations.extend(request.get("limitations") or [])
    if answer is not None:
        limitations.extend(answer.get("limitations") or [])
    if transaction.get("limitations"):
        limitations.extend(transaction["limitations"])
    observation = {
        "observation_reference": _observation_reference(capture, anchor),
        "procedure": procedure,
        "procedure_family": procedure_family,
        "command_code": command_code,
        "command_name": COMMANDS.get(command_code, (None, "", ""))[0],
        "message_status": message_status,
        "transaction_status": transaction["correlation_status"],
        "application_result": effective_result,
        "authentication_information": (
            _auth_information("authentication", answer)
            if procedure_family == "AUTHENTICATION_INFORMATION" and answer is not None
            else "NOT_APPLICABLE"
        ),
        "request": _reference_projection(request),
        "answer": _reference_projection(answer),
        "response_candidates": [_reference_projection(item) for item in candidates],
        "latency_seconds": transaction.get("latency_seconds") if transaction["correlation_status"] == "MATCHED" else None,
        "transaction_reference": transaction["transaction_reference"],
        "result": (
            {**result, "application_result": effective_result, "limitations": result["limitations"]}
        ),
        "request_avp_presence": _presence_set(
            request,
            AIR_PRESENCE if procedure_family == "AUTHENTICATION_INFORMATION" else ULR_PRESENCE,
        ),
        "answer_avp_presence": _presence_set(
            answer,
            AIA_AUTHENTICATION if procedure_family == "AUTHENTICATION_INFORMATION" else ULA_PRESENCE,
        ),
        "limitations": sorted({item for item in limitations if item}),
        "not_confirmed": _not_confirmed(procedure_family, effective_result),
    }
    return observation


def _not_confirmed(procedure_family: str | None, application_result: str) -> list[str]:
    items = ["the Diameter result does not prove EPS Attach, UE authentication or network access"]
    if procedure_family == "AUTHENTICATION_INFORMATION":
        items.append("usable authentication-vector correctness is not proven")
        if application_result == "SUCCESS_REPORTED":
            items.append("AIA success does not prove that the UE later authenticated successfully")
    if procedure_family == "UPDATE_LOCATION":
        items.append("subscription-profile contents and HSS authorization beyond the Diameter result are not proven")
        items.append("MME or SGSN context installation and registration success are not proven")
    return items


def analyze(
    events: list[dict[str, Any]],
    transaction_document: dict[str, Any],
    *,
    input_provenance: dict[str, Any],
) -> dict[str, Any]:
    index, transactions = validate_core(events, transaction_document)
    capture = events[0]["capture_file"]
    observations: list[dict[str, Any]] = []
    referenced: set[tuple[int, int]] = set()

    for transaction in transactions:
        request = transaction["request"]
        answer = transaction["answer"]
        request_event = _resolve(index, request, "request") if request is not None else None
        answer_event = _resolve(index, answer, "answer") if answer is not None else None
        candidates = [
            _resolve(index, candidate, "ambiguous candidate")
            for candidate in transaction.get("response_candidates") or []
        ]
        for event in (request_event, answer_event):
            if event is not None:
                referenced.add((event["frame_number"], event["message_occurrence"]))
        for candidate in candidates:
            referenced.add((candidate["frame_number"], candidate["message_occurrence"]))
        if transaction["application_id"] != S6A_APPLICATION_ID:
            continue
        command = int(transaction["command_code"])
        if command in SUPPORTED_COMMANDS:
            family = "AUTHENTICATION_INFORMATION" if command == 318 else "UPDATE_LOCATION"
            observations.append(
                _observation(
                    capture=capture,
                    transaction=transaction,
                    request=request_event,
                    answer=answer_event,
                    candidates=candidates,
                    message_status="OBSERVED",
                    procedure_family=family,
                )
            )
        elif command in REVIEWED_UNSUPPORTED_COMMANDS:
            observations.append(
                _observation(
                    capture=capture,
                    transaction=transaction,
                    request=request_event,
                    answer=answer_event,
                    candidates=candidates,
                    message_status="UNSUPPORTED",
                    procedure_family=COMMANDS[command][0].upper().replace("-", "_"),
                )
            )

    for event in events:
        key = (event["frame_number"], event["message_occurrence"])
        if key in referenced or event["application_id"] != S6A_APPLICATION_ID:
            continue
        command = int(event["command_code"])
        if command not in SUPPORTED_COMMANDS and command not in REVIEWED_UNSUPPORTED_COMMANDS:
            continue
        synthetic = {
            "transaction_reference": f"diameter-epc-unresolved:{capture}:{event['frame_number']}.{event['message_occurrence']}",
            "command_code": command,
            "application_id": event["application_id"],
            "correlation_status": "RESPONSE_ONLY" if event["direction"] == "ANSWER" else "OPEN_REQUEST",
            "request": {"frame_number": event["frame_number"], "message_occurrence": event["message_occurrence"], "direction": event["direction"], "command_code": event["command_code"], "application_id": event["application_id"], "hop_by_hop_id": event["hop_by_hop_id"], "end_to_end_id": event["end_to_end_id"], "source_endpoint": "unknown", "destination_endpoint": "unknown"} if event["direction"] == "REQUEST" else None,
            "answer": {"frame_number": event["frame_number"], "message_occurrence": event["message_occurrence"], "direction": event["direction"], "command_code": event["command_code"], "application_id": event["application_id"], "hop_by_hop_id": event["hop_by_hop_id"], "end_to_end_id": event["end_to_end_id"], "source_endpoint": "unknown", "destination_endpoint": "unknown"} if event["direction"] == "ANSWER" else None,
            "response_candidates": [],
            "latency_seconds": None,
            "limitations": ["no accepted Diameter Core transaction references this event; application pairing is unresolved"],
        }
        if event["direction"] == "ANSWER":
            synthetic["response_candidates"] = [synthetic["answer"]]
        observations.append(
            _observation(
                capture=capture,
                transaction=synthetic,
                request=event if event["direction"] == "REQUEST" else None,
                answer=event if event["direction"] == "ANSWER" else None,
                candidates=[],
                message_status="INSUFFICIENT",
                procedure_family=("AUTHENTICATION_INFORMATION" if command == 318 else "UPDATE_LOCATION"),
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
            "supported_commands": ["316 ULR/ULA", "318 AIR/AIA"],
            "recognized_unsupported_commands": [f"{code} {COMMANDS[code][0]}" for code in sorted(REVIEWED_UNSUPPORTED_COMMANDS)],
            "application_id": S6A_APPLICATION_ID,
            "application_name": "S6a/S6d",
            "interface_identity": "UNPROVED",
            "interface_identity_basis": [],
        },
        "input_provenance": input_provenance,
        "command_inventory": inventory,
        "observations": published,
        "completeness": {
            "observation_count": len(published),
            "observations_omitted": omitted,
            "s6a_event_count": sum(1 for event in events if event["application_id"] == S6A_APPLICATION_ID),
            "s6a_transaction_count": sum(1 for transaction in transactions if transaction["application_id"] == S6A_APPLICATION_ID),
            "events_with_avp_omissions": sum(1 for event in events if int(event.get("avps_omitted") or 0) > 0),
            "unresolved_core_transactions": sum(1 for observation in published if observation["message_status"] == "INSUFFICIENT"),
            "truncated_observations": sum(
                1 for observation in published
                if any(
                    avp["status"] == "NOT_OBSERVED_IN_PUBLISHED_SUBSET"
                    for avp in observation["request_avp_presence"] + observation["answer_avp_presence"]
                )
            ),
        },
        "not_confirmed": NOT_CONFIRMED,
        "limitations": LIMITATIONS,
    }


def _inventory(events: list[dict[str, Any]], transactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[int, int, str, str], int] = {}
    transaction_counts: dict[tuple[int, int], int] = {}
    for event in events:
        key = (
            event["application_id"],
            event["command_code"],
            event.get("command_name"),
            event["direction"],
        )
        counts[key] = counts.get(key, 0) + 1
    for transaction in transactions:
        key = (transaction["application_id"], transaction["command_code"])
        transaction_counts[key] = transaction_counts.get(key, 0) + 1
    inventory = []
    for (application_id, command_code, command_name, direction), count in sorted(counts.items(), key=str):
        if application_id == S6A_APPLICATION_ID and command_code in SUPPORTED_COMMANDS:
            scope = "SUPPORTED"
        elif application_id == S6A_APPLICATION_ID and command_code in REVIEWED_UNSUPPORTED_COMMANDS:
            scope = "KNOWN_UNSUPPORTED"
        elif application_id == S6A_APPLICATION_ID:
            scope = "BASE_OR_UNKNOWN"
        elif application_id == 0:
            scope = "BASE_OR_UNKNOWN"
        else:
            scope = "NON_S6A_APPLICATION"
        inventory.append(
            {
                "application_id": application_id,
                "command_code": command_code,
                "command_name": COMMANDS.get(command_code, (command_name or None,))[0] if application_id == S6A_APPLICATION_ID else command_name,
                "direction": direction,
                "event_count": count,
                "transaction_count": transaction_counts.get((application_id, command_code), 0),
                "scope": scope,
            }
        )
    return inventory


def render_timeline(document: dict[str, Any]) -> str:
    lines = [
        "frame     direction  command  core-status    result                 auth-information  latency",
        "--------  ---------  -------  -------------  ---------------------  ----------------  -------",
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
        direction = (request or answer)["direction"]
        command = observation["procedure"] or f"CMD-{observation['command_code']}"
        result = observation["result"]
        if result["base_result_code"] is not None:
            result_text = f"base:{result['base_result_code']}({result['base_result_code_name'] or 'UNNAMED'})"
        elif result["experimental_result_code"] is not None:
            prefix = "3gpp" if result["namespace_status"] == "3GPP_TS_29_272_EXPERIMENTAL" else "exp"
            result_text = f"{prefix}:{result['experimental_result_code']}({result['experimental_result_code_name'] or 'UNREVIEWED'})"
        else:
            result_text = "unresolved"
        lines.append(
            f"{frame:<9} {direction:<10} {command:<8} {observation['transaction_status']:<14} "
            f"{result_text:<22} {observation['authentication_information']:<17} {observation['latency_seconds'] or '-'}"
        )
    return "\n".join(lines) + "\n"