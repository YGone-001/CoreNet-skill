#!/usr/bin/env python3
"""Bounded EPC session-control evidence model over accepted GTPv2-C output.

The model consumes the detailed GTPv2-C events and the protocol-local
transaction correlation produced by the accepted `gtpv2` Protocol Skill. It
never decodes a capture, never reinterprets GTPv2 binary fields, and never
asserts that a PDN connection, a default bearer or user-plane forwarding exists.

Scope rules:

* A transaction observation keeps the correlation status and the protocol Cause
  as two independent facts.
* Message-scope and bearer-scope Cause values are never merged.
* An interface is only published when a reviewed control-plane F-TEID or a
  control-plane TEID continuity establishes it; a transport address never does.
* S11 and S5/S8 transactions are only grouped when control-plane TEID continuity
  and the directed endpoint pair agree. Otherwise they stay separate subjects.
* An accepted Delete Session closes its context generation, so a later reuse of
  the same TEID starts a new generation and is reported as reuse.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.2.0"
ANALYSIS_SCOPE = "epc-session-control"
PROCEDURE = "epc-session-control"
MODEL_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_TRANSACTIONS = 6
EXIT_OUTPUT_FAILURE = 7

INTERFACE_S11 = "S11"
INTERFACE_S5S8 = "S5/S8"
INTERFACE_UNKNOWN = "UNKNOWN_INTERFACE"
INTERFACES = (INTERFACE_S11, INTERFACE_S5S8, INTERFACE_UNKNOWN)

# TS 29.274 F-TEID interface types that identify a control-plane hop.
S11_CONTROL_TYPES = frozenset({10, 11})
S5S8_CONTROL_TYPES = frozenset({6, 7})

INTERFACE_LABELS = {
    INTERFACE_S11: "S11 (MME to SGW-C)",
    INTERFACE_S5S8: "S5/S8 (SGW-C to PGW-C)",
    INTERFACE_UNKNOWN: "unresolved control-plane hop",
}

# Transaction outcome vocabulary. The response-side value is the primary
# classification; REQUEST_OBSERVED is additionally recorded per transaction.
OUTCOME_REQUEST_OBSERVED = "REQUEST_OBSERVED"
OUTCOME_ACCEPTED = "RESPONSE_ACCEPTED_OBSERVED"
OUTCOME_REJECTED = "RESPONSE_REJECTED_OBSERVED"
OUTCOME_UNKNOWN = "RESPONSE_OUTCOME_UNKNOWN"
OUTCOME_OPEN = "OPEN_REQUEST"
OUTCOME_RESPONSE_ONLY = "RESPONSE_ONLY"
OUTCOME_AMBIGUOUS = "AMBIGUOUS_TRANSACTION"

OUTCOMES = (
    OUTCOME_ACCEPTED,
    OUTCOME_REJECTED,
    OUTCOME_UNKNOWN,
    OUTCOME_OPEN,
    OUTCOME_RESPONSE_ONLY,
    OUTCOME_AMBIGUOUS,
)

# TS 29.274 causes that accept a request. 17 is partial acceptance and is kept
# distinguishable from full acceptance.
CAUSE_ACCEPTED = 16
CAUSE_ACCEPTED_PARTIALLY = 17
ACCEPTING_CAUSES = frozenset({CAUSE_ACCEPTED, CAUSE_ACCEPTED_PARTIALLY})

FAMILY_LABELS = {
    "create-session": "Create Session",
    "modify-bearer": "Modify Bearer",
    "delete-session": "Delete Session",
    "release-access-bearers": "Release Access Bearers",
    "echo": "Echo",
}
FAMILY_ORDER = (
    "create-session",
    "modify-bearer",
    "delete-session",
    "release-access-bearers",
    "echo",
)

DEVIATION_CREATE_REJECTED = "CREATE_SESSION_REJECTED_OBSERVED"
DEVIATION_MODIFY_REJECTED = "MODIFY_BEARER_REJECTED_OBSERVED"
DEVIATION_DELETE_REJECTED = "DELETE_SESSION_REJECTED_OBSERVED"
DEVIATION_BEARER_REJECTED = "BEARER_CONTEXT_REJECTED_OBSERVED"
DEVIATION_OPEN_REQUEST = "OPEN_REQUEST_OBSERVED"
DEVIATION_RESPONSE_ONLY = "RESPONSE_ONLY_OBSERVED"
DEVIATION_AMBIGUOUS = "AMBIGUOUS_TRANSACTION_OBSERVED"
DEVIATION_INTERFACE_UNRESOLVED = "INTERFACE_EVIDENCE_UNAVAILABLE"
DEVIATION_INTERFACE_CONFLICT = "INTERFACE_EVIDENCE_CONFLICT"
DEVIATION_CONTEXT_REUSE = "CONTEXT_REUSE_AFTER_DELETION"
DEVIATION_BEARER_UNBOUND = "BEARER_CONTEXT_BINDING_UNAVAILABLE"

ASSOCIATION_STRENGTHS = ("STRONG", "SUPPORTED", "AMBIGUOUS", "UNBOUND")

CROSS_INTERFACE_NOT_ESTABLISHED = "NOT_ESTABLISHED"
ATTACH_ASSOCIATION_NOT_ESTABLISHED = "NOT_ESTABLISHED"

NOT_CONFIRMED = (
    "PDN connection establishment",
    "default EPS bearer service availability",
    "user-plane packet forwarding",
    "S11 to S5/S8 session association",
    "EPS Attach UE to GTPv2-C session association",
    "session or bearer deletion completeness",
    "end-to-end EPC service success",
)

GLOBAL_BOUNDARY_NOTE = (
    "This Domain analysis produces procedure-local session-control evidence only. "
    "EPC global first-abnormal-boundary selection remains NOT_EVALUATED."
)

MAX_TRANSACTIONS = 64
MAX_SUBJECTS = 32
MAX_EVIDENCE_REFERENCES = 10
MAX_LIST_ITEMS = 20


class InputError(ValueError):
    """Raised when an accepted input artifact cannot be normalized."""


def safe_name(path: Path) -> str:
    return path.name


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name} line {number}: {exc.msg}") from exc
            if not isinstance(record, dict):
                raise InputError(f"{path.name} line {number}: record is not an object")
            records.append(record)
    return records


def _require(record: dict[str, Any], field: str, source: str) -> Any:
    if field not in record:
        raise InputError(f"{source} lacks the required field '{field}'")
    return record[field]


def load_inputs(
    events_path: Path, transactions_path: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not events_path.is_file():
        raise InputError(f"GTPv2-C event input does not exist: {events_path}")
    if not transactions_path.is_file():
        raise InputError(f"transaction input does not exist: {transactions_path}")
    events = read_jsonl(events_path)
    try:
        document = json.loads(transactions_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{transactions_path.name}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise InputError(f"{transactions_path.name}: transaction document is not an object")
    return events, document


def validate_events(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    validated: list[dict[str, Any]] = []
    for event in events:
        if event.get("protocol") != "GTPv2-C":
            raise InputError("GTPv2-C event input contains a record from another protocol")
        _require(event, "frame_number", "GTPv2-C event")
        _require(event, "message_type_code", "GTPv2-C event")
        header = _require(event, "header", "GTPv2-C event")
        if not isinstance(header, dict) or "teid_state" not in header:
            raise InputError("GTPv2-C event header lacks 'teid_state'")
        validated.append(event)
    return validated


def validate_transactions(document: dict[str, Any]) -> list[dict[str, Any]]:
    if document.get("protocol") != "GTPv2-C":
        raise InputError("transaction document is not a GTPv2-C correlation result")
    transactions = document.get("transactions")
    if not isinstance(transactions, list):
        raise InputError("transaction document lacks a 'transactions' list")
    for transaction in transactions:
        if not isinstance(transaction, dict):
            raise InputError("transaction record is not an object")
        _require(transaction, "correlation_status", "transaction record")
        _require(transaction, "transaction_reference", "transaction record")
    return transactions


# ---------------------------------------------------------------------------
# Interface evidence
# ---------------------------------------------------------------------------


def _control_family(interface_type: Any) -> str | None:
    if not isinstance(interface_type, int) or isinstance(interface_type, bool):
        return None
    if interface_type in S11_CONTROL_TYPES:
        return INTERFACE_S11
    if interface_type in S5S8_CONTROL_TYPES:
        return INTERFACE_S5S8
    return None


def _message_scope_fteids(event: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(event, dict):
        return []
    return [
        item
        for item in event.get("f_teids") or []
        if isinstance(item, dict) and item.get("scope") == "message"
    ]


def _teid_of(item: dict[str, Any]) -> int | None:
    value = item.get("teid")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def _header_teid(event: dict[str, Any] | None) -> int | None:
    if not isinstance(event, dict):
        return None
    header = event.get("header") or {}
    if header.get("teid_state") != "PRESENT":
        return None
    value = header.get("teid")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


def teid_hex(value: int) -> str:
    return f"0x{value:08x}"


def interface_evidence(
    request: dict[str, Any] | None,
    response: dict[str, Any] | None,
    teid_index: dict[int, set[str]],
) -> dict[str, Any]:
    """Resolve the control-plane hop from reviewed evidence only.

    Order of proof: a non-zero control-plane F-TEID in the request, then the
    same in the response, then control-plane TEID continuity with an earlier
    transaction. A transport address or port is never used.
    """
    for event, label in ((request, "request"), (response, "response")):
        families: dict[str, list[int]] = {}
        for item in _message_scope_fteids(event):
            family = _control_family(item.get("interface_type"))
            teid = _teid_of(item)
            if family is None or teid is None:
                continue
            families.setdefault(family, []).append(item.get("interface_type"))
        if len(families) == 1:
            family = next(iter(families))
            return {
                "interface": family,
                "basis": "control_plane_f_teid_in_message",
                "evidence_message": label,
                "supporting_interface_types": sorted(set(families[family])),
                "supporting_frames": [event.get("frame_number")] if event else [],
            }
        if len(families) > 1:
            return {
                "interface": INTERFACE_UNKNOWN,
                "basis": "conflicting_control_plane_f_teids",
                "evidence_message": label,
                "supporting_interface_types": sorted(
                    {value for values in families.values() for value in values}
                ),
                "supporting_frames": [event.get("frame_number")] if event else [],
            }

    for event, label in ((request, "request"), (response, "response")):
        teid = _header_teid(event)
        if teid is None:
            continue
        families = teid_index.get(teid) or set()
        if len(families) == 1:
            return {
                "interface": next(iter(families)),
                "basis": "control_plane_teid_continuity",
                "evidence_message": label,
                "supporting_interface_types": [],
                "supporting_frames": [event.get("frame_number")],
                "continuity_teid": teid_hex(teid),
            }
        if len(families) > 1:
            return {
                "interface": INTERFACE_UNKNOWN,
                "basis": "conflicting_control_plane_teid_continuity",
                "evidence_message": label,
                "supporting_interface_types": [],
                "supporting_frames": [event.get("frame_number")],
                "continuity_teid": teid_hex(teid),
            }

    return {
        "interface": INTERFACE_UNKNOWN,
        "basis": "unavailable",
        "evidence_message": None,
        "supporting_interface_types": [],
        "supporting_frames": [],
    }


def index_control_teids(teid_index: dict[int, set[str]], *events: dict[str, Any] | None) -> None:
    for event in events:
        for item in _message_scope_fteids(event):
            family = _control_family(item.get("interface_type"))
            teid = _teid_of(item)
            if family is None or teid is None:
                continue
            teid_index.setdefault(teid, set()).add(family)


def context_tokens(
    request: dict[str, Any] | None,
    response: dict[str, Any] | None,
    interface: str,
) -> set[int]:
    """Control-plane TEIDs that belong to this hop, used for safe grouping."""
    if interface == INTERFACE_UNKNOWN:
        return set()
    tokens: set[int] = set()
    header = _header_teid(request)
    if header is not None:
        tokens.add(header)
    for event in (request, response):
        for item in _message_scope_fteids(event):
            if _control_family(item.get("interface_type")) != interface:
                continue
            teid = _teid_of(item)
            if teid is not None:
                tokens.add(teid)
    return tokens


# ---------------------------------------------------------------------------
# Transaction observation
# ---------------------------------------------------------------------------


def outcome_of(transaction: dict[str, Any], response: dict[str, Any] | None) -> str:
    status = transaction.get("correlation_status")
    if status == "OPEN_REQUEST":
        return OUTCOME_OPEN
    if status == "RESPONSE_ONLY":
        return OUTCOME_RESPONSE_ONLY
    if status == "AMBIGUOUS":
        return OUTCOME_AMBIGUOUS
    if status != "MATCHED" or response is None:
        return OUTCOME_UNKNOWN
    cause = response.get("message_cause")
    if not isinstance(cause, dict):
        return OUTCOME_UNKNOWN
    code = cause.get("cause_code")
    if not isinstance(code, int) or isinstance(code, bool):
        return OUTCOME_UNKNOWN
    return OUTCOME_ACCEPTED if code in ACCEPTING_CAUSES else OUTCOME_REJECTED


def _reference(event: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(event, dict):
        return None
    return {
        "frame_number": event.get("frame_number"),
        "protocol": "GTPv2-C",
        "message_type": event.get("message_type"),
        "message_type_code": event.get("message_type_code"),
        "evidence_level": (event.get("evidence") or {}).get("level"),
    }


def _window(events: list[dict[str, Any]]) -> dict[str, int] | None:
    frames = [
        event.get("frame_number")
        for event in events
        if isinstance(event.get("frame_number"), int) and not isinstance(event.get("frame_number"), bool)
    ]
    if not frames:
        return None
    return {"start_frame": min(frames), "end_frame": max(frames)}


def bearer_contexts_of(event: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Item-scoped bearer evidence, kept separate from message scope."""
    if not isinstance(event, dict):
        return []
    contexts: list[dict[str, Any]] = []
    for context in event.get("bearer_contexts") or []:
        if not isinstance(context, dict):
            continue
        cause = context.get("cause") if isinstance(context.get("cause"), dict) else None
        contexts.append(
            {
                "item_index": context.get("item_index"),
                "ebi": context.get("ebi"),
                "cause": (
                    {
                        "cause_code": cause.get("cause_code"),
                        "cause_name": cause.get("cause_name"),
                        "scope": "bearer",
                    }
                    if cause
                    else None
                ),
                "f_teids": [
                    {
                        "scope": "bearer",
                        "interface_type": item.get("interface_type"),
                        "interface_type_name": item.get("interface_type_name"),
                        "teid": item.get("teid"),
                    }
                    for item in context.get("f_teids") or []
                    if isinstance(item, dict)
                ],
                "charging_id_present": context.get("charging_id_present"),
                "binding_basis": context.get("binding_basis"),
                "scope": "bearer",
            }
        )
    return contexts


def transaction_observation(
    transaction: dict[str, Any],
    events_by_frame: dict[int, dict[str, Any]],
    teid_index: dict[int, set[str]],
) -> dict[str, Any]:
    request_ref = transaction.get("request") or None
    response_ref = transaction.get("response") or None
    request = events_by_frame.get((request_ref or {}).get("frame_number")) if request_ref else None
    response = events_by_frame.get((response_ref or {}).get("frame_number")) if response_ref else None

    evidence = interface_evidence(request, response, teid_index)
    interface = evidence["interface"]
    outcome = outcome_of(transaction, response)
    tokens = context_tokens(request, response, interface)
    index_control_teids(teid_index, request, response)

    message_cause = response.get("message_cause") if isinstance(response, dict) else None
    bearer_contexts = bearer_contexts_of(response) or bearer_contexts_of(request)

    limitations: list[str] = []
    if interface == INTERFACE_UNKNOWN:
        limitations.append(
            "no reviewed control-plane F-TEID or TEID continuity establishes the hop; "
            "a transport address alone does not identify an interface"
        )
    if outcome == OUTCOME_OPEN:
        limitations.append(
            "the request has no observed response inside this capture; this is not a proven timeout"
        )
    elif outcome == OUTCOME_AMBIGUOUS:
        limitations.append(
            "several responses satisfy the correlation keys; no response is selected for this transaction"
        )
    if outcome == OUTCOME_RESPONSE_ONLY:
        limitations.append("the request was not captured, so no pairing is asserted")
    if bearer_contexts and all(item.get("binding_basis") != "pdml_grouped_ie" for item in bearer_contexts):
        limitations.append(
            "bearer context binding is unavailable in this input, so no item-scoped bearer claim is made"
        )

    observation: dict[str, Any] = {
        "transaction_reference": transaction.get("transaction_reference"),
        "procedure_family": transaction.get("procedure_family"),
        "procedure_label": FAMILY_LABELS.get(transaction.get("procedure_family") or "", None),
        "correlation_status": transaction.get("correlation_status"),
        "correlation_strength": transaction.get("correlation_strength"),
        "outcome": outcome,
        "observations": [OUTCOME_REQUEST_OBSERVED] if request is not None else [],
        "request": _reference(request),
        "response": _reference(response),
        "interface_evidence": evidence,
        "message_cause": (
            {
                "cause_code": message_cause.get("cause_code"),
                "cause_name": message_cause.get("cause_name"),
                "scope": "message",
            }
            if isinstance(message_cause, dict)
            else None
        ),
        "bearer_contexts": bearer_contexts,
        "f_teids": [
            {
                "scope": "message",
                "interface_type": item.get("interface_type"),
                "interface_type_name": item.get("interface_type_name"),
                "teid": item.get("teid"),
            }
            for item in _message_scope_fteids(response) or _message_scope_fteids(request)
        ],
        "evidence_refs": [
            reference for reference in (_reference(request), _reference(response)) if reference is not None
        ],
        "observation_window": _window([event for event in (request, response) if event is not None]),
        "limitations": limitations,
        "_tokens": sorted(tokens),
        "_endpoints": {
            "request_source": (request or {}).get("source"),
            "request_destination": (request or {}).get("destination"),
        },
    }
    if outcome == OUTCOME_ACCEPTED and message_cause is not None:
        observation["observations"].append(OUTCOME_ACCEPTED)
    elif outcome == OUTCOME_REJECTED:
        observation["observations"].append(OUTCOME_REJECTED)
    return observation


# ---------------------------------------------------------------------------
# Subject construction
# ---------------------------------------------------------------------------


def _endpoint_key(event: dict[str, Any] | None, role: str) -> str:
    endpoint = (event or {}).get(role) or {}
    return f"{endpoint.get('address')}:{endpoint.get('port')}"


def _endpoint_text(endpoint: Any) -> str:
    if not isinstance(endpoint, dict):
        return "unknown"
    return f"{endpoint.get('address')}:{endpoint.get('port')}"


def subject_reference(capture: str, interface: str, tokens: set[int], first_frame: int) -> str:
    slug = {
        INTERFACE_S11: "s11",
        INTERFACE_S5S8: "s5s8",
        INTERFACE_UNKNOWN: "unknown",
    }[interface]
    seed = "|".join(
        [capture, interface, ",".join(teid_hex(token) for token in sorted(tokens)), str(first_frame)]
    )
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8]
    return f"epc-session-{slug}-{digest}"


def build_subjects(observations: list[dict[str, Any]], capture: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Group transaction observations into safe session-control subjects.

    Grouping requires the same resolved interface, the same directed request
    endpoint pair and at least one shared control-plane TEID. Transactions whose
    hop is unresolved never join another subject.
    """
    subjects: list[dict[str, Any]] = []
    deviations: list[dict[str, Any]] = []
    active: dict[tuple[str, str, int], int] = {}
    closed: dict[tuple[str, int], str] = {}

    for observation in observations:
        interface = observation["interface_evidence"]["interface"]
        tokens = set(observation.get("_tokens") or [])
        endpoints = observation.get("_endpoints") or {}
        request = observation.get("request") or {}
        frame = request.get("frame_number") or (observation.get("response") or {}).get("frame_number") or 0
        pair = (
            f"{_endpoint_text(endpoints.get('request_source'))}"
            f"->{_endpoint_text(endpoints.get('request_destination'))}"
        )

        index = None
        if interface != INTERFACE_UNKNOWN:
            for token in sorted(tokens):
                candidate = active.get((interface, pair, token))
                if candidate is not None:
                    index = candidate
                    break

        reused = None
        if interface != INTERFACE_UNKNOWN and index is None:
            for token in sorted(tokens):
                if (interface, token) in closed:
                    reused = closed[(interface, token)]
                    break

        if index is None:
            subject = {
                "subject_reference": subject_reference(capture, interface, tokens, frame),
                "subject_type": "EPC_SESSION_CONTROL",
                "interface": interface,
                "interface_label": INTERFACE_LABELS[interface],
                "interface_evidence": observation["interface_evidence"],
                "capture_file": capture,
                "endpoint_pair": pair,
                "tokens": set(),
                "transactions": [],
                "first_frame": frame,
                "last_frame": frame,
                "limitations": [],
                "association_strength": "UNBOUND",
            }
            subjects.append(subject)
            index = len(subjects) - 1

        subject = subjects[index]
        subject["transactions"].append(observation)
        subject["tokens"].update(tokens)
        window = observation.get("observation_window") or {}
        last_seen = window.get("end_frame") or frame
        subject["last_frame"] = max(subject["last_frame"], last_seen)
        if interface != INTERFACE_UNKNOWN:
            for token in tokens:
                active[(interface, pair, token)] = index

        if reused is not None:
            deviations.append(
                {
                    "deviation_type": DEVIATION_CONTEXT_REUSE,
                    "transaction_reference": observation.get("transaction_reference"),
                    "procedure_family": observation.get("procedure_family"),
                    "frame_number": frame,
                    "protocol": "GTPv2-C",
                    "message_type": (observation.get("request") or {}).get("message_type"),
                    "explanation": (
                        "a control-plane TEID previously closed by an accepted Delete Session is "
                        "observed again; the new generation is kept separate and the reuse is explicit"
                    ),
                    "evidence_refs": observation.get("evidence_refs") or [],
                    "observation_window": observation.get("observation_window"),
                    "limitations": ["identifier reuse prevents a safe link to the closed generation"],
                    "prior_subject_reference": reused,
                }
            )

        if observation.get("procedure_family") == "delete-session" and observation.get("outcome") == OUTCOME_ACCEPTED:
            for token in tokens:
                active.pop((interface, pair, token), None)
                closed[(interface, token)] = subject["subject_reference"]

    for subject in subjects:
        # A single transaction asserts no grouping; several transactions share a
        # control-plane TEID by construction, which is the strong case.
        subject["association_strength"] = (
            "STRONG" if len(subject["transactions"]) > 1 else "UNBOUND"
        )
        subject["tokens"] = sorted(teid_hex(token) for token in subject["tokens"])
    return subjects, deviations


def _subject_families(transactions: list[dict[str, Any]]) -> list[str]:
    present = {item.get("procedure_family") for item in transactions if item.get("procedure_family")}
    ordered = [family for family in FAMILY_ORDER if family in present]
    ordered.extend(sorted(present - set(FAMILY_ORDER)))
    return ordered


def _primary_transaction(transactions: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not transactions:
        return None
    first = transactions[0]
    return {
        "transaction_reference": first.get("transaction_reference"),
        "procedure_family": first.get("procedure_family"),
        "outcome": first.get("outcome"),
        "request_frame": (first.get("request") or {}).get("frame_number"),
        "response_frame": (first.get("response") or {}).get("frame_number"),
        "message_cause": first.get("message_cause"),
    }


def _procedure_observations(subject: dict[str, Any]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for observation in subject["transactions"]:
        family = observation.get("procedure_family") or "unknown"
        grouped.setdefault(family, []).append(observation)
    payload: dict[str, Any] = {}
    for family in FAMILY_ORDER + tuple(sorted(set(grouped) - set(FAMILY_ORDER))):
        items = grouped.get(family)
        if not items:
            continue
        payload[family] = {
            "procedure_label": FAMILY_LABELS.get(family, family),
            "transaction_count": len(items),
            "outcomes": [item["outcome"] for item in items],
            "transactions": items[:MAX_LIST_ITEMS],
            "transactions_omitted": max(0, len(items) - MAX_LIST_ITEMS),
        }
    return payload


def _anchor_of(observation: dict[str, Any]) -> tuple[int | None, str | None]:
    """Anchor a deviation at the frame that defines the observed outcome.

    A response-defined outcome is anchored at the response frame, because that
    frame is where the negative result became visible. An open or ambiguous
    transaction has no single observed response, so the request frame is used as
    the observation anchor only; it never stands for a negative network outcome.
    """
    request = observation.get("request") or {}
    response = observation.get("response") or {}
    outcome = observation.get("outcome")
    if response and outcome not in (OUTCOME_OPEN, OUTCOME_AMBIGUOUS):
        return response.get("frame_number"), response.get("message_type")
    if request:
        return request.get("frame_number"), request.get("message_type")
    return response.get("frame_number"), response.get("message_type")


def _deviations_for_observation(observation: dict[str, Any]) -> list[dict[str, Any]]:
    family = observation.get("procedure_family")
    outcome = observation.get("outcome")
    frame, message_type = _anchor_of(observation)
    evidence_refs = observation.get("evidence_refs") or []
    window = observation.get("observation_window")
    limitations = list(observation.get("limitations") or [])
    deviations: list[dict[str, Any]] = []

    def add(
        deviation_type: str,
        explanation: str,
        *,
        cause_code: int | None = None,
        cause_scope: str | None = None,
        bearer_item_index: int | None = None,
    ) -> None:
        entry: dict[str, Any] = {
            "deviation_type": deviation_type,
            "transaction_reference": observation.get("transaction_reference"),
            "procedure_family": family,
            "frame_number": frame,
            "protocol": "GTPv2-C",
            "message_type": message_type,
            "evidence_level": "OBSERVED",
            "explanation": explanation,
            "evidence_refs": evidence_refs,
            "observation_window": window,
            "limitations": limitations,
        }
        if cause_code is not None:
            entry["cause_code"] = cause_code
            entry["cause_scope"] = cause_scope
        if bearer_item_index is not None:
            entry["bearer_item_index"] = bearer_item_index
        deviations.append(entry)

    if outcome == OUTCOME_REJECTED:
        mapping = {
            "create-session": DEVIATION_CREATE_REJECTED,
            "modify-bearer": DEVIATION_MODIFY_REJECTED,
            "delete-session": DEVIATION_DELETE_REJECTED,
        }
        cause = (observation.get("message_cause") or {}).get("cause_code")
        add(
            mapping.get(family, DEVIATION_CREATE_REJECTED),
            f"the observed {FAMILY_LABELS.get(family, family)} response carries an explicit "
            f"non-accepting Cause {cause}",
            cause_code=cause if isinstance(cause, int) else None,
            cause_scope="message",
        )
    elif outcome == OUTCOME_OPEN:
        add(DEVIATION_OPEN_REQUEST, "the request has no observed response inside this capture")
    elif outcome == OUTCOME_RESPONSE_ONLY:
        add(DEVIATION_RESPONSE_ONLY, "the response was observed without its request in this capture")
    elif outcome == OUTCOME_AMBIGUOUS:
        add(DEVIATION_AMBIGUOUS, "several responses satisfy the correlation keys and none is selected")

    for context in observation.get("bearer_contexts") or []:
        cause = context.get("cause") or {}
        code = cause.get("cause_code")
        if isinstance(code, int) and not isinstance(code, bool) and code not in ACCEPTING_CAUSES:
            item_index = context.get("item_index")
            add(
                DEVIATION_BEARER_REJECTED,
                f"bearer item {item_index} (EBI {context.get('ebi')}) carries a "
                f"non-accepting Cause {code}",
                cause_code=code,
                cause_scope="bearer",
                bearer_item_index=item_index if isinstance(item_index, int) else None,
            )

    if observation["interface_evidence"]["interface"] == INTERFACE_UNKNOWN:
        basis = observation["interface_evidence"]["basis"]
        add(
            DEVIATION_INTERFACE_CONFLICT if "conflicting" in basis else DEVIATION_INTERFACE_UNRESOLVED,
            "the control-plane hop of this transaction is not established by reviewed evidence",
        )
    return deviations


def _unbound_evidence(observation: dict[str, Any]) -> list[dict[str, Any]]:
    unbound: list[dict[str, Any]] = []
    for context in observation.get("bearer_contexts") or []:
        if context.get("binding_basis") != "pdml_grouped_ie":
            unbound.append(
                {
                    "transaction_reference": observation.get("transaction_reference"),
                    "kind": DEVIATION_BEARER_UNBOUND,
                    "frame_number": (observation.get("response") or {}).get("frame_number"),
                    "limitations": ["item-scoped bearer binding is unavailable in this input"],
                }
            )
    return unbound


def analyze(
    events: list[dict[str, Any]],
    document: dict[str, Any],
    events_name: str,
    transactions_name: str,
) -> dict[str, Any]:
    """Build the bounded EPC session-control analysis."""
    validated_events = validate_events(events)
    transactions = validate_transactions(document)
    events_by_frame = {
        event["frame_number"]: event
        for event in validated_events
        if isinstance(event.get("frame_number"), int)
    }
    ordered = sorted(
        transactions,
        key=lambda item: (
            ((item.get("request") or {}).get("frame_number")
             or (item.get("response") or {}).get("frame_number")
             or 0),
            str(item.get("transaction_reference")),
        ),
    )

    teid_index: dict[int, set[str]] = {}
    observations: list[dict[str, Any]] = []
    for transaction in ordered:
        observations.append(transaction_observation(transaction, events_by_frame, teid_index))

    capture_files = sorted(
        {
            str(event.get("capture_file"))
            for event in validated_events
            if event.get("capture_file")
        }
    )
    capture = capture_files[0] if len(capture_files) == 1 else (capture_files[0] if capture_files else events_name)

    subjects, reuse_deviations = build_subjects(observations, capture)

    deviations_by_transaction: dict[str, list[dict[str, Any]]] = {}
    deviations: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    for observation in observations:
        transaction_deviations = _deviations_for_observation(observation)
        deviations_by_transaction[str(observation.get("transaction_reference"))] = transaction_deviations
        deviations.extend(transaction_deviations)
        unbound.extend(_unbound_evidence(observation))
        if observation.get("outcome") == OUTCOME_AMBIGUOUS:
            ambiguous.append(
                {
                    "transaction_reference": observation.get("transaction_reference"),
                    "kind": DEVIATION_AMBIGUOUS,
                    "frame_number": (observation.get("request") or {}).get("frame_number"),
                    "limitations": ["no response is selected for this transaction"],
                }
            )
    deviations.extend(reuse_deviations)

    public_observations = []
    for observation in observations:
        public = {key: value for key, value in observation.items() if not key.startswith("_")}
        public_observations.append(public)

    subject_payloads = []
    for subject in subjects[:MAX_SUBJECTS]:
        transaction_public = [
            {key: value for key, value in item.items() if not key.startswith("_")}
            for item in subject["transactions"]
        ]
        references = [item["transaction_reference"] for item in transaction_public]
        evidence_refs: list[dict[str, Any]] = []
        for item in transaction_public:
            for reference in item.get("evidence_refs") or []:
                if reference not in evidence_refs:
                    evidence_refs.append(reference)
        limitations = sorted({text for item in transaction_public for text in item.get("limitations") or []})
        subject_deviations: list[dict[str, Any]] = []
        for item in transaction_public:
            subject_deviations.extend(
                deviations_by_transaction.get(str(item.get("transaction_reference"))) or []
            )
        subject_payloads.append(
            {
                "subject_reference": subject["subject_reference"],
                "subject_type": subject["subject_type"],
                "interface": subject["interface"],
                "interface_label": subject["interface_label"],
                "interface_evidence": subject["interface_evidence"],
                "capture_file": subject["capture_file"],
                "endpoint_pair": subject["endpoint_pair"],
                "control_plane_teids": subject["tokens"],
                "association_strength": subject["association_strength"],
                "cross_interface_association": CROSS_INTERFACE_NOT_ESTABLISHED,
                "attach_association": ATTACH_ASSOCIATION_NOT_ESTABLISHED,
                "transaction_references": references,
                "procedure_local_deviations": subject_deviations[:MAX_LIST_ITEMS],
                "procedure_local_deviation_count": len(subject_deviations),
                "procedure_local_deviations_omitted": max(
                    0, len(subject_deviations) - MAX_LIST_ITEMS
                ),
                "procedure_families": _subject_families(transaction_public),
                "primary_transaction": _primary_transaction(transaction_public),
                "procedure_observations": _procedure_observations(subject),
                "bearer_contexts": [
                    {**context, "transaction_reference": item.get("transaction_reference")}
                    for item in transaction_public
                    for context in item.get("bearer_contexts") or []
                ][:MAX_LIST_ITEMS],
                "f_teid_evidence": [
                    {**fteid, "transaction_reference": item.get("transaction_reference")}
                    for item in transaction_public
                    for fteid in item.get("f_teids") or []
                ][:MAX_LIST_ITEMS],
                "evidence_refs": evidence_refs[:MAX_EVIDENCE_REFERENCES],
                "evidence_refs_omitted": max(0, len(evidence_refs) - MAX_EVIDENCE_REFERENCES),
                "observation_window": {
                    "start_frame": subject["first_frame"],
                    "end_frame": subject["last_frame"],
                },
                "limitations": limitations[:MAX_LIST_ITEMS],
            }
        )

    families = sorted(
        {
            observation.get("procedure_family")
            for observation in public_observations
            if observation.get("procedure_family")
        }
    )
    limitations: list[str] = []
    if any(item["interface"] == INTERFACE_UNKNOWN for item in subject_payloads):
        limitations.append(
            "at least one session-control subject has an unresolved control-plane hop; its interface "
            "is reported as UNKNOWN_INTERFACE rather than inferred from a transport address"
        )
    if any(item["interface"] == INTERFACE_S11 for item in subject_payloads) and any(
        item["interface"] == INTERFACE_S5S8 for item in subject_payloads
    ):
        limitations.append(
            "S11 and S5/S8 transactions are reported as independent subjects; no reviewed identity "
            "bridge links a specific S11 transaction to a specific S5/S8 transaction"
        )
    if not any(event.get("bearer_contexts") for event in validated_events):
        limitations.append("no grouped Bearer Context IE was observed in the accepted events")
    limitations.append(GLOBAL_BOUNDARY_NOTE)

    additional: list[str] = []
    if any(item["interface"] == INTERFACE_UNKNOWN for item in subject_payloads):
        additional.append(
            "a control-plane F-TEID or TEID continuity observation for the unresolved hop"
        )
    additional.append(
        "a reviewed S1AP/GTPv2 identity bridge before any Attach-to-session association is attempted"
    )
    additional.append(
        "an independently justified SGW-C identity observation before any S11-to-S5/S8 association"
    )

    return {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_scope": ANALYSIS_SCOPE,
        "procedure": PROCEDURE,
        "procedure_label": "EPC Session Control",
        "model_version": MODEL_VERSION,
        "input_provenance": {
            "gtpv2_events_file": events_name,
            "gtpv2_event_count": len(validated_events),
            "transactions_file": transactions_name,
            "transaction_count": len(transactions),
            "capture_files": capture_files,
            "hierarchy_basis": sorted(
                {str(event.get("hierarchy_basis")) for event in validated_events if event.get("hierarchy_basis")}
            ),
            "protocol_skill": "gtpv2",
            "protocol_skill_version": "0.1.0",
        },
        "control_plane_subject_count": len(subject_payloads),
        "control_plane_subjects": subject_payloads,
        "transaction_observations": public_observations[:MAX_TRANSACTIONS],
        "transaction_observations_omitted": max(0, len(public_observations) - MAX_TRANSACTIONS),
        "bearer_context_observations": [
            {
                "transaction_reference": observation.get("transaction_reference"),
                "frame_number": (observation.get("response") or {}).get("frame_number"),
                "bearer_contexts": observation.get("bearer_contexts") or [],
            }
            for observation in public_observations
            if observation.get("bearer_contexts")
        ][:MAX_TRANSACTIONS],
        "procedure_local_deviations": deviations[:MAX_LIST_ITEMS],
        "procedure_local_deviation_count": len(deviations),
        "procedure_local_deviations_omitted": max(0, len(deviations) - MAX_LIST_ITEMS),
        "unbound_evidence": unbound[:MAX_LIST_ITEMS],
        "ambiguous_evidence": ambiguous[:MAX_LIST_ITEMS],
        "procedure_families": families,
        "evidence_limitations": limitations,
        "additional_evidence_needed": additional,
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_EVALUATED",
        "first_abnormal_boundary": None,
    }


def procedure_rows(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten subject procedure observations into a stable timeline."""
    rows: list[dict[str, Any]] = []
    for subject in analysis.get("control_plane_subjects") or []:
        for family, payload in (subject.get("procedure_observations") or {}).items():
            for transaction in payload.get("transactions") or []:
                window = transaction.get("observation_window") or {}
                rows.append(
                    {
                        "subject_reference": subject["subject_reference"],
                        "interface": subject["interface"],
                        "procedure_family": family,
                        "outcome": transaction.get("outcome"),
                        "transaction_reference": transaction.get("transaction_reference"),
                        "request_frame": (transaction.get("request") or {}).get("frame_number"),
                        "response_frame": (transaction.get("response") or {}).get("frame_number"),
                        "message_cause": (transaction.get("message_cause") or {}).get("cause_code"),
                        "start_frame": window.get("start_frame"),
                        "end_frame": window.get("end_frame"),
                    }
                )
    rows.sort(key=lambda row: (row.get("start_frame") or 0, row["subject_reference"], row["procedure_family"]))
    return rows
