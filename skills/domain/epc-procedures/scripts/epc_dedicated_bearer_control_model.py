"""Bounded EPC dedicated-bearer control-plane outcome evidence producer.

Consumes the accepted GTPv2-C detailed events and transaction artifact. It never
reconstructs request/response correlation, never establishes a dedicated-bearer
lifecycle and never promotes an observed control outcome into bearer activation,
resource admission, TFT installation or user-plane delivery.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

DOMAIN = "epc-procedures"
ANALYSIS_NAME = "epc-dedicated-bearer-control"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_SUBJECTS = 6
EXIT_OUTPUT_FAILURE = 7

FAMILY_CREATE = "create-bearer"
FAMILY_UPDATE = "update-bearer"
FAMILY_DELETE = "delete-bearer"
CONTROL_FAMILIES = (FAMILY_CREATE, FAMILY_UPDATE, FAMILY_DELETE)
CONTROL_MESSAGE_CODES = (95, 96, 97, 98, 99, 100)
EXPECTED_REQUEST_CODE = {
    FAMILY_CREATE: 95,
    FAMILY_UPDATE: 97,
    FAMILY_DELETE: 99,
}
EXPECTED_RESPONSE_CODE = {
    FAMILY_CREATE: 96,
    FAMILY_UPDATE: 98,
    FAMILY_DELETE: 100,
}

CORRELATION_MATCHED = "MATCHED"
CORRELATION_OPEN = "OPEN_REQUEST"
CORRELATION_RESPONSE_ONLY = "RESPONSE_ONLY"
CORRELATION_AMBIGUOUS = "AMBIGUOUS"
CORRELATION_VOCABULARY = {
    CORRELATION_MATCHED,
    CORRELATION_OPEN,
    CORRELATION_RESPONSE_ONLY,
    CORRELATION_AMBIGUOUS,
}

MESSAGE_ACCEPTED = "MESSAGE_ACCEPTED_OBSERVED"
MESSAGE_PARTIALLY_ACCEPTED = "MESSAGE_PARTIALLY_ACCEPTED_OBSERVED"
MESSAGE_REJECTED = "MESSAGE_REJECTED_OBSERVED"
MESSAGE_NOT_OBSERVED = "MESSAGE_OUTCOME_NOT_OBSERVED"
MESSAGE_AMBIGUOUS = "MESSAGE_OUTCOME_AMBIGUOUS"
MESSAGE_UNRESOLVED = "MESSAGE_OUTCOME_UNRESOLVED"

TX_ACCEPTED = "CONTROL_ACCEPTED_OBSERVED"
TX_REJECTED = "CONTROL_REJECTED_OBSERVED"
TX_PARTIAL = "CONTROL_PARTIAL_OR_MIXED"
TX_UNRESOLVED = "CONTROL_OUTCOME_UNRESOLVED"

ITEM_ACCEPTED = "ITEM_CONTROL_ACCEPTED_OBSERVED"
ITEM_PARTIALLY_ACCEPTED = "ITEM_CONTROL_PARTIALLY_ACCEPTED_OBSERVED"
ITEM_REJECTED = "ITEM_CONTROL_REJECTED_OBSERVED"
ITEM_NOT_OBSERVED = "ITEM_OUTCOME_NOT_OBSERVED"
ITEM_REQUEST_ONLY = "ITEM_REQUEST_EVIDENCE_ONLY"
ITEM_UNRESOLVED = "ITEM_OUTCOME_UNRESOLVED"

ASSOC_ESTABLISHED = "ITEM_ASSOCIATION_ESTABLISHED"
ASSOC_AMBIGUOUS = "ITEM_ASSOCIATION_AMBIGUOUS"
ASSOC_NOT_ESTABLISHED = "ITEM_ASSOCIATION_NOT_ESTABLISHED"

COMPLETE = "COMPLETE"
TRUNCATED = "TRUNCATED"
INVALID = "INVALID"

SIDE_REQUEST = "REQUEST"
SIDE_RESPONSE = "RESPONSE"

ACCEPTED_CAUSE_CODE = 16
PARTIALLY_ACCEPTED_CAUSE_CODE = 17
REVIEWED_REJECTION_CAUSES = frozenset({64, 72, 73})
MAX_TRANSACTIONS = 128
MAX_ITEMS = 256
MAX_ASSOCIATIONS = 256
MAX_FINDINGS = 64
MAX_TEXT = 240

FORBIDDEN_TEXT = (
    re.compile(r"\b\d{9,}\b"),
    re.compile(r"[\w.+-]+@[\w.-]+"),
    re.compile(r"\b(?:imsi|msisdn|imei|apn)\b", re.IGNORECASE),
)

NOT_CONFIRMED = (
    "a correlated Create/Update/Delete Bearer transaction proves an observed signaling exchange only",
    "a message-level accepted Cause proves the observed message outcome only",
    "a bearer-item accepted Cause does not prove UE acceptance, radio bearer establishment or S1-U delivery",
    "QoS values are signaling evidence, not resource admission",
    "TFT IE presence is signaling evidence, not TFT installation or packet-filter content",
    "no dedicated-bearer activation, modification or effective removal is proven",
    "no root cause, policy decision or forwarding state is inferred",
)


class InputError(Exception):
    """Malformed or unusable input document."""


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _safe_text(value: Any, limit: int = MAX_TEXT) -> str | None:
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    if any(pattern.search(text) for pattern in FORBIDDEN_TEXT):
        return None
    return text


def safe_capture(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    name = Path(value).name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    return name[:120] or None


def read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"input document not found: {path.name}") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"unreadable input document {path.name}: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"input document {path.name} is not an object")
    return payload


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(f"{path.name} line {number}: {exc.msg}") from exc
            if not isinstance(payload, dict):
                raise InputError(f"{path.name} line {number}: record is not an object")
            records.append(payload)
    except FileNotFoundError as exc:
        raise InputError(f"input document not found: {path.name}") from exc
    except OSError as exc:
        raise InputError(f"unreadable input document {path.name}: {exc}") from exc
    if not records:
        raise InputError(f"{path.name}: no detailed GTPv2-C events found")
    return records


def _validate_event(event: dict[str, Any]) -> None:
    for field in ("frame_number", "message_type_code", "header"):
        if field not in event:
            raise InputError(f"GTPv2-C event lacks required field: {field}")


def _reference_key(reference: dict[str, Any]) -> tuple[Any, Any, Any, Any]:
    return (
        _int(reference.get("frame_number")),
        _int(reference.get("message_occurrence")) or 0,
        _int(reference.get("message_type_code")),
        _int((reference.get("sequence_number"))),
    )


def _reference_of(event: dict[str, Any]) -> dict[str, Any]:
    header = _dict(event.get("header"))
    payload = {
        "frame_number": event.get("frame_number"),
        "message_type": event.get("message_type"),
        "message_type_code": event.get("message_type_code"),
        "sequence_number": header.get("sequence_number"),
        "header_teid": header.get("teid"),
        "header_teid_state": header.get("teid_state"),
    }
    occurrence = _int(event.get("message_occurrence")) or 0
    if occurrence:
        payload["message_occurrence"] = occurrence
    return payload


def _resolve_reference(
    reference: dict[str, Any],
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, str, str | None]:
    key = _reference_key(reference)
    if any(value is None for value in key):
        return None, INVALID, "the protocol reference lacks frame, type, sequence or message identity"
    matches = []
    for event in events:
        header = _dict(event.get("header"))
        occurrence = _int(event.get("message_occurrence")) or 0
        if (
            _int(event.get("frame_number")),
            occurrence,
            _int(event.get("message_type_code")),
            _int(header.get("sequence_number")),
        ) == key:
            matches.append(event)
    if not matches:
        return None, TRUNCATED, "the referenced message occurrence is not present in the supplied events"
    captures = {safe_capture(event.get("capture_file")) for event in matches}
    if len(captures) > 1:
        return None, INVALID, "the reference resolves in more than one capture and is not capture-scoped"
    if len(matches) > 1:
        return None, INVALID, "the reference resolves to more than one message occurrence"
    return matches[0], COMPLETE, None


def _cause(
    event: dict[str, Any] | None,
    key: str,
    expected_scope: str,
) -> tuple[dict[str, Any] | None, str | None]:
    if event is None:
        return None, None
    cause = _dict(event.get(key))
    if not cause:
        return None, None
    code = _int(cause.get("cause_code"))
    if code is None:
        return None, None
    name = _safe_text(cause.get("cause_name"))
    scope_value = cause.get("scope")
    scope = scope_value if scope_value in ("message", "bearer") else None
    observed = {"cause_code": code, "cause_name": name, "scope": scope}
    if scope_value != expected_scope:
        return observed, (
            f"{key} carries scope {scope_value!r}; the required scope is "
            f"{expected_scope!r}, so this Cause does not establish an outcome at this level"
        )
    return observed, None


def classify_message_cause(
    cause: dict[str, Any] | None,
    detail: str | None,
) -> tuple[str, list[str]]:
    if cause is None:
        return MESSAGE_NOT_OBSERVED, []
    if detail is not None:
        return MESSAGE_UNRESOLVED, [detail]
    code = cause.get("cause_code")
    if code == ACCEPTED_CAUSE_CODE:
        return MESSAGE_ACCEPTED, []
    if code == PARTIALLY_ACCEPTED_CAUSE_CODE:
        return MESSAGE_PARTIALLY_ACCEPTED, []
    if code in REVIEWED_REJECTION_CAUSES:
        return MESSAGE_REJECTED, []
    return MESSAGE_UNRESOLVED, [
        f"Cause code {code} is not in the reviewed rejection set; no accepted or rejected outcome is assigned"
    ]


def classify_item_cause(
    cause: dict[str, Any] | None,
    detail: str | None,
) -> str:
    if cause is None:
        return ITEM_NOT_OBSERVED
    if detail is not None:
        return ITEM_UNRESOLVED
    code = cause.get("cause_code")
    if code == ACCEPTED_CAUSE_CODE:
        return ITEM_ACCEPTED
    if code == PARTIALLY_ACCEPTED_CAUSE_CODE:
        return ITEM_PARTIALLY_ACCEPTED
    if code in REVIEWED_REJECTION_CAUSES:
        return ITEM_REJECTED
    return ITEM_UNRESOLVED


def _ebi_status(
    ebi: Any,
    item: dict[str, Any],
    duplicate_across: bool,
) -> tuple[int | None, bool, str]:
    values = [_int(value) for value in _list(item.get("ebi_values")) if _int(value) is not None]
    if len(values) > 1:
        return _int(ebi), False, "DUPLICATE_IN_CONTEXT"
    value = _int(ebi)
    if value is None:
        return None, False, "MISSING"
    if value < 1 or value > 15:
        return value, False, "INVALID"
    if duplicate_across:
        return value, False, "DUPLICATE_ACROSS_CONTEXTS"
    return value, True, "VALID"


def _item_reference(
    transaction_reference: str,
    side: str,
    frame: Any,
    occurrence: int,
    item_index: int,
) -> str:
    return (
        f"epc-db-item:{transaction_reference}:{side.lower()}:"
        f"{frame}:{occurrence}:{item_index}"
    )


def _item_observations(
    *,
    event: dict[str, Any] | None,
    side: str,
    capture: str,
    transaction_reference: str,
    source_status: str,
) -> list[dict[str, Any]]:
    if event is None:
        return []
    frame = event.get("frame_number")
    occurrence = _int(event.get("message_occurrence")) or 0
    contexts = [_dict(item) for item in _list(event.get("bearer_contexts"))]
    ebi_counts: dict[int, int] = {}
    for item in contexts:
        value = _int(item.get("ebi"))
        if value is not None:
            ebi_counts[value] = ebi_counts.get(value, 0) + 1
    observations: list[dict[str, Any]] = []
    for index, item in enumerate(contexts):
        ebi, valid, ebi_status = _ebi_status(
            item.get("ebi"),
            item,
            ebi_counts.get(_int(item.get("ebi")) or -1, 0) > 1,
        )
        cause = None
        cause_detail = None
        if side == SIDE_RESPONSE:
            cause, cause_detail = _cause(item, "cause", "bearer")
            item_outcome = classify_item_cause(cause, cause_detail)
        else:
            item_outcome = ITEM_REQUEST_ONLY
        limitations: list[str] = []
        if ebi_status == "MISSING":
            limitations.append("the Bearer Context item has no EBI; it is never associated by list position")
        elif ebi_status == "INVALID":
            limitations.append("the EBI is outside the reviewed dedicated-bearer identity range")
        elif ebi_status in ("DUPLICATE_IN_CONTEXT", "DUPLICATE_ACROSS_CONTEXTS"):
            limitations.append("duplicate EBI evidence prevents a unique item identity")
        if side == SIDE_RESPONSE and cause is None:
            limitations.append("the response Bearer Context item has no observed Cause; no outcome is invented")
        if cause_detail is not None:
            limitations.append(cause_detail)
        observations.append(
            {
                "item_reference": _item_reference(
                    transaction_reference, side, frame, occurrence, index
                ),
                "capture": capture,
                "transaction_reference": transaction_reference,
                "procedure_family": event.get("procedure_family"),
                "side": side,
                "frame_number": frame,
                "message_occurrence": occurrence,
                "item_index": index,
                "ebi": ebi,
                "ebi_valid": valid,
                "ebi_status": ebi_status,
                "cause": cause,
                "item_outcome": item_outcome,
                "f_teids": [_dict(value) for value in _list(item.get("f_teids"))][:8],
                "qos": _dict(item.get("qos")) or None,
                "tft": _dict(item.get("tft")) or None,
                "source_completeness_status": source_status,
                "evidence_limitations": limitations,
            }
        )
    return observations


def _top_level_ebis(event: dict[str, Any] | None) -> list[dict[str, Any]]:
    if event is None:
        return []
    metadata = event.get("unbound_ie_metadata")
    entries = metadata if isinstance(metadata, list) else [_dict(metadata)]
    values: list[int] = []
    for entry in entries:
        for value in _list(entry.get("ebi_values")):
            parsed = _int(value)
            if parsed is not None and parsed not in values:
                values.append(parsed)
    return [
        {
            "request_top_level_ebi_reference": (
                f"epc-db-top-ebi:{safe_capture(event.get('capture_file'))}:"
                f"{event.get('frame_number')}:{value}"
            ),
            "capture": safe_capture(event.get("capture_file")),
            "ebi": value,
            "ebi_valid": 1 <= value <= 15,
            "binding_basis": "flat_unbound_message_scope",
            "limitation": (
                "a top-level EBI is message-scope evidence; it is not a grouped Bearer Context item "
                "and no dedicated-bearer item association is established from it"
            ),
        }
        for value in values
    ]


def _association(
    request_item: dict[str, Any] | None,
    response_item: dict[str, Any] | None,
    status: str,
    basis: list[str],
    limitations: list[str],
) -> dict[str, Any]:
    request_ref = request_item.get("item_reference") if request_item else None
    response_ref = response_item.get("item_reference") if response_item else None
    capture = (request_item or response_item or {}).get("capture") or "unresolved"
    tx_ref = (request_item or response_item or {}).get("transaction_reference") or "unresolved"
    return {
        "association_reference": (
            f"epc-db-assoc:{tx_ref}:"
            f"{request_ref or 'none'}:{response_ref or 'none'}"
        ),
        "capture": capture,
        "transaction_reference": tx_ref,
        "request_item_reference": request_ref,
        "response_item_reference": response_ref,
        "ebi": (response_item or request_item or {}).get("ebi"),
        "status": status,
        "basis": basis,
        "limitations": limitations,
    }


def _associate_items(
    request_items: list[dict[str, Any]],
    response_items: list[dict[str, Any]],
    correlation_status: str,
) -> list[dict[str, Any]]:
    associations: list[dict[str, Any]] = []
    if correlation_status != CORRELATION_MATCHED:
        status = ASSOC_AMBIGUOUS if correlation_status == CORRELATION_AMBIGUOUS else ASSOC_NOT_ESTABLISHED
        for item in request_items:
            associations.append(
                _association(
                    item,
                    None,
                    status,
                    ["transaction correlation is not MATCHED"],
                    ["no response-side item can be associated through an unresolved transaction"],
                )
            )
        for item in response_items:
            associations.append(
                _association(
                    None,
                    item,
                    status,
                    ["transaction correlation is not MATCHED"],
                    ["the response item stays response-side evidence without a request identity"],
                )
            )
        return associations

    request_by_ebi: dict[int, list[dict[str, Any]]] = {}
    response_by_ebi: dict[int, list[dict[str, Any]]] = {}
    for item in request_items:
        if item["ebi"] is not None:
            request_by_ebi.setdefault(item["ebi"], []).append(item)
    for item in response_items:
        if item["ebi"] is not None:
            response_by_ebi.setdefault(item["ebi"], []).append(item)

    matched_request: set[str] = set()
    matched_response: set[str] = set()
    for response_item in response_items:
        ebi = response_item["ebi"]
        if ebi is None or not response_item["ebi_valid"]:
            duplicate = response_item["ebi_status"] in (
                "DUPLICATE_IN_CONTEXT",
                "DUPLICATE_ACROSS_CONTEXTS",
            )
            associations.append(
                _association(
                    None,
                    response_item,
                    ASSOC_AMBIGUOUS if duplicate else ASSOC_NOT_ESTABLISHED,
                    ["response item has missing, invalid or duplicate EBI identity"],
                    [
                        "duplicate EBI evidence preserves ambiguity"
                        if duplicate
                        else "no request item can be associated without a valid item identity"
                    ],
                )
            )
            continue
        candidates = request_by_ebi.get(ebi, [])
        if len(candidates) == 1 and len(response_by_ebi.get(ebi, [])) == 1 and candidates[0]["ebi_valid"]:
            associations.append(
                _association(
                    candidates[0],
                    response_item,
                    ASSOC_ESTABLISHED,
                    [
                        "same capture and MATCHED transaction",
                        "unique valid EBI on both request and response items",
                    ],
                    [],
                )
            )
            matched_request.add(candidates[0]["item_reference"])
            matched_response.add(response_item["item_reference"])
        elif len(candidates) > 1 or len(response_by_ebi.get(ebi, [])) > 1:
            associations.append(
                _association(
                    candidates[0] if len(candidates) == 1 else None,
                    response_item,
                    ASSOC_AMBIGUOUS,
                    ["duplicate EBI evidence on one or both sides"],
                    ["more than one item claims the same EBI; no unique association is selected"],
                )
            )
        else:
            associations.append(
                _association(
                    None,
                    response_item,
                    ASSOC_NOT_ESTABLISHED,
                    ["no request item carries the response EBI"],
                    ["response-side evidence is preserved without inventing a request item"],
                )
            )

    for request_item in request_items:
        if request_item["item_reference"] in matched_request:
            continue
        if request_item["ebi"] is None or not request_item["ebi_valid"]:
            status = ASSOC_NOT_ESTABLISHED
            basis = ["request item lacks a valid EBI identity"]
            limitations = ["no item identity is inferred from list position, TEID or QCI"]
        elif not response_by_ebi.get(request_item["ebi"]):
            status = ASSOC_NOT_ESTABLISHED
            basis = ["no uniquely selected response item carries the request EBI"]
            limitations = ["the request item stays request-side evidence"]
        else:
            status = ASSOC_AMBIGUOUS
            basis = ["duplicate response-side EBI evidence"]
            limitations = ["more than one response item claims the EBI; no unique association is selected"]
        associations.append(
            _association(request_item, None, status, basis, limitations)
        )
    return associations


def _transaction_outcome(
    message_status: str,
    response_items: list[dict[str, Any]],
) -> tuple[str, list[str]]:
    if message_status == MESSAGE_REJECTED:
        return TX_REJECTED, ["the observed message-level Cause is a reviewed rejection"]
    if message_status == MESSAGE_PARTIALLY_ACCEPTED:
        return TX_PARTIAL, [
            "the observed message-level Cause is partial acceptance; it is not ordinary acceptance or rejection"
        ]
    if message_status != MESSAGE_ACCEPTED:
        return TX_UNRESOLVED, ["no accepted or explicitly partial message-level control outcome is observed"]
    if not response_items:
        return TX_ACCEPTED, ["message-level acceptance is observed; no bearer item outcome is available"]
    outcomes = [item["item_outcome"] for item in response_items]
    if all(outcome == ITEM_ACCEPTED for outcome in outcomes):
        return TX_ACCEPTED, ["message-level acceptance and every observed bearer item Cause are accepted"]
    return TX_PARTIAL, [
        "message-level acceptance is observed, but at least one bearer item is rejected, partially accepted or lacks an observed Cause"
    ]


def _sorted_transactions(transactions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        transactions,
        key=lambda item: (
            str(item.get("capture") or ""),
            _int((_dict(item.get("request")).get("frame_number"))) or 0,
            str(item.get("protocol_transaction_reference") or ""),
        ),
    )


def _resolve_expected_reference(
    reference: dict[str, Any],
    events: list[dict[str, Any]],
    expected: bool,
    expected_code: int | None,
    kind: str,
) -> tuple[dict[str, Any] | None, str, str | None]:
    if not reference:
        if expected:
            return None, TRUNCATED, f"the transaction has no {kind} reference"
        return None, COMPLETE, None
    if _int(reference.get("message_type_code")) != expected_code:
        return (
            None,
            INVALID,
            f"the {kind} reference does not identify the expected message type {expected_code}",
        )
    return _resolve_reference(reference, events)


def analyze(
    events: list[dict[str, Any]],
    transaction_document: dict[str, Any],
    session_identity: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    for event in events:
        _validate_event(event)
    if transaction_document.get("protocol") not in (None, "GTPv2-C"):
        raise InputError("the transaction artifact is not a GTPv2-C document")
    protocol_transactions = [_dict(item) for item in _list(transaction_document.get("transactions"))]
    if not isinstance(transaction_document.get("transactions"), list):
        raise InputError("the transaction artifact has no transactions collection")

    global_status = COMPLETE
    missing_references: list[dict[str, Any]] = []
    control_transactions: list[dict[str, Any]] = []
    all_items: list[dict[str, Any]] = []
    all_associations: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    ignored_families: list[str] = []

    for transaction in protocol_transactions:
        family = transaction.get("procedure_family")
        if family not in CONTROL_FAMILIES:
            if isinstance(family, str) and family not in ignored_families:
                ignored_families.append(family)
            continue
        protocol_reference = transaction.get("transaction_reference")
        if not isinstance(protocol_reference, str) or not protocol_reference:
            global_status = _merge_status(global_status, INVALID)
            unresolved.append(
                {
                    "kind": "MALFORMED_TRANSACTION_REFERENCE",
                    "transaction_reference": None,
                    "limitation": "a dedicated-bearer transaction lacks a usable protocol transaction reference",
                }
            )
            continue
        correlation_status = transaction.get("correlation_status")
        if correlation_status not in CORRELATION_VOCABULARY:
            global_status = _merge_status(global_status, INVALID)
            correlation_status = CORRELATION_AMBIGUOUS
        correlation_strength = transaction.get("correlation_strength")
        if correlation_strength not in ("STRONG", "SUPPORTED", "NONE", None):
            correlation_strength = None

        request_reference = _dict(transaction.get("request"))
        response_reference = _dict(transaction.get("response"))
        expected_request = correlation_status in (
            CORRELATION_MATCHED,
            CORRELATION_OPEN,
            CORRELATION_AMBIGUOUS,
        )
        expected_response = correlation_status in (
            CORRELATION_MATCHED,
            CORRELATION_RESPONSE_ONLY,
        )
        request_event, request_status, request_detail = _resolve_expected_reference(
            request_reference,
            events,
            expected_request,
            EXPECTED_REQUEST_CODE.get(family),
            "request",
        )
        response_event, response_status, response_detail = _resolve_expected_reference(
            response_reference,
            events,
            expected_response,
            EXPECTED_RESPONSE_CODE.get(family),
            "response",
        )
        if expected_request and request_status != COMPLETE:
            global_status = _merge_status(global_status, request_status)
            missing_references.append(
                {
                    "kind": "REQUEST_EVENT",
                    "transaction_reference": protocol_reference,
                    "limitation": request_detail,
                }
            )
        if expected_response and response_status != COMPLETE:
            global_status = _merge_status(global_status, response_status)
            missing_references.append(
                {
                    "kind": "RESPONSE_EVENT",
                    "transaction_reference": protocol_reference,
                    "limitation": response_detail,
                }
            )

        request_capture = safe_capture((request_event or {}).get("capture_file"))
        response_capture = safe_capture((response_event or {}).get("capture_file"))
        if request_capture and response_capture and request_capture != response_capture:
            global_status = _merge_status(global_status, INVALID)
            capture = None
        else:
            capture = request_capture or response_capture
        if capture is None:
            global_status = _merge_status(global_status, INVALID)

        transaction_reference = f"epc-db-tx:{capture or 'unresolved'}:{protocol_reference}"

        message_outcome_status = MESSAGE_NOT_OBSERVED
        message_cause = None
        message_limitations: list[str] = []
        if correlation_status != CORRELATION_MATCHED:
            if correlation_status == CORRELATION_AMBIGUOUS:
                message_outcome_status = MESSAGE_AMBIGUOUS
                message_limitations.append(
                    "response ownership is AMBIGUOUS; no response message outcome is selected"
                )
            else:
                message_limitations.append(
                    "the transaction is not MATCHED; no response message outcome is established"
                )
        elif response_event is None:
            message_limitations.append("the selected response message is not present in the supplied events")
        else:
            message_cause, message_cause_detail = _cause(
                response_event, "message_cause", "message"
            )
            message_outcome_status, cause_limitations = classify_message_cause(
                message_cause, message_cause_detail
            )
            message_limitations.extend(cause_limitations)
            if message_cause is None:
                message_limitations.append("the response has no valid message-level Cause")

        request_items = _item_observations(
            event=request_event,
            side=SIDE_REQUEST,
            capture=capture or "unresolved",
            transaction_reference=transaction_reference,
            source_status=request_status,
        )
        response_items = _item_observations(
            event=response_event,
            side=SIDE_RESPONSE,
            capture=capture or "unresolved",
            transaction_reference=transaction_reference,
            source_status=response_status,
        )
        top_level_ebis = _top_level_ebis(request_event)
        associations = _associate_items(request_items, response_items, correlation_status)
        for top_level in top_level_ebis:
            associations.append(
                {
                    "association_reference": (
                        f"epc-db-assoc:{transaction_reference}:"
                        f"top-ebi:{top_level['ebi']}:none"
                    ),
                    "capture": capture or "unresolved",
                    "transaction_reference": transaction_reference,
                    "request_item_reference": None,
                    "response_item_reference": None,
                    "request_top_level_ebi_reference": top_level[
                        "request_top_level_ebi_reference"
                    ],
                    "ebi": top_level["ebi"],
                    "status": ASSOC_NOT_ESTABLISHED,
                    "basis": ["top-level EBI is not a grouped Bearer Context item"],
                    "limitations": [top_level["limitation"]],
                }
            )

        transaction_outcome, outcome_basis = _transaction_outcome(
            message_outcome_status, response_items
        )
        if correlation_status != CORRELATION_MATCHED:
            transaction_outcome = TX_UNRESOLVED
            outcome_basis = [
                "the accepted transaction correlation does not establish a unique control exchange"
            ]

        limitations: list[str] = []
        if correlation_status == CORRELATION_OPEN:
            limitations.append(
                "an unmatched request is an open observed transaction, not a proven network timeout"
            )
        if correlation_status == CORRELATION_RESPONSE_ONLY:
            limitations.append(
                "a response-only observation is not an independently established request/response transaction"
            )
        if correlation_status == CORRELATION_AMBIGUOUS:
            limitations.append(
                "competing response candidates remain ambiguous; no response is selected by EBI, frame proximity or timestamp"
            )
        if isinstance(transaction.get("limitations"), list):
            for value in transaction["limitations"]:
                safe = _safe_text(value)
                if safe and safe not in limitations:
                    limitations.append(safe)

        source_status = COMPLETE
        if request_status != COMPLETE and expected_request:
            source_status = _merge_status(source_status, request_status)
        if response_status != COMPLETE and expected_response:
            source_status = _merge_status(source_status, response_status)
        if capture is None:
            source_status = INVALID

        if source_status != COMPLETE or capture is None:
            transaction_outcome = TX_UNRESOLVED
            outcome_basis = [
                "source completeness or capture identity does not support a complete control outcome"
            ]
            for association in associations:
                if association["status"] == ASSOC_ESTABLISHED:
                    association["status"] = ASSOC_NOT_ESTABLISHED
                    association["limitations"].append(
                        "source completeness or capture identity does not support an established item association"
                    )

        control_transaction = {
            "transaction_reference": transaction_reference,
            "protocol_transaction_reference": protocol_reference,
            "capture": capture,
            "procedure_family": family,
            "correlation_status": correlation_status,
            "correlation_strength": correlation_strength,
            "correlation_basis": [
                safe
                for safe in (
                    _safe_text(value) for value in _list(transaction.get("correlation_basis"))
                )
                if safe
            ],
            "request": _reference_of(request_event)
            if request_event is not None
            else (request_reference or None),
            "response": _reference_of(response_event) if response_event is not None else (
                response_reference or None
            ),
            "retransmissions": [
                _dict(item) for item in _list(transaction.get("retransmissions"))
            ][:8],
            "frame_anchors": {
                "request_frame": (request_event or {}).get("frame_number"),
                "response_frame": (response_event or {}).get("frame_number"),
            },
            "message_outcome": {
                "status": message_outcome_status,
                "cause": message_cause,
                "source_reference": _reference_of(response_event) if response_event else None,
                "limitations": message_limitations,
            },
            "transaction_outcome": transaction_outcome,
            "transaction_outcome_basis": outcome_basis,
            "request_bearer_item_references": [
                item["item_reference"] for item in request_items
            ],
            "response_bearer_item_references": [
                item["item_reference"] for item in response_items
            ],
            "request_top_level_ebi_references": [
                item["request_top_level_ebi_reference"] for item in top_level_ebis
            ],
            "source_completeness_status": source_status,
            "evidence_limitations": limitations,
        }
        control_transactions.append(control_transaction)
        all_items.extend(request_items)
        all_items.extend(response_items)
        all_associations.extend(associations)
        if transaction_outcome != TX_ACCEPTED or source_status != COMPLETE:
            unresolved.append(
                {
                    "kind": transaction_outcome,
                    "transaction_reference": transaction_reference,
                    "limitation": "; ".join(limitations) or "transaction outcome is not a complete accepted observation",
                }
            )
        global_status = _merge_status(global_status, source_status)

    all_items.sort(
        key=lambda item: (
            str(item.get("capture") or ""),
            str(item.get("transaction_reference") or ""),
            0 if item.get("side") == SIDE_REQUEST else 1,
            _int(item.get("frame_number")) or 0,
            _int(item.get("message_occurrence")) or 0,
            _int(item.get("item_index")) or 0,
        )
    )
    all_associations.sort(
        key=lambda item: (
            str(item.get("capture") or ""),
            str(item.get("transaction_reference") or ""),
            str(item.get("request_item_reference") or ""),
            str(item.get("response_item_reference") or ""),
        )
    )
    control_transactions = _sorted_transactions(control_transactions)

    outcome_counts: dict[str, int] = {}
    message_counts: dict[str, int] = {}
    item_counts: dict[str, int] = {}
    association_counts: dict[str, int] = {}
    for item in control_transactions:
        outcome_counts[item["transaction_outcome"]] = outcome_counts.get(item["transaction_outcome"], 0) + 1
        key = item["message_outcome"]["status"]
        message_counts[key] = message_counts.get(key, 0) + 1
    for item in all_items:
        item_counts[item["item_outcome"]] = item_counts.get(item["item_outcome"], 0) + 1
    for item in all_associations:
        association_counts[item["status"]] = association_counts.get(item["status"], 0) + 1

    if session_identity is None:
        session_context = {
            "status": "NOT_PROVIDED",
            "artifact": None,
            "captures": [],
            "associated_transaction_references": [],
            "limitations": [],
        }
    else:
        if session_identity.get("analysis_name") not in (None, "epc-session-identity"):
            raise InputError("the supplied session-identity artifact has an incompatible analysis name")
        session_context = {
            "status": "NOT_ESTABLISHED",
            "artifact": (provenance or {}).get("session_identity"),
            "captures": sorted(
                {
                    safe_capture(_dict(item).get("capture_file"))
                    for item in _list(session_identity.get("hop_local_contexts"))
                    if safe_capture(_dict(item).get("capture_file"))
                }
            ),
            "associated_transaction_references": [],
            "limitations": [
                "the accepted session-identity contract does not publish an established relationship from a "
                "dedicated-bearer control transaction to a hop-local session context",
                "no join by header TEID or EBI alone was attempted",
            ],
        }

    evidence_limitations = [
        "the input artifacts do not declare an exhaustive dedicated-bearer universe; bounded publication is not exhaustive coverage",
        "a MATCHED transaction is an observed signaling exchange, not bearer activation or teardown proof",
        "bearer-item Cause values are independent per item; a message-level Cause is never copied",
        "QoS and TFT presence are signaling evidence only",
    ]
    evidence_limitations.extend(
        f"ignored non-dedicated-bearer procedure family: {family}"
        for family in sorted(ignored_families)
    )

    return {
        "domain": DOMAIN,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": {
            "gtpv2_events": (provenance or {}).get("gtpv2_events"),
            "transaction_artifact": (provenance or {}).get("transaction_artifact"),
            "session_identity": (provenance or {}).get("session_identity"),
            "event_count": len(events),
            "protocol_transaction_count": len(protocol_transactions),
            "control_transaction_input_count": sum(
                1 for item in protocol_transactions if item.get("procedure_family") in CONTROL_FAMILIES
            ),
        },
        "analysis_scope": {
            "procedures": list(CONTROL_FAMILIES),
            "message_types": list(CONTROL_MESSAGE_CODES),
            "transaction_correlation_source": "accepted GTPv2-C transaction artifact",
            "not_inferred": list(NOT_CONFIRMED),
        },
        "source_completeness": {
            "status": global_status,
            "exhaustive_coverage_proven": False,
            "reference_complete": global_status == COMPLETE,
            "missing_references": missing_references[:MAX_FINDINGS],
            "missing_reference_count": len(missing_references),
            "limitations": [
                "the supplied inputs do not publish a declared total event or bearer universe"
            ],
        },
        "control_transactions": control_transactions[:MAX_TRANSACTIONS],
        "control_transaction_count": len(control_transactions),
        "control_transactions_omitted": max(0, len(control_transactions) - MAX_TRANSACTIONS),
        "bearer_item_observations": all_items[:MAX_ITEMS],
        "bearer_item_observation_count": len(all_items),
        "bearer_item_observations_omitted": max(0, len(all_items) - MAX_ITEMS),
        "item_associations": all_associations[:MAX_ASSOCIATIONS],
        "item_association_count": len(all_associations),
        "item_associations_omitted": max(0, len(all_associations) - MAX_ASSOCIATIONS),
        "session_identity_context": session_context,
        "outcome_summary": {
            "transaction_classification_counts": {
                key: outcome_counts[key] for key in sorted(outcome_counts)
            },
            "message_outcome_counts": {key: message_counts[key] for key in sorted(message_counts)},
            "item_outcome_counts": {key: item_counts[key] for key in sorted(item_counts)},
            "item_association_status_counts": {
                key: association_counts[key] for key in sorted(association_counts)
            },
        },
        "unresolved_findings": unresolved[:MAX_FINDINGS],
        "unresolved_finding_count": len(unresolved),
        "evidence_limitations": evidence_limitations,
        "not_confirmed": list(NOT_CONFIRMED),
        "bounded": True,
        "limits": {
            "control_transactions": MAX_TRANSACTIONS,
            "bearer_items": MAX_ITEMS,
            "item_associations": MAX_ASSOCIATIONS,
            "unresolved_findings": MAX_FINDINGS,
        },
    }


def _merge_status(current: str, new: str) -> str:
    if INVALID in (current, new):
        return INVALID
    if TRUNCATED in (current, new):
        return TRUNCATED
    return COMPLETE


def build_timeline(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for transaction in analysis.get("control_transactions") or []:
        rows.append(
            {
                "protocol": "GTPv2-C",
                "domain": DOMAIN,
                "event_kind": "dedicated_bearer_control_transaction",
                "capture": transaction.get("capture"),
                "transaction_reference": transaction.get("transaction_reference"),
                "procedure_family": transaction.get("procedure_family"),
                "frame_anchor": transaction.get("frame_anchors", {}).get("request_frame"),
                "correlation_status": transaction.get("correlation_status"),
                "transaction_outcome": transaction.get("transaction_outcome"),
                "message_outcome": transaction.get("message_outcome", {}).get("status"),
            }
        )
    return rows