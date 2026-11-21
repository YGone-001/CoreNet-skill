#!/usr/bin/env python3
"""Bounded IMS session establishment and release Domain evidence model.

This Domain consumes accepted SIP event, transaction and dialog artifacts. It
does not decode packets, rematch SIP transactions, rebuild SIP dialogs, or
produce call-success, media-delivery, RTP, QoS or VoLTE verdicts.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SIP_SCRIPTS = HERE.parents[2] / "protocol" / "sip" / "scripts"
if str(SIP_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SIP_SCRIPTS))

import sip_dialogs  # noqa: E402
import sip_model  # noqa: E402
import sip_transactions  # noqa: E402

ANALYSIS_NAME = "ims-session"
ANALYSIS_VERSION = "0.1.0"
DOMAIN = "ims-session"
CAPABILITY = "IMS session establishment and release signaling evidence"

EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")
TRANSACTION_REFERENCE_PATTERN = re.compile(
    r"^sip-transaction:.+:(?:request|response):[0-9]+\.[0-9]+$"
)
DIALOG_REFERENCE_PATTERN = re.compile(r"^sip-dialog:.+:[0-9]+\.[0-9]+$")
ATTEMPT_REFERENCE_PATTERN = re.compile(r"^ims-session:.+:[0-9]+\.[0-9]+$")

MAX_REFERENCES = 64
MAX_ATTEMPTS = 64
MAX_BRANCHES = 64
MAX_UNBOUND = 64
MAX_IN_DIALOG = 64
MAX_LIMITATIONS = 16

EVENT_KEYS = (
    "source_reference",
    "capture_file",
    "frame_number",
    "message_occurrence",
    "message_type",
    "method",
    "status_code",
    "transaction_reference",
    "event_schema_version",
    "headers",
    "message_completeness",
    "extraction_status",
    "integrity_findings",
)
TRANSACTION_REFERENCE_KEYS = (
    "request_event_references",
    "response_event_references",
    "provisional_response_event_references",
    "final_response_event_references",
    "associated_control_event_references",
    "retransmission_event_references",
    "repeated_observation_event_references",
    "conflicting_request_event_references",
    "retransmission_candidate_event_references",
)
DIALOG_REFERENCE_KEYS = (
    "early_response_event_references",
    "confirming_response_event_references",
    "ack_event_references",
    "associated_message_event_references",
)
DIALOG_TRANSACTION_KEYS = (
    "in_dialog_transaction_references",
    "bye_transaction_references",
)
BASE_LIMITATIONS = (
    "IMS session analysis is Domain signaling evidence only and does not prove call success, media delivery or two-way audio",
    "SIP transaction and dialog identity remain owned by the accepted SIP Protocol contracts",
    "missing messages at the capture boundary are incompleteness, not proof of a timeout or failure",
    "a non-2xx INVITE final response is not a successful session establishment",
    "one initial INVITE transaction may carry multiple independent forked dialog branches",
    "CANCEL acknowledges its own transaction and does not by itself establish INVITE termination",
    "BYE signaling does not prove that RTP stopped or that media resources were released",
    "re-INVITE and UPDATE are retained as in-dialog observations without session-modification conclusions",
)
NOT_CONFIRMED = (
    "IMS_CALL_SUCCESS",
    "IMS_CALL_FAILURE",
    "TWO_WAY_AUDIO",
    "RTP_DELIVERY",
    "EARLY_MEDIA_DELIVERY",
    "SESSION_MODIFICATION",
    "SUBSCRIBER_REACHABILITY",
    "VOLTE_SERVICE_SUCCESS",
    "SIP_TIMEOUT",
    "REGISTRATION_TO_SESSION_ASSOCIATION",
    "CROSS_PROTOCOL_ASSOCIATION",
)
BRANCH_OUTCOMES = (
    "ACCEPTED_2XX",
    "NEGATIVE_FINAL",
    "EARLY_ONLY",
    "PROVISIONAL_ONLY",
    "NO_FINAL_RESPONSE",
    "UNRESOLVED",
)
ACK_STATUSES = (
    "OBSERVED_FOR_ALL_ACCEPTED_BRANCHES",
    "MISSING_FOR_ACCEPTED_BRANCH",
    "NOT_APPLICABLE",
)
CANCEL_OUTCOMES = (
    "NO_CANCEL_OBSERVED",
    "CANCEL_REQUEST_OBSERVED",
    "CANCEL_RESPONSE_OBSERVED",
    "CANCEL_INVITE_SEQUENCE_OBSERVED",
    "CANCEL_ASSOCIATION_NOT_ESTABLISHED",
    "CANCEL_AFTER_INVITE_FINAL_RESPONSE",
)
RELEASE_OUTCOMES = (
    "NO_BYE_OBSERVED",
    "BYE_REQUEST_OBSERVED",
    "BYE_RESPONSE_OBSERVED",
    "BYE_RESPONSE_NOT_OBSERVED",
    "BYE_NEGATIVE_RESPONSE_OBSERVED",
    "SIP_TERMINATION_SIGNALING_SUPPORTED",
)
INVITE_OUTCOMES = (
    "ACCEPTED_2XX_OBSERVED",
    "NEGATIVE_FINAL_OBSERVED",
    "PROVISIONAL_ONLY",
    "NO_RESPONSE_OBSERVED",
    "INCOMPLETE_EVIDENCE",
)


class InputError(ValueError):
    """Raised when accepted input artifacts are malformed or inconsistent."""


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return event


def _ordered(reference: str) -> tuple[str, int, int]:
    prefix, _, tail = reference.rpartition(":")
    frame, _, occurrence = tail.partition(".")
    return prefix, int(frame), int(occurrence)


def _capture_of(reference: str) -> str:
    prefix = reference.rpartition(":")[0]
    parts = prefix.split(":")
    return ":".join(parts[1:-1]) if len(parts) > 2 else parts[-1]


def _frame_of_event(event: dict[str, Any]) -> int:
    return int(event["frame_number"])


def _status(event: dict[str, Any]) -> int | None:
    value = event.get("status_code")
    return value if isinstance(value, int) else None


def _unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values), key=_ordered)


def _bounded(values: list[str], limit: int = MAX_REFERENCES) -> tuple[list[str], int]:
    unique = _unique(values)
    return unique[:limit], max(0, len(unique) - limit)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"{label} could not be read: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(f"{label} is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise InputError(f"{label} must be a JSON object")
    return document


def load_events(path: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise InputError(f"SIP event input could not be read: {exc}") from exc
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InputError(f"SIP event line {line_number} is not valid JSON: {exc}") from exc
        if not isinstance(event, dict):
            raise InputError(f"SIP event line {line_number} is not an object")
        _validate_event(event, line_number)
        events.append(event)
    if not events:
        raise InputError("SIP event input contains no events")
    return sorted(
        events,
        key=lambda item: (item["capture_file"], item["frame_number"], item["message_occurrence"]),
    )


def _validate_event(event: dict[str, Any], line_number: int) -> None:
    for key in EVENT_KEYS:
        if key not in event:
            raise InputError(f"SIP event line {line_number} is missing {key}")
    reference = event["source_reference"]
    if not isinstance(reference, str) or not EVENT_REFERENCE_PATTERN.fullmatch(reference):
        raise InputError(f"SIP event line {line_number} has an invalid source reference")
    if event["event_schema_version"] not in {"1.0.0", sip_model.EVENT_SCHEMA_VERSION}:
        raise InputError(
            f"SIP event line {line_number} has an unsupported schema version "
            f"{event['event_schema_version']}"
        )
    frame = event["frame_number"]
    occurrence = event["message_occurrence"]
    if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
        raise InputError(f"SIP event line {line_number} has an invalid frame number")
    if isinstance(occurrence, bool) or not isinstance(occurrence, int) or occurrence < 1:
        raise InputError(f"SIP event line {line_number} has an invalid message occurrence")
    if not isinstance(event["capture_file"], str) or not event["capture_file"]:
        raise InputError(f"SIP event line {line_number} has no capture identity")
    if event["message_type"] not in {"REQUEST", "RESPONSE"}:
        raise InputError(f"SIP event line {line_number} has an invalid message type")
    headers = event["headers"]
    if not isinstance(headers, dict) or not isinstance(headers.get("cseq"), dict):
        raise InputError(f"SIP event line {line_number} has no accepted CSeq evidence")
    if not isinstance(headers.get("to"), dict):
        raise InputError(f"SIP event line {line_number} has no accepted To evidence")
    if event["message_completeness"] not in {
        "COMPLETE",
        "TRUNCATED",
        "MALFORMED",
        "INCOMPLETE",
    }:
        raise InputError(f"SIP event line {line_number} has an invalid completeness value")


def load_transactions(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SIP transaction input")
    try:
        sip_transactions.validate_transaction_document(document)
    except sip_transactions.TransactionError as exc:
        raise InputError(f"SIP transaction contract is not accepted: {exc}") from exc
    if document.get("analysis_version") != sip_transactions.TRANSACTION_SCHEMA_VERSION:
        raise InputError("SIP transaction document has an unsupported analysis version")
    return document


def load_dialogs(path: Path) -> dict[str, Any]:
    document = _load_json(path, "SIP dialog input")
    try:
        sip_dialogs.validate_dialog_document(document)
    except sip_dialogs.DialogError as exc:
        raise InputError(f"SIP dialog contract is not accepted: {exc}") from exc
    if document.get("analysis_version") != sip_dialogs.DIALOG_SCHEMA_VERSION:
        raise InputError("SIP dialog document has an unsupported analysis version")
    return document


def _validate_contracts(
    events: list[dict[str, Any]],
    transactions: dict[str, Any],
    dialogs: dict[str, Any],
) -> None:
    event_refs = [event["source_reference"] for event in events]
    if len(event_refs) != len(set(event_refs)):
        raise InputError("SIP event source references are not unique")
    event_captures = sorted({event["capture_file"] for event in events})
    transaction_captures = sorted({str(item) for item in transactions.get("capture_files") or []})
    dialog_captures = sorted(
        {str(item) for item in dialogs.get("capture_provenance", {}).get("capture_files") or []}
    )
    if len(event_captures) != 1:
        raise InputError("IMS session Domain requires exactly one capture identity")
    if transaction_captures != event_captures or dialog_captures != event_captures:
        raise InputError(
            "SIP event, transaction and dialog artifacts do not share one capture provenance"
        )
    capture = event_captures[0]
    for reference in event_refs:
        if _capture_of(reference) != capture:
            raise InputError("a SIP event reference is not capture-scoped to the input capture")
    by_event = {event["source_reference"]: event for event in events}
    by_transaction = {
        transaction["transaction_reference"]: transaction
        for transaction in transactions.get("transactions") or []
    }
    if len(by_transaction) != len(transactions.get("transactions") or []):
        raise InputError("SIP transaction references are not unique")
    for transaction in by_transaction.values():
        for key in TRANSACTION_REFERENCE_KEYS:
            for reference in transaction.get(key) or []:
                if reference not in by_event:
                    raise InputError(f"transaction references a missing source event: {reference}")
                event = by_event[reference]
                event_transaction = event.get("transaction_reference")
                if event_transaction is not None and event_transaction != transaction["transaction_reference"]:
                    raise InputError("a transaction references an event owned by another transaction")
    for event in events:
        transaction_reference = event.get("transaction_reference")
        if transaction_reference is not None and transaction_reference not in by_transaction:
            raise InputError(
                f"SIP event references a missing transaction: {transaction_reference}"
            )
    dialog_refs = [dialog["dialog_reference"] for dialog in dialogs.get("dialogs") or []]
    if len(dialog_refs) != len(set(dialog_refs)):
        raise InputError("SIP dialog references are not unique")
    for dialog in dialogs.get("dialogs") or []:
        reference = dialog["dialog_reference"]
        if not DIALOG_REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("a SIP dialog reference is invalid")
        if _capture_of(reference) != capture:
            raise InputError("a SIP dialog reference is not capture-scoped to the input capture")
        initiating = dialog.get("initiating_transaction_reference")
        transaction = by_transaction.get(initiating)
        if transaction is None:
            raise InputError("a dialog initiating transaction is absent from the transaction input")
        if transaction.get("transaction_type") != "INVITE" or transaction.get("transaction_method") != "INVITE":
            raise InputError("a dialog initiating transaction is not an INVITE")
        request_refs = transaction.get("request_event_references") or []
        if not request_refs or request_refs[0] not in by_event:
            raise InputError("a dialog initiating INVITE has no accepted request event")
        for key in DIALOG_REFERENCE_KEYS:
            for ref in dialog.get(key) or []:
                if ref not in by_event:
                    raise InputError(f"dialog references a missing source event: {ref}")
        for key in DIALOG_TRANSACTION_KEYS:
            for ref in dialog.get(key) or []:
                if ref not in by_transaction:
                    raise InputError(f"dialog references a missing transaction: {ref}")
    for observation in list(dialogs.get("unbound_observations") or []) + list(
        dialogs.get("ambiguous_observations") or []
    ):
        for ref in observation.get("event_references") or []:
            if ref not in by_event:
                raise InputError(f"dialog observation references a missing source event: {ref}")
        for ref in observation.get("transaction_references") or []:
            if ref not in by_transaction:
                raise InputError(f"dialog observation references a missing transaction: {ref}")
    if not capture:
        raise InputError("SIP inputs do not carry a capture identity")


def _event_statuses(refs: list[str], by_event: dict[str, dict[str, Any]]) -> list[int]:
    return [
        status
        for ref in refs
        for status in [_status(by_event[ref])]
        if status is not None
    ]


def _provisional_groups(
    refs: list[str], by_event: dict[str, dict[str, Any]]
) -> dict[str, list[str]]:
    trying: list[str] = []
    ringing: list[str] = []
    progress: list[str] = []
    untagged: list[str] = []
    for reference in refs:
        event = by_event[reference]
        status = _status(event)
        tagged = bool(event.get("headers", {}).get("to", {}).get("tag_present"))
        if status == 100:
            trying.append(reference)
        elif status == 180:
            (ringing if tagged else untagged).append(reference)
        elif status == 183:
            (progress if tagged else untagged).append(reference)
        elif status is not None and 100 <= status < 200 and not tagged:
            untagged.append(reference)
    return {
        "trying": _unique(trying),
        "ringing": _unique(ringing),
        "progress": _unique(progress),
        "untagged": _unique(untagged),
    }


def _dialog_branch(
    dialog: dict[str, Any],
    by_event: dict[str, dict[str, Any]],
    transactions: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    early = list(dialog.get("early_response_event_references") or [])
    confirming = list(dialog.get("confirming_response_event_references") or [])
    ack_refs = list(dialog.get("ack_event_references") or [])
    response_refs = _unique(early + confirming)
    statuses = _event_statuses(response_refs, by_event)
    if confirming and any(200 <= status < 300 for status in statuses):
        outcome = "ACCEPTED_2XX"
    elif early:
        outcome = "EARLY_ONLY"
    else:
        outcome = "UNRESOLVED"
    if outcome == "ACCEPTED_2XX":
        ack_status = "OBSERVED_FOR_ALL_ACCEPTED_BRANCHES" if ack_refs else "MISSING_FOR_ACCEPTED_BRANCH"
    else:
        ack_status = "NOT_APPLICABLE"
    release = _branch_release(dialog, transactions)
    missing: list[str] = []
    if outcome == "ACCEPTED_2XX" and not ack_refs:
        missing.append("TWO_XX_ACK_NOT_OBSERVED")
    if outcome == "EARLY_ONLY":
        missing.append("CONFIRMING_RESPONSE_NOT_OBSERVED")
    return {
        "branch_reference": dialog["dialog_reference"],
        "dialog_reference": dialog["dialog_reference"],
        "fork_branch_reference": dialog.get("fork_branch_reference"),
        "identity_status": dialog.get("identity_status"),
        "dialog_state": dialog.get("dialog_state"),
        "observed_lifecycle_status": dialog.get("observed_lifecycle_status"),
        "response_event_references": response_refs,
        "response_status_codes": statuses,
        "outcome": outcome,
        "ack_event_references": _unique(ack_refs)[:MAX_REFERENCES],
        "ack_status": ack_status,
        "release": release,
        "missing_evidence": missing,
        "conflict_findings": sorted(set(dialog.get("conflict_findings") or [])),
    }


def _branch_release(
    dialog: dict[str, Any], transactions: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    bye_refs = list(dialog.get("bye_transaction_references") or [])
    observations = []
    for reference in bye_refs:
        transaction = transactions.get(reference)
        if transaction is None:
            continue
        statuses = list(transaction.get("final_response_status_codes") or [])
        request_refs = list(transaction.get("request_event_references") or [])
        response_refs = list(transaction.get("final_response_event_references") or [])
        if any(200 <= status < 300 for status in statuses):
            outcome = "BYE_RESPONSE_OBSERVED"
        elif statuses:
            outcome = "BYE_NEGATIVE_RESPONSE_OBSERVED"
        else:
            outcome = "BYE_RESPONSE_NOT_OBSERVED"
        observations.append(
            {
                "bye_transaction_reference": reference,
                "bye_request_event_references": request_refs[:MAX_REFERENCES],
                "bye_final_response_event_references": response_refs[:MAX_REFERENCES],
                "final_response_status_codes": statuses,
                "outcome": outcome,
                "termination_supported": bool(
                    any(200 <= status < 300 for status in statuses)
                    and dialog.get("dialog_state") in {"CONFIRMED", "TERMINATED"}
                ),
                "missing_evidence": [] if statuses else ["BYE_FINAL_RESPONSE_NOT_OBSERVED"],
            }
        )
    if not observations:
        outcome = "NO_BYE_OBSERVED"
    elif any(item["outcome"] == "BYE_RESPONSE_OBSERVED" for item in observations):
        outcome = "SIP_TERMINATION_SIGNALING_SUPPORTED"
    elif any(item["outcome"] == "BYE_RESPONSE_NOT_OBSERVED" for item in observations):
        outcome = "BYE_RESPONSE_NOT_OBSERVED"
    elif any(item["outcome"] == "BYE_NEGATIVE_RESPONSE_OBSERVED" for item in observations):
        outcome = "BYE_NEGATIVE_RESPONSE_OBSERVED"
    else:
        outcome = "BYE_REQUEST_OBSERVED"
    return {
        "outcome": outcome,
        "bye_transaction_count": len(observations),
        "observations": observations[:MAX_REFERENCES],
        "termination_supported_dialog_references": (
            [dialog["dialog_reference"]]
            if any(item["termination_supported"] for item in observations)
            else []
        ),
    }


def _cancel_evidence(
    initial_transaction: dict[str, Any],
    cancel_transactions: list[dict[str, Any]],
    by_event: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    if not cancel_transactions:
        return {
            "outcome": "NO_CANCEL_OBSERVED",
            "cancel_transaction_references": [],
            "cancel_request_event_references": [],
            "cancel_final_response_event_references": [],
            "cancel_final_response_status_codes": [],
            "association_status": "NOT_OBSERVED",
            "response_sequence_observed": False,
            "invite_final_response_status": None,
            "invite_transaction_termination_established": False,
            "missing_evidence": [],
            "conflict_findings": [],
        }
    transaction = cancel_transactions[0]
    cancel_request_refs = list(transaction.get("request_event_references") or [])
    cancel_response_refs = list(transaction.get("final_response_event_references") or [])
    cancel_statuses = list(transaction.get("final_response_status_codes") or [])
    association_status = transaction.get("cancel_invite_association_status") or "NOT_ESTABLISHED"
    invite_status = transaction.get("invite_final_response_status")
    if invite_status is None:
        invite_status = next(
            iter(initial_transaction.get("final_response_status_codes") or []), None
        )
    conflicts: list[str] = []
    missing: list[str] = []
    first_cancel_frame = (
        _frame_of_event(by_event[cancel_request_refs[0]]) if cancel_request_refs else None
    )
    invite_final_frames = [
        _frame_of_event(by_event[reference])
        for reference in initial_transaction.get("final_response_event_references") or []
    ]
    if (
        first_cancel_frame is not None
        and invite_final_frames
        and first_cancel_frame > min(invite_final_frames)
    ):
        conflicts.append("CANCEL_AFTER_INVITE_FINAL_RESPONSE")
    if association_status == "AMBIGUOUS":
        conflicts.append("CANCEL_INVITE_ASSOCIATION_AMBIGUOUS")
    if not cancel_response_refs:
        missing.append("CANCEL_FINAL_RESPONSE_NOT_OBSERVED")
    sequence_observed = bool(
        transaction.get("cancel_response_sequence_observed")
        or initial_transaction.get("cancel_response_sequence_observed")
    )
    if association_status != "ASSOCIATED":
        outcome = "CANCEL_ASSOCIATION_NOT_ESTABLISHED"
    elif "CANCEL_AFTER_INVITE_FINAL_RESPONSE" in conflicts:
        outcome = "CANCEL_AFTER_INVITE_FINAL_RESPONSE"
    elif sequence_observed:
        outcome = "CANCEL_INVITE_SEQUENCE_OBSERVED"
    elif cancel_statuses:
        outcome = "CANCEL_RESPONSE_OBSERVED"
    else:
        outcome = "CANCEL_REQUEST_OBSERVED"
    return {
        "outcome": outcome,
        "cancel_transaction_references": [transaction["transaction_reference"]],
        "cancel_request_event_references": cancel_request_refs[:MAX_REFERENCES],
        "cancel_final_response_event_references": cancel_response_refs[:MAX_REFERENCES],
        "cancel_final_response_status_codes": cancel_statuses,
        "association_status": association_status,
        "response_sequence_observed": sequence_observed,
        "invite_final_response_status": invite_status,
        "invite_transaction_termination_established": False,
        "missing_evidence": missing,
        "conflict_findings": conflicts,
    }


def _release_summary(branches: list[dict[str, Any]]) -> dict[str, Any]:
    releases = [branch["release"] for branch in branches]
    bye_refs = _unique(
        [
            observation["bye_transaction_reference"]
            for release in releases
            for observation in release["observations"]
        ]
    )
    supported = _unique(
        [
            ref
            for release in releases
            for ref in release["termination_supported_dialog_references"]
        ]
    )
    if not bye_refs:
        outcome = "NO_BYE_OBSERVED"
    elif supported:
        outcome = "SIP_TERMINATION_SIGNALING_SUPPORTED"
    elif any(item["outcome"] == "BYE_RESPONSE_NOT_OBSERVED" for item in releases):
        outcome = "BYE_RESPONSE_NOT_OBSERVED"
    elif any(item["outcome"] == "BYE_NEGATIVE_RESPONSE_OBSERVED" for item in releases):
        outcome = "BYE_NEGATIVE_RESPONSE_OBSERVED"
    else:
        outcome = "BYE_REQUEST_OBSERVED"
    return {
        "outcome": outcome,
        "bye_transaction_references": bye_refs[:MAX_REFERENCES],
        "termination_supported_dialog_references": supported[:MAX_REFERENCES],
    }


def _attempt(
    transaction: dict[str, Any],
    by_event: dict[str, dict[str, Any]],
    dialogs_by_initiating: dict[str, list[dict[str, Any]]],
    all_transactions: list[dict[str, Any]],
    by_transaction: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    request_refs = list(transaction.get("request_event_references") or [])
    initial_event = by_event[request_refs[0]]
    capture = initial_event["capture_file"]
    frame = initial_event["frame_number"]
    occurrence = initial_event["message_occurrence"]
    attempt_reference = f"ims-session:{capture}:{frame}.{occurrence}"
    provisional_refs = list(transaction.get("provisional_response_event_references") or [])
    provisional = _provisional_groups(provisional_refs, by_event)
    final_refs = list(transaction.get("final_response_event_references") or [])
    final_statuses = _event_statuses(final_refs, by_event)
    accepted_refs = [
        ref
        for ref in final_refs
        if (_status(by_event[ref]) or 0) >= 200 and (_status(by_event[ref]) or 0) < 300
    ]
    negative_refs = [
        ref for ref in final_refs if (_status(by_event[ref]) or 0) >= 300
    ]

    dialogs = dialogs_by_initiating.get(transaction["transaction_reference"], [])
    branches = [_dialog_branch(dialog, by_event, by_transaction) for dialog in dialogs]
    covered_final = {
        ref
        for branch in branches
        for ref in branch["response_event_references"]
    }
    for reference in _unique(final_refs):
        if reference in covered_final:
            continue
        status = _status(by_event[reference]) or 0
        if 200 <= status < 300:
            outcome = "ACCEPTED_2XX"
        elif status >= 300:
            outcome = "NEGATIVE_FINAL"
        else:
            outcome = "UNRESOLVED"
        branches.append(
            {
                "branch_reference": reference,
                "dialog_reference": None,
                "fork_branch_reference": None,
                "identity_status": "INSUFFICIENT_EVIDENCE",
                "dialog_state": "UNKNOWN",
                "observed_lifecycle_status": "UNRESOLVED",
                "response_event_references": [reference],
                "response_status_codes": [status] if status else [],
                "outcome": outcome,
                "ack_event_references": [],
                "ack_status": "NOT_APPLICABLE",
                "release": {
                    "outcome": "NO_BYE_OBSERVED",
                    "bye_transaction_count": 0,
                    "observations": [],
                    "termination_supported_dialog_references": [],
                },
                "missing_evidence": ["CONFIRMED_DIALOG_NOT_OBSERVED"]
                if outcome == "ACCEPTED_2XX"
                else [],
                "conflict_findings": [],
            }
        )
    if not branches:
        if provisional_refs:
            branches.append(
                {
                    "branch_reference": initial_event["source_reference"],
                    "dialog_reference": None,
                    "fork_branch_reference": None,
                    "identity_status": "INSUFFICIENT_EVIDENCE",
                    "dialog_state": "UNKNOWN",
                    "observed_lifecycle_status": "UNRESOLVED",
                    "response_event_references": provisional_refs[:MAX_REFERENCES],
                    "response_status_codes": _event_statuses(provisional_refs, by_event),
                    "outcome": "PROVISIONAL_ONLY",
                    "ack_event_references": [],
                    "ack_status": "NOT_APPLICABLE",
                    "release": {
                        "outcome": "NO_BYE_OBSERVED",
                        "bye_transaction_count": 0,
                        "observations": [],
                        "termination_supported_dialog_references": [],
                    },
                    "missing_evidence": ["FINAL_RESPONSE_NOT_OBSERVED"],
                    "conflict_findings": [],
                }
            )
        else:
            branches.append(
                {
                    "branch_reference": initial_event["source_reference"],
                    "dialog_reference": None,
                    "fork_branch_reference": None,
                    "identity_status": "NOT_ESTABLISHED",
                    "dialog_state": "UNKNOWN",
                    "observed_lifecycle_status": "INCOMPLETE_CAPTURE",
                    "response_event_references": [],
                    "response_status_codes": [],
                    "outcome": "NO_FINAL_RESPONSE",
                    "ack_event_references": [],
                    "ack_status": "NOT_APPLICABLE",
                    "release": {
                        "outcome": "NO_BYE_OBSERVED",
                        "bye_transaction_count": 0,
                        "observations": [],
                        "termination_supported_dialog_references": [],
                    },
                    "missing_evidence": ["PROVISIONAL_OR_FINAL_RESPONSE_NOT_OBSERVED"],
                    "conflict_findings": [],
                }
            )
    observed_branch_count = len(branches)
    branches = branches[:MAX_BRANCHES]
    branches_omitted = max(0, observed_branch_count - len(branches))
    accepted_branches = [branch for branch in branches if branch["outcome"] == "ACCEPTED_2XX"]
    confirmed_branches = [branch for branch in branches if branch["dialog_reference"]]
    twoxx_ack_refs = _unique(
        [
            ref
            for branch in accepted_branches
            for ref in branch["ack_event_references"]
        ]
    )
    non_twoxx_ack_refs = list(transaction.get("associated_control_event_references") or [])
    if not accepted_branches:
        ack_status = "NOT_APPLICABLE"
    elif any(branch["ack_status"] == "MISSING_FOR_ACCEPTED_BRANCH" for branch in accepted_branches):
        ack_status = "MISSING_FOR_ACCEPTED_BRANCH"
    else:
        ack_status = "OBSERVED_FOR_ALL_ACCEPTED_BRANCHES"
    final_refs_for_invite = _unique(final_refs + provisional_refs)
    if accepted_refs:
        invite_outcome = "ACCEPTED_2XX_OBSERVED"
    elif negative_refs:
        invite_outcome = "NEGATIVE_FINAL_OBSERVED"
    elif provisional_refs:
        invite_outcome = "PROVISIONAL_ONLY"
    elif not final_refs and not provisional_refs:
        invite_outcome = "NO_RESPONSE_OBSERVED"
    else:
        invite_outcome = "INCOMPLETE_EVIDENCE"

    cancel_transactions = [
        item
        for item in all_transactions
        if item.get("transaction_method") == "CANCEL"
        and transaction["transaction_reference"]
        in (item.get("associated_transaction_references") or [])
    ]
    cancel = _cancel_evidence(transaction, cancel_transactions, by_event)
    release = _release_summary(branches)

    missing: list[str] = []
    conflicts: list[str] = []
    if not final_refs:
        missing.append("INVITE_FINAL_RESPONSE_NOT_OBSERVED")
    if accepted_refs and not any(branch["dialog_reference"] for branch in accepted_branches):
        missing.append("CONFIRMED_DIALOG_NOT_OBSERVED")
    if ack_status == "MISSING_FOR_ACCEPTED_BRANCH":
        missing.append("TWO_XX_ACK_NOT_OBSERVED")
    if any(branch["outcome"] == "NEGATIVE_FINAL" for branch in branches) and accepted_branches:
        conflicts.append("MIXED_FORKED_BRANCH_OUTCOMES")
    conflicts.extend(cancel.get("conflict_findings") or [])
    for branch in branches:
        conflicts.extend(branch.get("conflict_findings") or [])
    attempt_event_refs = list(request_refs + provisional_refs + final_refs)
    attempt_event_refs.extend(
        ref
        for branch in branches
        for ref in branch.get("ack_event_references") or []
    )
    attempt_event_refs.extend(cancel.get("cancel_request_event_references") or [])
    attempt_event_refs.extend(cancel.get("cancel_final_response_event_references") or [])
    for branch in branches:
        for observation in branch.get("release", {}).get("observations") or []:
            attempt_event_refs.extend(observation.get("bye_request_event_references") or [])
            attempt_event_refs.extend(
                observation.get("bye_final_response_event_references") or []
            )
    all_frames = [
        _frame_of_event(by_event[ref])
        for ref in _unique(attempt_event_refs)
        if ref in by_event
    ]
    return {
        "attempt_reference": attempt_reference,
        "capture_file": capture,
        "first_observed_frame": min(all_frames) if all_frames else frame,
        "last_observed_frame": max(all_frames) if all_frames else frame,
        "initial_invite_transaction_reference": transaction["transaction_reference"],
        "initial_invite_event_reference": initial_event["source_reference"],
        "invite_outcome": invite_outcome,
        "stage_evidence": {
            "initial_invite_request_event_reference": initial_event["source_reference"],
            "trying_100_event_references": provisional["trying"][:MAX_REFERENCES],
            "ringing_180_event_references": provisional["ringing"][:MAX_REFERENCES],
            "session_progress_183_event_references": provisional["progress"][:MAX_REFERENCES],
            "untagged_provisional_event_references": provisional["untagged"][:MAX_REFERENCES],
            "provisional_response_event_references": _unique(provisional_refs)[:MAX_REFERENCES],
            "final_response_event_references": _unique(final_refs)[:MAX_REFERENCES],
            "final_response_status_codes": final_statuses,
            "accepted_2xx_event_references": _unique(accepted_refs)[:MAX_REFERENCES],
            "negative_final_event_references": _unique(negative_refs)[:MAX_REFERENCES],
            "early_dialog_references": _unique(
                [
                    dialog["dialog_reference"]
                    for dialog in dialogs
                    if dialog.get("early_response_event_references")
                ]
            )[:MAX_REFERENCES],
            "confirmed_dialog_references": _unique(
                [
                    dialog["dialog_reference"]
                    for dialog in dialogs
                    if dialog.get("confirming_response_event_references")
                ]
            )[:MAX_REFERENCES],
        },
        "branch_count": len(branches),
        "branches": branches,
        "branches_omitted": branches_omitted,
        "ack_evidence": {
            "status": ack_status,
            "twoxx_ack_event_references": twoxx_ack_refs[:MAX_REFERENCES],
            "non_twoxx_ack_event_references": _unique(non_twoxx_ack_refs)[:MAX_REFERENCES],
        },
        "cancel_evidence": cancel,
        "release_evidence": release,
        "missing_evidence": sorted(set(missing)),
        "conflict_findings": sorted(set(conflicts)),
        "not_confirmed": list(NOT_CONFIRMED),
        "evidence_class": "DERIVED",
    }


def _unbound_observations(
    dialogs: dict[str, Any],
    assigned_cancel_refs: set[str],
    all_transactions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for item in dialogs.get("unbound_observations") or []:
        observations.append(
            {
                "observation_reference": item.get("observation_reference"),
                "kind": "UNBOUND",
                "reason": item.get("reason"),
                "identity_status": item.get("identity_status"),
                "event_references": list(item.get("event_references") or [])[:MAX_REFERENCES],
                "transaction_references": list(item.get("transaction_references") or [])[
                    :MAX_REFERENCES
                ],
                "candidate_dialog_references": [],
            }
        )
    for item in dialogs.get("ambiguous_observations") or []:
        observations.append(
            {
                "observation_reference": item.get("observation_reference"),
                "kind": "AMBIGUOUS",
                "reason": item.get("reason"),
                "identity_status": item.get("identity_status"),
                "event_references": [],
                "transaction_references": [item.get("transaction_reference")]
                if item.get("transaction_reference")
                else [],
                "candidate_dialog_references": list(item.get("candidate_dialog_references") or [])[
                    :MAX_REFERENCES
                ],
            }
        )
    for transaction in all_transactions:
        if transaction.get("transaction_method") != "CANCEL":
            continue
        reference = transaction["transaction_reference"]
        if reference in assigned_cancel_refs:
            continue
        association = transaction.get("cancel_invite_association_status")
        if association == "ASSOCIATED":
            continue
        observations.append(
            {
                "observation_reference": reference,
                "kind": "UNBOUND",
                "reason": "CANCEL_ASSOCIATION_NOT_ESTABLISHED",
                "identity_status": "INSUFFICIENT_EVIDENCE",
                "event_references": list(transaction.get("request_event_references") or [])[
                    :MAX_REFERENCES
                ],
                "transaction_references": [reference],
                "candidate_dialog_references": [],
            }
        )
    observations.sort(key=lambda item: (item["kind"], item["observation_reference"] or ""))
    return observations


def _in_dialog_observations(
    dialogs: dict[str, Any], by_transaction: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dialog in dialogs.get("dialogs") or []:
        for reference in dialog.get("in_dialog_transaction_references") or []:
            if reference in seen:
                continue
            transaction = by_transaction.get(reference)
            if transaction is None:
                continue
            method = transaction.get("transaction_method")
            if method not in {"INVITE", "UPDATE"}:
                continue
            seen.add(reference)
            request_refs = list(transaction.get("request_event_references") or [])
            if not request_refs:
                continue
            observations.append(
                {
                    "observation_reference": request_refs[0],
                    "dialog_reference": dialog["dialog_reference"],
                    "transaction_reference": reference,
                    "method": method,
                    "conclusion": "NOT_INTERPRETED",
                    "limitations": [
                        "session modification and SDP offer/answer semantics are outside this phase"
                    ],
                }
            )
    observations.sort(key=lambda item: _ordered(item["observation_reference"]))
    return observations


def build_analysis(
    events: list[dict[str, Any]],
    transactions: dict[str, Any],
    dialogs: dict[str, Any],
    *,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_contracts(events, transactions, dialogs)
    by_event = {event["source_reference"]: event for event in events}
    all_transactions = list(transactions.get("transactions") or [])
    by_transaction = {item["transaction_reference"]: item for item in all_transactions}
    dialog_initiating = {
        dialog["initiating_transaction_reference"] for dialog in dialogs.get("dialogs") or []
    }
    in_dialog = {
        reference
        for dialog in dialogs.get("dialogs") or []
        for reference in dialog.get("in_dialog_transaction_references") or []
    }
    dialogs_by_initiating: dict[str, list[dict[str, Any]]] = {}
    for dialog in dialogs.get("dialogs") or []:
        dialogs_by_initiating.setdefault(
            dialog["initiating_transaction_reference"], []
        ).append(dialog)
    initial_transactions: list[dict[str, Any]] = []
    for transaction in all_transactions:
        if transaction.get("transaction_type") != "INVITE":
            continue
        reference = transaction["transaction_reference"]
        if reference in in_dialog and reference not in dialog_initiating:
            continue
        request_refs = transaction.get("request_event_references") or []
        if not request_refs:
            continue
        event = by_event[request_refs[0]]
        tagged = bool(event.get("headers", {}).get("to", {}).get("tag_present"))
        if reference in dialog_initiating or not tagged:
            initial_transactions.append(transaction)
    initial_transactions.sort(key=lambda item: _ordered(item["transaction_reference"]))
    published_attempts = initial_transactions[:MAX_ATTEMPTS]
    attempts = [
        _attempt(
            transaction,
            by_event,
            dialogs_by_initiating,
            all_transactions,
            by_transaction,
        )
        for transaction in published_attempts
    ]
    assigned_cancel_refs = {
        reference
        for attempt in attempts
        for reference in attempt["cancel_evidence"]["cancel_transaction_references"]
    }
    unbound = _unbound_observations(dialogs, assigned_cancel_refs, all_transactions)
    published_unbound = unbound[:MAX_UNBOUND]
    all_in_dialog = _in_dialog_observations(dialogs, by_transaction)
    in_dialog_observations = all_in_dialog[:MAX_IN_DIALOG]
    in_dialog_omitted = max(0, len(all_in_dialog) - len(in_dialog_observations))
    capture = events[0]["capture_file"]
    event_refs = [event["source_reference"] for event in events]
    transaction_refs = [item["transaction_reference"] for item in all_transactions]
    dialog_refs = [dialog["dialog_reference"] for dialog in dialogs.get("dialogs") or []]
    capture_completeness = "COMPLETE"
    if any(event.get("message_completeness") != "COMPLETE" for event in events):
        capture_completeness = "PARTIAL"
    if any(event.get("integrity_findings") for event in events):
        capture_completeness = "PARTIAL"
    if dialogs.get("capture_provenance", {}).get("capture_completeness") == "PARTIAL":
        capture_completeness = "PARTIAL"
    source_provenance = provenance or {}
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "capability": CAPABILITY,
        "input_provenance": {
            "capture_files": [capture],
            "event_source_name": source_provenance.get("event_source_name"),
            "event_sha256": source_provenance.get("event_sha256"),
            "event_schema_version": sip_model.EVENT_SCHEMA_VERSION,
            "transaction_source_name": source_provenance.get("transaction_source_name"),
            "transaction_sha256": source_provenance.get("transaction_sha256"),
            "transaction_analysis_version": sip_transactions.TRANSACTION_SCHEMA_VERSION,
            "dialog_source_name": source_provenance.get("dialog_source_name"),
            "dialog_sha256": source_provenance.get("dialog_sha256"),
            "dialog_analysis_version": sip_dialogs.DIALOG_SCHEMA_VERSION,
            "capture_completeness": capture_completeness,
            "input_status": "ACCEPTED",
        },
        "session_attempt_count": len(attempts),
        "session_attempts": attempts,
        "unbound_observation_count": len(published_unbound),
        "unbound_observations": published_unbound,
        "in_dialog_observation_count": len(in_dialog_observations),
        "in_dialog_observations": in_dialog_observations,
        "completeness": {
            "sip_event_count": len(event_refs),
            "sip_transaction_count": len(transaction_refs),
            "sip_dialog_count": len(dialog_refs),
            "initial_invite_transaction_count": len(initial_transactions),
            "session_attempt_count": len(initial_transactions),
            "attempts_omitted": max(0, len(initial_transactions) - len(attempts)),
            "branch_count": sum(attempt["branch_count"] for attempt in attempts),
            "branches_omitted": sum(attempt["branches_omitted"] for attempt in attempts),
            "unbound_observation_count": len(unbound),
            "unbound_observations_omitted": max(0, len(unbound) - len(published_unbound)),
            "in_dialog_observation_count": len(all_in_dialog),
            "in_dialog_observations_omitted": in_dialog_omitted,
            "capture_completeness": capture_completeness,
        },
        "limitations": [
            "SIP transaction and dialog identity are consumed from the accepted SIP Protocol Skills",
            "the Domain does not decode packets or reconstruct transaction or dialog identity",
            "no IMS media, SDP, RTP, QoS or subscriber-reachability evidence is available",
            "3GPP TS 24.229 session procedures were not directly retrieved in this phase; IMS-specific claims are restricted",
        ],
        "not_confirmed": list(NOT_CONFIRMED),
    }


def validate_analysis(
    document: dict[str, Any],
    *,
    event_references: set[str] | None = None,
    transaction_references: set[str] | None = None,
    dialog_references: set[str] | None = None,
) -> None:
    if not isinstance(document, dict):
        raise InputError("IMS session analysis must be an object")
    if document.get("analysis_name") != ANALYSIS_NAME:
        raise InputError("IMS session analysis_name is not accepted")
    if document.get("analysis_version") != ANALYSIS_VERSION:
        raise InputError("IMS session analysis_version is not accepted")
    if document.get("domain") != DOMAIN:
        raise InputError("IMS session domain is not accepted")
    if document.get("session_attempt_count") != len(document.get("session_attempts") or []):
        raise InputError("session_attempt_count does not match the attempt array")
    known_event = event_references or set()
    known_transaction = transaction_references or set()
    known_dialog = dialog_references or set()
    attempt_refs: set[str] = set()
    branch_total = 0
    for attempt in document.get("session_attempts") or []:
        reference = attempt.get("attempt_reference")
        if not isinstance(reference, str) or not ATTEMPT_REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("an IMS session attempt reference is invalid")
        if reference in attempt_refs:
            raise InputError("IMS session attempt references are not unique")
        attempt_refs.add(reference)
        if attempt.get("invite_outcome") not in INVITE_OUTCOMES:
            raise InputError("an IMS session attempt has an invalid INVITE outcome")
        branches = attempt.get("branches") or []
        if attempt.get("branch_count") != len(branches):
            raise InputError("branch_count does not match the branch array")
        branch_total += len(branches)
        for branch in branches:
            if branch.get("outcome") not in BRANCH_OUTCOMES:
                raise InputError("a session branch has an invalid outcome")
            dialog_reference = branch.get("dialog_reference")
            if dialog_reference is not None:
                if known_dialog and dialog_reference not in known_dialog:
                    raise InputError("a branch references a missing dialog")
                if dialog_reference not in attempt.get("stage_evidence", {}).get(
                    "confirmed_dialog_references", []
                ) and dialog_reference not in attempt.get("stage_evidence", {}).get(
                    "early_dialog_references", []
                ):
                    raise InputError("a branch dialog is absent from stage evidence")
            if branch.get("ack_status") not in ACK_STATUSES:
                raise InputError("a branch has an invalid ACK status")
            if branch.get("release", {}).get("outcome") not in RELEASE_OUTCOMES:
                raise InputError("a branch has an invalid release outcome")
        ack = attempt.get("ack_evidence") or {}
        if ack.get("status") not in ACK_STATUSES:
            raise InputError("an attempt has an invalid ACK status")
        cancel = attempt.get("cancel_evidence") or {}
        if cancel.get("outcome") not in CANCEL_OUTCOMES:
            raise InputError("an attempt has an invalid CANCEL outcome")
        if cancel.get("invite_transaction_termination_established"):
            raise InputError("INVITE transaction termination cannot be claimed")
        if cancel.get("outcome") == "CANCEL_INVITE_SEQUENCE_OBSERVED" and not cancel.get(
            "response_sequence_observed"
        ):
            raise InputError("CANCEL sequence outcome requires sequence evidence")
        release = attempt.get("release_evidence") or {}
        if release.get("outcome") not in RELEASE_OUTCOMES:
            raise InputError("an attempt has an invalid release outcome")
        for ref in (
            [attempt.get("initial_invite_transaction_reference")]
            + list((attempt.get("stage_evidence") or {}).get("final_response_event_references") or [])
        ):
            if not isinstance(ref, str):
                raise InputError("an attempt publishes a missing reference")
            if ref.startswith("sip-event:") and known_event and ref not in known_event:
                raise InputError("an attempt references a missing source event")
            if ref.startswith("sip-transaction:") and known_transaction and ref not in known_transaction:
                raise InputError("an attempt references a missing transaction")
    completeness = document.get("completeness") or {}
    if completeness.get("session_attempt_count") != document.get(
        "session_attempt_count"
    ) + completeness.get("attempts_omitted", 0):
        raise InputError("session attempt count conservation failed")
    if completeness.get("branch_count") != branch_total + completeness.get(
        "branches_omitted", 0
    ):
        raise InputError("branch count conservation failed")
    if completeness.get("unbound_observation_count") != len(
        document.get("unbound_observations") or []
    ) + completeness.get("unbound_observations_omitted", 0):
        raise InputError("unbound observation count conservation failed")
    if completeness.get("in_dialog_observation_count") != len(
        document.get("in_dialog_observations") or []
    ) + completeness.get("in_dialog_observations_omitted", 0):
        raise InputError("in-dialog observation count conservation failed")
    for observation in document.get("unbound_observations") or []:
        for ref in observation.get("event_references") or []:
            if known_event and ref not in known_event:
                raise InputError("an unbound observation references a missing event")
        for ref in observation.get("transaction_references") or []:
            if known_transaction and ref not in known_transaction:
                raise InputError("an unbound observation references a missing transaction")
    for observation in document.get("in_dialog_observations") or []:
        if observation.get("method") not in {"INVITE", "UPDATE"}:
            raise InputError("in-dialog observation method is not accepted")
        if observation.get("conclusion") != "NOT_INTERPRETED":
            raise InputError("session modification must remain not interpreted")
    for forbidden in ("call_success", "ims_call_success", "media_delivery", "rtp_delivery", "two_way_audio"):
        if forbidden in document:
            raise InputError(f"forbidden success field published: {forbidden}")


def load_inputs(
    events_path: Path, transactions_path: Path, dialogs_path: Path
) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    events = load_events(events_path)
    transactions = load_transactions(transactions_path)
    dialogs = load_dialogs(dialogs_path)
    provenance = {
        "event_source_name": events_path.name,
        "event_sha256": _sha256(events_path),
        "transaction_source_name": transactions_path.name,
        "transaction_sha256": _sha256(transactions_path),
        "dialog_source_name": dialogs_path.name,
        "dialog_sha256": _sha256(dialogs_path),
    }
    return events, transactions, dialogs, provenance