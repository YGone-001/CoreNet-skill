#!/usr/bin/env python3
"""Bounded, privacy-safe SIP dialog evidence.

This module consumes the accepted SIP message records and transaction document. It
derives capture-scoped dialog evidence for INVITE-created dialogs, including early
and confirmed branches, forking isolation, 2xx ACK association, in-dialog request
association and BYE lifecycle signaling.

Raw dialog identity values stay in memory. Published dialog references are derived
only from safe source-event references.
"""

from __future__ import annotations

import re
from typing import Any

from sip_transactions import (
    TRANSACTION_REFERENCE_PATTERN,
    TransactionError,
    validate_transaction_document,
)

PROTOCOL = "SIP"
DIALOG_SCHEMA_VERSION = "1.0.0"
ANALYSIS_NAME = "sip-dialogs"

MAX_EVENT_REFERENCES = 64
MAX_TRANSACTION_REFERENCES = 64
MAX_CANDIDATES = 16
MAX_CSEQ_VALUES = 16
MAX_LIMITATIONS = 16

DIALOG_REFERENCE_PATTERN = re.compile(r"^sip-dialog:.+:[0-9]+\.[0-9]+$")
FORK_REFERENCE_PATTERN = re.compile(r"^sip-fork:.+:[0-9]+\.[0-9]+$")
OBSERVATION_REFERENCE_PATTERN = re.compile(r"^sip-observation:.+:[0-9]+\.[0-9]+$")
EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")

IDENTITY_STATUSES = ("ESTABLISHED", "AMBIGUOUS", "INSUFFICIENT_EVIDENCE", "NOT_ESTABLISHED")
DIALOG_STATES = ("EARLY", "CONFIRMED", "TERMINATED", "UNKNOWN")
LIFECYCLE_STATUSES = (
    "EARLY_OBSERVED",
    "CONFIRMATION_OBSERVED",
    "TERMINATION_SIGNALING_OBSERVED",
    "INCOMPLETE_CAPTURE",
    "UNRESOLVED",
)
DIRECTIONS = ("ORIGINAL", "REVERSE", "UNKNOWN")

IN_DIALOG_METHODS = ("BYE", "INVITE", "UPDATE", "INFO", "PRACK", "REFER", "MESSAGE")
UNSUPPORTED_DIALOG_METHODS = ("SUBSCRIBE", "NOTIFY")

MISSING_EVIDENCE = (
    "CALL_ID_NOT_OBSERVED",
    "FROM_TAG_NOT_OBSERVED",
    "TO_TAG_NOT_OBSERVED",
    "CSEQ_NOT_OBSERVED",
    "INITIAL_INVITE_NOT_OBSERVED",
    "CONFIRMING_RESPONSE_NOT_OBSERVED",
    "PROVISIONAL_RESPONSE_NOT_OBSERVED",
    "ACK_NOT_OBSERVED",
    "BYE_RESPONSE_NOT_OBSERVED",
    "CAPTURE_TRUNCATED",
    "DIALOG_CREATOR_NOT_OBSERVED",
    "SUBSCRIPTION_DIALOG_UNSUPPORTED",
)

CONFLICT_FINDINGS = (
    "CALL_ID_MISMATCH",
    "TAG_PAIR_MISMATCH",
    "CSEQ_MISMATCH",
    "TO_TAG_MISMATCH",
    "CONFIRMATION_WITHOUT_IDENTITY",
    "MULTIPLE_DIALOG_CANDIDATES",
    "CONTRADICTORY_TAG_EVIDENCE",
)

NOT_CONFIRMED = (
    "a SIP dialog is signaling evidence only; it does not prove RTP media, two-way audio, IMS registration or call completion",
    "ready-state and confirmed-state branches are capture-local observations",
    "BYE signaling does not prove that media stopped or that the network delivered an end-to-end release event",
    "dialog timeout is not inferred from elapsed capture time",
    "non-INVITE dialog usages such as event subscriptions are not modelled",
)

BASE_LIMITATIONS = (
    "SIP dialog analysis is protocol-local and does not assign IMS Domain, media, authentication or call verdicts",
    "passive capture cannot establish which stack side is local, so dialog orientation is derived from the initiating INVITE and observed tags",
    "missing messages at the capture boundary are incompleteness, not proof of a timeout or failure",
    "one Call-ID may carry multiple forked dialog branches",
    "the raw dialog identity tuple is never published",
)


class DialogError(ValueError):
    """Raised when dialog evidence violates its contract."""


def _match(message: dict[str, Any]) -> dict[str, Any]:
    return message["match"]


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _refs(transaction: dict[str, Any], key: str) -> list[str]:
    return list(transaction.get(key) or [])


def _unique(values: list[str]) -> list[str]:
    return sorted(dict.fromkeys(values), key=_reference_order)


def _reference_order(reference: str) -> tuple[Any, ...]:
    prefix, _, tail = reference.rpartition(":")
    frame, _, occurrence = tail.partition(".")
    return (prefix, int(frame) if frame.isdigit() else 0, int(occurrence) if occurrence.isdigit() else 0)


def _frame_of(reference: str) -> int:
    tail = reference.rpartition(":")[2]
    frame = tail.partition(".")[0]
    return int(frame) if frame.isdigit() else 0


def _capture_of(reference: str) -> str:
    parts = reference.split(":")
    return ":".join(parts[1:-1]) if len(parts) >= 3 else ""


def _event_reference(capture: str, frame: int, occurrence: int) -> str:
    return f"sip-event:{capture}:{frame}.{occurrence}"


def _dialog_reference(capture: str, frame: int, occurrence: int) -> str:
    return f"sip-dialog:{capture}:{frame}.{occurrence}"


def _fork_reference(capture: str, frame: int, occurrence: int) -> str:
    return f"sip-fork:{capture}:{frame}.{occurrence}"


def _observation_reference(capture: str, frame: int, occurrence: int) -> str:
    return f"sip-observation:{capture}:{frame}.{occurrence}"


def _bounded(values: list[str], limit: int = MAX_EVENT_REFERENCES) -> tuple[list[str], int]:
    unique = _unique(values)
    return unique[:limit], max(0, len(unique) - limit)


def _new_dialog(
    *,
    reference: str,
    capture: str,
    call_id: str,
    initiator_tag: str,
    remote_tag: str,
    invite_cseq: int | None,
    initiating_transaction: str,
    first_reference: str,
) -> dict[str, Any]:
    return {
        "reference": reference,
        "capture": capture,
        "call_id": call_id,
        "initiator_tag": initiator_tag,
        "remote_tag": remote_tag,
        "invite_cseq": invite_cseq,
        "initiating_transaction": initiating_transaction,
        "state": "EARLY",
        "early_refs": [],
        "confirm_refs": [],
        "ack_refs": [],
        "in_dialog_transactions": [],
        "bye_transactions": [],
        "associated_refs": [],
        "first_frame": _frame_of(first_reference),
        "last_frame": _frame_of(first_reference),
        "missing": [],
        "conflicts": [],
        "limitations": [],
        "basis": [],
        "cseq": {"ORIGINAL": [], "REVERSE": []},
        "directions": [],
        "fork_reference": _fork_reference(capture, _frame_of(first_reference), int(first_reference.rpartition(".")[2])),
    }


def _update_frames(dialog: dict[str, Any], reference: str) -> None:
    frame = _frame_of(reference)
    dialog["first_frame"] = min(dialog["first_frame"], frame)
    dialog["last_frame"] = max(dialog["last_frame"], frame)


def _add_reference(dialog: dict[str, Any], reference: str) -> None:
    if reference not in dialog["associated_refs"]:
        dialog["associated_refs"].append(reference)
    _update_frames(dialog, reference)


def _identity_conflicts(match: dict[str, Any], call_id: str, initiator_tag: str) -> list[str]:
    conflicts: list[str] = []
    if _present(match.get("call_id")) and match["call_id"] != call_id:
        conflicts.append("CALL_ID_MISMATCH")
    if _present(match.get("from_tag")) and match["from_tag"] != initiator_tag:
        conflicts.append("TAG_PAIR_MISMATCH")
    return conflicts


def _unbound(
    *,
    reference: str,
    capture: str,
    frame: int,
    occurrence: int,
    identity_status: str,
    reason: str,
    event_references: list[str],
    transaction_references: list[str],
    tag_pair_observed: bool,
    missing: list[str] | None = None,
    conflicts: list[str] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "observation_reference": _observation_reference(capture, frame, occurrence),
        "event_references": _bounded(event_references)[0],
        "transaction_references": _bounded(transaction_references)[0],
        "identity_status": identity_status,
        "reason": reason,
        "tag_pair_observed": tag_pair_observed,
        "missing_evidence": sorted(dict.fromkeys(missing or [])),
        "conflict_findings": sorted(dict.fromkeys(conflicts or [])),
        "limitations": _bounded(limitations or [], MAX_LIMITATIONS)[0],
    }


def _ambiguous(
    *,
    reference: str,
    capture: str,
    frame: int,
    occurrence: int,
    transaction_reference: str,
    reason: str,
    candidates: list[str],
    missing: list[str] | None = None,
    conflicts: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "observation_reference": _observation_reference(capture, frame, occurrence),
        "transaction_reference": transaction_reference,
        "reason": reason,
        "candidate_dialog_references": _bounded(candidates, MAX_CANDIDATES)[0],
        "missing_evidence": sorted(dict.fromkeys(missing or [])),
        "conflict_findings": sorted(dict.fromkeys(conflicts or [])),
    }


def _branch_key(call_id: str, initiator_tag: str, remote_tag: str) -> tuple[str, str, str]:
    return (call_id, initiator_tag, remote_tag)


def _build_dialogs(
    messages: list[dict[str, Any]],
    transaction_document: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    by_reference = {_match(message)["source_reference"]: _match(message) for message in messages}
    transactions = transaction_document["transactions"]
    dialogs: list[dict[str, Any]] = []
    by_branch: dict[tuple[str, str, str], dict[str, Any]] = {}
    unbound: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []

    def dialogs_for(capture: str, call_id: str, tags: set[str]) -> list[dict[str, Any]]:
        return [
            dialog
            for dialog in dialogs
            if dialog["capture"] == capture
            and dialog["call_id"] == call_id
            and {dialog["initiator_tag"], dialog["remote_tag"]} == tags
        ]

    invite_transactions = [
        transaction
        for transaction in transactions
        if transaction["transaction_type"] == "INVITE"
        and transaction["transaction_method"] == "INVITE"
        and transaction["transaction_identity_available"]
    ]

    for transaction in invite_transactions:
        request_refs = _refs(transaction, "request_event_references")
        if not request_refs:
            continue
        request = by_reference.get(request_refs[0])
        if request is None:
            continue
        if _present(request.get("to_tag")):
            continue
        capture = request["capture"]
        call_id = request.get("call_id")
        initiator_tag = request.get("from_tag")
        if not (_present(call_id) and _present(initiator_tag)):
            unbound.append(
                _unbound(
                    reference=request["source_reference"],
                    capture=capture,
                    frame=request["frame"],
                    occurrence=request["occurrence"],
                    identity_status="INSUFFICIENT_EVIDENCE",
                    reason="MISSING_DIALOG_IDENTITY",
                    event_references=request_refs,
                    transaction_references=[transaction["transaction_reference"]],
                    tag_pair_observed=False,
                    missing=[
                        label
                        for label, value in (
                            ("CALL_ID_NOT_OBSERVED", call_id),
                            ("FROM_TAG_NOT_OBSERVED", initiator_tag),
                        )
                        if not _present(value)
                    ],
                )
            )
            continue

        for reference in _refs(transaction, "provisional_response_event_references"):
            response = by_reference.get(reference)
            if response is None:
                continue
            if response.get("status_code") == 100:
                continue
            if not _present(response.get("to_tag")):
                unbound.append(
                    _unbound(
                        reference=response["source_reference"],
                        capture=capture,
                        frame=response["frame"],
                        occurrence=response["occurrence"],
                        identity_status="INSUFFICIENT_EVIDENCE",
                        reason="PROVISIONAL_WITHOUT_TO_TAG",
                        event_references=[reference],
                        transaction_references=[transaction["transaction_reference"]],
                        tag_pair_observed=False,
                        missing=["TO_TAG_NOT_OBSERVED"],
                    )
                )
                continue
            key = _branch_key(call_id, initiator_tag, response["to_tag"])
            dialog = by_branch.get(key)
            if dialog is None:
                dialog = _new_dialog(
                    reference=_dialog_reference(
                        capture, response["frame"], response["occurrence"]
                    ),
                    capture=capture,
                    call_id=call_id,
                    initiator_tag=initiator_tag,
                    remote_tag=response["to_tag"],
                    invite_cseq=request.get("cseq_number"),
                    initiating_transaction=transaction["transaction_reference"],
                    first_reference=response["source_reference"],
                )
                dialog["basis"].append("tagged_provisional_response")
                by_branch[key] = dialog
                dialogs.append(dialog)
            dialog["early_refs"].append(reference)
            _add_reference(dialog, reference)
            dialog["conflicts"].extend(_identity_conflicts(response, call_id, initiator_tag))

        for reference in _refs(transaction, "final_response_event_references"):
            response = by_reference.get(reference)
            if response is None:
                continue
            status = response.get("status_code")
            if status is None or not 200 <= status < 300:
                continue
            if not _present(response.get("to_tag")):
                unbound.append(
                    _unbound(
                        reference=response["source_reference"],
                        capture=capture,
                        frame=response["frame"],
                        occurrence=response["occurrence"],
                        identity_status="INSUFFICIENT_EVIDENCE",
                        reason="CONFIRMATION_WITHOUT_TO_TAG",
                        event_references=[reference],
                        transaction_references=[transaction["transaction_reference"]],
                        tag_pair_observed=False,
                        missing=["TO_TAG_NOT_OBSERVED"],
                        conflicts=["CONFIRMATION_WITHOUT_IDENTITY"],
                    )
                )
                continue
            key = _branch_key(call_id, initiator_tag, response["to_tag"])
            dialog = by_branch.get(key)
            if dialog is None:
                dialog = _new_dialog(
                    reference=_dialog_reference(
                        capture, response["frame"], response["occurrence"]
                    ),
                    capture=capture,
                    call_id=call_id,
                    initiator_tag=initiator_tag,
                    remote_tag=response["to_tag"],
                    invite_cseq=request.get("cseq_number"),
                    initiating_transaction=transaction["transaction_reference"],
                    first_reference=response["source_reference"],
                )
                dialog["basis"].append("confirmation_without_provisional")
                by_branch[key] = dialog
                dialogs.append(dialog)
            dialog["state"] = "CONFIRMED"
            dialog["confirm_refs"].append(reference)
            dialog["basis"].append("accepting_invite_response")
            _add_reference(dialog, reference)
            dialog["conflicts"].extend(_identity_conflicts(response, call_id, initiator_tag))

        for dialog in dialogs:
            if dialog["initiating_transaction"] == transaction["transaction_reference"]:
                for reference in request_refs:
                    _add_reference(dialog, reference)

    # Associate 2xx ACKs with a uniquely matching confirmed branch.
    for transaction in transactions:
        if transaction["transaction_type"] not in {"ACK_2XX", "ACK_ORPHAN", "ACK_AMBIGUOUS"}:
            continue
        refs = _refs(transaction, "request_event_references")
        if not refs:
            continue
        ack = by_reference.get(refs[0])
        if ack is None or ack.get("cseq_method") != "ACK":
            continue
        candidates = [
            dialog
            for dialog in dialogs
            if dialog["state"] == "CONFIRMED"
            and dialog["capture"] == ack["capture"]
            and dialog["call_id"] == ack.get("call_id")
            and dialog["initiator_tag"] == ack.get("from_tag")
            and dialog["remote_tag"] == ack.get("to_tag")
            and dialog["invite_cseq"] == ack.get("cseq_number")
            and _present(dialog["invite_cseq"])
        ]
        if len(candidates) == 1:
            dialog = candidates[0]
            dialog["ack_refs"].append(refs[0])
            dialog["basis"].append("dialog_scoped_2xx_ack")
            _add_reference(dialog, refs[0])
            continue
        if len(candidates) > 1:
            ambiguous.append(
                _ambiguous(
                    reference=ack["source_reference"],
                    capture=ack["capture"],
                    frame=ack["frame"],
                    occurrence=ack["occurrence"],
                    transaction_reference=transaction["transaction_reference"],
                    reason="MULTIPLE_DIALOG_CANDIDATES",
                    candidates=[dialog["reference"] for dialog in candidates],
                    conflicts=["MULTIPLE_DIALOG_CANDIDATES"],
                )
            )
        else:
            unbound.append(
                _unbound(
                    reference=ack["source_reference"],
                    capture=ack["capture"],
                    frame=ack["frame"],
                    occurrence=ack["occurrence"],
                    identity_status="NOT_ESTABLISHED",
                    reason="CONFIRMING_RESPONSE_NOT_OBSERVED",
                    event_references=refs,
                    transaction_references=[transaction["transaction_reference"]],
                    tag_pair_observed=all(
                        _present(ack.get(field)) for field in ("call_id", "from_tag", "to_tag")
                    ),
                    missing=["CONFIRMING_RESPONSE_NOT_OBSERVED"],
                )
            )

    # Associate in-dialog requests to one dialog.
    for transaction in transactions:
        method = transaction["transaction_method"]
        if method in UNSUPPORTED_DIALOG_METHODS:
            refs = _refs(transaction, "request_event_references")
            if refs and refs[0] in by_reference:
                request = by_reference[refs[0]]
                unbound.append(
                    _unbound(
                        reference=request["source_reference"],
                        capture=request["capture"],
                        frame=request["frame"],
                        occurrence=request["occurrence"],
                        identity_status="NOT_ESTABLISHED",
                        reason="UNSUPPORTED_SUBSCRIPTION_DIALOG",
                        event_references=refs,
                        transaction_references=[transaction["transaction_reference"]],
                        tag_pair_observed=True,
                        missing=["SUBSCRIPTION_DIALOG_UNSUPPORTED"],
                    )
                )
            continue
        if method not in IN_DIALOG_METHODS:
            continue
        if transaction["transaction_type"] not in {"NON_INVITE", "INVITE"}:
            continue
        refs = _refs(transaction, "request_event_references")
        if not refs or refs[0] not in by_reference:
            continue
        request = by_reference[refs[0]]
        if method == "INVITE" and not _present(request.get("to_tag")):
            continue
        if not all(
            _present(request.get(field)) for field in ("call_id", "from_tag", "to_tag")
        ):
            unbound.append(
                _unbound(
                    reference=request["source_reference"],
                    capture=request["capture"],
                    frame=request["frame"],
                    occurrence=request["occurrence"],
                    identity_status="INSUFFICIENT_EVIDENCE",
                    reason="MISSING_DIALOG_IDENTITY",
                    event_references=refs,
                    transaction_references=[transaction["transaction_reference"]],
                    tag_pair_observed=False,
                    missing=[
                        label
                        for label, field in (
                            ("CALL_ID_NOT_OBSERVED", "call_id"),
                            ("FROM_TAG_NOT_OBSERVED", "from_tag"),
                            ("TO_TAG_NOT_OBSERVED", "to_tag"),
                        )
                        if not _present(request.get(field))
                    ],
                )
            )
            continue
        tags = {request["from_tag"], request["to_tag"]}
        candidates = dialogs_for(request["capture"], request["call_id"], tags)
        if len(candidates) == 1:
            dialog = candidates[0]
            dialog["in_dialog_transactions"].append(transaction["transaction_reference"])
            if method == "BYE":
                dialog["bye_transactions"].append(transaction["transaction_reference"])
            direction = (
                "ORIGINAL"
                if request["from_tag"] == dialog["initiator_tag"]
                else "REVERSE"
                if request["from_tag"] == dialog["remote_tag"]
                else "UNKNOWN"
            )
            if direction == "UNKNOWN":
                dialog["conflicts"].append("TAG_PAIR_MISMATCH")
            else:
                dialog["directions"].append(direction)
                if _present(request.get("cseq_number")):
                    dialog["cseq"][direction].append(request["cseq_number"])
            dialog["basis"].append(f"in_dialog_{method.lower()}")
            for reference in refs:
                _add_reference(dialog, reference)
            for reference in _refs(transaction, "response_event_references"):
                _add_reference(dialog, reference)
            if method == "BYE":
                statuses = list(transaction["final_response_status_codes"])
                if any(200 <= status < 300 for status in statuses) and dialog["state"] == "CONFIRMED":
                    dialog["state"] = "TERMINATED"
                    dialog["basis"].append("bye_2xx_response")
                else:
                    dialog["basis"].append("termination_signaling_only")
                    if not statuses:
                        dialog["missing"].append("BYE_RESPONSE_NOT_OBSERVED")
                    elif not any(200 <= status < 300 for status in statuses):
                        dialog["limitations"].append(
                            "the BYE received a non-2xx final response; dialog termination is not established"
                        )
        elif len(candidates) > 1:
            ambiguous.append(
                _ambiguous(
                    reference=request["source_reference"],
                    capture=request["capture"],
                    frame=request["frame"],
                    occurrence=request["occurrence"],
                    transaction_reference=transaction["transaction_reference"],
                    reason="MULTIPLE_DIALOG_CANDIDATES",
                    candidates=[dialog["reference"] for dialog in candidates],
                    conflicts=["MULTIPLE_DIALOG_CANDIDATES"],
                )
            )
        else:
            unbound.append(
                _unbound(
                    reference=request["source_reference"],
                    capture=request["capture"],
                    frame=request["frame"],
                    occurrence=request["occurrence"],
                    identity_status="NOT_ESTABLISHED",
                    reason="DIALOG_CREATOR_NOT_OBSERVED",
                    event_references=refs,
                    transaction_references=[transaction["transaction_reference"]],
                    tag_pair_observed=True,
                    missing=["INITIAL_INVITE_NOT_OBSERVED"],
                )
            )

    dialogs.sort(key=lambda dialog: (dialog["first_frame"], dialog["reference"]))
    unbound.sort(key=lambda item: item["observation_reference"])
    ambiguous.sort(key=lambda item: item["observation_reference"])
    return dialogs, unbound, ambiguous


def _cseq_observations(dialog: dict[str, Any]) -> dict[str, Any]:
    original = sorted(set(dialog["cseq"]["ORIGINAL"]))[:MAX_CSEQ_VALUES]
    reverse = sorted(set(dialog["cseq"]["REVERSE"]))[:MAX_CSEQ_VALUES]
    all_values = sorted(set(original + reverse))
    gap = any(right - left > 1 for left, right in zip(all_values, all_values[1:]))
    return {
        "initiator_direction_values": original,
        "responder_direction_values": reverse,
        "sequence_gap_observed": gap,
        "assessment": "DIRECTION_AWARE_OBSERVATION_ONLY",
    }


def _public_dialog(dialog: dict[str, Any]) -> dict[str, Any]:
    state = dialog["state"]
    if dialog["bye_transactions"]:
        lifecycle = "TERMINATION_SIGNALING_OBSERVED"
    elif state == "CONFIRMED":
        lifecycle = "CONFIRMATION_OBSERVED"
    elif dialog["early_refs"]:
        lifecycle = "EARLY_OBSERVED"
    else:
        lifecycle = "UNRESOLVED"
    missing = list(dialog["missing"])
    if dialog["bye_transactions"] and not dialog["confirm_refs"]:
        missing.append("CONFIRMING_RESPONSE_NOT_OBSERVED")
    if not dialog["early_refs"] and not dialog["confirm_refs"]:
        missing.append("PROVISIONAL_RESPONSE_NOT_OBSERVED")
    associated, omitted = _bounded(dialog["associated_refs"])
    limitations = list(dict.fromkeys(dialog["limitations"] + list(BASE_LIMITATIONS)))
    return {
        "dialog_reference": dialog["reference"],
        "identity_status": "ESTABLISHED",
        "dialog_state": state,
        "observed_lifecycle_status": lifecycle,
        "initiating_transaction_reference": dialog["initiating_transaction"],
        "early_response_event_references": _bounded(dialog["early_refs"])[0],
        "confirming_response_event_references": _bounded(dialog["confirm_refs"])[0],
        "ack_event_references": _bounded(dialog["ack_refs"])[0],
        "in_dialog_transaction_references": _bounded(dialog["in_dialog_transactions"])[0],
        "bye_transaction_references": _bounded(dialog["bye_transactions"])[0],
        "associated_message_event_references": associated,
        "omitted_associated_event_count": omitted,
        "first_observed_frame": dialog["first_frame"],
        "last_observed_frame": dialog["last_frame"],
        "fork_branch_reference": dialog["fork_reference"],
        "lifecycle_evidence": sorted(dict.fromkeys(dialog["basis"])),
        "direction_observations": sorted(dict.fromkeys(dialog["directions"])),
        "cseq_observations": _cseq_observations(dialog),
        "missing_evidence": sorted(dict.fromkeys(missing)),
        "conflict_findings": sorted(dict.fromkeys(dialog["conflicts"])),
        "limitations": _bounded(limitations, MAX_LIMITATIONS)[0],
        "not_confirmed": list(NOT_CONFIRMED),
        "evidence_class": "DERIVED",
    }


def build_dialog_document(
    messages: list[dict[str, Any]],
    transaction_document: dict[str, Any],
    *,
    capture_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build dialog evidence from the same capture-local message and transaction set."""
    if not isinstance(messages, list) or not messages:
        raise DialogError("dialog analysis requires SIP message records")
    if not isinstance(transaction_document, dict):
        raise DialogError("dialog analysis requires a transaction document")
    validate_transaction_document(transaction_document, messages)
    transactions = transaction_document["transactions"]
    captures = sorted({_match(message)["capture"] for message in messages})
    dialog_captures = sorted(
        {
            _capture_of(reference)
            for transaction in transactions
            for reference in _refs(transaction, "request_event_references")
        }
    )
    if any(capture not in captures for capture in dialog_captures):
        raise DialogError("transaction evidence refers to a capture absent from the message set")

    dialogs, unbound, ambiguous = _build_dialogs(messages, transaction_document)
    public = [_public_dialog(dialog) for dialog in dialogs]
    state_counts: dict[str, int] = {}
    lifecycle_counts: dict[str, int] = {}
    for dialog in public:
        state_counts[dialog["dialog_state"]] = state_counts.get(dialog["dialog_state"], 0) + 1
        lifecycle_counts[dialog["observed_lifecycle_status"]] = (
            lifecycle_counts.get(dialog["observed_lifecycle_status"], 0) + 1
        )
    forked = len(
        {
            dialog["initiating_transaction_reference"]
            for dialog in public
            if sum(
                1
                for other in public
                if other["initiating_transaction_reference"]
                == dialog["initiating_transaction_reference"]
            )
            > 1
        }
    )
    provenance = {
        "capture_files": captures,
        "input_format": (capture_provenance or {}).get("input_format"),
        "capture_sha256": (capture_provenance or {}).get("capture_sha256"),
        "decoder": (capture_provenance or {}).get("decoder"),
        "source_event_count": len(messages),
        "accepted_transaction_count": len(transactions),
        "capture_completeness": (capture_provenance or {}).get("capture_completeness", "UNKNOWN"),
    }
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": DIALOG_SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "capture_provenance": provenance,
        "dialog_count": len(public),
        "dialog_summary": {
            "identity_status_counts": {"ESTABLISHED": len(public)} if public else {},
            "dialog_state_counts": dict(sorted(state_counts.items())),
            "observed_lifecycle_status_counts": dict(sorted(lifecycle_counts.items())),
            "forked_initiating_transaction_count": forked,
            "unbound_observation_count": len(unbound),
            "ambiguous_observation_count": len(ambiguous),
        },
        "dialogs": public,
        "unbound_observations": unbound,
        "ambiguous_observations": ambiguous,
        "limitations": list(BASE_LIMITATIONS),
        "not_confirmed": list(NOT_CONFIRMED),
    }


def validate_dialog_document(
    document: dict[str, Any],
    messages: list[dict[str, Any]] | None = None,
    transaction_document: dict[str, Any] | None = None,
) -> None:
    """Validate dialog cross-field semantics beyond structural JSON Schema."""
    if not isinstance(document, dict):
        raise DialogError("dialog document must be an object")
    for field in (
        "analysis_name",
        "analysis_version",
        "protocol",
        "capture_provenance",
        "dialog_count",
        "dialog_summary",
        "dialogs",
        "unbound_observations",
        "ambiguous_observations",
        "limitations",
        "not_confirmed",
    ):
        if field not in document:
            raise DialogError(f"dialog document is missing {field}")
    if document["analysis_name"] != ANALYSIS_NAME:
        raise DialogError("dialog document analysis_name is not accepted")
    if document["protocol"] != PROTOCOL:
        raise DialogError("dialog document protocol is not SIP")
    if document["analysis_version"] != DIALOG_SCHEMA_VERSION:
        raise DialogError("dialog document version is not accepted")
    if document["dialog_count"] != len(document["dialogs"]):
        raise DialogError("dialog_count does not match the dialog array")

    dialog_references: set[str] = set()
    assigned_events: set[str] = set()
    assigned_transactions: set[str] = set()
    known_transactions: set[str] = set()
    known_events: set[str] = set()
    if messages is not None:
        known_events = {_match(message)["source_reference"] for message in messages}
    if transaction_document is not None:
        known_transactions = {
            transaction["transaction_reference"]
            for transaction in transaction_document["transactions"]
        }

    for dialog in document["dialogs"]:
        reference = dialog.get("dialog_reference")
        if not isinstance(reference, str) or not DIALOG_REFERENCE_PATTERN.fullmatch(reference):
            raise DialogError("invalid dialog reference")
        if reference in dialog_references:
            raise DialogError("duplicate dialog reference")
        dialog_references.add(reference)
        if dialog.get("identity_status") not in IDENTITY_STATUSES:
            raise DialogError("invalid dialog identity status")
        if dialog.get("dialog_state") not in DIALOG_STATES:
            raise DialogError("invalid dialog state")
        if dialog.get("observed_lifecycle_status") not in LIFECYCLE_STATUSES:
            raise DialogError("invalid dialog lifecycle status")
        if dialog.get("dialog_state") == "TERMINATED":
            if not dialog.get("bye_transaction_references"):
                raise DialogError("TERMINATED requires a BYE transaction reference")
            if not dialog.get("confirming_response_event_references"):
                raise DialogError("TERMINATED requires confirmed dialog evidence")
        fork = dialog.get("fork_branch_reference")
        if not isinstance(fork, str) or not FORK_REFERENCE_PATTERN.fullmatch(fork):
            raise DialogError("invalid fork branch reference")
        initiating = dialog.get("initiating_transaction_reference")
        if not isinstance(initiating, str) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(initiating):
            raise DialogError("invalid initiating transaction reference")
        if known_transactions and initiating not in known_transactions:
            raise DialogError("initiating transaction reference is not present")
        if not dialog.get("confirming_response_event_references") and not dialog.get(
            "early_response_event_references"
        ):
            raise DialogError("a dialog requires at least one observed response")
        associated = list(dialog.get("associated_message_event_references") or [])
        for key in (
            "early_response_event_references",
            "confirming_response_event_references",
            "ack_event_references",
        ):
            for event_reference in dialog.get(key) or []:
                if event_reference not in associated:
                    raise DialogError(f"{key} is not part of the associated references")
        for event_reference in associated:
            if not isinstance(event_reference, str) or not EVENT_REFERENCE_PATTERN.fullmatch(
                event_reference
            ):
                raise DialogError("invalid associated event reference")
            if event_reference in assigned_events:
                continue
            assigned_events.add(event_reference)
            if known_events and event_reference not in known_events:
                raise DialogError("associated event reference is not present")
        dialog_transactions: set[str] = set()
        for key in ("in_dialog_transaction_references", "bye_transaction_references"):
            for transaction_reference in dialog.get(key) or []:
                if not isinstance(
                    transaction_reference, str
                ) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(transaction_reference):
                    raise DialogError(f"invalid transaction reference in {key}")
                if transaction_reference in dialog_transactions:
                    continue
                if transaction_reference in assigned_transactions:
                    raise DialogError("a transaction is assigned to more than one dialog")
                dialog_transactions.add(transaction_reference)
                assigned_transactions.add(transaction_reference)
                if known_transactions and transaction_reference not in known_transactions:
                    raise DialogError(f"{key} is not present in the transaction document")

    for observation in document["unbound_observations"] + document["ambiguous_observations"]:
        reference = observation.get("observation_reference")
        if not isinstance(reference, str) or not OBSERVATION_REFERENCE_PATTERN.fullmatch(reference):
            raise DialogError("invalid observation reference")
        for event_reference in observation.get("event_references") or []:
            if known_events and event_reference not in known_events:
                raise DialogError("unbound observation event reference is not present")
        for transaction_reference in observation.get("transaction_references") or [
            observation.get("transaction_reference")
        ]:
            if transaction_reference is None:
                continue
            if known_transactions and transaction_reference not in known_transactions:
                raise DialogError("observation transaction reference is not present")
        for candidate in observation.get("candidate_dialog_references") or []:
            if candidate not in dialog_references:
                raise DialogError("candidate dialog reference is not present")