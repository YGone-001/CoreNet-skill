#!/usr/bin/env python3
"""Protocol-local SIP transaction correlation.

Correlation follows RFC 3261 transaction identity: top Via branch, top Via
sent-by and request method for a client/server transaction, with CSeq method and
number, Call-ID and From tag used as consistency evidence. A response is matched
to a request transaction only through those reviewed fields; Call-ID alone is
never a transaction identity.

Raw matching values are consumed from the in-memory message records produced by
the extractor and are never copied into the transaction document. The document
publishes only opaque transaction references derived from source event references,
transaction state, matching evidence, retransmission classification and explicit
missing evidence.

This module owns transaction correlation only. It does not own SIP dialogs,
cross-protocol correlation, IMS registration, authentication, calls, SDP or RTP.
"""

from __future__ import annotations

import re
from typing import Any

PROTOCOL = "SIP"
TRANSACTION_SCHEMA_VERSION = "1.1.0"
ANALYSIS_NAME = "sip-transactions"

MAX_TRANSACTION_EVENT_REFERENCES = 64
MAX_TRANSACTION_LIMITATIONS = 16

MAGIC_COOKIE = "z9hG4bK"
MATCHING_MODES = ("MODERN", "LEGACY", "UNAVAILABLE")
TRANSACTION_ROLES = ("CLIENT", "SERVER", "UNKNOWN")

TRANSACTION_REFERENCE_PATTERN = re.compile(r"^sip-transaction:.+:(?:request|response):[0-9]+\.[0-9]+$")
EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")

TRANSACTION_TYPES = (
    "INVITE",
    "NON_INVITE",
    "CANCEL",
    "ACK_2XX",
    "ACK_ORPHAN",
    "ACK_AMBIGUOUS",
    "RESPONSE_ONLY",
    "AMBIGUOUS",
    "UNKNOWN",
)
OBSERVED_EVIDENCE_STATUSES = (
    "REQUEST_OBSERVED",
    "PROVISIONAL_RESPONSE_OBSERVED",
    "FINAL_RESPONSE_OBSERVED",
    "NON_2XX_ACK_OBSERVED",
    "CANCEL_RESPONSE_SEQUENCE_OBSERVED",
    "OPEN_IN_CAPTURE",
    "RESPONSE_ONLY",
    "REQUEST_ONLY",
    "AMBIGUOUS",
    "INCOMPLETE_EVIDENCE",
)
RFC_TRANSACTION_STATES = (
    "TRYING",
    "PROCEEDING",
    "COMPLETED",
    "CONFIRMED",
    "TERMINATED",
    "ACCEPTED",
)
TRANSACTION_STATES = OBSERVED_EVIDENCE_STATUSES + RFC_TRANSACTION_STATES
MATCHING_STATUSES = (
    "MATCHED",
    "PARTIALLY_MATCHED",
    "REQUEST_ONLY",
    "RESPONSE_ONLY",
    "AMBIGUOUS",
    "NOT_ESTABLISHED",
)
CAPTURE_COMPLETENESS = ("COMPLETE", "PARTIAL", "TRUNCATED", "UNKNOWN")
MESSAGE_CLASSIFICATIONS = (
    "ORIGINAL",
    "ORIGINAL_RESPONSE",
    "EXACT_RETRANSMISSION",
    "RESPONSE_RETRANSMISSION",
    "RETRANSMISSION_CANDIDATE",
    "FIELD_EQUIVALENT_OBSERVATION",
    "FINGERPRINT_UNAVAILABLE",
    "REPEATED_OBSERVATION",
    "REPEATED_TCP_OBSERVATION",
    "DISTINCT_RESPONSE_BRANCH",
    "CONFLICTING_REQUEST",
    "ASSOCIATED_CONTROL",
)
MESSAGE_ROLES = ("REQUEST", "RESPONSE", "CONTROL")
MISSING_EVIDENCE = (
    "REQUEST_NOT_OBSERVED",
    "FINAL_RESPONSE_NOT_OBSERVED",
    "ACK_NOT_OBSERVED",
    "CANCEL_RESPONSE_NOT_OBSERVED",
    "INVITE_TRANSACTION_NOT_OBSERVED",
    "VIA_BRANCH_NOT_OBSERVED",
    "VIA_SENT_BY_NOT_OBSERVED",
    "CSEQ_NOT_OBSERVED",
    "CALL_ID_NOT_OBSERVED",
    "FROM_TAG_NOT_OBSERVED",
    "REQUEST_URI_NOT_OBSERVED",
    "FROM_VALUE_NOT_OBSERVED",
    "TO_VALUE_NOT_OBSERVED",
    "CAPTURE_TRUNCATED",
    "CONSISTENT_REQUEST_IDENTITY",
    "SINGLE_REQUEST_TRANSACTION",
    "SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED",
    "DIALOG_ASSOCIATION_UNAVAILABLE",
    "TRANSACTION_ROLE_UNKNOWN",
    "RETRANSMISSION_FINGERPRINT_INCOMPLETE",
    "TRANSACTION_TERMINATION_NOT_ESTABLISHED",
)
CONFLICT_FINDINGS = (
    "CSEQ_MISMATCH",
    "CSEQ_METHOD_MISMATCH",
    "CALL_ID_MISMATCH",
    "FROM_TAG_MISMATCH",
    "FROM_VALUE_MISMATCH",
    "TO_VALUE_MISMATCH",
    "TO_TAG_MISMATCH",
    "REQUEST_URI_MISMATCH",
    "VIA_BRANCH_MISMATCH",
    "VIA_SENT_BY_MISMATCH",
    "METHOD_MISMATCH",
    "MESSAGE_CONTENT_MISMATCH",
)

BASE_NOT_CONFIRMED = (
    "SIP_DIALOG",
    "IMS_REGISTRATION",
    "IMS_AUTHENTICATION",
    "IMS_CALL",
    "SIP_TIMEOUT",
    "CROSS_PROTOCOL_ASSOCIATION",
)


class TransactionError(Exception):
    pass


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _event(message: dict[str, Any]) -> dict[str, Any]:
    return message["event"]


def _match(message: dict[str, Any]) -> dict[str, Any]:
    return message["match"]


def _order(message: dict[str, Any]) -> tuple[int, int]:
    match = _match(message)
    return int(match["frame"]), int(match["occurrence"])


def _sort(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(messages, key=_order)


def _same(left: Any, right: Any) -> bool:
    return left == right


def _present(value: Any) -> bool:
    return value is not None and value != ""


def _add_unique(target: list[str], value: str) -> None:
    if value not in target:
        target.append(value)


def _matching_mode(match: dict[str, Any]) -> str:
    branch = match.get("via_branch")
    if not _present(branch):
        return "UNAVAILABLE"
    return "MODERN" if str(branch).startswith(MAGIC_COOKIE) else "LEGACY"


def _top_via_value(match: dict[str, Any]) -> tuple[Any, ...] | str | None:
    value = match.get("top_via")
    if _present(value):
        return value
    branch = match.get("via_branch")
    sent_by = match.get("via_sent_by")
    if not (_present(branch) and _present(sent_by)):
        return None
    return (branch, sent_by, match.get("via_transport"))


def _address_value(match: dict[str, Any], side: str) -> tuple[Any, Any] | None:
    uri = match.get(f"{side}_uri")
    if not _present(uri):
        return None
    return (uri, match.get(f"{side}_tag"))


def _request_key(match: dict[str, Any]) -> tuple[Any, ...] | None:
    mode = _matching_mode(match)
    method = match.get("method")
    branch = match.get("via_branch")
    sent_by = match.get("via_sent_by")
    if mode == "MODERN":
        if not (_present(branch) and _present(sent_by) and _present(method)):
            return None
        return (mode, match.get("capture"), branch, sent_by, method)
    if mode == "LEGACY":
        top_via = _top_via_value(match)
        from_value = _address_value(match, "from")
        to_value = _address_value(match, "to")
        request_uri = match.get("request_uri")
        call_id = match.get("call_id")
        cseq_number = match.get("cseq_number")
        cseq_method = match.get("cseq_method")
        if not (
            _present(request_uri)
            and from_value is not None
            and to_value is not None
            and _present(call_id)
            and cseq_number is not None
            and _present(cseq_method)
            and top_via is not None
        ):
            return None
        return (
            mode,
            match.get("capture"),
            request_uri,
            to_value,
            from_value,
            call_id,
            cseq_number,
            cseq_method,
            top_via,
        )
    return None


def _transaction_marker(match: dict[str, Any]) -> tuple[Any, ...] | None:
    """Key shared by a request transaction and its responses."""
    mode = _matching_mode(match)
    if mode == "MODERN":
        branch = match.get("via_branch")
        sent_by = match.get("via_sent_by")
        method = match.get("cseq_method") or match.get("method")
        if not (_present(branch) and _present(sent_by) and _present(method)):
            return None
        return (mode, match.get("capture"), branch, sent_by, method)
    if mode == "LEGACY":
        top_via = _top_via_value(match)
        from_value = _address_value(match, "from")
        call_id = match.get("call_id")
        cseq_number = match.get("cseq_number")
        method = match.get("cseq_method") or match.get("method")
        if not (
            from_value is not None
            and _present(call_id)
            and cseq_number is not None
            and _present(method)
            and top_via is not None
        ):
            return None
        return (mode, match.get("capture"), from_value, call_id, cseq_number, method, top_via)
    return None


def _request_identity(match: dict[str, Any]) -> tuple[Any, ...]:
    return (
        match.get("cseq_number"),
        match.get("cseq_method"),
        match.get("call_id"),
        match.get("from_tag"),
        match.get("request_uri"),
        _address_value(match, "to"),
        _top_via_value(match),
    )


def _response_identity(match: dict[str, Any]) -> tuple[Any, ...]:
    return (
        match.get("cseq_number"),
        match.get("cseq_method"),
        match.get("call_id"),
        match.get("from_tag"),
        match.get("status_code"),
        match.get("to_tag"),
        match.get("transport_protocol"),
    )


def _transaction_reference(kind: str, match: dict[str, Any]) -> str:
    return (
        f"sip-transaction:{match['capture']}:{kind}:"
        f"{match['frame']}.{match['occurrence']}"
    )


def _new_transaction(
    reference: str,
    transaction_type: str,
    method: str | None,
    *,
    identity_available: bool,
) -> dict[str, Any]:
    return {
        "reference": reference,
        "type": transaction_type,
        "method": method,
        "requests": [],
        "responses": [],
        "control": [],
        "state": "INCOMPLETE_EVIDENCE",
        "observed_evidence_status": "INCOMPLETE_EVIDENCE",
        "transaction_role": "UNKNOWN",
        "rfc_transaction_state": None,
        "matching_mode": None,
        "state_semantics": "EVIDENCE_DERIVED",
        "matching_status": "NOT_ESTABLISHED",
        "basis": [],
        "missing": [],
        "conflicts": [],
        "limitations": [],
        "partial": False,
        "identity_available": identity_available,
        "identity": None,
        "associated_reference": None,
        "associated_references": [],
        "candidate_references": [],
        "termination_basis": None,
        "cancel_sequence_observed": False,
        "cancel_final_response_status": None,
        "invite_final_response_status": None,
        "cancel_invite_association_status": None,
        "invite_transaction_termination_established": False,
        "classifications": [],
        "retransmission_refs": [],
        "retransmission_candidate_refs": [],
        "repeated_refs": [],
        "conflicting_refs": [],
        "selected_final_ref": None,
        "final_status_codes": [],
        "final_response_refs": [],
        "provisional_response_refs": [],
        "response_branch_count": 0,
        "final_response_group_count": 0,
    }


def _base_limitations(transaction_type: str) -> list[str]:
    limitations = [
        "SIP transaction correlation is protocol-local and is not SIP dialog correlation, cross-protocol correlation or IMS procedure analysis",
        "raw Call-ID, Via branch, tags, URIs and credentials are used only in memory and are never published",
    ]
    if transaction_type == "INVITE":
        limitations.append(
            "an unobserved final response or ACK is capture incompleteness, not proof of a transaction timeout or network failure"
        )
    if transaction_type == "ACK_2XX":
        limitations.append(
            "ACK for a 2xx INVITE is an independent request transaction; dialog association is unavailable in this phase"
        )
    if transaction_type == "CANCEL":
        limitations.append(
            "a 200 OK to CANCEL acknowledges the CANCEL request only; it does not by itself prove that the INVITE was cancelled"
        )
    return limitations


def _classify_duplicates(
    transaction: dict[str, Any],
    messages: list[dict[str, Any]],
    *,
    response: bool,
) -> None:
    ordered = _sort(messages)
    seen: dict[tuple[Any, ...], str] = {}
    for index, message in enumerate(ordered):
        match = _match(message)
        role = "RESPONSE" if response else "REQUEST"
        fingerprint = match.get("content_fingerprint")
        completeness = match.get("fingerprint_completeness", "UNAVAILABLE")
        if index == 0:
            classification = "ORIGINAL_RESPONSE" if response else "ORIGINAL"
            seen[fingerprint] = completeness
        elif fingerprint in seen:
            if match.get("transport_protocol") == "TCP":
                classification = "REPEATED_TCP_OBSERVATION"
                transaction["repeated_refs"].append(match["source_reference"])
            elif completeness == "FULL_MESSAGE":
                classification = "RESPONSE_RETRANSMISSION" if response else "EXACT_RETRANSMISSION"
                transaction["retransmission_refs"].append(match["source_reference"])
            elif completeness == "UNAVAILABLE":
                classification = "FINGERPRINT_UNAVAILABLE"
                _add_unique(transaction["missing"], "RETRANSMISSION_FINGERPRINT_INCOMPLETE")
            else:
                classification = "RETRANSMISSION_CANDIDATE"
                transaction["retransmission_candidate_refs"].append(match["source_reference"])
                _add_unique(transaction["missing"], "RETRANSMISSION_FINGERPRINT_INCOMPLETE")
        else:
            seen[fingerprint] = completeness
            classification = "DISTINCT_RESPONSE_BRANCH" if response else "CONFLICTING_REQUEST"
            if not response:
                transaction["conflicting_refs"].append(match["source_reference"])
                _add_unique(transaction["conflicts"], "MESSAGE_CONTENT_MISMATCH")
        transaction["classifications"].append(
            {"event_reference": match["source_reference"], "role": role, "classification": classification}
        )


def _finalize_responses(transaction: dict[str, Any]) -> None:
    if not transaction["responses"]:
        if transaction["conflicts"]:
            transaction["matching_status"] = "NOT_ESTABLISHED"
        else:
            transaction["matching_status"] = "REQUEST_ONLY"
        _add_unique(transaction["missing"], "FINAL_RESPONSE_NOT_OBSERVED")
        return

    ordered = _sort(transaction["responses"])
    _classify_duplicates(transaction, ordered, response=True)
    provisional = [message for message in ordered if (message["match"].get("status_code") or 0) < 200]
    finals = [message for message in ordered if (message["match"].get("status_code") or 0) >= 200]
    transaction["provisional_response_refs"] = [
        message["match"]["source_reference"] for message in provisional
    ]
    transaction["final_response_refs"] = [
        message["match"]["source_reference"] for message in finals
    ]
    final_groups: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = {}
    for message in finals:
        key = (
            message["match"].get("status_code"),
            message["match"].get("to_tag"),
            message["match"].get("content_fingerprint"),
        )
        final_groups.setdefault(key, []).append(message)
    tags = {
        message["match"].get("to_tag")
        for message in ordered
        if message["match"].get("to_tag") is not None
    }
    transaction["response_branch_count"] = len(tags)
    transaction["final_response_group_count"] = len(final_groups)
    transaction["final_status_codes"] = sorted(
        {
            message["match"]["status_code"]
            for message in finals
            if message["match"].get("status_code") is not None
        }
    )
    if len(final_groups) == 1:
        transaction["selected_final_ref"] = _sort(next(iter(final_groups.values())))[0]["match"][
            "source_reference"
        ]
    else:
        transaction["selected_final_ref"] = None

    if not finals:
        transaction["matching_status"] = "PARTIALLY_MATCHED"
        _add_unique(transaction["missing"], "FINAL_RESPONSE_NOT_OBSERVED")
    else:
        transaction["matching_status"] = "PARTIALLY_MATCHED" if transaction["partial"] else "MATCHED"
        if len(final_groups) > 1:
            _add_unique(transaction["missing"], "SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED")
            transaction["limitations"].append(
                "multiple distinct final responses are preserved; forked branches are not collapsed into a SIP dialog"
            )
        statuses = transaction["final_status_codes"]
        if transaction["type"] == "INVITE":
            if any(200 <= status < 300 for status in statuses):
                _add_unique(transaction["missing"], "DIALOG_ASSOCIATION_UNAVAILABLE")
                transaction["limitations"].append(
                    "a 2xx INVITE response is protocol evidence only; ACK and dialog semantics are outside this phase"
                )
            if any(status >= 300 for status in statuses):
                _add_unique(transaction["missing"], "ACK_NOT_OBSERVED")
        if any(200 <= status < 300 for status in statuses) and any(
            status >= 300 for status in statuses
        ):
            _add_unique(transaction["missing"], "SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED")

    if transaction["responses"]:
        transaction["limitations"].append(
            "status codes are observed protocol evidence; they do not prove an IMS registration, authentication or call outcome"
        )


def _capture_completeness(transaction: dict[str, Any]) -> str:
    members = transaction["requests"] + transaction["responses"] + transaction["control"]
    if not members:
        return "UNKNOWN"
    if any(_event(message)["message_completeness"] == "TRUNCATED" for message in members):
        return "TRUNCATED"
    has_request = bool(transaction["requests"])
    has_final = bool(transaction["final_response_refs"])
    if has_request and has_final:
        return "COMPLETE"
    return "PARTIAL"


def _transaction_role(transaction: dict[str, Any]) -> str:
    members = transaction["requests"] + transaction["responses"] + transaction["control"]
    roles = {_match(message).get("observation_role", "UNKNOWN") for message in members}
    if roles == {"CLIENT"}:
        return "CLIENT"
    if roles == {"SERVER"}:
        return "SERVER"
    return "UNKNOWN"


def _observed_evidence_status(transaction: dict[str, Any]) -> str:
    if transaction["conflicts"]:
        return "INCOMPLETE_EVIDENCE"
    if transaction["type"] == "ACK_ORPHAN":
        return "REQUEST_ONLY"
    if transaction["matching_status"] == "NOT_ESTABLISHED":
        return "INCOMPLETE_EVIDENCE"
    if transaction["type"] == "AMBIGUOUS":
        return "AMBIGUOUS"
    if not transaction["requests"] and transaction["responses"]:
        return "RESPONSE_ONLY"
    if not transaction["requests"] and not transaction["responses"]:
        return "INCOMPLETE_EVIDENCE"
    if transaction.get("cancel_sequence_observed"):
        return "CANCEL_RESPONSE_SEQUENCE_OBSERVED"
    if transaction["control"] and any(
        status >= 300 for status in transaction["final_status_codes"]
    ):
        return "NON_2XX_ACK_OBSERVED"
    if transaction["final_status_codes"]:
        return "FINAL_RESPONSE_OBSERVED"
    if transaction["provisional_response_refs"]:
        return "PROVISIONAL_RESPONSE_OBSERVED"
    if not transaction["responses"]:
        return "OPEN_IN_CAPTURE" if transaction["type"] == "INVITE" else "REQUEST_OBSERVED"
    return "INCOMPLETE_EVIDENCE"


def _rfc_transaction_state(transaction: dict[str, Any]) -> str | None:
    """Project an RFC 3261/RFC 6026 state only when the observed role is known."""
    role = transaction["transaction_role"]
    if role not in {"CLIENT", "SERVER"}:
        return None
    statuses = transaction["final_status_codes"]
    has_2xx = any(200 <= status < 300 for status in statuses)
    has_non_2xx = any(status >= 300 for status in statuses)
    has_provisional = bool(transaction["provisional_response_refs"])
    if transaction["type"] == "INVITE":
        if has_2xx:
            return "ACCEPTED"
        if has_non_2xx:
            if role == "SERVER":
                return "CONFIRMED" if transaction["control"] else "COMPLETED"
            return "TERMINATED" if transaction["control"] else "COMPLETED"
        return "PROCEEDING" if has_provisional else "TRYING"
    if transaction["type"] == "NON_INVITE":
        if statuses:
            return "COMPLETED"
        return "PROCEEDING" if has_provisional else "TRYING"
    return None


def _finalize_state(transaction: dict[str, Any]) -> None:
    transaction["transaction_role"] = _transaction_role(transaction)
    transaction["observed_evidence_status"] = _observed_evidence_status(transaction)
    transaction["rfc_transaction_state"] = _rfc_transaction_state(transaction)
    if transaction["rfc_transaction_state"] is not None:
        transaction["state_semantics"] = "RFC_STATE"
        transaction["state"] = transaction["rfc_transaction_state"]
    else:
        transaction["state_semantics"] = "EVIDENCE_ONLY"
        transaction["state"] = transaction["observed_evidence_status"]


def _finalize_common(transaction: dict[str, Any]) -> None:
    _finalize_state(transaction)
    transaction["basis"] = sorted(dict.fromkeys(transaction["basis"]))
    transaction["missing"] = sorted(dict.fromkeys(transaction["missing"]))
    transaction["conflicts"] = sorted(dict.fromkeys(transaction["conflicts"]))
    transaction["retransmission_refs"] = sorted(
        dict.fromkeys(transaction["retransmission_refs"]),
        key=_reference_order,
    )
    transaction["retransmission_candidate_refs"] = sorted(
        dict.fromkeys(transaction["retransmission_candidate_refs"]),
        key=_reference_order,
    )
    transaction["repeated_refs"] = sorted(
        dict.fromkeys(transaction["repeated_refs"]),
        key=_reference_order,
    )
    transaction["conflicting_refs"] = sorted(
        dict.fromkeys(transaction["conflicting_refs"]), key=_reference_order
    )
    limitations = _base_limitations(transaction["type"])
    for item in transaction["limitations"]:
        if item not in limitations:
            limitations.append(item)
    transaction["limitations"] = limitations[:MAX_TRANSACTION_LIMITATIONS]


def _reference_order(reference: str) -> tuple[int, int]:
    tail = reference.rsplit(":", 1)[-1]
    frame, _, occurrence = tail.partition(".")
    try:
        return int(frame), int(occurrence)
    except ValueError:
        return 0, 0


# ---------------------------------------------------------------------------
# Request transactions
# ---------------------------------------------------------------------------


def _request_transaction(group: list[dict[str, Any]], method: str) -> dict[str, Any]:
    ordered = _sort(group)
    first = ordered[0]
    match = _match(first)
    transaction_type = "INVITE" if method == "INVITE" else "NON_INVITE" if method != "CANCEL" else "CANCEL"
    transaction = _new_transaction(
        _transaction_reference("request", match),
        transaction_type,
        method,
        identity_available=True,
    )
    transaction["requests"] = ordered
    transaction["identity"] = match
    transaction["matching_mode"] = _matching_mode(match)
    if transaction["matching_mode"] == "MODERN":
        transaction["basis"].extend(
            [
                "rfc3261_magic_cookie_branch",
                "top_via_branch_match",
                "top_via_sent_by_match",
                "request_method_match",
            ]
        )
    else:
        transaction["basis"].extend(
            [
                "rfc2543_legacy_via_matching",
                "request_uri_match",
                "to_value_match",
                "from_value_match",
                "top_via_value_match",
            ]
        )
        for field, label in (
            ("request_uri", "REQUEST_URI_NOT_OBSERVED"),
            ("from_uri", "FROM_VALUE_NOT_OBSERVED"),
            ("to_uri", "TO_VALUE_NOT_OBSERVED"),
        ):
            if not _present(match.get(field)):
                _add_unique(transaction["missing"], label)
                transaction["partial"] = True
    if match.get("cseq_number") is not None:
        transaction["basis"].append("cseq_number_observed")
    else:
        _add_unique(transaction["missing"], "CSEQ_NOT_OBSERVED")
        transaction["partial"] = True
    if match.get("call_id") is None:
        _add_unique(transaction["missing"], "CALL_ID_NOT_OBSERVED")
        transaction["partial"] = True
    else:
        transaction["basis"].append("call_id_observed")
    if match.get("from_tag") is None:
        _add_unique(transaction["missing"], "FROM_TAG_NOT_OBSERVED")
        transaction["partial"] = True
    else:
        transaction["basis"].append("from_tag_observed")

    method_conflicts = [
        message
        for message in ordered
        if _match(message).get("cseq_method") != method
    ]
    if method_conflicts:
        transaction["matching_status"] = "NOT_ESTABLISHED"
        _add_unique(transaction["missing"], "CONSISTENT_REQUEST_IDENTITY")
        _add_unique(transaction["conflicts"], "METHOD_MISMATCH")
        _add_unique(transaction["conflicts"], "CSEQ_METHOD_MISMATCH")
        for message in method_conflicts:
            _add_unique(
                transaction["conflicting_refs"], _match(message)["source_reference"]
            )
        transaction["limitations"].append(
            "the request-line method contradicts the CSeq method; the observation is retained as incomplete evidence and is not a valid transaction identity"
        )
        identities = [_request_identity(_match(message)) for message in ordered]
        for index, message in enumerate(ordered):
            transaction["classifications"].append(
                {
                    "event_reference": _match(message)["source_reference"],
                    "role": "REQUEST",
                    "classification": "ORIGINAL"
                    if index == 0 and message not in method_conflicts
                    else "CONFLICTING_REQUEST",
                }
            )
        return transaction

    identities = [_request_identity(_match(message)) for message in ordered]
    consistent = all(identity == identities[0] for identity in identities)
    if consistent:
        _classify_duplicates(transaction, ordered, response=False)
    else:
        transaction["matching_status"] = "NOT_ESTABLISHED"
        _add_unique(transaction["missing"], "CONSISTENT_REQUEST_IDENTITY")
        for index, message in enumerate(ordered):
            item = _match(message)
            classification = "ORIGINAL" if index == 0 else "CONFLICTING_REQUEST"
            transaction["classifications"].append(
                {
                    "event_reference": item["source_reference"],
                    "role": "REQUEST",
                    "classification": classification,
                }
            )
            if index:
                transaction["conflicting_refs"].append(item["source_reference"])
        for left, right in zip(identities, identities[1:]):
            if left[0] != right[0]:
                _add_unique(transaction["conflicts"], "CSEQ_MISMATCH")
            if left[1] != right[1]:
                _add_unique(transaction["conflicts"], "CSEQ_METHOD_MISMATCH")
            if left[2] != right[2]:
                _add_unique(transaction["conflicts"], "CALL_ID_MISMATCH")
            if left[3] != right[3]:
                _add_unique(transaction["conflicts"], "FROM_TAG_MISMATCH")
            if left[4] != right[4]:
                _add_unique(transaction["conflicts"], "REQUEST_URI_MISMATCH")
            if left[5] != right[5]:
                _add_unique(transaction["conflicts"], "TO_VALUE_MISMATCH")
            if left[6] != right[6]:
                _add_unique(transaction["conflicts"], "VIA_BRANCH_MISMATCH")
        transaction["limitations"].append(
            "requests sharing the transaction key disagree on CSeq, Call-ID, address values or top Via; no request is selected as the transaction identity"
        )
    return transaction


def _incomplete_request_transaction(message: dict[str, Any]) -> dict[str, Any]:
    match = _match(message)
    method = match.get("method")
    transaction_type = (
        "INVITE" if method == "INVITE" else "CANCEL" if method == "CANCEL"
        else "NON_INVITE" if method is not None else "UNKNOWN"
    )
    transaction = _new_transaction(
        _transaction_reference("request", match),
        transaction_type,
        method,
        identity_available=False,
    )
    transaction["requests"] = [message]
    transaction["matching_mode"] = _matching_mode(match)
    transaction["matching_status"] = "NOT_ESTABLISHED"
    transaction["classifications"].append(
        {"event_reference": match["source_reference"], "role": "REQUEST", "classification": "ORIGINAL"}
    )
    if match.get("via_branch") is None:
        _add_unique(transaction["missing"], "VIA_BRANCH_NOT_OBSERVED")
    if match.get("via_sent_by") is None:
        _add_unique(transaction["missing"], "VIA_SENT_BY_NOT_OBSERVED")
    if match.get("cseq_number") is None or match.get("cseq_method") is None:
        _add_unique(transaction["missing"], "CSEQ_NOT_OBSERVED")
    if match.get("call_id") is None:
        _add_unique(transaction["missing"], "CALL_ID_NOT_OBSERVED")
    if match.get("from_tag") is None:
        _add_unique(transaction["missing"], "FROM_TAG_NOT_OBSERVED")
    if _matching_mode(match) == "LEGACY":
        if not _present(match.get("request_uri")):
            _add_unique(transaction["missing"], "REQUEST_URI_NOT_OBSERVED")
        if not _present(match.get("from_uri")):
            _add_unique(transaction["missing"], "FROM_VALUE_NOT_OBSERVED")
        if not _present(match.get("to_uri")):
            _add_unique(transaction["missing"], "TO_VALUE_NOT_OBSERVED")
    transaction["limitations"].append(
        "the SIP transaction identity is incomplete; no matching is attempted from Call-ID, addresses, ports or proximity"
    )
    return transaction


# ---------------------------------------------------------------------------
# Response-only and ambiguous transactions
# ---------------------------------------------------------------------------


def _response_only_transaction(group: list[dict[str, Any]], *, ambiguous: bool, candidates: list[str]) -> dict[str, Any]:
    ordered = _sort(group)
    first = ordered[0]
    match = _match(first)
    reference = _transaction_reference("response", match)
    transaction = _new_transaction(
        reference,
        "AMBIGUOUS" if ambiguous else "RESPONSE_ONLY",
        match.get("cseq_method"),
        identity_available=False,
    )
    transaction["responses"] = ordered
    transaction["candidate_references"] = sorted(set(candidates))
    if ambiguous:
        transaction["state"] = "AMBIGUOUS"
        transaction["matching_status"] = "AMBIGUOUS"
        _add_unique(transaction["missing"], "SINGLE_REQUEST_TRANSACTION")
        transaction["limitations"].append(
            "more than one request transaction shares the response transaction key; no request candidate is selected"
        )
    else:
        transaction["state"] = "RESPONSE_ONLY"
        transaction["matching_status"] = "RESPONSE_ONLY"
        _add_unique(transaction["missing"], "REQUEST_NOT_OBSERVED")
        transaction["limitations"].append(
            "the response request is outside the observed capture scope; no timeout or network outcome is inferred"
        )
    _classify_duplicates(transaction, ordered, response=True)
    _finalize_responses(transaction)
    if ambiguous:
        transaction["state"] = "AMBIGUOUS"
        transaction["matching_status"] = "AMBIGUOUS"
        transaction["selected_final_ref"] = None
        _add_unique(transaction["missing"], "SINGLE_FINAL_RESPONSE_NOT_ESTABLISHED")
    else:
        transaction["state"] = "RESPONSE_ONLY"
        transaction["matching_status"] = "RESPONSE_ONLY"
    return transaction


def _incomplete_response_transaction(message: dict[str, Any]) -> dict[str, Any]:
    match = _match(message)
    transaction = _new_transaction(
        _transaction_reference("response", match),
        "RESPONSE_ONLY",
        match.get("cseq_method"),
        identity_available=False,
    )
    transaction["responses"] = [message]
    _single_response_metadata(transaction, match)
    transaction["state"] = "INCOMPLETE_EVIDENCE"
    transaction["matching_status"] = "NOT_ESTABLISHED"
    transaction["classifications"].append(
        {"event_reference": match["source_reference"], "role": "RESPONSE", "classification": "ORIGINAL_RESPONSE"}
    )
    if match.get("via_branch") is None:
        _add_unique(transaction["missing"], "VIA_BRANCH_NOT_OBSERVED")
    if match.get("via_sent_by") is None:
        _add_unique(transaction["missing"], "VIA_SENT_BY_NOT_OBSERVED")
    if match.get("cseq_number") is None or match.get("cseq_method") is None:
        _add_unique(transaction["missing"], "CSEQ_NOT_OBSERVED")
    if match.get("call_id") is None:
        _add_unique(transaction["missing"], "CALL_ID_NOT_OBSERVED")
    if match.get("from_tag") is None:
        _add_unique(transaction["missing"], "FROM_TAG_NOT_OBSERVED")
    transaction["limitations"].append(
        "the response lacks sufficient reviewed transaction identity; no request association is claimed"
    )
    return transaction


def _single_response_metadata(transaction: dict[str, Any], match: dict[str, Any]) -> None:
    reference = match["source_reference"]
    status = match.get("status_code")
    if status is None:
        return
    if 100 <= status < 200:
        transaction["provisional_response_refs"] = [reference]
    elif status >= 200:
        transaction["final_response_refs"] = [reference]
        transaction["final_status_codes"] = [status]
        transaction["selected_final_ref"] = reference
        transaction["response_branch_count"] = 1 if match.get("to_tag") is not None else 0
        transaction["final_response_group_count"] = 1


def _conflict_response_transaction(
    message: dict[str, Any],
    candidates: list[str],
    conflicts: list[str],
) -> dict[str, Any]:
    match = _match(message)
    transaction = _new_transaction(
        _transaction_reference("response", match),
        "RESPONSE_ONLY",
        match.get("cseq_method"),
        identity_available=False,
    )
    transaction["responses"] = [message]
    _single_response_metadata(transaction, match)
    transaction["candidate_references"] = sorted(set(candidates))
    transaction["state"] = "INCOMPLETE_EVIDENCE"
    transaction["matching_status"] = "NOT_ESTABLISHED"
    transaction["conflicts"] = list(conflicts)
    transaction["classifications"].append(
        {"event_reference": match["source_reference"], "role": "RESPONSE", "classification": "ORIGINAL_RESPONSE"}
    )
    _add_unique(transaction["missing"], "SINGLE_REQUEST_TRANSACTION")
    transaction["limitations"].append(
        "the response shares a transaction key with a request but conflicts on CSeq, Call-ID or From tag; no request is selected"
    )
    return transaction


# ---------------------------------------------------------------------------
# ACK and CANCEL association
# ---------------------------------------------------------------------------


def _final_statuses(transaction: dict[str, Any]) -> list[int]:
    return list(transaction["final_status_codes"])


def _ack_header_conflicts(
    ack: dict[str, Any], invite_transactions: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str]]:
    match = _match(ack)
    compatible: list[dict[str, Any]] = []
    conflicts: list[str] = []
    for transaction in invite_transactions:
        identity = transaction["identity"]
        if identity is None or identity.get("capture") != match.get("capture"):
            continue
        same_branch = (
            identity.get("via_branch") is not None
            and identity.get("via_branch") == match.get("via_branch")
            and identity.get("via_sent_by") == match.get("via_sent_by")
        )
        if not same_branch and identity.get("cseq_number") != match.get("cseq_number"):
            continue
        if not transaction["identity_available"] or "CONSISTENT_REQUEST_IDENTITY" in transaction["missing"]:
            continue
        if identity.get("cseq_method") != "INVITE" or match.get("cseq_method") != "ACK":
            continue
        if not _present(match.get("request_uri")) or not _present(match.get("from_uri")):
            continue
        local: list[str] = []
        if identity.get("request_uri") != match.get("request_uri"):
            local.append("REQUEST_URI_MISMATCH")
        if _address_value(identity, "to") is not None and _address_value(match, "to") is not None:
            if identity.get("to_uri") != match.get("to_uri"):
                local.append("TO_VALUE_MISMATCH")
        if _address_value(identity, "from") != _address_value(match, "from"):
            local.append("FROM_VALUE_MISMATCH")
        if _present(identity.get("call_id")) and _present(match.get("call_id")):
            if identity["call_id"] != match["call_id"]:
                local.append("CALL_ID_MISMATCH")
        if identity.get("cseq_number") != match.get("cseq_number"):
            local.append("CSEQ_MISMATCH")
        if same_branch:
            if _matching_mode(match) == "MODERN":
                if identity.get("via_branch") != match.get("via_branch"):
                    local.append("VIA_BRANCH_MISMATCH")
                if identity.get("via_sent_by") != match.get("via_sent_by"):
                    local.append("VIA_SENT_BY_MISMATCH")
            elif _top_via_value(identity) != _top_via_value(match):
                local.append("VIA_BRANCH_MISMATCH")
        if local:
            conflicts.extend(local)
        else:
            compatible.append(transaction)
    return compatible, sorted(dict.fromkeys(conflicts))


def _ack_candidates(
    ack: dict[str, Any],
    invite_transactions: list[dict[str, Any]],
    *,
    strict_branch: bool,
) -> list[dict[str, Any]]:
    match = _match(ack)
    candidates: list[dict[str, Any]] = []
    if match.get("cseq_method") != "ACK":
        return candidates
    for transaction in invite_transactions:
        identity = transaction["identity"]
        if identity is None or identity.get("capture") != match.get("capture"):
            continue
        if not transaction["identity_available"] or "CONSISTENT_REQUEST_IDENTITY" in transaction["missing"]:
            continue
        if identity.get("cseq_method") != "INVITE":
            continue
        if identity.get("cseq_number") != match.get("cseq_number"):
            continue
        if _present(identity.get("call_id")) and _present(match.get("call_id")):
            if identity["call_id"] != match["call_id"]:
                continue
        if _present(identity.get("request_uri")) and _present(match.get("request_uri")):
            if identity["request_uri"] != match["request_uri"]:
                continue
        if _present(identity.get("to_uri")) and _present(match.get("to_uri")):
            if identity["to_uri"] != match["to_uri"]:
                continue
        if _address_value(identity, "from") is not None and _address_value(match, "from") is not None:
            if _address_value(identity, "from") != _address_value(match, "from"):
                continue
        if strict_branch:
            if _matching_mode(match) == "LEGACY":
                if _top_via_value(identity) != _top_via_value(match):
                    continue
            elif (
                identity.get("via_branch") != match.get("via_branch")
                or identity.get("via_sent_by") != match.get("via_sent_by")
            ):
                continue
        candidates.append(transaction)
    return candidates


def _group_ack_transactions(
    acks: list[dict[str, Any]],
    transaction_type: str,
    *,
    conflicts: list[str] | None = None,
) -> list[dict[str, Any]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for ack in acks:
        match = _match(ack)
        key = (
            match.get("capture"),
            match.get("via_branch"),
            match.get("via_sent_by"),
            match.get("cseq_number"),
            match.get("call_id"),
            match.get("from_tag"),
            match.get("to_tag"),
            match.get("transport_protocol"),
        )
        groups.setdefault(key, []).append(ack)
    transactions: list[dict[str, Any]] = []
    for group in groups.values():
        ordered = _sort(group)
        first = ordered[0]
        match = _match(first)
        transaction = _new_transaction(
            _transaction_reference("request", match),
            transaction_type,
            "ACK",
            identity_available=bool(_request_key(match)),
        )
        transaction["requests"] = ordered
        transaction["identity"] = match
        transaction["matching_mode"] = _matching_mode(match)
        transaction["matching_status"] = "REQUEST_ONLY" if transaction_type == "ACK_2XX" else "NOT_ESTABLISHED"
        if match.get("cseq_method") != "ACK":
            transaction["matching_status"] = "NOT_ESTABLISHED"
            _add_unique(transaction["missing"], "CONSISTENT_REQUEST_IDENTITY")
            _add_unique(transaction["conflicts"], "METHOD_MISMATCH")
            _add_unique(transaction["conflicts"], "CSEQ_METHOD_MISMATCH")
            transaction["limitations"].append(
                "the ACK request-line method contradicts its CSeq method; the observation is not a valid transaction identity"
            )
        if conflicts:
            transaction["conflicts"] = sorted(set(transaction["conflicts"]) | set(conflicts))
        _classify_duplicates(transaction, ordered, response=False)
        if transaction_type == "ACK_2XX":
            transaction["basis"].extend(["ack_method_observed"])
            if match.get("cseq_number") is not None:
                transaction["basis"].append("cseq_number_observed")
            if match.get("call_id") is not None:
                transaction["basis"].append("call_id_observed")
            if match.get("from_tag") is not None:
                transaction["basis"].append("from_tag_observed")
            _add_unique(transaction["missing"], "DIALOG_ASSOCIATION_UNAVAILABLE")
            transaction["limitations"].append(
                "the ACK is retained as an independent request transaction; no dialog transaction merge is performed"
            )
        else:
            _add_unique(transaction["missing"], "FINAL_RESPONSE_NOT_OBSERVED")
            transaction["limitations"].append(
                "the ACK could not be associated with an observed INVITE transaction outcome"
            )
        transactions.append(transaction)
    return transactions


def _non_2xx_to_tag_matches(transaction: dict[str, Any], ack_match: dict[str, Any]) -> bool:
    to_tag = ack_match.get("to_tag")
    if not _present(to_tag):
        return False
    return any(
        (response["match"].get("status_code") or 0) >= 300
        and response["match"].get("to_tag") == to_tag
        for response in transaction["responses"]
    )


def _associate_ack(
    ack: dict[str, Any],
    invite_transactions: list[dict[str, Any]],
) -> tuple[str, dict[str, Any] | None, list[dict[str, Any]], list[str]]:
    match = _match(ack)
    compatible, conflicts = _ack_header_conflicts(ack, invite_transactions)
    strict = _ack_candidates(ack, invite_transactions, strict_branch=True)
    if len(strict) == 1:
        transaction = strict[0]
        statuses = _final_statuses(transaction)
        has_2xx = any(200 <= status < 300 for status in statuses)
        has_non_2xx = any(status >= 300 for status in statuses)
        if has_2xx and has_non_2xx:
            return "ACK_AMBIGUOUS", None, strict, sorted(set(conflicts))
        if has_2xx:
            return "ACK_2XX", None, strict, sorted(set(conflicts))
        if has_non_2xx:
            if _non_2xx_to_tag_matches(transaction, match):
                return "ASSOCIATED", transaction, strict, sorted(set(conflicts))
            return "ACK_ORPHAN", None, strict, sorted(set(conflicts) | {"TO_TAG_MISMATCH"})
        return "ACK_ORPHAN", None, strict, sorted(set(conflicts))
    if len(strict) > 1:
        return "ACK_AMBIGUOUS", None, strict, sorted(set(conflicts))
    loose = _ack_candidates(ack, invite_transactions, strict_branch=False)
    if len(loose) == 1 and any(
        200 <= status < 300 for status in _final_statuses(loose[0])
    ):
        return "ACK_2XX", None, loose, sorted(set(conflicts))
    if len(loose) > 1:
        return "ACK_AMBIGUOUS", None, loose, sorted(set(conflicts))
    if not strict and not loose and compatible:
        return "ACK_ORPHAN", None, compatible, sorted(set(conflicts) | {"TO_TAG_MISMATCH"})
    return "ACK_ORPHAN", None, [], sorted(set(conflicts))


def _attach_ack_control(transaction: dict[str, Any], ack: dict[str, Any]) -> None:
    match = _match(ack)
    transaction["control"].append(ack)
    transaction["basis"].extend(
        [
            "ack_branch_match",
            "ack_sent_by_match",
            "ack_cseq_number_match",
            "ack_request_uri_match",
            "ack_from_value_match",
            "ack_to_tag_matches_final_response",
            "non_2xx_final_response_observed",
        ]
    )
    if match.get("call_id") is not None:
        transaction["basis"].append("ack_call_id_match")
    if "ACK_NOT_OBSERVED" in transaction["missing"]:
        transaction["missing"].remove("ACK_NOT_OBSERVED")
    existing = [
        item
        for item in transaction["classifications"]
        if item["role"] == "CONTROL"
    ]
    if not existing:
        classification = "ASSOCIATED_CONTROL"
    elif match.get("transport_protocol") == "UDP" and existing[-1]["classification"] == "ASSOCIATED_CONTROL":
        classification = "EXACT_RETRANSMISSION"
        transaction["retransmission_refs"].append(match["source_reference"])
    elif match.get("transport_protocol") == "TCP":
        classification = "REPEATED_TCP_OBSERVATION"
        transaction["repeated_refs"].append(match["source_reference"])
    else:
        classification = "REPEATED_OBSERVATION"
        transaction["repeated_refs"].append(match["source_reference"])
    transaction["classifications"].append(
        {"event_reference": match["source_reference"], "role": "CONTROL", "classification": classification}
    )


def _cancel_header_conflicts(
    identity: dict[str, Any], invite: dict[str, Any]
) -> list[str]:
    conflicts: list[str] = []
    if _present(identity.get("request_uri")) and _present(invite.get("request_uri")):
        if identity["request_uri"] != invite["request_uri"]:
            conflicts.append("REQUEST_URI_MISMATCH")
    if _address_value(identity, "from") is not None and _address_value(invite, "from") is not None:
        if _address_value(identity, "from") != _address_value(invite, "from"):
            conflicts.append("FROM_VALUE_MISMATCH")
    if _address_value(identity, "to") is not None and _address_value(invite, "to") is not None:
        if _address_value(identity, "to") != _address_value(invite, "to"):
            conflicts.append("TO_VALUE_MISMATCH")
    if _present(identity.get("call_id")) and _present(invite.get("call_id")):
        if identity["call_id"] != invite["call_id"]:
            conflicts.append("CALL_ID_MISMATCH")
    if identity.get("cseq_number") != invite.get("cseq_number"):
        conflicts.append("CSEQ_MISMATCH")
    if _matching_mode(identity) == "MODERN":
        if identity.get("via_branch") != invite.get("via_branch"):
            conflicts.append("VIA_BRANCH_MISMATCH")
        if identity.get("via_sent_by") != invite.get("via_sent_by"):
            conflicts.append("VIA_SENT_BY_MISMATCH")
    elif _top_via_value(identity) != _top_via_value(invite):
        conflicts.append("VIA_BRANCH_MISMATCH")
    return conflicts


def _associate_cancel(
    cancel_transaction: dict[str, Any],
    invite_transactions: list[dict[str, Any]],
) -> None:
    identity = cancel_transaction["identity"]
    if identity is None:
        return
    if identity.get("cseq_method") != "CANCEL":
        cancel_transaction["matching_status"] = "NOT_ESTABLISHED"
        _add_unique(cancel_transaction["conflicts"], "METHOD_MISMATCH")
        cancel_transaction["limitations"].append(
            "the CANCEL request-line method contradicts its CSeq method; no INVITE association is attempted"
        )
        return
    candidates: list[dict[str, Any]] = []
    conflicts: list[str] = []
    for transaction in invite_transactions:
        invite = transaction["identity"]
        if invite is None or invite.get("capture") != identity.get("capture"):
            continue
        if not transaction["identity_available"] or "CONSISTENT_REQUEST_IDENTITY" in transaction["missing"]:
            continue
        if invite.get("cseq_method") != "INVITE":
            continue
        local = _cancel_header_conflicts(identity, invite)
        if local:
            conflicts.extend(local)
            continue
        candidates.append(transaction)
    if len(candidates) == 1:
        invite = candidates[0]
        cancel_transaction["associated_reference"] = invite["reference"]
        cancel_transaction["associated_references"] = [invite["reference"]]
        cancel_transaction["cancel_invite_association_status"] = "ASSOCIATED"
        cancel_transaction["basis"].extend(
            [
                "cancel_branch_match",
                "cancel_sent_by_match",
                "cancel_cseq_number_match",
                "cancel_request_uri_match",
                "cancel_from_value_match",
                "cancel_to_value_match",
            ]
        )
        if identity.get("call_id") is not None:
            cancel_transaction["basis"].append("cancel_call_id_match")
        invite["associated_references"].append(cancel_transaction["reference"])
        invite_final = 487 if 487 in _final_statuses(invite) else None
        cancel_final = 200 if 200 in _final_statuses(cancel_transaction) else None
        cancel_transaction["invite_final_response_status"] = invite_final
        cancel_transaction["cancel_final_response_status"] = cancel_final
        invite["cancel_invite_association_status"] = "ASSOCIATED"
        invite["invite_final_response_status"] = invite_final
        invite["cancel_final_response_status"] = cancel_final
        invite["invite_transaction_termination_established"] = False
        invite["termination_basis"] = None
        if invite_final == 487 and cancel_final == 200:
            invite["cancel_sequence_observed"] = True
            _add_unique(invite["missing"], "TRANSACTION_TERMINATION_NOT_ESTABLISHED")
            invite["limitations"].append(
                "487 INVITE and 200 CANCEL are separately observed; RFC timer and TERMINATED state evidence is unavailable from a passive capture"
            )
        else:
            cancel_transaction["limitations"].append(
                "the CANCEL is associated with an INVITE transaction, but the final INVITE outcome is not inferred from the 200 OK to CANCEL"
            )
    elif len(candidates) > 1:
        cancel_transaction["candidate_references"] = sorted(
            transaction["reference"] for transaction in candidates
        )
        cancel_transaction["cancel_invite_association_status"] = "AMBIGUOUS"
        cancel_transaction["matching_status"] = "AMBIGUOUS"
        _add_unique(cancel_transaction["missing"], "SINGLE_REQUEST_TRANSACTION")
        cancel_transaction["limitations"].append(
            "more than one INVITE transaction shares the CANCEL transaction evidence; no INVITE association is selected"
        )
    else:
        cancel_transaction["cancel_invite_association_status"] = "NOT_ESTABLISHED"
        _add_unique(cancel_transaction["missing"], "INVITE_TRANSACTION_NOT_OBSERVED")
        if conflicts:
            cancel_transaction["conflicts"] = sorted(set(conflicts))
            cancel_transaction["limitations"].append(
                "an INVITE transaction shares the CANCEL transaction identity but contradicts required header evidence; no association is claimed"
            )
        else:
            cancel_transaction["limitations"].append(
                "no INVITE transaction matches the CANCEL identity; the CANCEL remains independently observed"
            )
    if not cancel_transaction["final_response_refs"]:
        _add_unique(cancel_transaction["missing"], "CANCEL_RESPONSE_NOT_OBSERVED")


# ---------------------------------------------------------------------------
# Correlation entry point
# ---------------------------------------------------------------------------


def correlate(messages: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(messages, list):
        raise TransactionError("messages must be a list")
    requests = [message for message in messages if _match(message).get("direction") == "REQUEST"]
    responses = [message for message in messages if _match(message).get("direction") == "RESPONSE"]
    unknowns = [message for message in messages if _match(message).get("direction") == "UNKNOWN"]

    ack_requests = [message for message in requests if _match(message).get("method") == "ACK"]
    non_ack_requests = [message for message in requests if _match(message).get("method") != "ACK"]

    transactions: list[dict[str, Any]] = []
    transaction_by_marker: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    candidate_by_marker: dict[tuple[Any, ...], list[dict[str, Any]]] = {}

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for message in non_ack_requests:
        key = _request_key(_match(message))
        if key is None:
            transactions.append(_incomplete_request_transaction(message))
        else:
            groups.setdefault(key, []).append(message)

    for key in sorted(groups, key=lambda item: tuple(str(part) for part in item)):
        group = _sort(groups[key])
        method = _match(group[0]).get("method")
        if method is None:
            transactions.append(_incomplete_request_transaction(group[0]))
            continue
        transaction = _request_transaction(group, method)
        transactions.append(transaction)
        marker = _transaction_marker(transaction["identity"])
        if marker is not None and transaction["identity_available"]:
            candidate_by_marker.setdefault(marker, []).append(transaction)
            if "CONSISTENT_REQUEST_IDENTITY" not in transaction["missing"]:
                transaction_by_marker.setdefault(marker, []).append(transaction)

    invite_transactions = [transaction for transaction in transactions if transaction["type"] == "INVITE"]

    response_groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    ambiguous_groups: dict[tuple[Any, ...], tuple[list[dict[str, Any]], list[str]]] = {}
    for message in responses:
        match = _match(message)
        if match.get("cseq_number") is None:
            transactions.append(_incomplete_response_transaction(message))
            continue
        key = _transaction_marker(match)
        if key is None:
            transactions.append(_incomplete_response_transaction(message))
            continue
        candidates = transaction_by_marker.get(key, [])
        if not candidates:
            conflicting = candidate_by_marker.get(key, [])
            if conflicting:
                identity = _response_identity(match) + (
                    tuple(sorted(item["reference"] for item in conflicting)),
                )
                if identity not in ambiguous_groups:
                    ambiguous_groups[identity] = (
                        [],
                        sorted(item["reference"] for item in conflicting),
                    )
                ambiguous_groups[identity][0].append(message)
            else:
                response_groups.setdefault(_response_identity(match), []).append(message)
            continue
        if len(candidates) > 1:
            identity = _response_identity(match) + (tuple(sorted(t["reference"] for t in candidates)),)
            if identity not in ambiguous_groups:
                ambiguous_groups[identity] = ([], sorted(t["reference"] for t in candidates))
            ambiguous_groups[identity][0].append(message)
            continue
        transaction = candidates[0]
        request = transaction["identity"]
        conflicts: list[str] = []
        if request.get("cseq_number") != match.get("cseq_number"):
            conflicts.append("CSEQ_MISMATCH")
        if (
            _present(request.get("call_id"))
            and _present(match.get("call_id"))
            and request["call_id"] != match["call_id"]
        ):
            conflicts.append("CALL_ID_MISMATCH")
        if (
            _present(request.get("from_tag"))
            and _present(match.get("from_tag"))
            and request["from_tag"] != match["from_tag"]
        ):
            conflicts.append("FROM_TAG_MISMATCH")
        if _matching_mode(request) == "LEGACY":
            if (
                _present(request.get("to_uri"))
                and _present(match.get("to_uri"))
                and request["to_uri"] != match["to_uri"]
            ):
                conflicts.append("TO_VALUE_MISMATCH")
        if conflicts:
            transactions.append(
                _conflict_response_transaction(message, [transaction["reference"]], conflicts)
            )
            continue
        transaction["responses"].append(message)
        transaction["basis"].extend(
            [
                "top_via_branch_match",
                "top_via_sent_by_match",
                "cseq_number_match",
                "cseq_method_match",
            ]
        )
        if _present(request.get("call_id")) and _present(match.get("call_id")):
            transaction["basis"].append("call_id_match")
        else:
            transaction["partial"] = True
        if _present(request.get("from_tag")) and _present(match.get("from_tag")):
            transaction["basis"].append("from_tag_match")
        else:
            transaction["partial"] = True
        if (
            request.get("transport_protocol") == "TCP"
            and request.get("stream_id") is not None
            and request.get("stream_id") == match.get("stream_id")
        ):
            transaction["basis"].append("same_tcp_stream")
        if (
            request.get("source_address") == match.get("destination_address")
            and request.get("destination_address") == match.get("source_address")
        ):
            transaction["basis"].append("opposite_endpoint_direction")

    for transaction in transactions:
        if (
            transaction["type"] in {"INVITE", "NON_INVITE", "CANCEL"}
            and transaction["identity_available"]
            and "CONSISTENT_REQUEST_IDENTITY" not in transaction["missing"]
        ):
            _finalize_responses(transaction)

    for group in response_groups.values():
        transactions.append(_response_only_transaction(group, ambiguous=False, candidates=[]))
    for group, candidates in ambiguous_groups.values():
        transactions.append(_response_only_transaction(group, ambiguous=True, candidates=candidates))

    for transaction in invite_transactions:
        if transaction["matching_status"] == "NOT_ESTABLISHED":
            _add_unique(transaction["missing"], "CONSISTENT_REQUEST_IDENTITY")

    for transaction in transactions:
        if transaction["type"] == "CANCEL":
            _associate_cancel(transaction, invite_transactions)

    ack_groups: dict[str, list[dict[str, Any]]] = {
        "ACK_2XX": [],
        "ACK_ORPHAN": [],
        "ACK_AMBIGUOUS": [],
    }
    ack_candidates: dict[str, list[str]] = {}
    ack_conflicts: dict[str, list[str]] = {}
    for ack in _sort(ack_requests):
        kind, invite, candidates, conflicts = _associate_ack(ack, invite_transactions)
        ack_conflicts[_match(ack)["source_reference"]] = conflicts
        if kind == "ASSOCIATED" and invite is not None:
            _attach_ack_control(invite, ack)
            continue
        ack_groups[kind].append(ack)
        ack_candidates[_match(ack)["source_reference"]] = sorted(
            item["reference"] for item in candidates
        )

    for kind in ("ACK_2XX", "ACK_ORPHAN", "ACK_AMBIGUOUS"):
        group = ack_groups.get(kind, [])
        if not group:
            continue
        if kind == "ACK_AMBIGUOUS":
            groups_by_identity: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
            for ack in group:
                match = _match(ack)
                key = (
                    match.get("capture"),
                    match.get("via_branch"),
                    match.get("via_sent_by"),
                    match.get("cseq_number"),
                    match.get("call_id"),
                    match.get("from_tag"),
                    match.get("to_tag"),
                )
                groups_by_identity.setdefault(key, []).append(ack)
            for ack_group in groups_by_identity.values():
                group_conflicts: list[str] = []
                for ack in ack_group:
                    group_conflicts.extend(ack_conflicts.get(_match(ack)["source_reference"], []))
                transaction = _group_ack_transactions(
                    ack_group, "ACK_AMBIGUOUS", conflicts=group_conflicts
                )[0]
                transaction["matching_status"] = "AMBIGUOUS"
                _add_unique(transaction["missing"], "SINGLE_REQUEST_TRANSACTION")
                for ack in ack_group:
                    transaction["candidate_references"].extend(
                        ack_candidates.get(_match(ack)["source_reference"], [])
                    )
                transaction["candidate_references"] = sorted(set(transaction["candidate_references"]))
                transactions.append(transaction)
        else:
            for transaction in _group_ack_transactions(
                group,
                kind,
                conflicts=[
                    conflict
                    for ack in group
                    for conflict in ack_conflicts.get(_match(ack)["source_reference"], [])
                ],
            ):
                for ack in transaction["requests"]:
                    transaction["candidate_references"].extend(
                        ack_candidates.get(_match(ack)["source_reference"], [])
                    )
                transaction["candidate_references"] = sorted(set(transaction["candidate_references"]))
                transactions.append(transaction)

    for message in unknowns:
        match = _match(message)
        transaction = _new_transaction(
            _transaction_reference("request", match),
            "UNKNOWN",
            None,
            identity_available=False,
        )
        transaction["requests"] = [message]
        transaction["state"] = "INCOMPLETE_EVIDENCE"
        transaction["matching_status"] = "NOT_ESTABLISHED"
        transaction["classifications"].append(
            {"event_reference": match["source_reference"], "role": "REQUEST", "classification": "ORIGINAL"}
        )
        _add_unique(transaction["missing"], "CSEQ_NOT_OBSERVED")
        transaction["limitations"].append(
            "the observation has no usable SIP start line; no transaction identity is claimed"
        )
        transactions.append(transaction)

    for transaction in transactions:
        _finalize_common(transaction)

    transactions.sort(key=lambda item: (_first_frame(item), item["reference"]))
    document = _document(transactions)
    validate_transaction_document(document, messages)
    return document


def _first_frame(transaction: dict[str, Any]) -> int:
    frames = [
        _match(message)["frame"]
        for message in transaction["requests"] + transaction["responses"] + transaction["control"]
    ]
    return min(frames) if frames else 0


def _last_frame(transaction: dict[str, Any]) -> int:
    frames = [
        _match(message)["frame"]
        for message in transaction["requests"] + transaction["responses"] + transaction["control"]
    ]
    return max(frames) if frames else 0


def _event_references(messages: list[dict[str, Any]]) -> list[str]:
    return [ _match(message)["source_reference"] for message in _sort(messages) ]


def _public_transaction(transaction: dict[str, Any]) -> dict[str, Any]:
    request_refs = _event_references(transaction["requests"])
    response_refs = _event_references(transaction["responses"])
    control_refs = _event_references(transaction["control"])
    members = transaction["requests"] + transaction["responses"] + transaction["control"]
    classifications = sorted(
        transaction["classifications"],
        key=lambda item: _reference_order(item["event_reference"]),
    )
    return {
        "transaction_reference": transaction["reference"],
        "transaction_type": transaction["type"],
        "transaction_method": transaction["method"],
        "transaction_state": transaction["state"],
        "observed_evidence_status": transaction["observed_evidence_status"],
        "transaction_role": transaction["transaction_role"],
        "rfc_transaction_state": transaction["rfc_transaction_state"],
        "state_semantics": transaction["state_semantics"],
        "matching_mode": transaction["matching_mode"],
        "matching_status": transaction["matching_status"],
        "matching_basis": list(transaction["basis"]),
        "transaction_identity_available": transaction["identity_available"],
        "request_event_references": request_refs,
        "response_event_references": response_refs,
        "provisional_response_event_references": list(transaction["provisional_response_refs"]),
        "final_response_event_references": list(transaction["final_response_refs"]),
        "associated_control_event_references": control_refs,
        "associated_transaction_reference": transaction["associated_reference"],
        "associated_transaction_references": sorted(set(transaction["associated_references"])),
        "candidate_transaction_references": sorted(set(transaction["candidate_references"])),
        "retransmission_count": len(transaction["retransmission_refs"]),
        "retransmission_event_references": list(transaction["retransmission_refs"]),
        "retransmission_candidate_count": len(transaction["retransmission_candidate_refs"]),
        "retransmission_candidate_event_references": list(
            transaction["retransmission_candidate_refs"]
        ),
        "repeated_observation_event_references": list(transaction["repeated_refs"]),
        "conflicting_request_event_references": list(transaction["conflicting_refs"]),
        "message_classifications": classifications,
        "first_observed_frame": _first_frame(transaction),
        "last_observed_frame": _last_frame(transaction),
        "request_frame": _match(transaction["requests"][0])["frame"] if transaction["requests"] else None,
        "response_frame": _match(transaction["responses"][0])["frame"] if transaction["responses"] else None,
        "provisional_response_count": len(transaction["provisional_response_refs"]),
        "final_response_count": len(transaction["final_response_refs"]),
        "distinct_final_response_count": transaction["final_response_group_count"],
        "response_branch_count": transaction["response_branch_count"],
        "final_response_status_codes": list(transaction["final_status_codes"]),
        "selected_final_response_reference": transaction["selected_final_ref"],
        "capture_completeness": _capture_completeness(transaction),
        "missing_evidence": list(transaction["missing"]),
        "conflict_findings": list(transaction["conflicts"]),
        "termination_basis": transaction["termination_basis"],
        "cancel_response_sequence_observed": bool(transaction["cancel_sequence_observed"]),
        "cancel_final_response_status": transaction["cancel_final_response_status"],
        "invite_final_response_status": transaction["invite_final_response_status"],
        "cancel_invite_association_status": transaction["cancel_invite_association_status"],
        "invite_transaction_termination_established": bool(
            transaction["invite_transaction_termination_established"]
        ),
        "limitations": list(transaction["limitations"]),
        "not_confirmed": list(BASE_NOT_CONFIRMED),
        "evidence_class": "DERIVED",
    }


def _document(transactions: list[dict[str, Any]]) -> dict[str, Any]:
    public = [_public_transaction(transaction) for transaction in transactions]
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    matching_counts: dict[str, int] = {}
    role_counts: dict[str, int] = {}
    observed_counts: dict[str, int] = {}
    for transaction in public:
        type_counts[transaction["transaction_type"]] = type_counts.get(transaction["transaction_type"], 0) + 1
        state_counts[transaction["transaction_state"]] = state_counts.get(transaction["transaction_state"], 0) + 1
        matching_counts[transaction["matching_status"]] = matching_counts.get(transaction["matching_status"], 0) + 1
        role_counts[transaction["transaction_role"]] = role_counts.get(transaction["transaction_role"], 0) + 1
        observed_counts[transaction["observed_evidence_status"]] = (
            observed_counts.get(transaction["observed_evidence_status"], 0) + 1
        )
    capture_files = sorted(
        {
            _match(message)["capture"]
            for transaction in transactions
            for message in transaction["requests"] + transaction["responses"] + transaction["control"]
        }
    )
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": TRANSACTION_SCHEMA_VERSION,
        "protocol": PROTOCOL,
        "capture_files": capture_files,
        "transaction_count": len(public),
        "summary": {
            "transaction_type_counts": dict(sorted(type_counts.items())),
            "transaction_state_counts": dict(sorted(state_counts.items())),
            "observed_evidence_status_counts": dict(sorted(observed_counts.items())),
            "transaction_role_counts": dict(sorted(role_counts.items())),
            "matching_status_counts": dict(sorted(matching_counts.items())),
            "retransmission_event_count": sum(
                transaction["retransmission_count"] for transaction in public
            ),
        },
        "transactions": public,
        "limitations": [
            "SIP transaction correlation is protocol-local and is not SIP dialog correlation, cross-protocol correlation or IMS Domain analysis",
            "unobserved responses and ACKs are capture incompleteness, not proof of a transaction timeout or network failure",
            "a 200 OK to CANCEL does not prove the INVITE was cancelled without corresponding INVITE response evidence",
            "ACK for a 2xx INVITE is an independent request transaction; dialog association is unavailable",
            "multiple final responses are preserved as separate branches; no SIP dialog is inferred",
            "TCP repeated messages are not automatically SIP retransmissions",
            "retransmission equality is evaluated from reviewed protocol fields and the in-memory content fingerprint available in the input; an unavailable message body is never reconstructed",
            "RFC 3261 magic-cookie and legacy Via matching are kept separate; legacy matching does not fall back to Call-ID-only association",
            "passive capture cannot establish client or server stack role, so RFC transaction state is published only when the observed role is explicitly known; otherwise an evidence status is published",
            "RFC 6026 Accepted state is an INVITE 2xx transaction projection, not a capture-observed timer state",
            "487 INVITE plus 200 CANCEL are separately observed evidence; RFC timer expiration and TERMINATED state are never inferred from capture silence",
        ],
        "not_confirmed": list(BASE_NOT_CONFIRMED),
    }


def attach_transaction_references(
    messages: list[dict[str, Any]], document: dict[str, Any]
) -> None:
    mapping: dict[str, str] = {}
    for transaction in document["transactions"]:
        reference = transaction["transaction_reference"]
        for key in (
            "request_event_references",
            "response_event_references",
            "associated_control_event_references",
        ):
            for event_reference in transaction[key]:
                if event_reference in mapping and mapping[event_reference] != reference:
                    raise TransactionError(
                        "one SIP event reference was assigned to more than one transaction"
                    )
                mapping[event_reference] = reference
    for message in messages:
        match = _match(message)
        reference = mapping.get(match["source_reference"])
        if reference is None:
            raise TransactionError("a SIP event is absent from transaction correlation output")
        message["event"]["transaction_reference"] = reference


def _refs_in(transaction: dict[str, Any], key: str) -> list[str]:
    return list(transaction.get(key) or [])


def validate_transaction_document(
    document: dict[str, Any],
    messages: list[dict[str, Any]] | None = None,
) -> None:
    if not isinstance(document, dict):
        raise TransactionError("transaction document must be an object")
    for field in ("analysis_name", "analysis_version", "protocol", "capture_files", "transaction_count", "transactions", "limitations", "not_confirmed"):
        if field not in document:
            raise TransactionError(f"transaction document is missing {field}")
    if document["analysis_name"] != ANALYSIS_NAME:
        raise TransactionError("transaction document analysis_name is not accepted")
    if document["transaction_count"] != len(document["transactions"]):
        raise TransactionError("transaction_count does not match the transaction array")
    transaction_references: set[str] = set()
    event_references: set[str] = set()
    for transaction in document["transactions"]:
        reference = transaction.get("transaction_reference")
        if not isinstance(reference, str) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(reference):
            raise TransactionError("invalid transaction reference")
        if reference in transaction_references:
            raise TransactionError("duplicate transaction reference")
        transaction_references.add(reference)
        if transaction.get("transaction_type") not in TRANSACTION_TYPES:
            raise TransactionError("invalid transaction type")
        if transaction.get("transaction_state") not in TRANSACTION_STATES:
            raise TransactionError("invalid transaction state")
        if transaction.get("observed_evidence_status") not in OBSERVED_EVIDENCE_STATUSES:
            raise TransactionError("invalid observed evidence status")
        if transaction.get("transaction_role") not in TRANSACTION_ROLES:
            raise TransactionError("invalid transaction role")
        if transaction.get("matching_mode") not in MATCHING_MODES + (None,):
            raise TransactionError("invalid matching mode")
        rfc_state = transaction.get("rfc_transaction_state")
        if rfc_state is not None and rfc_state not in RFC_TRANSACTION_STATES:
            raise TransactionError("invalid RFC transaction state")
        if transaction.get("transaction_role") == "UNKNOWN" and rfc_state is not None:
            raise TransactionError("RFC transaction state cannot be published for an unknown role")
        if rfc_state is None and transaction.get("transaction_state") != transaction.get(
            "observed_evidence_status"
        ):
            raise TransactionError("evidence-only state must match the observed evidence status")
        if transaction.get("state_semantics") not in {"RFC_STATE", "EVIDENCE_ONLY"}:
            raise TransactionError("invalid state semantics")
        if transaction.get("retransmission_candidate_count") != len(
            transaction.get("retransmission_candidate_event_references") or []
        ):
            raise TransactionError(
                "retransmission candidate count does not match its event references"
            )
        if transaction.get("matching_status") not in MATCHING_STATUSES:
            raise TransactionError("invalid matching status")
        if transaction.get("capture_completeness") not in CAPTURE_COMPLETENESS:
            raise TransactionError("invalid capture completeness")
        for key in (
            "request_event_references",
            "response_event_references",
            "provisional_response_event_references",
            "final_response_event_references",
            "associated_control_event_references",
            "retransmission_event_references",
            "repeated_observation_event_references",
            "conflicting_request_event_references",
        ):
            values = _refs_in(transaction, key)
            if len(values) != len(set(values)):
                raise TransactionError(f"duplicate source reference in {key}")
            for value in values:
                if not isinstance(value, str) or not EVENT_REFERENCE_PATTERN.fullmatch(value):
                    raise TransactionError(f"invalid source reference in {key}")
                if value in event_references and key in {
                    "request_event_references",
                    "response_event_references",
                    "associated_control_event_references",
                }:
                    raise TransactionError("a source event reference is assigned to more than one transaction")
            if key in {
                "request_event_references",
                "response_event_references",
                "associated_control_event_references",
            }:
                event_references.update(values)
        main_references = set(
            _refs_in(transaction, "request_event_references")
            + _refs_in(transaction, "response_event_references")
            + _refs_in(transaction, "associated_control_event_references")
        )
        for key in (
            "retransmission_event_references",
            "retransmission_candidate_event_references",
            "repeated_observation_event_references",
            "conflicting_request_event_references",
        ):
            if not set(_refs_in(transaction, key)).issubset(main_references):
                raise TransactionError(f"{key} contains a source reference outside the transaction")
        for key in ("provisional_response_event_references", "final_response_event_references"):
            if not set(_refs_in(transaction, key)).issubset(
                set(_refs_in(transaction, "response_event_references"))
            ):
                raise TransactionError(f"{key} contains a non-response source reference")
        if transaction.get("provisional_response_count") != len(
            transaction.get("provisional_response_event_references") or []
        ):
            raise TransactionError("provisional response count does not match its event references")
        if transaction.get("final_response_count") != len(
            transaction.get("final_response_event_references") or []
        ):
            raise TransactionError("final response count does not match its event references")
        if transaction.get("retransmission_count") != len(
            transaction.get("retransmission_event_references") or []
        ):
            raise TransactionError("retransmission count does not match its event references")
        selected = transaction.get("selected_final_response_reference")
        if selected is not None and selected not in _refs_in(transaction, "final_response_event_references"):
            raise TransactionError("selected final response is not a final response reference")
        associated = transaction.get("associated_transaction_reference")
        if associated is not None and associated not in transaction_references and associated not in {
            item["transaction_reference"] for item in document["transactions"]
        }:
            raise TransactionError("associated transaction reference is not present")
        for candidate in transaction.get("candidate_transaction_references") or []:
            if candidate not in {item["transaction_reference"] for item in document["transactions"]}:
                raise TransactionError("candidate transaction reference is not present")
    summary = document.get("summary")
    if not isinstance(summary, dict):
        raise TransactionError("transaction summary is missing")
    for key in (
        "transaction_type_counts",
        "transaction_state_counts",
        "observed_evidence_status_counts",
        "transaction_role_counts",
        "matching_status_counts",
    ):
        counts = summary.get(key)
        if not isinstance(counts, dict):
            raise TransactionError(f"transaction summary {key} is missing")
        if sum(counts.values()) != document["transaction_count"]:
            raise TransactionError(f"transaction summary {key} does not total the transaction count")
    if summary.get("retransmission_event_count") != sum(
        transaction.get("retransmission_count", 0) for transaction in document["transactions"]
    ):
        raise TransactionError("transaction summary retransmission count is inconsistent")
    if messages is not None:
        expected = {_match(message)["source_reference"] for message in messages}
        if event_references != expected:
            missing = sorted(expected - event_references)
            extra = sorted(event_references - expected)
            raise TransactionError(
                f"transaction event coverage mismatch: missing={missing[:3]} extra={extra[:3]}"
            )