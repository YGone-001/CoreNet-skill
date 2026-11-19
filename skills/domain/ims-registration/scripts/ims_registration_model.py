#!/usr/bin/env python3
"""Bounded IMS registration Domain evidence.

Consumes the accepted SIP message records and transaction document, and optionally
the accepted Diameter IMS Cx/Dx analysis document. Publishes registration-attempt
evidence, authentication challenge/retry observations, independent Diameter
observations, and fail-closed cross-protocol associations.

No SIP or Diameter packet is decoded here. Raw subscriber and authentication values
remain in the private SIP in-memory records and are never published.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

ANALYSIS_NAME = "ims-registration"
ANALYSIS_VERSION = "1.1.0"
DOMAIN = "domain"
CAPABILITY_STATUS = "IMS_REGISTRATION_DOMAIN_IMPLEMENTED"

MAX_INVENTORY = 256
MAX_ATTEMPTS = 256
MAX_DIAMETER = 256
MAX_ASSOCIATIONS = 256
MAX_TIMELINE_ROWS = 512
MAX_REFERENCES = 64
MAX_LIMITATIONS = 16

REGISTRATION_REFERENCE_PATTERN = re.compile(r"^sip-registration:.+:[0-9]+\.[0-9]+$")
TIMELINE_REFERENCE_PATTERN = re.compile(r"^ims-timeline:.+:[0-9]+\.[0-9]+:.+$")
DIAMETER_REFERENCE_PATTERN = re.compile(r"^diameter-ims:.+$")
EVENT_REFERENCE_PATTERN = re.compile(r"^sip-event:.+:[0-9]+\.[0-9]+$")
TRANSACTION_REFERENCE_PATTERN = re.compile(r"^sip-transaction:.+:(?:request|response):[0-9]+\.[0-9]+$")

REGISTRATION_TYPES = (
    "INITIAL_REGISTRATION_CANDIDATE",
    "INITIAL_REGISTRATION_SUPPORTED",
    "RE_REGISTRATION_CANDIDATE",
    "REFRESH_OBSERVED",
    "DEREGISTRATION_REQUESTED",
    "UNDETERMINED",
)
AUTHENTICATION_STATUSES = (
    "NOT_OBSERVED",
    "CHALLENGE_OBSERVED",
    "RETRY_OBSERVED",
    "CHALLENGE_RETRY_ASSOCIATED",
    "CHALLENGE_WITHOUT_OBSERVED_RETRY",
    "RETRY_WITHOUT_OBSERVED_CHALLENGE",
    "AUTHENTICATION_OUTCOME_UNPROVED",
    "RETRY_NOT_ESTABLISHED",
)
SIP_OUTCOMES = (
    "SUCCESS_RESPONSE_OBSERVED",
    "NEGATIVE_RESPONSE_OBSERVED",
    "OPEN_IN_CAPTURE",
    "AMBIGUOUS",
    "INCOMPLETE_EVIDENCE",
)
DEREGISTRATION_OUTCOMES = (
    "DEREGISTRATION_REQUEST_OBSERVED",
    "DEREGISTRATION_RESPONSE_OBSERVED",
    "DEREGISTRATION_ACCEPTED_BY_SIP",
    "DEREGISTRATION_OUTCOME_UNPROVED",
)
DIAMETER_STATUSES = (
    "OBSERVED",
    "NOT_OBSERVED_IN_SUPPLIED_ARTIFACT",
    "NOT_SUPPLIED",
    "AMBIGUOUS",
    "CONFLICTING",
)
ASSOCIATION_STATUSES = (
    "ESTABLISHED",
    "SUPPORTED",
    "AMBIGUOUS",
    "NOT_ESTABLISHED",
    "INSUFFICIENT_EVIDENCE",
)
CX_COMMANDS = {
    300: "UAR",
    301: "SAR",
    302: "LIR",
    303: "MAR",
    304: "RTR",
    305: "PPR",
}
DIAMETER_NAMED_STATUSES = ("MATCHED", "OPEN_REQUEST", "RESPONSE_ONLY", "AMBIGUOUS")

MISSING_EVIDENCE = (
    "CALL_ID_NOT_OBSERVED",
    "FROM_TAG_NOT_OBSERVED",
    "CSEQ_NOT_OBSERVED",
    "REQUEST_URI_NOT_OBSERVED",
    "DIAMETER_ARTIFACT_NOT_SUPPLIED",
    "COMMON_CAPTURE_NOT_VERIFIED",
    "SUBSCRIBER_IDENTITY_BRIDGE_UNAVAILABLE",
    "FINAL_RESPONSE_NOT_OBSERVED",
    "REQUEST_NOT_OBSERVED",
    "AUTHORIZATION_NOT_OBSERVED",
    "CHALLENGE_NOT_OBSERVED",
    "EXPIRATION_NOT_OBSERVED",
    "CAPTURE_TRUNCATED",
)

CONFLICT_FINDINGS = (
    "CALL_ID_MISMATCH",
    "FROM_TAG_MISMATCH",
    "REQUEST_URI_MISMATCH",
    "CSEQ_INCOMPATIBLE",
    "MULTIPLE_RETRY_CANDIDATES",
    "AUTHORIZATION_PRECEDED_CHALLENGE",
    "WRONG_AUTHORIZATION_TYPE",
    "INVALID_DEREGISTRATION_REQUEST",
    "WILDCARD_WITHOUT_EXPIRES",
    "WILDCARD_WITH_NONZERO_EXPIRES",
    "WILDCARD_WITH_ADDITIONAL_CONTACT",
    "EXPIRES_MALFORMED",
    "CONTACT_EXPIRES_MALFORMED",
    "CONTACT_EXPIRATION_OVERRIDES_EXPIRES",
    "EXPIRES_WITHOUT_CONTACT",
    "CHALLENGE_RESPONSE_NOT_BEFORE_RETRY",
    "CHALLENGE_RESPONSE_NOT_AFTER_REQUEST",
    "CHALLENGE_RESPONSE_REFERENCE_UNVERIFIED",
    "CHALLENGE_RESPONSE_STATUS_MISMATCH",
    "CAPTURE_IDENTITY_MISMATCH",
    "DIAMETER_PROVENANCE_CONFLICT",
    "UNSUPPORTED_CROSS_PROTOCOL_CLASS",

)

NOT_CONFIRMED = (
    "a SIP 200 OK to REGISTER is an observed registration response, not proof of persistent IMS registration, HSS assignment or call reachability",
    "401 and 407 are authentication challenges, not terminal registration failures",
    "Authorization header presence does not prove cryptographic authentication",
    "a Diameter Cx/Dx success is an independent application result, not proof of the SIP registration outcome",
    "no privacy-safe cross-protocol subscriber identity bridge exists, so SIP and Diameter evidence remain independent",
    "the first observed REGISTER in a capture is not necessarily the subscriber's first registration",
)

BASE_LIMITATIONS = (
    "IMS registration analysis is protocol-local and does not implement IMS session, media, SDP, RTP, Rx, Sh, charging or failure-boundary diagnosis",
    "SIP transaction and registration-attempt evidence are distinct; all attempts are capture-scoped",
    "multi-hop proxy roles are not inferred from addresses, ports or hostnames",
    "missing messages at the capture boundary are incompleteness, not proof of a timeout or failure",
    "Diameter Cx/Dx observations retain independent protocol semantics and are not joined to SIP attempts without a proven identity bridge",
    "raw Call-ID, tags, URIs, subscriber identities and authentication values are never published",
)


class InputError(ValueError):
    """Raised for malformed SIP or Diameter input."""


def _present(value: Any) -> bool:
    return value is not None and value != ""


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


def _bounded(values: list[str], limit: int = MAX_REFERENCES) -> tuple[list[str], int]:
    unique = _unique(values)
    return unique[:limit], max(0, len(unique) - limit)


def _sha256(path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _match(message: dict[str, Any]) -> dict[str, Any]:
    return message["match"]


def _first_request_match(transaction: dict[str, Any], by_reference: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    refs = transaction.get("request_event_references") or []
    return by_reference.get(refs[0]) if refs else None


def _transaction_refs(transaction: dict[str, Any], key: str) -> list[str]:
    return list(transaction.get(key) or [])


def _identity_key(match: dict[str, Any]) -> tuple[str, ...] | None:
    if not (_present(match.get("call_id")) and _present(match.get("from_tag")) and _present(match.get("request_uri"))):
        return None
    return (
        match.get("capture", ""),
        match["call_id"],
        match["request_uri"],
        match.get("from_uri") or "",
        match["from_tag"],
    )


def _standalone_attempt(transaction: dict[str, Any], request: dict[str, Any] | None, reason: str) -> dict[str, Any]:
    references = _transaction_refs(transaction, "request_event_references")[:1]
    first_ref = references[0] if references else (transaction.get("response_event_references") or [None])[0]
    capture = request.get("capture") if request else _capture_of(first_ref or "")
    frame = request.get("frame") if request else _frame_of(first_ref or "")
    if request:
        occurrence = request.get("occurrence", 1)
    else:
        tail = (first_ref or "").rpartition(":")[2]
        occurrence = int(tail.rpartition(".")[2]) if tail.rpartition(".")[2].isdigit() else 1
    return {
        "reference": f"sip-registration:{capture}:{frame}.{occurrence}",
        "capture": capture,
        "identity": None,
        "transactions": [transaction],
        "request_matches": [request] if request else [],
        "missing": ["CALL_ID_NOT_OBSERVED"] if reason == "MISSING_IDENTITY" else [],
        "conflicts": [],
        "limitations": [
            "registration-attempt grouping is unavailable because mandatory private identity evidence is absent"
            if reason == "MISSING_IDENTITY"
            else "the transaction is retained as an independent observation"
        ],
        "first_frame": frame,
        "multi_hop_candidate": False,
        "cseq_progression": "UNKNOWN",
        "standalone_reason": reason,
    }


def _group_attempts(
    transactions: list[dict[str, Any]], by_reference: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, ...], list[tuple[dict[str, Any], dict[str, Any] | None]]] = {}
    standalone: list[dict[str, Any]] = []
    for transaction in transactions:
        request = _first_request_match(transaction, by_reference)
        key = _identity_key(request) if request else None
        if key is None:
            standalone.append(
                _standalone_attempt(
                    transaction,
                    request,
                    "MISSING_IDENTITY" if request else "RESPONSE_ONLY",
                )
            )
            continue
        grouped.setdefault(key, []).append((transaction, request))

    attempts: list[dict[str, Any]] = []
    for key, members in grouped.items():
        ordered = sorted(members, key=lambda item: _match_frame(item[0]))
        current: dict[str, Any] | None = None
        for transaction, request in ordered:
            cseq = request.get("cseq_number") if request else None
            branch = request.get("via_branch") if request else None
            auth = bool(request and (request.get("authorization_count") or request.get("proxy_authorization_count")))
            previous = current
            previous_statuses = (
                list(previous["transactions"][-1].get("final_response_status_codes") or [])
                if previous
                else []
            )
            same_cseq = (
                previous is not None
                and cseq is not None
                and previous.get("last_cseq") == cseq
            )
            branch_changed = (
                previous is not None
                and branch is not None
                and previous.get("last_branch") is not None
                and branch != previous.get("last_branch")
            )
            retry_chain = (
                previous is not None
                and cseq is not None
                and previous.get("last_cseq") is not None
                and cseq > previous["last_cseq"]
                and any(status in (401, 407, 423) for status in previous_statuses)
                and (auth or not any(status in (401, 407) for status in previous_statuses))
            )
            incompatible = (
                previous is not None
                and cseq is not None
                and previous.get("last_cseq") is not None
                and cseq < previous["last_cseq"]
            )
            if current is None:
                current = {
                    "reference": f"sip-registration:{request['capture']}:{request['frame']}.{request['occurrence']}",
                    "capture": request["capture"],
                    "identity": key,
                    "transactions": [],
                    "request_matches": [],
                    "missing": [],
                    "conflicts": [],
                    "limitations": [],
                    "first_frame": request["frame"],
                    "multi_hop_candidate": False,
                    "cseq_progression": "UNKNOWN",
                    "last_cseq": None,
                    "last_branch": None,
                }
                attempts.append(current)
            elif incompatible:
                current = {
                    "reference": f"sip-registration:{request['capture']}:{request['frame']}.{request['occurrence']}",
                    "capture": request["capture"],
                    "identity": key,
                    "transactions": [],
                    "request_matches": [],
                    "missing": [],
                    "conflicts": ["CSEQ_INCOMPATIBLE"],
                    "limitations": ["the observed CSeq sequence is not compatible with one registration attempt"],
                    "first_frame": request["frame"],
                    "multi_hop_candidate": False,
                    "cseq_progression": "INCOMPATIBLE",
                    "last_cseq": None,
                    "last_branch": None,
                }
                attempts.append(current)
            elif same_cseq and branch_changed:
                current["multi_hop_candidate"] = True
                current["limitations"].append(
                    "a REGISTER with the same CSeq and a different Via branch was observed; a forwarding or proxy relationship is not proved"
                )
            elif not (same_cseq or retry_chain):
                current = {
                    "reference": f"sip-registration:{request['capture']}:{request['frame']}.{request['occurrence']}",
                    "capture": request["capture"],
                    "identity": key,
                    "transactions": [],
                    "request_matches": [],
                    "missing": [],
                    "conflicts": [],
                    "limitations": [],
                    "first_frame": request["frame"],
                    "multi_hop_candidate": False,
                    "cseq_progression": "UNKNOWN",
                    "last_cseq": None,
                    "last_branch": None,
                }
                attempts.append(current)
            current["transactions"].append(transaction)
            current["request_matches"].append(request)
            if cseq is not None:
                current["last_cseq"] = cseq
            if branch is not None:
                current["last_branch"] = branch
    return sorted(standalone + attempts, key=lambda item: (item["first_frame"], item["reference"]))


def _match_frame(transaction: dict[str, Any]) -> int:
    frame = transaction.get("first_observed_frame")
    return frame if isinstance(frame, int) else 0


def _attempt_cseq(attempt: dict[str, Any]) -> dict[str, Any]:
    values = sorted(
        {
            request["cseq_number"]
            for request in attempt["request_matches"]
            if request and request.get("cseq_number") is not None
        }
    )
    if len(values) < 2:
        progression = "SINGLE_OBSERVATION" if values else "UNKNOWN"
    elif all(right > left for left, right in zip(values, values[1:])):
        progression = "INCREASING"
    elif all(right == left for left, right in zip(values, values[1:])):
        progression = "EQUAL_OR_DUPLICATE"
    else:
        progression = "INCOMPATIBLE"
    return {"values": values[:MAX_REFERENCES], "progression": progression}


def _attempt_events(
    attempt: dict[str, Any], by_reference: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    requests: list[str] = []
    responses: list[str] = []
    challenges: list[str] = []
    retries: list[str] = []
    finals: list[str] = []
    min_expires: int | None = None
    for transaction, request in zip(attempt["transactions"], attempt["request_matches"]):
        requests.extend(transaction.get("request_event_references") or [])
        responses.extend(transaction.get("response_event_references") or [])
        statuses = transaction.get("final_response_status_codes") or []
        if 401 in statuses or 407 in statuses:
            challenges.extend(transaction.get("final_response_event_references") or [])
        finals.extend(transaction.get("final_response_event_references") or [])
        for reference in transaction.get("final_response_event_references") or []:
            match = by_reference.get(reference) or {}
            if min_expires is None and match.get("min_expires_seconds") is not None:
                min_expires = match["min_expires_seconds"]
        if request and (request.get("authorization_count") or request.get("proxy_authorization_count")):
            retries.extend(transaction.get("request_event_references") or [])
    return {
        "requests": requests,
        "responses": responses,
        "challenges": challenges,
        "retries": retries,
        "finals": finals,
        "min_expires_seconds": min_expires,
    }


def _attempt_outcome(attempt: dict[str, Any]) -> str:
    last = attempt["transactions"][-1]
    statuses = list(last.get("final_response_status_codes") or [])
    if not statuses:
        return "OPEN_IN_CAPTURE"
    if any(200 <= status < 300 for status in statuses):
        return "SUCCESS_RESPONSE_OBSERVED"
    if all(status in (401, 407) for status in statuses):
        return "INCOMPLETE_EVIDENCE"
    return "NEGATIVE_RESPONSE_OBSERVED"


def _challenge_retry_association(attempt: dict[str, Any], by_reference: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    """Decide whether a later REGISTER is an eligible retry of an observed challenge."""
    pairs = list(zip(attempt["transactions"], attempt["request_matches"]))
    challenge_index: int | None = None
    challenge_status: int | None = None
    for index, (transaction, _request) in enumerate(pairs):
        statuses = transaction.get("final_response_status_codes") or []
        if 401 in statuses:
            challenge_index, challenge_status = index, 401
            break
        if 407 in statuses:
            challenge_index, challenge_status = index, 407
            break

    def authenticated(request: dict[str, Any] | None, status: int) -> bool:
        if not request:
            return False
        if status == 401:
            return int(request.get("authorization_count") or 0) > 0
        if status == 407:
            return int(request.get("proxy_authorization_count") or 0) > 0
        return bool(
            (request.get("authorization_count") or 0)
            or (request.get("proxy_authorization_count") or 0)
        )

    if challenge_index is None:
        for transaction, request in pairs:
            if authenticated(request, 401) or authenticated(request, 407):
                return {
                    "status": "RETRY_WITHOUT_CHALLENGE",
                    "challenge_transaction_reference": None,
                    "challenge_response_event_reference": None,
                    "retry_transaction_reference": transaction["transaction_reference"],
                    "retry_request_event_reference": (
                        (transaction.get("request_event_references") or [None])[0]
                    ),
                    "basis": ["authorization_present_without_observed_challenge"],
                    "missing_evidence": ["CHALLENGE_NOT_OBSERVED"],
                    "conflict_findings": [],
                }
        return None

    challenge_transaction, challenge_request = pairs[challenge_index]
    challenge_response = (challenge_transaction.get("final_response_event_references") or [None])[0]
    challenge_cseq = challenge_request.get("cseq_number") if challenge_request else None
    base = {
        "challenge_transaction_reference": challenge_transaction["transaction_reference"],
        "challenge_response_event_reference": challenge_response,
        "retry_transaction_reference": None,
        "retry_request_event_reference": None,
        "basis": ["challenge_observed"],
        "missing_evidence": [],
        "conflict_findings": [],
    }
    challenge_event = (
        by_reference.get(challenge_response) if challenge_response is not None else None
    )
    challenge_request_reference = (
        (challenge_transaction.get("request_event_references") or [None])[0]
    )
    challenge_evidence_conflict: str | None = None
    if challenge_response is None:
        challenge_evidence_conflict = "FINAL_RESPONSE_NOT_OBSERVED"
    elif challenge_event is None:
        challenge_evidence_conflict = "CHALLENGE_RESPONSE_REFERENCE_UNVERIFIED"
    elif challenge_event.get("status_code") != challenge_status:
        challenge_evidence_conflict = "CHALLENGE_RESPONSE_STATUS_MISMATCH"
    elif challenge_request_reference is None or (
        _reference_order(challenge_response) <= _reference_order(challenge_request_reference)
    ):
        challenge_evidence_conflict = "CHALLENGE_RESPONSE_NOT_AFTER_REQUEST"
    ordering_conflict: str | None = None
    authorization_before = any(
        authenticated(request, challenge_status)
        for _transaction, request in pairs[: challenge_index + 1]
    )
    candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
    wrong_type = False
    incompatible = False
    if challenge_evidence_conflict is None:
        for transaction, request in pairs[challenge_index + 1 :]:
            if not request:
                continue
            statuses = transaction.get("final_response_status_codes") or []
            next_challenge = 401 in statuses or 407 in statuses
            other_status = 407 if challenge_status == 401 else 401
            if authenticated(request, other_status) and not authenticated(request, challenge_status):
                wrong_type = True
                if next_challenge:
                    break
                continue
            if not authenticated(request, challenge_status):
                if next_challenge:
                    break
                continue
            cseq = request.get("cseq_number")
            if cseq is None or challenge_cseq is None or cseq <= challenge_cseq:
                incompatible = True
                if next_challenge:
                    break
                continue
            retry_reference = (transaction.get("request_event_references") or [None])[0]
            if retry_reference is None:
                continue
            if _capture_of(challenge_response) != _capture_of(retry_reference):
                ordering_conflict = "CAPTURE_IDENTITY_MISMATCH"
                if next_challenge:
                    break
                continue
            if _reference_order(retry_reference) <= _reference_order(challenge_response):
                ordering_conflict = "CHALLENGE_RESPONSE_NOT_BEFORE_RETRY"
                if next_challenge:
                    break
                continue
            candidates.append((transaction, request))
            if next_challenge:
                break
    if challenge_evidence_conflict is not None:
        if challenge_evidence_conflict == "FINAL_RESPONSE_NOT_OBSERVED":
            base.update(
                {
                    "status": "CHALLENGE_WITHOUT_RETRY",
                    "missing_evidence": ["FINAL_RESPONSE_NOT_OBSERVED"],
                    "basis": ["challenge_response_evidence_missing"],
                }
            )
            return base
        base.update(
            {
                "status": "NOT_ASSOCIATED",
                "conflict_findings": [challenge_evidence_conflict],
                "basis": ["challenge_response_evidence_not_usable"],
            }
        )
        return base
    if len(candidates) == 0 and ordering_conflict is not None:
        base.update(
            {
                "status": "NOT_ASSOCIATED",
                "conflict_findings": [ordering_conflict],
                "basis": ["challenge_response_does_not_precede_eligible_retry"],
            }
        )
        return base
    if len(candidates) == 1:
        transaction, request = candidates[0]
        base.update(
            {
                "status": "ASSOCIATED",
                "retry_transaction_reference": transaction["transaction_reference"],
                "retry_request_event_reference": (
                    (transaction.get("request_event_references") or [None])[0]
                ),
                "basis": [
                    "challenge_observed",
                    "challenge_response_precedes_retry",
                    "later_register_observed",
                    "cseq_increased",
                    "authorization_present",
                ],
            }
        )
        return base
    if len(candidates) > 1:
        cseq_values = {
            request.get("cseq_number") for _transaction, request in candidates
        }
        if len(cseq_values) == 1:
            transaction, request = candidates[0]
            base.update(
                {
                    "status": "ASSOCIATED",
                    "retry_transaction_reference": transaction["transaction_reference"],
                    "retry_request_event_reference": (
                        (transaction.get("request_event_references") or [None])[0]
                    ),
                    "candidate_transaction_references": [
                        item[0]["transaction_reference"] for item in candidates[:MAX_REFERENCES]
                    ],
                    "candidate_request_event_references": [
                        (item[0].get("request_event_references") or [None])[0]
                        for item in candidates[:MAX_REFERENCES]
                    ],
                    "basis": [
                        "challenge_observed",
                        "challenge_response_precedes_retry",
                        "later_register_observed",
                        "cseq_increased",
                        "authorization_present",
                        "multi_hop_copies_of_one_logical_retry",
                    ],
                }
            )
            return base
        base.update(
            {
                "status": "AMBIGUOUS",
                "candidate_transaction_references": [
                    transaction["transaction_reference"] for transaction, _request in candidates[:MAX_REFERENCES]
                ],
                "candidate_request_event_references": [
                    (transaction.get("request_event_references") or [None])[0]
                    for transaction, _request in candidates[:MAX_REFERENCES]
                ],
                "conflict_findings": ["MULTIPLE_RETRY_CANDIDATES"],
            }
        )
        return base
    if authorization_before:
        base.update(
            {
                "status": "NOT_ASSOCIATED",
                "conflict_findings": ["AUTHORIZATION_PRECEDED_CHALLENGE"],
                "basis": ["authorization_preceded_challenge"],
            }
        )
        return base
    if incompatible:
        base.update(
            {
                "status": "NOT_ASSOCIATED",
                "conflict_findings": ["CSEQ_INCOMPATIBLE"],
                "basis": ["later_authorized_register_with_incompatible_cseq"],
            }
        )
        return base
    if wrong_type:
        base.update(
            {
                "status": "NOT_ASSOCIATED",
                "conflict_findings": ["WRONG_AUTHORIZATION_TYPE"],
                "basis": ["later_register_used_the_other_challenge_type"],
            }
        )
        return base
    base["status"] = "CHALLENGE_WITHOUT_RETRY"
    base["missing_evidence"] = ["AUTHORIZATION_NOT_OBSERVED"]
    return base


def _authentication_status(association: dict[str, Any] | None) -> str:
    if association is None:
        return "NOT_OBSERVED"
    return {
        "ASSOCIATED": "CHALLENGE_RETRY_ASSOCIATED",
        "CHALLENGE_WITHOUT_RETRY": "CHALLENGE_WITHOUT_OBSERVED_RETRY",
        "RETRY_WITHOUT_CHALLENGE": "RETRY_WITHOUT_OBSERVED_CHALLENGE",
        "NOT_ASSOCIATED": "RETRY_NOT_ESTABLISHED",
        "AMBIGUOUS": "RETRY_NOT_ESTABLISHED",
    }[association["status"]]


def _contact_evidence(request: dict[str, Any]) -> dict[str, Any]:
    wildcard_count = int(request.get("contact_wildcard_count") or 0)
    non_wildcard_count = int(request.get("contact_non_wildcard_count") or 0)
    if request.get("contact_wildcard"):
        wildcard_count = max(wildcard_count, 1)
    if request.get("contact_non_wildcard"):
        non_wildcard_count = max(non_wildcard_count, 1)
    if not non_wildcard_count and (
        request.get("contact_expires_seconds") is not None
        or request.get("contact_expires_present")
    ):
        non_wildcard_count = 1
    entry_count = int(request.get("contact_entry_count") or 0)
    entry_count = max(entry_count, wildcard_count + non_wildcard_count)
    return {
        "entry_count": entry_count,
        "wildcard_count": wildcard_count,
        "non_wildcard_count": non_wildcard_count,
        "explicit_count": int(request.get("contact_explicit_expires_count") or 0),
        "zero_count": int(request.get("contact_zero_expires_count") or 0),
        "positive_count": int(request.get("contact_positive_expires_count") or 0),
        "malformed_count": int(request.get("contact_malformed_expires_count") or 0),
        "without_explicit_count": int(
            request.get("contact_without_explicit_expires_count") or 0
        ),
        "complete": bool(request.get("contact_expiration_complete")),
    }


def _removal_observation(
    transaction: dict[str, Any], request: dict[str, Any]
) -> dict[str, Any] | None:
    """Return one REGISTER request's own binding-removal observation."""
    contact = _contact_evidence(request)
    expires_present = bool(request.get("expires_present"))
    expires_valid = request.get("expires_valid", True) is not False
    expires = request.get("expires_seconds")
    expires_malformed = expires_present and not expires_valid
    contact_malformed = contact["malformed_count"] > 0
    wildcard = contact["wildcard_count"] > 0
    non_wildcard = contact["non_wildcard_count"] > 0
    expires_zero = expires_present and expires_valid and expires == 0
    removal_related = (
        wildcard
        or expires_zero
        or contact["zero_count"] > 0
        or expires_malformed
        or contact_malformed
    )
    if not removal_related:
        return None

    invalidity: list[str] = []
    scope = "NONE"
    valid_all_bindings = False
    if wildcard:
        if non_wildcard:
            invalidity.append("WILDCARD_WITH_ADDITIONAL_CONTACT")
        if expires_malformed:
            invalidity.append("EXPIRES_MALFORMED")
        elif not expires_present:
            invalidity.append("WILDCARD_WITHOUT_EXPIRES")
        elif expires != 0:
            invalidity.append("WILDCARD_WITH_NONZERO_EXPIRES")
        elif not non_wildcard and not contact_malformed:
            scope = "ALL_BINDINGS"
            valid_all_bindings = True
    elif non_wildcard:
        if expires_malformed:
            invalidity.append("EXPIRES_MALFORMED")
        if contact_malformed:
            invalidity.append("CONTACT_EXPIRES_MALFORMED")
        explicit_zero = contact["zero_count"] > 0
        default_zero_applies = expires_zero and contact["without_explicit_count"] > 0
        if explicit_zero or default_zero_applies:
            scope = "CONTACT_SCOPED"
        elif expires_zero and contact["without_explicit_count"] == 0 and (
            contact["positive_count"] > 0
        ):
            invalidity.append("CONTACT_EXPIRATION_OVERRIDES_EXPIRES")
    elif expires_malformed:
        invalidity.append("EXPIRES_MALFORMED")
    elif expires_zero:
        invalidity.append("EXPIRES_WITHOUT_CONTACT")

    request_valid = (
        scope != "NONE"
        and not contact_malformed
        and not (wildcard and invalidity)
    )
    statuses = list(transaction.get("final_response_status_codes") or [])
    final_references = list(transaction.get("final_response_event_references") or [])
    response_reference = final_references[0] if final_references else None
    response_code = statuses[0] if statuses else None
    accepted = any(200 <= status < 300 for status in statuses)
    if scope != "NONE" and request_valid and accepted:
        outcome = "DEREGISTRATION_ACCEPTED_BY_SIP"
    elif scope != "NONE" and statuses:
        outcome = "DEREGISTRATION_RESPONSE_OBSERVED"
    else:
        outcome = "DEREGISTRATION_OUTCOME_UNPROVED"
    missing = []
    if not statuses:
        missing.append("FINAL_RESPONSE_NOT_OBSERVED")
    return {
        "transaction_reference": transaction.get("transaction_reference"),
        "request_event_reference": (transaction.get("request_event_references") or [None])[0],
        "scope": scope,
        "valid_all_bindings_request": valid_all_bindings,
        "request_valid": request_valid,
        "removal_request": scope != "NONE",
        "mixed_contact_expiration": (
            contact["zero_count"] > 0 and contact["positive_count"] > 0
        ),
        "contact_expiration_complete": contact["complete"],
        "contact_entry_count": contact["entry_count"],
        "contact_zero_expires_count": contact["zero_count"],
        "contact_positive_expires_count": contact["positive_count"],
        "contact_without_explicit_expires_count": contact["without_explicit_count"],
        "contact_malformed_expires_count": contact["malformed_count"],
        "response_event_reference": response_reference,
        "response_code": response_code,
        "response_observed": bool(statuses),
        "accepted_by_sip": accepted,
        "outcome": outcome,
        "invalidity": sorted(dict.fromkeys(invalidity)),
        "missing_evidence": missing,
    }


def _deregistration(
    attempt: dict[str, Any], events: dict[str, Any]
) -> dict[str, Any] | None:
    """Return per-transaction binding-removal evidence, including invalid requests.

    RFC 3261 wildcard removal requires ``Contact: *`` together with ``Expires: 0``.
    A zero default ``Expires`` header without a Contact does not change the
    binding list, and a Contact-specific expiration parameter overrides the
    default. Each removal observation is bound to its own REGISTER transaction
    and final response; a 2xx for an unrelated transaction is never attributed
    to a removal request.
    """
    observations: list[dict[str, Any]] = []
    for transaction, request in zip(attempt["transactions"], attempt["request_matches"]):
        if not request:
            continue
        observation = _removal_observation(transaction, request)
        if observation is not None:
            observations.append(observation)
    if not observations:
        return None

    scopes = [observation["scope"] for observation in observations]
    if "ALL_BINDINGS" in scopes:
        scope = "ALL_BINDINGS"
    elif "CONTACT_SCOPED" in scopes:
        scope = "CONTACT_SCOPED"
    else:
        scope = "NONE"
    accepted = any(observation["accepted_by_sip"] for observation in observations)
    if any(item["outcome"] == "DEREGISTRATION_ACCEPTED_BY_SIP" for item in observations):
        outcome = "DEREGISTRATION_ACCEPTED_BY_SIP"
    elif any(item["outcome"] == "DEREGISTRATION_RESPONSE_OBSERVED" for item in observations):
        outcome = "DEREGISTRATION_RESPONSE_OBSERVED"
    else:
        outcome = "DEREGISTRATION_OUTCOME_UNPROVED"
    invalidity = sorted(
        dict.fromkeys(
            finding
            for observation in observations
            for finding in observation["invalidity"]
        )
    )
    return {
        "request_observed": True,
        "response_observed": any(item["response_observed"] for item in observations),
        "accepted_by_sip": accepted,
        "outcome": outcome,
        "scope": scope,
        "valid_all_bindings_request": any(
            item["valid_all_bindings_request"] for item in observations
        ),
        "expires_seconds": next(
            (request.get("expires_seconds") for request in attempt["request_matches"]
             if request and request.get("expires_seconds") is not None),
            None,
        ),
        "contact_expires_seconds": next(
            (request.get("contact_expires_seconds") for request in attempt["request_matches"]
             if request and request.get("contact_expires_seconds") is not None),
            None,
        ),
        "contact_wildcard": any(
            request and request.get("contact_wildcard")
            for request in attempt["request_matches"]
        ),
        "contact_non_wildcard": any(
            request and request.get("contact_non_wildcard")
            for request in attempt["request_matches"]
        ),
        "mixed_contact_expiration": any(
            observation["mixed_contact_expiration"] for observation in observations
        ),
        "contact_expiration_complete": all(
            observation["contact_expiration_complete"] for observation in observations
        ),
        "contact_entry_count": max(
            (observation["contact_entry_count"] for observation in observations),
            default=0,
        ),
        "contact_zero_expires_count": sum(
            observation["contact_zero_expires_count"] for observation in observations
        ),
        "contact_positive_expires_count": sum(
            observation["contact_positive_expires_count"] for observation in observations
        ),
        "contact_without_explicit_expires_count": sum(
            observation["contact_without_explicit_expires_count"]
            for observation in observations
        ),
        "contact_malformed_expires_count": sum(
            observation["contact_malformed_expires_count"] for observation in observations
        ),
        "transaction_observations": observations[:MAX_REFERENCES],
        "omitted_transaction_observation_count": max(
            0, len(observations) - MAX_REFERENCES
        ),
        "invalidity": invalidity,
    }


def _registration_type(
    attempt: dict[str, Any],
    previous_success: bool,
    events: dict[str, list[str]],
) -> str:
    requests = [request for request in attempt["request_matches"] if request]
    if not requests:
        return "UNDETERMINED"
    expires_values = [request.get("expires_seconds") for request in requests]
    positive_expires = any(value is not None and value > 0 for value in expires_values)
    if previous_success and positive_expires and not events["challenges"]:
        return "REFRESH_OBSERVED"
    if previous_success:
        return "RE_REGISTRATION_CANDIDATE"
    return "INITIAL_REGISTRATION_CANDIDATE"


def _public_association(association: dict[str, Any] | None) -> dict[str, Any] | None:
    if association is None:
        return None
    return {
        "status": association["status"],
        "challenge_transaction_reference": association.get("challenge_transaction_reference"),
        "challenge_response_event_reference": association.get("challenge_response_event_reference"),
        "retry_transaction_reference": association.get("retry_transaction_reference"),
        "retry_request_event_reference": association.get("retry_request_event_reference"),
        "candidate_transaction_references": list(
            association.get("candidate_transaction_references") or []
        ),
        "candidate_request_event_references": list(
            association.get("candidate_request_event_references") or []
        ),
        "basis": list(association.get("basis") or []),
        "missing_evidence": list(association.get("missing_evidence") or []),
        "conflict_findings": list(association.get("conflict_findings") or []),
    }


def _build_attempt(
    attempt: dict[str, Any],
    previous_success: bool,
    by_reference: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    events = _attempt_events(attempt, by_reference)
    association = _challenge_retry_association(attempt, by_reference)
    has_request = bool([request for request in attempt["request_matches"] if request])
    outcome = _attempt_outcome(attempt)
    if not has_request:
        outcome = "INCOMPLETE_EVIDENCE"
    authentication = _authentication_status(association)
    deregistration = _deregistration(attempt, events)
    registration_type = (
        "DEREGISTRATION_REQUESTED"
        if deregistration is not None and deregistration["scope"] != "NONE"
        else "UNDETERMINED"
        if attempt["identity"] is None
        else _registration_type(attempt, previous_success, events)
    )
    missing = list(attempt["missing"])
    conflicts = list(attempt["conflicts"])
    if association is not None:
        missing.extend(association.get("missing_evidence") or [])
        conflicts.extend(association.get("conflict_findings") or [])
    if deregistration is not None and deregistration["scope"] == "NONE":
        conflicts.append("INVALID_DEREGISTRATION_REQUEST")
        conflicts.extend(deregistration["invalidity"])
    if not has_request:
        missing.append("REQUEST_NOT_OBSERVED")
    if outcome == "OPEN_IN_CAPTURE":
        missing.append("FINAL_RESPONSE_NOT_OBSERVED")
    if deregistration is not None and not deregistration["response_observed"]:
        missing.append("FINAL_RESPONSE_NOT_OBSERVED")
    if not any(request and (request.get("expires_seconds") is not None or request.get("contact_expires_seconds") is not None) for request in attempt["request_matches"]):
        missing.append("EXPIRATION_NOT_OBSERVED")
    limitations = list(attempt["limitations"])
    if not has_request:
        limitations.append(
            "a REGISTER response without an observed request is retained as an independent response observation, not a successful registration attempt"
        )
    if events["retries"]:
        limitations.append(
            "Authorization presence and a 2xx response do not prove cryptographic authentication or persistent registration"
        )
    if attempt["multi_hop_candidate"]:
        limitations.append("multi-hop forwarding is unproved; the observations remain one candidate attempt")
    request_refs, request_omitted = _bounded(events["requests"])
    response_refs, response_omitted = _bounded(events["responses"])
    challenge_refs, challenge_omitted = _bounded(events["challenges"])
    retry_refs, retry_omitted = _bounded(events["retries"])
    final_refs, final_omitted = _bounded(events["finals"])
    source_frames, source_omitted = _bounded(
        sorted(
            {
                f"{attempt['capture']}:{reference.rpartition(':')[2]}"
                for reference in events["requests"] + events["responses"]
            }
        )
    )
    transaction_refs, transaction_omitted = _bounded(
        [transaction["transaction_reference"] for transaction in attempt["transactions"]]
    )
    return {
        "attempt_reference": attempt["reference"],
        "capture_identity": attempt["capture"],
        "registration_type": registration_type,
        "registration_type_evidence": sorted(
            {
                *(["observed_register_request"] if has_request else []),
                "prior_successful_attempt" if previous_success else "no_prior_successful_attempt",
                "positive_expires" if any(
                    request and (request.get("expires_seconds") or 0) > 0
                    for request in attempt["request_matches"]
                ) else "no_positive_expires",
            }
        ),
        "authentication_evidence_status": authentication,
        "authentication_cryptographically_verified": False,
        "challenge_retry_association": _public_association(association),
        "sip_outcome": outcome,
        "transaction_references": transaction_refs,
        "request_event_references": request_refs,
        "response_event_references": response_refs,
        "challenge_event_references": challenge_refs,
        "retry_event_references": retry_refs,
        "final_response_event_references": final_refs,
        "source_frame_references": source_frames,
        "deregistration": deregistration,
        "min_expires_evidence": {
            "present": events["min_expires_seconds"] is not None,
            "seconds": events["min_expires_seconds"],
        },
        "multi_hop_candidate": attempt["multi_hop_candidate"],
        "cseq_observations": _attempt_cseq(attempt),
        "omitted_transaction_count": transaction_omitted,
        "omitted_request_event_count": request_omitted,
        "omitted_response_event_count": response_omitted,
        "omitted_challenge_event_count": challenge_omitted,
        "omitted_retry_event_count": retry_omitted,
        "omitted_final_response_event_count": final_omitted,
        "omitted_source_frame_count": source_omitted,
        "missing_evidence": sorted(dict.fromkeys(missing)),
        "conflict_findings": sorted(dict.fromkeys(conflicts)),
        "limitations": _bounded(list(dict.fromkeys(limitations + list(BASE_LIMITATIONS))), MAX_LIMITATIONS)[0],
        "not_confirmed": list(NOT_CONFIRMED),
        "evidence_class": "DERIVED",
    }


def _load_diameter(
    path, expected_version: str | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    import json
    from pathlib import Path

    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InputError(f"supplied Diameter IMS artifact is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise InputError("supplied Diameter IMS artifact must be a JSON object")
    if raw.get("analysis_name") != "diameter-ims":
        raise InputError("supplied Diameter IMS artifact has an unexpected analysis_name")
    if raw.get("domain") != "protocol":
        raise InputError("supplied Diameter IMS artifact has an unexpected domain")
    if not isinstance(raw.get("observations"), list):
        raise InputError("supplied Diameter IMS artifact has no observation array")
    capability = raw.get("capability")
    if not isinstance(capability, dict) or capability.get("application_id") is None:
        raise InputError("supplied Diameter IMS artifact has no accepted capability block")
    for observation in raw["observations"]:
        if not isinstance(observation, dict):
            raise InputError("supplied Diameter IMS observation is not an object")
        if not isinstance(observation.get("observation_reference"), str):
            raise InputError("supplied Diameter IMS observation has no observation reference")
        if not isinstance(observation.get("transaction_reference"), str):
            raise InputError("supplied Diameter IMS observation has no transaction reference")
        if observation.get("command_code") not in CX_COMMANDS:
            continue
        if observation.get("transaction_status") not in DIAMETER_NAMED_STATUSES:
            raise InputError("supplied Diameter IMS observation has an invalid transaction status")
    evidence = {
        "source_name": source.name,
        "source_sha256": _sha256(source),
        "analysis_name": raw.get("analysis_name"),
        "analysis_version": raw.get("analysis_version"),
        "observation_count": len(raw["observations"]),
    }
    return raw, evidence


def _diameter_inventory(
    diameter: dict[str, Any] | None, evidence: dict[str, Any] | None
) -> tuple[list[dict[str, Any]], int, int, str]:
    if diameter is None:
        return [], 0, 0, "NOT_SUPPLIED"
    capability = diameter.get("capability") or {}
    application_id = capability.get("application_id")
    observations: list[dict[str, Any]] = []
    for observation in diameter["observations"]:
        if not isinstance(observation, dict):
            continue
        command_code = observation.get("command_code")
        if command_code not in CX_COMMANDS:
            continue
        result = observation.get("result") or {}
        source_refs = []
        for side in ("request", "answer"):
            reference = observation.get(side)
            if isinstance(reference, dict) and reference.get("event_reference"):
                source_refs.append(reference["event_reference"])
        sources, sources_omitted = _bounded(sorted(set(source_refs)))
        observations.append(
            {
                "diameter_observation_reference": observation.get("observation_reference"),
                "diameter_transaction_reference": observation.get("transaction_reference"),
                "command_code": command_code,
                "command_name": observation.get("command_name") or CX_COMMANDS.get(command_code),
                "application_id": application_id,
                "procedure_family": observation.get("procedure_family"),
                "transaction_status": observation.get("transaction_status"),
                "application_result": observation.get("application_result"),
                "result_namespace": result.get("namespace_status"),
                "base_result_code": result.get("base_result_code"),
                "base_result_code_name": result.get("base_result_code_name"),
                "experimental_result_code": result.get("experimental_result_code"),
                "experimental_result_code_name": result.get("experimental_result_code_name"),
                "experimental_vendor_id": result.get("experimental_vendor_id"),
                "source_event_references": sources,
                "omitted_source_event_count": sources_omitted,
                "capture_identity": (
                    (diameter.get("input_provenance") or {}).get("capture_files") or [None]
                )[0],
                "limitations": list(observation.get("limitations") or []),
                "not_confirmed": list(observation.get("not_confirmed") or []),
                "evidence_class": "OBSERVED",
            }
        )
    observations.sort(key=lambda item: (item["diameter_observation_reference"] or "", item["command_code"]))
    status = "OBSERVED" if observations else "NOT_OBSERVED_IN_SUPPLIED_ARTIFACT"
    total = len(observations)
    published = observations[:MAX_DIAMETER]
    return published, total, max(0, total - len(published)), status


def _associations(
    attempts: list[dict[str, Any]], diameter: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    total = len(attempts) * len(diameter)
    associations: list[dict[str, Any]] = []
    for attempt in attempts:
        if len(associations) >= MAX_ASSOCIATIONS:
            break
        for observation in diameter:
            if len(associations) >= MAX_ASSOCIATIONS:
                break
            same_capture = attempt["capture_identity"] == observation["capture_identity"]
            associations.append(
                {
                    "sip_attempt_reference": attempt["attempt_reference"],
                    "diameter_observation_reference": observation["diameter_observation_reference"],
                    "association_status": "NOT_ESTABLISHED",
                    "association_basis": [
                        "frame_order_only_not_sufficient",
                        "protocol_success_only_not_sufficient",
                        "no_privacy_safe_subscriber_identity_bridge",
                    ],
                    "missing_evidence": (
                        ["SUBSCRIBER_IDENTITY_BRIDGE_UNAVAILABLE"]
                        if same_capture
                        else ["COMMON_CAPTURE_NOT_VERIFIED", "SUBSCRIBER_IDENTITY_BRIDGE_UNAVAILABLE"]
                    ),
                    "conflict_findings": [],
                    "limitations": [
                        "SIP and Diameter evidence remain independent; no subscriber identity association is claimed"
                    ],
                }
            )
    return associations, total


def _timeline(
    attempt_pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    diameter: list[dict[str, Any]],
    captures: list[str],
    by_reference: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for raw, public in attempt_pairs:
        challenge_seen = False
        for transaction, request in zip(raw["transactions"], raw["request_matches"]):
            authenticated = bool(
                request
                and (request.get("authorization_count") or request.get("proxy_authorization_count"))
            )
            request_kind = "SIP_REGISTER_RETRY" if authenticated and challenge_seen else "SIP_REGISTER_REQUEST"
            for reference in transaction.get("request_event_references") or []:
                rows.append(
                    _row(reference, request_kind, transaction["transaction_reference"], public["attempt_reference"])
                )
            for reference in transaction.get("provisional_response_event_references") or []:
                rows.append(
                    _row(reference, "SIP_PROVISIONAL_RESPONSE", transaction["transaction_reference"], public["attempt_reference"])
                )
            for reference in transaction.get("final_response_event_references") or []:
                response = by_reference.get(reference) or {}
                status = response.get("status_code")
                kind = "SIP_AUTHENTICATION_CHALLENGE" if status in (401, 407) else "SIP_FINAL_RESPONSE"
                rows.append(
                    _row(reference, kind, transaction["transaction_reference"], public["attempt_reference"])
                )
            statuses = transaction.get("final_response_status_codes") or []
            if 401 in statuses or 407 in statuses:
                challenge_seen = True
    for observation in diameter:
        for reference in observation["source_event_references"]:
            rows.append(
                {
                    "row_reference": f"ims-timeline:{_capture_of(reference)}:{_frame_of(reference)}.{reference.rpartition('.')[2]}:DIAMETER",
                    "capture_identity": _capture_of(reference),
                    "frame_number": _frame_of(reference),
                    "source_reference": reference,
                    "event_kind": "UNASSOCIATED_DIAMETER_OBSERVATION",
                    "transaction_reference": observation["diameter_transaction_reference"],
                    "attempt_reference": None,
                    "evidence_class": "OBSERVED",
                }
            )
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        unique[row["row_reference"]] = row
    ordered = sorted(
        unique.values(),
        key=lambda row: (row["capture_identity"], row["frame_number"], row["row_reference"]),
    )
    omitted = max(0, len(ordered) - MAX_TIMELINE_ROWS)
    sip_rows = [row for row in ordered if row["event_kind"].startswith("SIP_")]
    diameter_rows = [row for row in ordered if not row["event_kind"].startswith("SIP_")]
    sip_captures = sorted({row["capture_identity"] for row in sip_rows})
    diameter_captures = sorted({row["capture_identity"] for row in diameter_rows})
    cross_source = bool(sip_rows and diameter_rows)
    if cross_source:
        global_order_proven = False
        ordering_basis = "SOURCE_LOCAL_ONLY"
        ordering_scope = "CROSS_SOURCE_UNVERIFIED"
    elif diameter_rows:
        global_order_proven = len(diameter_captures) <= 1
        ordering_basis = (
            "SINGLE_CAPTURE_FRAME_ORDER" if len(diameter_captures) <= 1 else "SOURCE_LOCAL_ONLY"
        )
        ordering_scope = (
            "DIAMETER_ONLY_SINGLE_CAPTURE"
            if len(diameter_captures) <= 1
            else "DIAMETER_ONLY_MULTI_CAPTURE"
        )
    else:
        global_order_proven = len(sip_captures) <= 1
        ordering_basis = (
            "SINGLE_CAPTURE_FRAME_ORDER" if len(sip_captures) <= 1 else "SOURCE_LOCAL_ONLY"
        )
        ordering_scope = (
            "SIP_ONLY_SINGLE_CAPTURE" if len(sip_captures) <= 1 else "SIP_ONLY_MULTI_CAPTURE"
        )
    return {
        "global_order_proven": global_order_proven,
        "ordering_basis": ordering_basis,
        "ordering_scope": ordering_scope,
        "sip_row_count": len(sip_rows),
        "diameter_row_count": len(diameter_rows),
        "row_count": len(ordered),
        "rows_omitted": omitted,
        "rows": ordered[:MAX_TIMELINE_ROWS],
    }


def _row(reference: str, kind: str, transaction_reference: str, attempt_reference: str) -> dict[str, Any]:
    tail = reference.rpartition(":")[2]
    return {
        "row_reference": f"ims-timeline:{_capture_of(reference)}:{tail}:{kind}",
        "capture_identity": _capture_of(reference),
        "frame_number": _frame_of(reference),
        "source_reference": reference,
        "event_kind": kind,
        "transaction_reference": transaction_reference,
        "attempt_reference": attempt_reference,
        "evidence_class": "OBSERVED",
    }


def build_analysis(
    messages: list[dict[str, Any]],
    transaction_document: dict[str, Any],
    *,
    diameter_document: dict[str, Any] | None = None,
    diameter_evidence: dict[str, Any] | None = None,
    sip_provenance: dict[str, Any],
) -> dict[str, Any]:
    by_reference = {_match(message)["source_reference"]: _match(message) for message in messages}
    transactions = [
        transaction
        for transaction in transaction_document["transactions"]
        if transaction["transaction_method"] == "REGISTER"
    ]
    attempts_raw = _group_attempts(transactions, by_reference)
    attempts_all: list[dict[str, Any]] = []
    seen_identity_success: dict[tuple[str, ...], bool] = {}
    for attempt in attempts_raw:
        identity = attempt["identity"]
        previous_success = seen_identity_success.get(identity, False)
        public = _build_attempt(attempt, previous_success, by_reference)
        attempts_all.append(public)
        if identity and public["sip_outcome"] == "SUCCESS_RESPONSE_OBSERVED":
            seen_identity_success[identity] = True
    published_attempts = attempts_all[:MAX_ATTEMPTS]
    diameter_published, diameter_total, diameter_omitted, diameter_status = _diameter_inventory(
        diameter_document, diameter_evidence
    )
    associations, association_total = _associations(published_attempts, diameter_published)
    captures = sorted({_match(message)["capture"] for message in messages})
    diameter_captures = sorted(
        (diameter_document or {}).get("input_provenance", {}).get("capture_files", []) or []
    )
    raw_by_reference = {raw["reference"]: raw for raw in attempts_raw}
    timeline = _timeline(
        [(raw_by_reference[public["attempt_reference"]], public) for public in published_attempts],
        diameter_published,
        captures,
        by_reference,
    )
    inventory_all = [_public_inventory(transaction) for transaction in transactions]
    inventory_published = inventory_all[:MAX_INVENTORY]
    return {
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "domain": DOMAIN,
        "capability": {
            "capability_status": CAPABILITY_STATUS,
            "implemented": [
                "SIP_REGISTER_TRANSACTION_INVENTORY",
                "REGISTRATION_ATTEMPT_EVIDENCE",
                "AUTHENTICATION_CHALLENGE_RETRY_EVIDENCE",
                "REGISTRATION_LIFECYCLE_EVIDENCE",
                "DIAMETER_CX_DX_INDEPENDENT_INVENTORY",
                "REGISTRATION_TIMELINE",
            ],
            "not_implemented": [
                "IMS_SESSION_DOMAIN",
                "IMS_MEDIA_DOMAIN",
                "SDP",
                "RTP",
                "DIAMETER_RX",
                "DIAMETER_SH",
                "CROSS_PROTOCOL_SUBSCRIBER_IDENTITY_BRIDGE",
                "IMS_FAILURE_BOUNDARY",
            ],
            "interface_identity": "UNPROVED",
            "cross_protocol_association_policy": "FAIL_CLOSED_WITHOUT_IDENTITY_BRIDGE",
        },
        "input_provenance": {
            "sip_inputs": [
                {
                    "source_name": sip_provenance.get("source_name"),
                    "source_sha256": sip_provenance.get("source_sha256"),
                    "input_format": sip_provenance.get("input_format"),
                    "decoder": sip_provenance.get("decoder"),
                    "event_count": len(messages),
                    "transaction_count": len(transaction_document["transactions"]),
                }
            ],
            "diameter_artifact": diameter_evidence,
            "diameter_status": diameter_status,
            "common_capture_verified": False,
            "capture_identity_basis": ["SIP source capture name; Diameter artifact captures are compared only for equality"],
            "capture_identities": captures,
            "diameter_capture_identities": diameter_captures,
        },
        "sip_registration_inventory": inventory_published,
        "registration_attempts": published_attempts,
        "diameter_ims_inventory": diameter_published,
        "cross_protocol_associations": associations,
        "timeline": timeline,
        "completeness": {
            "sip_event_count": len(messages),
            "sip_transaction_count": len(transaction_document["transactions"]),
            "register_transaction_count": len(transactions),
            "registration_inventory_count": len(inventory_all),
            "registration_inventory_omitted": len(inventory_all) - len(inventory_published),
            "attempt_count": len(attempts_all),
            "attempts_omitted": len(attempts_all) - len(published_attempts),
            "diameter_observation_count": diameter_total,
            "diameter_observations_omitted": diameter_omitted,
            "association_count": association_total,
            "associations_omitted": association_total - len(associations),
            "timeline_row_count": timeline["row_count"],
            "timeline_rows_omitted": timeline["rows_omitted"],
        },
        "limitations": list(BASE_LIMITATIONS),
        "not_confirmed": list(NOT_CONFIRMED),
    }


def _public_inventory(transaction: dict[str, Any]) -> dict[str, Any]:
    request_refs, request_omitted = _bounded(transaction.get("request_event_references") or [])
    final_refs, final_omitted = _bounded(transaction.get("final_response_event_references") or [])
    return {
        "transaction_reference": transaction["transaction_reference"],
        "transaction_method": transaction.get("transaction_method"),
        "transaction_state": transaction.get("transaction_state"),
        "observed_evidence_status": transaction.get("observed_evidence_status"),
        "matching_status": transaction.get("matching_status"),
        "request_event_references": request_refs,
        "provisional_response_event_references": _bounded(
            transaction.get("provisional_response_event_references") or []
        )[0],
        "final_response_event_references": final_refs,
        "response_event_references": _bounded(transaction.get("response_event_references") or [])[0],
        "final_response_status_codes": list(transaction.get("final_response_status_codes") or []),
        "first_observed_frame": transaction.get("first_observed_frame"),
        "last_observed_frame": transaction.get("last_observed_frame"),
        "capture_identity": _capture_of((request_refs or transaction.get("response_event_references") or [""])[0]),
        "retransmission_event_references": _bounded(transaction.get("retransmission_event_references") or [])[0],
        "omitted_request_event_count": request_omitted,
        "omitted_final_response_event_count": final_omitted,
        "missing_evidence": list(transaction.get("missing_evidence") or []),
        "conflict_findings": list(transaction.get("conflict_findings") or []),
        "limitations": list(transaction.get("limitations") or []),
        "evidence_class": "DERIVED",
    }


def validate_analysis(document: dict[str, Any], *, sip_event_references: set[str] | None = None, transaction_references: set[str] | None = None) -> None:
    if not isinstance(document, dict):
        raise InputError("analysis document must be an object")
    for field in ("analysis_name", "analysis_version", "domain", "capability", "input_provenance", "sip_registration_inventory", "registration_attempts", "diameter_ims_inventory", "cross_protocol_associations", "timeline", "completeness", "limitations", "not_confirmed"):
        if field not in document:
            raise InputError(f"analysis document is missing {field}")
    if document["analysis_name"] != ANALYSIS_NAME or document["analysis_version"] != ANALYSIS_VERSION:
        raise InputError("analysis document identity is not accepted")
    if document["capability"].get("capability_status") != CAPABILITY_STATUS:
        raise InputError("analysis capability status is not accepted")
    attempt_references = set()
    transaction_refs = set()
    for attempt in document["registration_attempts"]:
        reference = attempt.get("attempt_reference")
        if not isinstance(reference, str) or not REGISTRATION_REFERENCE_PATTERN.fullmatch(reference):
            raise InputError("invalid registration attempt reference")
        if reference in attempt_references:
            raise InputError("duplicate registration attempt reference")
        attempt_references.add(reference)
        if attempt.get("registration_type") not in REGISTRATION_TYPES:
            raise InputError("invalid registration type")
        if attempt.get("authentication_evidence_status") not in AUTHENTICATION_STATUSES:
            raise InputError("invalid authentication evidence status")
        if attempt.get("sip_outcome") not in SIP_OUTCOMES:
            raise InputError("invalid SIP outcome")
        for key in ("transaction_references", "request_event_references", "response_event_references", "challenge_event_references", "retry_event_references", "final_response_event_references"):
            for value in attempt.get(key) or []:
                if key == "transaction_references":
                    if not isinstance(value, str) or not TRANSACTION_REFERENCE_PATTERN.fullmatch(value):
                        raise InputError("invalid transaction reference in a registration attempt")
                    transaction_refs.add(value)
                elif not isinstance(value, str) or not EVENT_REFERENCE_PATTERN.fullmatch(value):
                    raise InputError("invalid source reference in a registration attempt")
                if sip_event_references is not None and key != "transaction_references" and value not in sip_event_references:
                    raise InputError("a registration attempt references an absent SIP event")
        if transaction_references is not None and not set(attempt.get("transaction_references") or []).issubset(transaction_references):
            raise InputError("a registration attempt references an absent SIP transaction")
        association = attempt.get("challenge_retry_association")
        if association is not None:
            if association.get("status") not in {
                "ASSOCIATED",
                "CHALLENGE_WITHOUT_RETRY",
                "RETRY_WITHOUT_CHALLENGE",
                "NOT_ASSOCIATED",
                "AMBIGUOUS",
            }:
                raise InputError("invalid challenge/retry association status")
            for key in (
                "challenge_transaction_reference",
                "retry_transaction_reference",
            ):
                value = association.get(key)
                if value is not None and (
                    not isinstance(value, str)
                    or not TRANSACTION_REFERENCE_PATTERN.fullmatch(value)
                ):
                    raise InputError("invalid challenge/retry transaction reference")
            for key in (
                "challenge_response_event_reference",
                "retry_request_event_reference",
            ):
                value = association.get(key)
                if value is not None and (
                    not isinstance(value, str) or not EVENT_REFERENCE_PATTERN.fullmatch(value)
                ):
                    raise InputError("invalid challenge/retry event reference")
            if attempt.get("authentication_evidence_status") == "CHALLENGE_RETRY_ASSOCIATED":
                if association.get("status") != "ASSOCIATED":
                    raise InputError(
                        "CHALLENGE_RETRY_ASSOCIATED requires an accepted association record"
                    )
                if not association.get("retry_transaction_reference"):
                    raise InputError(
                        "CHALLENGE_RETRY_ASSOCIATED requires an eligible retry transaction"
                    )
        for omitted_key in (
            "omitted_transaction_count",
            "omitted_request_event_count",
            "omitted_response_event_count",
            "omitted_challenge_event_count",
            "omitted_retry_event_count",
            "omitted_final_response_event_count",
            "omitted_source_frame_count",
        ):
            value = attempt.get(omitted_key)
            if not isinstance(value, int) or value < 0:
                raise InputError(f"invalid omission accounting in {omitted_key}")
        deregistration = attempt.get("deregistration")
        if deregistration is not None:
            if deregistration.get("scope") not in {"ALL_BINDINGS", "CONTACT_SCOPED", "NONE"}:
                raise InputError("invalid de-registration scope")
            if deregistration.get("valid_all_bindings_request"):
                wildcard_valid = (
                    deregistration.get("contact_wildcard")
                    and deregistration.get("expires_seconds") == 0
                    and not deregistration.get("contact_non_wildcard")
                )
                if not wildcard_valid:
                    raise InputError(
                        "valid all-bindings removal requires wildcard Contact with Expires: 0"
                    )
                if deregistration.get("scope") != "ALL_BINDINGS":
                    raise InputError("valid all-bindings removal requires ALL_BINDINGS scope")
            if (
                deregistration.get("outcome") == "DEREGISTRATION_ACCEPTED_BY_SIP"
                and deregistration.get("scope") == "NONE"
            ):
                raise InputError(
                    "an invalid de-registration request cannot be accepted as a valid removal"
                )
            observations = deregistration.get("transaction_observations")
            if observations is not None:
                if not isinstance(observations, list):
                    raise InputError("de-registration transaction observations must be an array")
                accepted_transaction_outcomes = 0
                for observation in observations:
                    if not isinstance(observation, dict):
                        raise InputError("a de-registration transaction observation is not an object")
                    if observation.get("scope") not in {"ALL_BINDINGS", "CONTACT_SCOPED", "NONE"}:
                        raise InputError("invalid per-transaction de-registration scope")
                    if observation.get("outcome") not in DEREGISTRATION_OUTCOMES:
                        raise InputError("invalid per-transaction de-registration outcome")
                    if observation.get("scope") == "NONE" and observation.get(
                        "outcome"
                    ) == "DEREGISTRATION_ACCEPTED_BY_SIP":
                        raise InputError(
                            "a non-removal transaction cannot establish removal acceptance"
                        )
                    if observation.get("outcome") == "DEREGISTRATION_ACCEPTED_BY_SIP":
                        accepted_transaction_outcomes += 1
                if accepted_transaction_outcomes > 1:
                    raise InputError("multiple transactions claim accepted removal")
                if accepted_transaction_outcomes and deregistration.get("outcome") != (
                    "DEREGISTRATION_ACCEPTED_BY_SIP"
                ):
                    raise InputError(
                        "an accepted removal transaction is missing from the aggregate outcome"
                    )
    for observation in document["diameter_ims_inventory"]:
        if observation.get("command_code") not in CX_COMMANDS:
            raise InputError("a Diameter observation is not a supported Cx/Dx command")
        if observation.get("transaction_status") not in DIAMETER_NAMED_STATUSES:
            raise InputError("invalid Diameter transaction status")
    for association in document["cross_protocol_associations"]:
        if association.get("association_status") not in ASSOCIATION_STATUSES:
            raise InputError("invalid cross-protocol association status")
        if association.get("association_status") == "ESTABLISHED":
            raise InputError("no cross-protocol identity bridge is accepted in this phase")
        if association.get("sip_attempt_reference") not in attempt_references:
            raise InputError("association references an absent registration attempt")
    timeline = document["timeline"]
    rows = timeline.get("rows") or []
    rows_omitted = timeline.get("rows_omitted")
    if not isinstance(rows_omitted, int) or rows_omitted < 0:
        raise InputError("invalid timeline omission accounting")
    if timeline.get("row_count") != len(rows) + rows_omitted:
        raise InputError("timeline row count does not satisfy count conservation")
    if timeline.get("ordering_scope") not in {
        "SIP_ONLY_SINGLE_CAPTURE",
        "SIP_ONLY_MULTI_CAPTURE",
        "DIAMETER_ONLY_SINGLE_CAPTURE",
        "DIAMETER_ONLY_MULTI_CAPTURE",
        "CROSS_SOURCE_UNVERIFIED",
        "VERIFIED_COMMON_CAPTURE",
    }:
        raise InputError("invalid timeline ordering scope")
    if timeline.get("ordering_basis") not in {
        "SINGLE_CAPTURE_FRAME_ORDER",
        "SOURCE_LOCAL_ONLY",
        "VERIFIED_COMMON_CAPTURE",
    }:
        raise InputError("invalid timeline ordering basis")
    sip_rows = timeline.get("sip_row_count")
    diameter_rows = timeline.get("diameter_row_count")
    if not isinstance(sip_rows, int) or not isinstance(diameter_rows, int):
        raise InputError("invalid timeline source row accounting")
    if sip_rows + diameter_rows != timeline["row_count"]:
        raise InputError("timeline source rows do not match the total")
    if sip_rows and diameter_rows and timeline.get("global_order_proven"):
        raise InputError("unverified cross-source rows cannot claim global frame order")
    for row in timeline.get("rows") or []:
        if not isinstance(row.get("row_reference"), str) or not TIMELINE_REFERENCE_PATTERN.fullmatch(row["row_reference"]):
            raise InputError("invalid timeline row reference")
        if row.get("event_kind") not in (
            "SIP_REGISTER_REQUEST",
            "SIP_PROVISIONAL_RESPONSE",
            "SIP_AUTHENTICATION_CHALLENGE",
            "SIP_REGISTER_RETRY",
            "SIP_FINAL_RESPONSE",
            "DIAMETER_APPLICATION_OBSERVATION",
            "UNASSOCIATED_DIAMETER_OBSERVATION",
        ):
            raise InputError("invalid timeline event kind")
        if row.get("attempt_reference") is not None and row["attempt_reference"] not in attempt_references:
            raise InputError("timeline row references an absent attempt")
    completeness = document["completeness"]
    for total_key, published, omitted_key in (
        (
            "registration_inventory_count",
            len(document["sip_registration_inventory"]),
            "registration_inventory_omitted",
        ),
        (
            "attempt_count",
            len(document["registration_attempts"]),
            "attempts_omitted",
        ),
        (
            "diameter_observation_count",
            len(document["diameter_ims_inventory"]),
            "diameter_observations_omitted",
        ),
        (
            "association_count",
            len(document["cross_protocol_associations"]),
            "associations_omitted",
        ),
    ):
        omitted = completeness.get(omitted_key)
        if not isinstance(omitted, int) or omitted < 0:
            raise InputError(f"invalid omission accounting in {omitted_key}")
        if completeness.get(total_key) != published + omitted:
            raise InputError(f"{total_key} does not satisfy count conservation")
    if completeness.get("timeline_row_count") != timeline["row_count"]:
        raise InputError("timeline row count diverges from completeness accounting")
    if completeness.get("timeline_rows_omitted") != timeline["rows_omitted"]:
        raise InputError("timeline omission count diverges from completeness accounting")


def sanitize(document: Any) -> Any:
    """Recursively reject raw identity fields from a Domain document."""
    forbidden = {
        "call_id",
        "from_tag",
        "to_tag",
        "request_uri",
        "from_uri",
        "to_uri",
        "via_branch",
        "authorization",
        "proxy_authorization",
        "www_authenticate",
        "proxy_authenticate",
        "nonce",
        "response",
        "impi",
        "impu",
        "imsi",
        "body",
    }
    if isinstance(document, dict):
        for key, value in document.items():
            if key in forbidden:
                raise InputError(f"analysis output contains a forbidden identity field: {key}")
            sanitize(value)
    elif isinstance(document, list):
        for item in document:
            sanitize(item)
    elif isinstance(document, str):
        for token in ("sip:", "tel:+", "Digest ", "Authorization:"):
            if token in document:
                raise InputError("analysis output contains a raw SIP identity or authentication token")
    return document