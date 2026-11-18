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
ANALYSIS_VERSION = "1.0.0"
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


def _authentication_status(attempt: dict[str, Any], events: dict[str, list[str]]) -> str:
    challenge = bool(events["challenges"])
    retry = bool(events["retries"])
    if challenge and retry:
        return "CHALLENGE_RETRY_ASSOCIATED"
    if challenge:
        return "CHALLENGE_WITHOUT_OBSERVED_RETRY"
    if retry:
        return "RETRY_WITHOUT_OBSERVED_CHALLENGE"
    return "NOT_OBSERVED"


def _deregistration(attempt: dict[str, Any], events: dict[str, list[str]]) -> dict[str, Any] | None:
    requests = attempt["request_matches"]
    expirations = [request.get("expires_seconds") for request in requests if request]
    contact_expirations = [request.get("contact_expires_seconds") for request in requests if request]
    wildcard = any(request.get("contact_wildcard") for request in requests if request)
    requested = any(
        (value == 0) for value in expirations
    ) or any((value == 0) for value in contact_expirations) or wildcard
    if not requested:
        return None
    statuses = [status for transaction in attempt["transactions"] for status in (transaction.get("final_response_status_codes") or [])]
    accepted = any(200 <= status < 300 for status in statuses)
    return {
        "request_observed": True,
        "response_observed": bool(statuses),
        "accepted_by_sip": accepted,
        "outcome": (
            "DEREGISTRATION_ACCEPTED_BY_SIP"
            if accepted
            else "DEREGISTRATION_RESPONSE_OBSERVED"
            if statuses
            else "DEREGISTRATION_OUTCOME_UNPROVED"
        ),
        "expires_seconds": next((value for value in expirations if value is not None), None),
        "contact_expires_seconds": next((value for value in contact_expirations if value is not None), None),
        "contact_wildcard": wildcard,
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


def _build_attempt(
    attempt: dict[str, Any],
    previous_success: bool,
    by_reference: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    events = _attempt_events(attempt, by_reference)
    has_request = bool([request for request in attempt["request_matches"] if request])
    outcome = _attempt_outcome(attempt)
    if not has_request:
        outcome = "INCOMPLETE_EVIDENCE"
    authentication = _authentication_status(attempt, events)
    deregistration = _deregistration(attempt, events)
    registration_type = (
        "DEREGISTRATION_REQUESTED"
        if deregistration is not None
        else "UNDETERMINED"
        if attempt["identity"] is None
        else _registration_type(attempt, previous_success, events)
    )
    missing = list(attempt["missing"])
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
    challenge_refs, _ = _bounded(events["challenges"])
    retry_refs, _ = _bounded(events["retries"])
    final_refs, _ = _bounded(events["finals"])
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
        "sip_outcome": outcome,
        "transaction_references": transaction_refs,
        "request_event_references": request_refs,
        "response_event_references": response_refs,
        "challenge_event_references": challenge_refs,
        "retry_event_references": retry_refs,
        "final_response_event_references": final_refs,
        "source_frame_references": sorted(
            {
                f"{attempt['capture']}:{reference.rpartition(':')[2]}"
                for reference in request_refs + response_refs
            }
        ),
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
        "missing_evidence": sorted(dict.fromkeys(missing)),
        "conflict_findings": sorted(dict.fromkeys(attempt["conflicts"])),
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
) -> tuple[list[dict[str, Any]], str]:
    if diameter is None:
        return [], "NOT_SUPPLIED"
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
        sources = sorted(set(source_refs))
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
                "source_event_references": sources[:MAX_REFERENCES],
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
    return observations[:MAX_DIAMETER], status


def _associations(
    attempts: list[dict[str, Any]], diameter: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    associations: list[dict[str, Any]] = []
    for attempt in attempts:
        for observation in diameter:
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
    return associations[:MAX_ASSOCIATIONS], max(0, len(associations) - MAX_ASSOCIATIONS)


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
    return {
        "global_order_proven": len(captures) <= 1,
        "ordering_basis": (
            "SINGLE_CAPTURE_FRAME_ORDER" if len(captures) <= 1 else "SOURCE_LOCAL_ONLY"
        ),
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
    attempts: list[dict[str, Any]] = []
    seen_identity_success: dict[tuple[str, ...], bool] = {}
    for attempt in attempts_raw:
        identity = attempt["identity"]
        previous_success = seen_identity_success.get(identity, False)
        public = _build_attempt(attempt, previous_success, by_reference)
        attempts.append(public)
        if identity and public["sip_outcome"] == "SUCCESS_RESPONSE_OBSERVED":
            seen_identity_success[identity] = True
    diameter_inventory, diameter_status = _diameter_inventory(diameter_document, diameter_evidence)
    associations, associations_omitted = _associations(attempts, diameter_inventory)
    captures = sorted({_match(message)["capture"] for message in messages})
    raw_by_reference = {raw["reference"]: raw for raw in attempts_raw}
    timeline = _timeline(
        [(raw_by_reference[public["attempt_reference"]], public) for public in attempts],
        diameter_inventory,
        captures,
        by_reference,
    )
    inventory = [_public_inventory(transaction) for transaction in transactions]
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
        },
        "sip_registration_inventory": inventory[:MAX_INVENTORY],
        "registration_attempts": attempts[:MAX_ATTEMPTS],
        "diameter_ims_inventory": diameter_inventory,
        "cross_protocol_associations": associations,
        "timeline": timeline,
        "completeness": {
            "sip_event_count": len(messages),
            "sip_transaction_count": len(transaction_document["transactions"]),
            "register_transaction_count": len(transactions),
            "registration_inventory_count": len(inventory),
            "registration_inventory_omitted": max(0, len(inventory) - MAX_INVENTORY),
            "attempt_count": len(attempts),
            "attempts_omitted": max(0, len(attempts) - MAX_ATTEMPTS),
            "diameter_observation_count": len(diameter_inventory),
            "diameter_observations_omitted": max(0, len(diameter_inventory) - MAX_DIAMETER),
            "association_count": len(associations),
            "associations_omitted": associations_omitted,
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
    if timeline.get("row_count") != len(timeline.get("rows") or []):
        raise InputError("timeline row count does not match the published rows")
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
    if document["completeness"].get("attempt_count") != len(document["registration_attempts"]):
        raise InputError("attempt count does not match the published attempts")


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