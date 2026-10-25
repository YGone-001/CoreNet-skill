#!/usr/bin/env python3
"""Bounded EPC bearer lifecycle-generation evidence.

The model consumes already-extracted evidence: GTPv2-C detailed events, their
accepted transaction correlation, the accepted EPC session-control and
default-bearer analyses, the accepted S1-U observation and, when frame-level
attribution is requested, the detailed GTP-U events.

It answers three separate questions and never conflates them:

* Do repeated S1-U F-TEID advertisements describe one allocation or several?
* Does any accepted lifecycle boundary prove a new generation of an endpoint?
* Which observed G-PDUs can be attributed to a proved generation?

An advertisement family is not a bearer. A matched request/response pair removes
duplicate-message ambiguity; it does not prove a complete lifecycle, an S11 to
S5/S8 identity, PDN connectivity, UE delivery or user-plane forwarding.

The model never decodes a capture, never parses protocol bytes, never rebuilds
request/response matching from timestamps and never publishes subscriber
identity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.5.0"
ANALYSIS_NAME = "epc-bearer-lifecycle"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_SUBJECTS = 6
EXIT_OUTPUT_FAILURE = 7

MAX_LIST_ITEMS = 32
MAX_EVIDENCE_REFERENCES = 32
MAX_SUBJECTS = 256

# Reviewed S1-U receiving roles and their F-TEID interface types (TS 29.274 8.22).
ROLE_SGW = "sgw_s1u"
ROLE_ENODEB = "enodeb_s1u"
INTERFACE_TYPE_ROLE = {1: ROLE_SGW, 0: ROLE_ENODEB}
ROLE_INTERFACE_TYPE = {ROLE_SGW: 1, ROLE_ENODEB: 0}
S1U_INTERFACE_TYPES = frozenset({0, 1})

# Advertisement-family classification. These are not interchangeable.
FAMILY_SINGLE = "SINGLE_ADVERTISEMENT"
FAMILY_SAME_TRANSACTION = "SAME_TRANSACTION_ADVERTISEMENTS"
FAMILY_UPDATE = "SAME_GENERATION_UPDATE_SUPPORTED"
FAMILY_SEPARATE = "SEPARATE_GENERATIONS_ESTABLISHED"
FAMILY_COMPETING = "COMPETING_ALLOCATION_EVIDENCE"
FAMILY_INSUFFICIENT = "INSUFFICIENT_GENERATION_EVIDENCE"
FAMILY_CLASSIFICATIONS = (
    FAMILY_SINGLE,
    FAMILY_SAME_TRANSACTION,
    FAMILY_UPDATE,
    FAMILY_SEPARATE,
    FAMILY_COMPETING,
    FAMILY_INSUFFICIENT,
)

# Bounded lifecycle observations.
OBS_ALLOCATION_ADVERTISED = "ALLOCATION_ADVERTISED"
OBS_ALLOCATION_RESPONSE = "ALLOCATION_RESPONSE_OBSERVED"
OBS_ALLOCATION_ACCEPTED = "ALLOCATION_ACCEPTED_OBSERVED"
OBS_UPDATE_ADVERTISED = "ENDPOINT_UPDATE_ADVERTISED"
OBS_UPDATE_ACCEPTED = "ENDPOINT_UPDATE_ACCEPTED_OBSERVED"
OBS_RELEASE_REQUEST = "RELEASE_REQUEST_OBSERVED"
OBS_RELEASE_ACCEPTED = "RELEASE_ACCEPTED_OBSERVED"
OBS_RELEASE_REJECTED = "RELEASE_REJECTED_OBSERVED"
OBS_RELEASE_UNRESOLVED = "RELEASE_STATUS_UNRESOLVED"
OBS_ENDPOINT_REUSE = "ENDPOINT_REUSE_OBSERVED"
OBS_BOUNDARY_ESTABLISHED = "GENERATION_BOUNDARY_ESTABLISHED"
OBS_BOUNDARY_AMBIGUOUS = "GENERATION_BOUNDARY_AMBIGUOUS"
OBSERVATIONS = (
    OBS_ALLOCATION_ADVERTISED,
    OBS_ALLOCATION_RESPONSE,
    OBS_ALLOCATION_ACCEPTED,
    OBS_UPDATE_ADVERTISED,
    OBS_UPDATE_ACCEPTED,
    OBS_RELEASE_REQUEST,
    OBS_RELEASE_ACCEPTED,
    OBS_RELEASE_REJECTED,
    OBS_RELEASE_UNRESOLVED,
    OBS_ENDPOINT_REUSE,
    OBS_BOUNDARY_ESTABLISHED,
    OBS_BOUNDARY_AMBIGUOUS,
)

# Generation state. A generation is never a bearer and never a stream.
GENERATION_OPEN = "OPEN_AT_CAPTURE_END"
GENERATION_CLOSED = "CLOSED_BY_ACCEPTED_RELEASE"
GENERATION_AMBIGUOUS = "BOUNDARY_AMBIGUOUS"
GENERATION_STATES = (GENERATION_OPEN, GENERATION_CLOSED, GENERATION_AMBIGUOUS)

ASSOCIATION_SUPPORTED = "SUPPORTED"
ASSOCIATION_AMBIGUOUS = "AMBIGUOUS"
ASSOCIATION_UNRESOLVED = "GENERATION_UNRESOLVED"
ASSOCIATION_NOT_ESTABLISHED = "NOT_ESTABLISHED"
ASSOCIATION_STATUSES = (
    ASSOCIATION_SUPPORTED,
    ASSOCIATION_AMBIGUOUS,
    ASSOCIATION_UNRESOLVED,
    ASSOCIATION_NOT_ESTABLISHED,
)

DEVIATION_BEARER_IDENTITY_CONFLICT = "BEARER_IDENTITY_CONFLICT"
DEVIATION_COMPETING_ALLOCATION = "COMPETING_ALLOCATION_EVIDENCE"
DEVIATION_UNRESOLVED_BOUNDARY = "GENERATION_BOUNDARY_UNRESOLVED"
DEVIATION_UNRESOLVED_PACKETS = "GENERATION_UNRESOLVED_PACKETS"
DEVIATION_ACCOUNTING_MISMATCH = "PACKET_ACCOUNTING_MISMATCH"
DEVIATION_TYPES = (
    DEVIATION_BEARER_IDENTITY_CONFLICT,
    DEVIATION_COMPETING_ALLOCATION,
    DEVIATION_UNRESOLVED_BOUNDARY,
    DEVIATION_UNRESOLVED_PACKETS,
    DEVIATION_ACCOUNTING_MISMATCH,
)

MATCHED = "MATCHED"

# Reviewed GTPv2-C correlation strengths (TS 29.274 based transaction contract).
STRENGTH_STRONG = "STRONG"
STRENGTH_SUPPORTED = "SUPPORTED"
STRENGTH_NONE = "NONE"
REVIEWED_STRENGTHS = frozenset({STRENGTH_STRONG, STRENGTH_SUPPORTED, STRENGTH_NONE})
# Only a corroborated correlation may establish a same-transaction proof. NONE is
# a matched pair without independent corroboration, so it never proves a family or
# a release; a missing or unreviewed value is equally insufficient.
PROOF_STRENGTHS = frozenset({STRENGTH_STRONG, STRENGTH_SUPPORTED})

# Release outcome vocabulary. These are Domain classifications of an observed
# control-plane outcome, not new protocol values.
RELEASE_ACCEPTED = "ACCEPTED"
RELEASE_REJECTED = "REJECTED_OBSERVED"
RELEASE_UNRESOLVED = "UNRESOLVED"
RELEASE_OUTCOMES = (RELEASE_ACCEPTED, RELEASE_REJECTED, RELEASE_UNRESOLVED)

ACCEPTED_CAUSE_CODES = frozenset({16, 17, 18})

DELETE_FAMILIES = frozenset({"delete-session", "delete-bearer"})
UPDATE_FAMILIES = frozenset({"modify-bearer"})
ALLOCATION_FAMILIES = frozenset({"create-session"})

NOT_CONFIRMED = (
    "an advertisement family is a group of protocol advertisements, not an EPS bearer",
    "a matched request and response prove correlation, not successful user-plane provisioning",
    "an accepted Cause is a control-plane outcome; it does not confirm UE delivery or application reachability",
    "a generation reference is a scoped pseudonymous label, never a subscriber identity",
    "a numerically reused TEID is not treated as a new generation without a proved boundary",
    "an unresolved generation attribution is not packet loss and not a tunnel failure",
    "no S11 to S5/S8 session identity is asserted",
    "no complete EPC bearer state machine is implemented",
    "a release that merely repeats an endpoint value never closes a generation",
    "the exact instant user-plane forwarding stopped is not proven by an accepted release response",
)


class InputError(ValueError):
    """Raised when a supplied structured input cannot be normalized."""


def safe_name(path: Path) -> str:
    return path.name


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path.name}")
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise InputError(
                    f"{path.name}: invalid JSON Lines at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(record, dict):
                raise InputError(f"{path.name}: JSON Lines record at line {line_number} is not an object")
            records.append(record)
    return records


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise InputError(f"input file does not exist: {path.name}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"{path.name}: invalid JSON: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"{path.name}: JSON document is not an object")
    return payload


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _window(frames: list[Any]) -> dict[str, int] | None:
    values = [frame for frame in frames if isinstance(frame, int) and not isinstance(frame, bool)]
    if not values:
        return None
    return {"start_frame": min(values), "end_frame": max(values)}


def proof_strength(strength: Any) -> tuple[bool, str]:
    """Decide whether an observed correlation strength may carry a proof."""
    if not isinstance(strength, str) or not strength:
        return False, "correlation_strength_unavailable"
    if strength == STRENGTH_NONE:
        return False, "correlation_strength_none"
    if strength not in REVIEWED_STRENGTHS:
        return False, "correlation_strength_unreviewed"
    return True, f"correlation_strength_{strength.lower()}"


def _message_cause(event: Any) -> int | None:
    """The message-scope Cause of one observed GTPv2-C message.

    A bearer-scope Cause belongs to one item-scoped bearer context and is never
    substituted for the message outcome.
    """
    if not isinstance(event, dict):
        return None
    cause = event.get("cause")
    if not isinstance(cause, dict):
        return None
    return _int(cause.get("cause_code"))


def _header_teid(message: Any) -> int | None:
    """The control-plane TEID carried by one transaction message, when present."""
    if not isinstance(message, dict):
        return None
    if message.get("header_teid_state") != "PRESENT":
        return None
    teid = _int(message.get("header_teid"))
    return teid if teid else None


def _evidence_ref(protocol: str, frame: Any, message_type: Any) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": _int(frame),
        "message_type": message_type if isinstance(message_type, str) else None,
        "evidence_level": "OBSERVED",
    }


def generation_reference(material: dict[str, Any]) -> str:
    """Deterministic, scoped, pseudonymous generation label.

    A GTP-U TEID alone is never the identifier, and neither an EBI nor an E-RAB
    identifier is treated as globally unique: the label is scoped by capture,
    role and interface type and anchored on a real source frame.
    """
    parts = [
        str(material.get("capture_file")),
        str(material.get("role")),
        str(material.get("address")),
        str(material.get("teid")),
        str(material.get("interface_type")),
        str(material.get("first_frame")),
    ]
    return "epc-bearer-generation-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def family_reference(material: dict[str, Any]) -> str:
    parts = [
        str(material.get("capture_file")),
        str(material.get("role")),
        str(material.get("address")),
        str(material.get("teid")),
        str(material.get("interface_type")),
        ",".join(str(frame) for frame in material.get("frames") or []),
    ]
    return "epc-advertisement-family-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Advertisement records and transaction binding
# ---------------------------------------------------------------------------
def transaction_index(transactions: Any) -> dict[int, dict[str, Any]]:
    """Map an observed message frame to its accepted transaction and role."""
    index: dict[int, dict[str, Any]] = {}
    if not isinstance(transactions, dict):
        return index
    for transaction in transactions.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        for role in ("request", "response"):
            message = transaction.get(role)
            if not isinstance(message, dict):
                continue
            frame = _int(message.get("frame_number"))
            if frame is None:
                continue
            index[frame] = {"transaction": transaction, "role": role}
        # A retransmission is another observed message of the same transaction, so
        # it joins the same advertisement family; it is never a new allocation.
        for message in transaction.get("retransmissions") or []:
            if not isinstance(message, dict):
                continue
            frame = _int(message.get("frame_number"))
            if frame is None or frame in index:
                continue
            message_type = str(message.get("message_type") or "")
            role = "request" if "Request" in message_type else "response" if "Response" in message_type else "retransmission"
            index[frame] = {"transaction": transaction, "role": role, "retransmission": True}
    return index


def transaction_endpoint_values(transactions: Any, gtpv2_events: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """S1-U endpoint values each side of an accepted transaction advertises."""
    by_frame = {
        _int(event.get("frame_number")): event
        for event in gtpv2_events
        if isinstance(event, dict) and _int(event.get("frame_number")) is not None
    }
    result: dict[str, dict[str, Any]] = {}
    if not isinstance(transactions, dict):
        return result
    for transaction in transactions.get("transactions") or []:
        if not isinstance(transaction, dict):
            continue
        reference = transaction.get("transaction_reference")
        if not isinstance(reference, str):
            continue
        sides: dict[str, list[tuple[int, int, str, int]]] = {"request": [], "response": []}
        for role in ("request", "response"):
            message = transaction.get(role)
            if not isinstance(message, dict):
                continue
            event = by_frame.get(_int(message.get("frame_number")))
            if not isinstance(event, dict):
                continue
            sides[role] = [
                (record["interface_type"], record["teid"], record["address"])
                for record in _event_endpoint_records(event)
            ]
        result[reference] = {
            "request": sorted(sides["request"]),
            "response": sorted(sides["response"]),
        }
    return result


def _event_endpoint_records(event: dict[str, Any]) -> list[dict[str, Any]]:
    """S1-U F-TEID advertisements carried by one GTPv2-C message."""
    records: list[dict[str, Any]] = []
    frame = _int(event.get("frame_number"))
    capture = str(event.get("capture_file"))
    message_type = event.get("message_type")
    family = event.get("procedure_family")

    def add(item: dict[str, Any], scope: str, ebi: Any, cause: Any) -> None:
        interface_type = _int(item.get("interface_type"))
        teid = _int(item.get("teid"))
        address = item.get("ipv4")
        if interface_type not in S1U_INTERFACE_TYPES or teid is None or not isinstance(address, str):
            return
        records.append(
            {
                "capture_file": capture,
                "frame_number": frame,
                "message_type": message_type,
                "procedure_family": family,
                "interface_type": interface_type,
                "role": INTERFACE_TYPE_ROLE[interface_type],
                "teid": teid,
                "address": address,
                "scope": scope,
                "eps_bearer_identity": _int(ebi),
                "cause_code": _int(cause),
            }
        )

    message_cause = None
    cause = event.get("cause")
    if isinstance(cause, dict):
        message_cause = cause.get("cause_code")
    for item in event.get("f_teids") or []:
        if isinstance(item, dict):
            add(item, "message", None, message_cause)
    for context in event.get("bearer_contexts") or []:
        if not isinstance(context, dict):
            continue
        bearer_cause = None
        if isinstance(context.get("cause"), dict):
            bearer_cause = context["cause"].get("cause_code")
        for item in context.get("f_teids") or []:
            if isinstance(item, dict):
                add(item, "bearer", context.get("ebi"), bearer_cause)
    return records


def endpoint_records(gtpv2_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """S1-U advertisements that describe an allocation or an update.

    A release transaction names the endpoint it releases; it never advertises a
    new allocation, so it is handled by the boundary model instead of the
    advertisement families.
    """
    records: list[dict[str, Any]] = []
    for event in gtpv2_events:
        if not isinstance(event, dict):
            continue
        if event.get("procedure_family") in DELETE_FAMILIES:
            continue
        records.extend(_event_endpoint_records(event))
    return records


# ---------------------------------------------------------------------------
# Advertisement families
# ---------------------------------------------------------------------------
def _partition_key(record: dict[str, Any], index: dict[int, dict[str, Any]]) -> str:
    binding = index.get(record["frame_number"])
    if binding is None:
        return f"uncorrelated:{record['frame_number']}"
    return str(binding["transaction"].get("transaction_reference"))


def _partition_classification(
    partition: list[dict[str, Any]],
    binding: dict[str, Any] | None,
    conflict: bool,
) -> tuple[str, str, list[str]]:
    """Classify one transaction-bound partition of advertisements."""
    limitations: list[str] = []
    if conflict:
        limitations.append(
            "the request and the response of this transaction advertise different S1-U endpoint "
            "values, so no single allocation is selected"
        )
        return FAMILY_COMPETING, "request_and_response_advertise_different_endpoints", limitations

    if binding is None:
        limitations.append(
            "no accepted GTPv2-C transaction contains this advertisement, so no request/response "
            "relationship is proved"
        )
        return FAMILY_INSUFFICIENT, "advertisement_not_in_any_accepted_transaction", limitations

    transaction = binding["transaction"]
    status = transaction.get("correlation_status")
    strength = transaction.get("correlation_strength")
    if status != MATCHED:
        limitations.append(
            f"the transaction correlation status is {status}, so it cannot establish a "
            "request/response advertisement family"
        )
        return FAMILY_INSUFFICIENT, f"transaction_correlation_{str(status).lower()}", limitations
    eligible, strength_basis = proof_strength(strength)
    if not eligible:
        limitations.append(
            f"the transaction correlation strength is {strength!r}, which cannot establish a "
            "same-transaction advertisement family"
        )
        return FAMILY_INSUFFICIENT, strength_basis, limitations

    roles = {item for item in (_role_of(record) for record in partition) if item}
    if not roles:
        roles = {binding["role"]}

    ebis = {record["eps_bearer_identity"] for record in partition if record["eps_bearer_identity"] is not None}
    if len(ebis) > 1:
        limitations.append(
            "the advertisements of this transaction carry different item-scoped bearer "
            f"identities ({sorted(ebis)}), so their F-TEIDs are not consolidated"
        )
        return FAMILY_COMPETING, "bearer_identity_conflict_within_transaction", limitations

    causes = [record["cause_code"] for record in partition if record["cause_code"] is not None]
    rejected = [code for code in causes if code not in ACCEPTED_CAUSE_CODES]
    if rejected:
        limitations.append(
            "a negative or non-accepted Cause is observed, so the advertisement is not treated as "
            "successful provisioning"
        )
        return FAMILY_INSUFFICIENT, "non_accepted_cause_observed", limitations

    if len(partition) == 1:
        return FAMILY_SINGLE, "single_observed_advertisement", limitations

    if {"request", "response"} <= roles:
        return FAMILY_SAME_TRANSACTION, "matched_request_and_response_advertise_the_same_endpoint", limitations

    limitations.append(
        "the transaction advertises this endpoint on one side only, so no request/response family "
        "is established"
    )
    return FAMILY_INSUFFICIENT, "single_sided_transaction_advertisement", limitations


def _role_of(record: dict[str, Any]) -> str | None:
    return record.get("_transaction_role")


def build_advertisement_families(
    records: list[dict[str, Any]],
    index: dict[int, dict[str, Any]],
    conflicts: dict[str, dict[str, Any]],
    boundaries: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Group S1-U advertisements per endpoint and classify each group."""
    for record in records:
        binding = index.get(record["frame_number"])
        record["_transaction_role"] = binding["role"] if binding else None
        record["_transaction_reference"] = (
            binding["transaction"].get("transaction_reference") if binding else None
        )

    groups: dict[tuple[str, str, int, int], list[dict[str, Any]]] = {}
    for record in records:
        key = (
            record["capture_file"],
            record["address"],
            record["teid"],
            record["interface_type"],
        )
        groups.setdefault(key, []).append(record)

    families: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda item: (item[0], item[1], item[2], item[3])):
        members = sorted(groups[key], key=lambda item: item["frame_number"])
        capture, address, teid, interface_type = key
        partitions: dict[str, list[dict[str, Any]]] = {}
        for record in members:
            partitions.setdefault(_partition_key(record, index), []).append(record)

        classifications: list[tuple[str, str, list[str]]] = []
        for partition_key in sorted(partitions):
            partition = sorted(partitions[partition_key], key=lambda item: item["frame_number"])
            binding = index.get(partition[0]["frame_number"])
            reference = (
                binding["transaction"].get("transaction_reference") if binding is not None else None
            )
            conflict = bool(
                reference
                and reference in conflicts
                and conflicts[reference].get("request")
                and conflicts[reference].get("response")
                and conflicts[reference]["request"] != conflicts[reference]["response"]
            )
            classifications.append(_partition_classification(partition, binding, conflict))

        partition_meta = _partition_metadata(partitions, index)
        if len(partitions) == 1:
            classification, basis, limitations = classifications[0]
        else:
            classification, basis, limitations = _multi_partition_classification(
                members, partitions, index, classifications, boundaries or [], partition_meta,
                (capture, address, teid, interface_type),
            )
            if classification == FAMILY_UPDATE and _boundary_between(
                boundaries or [], capture, address, teid, interface_type, partition_meta
            ):
                classification = FAMILY_SEPARATE
                basis = "accepted_release_separates_the_advertisements"
                limitations = [
                    "an accepted release that names this endpoint lies between the advertisements, "
                    "so they describe separate generations"
                ]

        frames = sorted({record["frame_number"] for record in members})
        family = {
            "advertisement_family_reference": family_reference(
                {
                    "capture_file": capture,
                    "role": INTERFACE_TYPE_ROLE[interface_type],
                    "address": address,
                    "teid": teid,
                    "interface_type": interface_type,
                    "frames": frames,
                }
            ),
            "capture_file": capture,
            "receiving_endpoint_address": address,
            "receiving_endpoint_teid": teid,
            "receiving_endpoint_role": INTERFACE_TYPE_ROLE[interface_type],
            "reviewed_interface_type": interface_type,
            "source_frames": frames[:MAX_LIST_ITEMS],
            "source_message_types": sorted(
                {str(record["message_type"]) for record in members if record["message_type"]}
            ),
            "source_protocols": ["GTPv2-C"],
            "source_transaction_references": sorted(
                {
                    str(record["_transaction_reference"])
                    for record in members
                    if record["_transaction_reference"]
                }
            ),
            "item_scope": sorted({str(record["scope"]) for record in members}),
            "bearer_identity_scope": sorted(
                {record["eps_bearer_identity"] for record in members if record["eps_bearer_identity"] is not None}
            ),
            "allocation_outcome": _allocation_outcome(members, index),
            "correlation_status": _common_value(
                index[record["frame_number"]]["transaction"].get("correlation_status")
                for record in members
                if record["frame_number"] in index
            ),
            "correlation_strength": _common_value(
                index[record["frame_number"]]["transaction"].get("correlation_strength")
                for record in members
                if record["frame_number"] in index
            ),
            "family_classification": classification,
            "classification_basis": basis,
            "advertisement_count": len(members),
            "partitions": partition_meta,
            "control_plane_context": {
                "session_teid": (
                    partition_meta[0]["session_teid"] if len(partition_meta) == 1 else None
                ),
                "basis": (
                    "accepted_transaction_header_teid"
                    if len(partition_meta) == 1 and partition_meta[0]["session_teid"]
                    else "unavailable"
                ),
            },
            "evidence_refs": [
                _evidence_ref("GTPv2-C", record["frame_number"], record["message_type"])
                for record in members[:MAX_EVIDENCE_REFERENCES]
            ],
            "observation_window": _window([record["frame_number"] for record in members]),
            "limitations": limitations[:MAX_LIST_ITEMS],
        }
        if len(members) > MAX_EVIDENCE_REFERENCES:
            family["evidence_refs_omitted"] = len(members) - MAX_EVIDENCE_REFERENCES
        families.append(family)
    return families


def _partition_metadata(
    partitions: dict[str, list[dict[str, Any]]],
    index: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    metadata: list[dict[str, Any]] = []
    for key in sorted(partitions):
        partition = sorted(partitions[key], key=lambda item: item["frame_number"])
        binding = index.get(partition[0]["frame_number"])
        transaction = binding["transaction"] if binding else None
        metadata.append(
            {
                "transaction_reference": (
                    transaction.get("transaction_reference") if transaction else None
                ),
                "procedure_family": transaction.get("procedure_family") if transaction else None,
                "frames": [record["frame_number"] for record in partition],
                "session_teid": _partition_session_teid(transaction),
                "bearer_identity_scope": sorted(
                    {
                        record["eps_bearer_identity"]
                        for record in partition
                        if record["eps_bearer_identity"] is not None
                    }
                ),
            }
        )
    return metadata


def _partition_session_teid(transaction: Any) -> int | None:
    """The control-plane TEID one accepted transaction is bound to, when present."""
    if not isinstance(transaction, dict):
        return None
    return _header_teid(transaction.get("response")) or _header_teid(transaction.get("request"))


def _release_provenance_match(
    boundary: dict[str, Any],
    capture: str,
    address: str,
    teid: int,
    interface_type: int,
    session_teid: int | None,
    bearer_identities: list[int],
) -> tuple[bool, str]:
    """Decide whether a release record describes this generation's own context.

    Endpoint equality alone is never enough: the release must belong to the same
    capture, name the same control-plane context and be compatible with the
    generation's bearer identity. The outcome is a separate question.
    """
    if boundary.get("capture_file") != capture:
        return False, "release_in_another_capture"
    if not any(
        endpoint["address"] == address
        and endpoint["teid"] == teid
        and endpoint["interface_type"] == interface_type
        for endpoint in boundary.get("released_endpoints") or []
    ):
        return False, "release_names_another_endpoint"
    boundary_session = (boundary.get("control_plane_context") or {}).get("session_teid")
    if session_teid is None or boundary_session is None:
        return False, "control_plane_context_unavailable"
    if boundary_session != session_teid:
        return False, "release_names_another_control_plane_context"
    boundary_identities = set(boundary.get("bearer_identity_scope") or [])
    generation_identities = set(bearer_identities)
    if boundary_identities and generation_identities and not (
        boundary_identities & generation_identities
    ):
        return False, "release_names_another_bearer_identity"
    return True, "same_capture_control_plane_context_and_endpoint"


def _release_binding(
    boundary: dict[str, Any],
    capture: str,
    address: str,
    teid: int,
    interface_type: int,
    session_teid: int | None,
    bearer_identities: list[int],
) -> tuple[bool, str]:
    """A release may close a generation only when it is both bound and accepted."""
    matched, basis = _release_provenance_match(
        boundary, capture, address, teid, interface_type, session_teid, bearer_identities
    )
    if not matched:
        return False, basis
    if boundary.get("release_outcome") != RELEASE_ACCEPTED:
        return False, f"release_outcome_{str(boundary.get('release_outcome')).lower()}"
    return True, basis


def _boundary_between(
    boundaries: list[dict[str, Any]],
    capture: str,
    address: str,
    teid: int,
    interface_type: int,
    partitions: list[dict[str, Any]],
) -> bool:
    """True when a release bound to the first allocation separates the partitions.

    The release must be bound to the control-plane context of the earlier
    allocation, not merely to an equal endpoint value.
    """
    if len(partitions) < 2:
        return False
    ordered = sorted(partitions, key=lambda item: item["frames"][0] if item.get("frames") else 0)
    first = ordered[0]
    starts = [item["frames"][0] for item in ordered if item.get("frames")]
    if not starts:
        return False
    for boundary in boundaries:
        bound, _basis = _release_binding(
            boundary,
            capture,
            address,
            teid,
            interface_type,
            first.get("session_teid"),
            first.get("bearer_identity_scope") or [],
        )
        if not bound:
            continue
        if starts[0] < boundary["request_frame"] < starts[-1]:
            return True
    return False


def _multi_partition_classification(
    members: list[dict[str, Any]],
    partitions: dict[str, list[dict[str, Any]]],
    index: dict[int, dict[str, Any]],
    classifications: list[tuple[str, str, list[str]]],
    boundaries: list[dict[str, Any]],
    partition_meta: list[dict[str, Any]],
    endpoint: tuple[str, str, int, int],
) -> tuple[str, str, list[str]]:
    """Classify an endpoint advertised by more than one transaction partition."""
    if any(item[0] == FAMILY_COMPETING for item in classifications):
        return (
            FAMILY_COMPETING,
            "a competing allocation advertises this endpoint",
            ["at least one advertisement partition is competing allocation evidence"],
        )
    if any(item[0] == FAMILY_INSUFFICIENT for item in classifications):
        return (
            FAMILY_INSUFFICIENT,
            "at least one advertisement partition is not a proved request/response family",
            [
                "this endpoint is advertised by more than one transaction and at least one of them "
                "is not a proved request/response family, so the advertisements are not merged"
            ],
        )

    families_of_procedure = [
        str(index[partition[0]["frame_number"]]["transaction"].get("procedure_family"))
        for partition in partitions.values()
        if partition[0]["frame_number"] in index
    ]
    allocations = [item for item in families_of_procedure if item in ALLOCATION_FAMILIES]
    updates = [item for item in families_of_procedure if item in UPDATE_FAMILIES]
    if len(allocations) > 1:
        capture, address, teid, interface_type = endpoint
        if len(allocations) == 2 and _boundary_between(
            boundaries, capture, address, teid, interface_type, partition_meta
        ):
            return (
                FAMILY_SEPARATE,
                "accepted_release_bound_to_the_earlier_allocation_separates_the_allocations",
                [
                    "one accepted release, bound to the control-plane context of the earlier "
                    "allocation and naming this endpoint, lies between the two allocations, so "
                    "they describe separate generations"
                ],
            )
        return (
            FAMILY_INSUFFICIENT,
            "more_than_one_allocation_transaction_advertises_this_endpoint",
            [
                "more than one allocation transaction advertises this endpoint and no release bound "
                "to the earlier allocation separates them, so they are not merged and not split"
            ],
        )
    if len(allocations) == 1 and len(updates) >= 1:
        return (
            FAMILY_UPDATE,
            "one_allocation_followed_by_reviewed_endpoint_updates",
            [
                "the later advertisements update an endpoint whose allocation was already observed; "
                "they are not treated as a new bearer generation"
            ],
        )
    if len(updates) > 1:
        return (
            FAMILY_UPDATE,
            "repeated_endpoint_updates_of_one_allocation",
            [
                "repeated endpoint updates of one allocation are not treated as a new bearer "
                "generation"
            ],
        )
    return (
        FAMILY_INSUFFICIENT,
        "unreviewed_repeated_advertisement",
        ["the advertisements cannot be ordered into one allocation plus updates"],
    )


def _allocation_outcome(
    members: list[dict[str, Any]],
    index: dict[int, dict[str, Any]],
) -> str:
    """Accepted only when the correlated response itself carries an accepted Cause.

    The Cause must belong to the same message scope as the advertisement, so a
    bearer-scope Cause for one bearer identity is never used for another.
    """
    for record in members:
        binding = index.get(record["frame_number"])
        if binding is None or binding.get("role") != "response":
            continue
        if record.get("cause_code") in ACCEPTED_CAUSE_CODES:
            return RELEASE_ACCEPTED
    return RELEASE_UNRESOLVED


def _common_value(values: Any) -> Any:
    distinct = {value for value in values if value is not None}
    return next(iter(distinct)) if len(distinct) == 1 else None


# ---------------------------------------------------------------------------
# Release boundaries
# ---------------------------------------------------------------------------
def release_boundaries(
    gtpv2_events: list[dict[str, Any]],
    index: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Observed release transactions with their capture and outcome provenance.

    A release record never asserts closure by itself. It publishes which capture it
    belongs to, which request initiated it, which correlated response established
    the outcome, and which control-plane context it names. Binding a release to a
    bearer generation is a separate decision that requires every provenance fact.
    """
    by_frame = {
        _int(event.get("frame_number")): event
        for event in gtpv2_events
        if isinstance(event, dict) and _int(event.get("frame_number")) is not None
    }
    boundaries: list[dict[str, Any]] = []
    for event in gtpv2_events:
        if not isinstance(event, dict):
            continue
        if event.get("procedure_family") not in DELETE_FAMILIES:
            continue
        frame = _int(event.get("frame_number"))
        if frame is None:
            continue
        binding = index.get(frame)
        if binding is not None:
            # A release boundary is anchored on the request side of one accepted
            # transaction; the response carries its outcome.
            if binding.get("role") != "request":
                continue
        elif not str(event.get("message_type") or "").endswith("Request"):
            continue

        transaction = binding["transaction"] if binding else None
        response = transaction.get("response") if isinstance(transaction, dict) else None
        response_frame = _int(response.get("frame_number")) if isinstance(response, dict) else None
        response_event = by_frame.get(response_frame) if response_frame is not None else None
        outcome, basis, limitations = _release_outcome(transaction, event, response_event, response)

        records = _event_endpoint_records(event)
        session_teid = _header_teid(response) or _header_teid(
            transaction.get("request") if isinstance(transaction, dict) else None
        )
        boundaries.append(
            {
                "capture_file": str(event.get("capture_file")),
                "transaction_reference": (
                    transaction.get("transaction_reference") if isinstance(transaction, dict) else None
                ),
                "request_frame": frame,
                "request_message_type": event.get("message_type"),
                "response_frame": response_frame,
                "response_message_type": (
                    response.get("message_type") if isinstance(response, dict) else None
                ),
                "correlation_status": (
                    transaction.get("correlation_status") if isinstance(transaction, dict) else None
                ),
                "correlation_strength": (
                    transaction.get("correlation_strength") if isinstance(transaction, dict) else None
                ),
                "release_outcome": outcome,
                "release_outcome_basis": basis,
                "released_endpoints": [
                    {
                        "address": record["address"],
                        "teid": record["teid"],
                        "interface_type": record["interface_type"],
                        "role": record["role"],
                    }
                    for record in records[:MAX_LIST_ITEMS]
                ],
                "control_plane_context": {
                    "session_teid": session_teid,
                    "basis": (
                        "correlated_response_header_teid"
                        if _header_teid(response)
                        else "request_header_teid"
                        if session_teid
                        else "unavailable"
                    ),
                },
                "bearer_identity_scope": sorted(
                    {record["eps_bearer_identity"] for record in records if record["eps_bearer_identity"] is not None}
                ),
                "evidence_refs": [
                    _evidence_ref("GTPv2-C", frame, event.get("message_type"))
                ]
                + (
                    [_evidence_ref("GTPv2-C", response_frame, response.get("message_type"))]
                    if isinstance(response, dict) and response_frame is not None
                    else []
                ),
                "limitations": limitations,
            }
        )
    return boundaries


def _release_outcome(
    transaction: Any,
    request_event: Any,
    response_event: Any,
    response_message: Any,
) -> tuple[str, str, list[str]]:
    """Classify a release outcome from its own correlated response only.

    The request is never a source of an accepted outcome, a negative response is
    never overridden by a request-side Cause, and an uncorrelated or weakly
    correlated transaction cannot establish acceptance.
    """
    if not isinstance(transaction, dict):
        return (
            RELEASE_UNRESOLVED,
            "release_not_in_an_accepted_transaction",
            ["the release is not a member of an accepted GTPv2-C transaction"],
        )
    status = transaction.get("correlation_status")
    if status != MATCHED:
        return (
            RELEASE_UNRESOLVED,
            f"release_correlation_{str(status).lower()}",
            [
                f"the release transaction correlation status is {status}, so its outcome is not "
                "established by an unambiguous request/response pair"
            ],
        )
    eligible, basis = proof_strength(transaction.get("correlation_strength"))
    if not eligible:
        return (
            RELEASE_UNRESOLVED,
            basis,
            [
                "the release transaction correlation is not corroborated strongly enough to "
                "establish an accepted outcome"
            ],
        )
    if not isinstance(response_message, dict):
        return (
            RELEASE_UNRESOLVED,
            "release_response_unavailable",
            ["no correlated response was observed for this release request"],
        )

    code = _message_cause(response_event)
    if code is None:
        code = _int(response_message.get("cause_code"))
    if code is None:
        return (
            RELEASE_UNRESOLVED,
            "release_response_cause_unavailable",
            [
                "the correlated release response carries no message-scope Cause, so the release "
                "outcome is unproved"
            ],
        )
    if code in ACCEPTED_CAUSE_CODES:
        return RELEASE_ACCEPTED, "accepted_cause_in_correlated_response", []
    return (
        RELEASE_REJECTED,
        "non_accepted_cause_in_correlated_response",
        [
            f"the correlated release response carries Cause {code}, so the release is not accepted"
        ],
    )


# ---------------------------------------------------------------------------
# Generations
# ---------------------------------------------------------------------------
def build_generations(
    families: list[dict[str, Any]],
    boundaries: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Turn eligible advertisement families into bounded generation observations."""
    eligible = [
        family
        for family in families
        if family["family_classification"]
        in (FAMILY_SINGLE, FAMILY_SAME_TRANSACTION, FAMILY_UPDATE, FAMILY_SEPARATE)
    ]
    eligible.sort(key=lambda item: (item["observation_window"]["start_frame"], item["advertisement_family_reference"]))

    generations: list[dict[str, Any]] = []
    reuse: list[dict[str, Any]] = []
    open_by_endpoint: dict[tuple[str, str, int, int], dict[str, Any]] = {}

    for family in eligible:
        if family["family_classification"] == FAMILY_SEPARATE:
            for generation in _generations_from_partitions(family, boundaries):
                generations.append(generation)
                open_by_endpoint[
                    (
                        generation["capture_file"],
                        generation["receiving_endpoint_address"],
                        generation["receiving_endpoint_teid"],
                        generation["reviewed_interface_type"],
                    )
                ] = generation
            key = (
                family["capture_file"],
                family["receiving_endpoint_address"],
                family["receiving_endpoint_teid"],
                family["reviewed_interface_type"],
            )
            if len(generations) >= 2:
                ordered = sorted(
                    [
                        item
                        for item in generations
                        if (item["capture_file"], item["receiving_endpoint_address"], item["receiving_endpoint_teid"], item["reviewed_interface_type"]) == key
                    ],
                    key=lambda item: item["observation_window"]["start_frame"],
                )
                for previous, current in zip(ordered, ordered[1:]):
                    reuse.append(
                        _reuse_observation(previous, current, family, "release_boundary_separates_generations")
                    )
            continue
        key = (
            family["capture_file"],
            family["receiving_endpoint_address"],
            family["receiving_endpoint_teid"],
            family["reviewed_interface_type"],
        )
        first_frame = family["observation_window"]["start_frame"]
        existing = open_by_endpoint.get(key)

        if existing is not None and existing["generation_state"] == GENERATION_CLOSED:
            # An accepted release of this endpoint separates the generations.
            generation = _new_generation(family, key, closed_from=existing)
            generations.append(generation)
            open_by_endpoint[key] = generation
            reuse.append(_reuse_observation(existing, generation, family, "release_boundary_separates_generations"))
            continue
        if existing is not None:
            # Repeated advertisements of an endpoint that is still open update the
            # same generation; they never open a new one.
            existing["advertisement_family_references"].append(family["advertisement_family_reference"])
            existing["observation_window"] = _window(
                [
                    existing["observation_window"]["start_frame"],
                    family["observation_window"]["end_frame"],
                ]
            )
            existing["observations"].append(OBS_UPDATE_ADVERTISED)
            if family["family_classification"] == FAMILY_UPDATE:
                existing["observations"].append(OBS_UPDATE_ACCEPTED)
            continue

        generation = _new_generation(family, key)
        closing = _closing_boundary(boundaries, family, first_frame)
        if closing is None:
            generation["observations"].append(OBS_RELEASE_UNRESOLVED)
            rejected = _rejected_release(boundaries, family, first_frame)
            if rejected is not None:
                generation["observations"].append(OBS_RELEASE_REJECTED)
                generation["limitations"].append(
                    "a release of this endpoint was observed but its correlated response was not "
                    "accepted, so no generation boundary is established"
                )
                generation["evidence_refs"] = (
                    generation["evidence_refs"] + rejected["evidence_refs"]
                )[:MAX_EVIDENCE_REFERENCES]
        else:
            generation["generation_state"] = GENERATION_CLOSED
            generation["generation_boundary"] = _boundary_payload(closing)
            generation["observations"].extend([OBS_RELEASE_REQUEST, OBS_RELEASE_ACCEPTED])
            generation["observations"].append(OBS_BOUNDARY_ESTABLISHED)
            generation["evidence_refs"] = (
                generation["evidence_refs"] + closing["evidence_refs"]
            )[:MAX_EVIDENCE_REFERENCES]
        generations.append(generation)
        open_by_endpoint[key] = generation

    for generation in generations:
        generation["observations"] = _unique(generation["observations"])[:MAX_LIST_ITEMS]
    return generations, reuse


def _generations_from_partitions(
    family: dict[str, Any],
    boundaries: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """One generation per advertisement partition separated by a proved release."""
    generations: list[dict[str, Any]] = []
    for partition in family.get("partitions") or []:
        frames = [frame for frame in partition.get("frames") or [] if isinstance(frame, int)]
        if not frames:
            continue
        synthetic = dict(family)
        synthetic["observation_window"] = {"start_frame": min(frames), "end_frame": max(frames)}
        synthetic["evidence_refs"] = [
            ref for ref in family["evidence_refs"] if ref["frame_number"] in set(frames)
        ] or family["evidence_refs"][:1]
        key = (
            family["capture_file"],
            family["receiving_endpoint_address"],
            family["receiving_endpoint_teid"],
            family["reviewed_interface_type"],
        )
        synthetic["control_plane_context"] = {
            "session_teid": partition.get("session_teid"),
            "basis": (
                "accepted_transaction_header_teid"
                if partition.get("session_teid")
                else "unavailable"
            ),
        }
        synthetic["bearer_identity_scope"] = list(partition.get("bearer_identity_scope") or [])
        generation = _new_generation(synthetic, key)
        closing = _closing_boundary(boundaries, synthetic, min(frames))
        last_frame = max(
            item["frames"][-1] for item in family.get("partitions") or [] if item.get("frames")
        )
        if closing is not None and closing["request_frame"] < last_frame:
            generation["generation_state"] = GENERATION_CLOSED
            generation["generation_boundary"] = _boundary_payload(closing)
            generation["observations"].extend(
                [OBS_RELEASE_REQUEST, OBS_RELEASE_ACCEPTED, OBS_BOUNDARY_ESTABLISHED]
            )
            generation["evidence_refs"] = (generation["evidence_refs"] + closing["evidence_refs"])[
                :MAX_EVIDENCE_REFERENCES
            ]
        else:
            generation["observations"].append(OBS_RELEASE_UNRESOLVED)
        generation["observations"] = _unique(generation["observations"])[:MAX_LIST_ITEMS]
        generations.append(generation)
    return generations


def _new_generation(
    family: dict[str, Any],
    key: tuple[str, str, int, int],
    closed_from: dict[str, Any] | None = None,
) -> dict[str, Any]:
    capture, address, teid, interface_type = key
    first_frame = family["observation_window"]["start_frame"]
    reference = generation_reference(
        {
            "capture_file": capture,
            "role": family["receiving_endpoint_role"],
            "address": address,
            "teid": teid,
            "interface_type": interface_type,
            "first_frame": first_frame,
        }
    )
    observations = [OBS_ALLOCATION_ADVERTISED]
    if family["family_classification"] in (FAMILY_SAME_TRANSACTION, FAMILY_UPDATE):
        observations.append(OBS_ALLOCATION_RESPONSE)
    if (
        family.get("allocation_outcome") == RELEASE_ACCEPTED
        and family.get("correlation_status") == MATCHED
    ):
        observations.append(OBS_ALLOCATION_ACCEPTED)
    return {
        "generation_reference": reference,
        "capture_file": capture,
        "receiving_endpoint_address": address,
        "receiving_endpoint_teid": teid,
        "receiving_endpoint_role": family["receiving_endpoint_role"],
        "reviewed_interface_type": interface_type,
        "generation_state": GENERATION_OPEN,
        "generation_boundary": None,
        "advertisement_family_references": [family["advertisement_family_reference"]],
        "observations": observations,
        "observation_window": dict(family["observation_window"]),
        "evidence_refs": list(family["evidence_refs"]),
        "limitations": [],
    }


def _bound_boundaries(
    boundaries: list[dict[str, Any]],
    family: dict[str, Any],
    after_frame: int,
) -> list[dict[str, Any]]:
    """Release records that are bound to this family's endpoint and context."""
    context = family.get("control_plane_context") or {}
    bound: list[dict[str, Any]] = []
    for boundary in boundaries:
        if boundary["request_frame"] < after_frame:
            continue
        ok, _basis = _release_provenance_match(
            boundary,
            family["capture_file"],
            family["receiving_endpoint_address"],
            family["receiving_endpoint_teid"],
            family["reviewed_interface_type"],
            context.get("session_teid"),
            family.get("bearer_identity_scope") or [],
        )
        if ok:
            bound.append(boundary)
    return bound


def _closing_boundary(
    boundaries: list[dict[str, Any]],
    family: dict[str, Any],
    after_frame: int,
) -> dict[str, Any] | None:
    """The single accepted release that may close this generation, if any."""
    candidates = [
        boundary
        for boundary in _bound_boundaries(boundaries, family, after_frame)
        if boundary["release_outcome"] == RELEASE_ACCEPTED
    ]
    if len(candidates) != 1:
        return None
    return candidates[0]


def _rejected_release(
    boundaries: list[dict[str, Any]],
    family: dict[str, Any],
    after_frame: int,
) -> dict[str, Any] | None:
    """A release of this endpoint whose correlated response was not accepted."""
    candidates = [
        boundary
        for boundary in _bound_boundaries(boundaries, family, after_frame)
        if boundary["release_outcome"] == RELEASE_REJECTED
    ]
    return candidates[0] if len(candidates) == 1 else None


def _boundary_payload(closing: dict[str, Any]) -> dict[str, Any]:
    """A boundary that separates initiation from confirmation."""
    return {
        "release_request_frame": closing["request_frame"],
        "release_confirmation_frame": closing["response_frame"],
        "frame_number": closing["response_frame"],
        "transaction_reference": closing["transaction_reference"],
        "basis": "accepted_release_response_bound_to_the_same_control_plane_context",
        "release_effective_frame_proven": False,
    }


def _reuse_observation(
    previous: dict[str, Any],
    current: dict[str, Any],
    family: dict[str, Any],
    basis: str,
) -> dict[str, Any]:
    return {
        "endpoint_address": current["receiving_endpoint_address"],
        "endpoint_teid": current["receiving_endpoint_teid"],
        "receiving_endpoint_role": current["receiving_endpoint_role"],
        "reviewed_interface_type": current["reviewed_interface_type"],
        "capture_file": current["capture_file"],
        "previous_generation_reference": previous["generation_reference"],
        "current_generation_reference": current["generation_reference"],
        "basis": basis,
        "observations": [OBS_ENDPOINT_REUSE, OBS_BOUNDARY_ESTABLISHED],
        "advertisement_family_reference": family["advertisement_family_reference"],
        "evidence_refs": list(family["evidence_refs"])[:MAX_EVIDENCE_REFERENCES],
        "limitations": [
            "a numerically identical endpoint is reused across two proved generations; the "
            "observation does not assert anything about the subscriber behind either generation"
        ],
    }


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


# ---------------------------------------------------------------------------
# Generation-aware GTP-U attribution
# ---------------------------------------------------------------------------
DIRECTION_ROLE = {"UPLINK": ROLE_SGW, "DOWNLINK": ROLE_ENODEB}


def _stream_events(
    events: list[dict[str, Any]],
) -> dict[tuple[str, str, str, int], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, str, int], list[dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        outer = event.get("outer")
        header = event.get("header")
        frame = _int(event.get("frame_number"))
        if not isinstance(outer, dict) or not isinstance(header, dict) or frame is None:
            continue
        source = outer.get("source_address")
        destination = outer.get("destination_address")
        teid = _int(header.get("teid"))
        if not isinstance(source, str) or not isinstance(destination, str) or teid is None:
            continue
        grouped.setdefault((str(event.get("capture_file")), source, destination, teid), []).append(event)
    for key in grouped:
        grouped[key].sort(key=lambda item: item["frame_number"])
    return grouped


def attribute_streams(
    s1u_analysis: dict[str, Any] | None,
    generations: list[dict[str, Any]],
    gtpu_events: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Attribute observed G-PDUs to proved generations without splitting counts."""
    if not isinstance(s1u_analysis, dict):
        return [], [], [], []

    grouped = _stream_events(gtpu_events)
    scoped: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    deviations: list[dict[str, Any]] = []

    generations_by_endpoint: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    for generation in generations:
        key = (
            generation["capture_file"],
            generation["receiving_endpoint_address"],
            generation["receiving_endpoint_teid"],
        )
        generations_by_endpoint.setdefault(key, []).append(generation)

    for stream in s1u_analysis.get("stream_observations") or []:
        if not isinstance(stream, dict):
            continue
        reference = stream.get("stream_reference")
        capture = stream.get("capture_file")
        destination = stream.get("outer_destination")
        teid = _int(stream.get("teid"))
        direction = stream.get("direction")
        aggregate_packets = _int(stream.get("observed_g_pdu_packet_count")) or 0
        aggregate_octets = _int(stream.get("observed_payload_byte_count")) or 0
        role = DIRECTION_ROLE.get(str(direction))

        candidates = []
        if role is not None and isinstance(capture, str) and isinstance(destination, str) and teid is not None:
            candidates = [
                generation
                for generation in generations_by_endpoint.get((capture, destination, teid), [])
                if generation["receiving_endpoint_role"] == role
            ]

        if stream.get("association_status") != ASSOCIATION_SUPPORTED or not candidates:
            unresolved.append(
                _unresolved_observation(
                    stream,
                    aggregate_packets,
                    aggregate_octets,
                    "no_supported_generation_covers_this_stream"
                    if not candidates
                    else "stream_is_not_bearer_supported",
                )
            )
            continue

        if len(candidates) > 1:
            ambiguous.append(
                {
                    "stream_reference": reference,
                    "capture_file": capture,
                    "generation_references": sorted(item["generation_reference"] for item in candidates),
                    "association_status": ASSOCIATION_AMBIGUOUS,
                    "basis": "several_generations_cover_this_endpoint",
                    "observed_g_pdu_packet_count": aggregate_packets,
                    "observed_payload_byte_count": aggregate_octets,
                }
            )
            unresolved.append(
                _unresolved_observation(
                    stream,
                    aggregate_packets,
                    aggregate_octets,
                    "several_generations_cover_this_endpoint",
                )
            )
            continue

        generation = candidates[0]
        key = (str(capture), str(stream.get("outer_source")), str(destination), teid)
        stream_events = grouped.get(key, [])
        packets, octets, pending_packets, pending_octets = _frame_level_totals(
            stream_events, generation
        )
        if packets > aggregate_packets:
            deviations.append(
                {
                    "deviation_type": DEVIATION_ACCOUNTING_MISMATCH,
                    "stream_reference": reference,
                    "detail": "frame-level G-PDU events exceed the aggregate stream count",
                    "frame_count": packets,
                    "aggregate_count": aggregate_packets,
                    "evidence_level": "OBSERVED",
                }
            )
            packets = aggregate_packets
            octets = min(octets, aggregate_octets)
        attributed_octets = min(octets, aggregate_octets)

        scoped.append(
            {
                "source_stream_reference": reference,
                "generation_reference": generation["generation_reference"],
                "receiving_endpoint_role": role,
                "direction": direction,
                "first_observed_frame": stream.get("first_frame"),
                "last_observed_frame": stream.get("last_frame"),
                "observed_g_pdu_count": packets,
                "observed_payload_octets": attributed_octets,
                "association_status": ASSOCIATION_SUPPORTED,
                "allocation_evidence_refs": generation["evidence_refs"][:MAX_EVIDENCE_REFERENCES],
                "generation_boundary_refs": (
                    [
                        _evidence_ref(
                            "GTPv2-C",
                            generation["generation_boundary"]["release_request_frame"],
                            "Delete Session Request",
                        ),
                        _evidence_ref(
                            "GTPv2-C",
                            generation["generation_boundary"]["release_confirmation_frame"],
                            "Delete Session Response",
                        ),
                    ]
                    if generation.get("generation_boundary")
                    else []
                ),
                "packet_evidence_refs": [
                    _evidence_ref("GTP-U", event["frame_number"], (event.get("header") or {}).get("message_type"))
                    for event in stream_events[:MAX_EVIDENCE_REFERENCES]
                ],
                "limitations": [
                    "packet counts are observations at the capture point; attribution to a generation "
                    "does not prove UE delivery or application reachability"
                ],
            }
        )
        remaining_packets = aggregate_packets - packets
        remaining_octets = aggregate_octets - attributed_octets
        pending_packets = min(pending_packets, remaining_packets)
        pending_octets = min(pending_octets, remaining_octets)
        if pending_packets or pending_octets:
            # The release was accepted, but nothing proves the exact instant
            # forwarding stopped, so this interval belongs to neither generation.
            unresolved.append(
                _unresolved_observation(
                    stream,
                    pending_packets,
                    pending_octets,
                    "release_in_progress_interval",
                )
            )
        outside_packets = remaining_packets - pending_packets
        outside_octets = remaining_octets - pending_octets
        if outside_packets or outside_octets:
            unresolved.append(
                _unresolved_observation(
                    stream,
                    outside_packets,
                    outside_octets,
                    "frames_outside_the_proved_generation_window",
                )
            )
    return scoped, unresolved, ambiguous, deviations


def _frame_level_totals(
    stream_events: list[dict[str, Any]],
    generation: dict[str, Any],
) -> tuple[int, int, int, int]:
    """Attribute packets to a generation, keeping the release interval apart.

    The generation owns the frames up to and including the release *request*; the
    frames between the request and the accepted confirmation belong to neither
    generation, because the instant user-plane forwarding stopped is not proved.
    """
    start = generation["observation_window"]["start_frame"]
    boundary = generation.get("generation_boundary")
    end = boundary["release_request_frame"] if boundary else None
    confirmation = boundary["release_confirmation_frame"] if boundary else None
    packets = 0
    octets = 0
    pending_packets = 0
    pending_octets = 0
    for event in stream_events:
        header = event.get("header") or {}
        if header.get("message_type") != "G-PDU":
            continue
        frame = event.get("frame_number")
        if not isinstance(frame, int):
            continue
        if frame < start:
            continue
        length = _int(header.get("message_length"))
        if end is not None and frame > end:
            if confirmation is not None and frame <= confirmation:
                pending_packets += 1
                if length is not None:
                    pending_octets += length
            continue
        packets += 1
        if length is not None:
            octets += length
    return packets, octets, pending_packets, pending_octets


def _unresolved_observation(
    stream: dict[str, Any],
    packets: int,
    octets: int,
    basis: str,
) -> dict[str, Any]:
    return {
        "stream_reference": stream.get("stream_reference"),
        "capture_file": stream.get("capture_file"),
        "direction": stream.get("direction"),
        "association_status": ASSOCIATION_UNRESOLVED,
        "basis": basis,
        "observed_g_pdu_count": packets,
        "observed_payload_octets": octets,
        "observation_window": _window([stream.get("first_frame"), stream.get("last_frame")]),
        "limitations": [
            "these packets remain visible and unassigned; an unresolved generation attribution is "
            "not packet loss and not a tunnel failure"
        ],
    }


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------
def analyze(
    gtpv2_events: list[dict[str, Any]],
    transactions: dict[str, Any] | None = None,
    session_analysis: dict[str, Any] | None = None,
    default_bearer: dict[str, Any] | None = None,
    s1u_analysis: dict[str, Any] | None = None,
    gtpu_events: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build bounded EPC bearer lifecycle-generation evidence."""
    if not isinstance(gtpv2_events, list):
        raise InputError("GTPv2-C events must be a list")
    gtpu_events = gtpu_events or []
    index = transaction_index(transactions)
    records = endpoint_records(gtpv2_events)
    conflicts = transaction_endpoint_values(transactions, gtpv2_events)
    boundaries = release_boundaries(gtpv2_events, index)
    families = build_advertisement_families(records, index, conflicts, boundaries)
    generations, reuse = build_generations(families, boundaries)
    scoped, unresolved, ambiguous, deviations = attribute_streams(s1u_analysis, generations, gtpu_events)

    limitations: list[str] = []
    if not isinstance(transactions, dict) or not transactions.get("transactions"):
        limitations.append(
            "no accepted GTPv2-C transaction correlation was supplied, so no advertisement family "
            "can be proved"
        )
    if not isinstance(s1u_analysis, dict):
        limitations.append(
            "no accepted S1-U observation was supplied, so no packet attribution is possible"
        )
    elif not gtpu_events:
        limitations.append(
            "no detailed GTP-U events were supplied, so no frame-level packet attribution is possible"
        )
    if not records:
        limitations.append("the supplied GTPv2-C events advertise no reviewed S1-U F-TEID")
    if any(boundary["release_outcome"] == "UNRESOLVED" for boundary in boundaries):
        limitations.append(
            "a release transaction reached no accepted outcome or named no S1-U endpoint, so no "
            "generation is closed by it"
        )
    if not boundaries:
        limitations.append(
            "no release transaction was observed, so every generation stays open at the capture end"
        )

    additional: list[str] = []
    if not reuse:
        additional.append(
            "an accepted release that names its S1-U endpoint is required to separate two "
            "generations that reuse one endpoint value"
        )
    if unresolved:
        additional.append(
            "a proved generation window covering the unresolved frames is required to attribute them"
        )
    if not isinstance(session_analysis, dict):
        additional.append(
            "the EPC session-control analysis is required to bind a release to a control-plane context"
        )

    for generation in generations:
        if generation["generation_state"] == GENERATION_OPEN:
            generation["limitations"] = [
                "no accepted release names this endpoint, so the generation stays open at the "
                "capture end; an open generation does not prove the bearer is still active"
            ]
        generation["observations"] = generation["observations"][:MAX_LIST_ITEMS]

    visible = generations[:MAX_SUBJECTS]
    result = {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": provenance or {},
        "analysis_scope": {
            "capability": "bounded EPC bearer lifecycle-generation evidence",
            "advertisement_family_classifications": list(FAMILY_CLASSIFICATIONS),
            "lifecycle_observations": list(OBSERVATIONS),
            "generation_states": list(GENERATION_STATES),
            "association_statuses": list(ASSOCIATION_STATUSES),
            "release_outcomes": list(RELEASE_OUTCOMES),
            "reviewed_correlation_strengths": sorted(REVIEWED_STRENGTHS),
            "proof_correlation_strengths": sorted(PROOF_STRENGTHS),
            "deviation_vocabulary": list(DEVIATION_TYPES),
            "identity_rule": (
                "a generation is scoped by capture, receiving role, endpoint address, endpoint TEID "
                "and interface type, and is anchored on its first accepted advertisement frame"
            ),
        },
        "lifecycle_subject_count": len(generations),
        "lifecycle_subjects": visible,
        "lifecycle_subjects_omitted": max(0, len(generations) - len(visible)),
        "advertisement_families": families[:MAX_SUBJECTS],
        "advertisement_family_count": len(families),
        "advertisement_families_omitted": max(0, len(families) - MAX_SUBJECTS),
        "generation_observations": _generation_observations(generations),
        "generation_boundary_evidence": boundaries[:MAX_SUBJECTS],
        "generation_boundary_count": sum(
            1 for generation in generations if generation.get("generation_boundary")
        ),
        "release_observation_count": len(boundaries),
        "endpoint_reuse_observations": reuse[:MAX_SUBJECTS],
        "endpoint_reuse_observation_count": len(reuse),
        "generation_scoped_s1u_observations": scoped[:MAX_SUBJECTS],
        "generation_scoped_observation_count": len(scoped),
        "unresolved_packet_observations": unresolved[:MAX_SUBJECTS],
        "unresolved_packet_observation_count": len(unresolved),
        "ambiguous_associations": ambiguous[:MAX_SUBJECTS],
        "ambiguous_association_count": len(ambiguous),
        "unbound_evidence": [
            family
            for family in families
            if family["family_classification"] in (FAMILY_COMPETING, FAMILY_INSUFFICIENT)
        ][:MAX_SUBJECTS],
        "procedure_local_deviations": deviations[:MAX_LIST_ITEMS],
        "procedure_local_deviation_count": len(deviations),
        "evidence_limitations": limitations[:MAX_LIST_ITEMS],
        "additional_evidence_needed": additional[:MAX_LIST_ITEMS],
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": (
            "a lifecycle generation boundary is not an abnormal failure boundary; this analysis "
            "never selects a first abnormal boundary"
        ),
        "accounting": _accounting(scoped, unresolved, s1u_analysis),
    }
    return result


def _generation_observations(generations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for generation in generations:
        for observation in generation["observations"]:
            observations.append(
                {
                    "observation": observation,
                    "generation_reference": generation["generation_reference"],
                    "capture_file": generation["capture_file"],
                    "receiving_endpoint_role": generation["receiving_endpoint_role"],
                    "reviewed_interface_type": generation["reviewed_interface_type"],
                    "observation_window": generation["observation_window"],
                    "evidence_refs": generation["evidence_refs"][:MAX_EVIDENCE_REFERENCES],
                }
            )
    return observations[:MAX_SUBJECTS * 4]


def _accounting(
    scoped: list[dict[str, Any]],
    unresolved: list[dict[str, Any]],
    s1u_analysis: dict[str, Any] | None,
) -> dict[str, Any]:
    aggregate_packets = 0
    aggregate_octets = 0
    if isinstance(s1u_analysis, dict):
        for stream in s1u_analysis.get("stream_observations") or []:
            if not isinstance(stream, dict):
                continue
            aggregate_packets += _int(stream.get("observed_g_pdu_packet_count")) or 0
            aggregate_octets += _int(stream.get("observed_payload_byte_count")) or 0
    attributed_packets = sum(item["observed_g_pdu_count"] for item in scoped)
    attributed_octets = sum(item["observed_payload_octets"] for item in scoped)
    unresolved_packets = sum(item["observed_g_pdu_count"] for item in unresolved)
    unresolved_octets = sum(item["observed_payload_octets"] for item in unresolved)
    return {
        "aggregate_g_pdu_count": aggregate_packets,
        "attributed_g_pdu_count": attributed_packets,
        "unresolved_g_pdu_count": unresolved_packets,
        "aggregate_payload_octets": aggregate_octets,
        "attributed_payload_octets": attributed_octets,
        "unresolved_payload_octets": unresolved_octets,
        "conserved_g_pdu": attributed_packets + unresolved_packets == aggregate_packets,
        "conserved_payload_octets": attributed_octets + unresolved_octets == aggregate_octets,
    }
