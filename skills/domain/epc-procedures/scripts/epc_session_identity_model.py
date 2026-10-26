"""Bounded EPC S11<->S5/S8 session-identity bridge and release-binding evidence.

This Domain capability consumes only accepted, already-extracted GTPv2-C event
JSONL, the accepted GTPv2-C transaction correlation and the accepted EPC
session-control, default-bearer and bearer-lifecycle documents. It never decodes
a capture and never rebuilds Protocol-layer transactions.

It publishes strictly separated kinds of evidence:

1. Hop-local GTPv2-C session contexts. A context is scoped by capture and by the
   control-plane F-TEIDs of one hop (S11 or S5/S8). A transaction joins a
   context only through receiver-side addressing: its request header TEID and
   destination address must equal a hop-local control-plane F-TEID published
   inside that context, and the request source address must equal a hop-local
   F-TEID address of the same context (the GTP-C path peer). Equal numeric TEID
   values never join anything by themselves, and a relayed F-TEID of a foreign
   interface type is never a join key.
2. Cross-interface evidence. A relayed control-plane F-TEID (an S5/S8 PGW
   GTP-C F-TEID published by an S11 Create Session Response and equal to the
   F-TEID the S5/S8 Create Session Response assigned) can establish a
   cross-interface session identity when it is unique on both sides. An equal
   bearer-scope user-plane F-TEID establishes only an endpoint correspondence,
   never session identity.
3. Release binding. A Delete Session transaction binds to the one session
   context whose hop-local F-TEID its request addresses. The release outcome is
   published separately from the binding, and closing a control-plane context is
   never by itself a bearer-generation closure: a generation closure candidate
   additionally requires a reviewed session-to-bearer-endpoint relationship for
   the same context.

Forbidden as identity evidence everywhere in this model: equal header TEID
alone, equal EBI alone, equal sequence number, equal Cause, event proximity,
capture membership and APN or subscriber identity. Subscriber identity is never
read and never published.
"""

from __future__ import annotations

import hashlib
from typing import Any

from epc_bearer_lifecycle_model import (
    ACCEPTED_CAUSE_CODES,
    ALLOCATION_FAMILIES,
    DELETE_FAMILIES,
    ITEM_IDENTITY_ASSIGNED,
    ITEM_IDENTITY_INVALID,
    ITEM_IDENTITY_UNASSIGNED,
    ITEM_IDENTITY_UNRESOLVED,
    InputError,
    MAX_EVIDENCE_REFERENCES,
    MAX_LIST_ITEMS,
    MAX_SUBJECTS,
    MATCHED,
    PROOF_STRENGTHS,
    RELEASE_ACCEPTED,
    _event_endpoint_records,
    _message_cause,
    _int,
    assigned_eps_bearer_identities,
    binding_for_event,
    classify_eps_bearer_identity,
    eps_bearer_identity_is_readable,
    event_key,
    proof_strength,
    read_json,
    read_jsonl,
    release_boundaries,
    safe_name,
    transaction_index,
)

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.6.0"
ANALYSIS_NAME = "epc-session-identity"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_SUBJECTS = 6
EXIT_OUTPUT_FAILURE = 7

INTERFACE_S11 = "S11"
INTERFACE_S5S8 = "S5/S8"
CONTROL_PLANE_INTERFACE_TYPES = frozenset({6, 7, 10, 11})
CLASS_INTERFACE_TYPES = {
    INTERFACE_S11: frozenset({10, 11}),
    INTERFACE_S5S8: frozenset({6, 7}),
}
INTERFACE_CLASS_BY_TYPE = {
    10: INTERFACE_S11,
    11: INTERFACE_S11,
    6: INTERFACE_S5S8,
    7: INTERFACE_S5S8,
}
# User-plane S5/S8 interface types that may appear as bearer-scope F-TEIDs on
# both hops; equality of such an F-TEID is endpoint correspondence evidence only.
S5S8_USER_PLANE_INTERFACE_TYPES = frozenset({2, 4, 5})

REL_HOP_LOCAL = "HOP_LOCAL_SESSION_CONTEXT"
REL_ENDPOINT_CORRESPONDENCE = "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE"
REL_SESSION_IDENTITY = "CROSS_INTERFACE_SESSION_IDENTITY"
REL_RELEASE_BINDING = "RELEASE_TO_SESSION_CONTEXT"
REL_SESSION_GENERATION = "SESSION_CONTEXT_TO_BEARER_GENERATION"
RELATIONSHIP_TYPES = (
    REL_HOP_LOCAL,
    REL_ENDPOINT_CORRESPONDENCE,
    REL_SESSION_IDENTITY,
    REL_RELEASE_BINDING,
    REL_SESSION_GENERATION,
)

STATUS_ESTABLISHED = "ESTABLISHED"
STATUS_SUPPORTED = "SUPPORTED"
STATUS_AMBIGUOUS = "AMBIGUOUS"
STATUS_NOT_ESTABLISHED = "NOT_ESTABLISHED"
ASSOCIATION_STATUSES = (
    STATUS_ESTABLISHED,
    STATUS_SUPPORTED,
    STATUS_AMBIGUOUS,
    STATUS_NOT_ESTABLISHED,
)

BASIS_RELAYED_CONTROL_PLANE_FTEID = (
    "relayed_pgw_s5s8_control_plane_fteid_equal_and_unique_on_both_hops"
)
BASIS_NO_BRIDGE = "no_independent_cross_interface_identity_bridge_observed"
BASIS_RECEIVER_SCOPED_ADDRESSING = (
    "request_addresses_one_hop_local_control_plane_fteid_with_its_path_peer"
)
BASIS_MEMBER_ALLOCATION = "member_of_the_context_through_its_allocation_transaction"
BASIS_MEMBER_ADDRESSING = "member_of_the_context_through_receiver_scoped_addressing"
BASIS_ENDPOINT_LINK = (
    "endpoint_advertised_by_a_member_transaction_of_one_established_context"
)
BASIS_GROUPED_IDENTITY_UNASSIGNED_OR_INVALID = (
    "grouped_bearer_item_identity_unassigned_or_invalid"
)
BASIS_ENDPOINT_IDENTITY_UNASSIGNED_OR_INVALID = (
    "endpoint_bearer_identity_unassigned_or_invalid"
)

NOT_CONFIRMED = [
    "a hop-local session context is a control-plane grouping, not proof of a complete EPC session",
    "an endpoint correspondence never establishes cross-interface session identity by itself",
    "a numerically equal TEID, EBI or sequence number is never an identity bridge",
    "a release bound to a control-plane context does not by itself close a bearer generation",
    "an accepted release outcome stays unchanged whatever the session binding resolves to",
    "the exact instant user-plane forwarding stopped is never proven by a release response",
    "no subscriber identity, APN name or assigned PDN address is read or published",
    "no complete EPC session or bearer state machine is implemented",
]


def context_reference(capture: str, interface_class: str, transaction: str, first_frame: Any) -> str:
    """Deterministic, scoped, pseudonymous hop-local session-context label."""
    parts = [
        "hop-local-session-context",
        str(capture),
        str(interface_class),
        str(transaction),
        str(_int(first_frame)),
    ]
    return "epc-session-context-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def bearer_endpoint_reference(
    capture: str, role: str, address: str, teid: Any, interface_type: Any
) -> str:
    parts = [
        "bearer-endpoint",
        str(capture),
        str(role),
        str(address),
        str(_int(teid)),
        str(_int(interface_type)),
    ]
    return "epc-bearer-endpoint-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def relationship_reference(kind: str, capture: str, source: str, target: str, first_frame: Any) -> str:
    parts = [str(kind), str(capture), str(source), str(target), str(_int(first_frame))]
    return "epc-identity-link-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


def _evidence_ref(protocol: str, frame: Any, message_type: Any) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": _int(frame),
        "message_type": message_type if isinstance(message_type, str) else None,
        "evidence_level": "OBSERVED",
    }


def _window(frames: list[Any]) -> dict[str, int] | None:
    values = sorted({_int(frame) for frame in frames if isinstance(frame, (int, str))} - {None})
    if not values:
        return None
    return {"start_frame": values[0], "end_frame": values[-1]}


def _destination_address(event: Any) -> str | None:
    if not isinstance(event, dict):
        return None
    destination = event.get("destination")
    if isinstance(destination, dict) and isinstance(destination.get("address"), str):
        return destination["address"]
    return None


def _source_address(event: Any) -> str | None:
    if not isinstance(event, dict):
        return None
    source = event.get("source")
    if isinstance(source, dict) and isinstance(source.get("address"), str):
        return source["address"]
    return None


def _control_fteid_records(event: Any) -> list[dict[str, Any]]:
    """Message-scope control-plane F-TEIDs carried by one observed message.

    A record with TEID 0 is an address hint without an allocated tunnel
    identifier; it is published but never used as a join key.
    """
    records: list[dict[str, Any]] = []
    if not isinstance(event, dict):
        return records
    for item in event.get("f_teids") or []:
        if not isinstance(item, dict):
            continue
        interface_type = _int(item.get("interface_type"))
        teid = _int(item.get("teid"))
        address = item.get("ipv4")
        if interface_type not in CONTROL_PLANE_INTERFACE_TYPES or teid is None:
            continue
        if not isinstance(address, str):
            continue
        interface_class = INTERFACE_CLASS_BY_TYPE[interface_type]
        records.append(
            {
                "interface_type": interface_type,
                "interface_type_name": item.get("interface_type_name"),
                "teid": teid,
                "address": address,
                "scope": "message",
                "hop_local": True,
                "join_capable": teid != 0,
                "interface_class": interface_class,
            }
        )
    return records


def _event_frame(event: Any) -> int | None:
    return _int(event.get("frame_number")) if isinstance(event, dict) else None


def _event_header_teid(event: Any) -> int | None:
    """The header TEID of one observed GTPv2-C event (not a transaction reference)."""
    if not isinstance(event, dict):
        return None
    header = event.get("header")
    if not isinstance(header, dict):
        return None
    return _int(header.get("teid"))


def _transaction_members(index: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Accepted transactions with their capture-scoped request/response events.

    The transaction object itself lives on the event binding of the accepted
    correlation index, not under the transaction reference entry.
    """
    by_key = {
        event_key(event): event
        for event in events
        if isinstance(event, dict) and event_key(event) is not None
    }
    members: list[dict[str, Any]] = []
    for reference in sorted(index.get("transactions") or {}):
        bound = index["transactions"][reference]
        request_event = by_key.get(bound.get("request_key"))
        response_event = by_key.get(bound.get("response_key")) if bound.get("response_key") else None
        transaction: dict[str, Any] = {}
        if request_event is not None:
            binding = index.get("events", {}).get(event_key(request_event)) or {}
            candidate = binding.get("transaction")
            if isinstance(candidate, dict):
                transaction = candidate
        members.append(
            {
                "transaction_reference": reference,
                "transaction": transaction,
                "capture_file": bound.get("capture_file"),
                "request_event": request_event,
                "response_event": response_event,
            }
        )
    return members


def _transaction_class(member: dict[str, Any]) -> str | None:
    """The hop class of one allocation transaction.

    Every candidate record must be corroborated by the message path: an F-TEID
    is the sender's or receiver's own hop identity only when its address is one
    of the two endpoints of the message that published it. A relayed F-TEID of
    a foreign interface type (an S5/S8 PGW address inside an S11 response)
    fails this test and can never classify the hop, while a response may still
    supply missing hop evidence when its own direction corroborates it.
    """
    request_event = member.get("request_event")
    request_addresses = {_source_address(request_event), _destination_address(request_event)}
    request_classes = {
        record["interface_class"]
        for record in _control_fteid_records(request_event)
        if record["join_capable"] and record["address"] in request_addresses
    }
    if len(request_classes) == 1:
        return next(iter(request_classes))
    response_event = member.get("response_event")
    response_addresses = {_source_address(response_event), _destination_address(response_event)}
    response_classes = {
        record["interface_class"]
        for record in _control_fteid_records(response_event)
        if record["join_capable"] and record["address"] in response_addresses
    }
    if not request_classes and len(response_classes) == 1:
        return next(iter(response_classes))
    return None


def _allocation_outcome_status(member: dict[str, Any]) -> tuple[str, int | None]:
    """The allocation outcome of one accepted transaction.

    Only the correlated response's message-scope Cause classifies it: a
    request-side Cause never overrides the response, and a response without a
    readable Cause is unresolved, never silently accepted.
    """
    code = _message_cause(member.get("response_event"))
    if code is None:
        return ("UNRESOLVED", None)
    if code in ACCEPTED_CAUSE_CODES:
        return ("ACCEPTED", code)
    return ("REJECTED_OBSERVED", code)


def _context_join_candidates(
    contexts: list[dict[str, Any]],
    capture: str,
    request_event: Any,
) -> list[dict[str, Any]]:
    """Contexts whose hop-local F-TEIDs the request addresses with its path peer.

    Receiver-side identification: the request header TEID and destination
    address must equal a hop-local control-plane F-TEID of the context. Peer
    identification: the request source address must equal a hop-local F-TEID
    address of the same context, because a GTP-C tunnel is scoped by TEID,
    address and its path peer. Relayed F-TEIDs of a foreign interface type are
    never join keys.
    """
    teid = _event_header_teid(request_event)
    destination = _destination_address(request_event)
    source = _source_address(request_event)
    if teid is None or teid == 0 or destination is None or source is None:
        return []
    matched: list[dict[str, Any]] = []
    for context in contexts:
        if context["capture_file"] != capture:
            continue
        hop_local_types = CLASS_INTERFACE_TYPES[context["interface_class"]]
        hop_local = [
            record
            for record in context["control_plane_fteids"]
            if record["join_capable"] and record["interface_type"] in hop_local_types
        ]
        receiver_match = any(
            record["teid"] == teid and record["address"] == destination for record in hop_local
        )
        if not receiver_match:
            continue
        peer_match = any(record["address"] == source for record in hop_local)
        if peer_match:
            matched.append(context)
    return matched


def build_hop_local_contexts(
    events: list[dict[str, Any]],
    index: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Hop-local session contexts, unbound transactions and ambiguous joins.

    Allocation transactions seed one context per capture and hop class. Every
    other transaction joins through receiver-scoped addressing; a join with
    several equal candidates is published as ambiguous and joins nothing.
    """
    members = _transaction_members(index, events)
    contexts: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []

    for member in members:
        if member["transaction"].get("procedure_family") not in ALLOCATION_FAMILIES:
            continue
        capture = str(member.get("capture_file"))
        interface_class = _transaction_class(member)
        request_event = member.get("request_event")
        response_event = member.get("response_event")
        frames = [_event_frame(request_event), _event_frame(response_event)]
        if interface_class is None:
            unbound.append(
                {
                    "kind": "transaction_insufficient_hop_evidence",
                    "capture_file": capture,
                    "transaction_reference": member["transaction_reference"],
                    "limitations": [
                        "hop classification: INSUFFICIENT_HOP_EVIDENCE; no path-corroborated "
                        "single-hop control-plane F-TEID set, so no hop-local context can be "
                        "seeded from it"
                    ],
                }
            )
            continue
        published: list[dict[str, Any]] = []
        for event, role in ((request_event, "request"), (response_event, "response")):
            for record in _control_fteid_records(event):
                published.append(
                    dict(
                        record,
                        published_by_transaction=member["transaction_reference"],
                        published_by_frame=_event_frame(event),
                        published_by_role=role,
                    )
                )
        joinable_hop_local = [
            record
            for record in published
            if record["interface_class"] == interface_class and record["join_capable"]
        ]
        correlation_proved = (
            member["transaction"].get("correlation_status") == MATCHED
            and proof_strength(member["transaction"].get("correlation_strength"))[0]
        )
        outcome_status, _outcome_code = _allocation_outcome_status(member)
        status = STATUS_NOT_ESTABLISHED
        basis = "context_evidence_insufficient"
        limitations: list[str] = []
        transaction_status = member["transaction"].get("correlation_status")
        eligible, strength_basis = proof_strength(member["transaction"].get("correlation_strength"))
        if transaction_status != MATCHED or not eligible:
            basis = (
                f"allocation_transaction_correlation_{str(transaction_status).lower()}"
                if transaction_status != MATCHED
                else strength_basis
            )
            limitations.append(
                "the allocation transaction is not a proved MATCHED request/response pair, so the "
                "context is not established"
            )
        elif not joinable_hop_local:
            basis = "no_joinable_hop_local_control_plane_fteid_published"
            limitations.append(
                "the allocation published no joinable hop-local control-plane F-TEID, so later "
                "transactions cannot address this context"
            )
        elif outcome_status != "ACCEPTED":
            basis = f"allocation_outcome_{str(outcome_status).lower()}"
            limitations.append(
                "the allocation transaction is correlated and its control-plane evidence is "
                "observed, but its correlated response does not carry an accepted message-level "
                "Cause, so the accepted allocation is not established and the context is a "
                "diagnostic candidate only"
            )
        else:
            status = STATUS_ESTABLISHED
            basis = "proved_allocation_transaction_with_unique_hop_local_control_plane_fteids"
        window = _window([frame for frame in frames if frame is not None])
        contexts.append(
            {
                "capture_file": capture,
                "session_context_reference": context_reference(
                    capture,
                    interface_class,
                    member["transaction_reference"],
                    window["start_frame"] if window else None,
                ),
                "interface_class": interface_class,
                "relationship_type": REL_HOP_LOCAL,
                "association_status": status,
                "association_basis": basis,
                "transaction_correlation_proved": correlation_proved,
                "allocation_outcome_status": outcome_status,
                "allocation_transaction_reference": member["transaction_reference"],
                "member_transactions": [
                    {
                        "transaction_reference": member["transaction_reference"],
                        "join_basis": BASIS_MEMBER_ALLOCATION,
                        "request_header_teid": _event_header_teid(request_event),
                        "frames": [frame for frame in frames if frame is not None],
                    }
                ],
                "control_plane_fteids": published,
                "bearer_user_plane_fteids": [],
                "observation_window": window,
                "evidence_refs": [
                    _evidence_ref(
                        "GTPv2-C",
                        frame,
                        event.get("message_type") if isinstance(event, dict) else None,
                    )
                    for event, frame in ((request_event, frames[0]), (response_event, frames[1]))
                    if isinstance(event, dict) and frame is not None
                ][:MAX_EVIDENCE_REFERENCES],
                "limitations": limitations,
            }
        )

    contexts.sort(
        key=lambda item: (
            item["capture_file"],
            (item["observation_window"] or {}).get("start_frame", 1 << 30),
            item["session_context_reference"],
        )
    )

    for member in members:
        if member["transaction"].get("procedure_family") in ALLOCATION_FAMILIES:
            continue
        capture = str(member.get("capture_file"))
        request_event = member.get("request_event")
        response_event = member.get("response_event")
        candidates = _context_join_candidates(contexts, capture, request_event)
        frames = [
            frame
            for frame in (_event_frame(request_event), _event_frame(response_event))
            if frame is not None
        ]
        request_teid = _event_header_teid(request_event)
        if request_teid is None or request_teid == 0:
            unbound.append(
                {
                    "kind": "transaction_without_receiver_scoped_addressing",
                    "capture_file": capture,
                    "transaction_reference": member["transaction_reference"],
                    "limitations": [
                        "the request carries no receiver-side TEID addressing, so no hop-local "
                        "context can be evaluated for it"
                    ],
                }
            )
            continue
        if len(candidates) > 1:
            ambiguous.append(
                {
                    "capture_file": capture,
                    "relationship_type": REL_HOP_LOCAL,
                    "source_subject_reference": member["transaction_reference"],
                    "association_status": STATUS_AMBIGUOUS,
                    "association_basis": "receiver_scoped_addressing_matches_several_contexts",
                    "competing_candidates": sorted(
                        candidate["session_context_reference"] for candidate in candidates
                    ),
                    "limitations": [
                        "the request addresses control-plane F-TEIDs of several hop-local "
                        "contexts, so it joins none of them"
                    ],
                }
            )
            continue
        if not candidates:
            unbound.append(
                {
                    "kind": "transaction_unmatched_by_receiver_scoped_addressing",
                    "capture_file": capture,
                    "transaction_reference": member["transaction_reference"],
                    "limitations": [
                        "no hop-local context publishes a hop-local control-plane F-TEID that "
                        "this request addresses together with its path peer"
                    ],
                }
            )
            continue
        context = candidates[0]
        context["member_transactions"].append(
            {
                "transaction_reference": member["transaction_reference"],
                "join_basis": BASIS_MEMBER_ADDRESSING,
                "request_header_teid": _event_header_teid(request_event),
                "frames": frames,
            }
        )
        for event, role in ((request_event, "request"), (response_event, "response")):
            for record in _control_fteid_records(event):
                context["control_plane_fteids"].append(
                    dict(
                        record,
                        published_by_transaction=member["transaction_reference"],
                        published_by_frame=_event_frame(event),
                        published_by_role=role,
                    )
                )

    for context in contexts:
        context["member_transactions"].sort(
            key=lambda item: (
                item["frames"][0] if item["frames"] else 1 << 30,
                str(item["transaction_reference"]),
            )
        )
        context["member_transaction_references"] = [
            item["transaction_reference"] for item in context["member_transactions"]
        ]
        context["observation_window"] = _window(
            [frame for item in context["member_transactions"] for frame in item["frames"]]
        )
    return contexts, unbound, ambiguous


def collect_bearer_fteids(
    events: list[dict[str, Any]],
    index: dict[str, Any],
    contexts: list[dict[str, Any]],
) -> tuple[dict[tuple[str, str, str, int, int], dict[str, Any]], list[dict[str, Any]]]:
    """Derive reviewed S1-U bearer endpoints and per-context user-plane F-TEIDs.

    The S1-U endpoints (interface types 0 and 1) advertised by non-release
    transactions are the generation-side subjects of the session-to-generation
    links. Bearer-scope S5/S8 user-plane F-TEIDs are collected per context for
    the endpoint-correspondence evaluation. Release transactions never
    advertise, so they contribute nothing here. Mutates the context records.
    """
    context_by_member: dict[tuple[str, str], dict[str, Any]] = {}
    for context in contexts:
        for member in context["member_transactions"]:
            context_by_member[(context["capture_file"], member["transaction_reference"])] = context

    by_key = {
        event_key(event): event
        for event in events
        if isinstance(event, dict) and event_key(event) is not None
    }

    user_plane: dict[str, list[dict[str, Any]]] = {}
    endpoints: dict[tuple[str, str, str, int, int], dict[str, Any]] = {}
    unbound: list[dict[str, Any]] = []
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("procedure_family") in DELETE_FAMILIES:
            continue
        binding = binding_for_event(index, event)
        transaction_reference = (
            binding["transaction"].get("transaction_reference")
            if binding is not None and isinstance(binding.get("transaction"), dict)
            else None
        )
        # The outcome fallback for every item of one transaction is the
        # correlated response's message-scope Cause: a request-side
        # advertisement has no outcome of its own.
        transaction_message_cause = None
        if transaction_reference is not None:
            bound = (index.get("transactions") or {}).get(str(transaction_reference)) or {}
            response_event = by_key.get(bound.get("response_key"))
            transaction_message_cause = _message_cause(response_event)
        context = (
            context_by_member.get((str(event.get("capture_file")), str(transaction_reference)))
            if transaction_reference is not None
            else None
        )
        for record in _event_endpoint_records(event):
            capture = str(record["capture_file"])
            key = (
                capture,
                str(record["role"]),
                str(record["address"]),
                int(record["teid"]),
                int(record["interface_type"]),
            )
            endpoint = endpoints.setdefault(
                key,
                {
                    "capture_file": capture,
                    "role": str(record["role"]),
                    "address": str(record["address"]),
                    "teid": int(record["teid"]),
                    "interface_type": int(record["interface_type"]),
                    "advertising_transactions": set(),
                    "ebis": set(),
                    "frames": set(),
                    "scopes": set(),
                    "items": [],
                },
            )
            if record["eps_bearer_identity"] is not None:
                endpoint["ebis"].add(int(record["eps_bearer_identity"]))
            endpoint["frames"].add(int(record["frame_number"]))
            endpoint["scopes"].add(str(record["scope"]))
            # One item record per grouped advertisement. The Cause scope is the
            # record's own F-TEID scope: a bearer-scope record carries its
            # grouped item's bearer Cause, a message-scope record carries the
            # message Cause. Flat unbound IE values are never consulted here.
            endpoint["items"].append(
                {
                    "transaction_reference": (
                        str(transaction_reference) if transaction_reference is not None else None
                    ),
                    "frame_number": int(record["frame_number"]),
                    "scope": str(record["scope"]),
                    "eps_bearer_identity": (
                        int(record["eps_bearer_identity"])
                        if record["eps_bearer_identity"] is not None
                        else None
                    ),
                    "cause_code": (
                        int(record["cause_code"]) if record["cause_code"] is not None else None
                    ),
                    "message_cause_code": transaction_message_cause,
                }
            )
            if transaction_reference is None:
                unbound.append(
                    {
                        "kind": "endpoint_advertisement_without_accepted_transaction",
                        "capture_file": capture,
                        "frame_number": record["frame_number"],
                        "limitations": [
                            "the endpoint advertisement is not a member of an accepted GTPv2-C "
                            "transaction, so it cannot be linked to a session context"
                        ],
                    }
                )
                continue
            endpoint["advertising_transactions"].add(str(transaction_reference))
            if context is not None and record["interface_type"] in S5S8_USER_PLANE_INTERFACE_TYPES:
                user_plane.setdefault(context["session_context_reference"], []).append(
                    {
                        "interface_type": int(record["interface_type"]),
                        "teid": int(record["teid"]),
                        "address": str(record["address"]),
                        "eps_bearer_identity": (
                            int(record["eps_bearer_identity"])
                            if record["eps_bearer_identity"] is not None
                            else None
                        ),
                        "frames": [int(record["frame_number"])],
                        "advertising_transactions": [str(transaction_reference)],
                    }
                )
        if context is None or transaction_reference is None:
            continue
        # Bearer-scope S5/S8 user-plane F-TEIDs are not S1-U records, so they are
        # collected directly from the bearer contexts of the accepted event
        # contract for the endpoint-correspondence evaluation.
        for bearer in event.get("bearer_contexts") or []:
            if not isinstance(bearer, dict):
                continue
            ebi = _int(bearer.get("ebi"))
            for item in bearer.get("f_teids") or []:
                if not isinstance(item, dict):
                    continue
                interface_type = _int(item.get("interface_type"))
                teid = _int(item.get("teid"))
                address = item.get("ipv4")
                if interface_type not in S5S8_USER_PLANE_INTERFACE_TYPES or teid is None:
                    continue
                if not isinstance(address, str):
                    continue
                user_plane.setdefault(context["session_context_reference"], []).append(
                    {
                        "interface_type": interface_type,
                        "teid": teid,
                        "address": address,
                        "eps_bearer_identity": ebi,
                        "frames": [_event_frame(event)],
                        "advertising_transactions": [str(transaction_reference)],
                    }
                )
    for context in contexts:
        merged: dict[tuple[int, int, str], dict[str, Any]] = {}
        for endpoint in user_plane.get(context["session_context_reference"]) or []:
            key = (endpoint["interface_type"], endpoint["teid"], endpoint["address"])
            existing = merged.get(key)
            if existing is None:
                merged[key] = dict(endpoint)
                continue
            existing["frames"] = sorted(set(existing["frames"]) | set(endpoint["frames"]))
            existing["advertising_transactions"] = sorted(
                set(existing["advertising_transactions"])
                | set(endpoint["advertising_transactions"])
            )
        context["bearer_user_plane_fteids"] = [
            merged[key] for key in sorted(merged, key=lambda item: (item[1], item[2]))
        ]
    return endpoints, unbound


def _item_outcome(item: dict[str, Any]) -> str:
    """Outcome of one grouped bearer item advertisement.

    A bearer-scope Cause on the grouped item decides its own outcome; only an
    item without any bearer Cause falls back to the correlated response's
    message-scope Cause, and a flat unbound IE value is never consulted.
    """
    cause = item.get("cause_code")
    if cause is not None:
        return "ACCEPTED" if cause in ACCEPTED_CAUSE_CODES else "REJECTED_OBSERVED"
    message_cause = item.get("message_cause_code")
    if message_cause is None:
        return "UNRESOLVED"
    return "ACCEPTED" if message_cause in ACCEPTED_CAUSE_CODES else "REJECTED_OBSERVED"


def _response_published_fteids(context: dict[str, Any], interface_type: int) -> list[dict[str, Any]]:
    return [
        record
        for record in context["control_plane_fteids"]
        if record["join_capable"]
        and record["interface_type"] == interface_type
        and record["published_by_role"] == "response"
    ]


def evaluate_cross_interface(
    contexts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Candidates, endpoint correspondence links and session identity links.

    A relayed control-plane F-TEID can prove session identity when it is unique
    on both sides and both contexts are established. An equal bearer-scope
    user-plane F-TEID proves only an endpoint correspondence. Every record
    carries its own status; nothing is silently promoted between the kinds.
    """
    s11_contexts = [item for item in contexts if item["interface_class"] == INTERFACE_S11]
    s5_contexts = [item for item in contexts if item["interface_class"] == INTERFACE_S5S8]
    candidates: list[dict[str, Any]] = []
    identities: list[dict[str, Any]] = []

    # Bridge evaluation is capture-scoped: a relayed F-TEID value that appears
    # in two captures is two independent pieces of evidence, never one ambiguous
    # candidate set.
    captures = sorted({str(item["capture_file"]) for item in contexts})
    for capture in captures:
        capture_s11 = [item for item in s11_contexts if item["capture_file"] == capture]
        capture_s5 = [item for item in s5_contexts if item["capture_file"] == capture]
        relay_by_triple: dict[tuple[int, int, str], list[dict[str, Any]]] = {}
        for context in capture_s11:
            for record in _response_published_fteids(context, 7):
                relay_by_triple.setdefault(
                    (record["interface_type"], record["teid"], record["address"]), []
                ).append(context)
        assigned_by_triple: dict[tuple[int, int, str], list[dict[str, Any]]] = {}
        for context in capture_s5:
            for record in _response_published_fteids(context, 7):
                assigned_by_triple.setdefault(
                    (record["interface_type"], record["teid"], record["address"]), []
                ).append(context)
        _evaluate_capture_bridges(
            capture, relay_by_triple, assigned_by_triple, candidates, identities
        )

    correspondences = _endpoint_correspondence(contexts)
    return candidates, correspondences, identities


def _evaluate_capture_bridges(
    capture: str,
    relay_by_triple: dict[tuple[int, int, str], list[dict[str, Any]]],
    assigned_by_triple: dict[tuple[int, int, str], list[dict[str, Any]]],
    candidates: list[dict[str, Any]],
    identities: list[dict[str, Any]],
) -> None:
    """Evaluate one capture's relayed control-plane F-TEID bridge candidates."""
    for triple in sorted(
        set(relay_by_triple) & set(assigned_by_triple), key=lambda item: (item[1], item[2], item[0])
    ):
        relays = relay_by_triple[triple]
        assignments = assigned_by_triple[triple]
        pair_unique = len(relays) == 1 and len(assignments) == 1
        for relay_context in relays:
            for assigned_context in assignments:
                established = (
                    pair_unique
                    and relay_context["association_status"] == STATUS_ESTABLISHED
                    and assigned_context["association_status"] == STATUS_ESTABLISHED
                    and relay_context["capture_file"] == assigned_context["capture_file"]
                )
                frames = sorted(
                    {
                        record["published_by_frame"]
                        for context in (relay_context, assigned_context)
                        for record in _response_published_fteids(context, 7)
                        if (record["interface_type"], record["teid"], record["address"]) == triple
                        and record["published_by_frame"] is not None
                    }
                )
                transactions = sorted(
                    {
                        relay_context["allocation_transaction_reference"],
                        assigned_context["allocation_transaction_reference"],
                    }
                )
                reference = relationship_reference(
                    REL_SESSION_IDENTITY,
                    relay_context["capture_file"],
                    relay_context["session_context_reference"],
                    assigned_context["session_context_reference"],
                    frames[0] if frames else None,
                )
                if established:
                    limitations: list[str] = []
                    basis = BASIS_RELAYED_CONTROL_PLANE_FTEID
                    status = STATUS_ESTABLISHED
                else:
                    status = (
                        STATUS_AMBIGUOUS if not pair_unique else STATUS_NOT_ESTABLISHED
                    )
                    basis = (
                        "the_fteid_is_claimed_by_several_contexts_on_one_hop"
                        if not pair_unique
                        else BASIS_NO_BRIDGE
                    )
                    limitations = (
                        []
                        if not pair_unique
                        else [
                            "the relayed control-plane F-TEID equality does not satisfy the "
                            "published cross-interface session identity gates"
                        ]
                    )
                record = {
                    "reference": reference,
                    "capture_file": relay_context["capture_file"],
                    "relationship_type": REL_SESSION_IDENTITY,
                    "source_subject_reference": relay_context["session_context_reference"],
                    "target_subject_reference": assigned_context["session_context_reference"],
                    "association_status": status,
                    "association_basis": basis,
                    "reviewed_identifiers": [
                        {
                            "kind": "relayed_control_plane_fteid",
                            "interface_type": triple[0],
                            "teid": triple[1],
                            "address": triple[2],
                            "scope": "message",
                        }
                    ],
                    "source_transaction_references": transactions,
                    "source_frames": frames,
                    "evidence_refs": [
                        _evidence_ref("GTPv2-C", frame, "Create Session Response")
                        for frame in frames
                    ][:MAX_EVIDENCE_REFERENCES],
                    "observation_window": {
                        "start_frame": frames[0] if frames else None,
                        "end_frame": frames[-1] if frames else None,
                    },
                    "competing_candidates": (
                        []
                        if pair_unique
                        else sorted(
                            item["session_context_reference"] for item in relays + assignments
                        )
                    ),
                    "limitations": limitations,
                }
                identities.append(record)
                candidates.append(dict(record, evaluated_as="session_identity"))


def _endpoint_correspondence(contexts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Equal bearer-scope user-plane F-TEIDs across an S11 and an S5/S8 context."""
    s11_contexts = [item for item in contexts if item["interface_class"] == INTERFACE_S11]
    s5_contexts = [item for item in contexts if item["interface_class"] == INTERFACE_S5S8]
    per_triple: dict[tuple[int, int, str], dict[str, list[dict[str, Any]]]] = {}
    for context in s11_contexts + s5_contexts:
        for endpoint in context.get("bearer_user_plane_fteids") or []:
            triple = (endpoint["interface_type"], endpoint["teid"], endpoint["address"])
            side = per_triple.setdefault(triple, {INTERFACE_S11: [], INTERFACE_S5S8: []})
            side[context["interface_class"]].append({"context": context, "endpoint": endpoint})
    records: list[dict[str, Any]] = []
    for triple in sorted(per_triple, key=lambda item: (item[1], item[2], item[0])):
        sides = per_triple[triple]
        s11_hits = sides[INTERFACE_S11]
        s5_hits = sides[INTERFACE_S5S8]
        unique = len(s11_hits) == 1 and len(s5_hits) == 1
        for s11_hit in s11_hits:
            for s5_hit in s5_hits:
                s11_context = s11_hit["context"]
                s5_context = s5_hit["context"]
                s11_endpoint = s11_hit["endpoint"]
                s5_endpoint = s5_hit["endpoint"]
                ebis = {
                    s11_endpoint.get("eps_bearer_identity"),
                    s5_endpoint.get("eps_bearer_identity"),
                }
                ebis.discard(None)
                identity_compatible = len(ebis) <= 1
                frames = sorted(
                    {
                        frame
                        for endpoint in (s11_endpoint, s5_endpoint)
                        for frame in endpoint.get("frames") or []
                    }
                )
                transactions = sorted(
                    set(s11_endpoint["advertising_transactions"])
                    | set(s5_endpoint["advertising_transactions"])
                )
                gates_passed = (
                    unique
                    and identity_compatible
                    and s11_context["association_status"] == STATUS_ESTABLISHED
                    and s5_context["association_status"] == STATUS_ESTABLISHED
                )
                limitations: list[str] = []
                if not unique:
                    limitations.append(
                        "the user-plane F-TEID is claimed by several contexts on one hop, so the "
                        "correspondence is ambiguous"
                    )
                if not identity_compatible:
                    limitations.append(
                        "the item-scoped bearer identities of the two advertisements disagree"
                    )
                if gates_passed:
                    status = STATUS_SUPPORTED
                    basis = (
                        "equal_bearer_scope_user_plane_fteid_with_compatible_item_scoped_ebi"
                    )
                elif not unique or not identity_compatible:
                    status = STATUS_AMBIGUOUS
                    basis = "endpoint_equality_does_not_satisfy_the_correspondence_gates"
                else:
                    status = STATUS_NOT_ESTABLISHED
                    basis = "endpoint_equality_does_not_satisfy_the_correspondence_gates"
                records.append(
                    {
                        "reference": relationship_reference(
                            REL_ENDPOINT_CORRESPONDENCE,
                            s11_context["capture_file"],
                            s11_context["session_context_reference"],
                            s5_context["session_context_reference"],
                            frames[0] if frames else None,
                        ),
                        "capture_file": s11_context["capture_file"],
                        "relationship_type": REL_ENDPOINT_CORRESPONDENCE,
                        "source_subject_reference": s11_context["session_context_reference"],
                        "target_subject_reference": s5_context["session_context_reference"],
                        "association_status": status,
                        "association_basis": basis,
                        "reviewed_identifiers": [
                            {
                                "kind": "user_plane_fteid",
                                "interface_type": triple[0],
                                "teid": triple[1],
                                "address": triple[2],
                                "scope": "bearer",
                                "eps_bearer_identity": next(iter(ebis)) if len(ebis) == 1 else None,
                            }
                        ],
                        "source_transaction_references": transactions,
                        "source_frames": frames,
                        "evidence_refs": [
                            _evidence_ref("GTPv2-C", frame, None) for frame in frames
                        ][:MAX_EVIDENCE_REFERENCES],
                        "observation_window": {
                            "start_frame": frames[0] if frames else None,
                            "end_frame": frames[-1] if frames else None,
                        },
                        "competing_candidates": (
                            []
                            if unique
                            else sorted(
                                item["context"]["session_context_reference"]
                                for item in s11_hits + s5_hits
                            )
                        ),
                        "limitations": limitations
                        + [
                            "an endpoint correspondence is never published as cross-interface "
                            "session identity"
                        ],
                    }
                )
    records.sort(
        key=lambda item: (
            item["capture_file"],
            item["observation_window"]["start_frame"] or 0,
            item["source_subject_reference"],
            item["target_subject_reference"],
        )
    )
    return records


def build_session_generation_links(
    contexts: list[dict[str, Any]],
    endpoints: dict[tuple[str, str, str, int, int], dict[str, Any]],
    identities: list[dict[str, Any]],
    lifecycle_analysis: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Reviewed session-context to bearer-endpoint relationships.

    A link is established only when the advertising transaction is a member of
    exactly one established context and the context owns exactly one endpoint of
    that receiving role. When a proved cross-interface session identity connects
    an S5/S8 context to an S11 context, an S5/S8-advertised endpoint may also be
    linked to the S11 context through that reviewed bridge; the bridge reference
    is published as part of the record and no circular proof is used.
    """
    links: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    context_by_reference = {
        context["session_context_reference"]: context for context in contexts
    }

    direct: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for key in sorted(endpoints, key=lambda item: (item[0], item[1], item[2], item[3], item[4])):
        capture, role, address, teid, interface_type = key
        endpoint = endpoints[key]
        advertising = sorted(endpoint["advertising_transactions"])
        if not advertising:
            continue
        member_contexts = {
            context["session_context_reference"]
            for context in contexts
            if context["capture_file"] == capture
            and set(advertising) & set(context["member_transaction_references"])
        }
        if len(member_contexts) != 1:
            unbound.append(
                {
                    "kind": "endpoint_advertisement_without_one_session_context",
                    "capture_file": capture,
                    "role": role,
                    "address": address,
                    "teid": teid,
                    "interface_type": interface_type,
                    "limitations": [
                        "the advertising transactions belong to no single hop-local session "
                        "context, so no session-to-generation relationship is published"
                    ],
                }
            )
            continue
        context = context_by_reference[next(iter(member_contexts))]
        same_role = [
            other_key
            for other_key, other in endpoints.items()
            if other_key[0] == capture
            and other_key[1] == role
            and set(other["advertising_transactions"])
            & set(context["member_transaction_references"])
        ]
        # Bearer-item evidence of this endpoint inside the owning context: the
        # item records come from the grouped bearer-context hierarchy only, so
        # a bearer-scope Cause blocks exactly its own item and flat unbound IE
        # values can never be assigned to any item by position. Only grouped
        # (bearer-scope) items can carry an item-scoped bearer identity; a
        # message-scope advertisement stays observable diagnostic evidence and
        # neither establishes nor blocks the association by itself.
        context_items = [
            item
            for item in endpoint.get("items") or []
            if item.get("transaction_reference")
            in set(context["member_transaction_references"])
        ]
        grouped_items = [
            item for item in context_items if item.get("scope") == "bearer"
        ]
        # Item-scoped identity classification. A readable grouped value is not
        # an assigned bearer identity: zero is the explicit "no EPS bearer
        # identity assigned" code and a value outside the 4-bit encoded domain
        # is no identity at all, so neither can isolate a bearer generation.
        assigned_identities: set[int] = set()
        unassigned_items = 0
        invalid_items = 0
        unreadable_items = 0
        for item in grouped_items:
            classification = classify_eps_bearer_identity(item.get("eps_bearer_identity"))
            if classification == ITEM_IDENTITY_ASSIGNED:
                assigned_identities.add(int(item["eps_bearer_identity"]))
            elif classification == ITEM_IDENTITY_UNRESOLVED:
                unreadable_items += 1
            elif eps_bearer_identity_is_readable(classification):
                unassigned_items += 1
            else:
                invalid_items += 1
        item_outcomes = {_item_outcome(item) for item in grouped_items}
        limitations: list[str] = []
        if context["association_status"] != STATUS_ESTABLISHED:
            status = STATUS_NOT_ESTABLISHED
            basis = "owning_session_context_not_established"
            limitations.append(
                "the owning session context is not established, so the link cannot be established"
            )
        elif not assigned_identities and (unassigned_items or invalid_items):
            status = STATUS_NOT_ESTABLISHED
            basis = BASIS_GROUPED_IDENTITY_UNASSIGNED_OR_INVALID
            detail = []
            if unassigned_items:
                detail.append(
                    f"{unassigned_items} item(s) advertise EPS Bearer Identity 0, which means no "
                    "EPS bearer identity was assigned"
                )
            if invalid_items:
                detail.append(
                    f"{invalid_items} item(s) advertise an identity outside the 4-bit encoded "
                    "domain (0..15)"
                )
            limitations.append(
                "no grouped bearer-context item of this endpoint carries a valid assigned "
                "item-scoped EPS bearer identity: " + "; ".join(detail)
            )
        elif not assigned_identities:
            status = STATUS_NOT_ESTABLISHED
            basis = "grouped_bearer_item_identity_missing"
            detail = (
                f" ({unreadable_items} grouped item(s) carry no readable item-scoped identity)"
                if unreadable_items
                else ""
            )
            limitations.append(
                "no grouped bearer-context item of this endpoint carries a readable item-scoped "
                "bearer identity, so the message-scope advertisement alone cannot establish a "
                "bearer association" + detail
            )
        elif unassigned_items or invalid_items:
            status = STATUS_NOT_ESTABLISHED
            basis = BASIS_GROUPED_IDENTITY_UNASSIGNED_OR_INVALID
            limitations.append(
                "the endpoint mixes assigned with unassigned or out-of-domain item-scoped "
                "identities, so the assigned item's ownership of this endpoint is not "
                "independently unique and no conflicting evidence is discarded to raise the "
                "established count"
            )
        elif len(assigned_identities) > 1:
            status = STATUS_AMBIGUOUS
            basis = "distinct_bearer_identities_share_one_endpoint"
            limitations.append(
                "the endpoint advertises more than one assigned item-scoped bearer identity "
                f"({sorted(assigned_identities)}), so no single EPS bearer generation is isolated"
            )
        elif "REJECTED_OBSERVED" in item_outcomes:
            status = STATUS_NOT_ESTABLISHED
            basis = "bearer_item_rejected_observed"
            limitations.append(
                "a grouped bearer item of this endpoint carries a non-accepted Cause; the "
                "message-level outcome never overrides a bearer-level rejection"
            )
        elif "UNRESOLVED" in item_outcomes:
            status = STATUS_NOT_ESTABLISHED
            basis = "bearer_item_outcome_unresolved"
            limitations.append(
                "no readable grouped bearer Cause and no accepted message-level Cause back this "
                "endpoint item, so its bearer association is unresolved"
            )
        elif len(same_role) != 1:
            status = STATUS_AMBIGUOUS
            basis = "several_endpoints_of_one_receiving_role_in_one_context"
            limitations.append(
                "the context advertises more than one endpoint of this receiving role, so the "
                "intended generation cannot be isolated"
            )
        else:
            status = STATUS_ESTABLISHED
            basis = BASIS_ENDPOINT_LINK
        ebis = sorted(endpoint["ebis"])
        frames = sorted(endpoint["frames"])
        links.append(
            {
                "capture_file": capture,
                "relationship_type": REL_SESSION_GENERATION,
                "source_subject_reference": context["session_context_reference"],
                "target_subject_reference": bearer_endpoint_reference(
                    capture, role, address, teid, interface_type
                ),
                "association_status": status,
                "association_basis": basis,
                "reviewed_identifiers": [
                    {
                        "kind": "bearer_endpoint_fteid",
                        "interface_type": interface_type,
                        "teid": teid,
                        "address": address,
                        "role": role,
                        "scope": sorted(endpoint["scopes"])[0] if endpoint["scopes"] else None,
                        "eps_bearer_identity": ebis[0] if len(ebis) == 1 else None,
                    }
                ],
                "source_transaction_references": advertising,
                "source_frames": frames,
                "evidence_refs": [
                    _evidence_ref("GTPv2-C", frame, None) for frame in frames
                ][:MAX_EVIDENCE_REFERENCES],
                "observation_window": {
                    "start_frame": frames[0] if frames else None,
                    "end_frame": frames[-1] if frames else None,
                },
                "competing_candidates": (
                    []
                    if len(same_role) == 1
                    else sorted(
                        bearer_endpoint_reference(capture, role, item[2], item[3], item[4])
                        for item in same_role
                    )
                ),
                "bearer_endpoint": {
                    "role": role,
                    "address": address,
                    "teid": teid,
                    "interface_type": interface_type,
                    "eps_bearer_identities": ebis,
                    "generation_references": [],
                },
                "limitations": limitations,
                "bridge_mediated": False,
            }
        )
        direct.append((context, links[-1]))

    # Bridge-mediated links: an endpoint advertised by one hop's context may also
    # be linked to the peer context through one proved session identity bridge.
    # The direction follows the bridge: the identity's source context adopts the
    # endpoint relationships of the identity's target context.
    established_identity_by_target: dict[str, list[dict[str, Any]]] = {}
    for identity in identities:
        if identity["association_status"] == STATUS_ESTABLISHED:
            established_identity_by_target.setdefault(
                identity["target_subject_reference"], []
            ).append(identity)
    for source_context, inner_link in direct:
        if inner_link["association_status"] != STATUS_ESTABLISHED:
            continue
        for identity in established_identity_by_target.get(
            inner_link["source_subject_reference"], []
        ):
            peer_context = context_by_reference.get(identity["source_subject_reference"])
            if peer_context is None:
                continue
            role = inner_link["bearer_endpoint"]["role"]
            competing = [
                other
                for other in links
                if other["capture_file"] == peer_context["capture_file"]
                and other["source_subject_reference"]
                == peer_context["session_context_reference"]
                and other["bearer_endpoint"]["role"] == role
            ]
            if competing:
                for other in competing:
                    if other["association_status"] == STATUS_ESTABLISHED:
                        other["association_status"] = STATUS_AMBIGUOUS
                        other["association_basis"] = (
                            "direct_and_bridge_mediated_endpoints_compete_for_one_role"
                        )
                        other["limitations"] = other["limitations"] + [
                            "a bridge-mediated endpoint competes with a directly advertised "
                            "endpoint of the same receiving role, so neither isolates a generation"
                        ]
                continue
            frames = list(inner_link["source_frames"])
            links.append(
                {
                    "capture_file": peer_context["capture_file"],
                    "relationship_type": REL_SESSION_GENERATION,
                    "source_subject_reference": peer_context["session_context_reference"],
                    "target_subject_reference": inner_link["target_subject_reference"],
                    "association_status": STATUS_ESTABLISHED,
                    "association_basis": (
                        "endpoint_advertised_by_a_member_of_the_peer_context_connected_by_a_"
                        "proved_cross_interface_session_identity"
                    ),
                    "reviewed_identifiers": list(inner_link["reviewed_identifiers"]),
                    "source_transaction_references": list(
                        inner_link["source_transaction_references"]
                    ),
                    "source_frames": frames,
                    "evidence_refs": [
                        _evidence_ref("GTPv2-C", frame, None) for frame in frames
                    ][:MAX_EVIDENCE_REFERENCES],
                    "observation_window": dict(inner_link["observation_window"]),
                    "competing_candidates": [],
                    "bearer_endpoint": dict(inner_link["bearer_endpoint"]),
                    "limitations": [
                        "the link crosses hops through one proved session identity bridge: "
                        + str(identity["reference"])
                    ],
                    "bridge_mediated": True,
                    "session_identity_reference": identity["reference"],
                }
            )

    if isinstance(lifecycle_analysis, dict):
        by_endpoint: dict[tuple[str, str, str, int, int], list[str]] = {}
        for subject in lifecycle_analysis.get("lifecycle_subjects") or []:
            if not isinstance(subject, dict) or not isinstance(
                subject.get("generation_reference"), str
            ):
                continue
            key = (
                str(subject.get("capture_file")),
                str(subject.get("receiving_endpoint_role")),
                str(subject.get("receiving_endpoint_address")),
                _int(subject.get("receiving_endpoint_teid")),
                _int(subject.get("reviewed_interface_type")),
            )
            by_endpoint.setdefault(key, []).append(subject["generation_reference"])
        for link in links:
            endpoint = link["bearer_endpoint"]
            key = (
                link["capture_file"],
                str(endpoint["role"]),
                str(endpoint["address"]),
                _int(endpoint["teid"]),
                _int(endpoint["interface_type"]),
            )
            link["bearer_endpoint"]["generation_references"] = sorted(by_endpoint.get(key, []))
    links.sort(
        key=lambda item: (
            item["capture_file"],
            item["observation_window"]["start_frame"] or 0,
            item["source_subject_reference"],
            item["target_subject_reference"],
        )
    )
    return links, unbound


def build_release_bindings(
    events: list[dict[str, Any]],
    index: dict[str, Any],
    contexts: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Release-to-session-context bindings with separately published outcomes.

    The release outcome is classified by the accepted lifecycle contract from
    the correlated response only, and is published beside the binding, never
    merged into it.
    """
    boundaries = release_boundaries(events, index)
    by_key = {
        event_key(event): event
        for event in events
        if isinstance(event, dict) and event_key(event) is not None
    }
    bindings: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    for boundary in sorted(
        boundaries,
        key=lambda item: (str(item.get("capture_file")), _int(item.get("request_frame")) or 0),
    ):
        capture = str(boundary.get("capture_file"))
        transaction_reference = boundary.get("transaction_reference")
        outcome = boundary.get("release_outcome")
        frames = [
            frame
            for frame in (boundary.get("request_frame"), boundary.get("response_frame"))
            if frame is not None
        ]
        if not isinstance(transaction_reference, str) or transaction_reference not in (
            index.get("transactions") or {}
        ):
            unbound.append(
                {
                    "kind": "release_without_accepted_transaction",
                    "capture_file": capture,
                    "frame_number": boundary.get("request_frame"),
                    "release_outcome_status": outcome,
                    "limitations": [
                        "the release is not a member of an accepted transaction, so no session "
                        "context can be evaluated for it"
                    ],
                }
            )
            continue
        bound = index["transactions"][transaction_reference]
        request_event = by_key.get(bound.get("request_key"))
        candidates = _context_join_candidates(contexts, capture, request_event)
        teid = _event_header_teid(request_event)
        destination = _destination_address(request_event)
        source = _source_address(request_event)
        # A release binds only to one structurally matching context that is
        # itself established; several structural matches stay ambiguous even
        # when only one of them is established.
        if len(candidates) == 1 and candidates[0]["association_status"] != STATUS_ESTABLISHED:
            binding_status = STATUS_NOT_ESTABLISHED
            binding_basis = "target_session_context_not_established"
            target_reference = None
        elif len(candidates) == 1:
            binding_status = STATUS_ESTABLISHED
            binding_basis = BASIS_RECEIVER_SCOPED_ADDRESSING
            target_reference = candidates[0]["session_context_reference"]
        elif len(candidates) > 1:
            binding_status = STATUS_AMBIGUOUS
            binding_basis = "receiver_scoped_addressing_matches_several_contexts"
            target_reference = None
        else:
            binding_status = STATUS_NOT_ESTABLISHED
            binding_basis = "no_session_context_matches_the_receiver_scoped_addressing"
            target_reference = None
        identifiers = [
            {
                "kind": "request_addressing",
                "header_teid": teid,
                "receiver_address": destination,
                "sender_address": source,
            }
        ]
        if len(candidates) == 1:
            identifiers.append(
                {
                    "kind": "matched_control_plane_fteid",
                    "session_context_reference": candidates[0]["session_context_reference"],
                    "interface_class": candidates[0]["interface_class"],
                }
            )
        limitations = [item for item in boundary.get("limitations") or [] if isinstance(item, str)]
        if len(candidates) > 1:
            limitations = limitations + [
                "the release request addresses several hop-local contexts, so it binds to none "
                "of them regardless of its outcome"
            ]
        bindings.append(
            {
                "capture_file": capture,
                "relationship_type": REL_RELEASE_BINDING,
                "source_subject_reference": transaction_reference,
                "target_subject_reference": target_reference,
                "association_status": binding_status,
                "association_basis": binding_basis,
                "reviewed_identifiers": identifiers,
                "source_transaction_references": [transaction_reference],
                "source_frames": frames,
                "evidence_refs": boundary.get("evidence_refs") or [],
                "observation_window": {
                    "start_frame": frames[0] if frames else None,
                    "end_frame": frames[-1] if frames else None,
                },
                "competing_candidates": (
                    []
                    if len(candidates) <= 1
                    else sorted(candidate["session_context_reference"] for candidate in candidates)
                ),
                "release_outcome_status": outcome,
                "release_outcome_basis": boundary.get("release_outcome_basis"),
                "lifecycle_control_plane_context": boundary.get("control_plane_context"),
                "limitations": limitations,
            }
        )
    return bindings, unbound


def _release_bearer_identities(
    events: list[dict[str, Any]], index: dict[str, Any]
) -> dict[str, list[int]]:
    """Message-scope Linked EPS Bearer ID values of each accepted release request.

    The values come from the accepted event contract's unbound message-scope
    metadata; they are item identities of the release request, never a bearer
    binding, and they are never sufficient on their own for anything.
    """
    by_key = {
        event_key(event): event
        for event in events
        if isinstance(event, dict) and event_key(event) is not None
    }
    identities: dict[str, list[int]] = {}
    for reference, bound in (index.get("transactions") or {}).items():
        request_event = by_key.get(bound.get("request_key"))
        if not isinstance(request_event, dict):
            continue
        if request_event.get("procedure_family") not in DELETE_FAMILIES:
            continue
        metadata = request_event.get("unbound_ie_metadata")
        values: Any = None
        if isinstance(metadata, dict):
            values = metadata.get("ebi_values")
        elif isinstance(metadata, list):
            for item in metadata:
                if isinstance(item, dict) and "ebi_values" in item:
                    values = item.get("ebi_values")
        if isinstance(values, list):
            ebis = sorted({_int(value) for value in values if _int(value) is not None})
            if ebis:
                identities[str(reference)] = ebis
    return identities


def build_closure_candidates(
    bindings: list[dict[str, Any]],
    links: list[dict[str, Any]],
    release_bearer_identities: dict[str, list[int]],
) -> list[dict[str, Any]]:
    """Reviewed generation-closure candidates from the full identity chain.

    A candidate exists only for one established release binding and one
    established session-to-generation link of the same context, when the
    release's message-scope bearer identities are compatible with the endpoint's
    item-scoped identities. The candidate is a reviewed input for the lifecycle
    capability; it never closes a generation by itself.
    """
    candidates: list[dict[str, Any]] = []
    links_by_context: dict[str, list[dict[str, Any]]] = {}
    for link in links:
        links_by_context.setdefault(link["source_subject_reference"], []).append(link)

    def _candidate(
        binding: dict[str, Any],
        link: dict[str, Any],
        status: str,
        basis: str,
        limitations: list[str],
    ) -> dict[str, Any]:
        return {
            "capture_file": binding["capture_file"],
            "session_context_reference": binding["target_subject_reference"],
            "release_transaction_reference": binding["source_subject_reference"],
            "bearer_endpoint_reference": link["target_subject_reference"],
            "association_status": status,
            "association_basis": basis,
            "limitations": limitations,
        }

    for binding in sorted(
        bindings,
        key=lambda item: (
            item["capture_file"],
            item["observation_window"]["start_frame"] or 0,
            str(item["source_subject_reference"]),
        ),
    ):
        context_reference_value = binding["target_subject_reference"]
        if binding["association_status"] != STATUS_ESTABLISHED or not context_reference_value:
            continue
        for link in links_by_context.get(context_reference_value, []):
            if link["association_status"] != STATUS_ESTABLISHED:
                candidates.append(
                    _candidate(
                        binding,
                        link,
                        STATUS_NOT_ESTABLISHED,
                        "session_to_generation_link_not_established",
                        [
                            "the session-to-generation relationship is not established, so no "
                            "closure candidate is published"
                        ],
                    )
                )
                continue
            if binding["release_outcome_status"] != RELEASE_ACCEPTED:
                candidates.append(
                    _candidate(
                        binding,
                        link,
                        STATUS_NOT_ESTABLISHED,
                        f"release_outcome_{str(binding['release_outcome_status']).lower()}",
                        [
                            "the release outcome is not accepted, so no closure candidate is "
                            "published even though the session binding is established"
                        ],
                    )
                )
                continue
            release_identities = set(
                release_bearer_identities.get(str(binding["source_subject_reference"]), [])
            )
            endpoint_identities = set(link["bearer_endpoint"]["eps_bearer_identities"] or [])
            # Independent defense: the candidate builder re-verifies the
            # endpoint's item-scoped identity instead of trusting the upstream
            # link status. A readable value is not an assigned bearer, so a
            # Delete Session naming EBI zero can never make zero an identity.
            assigned_endpoint_identities = assigned_eps_bearer_identities(endpoint_identities)
            if not endpoint_identities:
                candidates.append(
                    _candidate(
                        binding,
                        link,
                        STATUS_NOT_ESTABLISHED,
                        "endpoint_bearer_identity_unestablished",
                        [
                            "the linked endpoint carries no independently established item-scoped "
                            "bearer identity, so no closure candidate may rest on it"
                        ],
                    )
                )
                continue
            if not assigned_endpoint_identities:
                candidates.append(
                    _candidate(
                        binding,
                        link,
                        STATUS_NOT_ESTABLISHED,
                        BASIS_ENDPOINT_IDENTITY_UNASSIGNED_OR_INVALID,
                        [
                            "the linked endpoint carries no valid assigned item-scoped EPS bearer "
                            "identity: zero means no identity was assigned and a value outside the "
                            "4-bit encoded domain is no identity at all, so no closure candidate "
                            "may rest on it"
                        ],
                    )
                )
                continue
            if (
                release_identities
                and endpoint_identities
                and not (release_identities & endpoint_identities)
            ):
                candidates.append(
                    _candidate(
                        binding,
                        link,
                        STATUS_NOT_ESTABLISHED,
                        "release_bearer_identities_disjoint_from_the_endpoint",
                        [
                            "the release names bearer identities that the linked endpoint does "
                            "not carry, so the release does not target this generation"
                        ],
                    )
                )
                continue
            frames = [frame for frame in binding["source_frames"] if frame is not None]
            reference_parts = "|".join(
                [
                    str(binding["capture_file"]),
                    str(context_reference_value),
                    str(binding["source_subject_reference"]),
                    str(link["target_subject_reference"]),
                ]
            )
            candidates.append(
                {
                    "capture_file": binding["capture_file"],
                    "generation_closure_candidate_reference": "epc-generation-closure-"
                    + hashlib.sha256(reference_parts.encode("utf-8")).hexdigest()[:10],
                    "session_context_reference": context_reference_value,
                    "release_transaction_reference": binding["source_subject_reference"],
                    "bearer_endpoint_reference": link["target_subject_reference"],
                    "bearer_endpoint": dict(link["bearer_endpoint"]),
                    "association_status": STATUS_ESTABLISHED,
                    "association_basis": (
                        "accepted_release_bound_to_one_established_context_with_one_established_"
                        "session_to_generation_link"
                    ),
                    "chain": [
                        {
                            "relationship_type": REL_RELEASE_BINDING,
                            "subject_reference": binding["source_subject_reference"],
                            "association_status": binding["association_status"],
                        },
                        {
                            "relationship_type": REL_SESSION_GENERATION,
                            "subject_reference": link["target_subject_reference"],
                            "association_status": link["association_status"],
                        },
                    ],
                    "item_identities": {
                        "release_bearer_identities": sorted(release_identities),
                        "endpoint_bearer_identities": sorted(endpoint_identities),
                    },
                    "release_request_frame": binding["source_frames"][0] if frames else None,
                    "release_confirmation_frame": (
                        binding["source_frames"][1] if len(frames) > 1 else None
                    ),
                    "limitations": [],
                }
            )
    candidates.sort(
        key=lambda item: (
            item["capture_file"],
            str(item.get("session_context_reference")),
            str(item.get("release_transaction_reference")),
            str(item.get("bearer_endpoint_reference")),
        )
    )
    return candidates


def analyze(
    gtpv2_events: list[dict[str, Any]],
    transactions: dict[str, Any] | None = None,
    session_analysis: dict[str, Any] | None = None,
    default_bearer: dict[str, Any] | None = None,
    lifecycle_analysis: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build bounded EPC session-identity bridge and release-binding evidence."""
    if not isinstance(gtpv2_events, list):
        raise InputError("GTPv2-C events must be a list")
    if transactions is not None and not isinstance(transactions, dict):
        raise InputError("GTPv2-C transaction correlation must be an object")

    index = transaction_index(transactions, gtpv2_events)
    contexts, unbound, ambiguous = build_hop_local_contexts(gtpv2_events, index)
    endpoints, endpoint_unbound = collect_bearer_fteids(gtpv2_events, index, contexts)
    candidates, correspondences, identities = evaluate_cross_interface(contexts)
    links, link_unbound = build_session_generation_links(
        contexts, endpoints, identities, lifecycle_analysis
    )
    bindings, binding_unbound = build_release_bindings(gtpv2_events, index, contexts)
    release_identities = _release_bearer_identities(gtpv2_events, index)
    closure_candidates = build_closure_candidates(bindings, links, release_identities)

    limitations: list[str] = []
    if not isinstance(transactions, dict) or not transactions.get("transactions"):
        limitations.append(
            "no accepted GTPv2-C transaction correlation was supplied, so no hop-local context "
            "can be established"
        )
    if session_analysis is None:
        limitations.append(
            "no EPC session-control analysis was supplied, so no cross-check against the "
            "session-control subjects is recorded"
        )
    if default_bearer is None:
        limitations.append(
            "no EPS default-bearer analysis was supplied, so its supporting evidence is not "
            "cross-checked here"
        )
    if lifecycle_analysis is None:
        limitations.append(
            "no EPC bearer-lifecycle analysis was supplied, so generation references could not "
            "be attached to the session-to-generation links"
        )
    if index.get("notes"):
        limitations.append(
            "some GTPv2-C transactions could not be bound to observed messages capture-scoped, "
            "so their identity relationships are unbound"
        )
    unbound_records = unbound + endpoint_unbound + link_unbound + binding_unbound
    for reason, references in sorted((index.get("notes") or {}).items()):
        for reference in sorted(references):
            unbound_records.append(
                {
                    "kind": "transaction_not_bound_to_observed_messages",
                    "capture_file": None,
                    "transaction_reference": str(reference),
                    "limitations": [
                        f"the transaction could not be bound to observed messages: {reason}"
                    ],
                }
            )
    unbound_records.sort(
        key=lambda item: (
            str(item.get("kind")),
            str(item.get("capture_file")),
            str(item.get("transaction_reference")),
            str(item.get("frame_number")),
            str(item.get("role")),
            str(item.get("teid")),
        )
    )
    if unbound_records:
        limitations.append(
            "one or more observed items could not be bound to a hop-local session context; they "
            "are published under unbound evidence"
        )

    ambiguous_records = list(ambiguous)
    ambiguous_records.extend(
        record
        for record in correspondences + identities + links + bindings
        if record["association_status"] == STATUS_AMBIGUOUS
    )

    additional: list[str] = []
    if not identities or all(
        item["association_status"] != STATUS_ESTABLISHED for item in identities
    ):
        additional.append(
            "a relayed control-plane F-TEID that is equal and unique across the two Create "
            "Session responses is required to establish a cross-interface session identity"
        )
    if not bindings or all(
        item["association_status"] != STATUS_ESTABLISHED for item in bindings
    ):
        additional.append(
            "a release request that addresses exactly one hop-local control-plane F-TEID of one "
            "context is required to bind a release to a session context"
        )

    result = {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": provenance or {},
        "analysis_scope": {
            "capability": (
                "bounded EPC S11<->S5/S8 session-identity bridge and release-binding evidence"
            ),
            "relationship_types": list(RELATIONSHIP_TYPES),
            "association_statuses": list(ASSOCIATION_STATUSES),
            "identity_rule": (
                "a transaction joins a hop-local context only when its request header TEID and "
                "destination address equal one hop-local control-plane F-TEID of that context and "
                "its source address equals a hop-local F-TEID address of the same context; equal "
                "values alone never join, and relayed F-TEIDs of a foreign interface type are "
                "never join keys"
            ),
            "bridge_rule": (
                "a relayed control-plane F-TEID establishes session identity only when it is "
                "unique on both hops and both contexts are established; an equal user-plane "
                "F-TEID is endpoint correspondence only"
            ),
            "release_rule": (
                "the release outcome is classified from the correlated response only and is "
                "published separately from the session binding"
            ),
            "identity_validity_rule": (
                "an item-scoped EPS Bearer Identity establishes a bearer association only when it "
                "is an assigned value: zero is the explicit no-EPS-bearer-identity-assigned code "
                "and a value outside the 4-bit encoded domain is no identity, so neither can "
                "isolate a bearer generation or support a closure candidate"
            ),
        },
        "hop_local_contexts": contexts[:MAX_SUBJECTS],
        "hop_local_context_count": len(contexts),
        "established_hop_local_context_count": sum(
            1 for item in contexts if item["association_status"] == STATUS_ESTABLISHED
        ),
        "cross_interface_candidates": candidates[:MAX_SUBJECTS],
        "cross_interface_candidate_count": len(candidates),
        "endpoint_correspondence_links": correspondences[:MAX_SUBJECTS],
        "endpoint_correspondence_count": len(correspondences),
        "session_identity_links": identities[:MAX_SUBJECTS],
        "session_identity_count": len(identities),
        "release_session_bindings": bindings[:MAX_SUBJECTS],
        "release_session_binding_count": len(bindings),
        "release_session_bindings_omitted": max(0, len(bindings) - MAX_SUBJECTS),
        "session_to_generation_links": links[:MAX_SUBJECTS],
        "session_to_generation_count": len(links),
        "session_to_generation_omitted": max(0, len(links) - MAX_SUBJECTS),
        "generation_closure_candidates": closure_candidates[:MAX_SUBJECTS],
        "generation_closure_candidate_count": len(closure_candidates),
        "generation_closure_candidates_omitted": max(0, len(closure_candidates) - MAX_SUBJECTS),
        "established_closure_candidate_count": sum(
            1 for item in closure_candidates if item["association_status"] == STATUS_ESTABLISHED
        ),
        "ambiguous_associations": ambiguous_records[:MAX_SUBJECTS],
        "ambiguous_association_count": len(ambiguous_records),
        "unbound_evidence": unbound_records[:MAX_SUBJECTS],
        "unbound_evidence_count": len(unbound_records),
        "evidence_limitations": limitations[:MAX_LIST_ITEMS],
        "additional_evidence_needed": additional[:MAX_LIST_ITEMS],
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": (
            "a session-identity relationship is not an abnormal failure boundary; this analysis "
            "never selects a first abnormal boundary"
        ),
    }
    return result
