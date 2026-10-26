"""Bounded EPC session-level release narrative and temporal evidence reporting.

This Domain capability consumes only accepted, already-published EPC artifacts:

1. the accepted EPC session-identity analysis (hop-local contexts, cross-interface
   identity links, release-to-session bindings, session-to-generation links and
   generation-closure candidates);
2. the accepted EPC bearer-lifecycle analysis (generations, proved boundaries,
   generation-scoped and unresolved S1-U observations, conserved accounting);
3. optionally the accepted EPC S1-U observation (directed stream evidence);
4. optionally the detailed GTPv2-C events, used only to validate that a published
   frame anchor still corresponds to the supplied capture and to display the
   observed message metadata;
5. optionally the detailed GTP-U events, used only for exact frame-level temporal
   segmentation.

It never decodes a capture, never rebuilds a transaction correlation, never
re-derives session identity, never changes a packet or octet attribution and never
publishes subscriber identity.

The capability answers, per reviewed hop-local session context:

* which allocation and bearer relationships were actually established;
* which Delete Session Request was observed and which response confirmed it;
* which bearer generations were independently proved closed;
* what user-plane traffic was observed before, inside and after the release
  window, and which of those placements are frame-resolvable;
* which conclusions stay unsupported or temporally unresolved.

Hard separation rules, enforced throughout:

* a hop-local context is never silently merged with its bridge peer: an
  established cross-interface identity link yields an explicitly labelled
  narrative group, not one global PDN session;
* an endpoint correspondence is never a session identity bridge;
* an accepted release outcome, an established release-to-session binding and a
  proved bearer-generation closure are three separate facts;
* the response confirmation frame is never the forwarding-stop instant;
* an aggregate stream count is never divided across time windows;
* an observed G-PDU never proves UE receipt or application reachability.
"""

from __future__ import annotations

import hashlib
from typing import Any

from epc_bearer_lifecycle_model import (
    MAX_EVIDENCE_REFERENCES,
    MAX_LIST_ITEMS,
    MAX_SUBJECTS,
    InputError,
    _int,
    read_json,
    read_jsonl,
    safe_name,
)

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.7.0"
ANALYSIS_NAME = "epc-release-narrative"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_SUBJECTS = 6
EXIT_OUTPUT_FAILURE = 7

# Narrative stage labels. These are reporting stages, not Protocol-layer outcome
# states, and they never replace the accepted source classifications.
STAGE_ALLOCATION_OBSERVED = "ALLOCATION_OBSERVED"
STAGE_ALLOCATION_ACCEPTED = "ALLOCATION_ACCEPTED"
STAGE_SESSION_CONTEXT_ESTABLISHED = "SESSION_CONTEXT_ESTABLISHED"
STAGE_BEARER_ASSOCIATION_ESTABLISHED = "BEARER_ASSOCIATION_ESTABLISHED"
STAGE_RELEASE_REQUEST_OBSERVED = "RELEASE_REQUEST_OBSERVED"
STAGE_RELEASE_OUTCOME_ACCEPTED = "RELEASE_OUTCOME_ACCEPTED"
STAGE_RELEASE_OUTCOME_REJECTED = "RELEASE_OUTCOME_REJECTED_OBSERVED"
STAGE_RELEASE_OUTCOME_UNRESOLVED = "RELEASE_OUTCOME_UNRESOLVED"
STAGE_BINDING_ESTABLISHED = "RELEASE_SESSION_BINDING_ESTABLISHED"
STAGE_BINDING_NOT_ESTABLISHED = "RELEASE_SESSION_BINDING_NOT_ESTABLISHED"
STAGE_CLOSURE_ESTABLISHED = "GENERATION_CLOSURE_ESTABLISHED"
STAGE_CLOSURE_NOT_ESTABLISHED = "GENERATION_CLOSURE_NOT_ESTABLISHED"
STAGE_EFFECTIVE_INSTANT_UNPROVED = "RELEASE_EFFECTIVE_INSTANT_UNPROVED"

STAGE_LABELS = (
    STAGE_ALLOCATION_OBSERVED,
    STAGE_ALLOCATION_ACCEPTED,
    STAGE_SESSION_CONTEXT_ESTABLISHED,
    STAGE_BEARER_ASSOCIATION_ESTABLISHED,
    STAGE_RELEASE_REQUEST_OBSERVED,
    STAGE_RELEASE_OUTCOME_ACCEPTED,
    STAGE_RELEASE_OUTCOME_REJECTED,
    STAGE_RELEASE_OUTCOME_UNRESOLVED,
    STAGE_BINDING_ESTABLISHED,
    STAGE_BINDING_NOT_ESTABLISHED,
    STAGE_CLOSURE_ESTABLISHED,
    STAGE_CLOSURE_NOT_ESTABLISHED,
    STAGE_EFFECTIVE_INSTANT_UNPROVED,
)

# Evidence-status vocabulary. A stage may only use one of these tokens; free text
# can never masquerade as an established conclusion.
STATUS_OBSERVED = "OBSERVED"
STATUS_ACCEPTED = "ACCEPTED"
STATUS_REJECTED = "REJECTED_OBSERVED"
STATUS_UNRESOLVED = "UNRESOLVED"
STATUS_ESTABLISHED = "ESTABLISHED"
STATUS_NOT_ESTABLISHED = "NOT_ESTABLISHED"
STATUS_AMBIGUOUS = "AMBIGUOUS"
STATUS_INSUFFICIENT = "INSUFFICIENT_EVIDENCE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

EVIDENCE_STATUSES = (
    STATUS_OBSERVED,
    STATUS_ACCEPTED,
    STATUS_REJECTED,
    STATUS_UNRESOLVED,
    STATUS_ESTABLISHED,
    STATUS_NOT_ESTABLISHED,
    STATUS_AMBIGUOUS,
    STATUS_INSUFFICIENT,
    STATUS_NOT_APPLICABLE,
)

# Temporal placement outcomes.
TEMPORAL_ESTABLISHED = "ESTABLISHED"
TEMPORAL_NOT_ESTABLISHED = "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"

PARTITION_BEFORE = "before_release"
PARTITION_PENDING = "pending_release"
PARTITION_AFTER = "after_confirmation"
PARTITIONS = (PARTITION_BEFORE, PARTITION_PENDING, PARTITION_AFTER)

PARTITION_BASIS_FRAMES = "FRAME_LEVEL_EVENTS"
PARTITION_BASIS_AGGREGATE = "AGGREGATE_STREAM_ONLY"

# Source-completeness classifications. Reused from the accepted lifecycle contract.
COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_TRUNCATED = "SOURCE_CANDIDATES_TRUNCATED"
COMPLETENESS_INVALID = "SOURCE_CANDIDATES_METADATA_INVALID"
COMPLETENESS_NOT_SUPPLIED = "NOT_SUPPLIED"

RELEASE_ACCEPTED = "ACCEPTED"
RELEASE_REJECTED = "REJECTED_OBSERVED"
RELEASE_UNRESOLVED = "UNRESOLVED"

NARRATIVE_NOT_CONFIRMED = (
    "a hop-local session context is a control-plane grouping, not a global PDN session",
    "an established cross-interface identity link yields a labelled narrative group, never one subscriber",
    "an endpoint correspondence is not a session identity bridge",
    "an accepted release outcome does not prove that user-plane forwarding stopped",
    "the release confirmation frame is not the forwarding-stop frame",
    "a proved bearer-generation boundary does not forbid a later observed G-PDU",
    "an observed G-PDU never proves UE receipt or application reachability",
    "an unresolved stream is not packet loss and not a tunnel failure",
    "an aggregate stream count is never divided across time windows",
    "no subscriber identity, APN name or assigned PDN address is read or published",
    "this capability selects no first abnormal boundary and no root cause",
)


class NarrativeInputError(InputError):
    """Raised when a supplied source document cannot be consumed as published."""


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------
def _reference(prefix: str, parts: list[Any]) -> str:
    material = "|".join(str(part) for part in parts)
    return prefix + hashlib.sha256(material.encode("utf-8")).hexdigest()[:10]


def _evidence_ref(protocol: str, frame: Any, message_type: Any) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "frame_number": _int(frame),
        "message_type": message_type if isinstance(message_type, str) else None,
        "evidence_level": "OBSERVED",
    }


def _ref_for_message(
    evidence_refs: Any, message_type: str
) -> dict[str, Any] | None:
    """The first published evidence reference carrying one message type."""
    if not isinstance(evidence_refs, list):
        return None
    for item in evidence_refs:
        if isinstance(item, dict) and item.get("message_type") == message_type:
            return item
    return None


def _bounded(values: Any, limit: int = MAX_LIST_ITEMS) -> list[Any]:
    if not isinstance(values, list):
        return []
    return values[:limit]


def _strings(values: Any, limit: int = MAX_LIST_ITEMS) -> list[str]:
    return [item for item in _bounded(values, limit) if isinstance(item, str)]


def _source_document(value: Any, name: str, required: bool) -> dict[str, Any] | None:
    if value is None:
        if required:
            raise NarrativeInputError(f"{name} is required and was not supplied")
        return None
    if not isinstance(value, dict):
        raise NarrativeInputError(f"{name} is not a JSON object")
    return value


def _declared_count(document: dict[str, Any], key: str) -> int | None:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _omitted_count(document: dict[str, Any], key: str) -> int | None:
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _completeness_entry(
    document_name: str,
    document: dict[str, Any] | None,
    collection_key: str,
    count_key: str,
    omitted_key: str | None,
) -> dict[str, Any]:
    """Compare one published count with its published record array."""
    entry: dict[str, Any] = {
        "document": document_name,
        "collection": collection_key,
        "declared_count": None,
        "published_count": 0,
        "omitted_count": None,
        "status": COMPLETENESS_NOT_SUPPLIED,
    }
    if document is None:
        return entry
    records = document.get(collection_key)
    if not isinstance(records, list):
        entry["status"] = COMPLETENESS_INVALID
        return entry
    entry["published_count"] = len(records)
    declared = _declared_count(document, count_key)
    entry["declared_count"] = declared
    if declared is None:
        entry["status"] = COMPLETENESS_INVALID
        return entry
    if declared > len(records):
        entry["status"] = COMPLETENESS_TRUNCATED
        return entry
    if declared < len(records):
        entry["status"] = COMPLETENESS_INVALID
        return entry
    if omitted_key is not None:
        omitted = _omitted_count(document, omitted_key)
        entry["omitted_count"] = omitted
        if omitted is None or omitted != 0:
            entry["status"] = COMPLETENESS_INVALID
            return entry
    entry["status"] = COMPLETENESS_COMPLETE
    return entry


def source_completeness(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    s1u: dict[str, Any] | None,
) -> dict[str, Any]:
    """Affirmative completeness proof for every closure-critical collection.

    A narrative may only claim exhaustive release or generation coverage when
    every material source collection publishes a valid count equal to its own
    published records and a zero omitted count.
    """
    candidates = [
        _completeness_entry(
            "epc-session-identity",
            identity,
            "hop_local_contexts",
            "hop_local_context_count",
            None,
        ),
        _completeness_entry(
            "epc-session-identity",
            identity,
            "release_session_bindings",
            "release_session_binding_count",
            "release_session_bindings_omitted",
        ),
        _completeness_entry(
            "epc-session-identity",
            identity,
            "session_to_generation_links",
            "session_to_generation_count",
            "session_to_generation_omitted",
        ),
        _completeness_entry(
            "epc-session-identity",
            identity,
            "generation_closure_candidates",
            "generation_closure_candidate_count",
            "generation_closure_candidates_omitted",
        ),
        _completeness_entry(
            "epc-bearer-lifecycle",
            lifecycle,
            "lifecycle_subjects",
            "lifecycle_subject_count",
            "lifecycle_subjects_omitted",
        ),
        _completeness_entry(
            "epc-bearer-lifecycle",
            lifecycle,
            "advertisement_families",
            "advertisement_family_count",
            "advertisement_families_omitted",
        ),
    ]
    if s1u is not None:
        candidates.append(
            _completeness_entry(
                "epc-s1u-observation",
                s1u,
                "stream_observations",
                "stream_count",
                "streams_omitted",
            )
        )
    # A document that was not supplied makes no claim either way; its absence is
    # reported as a limitation and in the provenance, not as incomplete metadata.
    collections = [
        entry for entry in candidates if entry["status"] != COMPLETENESS_NOT_SUPPLIED
    ]
    statuses = {entry["status"] for entry in collections}
    if COMPLETENESS_TRUNCATED in statuses:
        status = COMPLETENESS_TRUNCATED
    elif COMPLETENESS_INVALID in statuses:
        status = COMPLETENESS_INVALID
    elif COMPLETENESS_NOT_SUPPLIED in statuses:
        status = COMPLETENESS_NOT_SUPPLIED
    else:
        status = COMPLETENESS_COMPLETE
    limitation: str | None = None
    if status == COMPLETENESS_TRUNCATED:
        limitation = (
            "SOURCE_CANDIDATES_TRUNCATED: a material source collection publishes fewer records "
            "than its own declared count, so no exhaustive release or generation coverage is "
            "claimed and no uniqueness is inferred from the visible subset"
        )
    elif status == COMPLETENESS_INVALID:
        limitation = (
            "SOURCE_CANDIDATES_METADATA_INVALID: a material source collection publishes a "
            "missing, invalid, underdeclared or nonzero-omitted count, so no exhaustive release "
            "or generation coverage is claimed"
        )
    return {
        "status": status,
        "exhaustive_coverage_proven": status == COMPLETENESS_COMPLETE,
        "limitation": limitation,
        "collections": collections,
    }


# ---------------------------------------------------------------------------
# Narrative subjects
# ---------------------------------------------------------------------------
def _context_references(identity: dict[str, Any]) -> list[dict[str, Any]]:
    contexts = [
        item
        for item in identity.get("hop_local_contexts") or []
        if isinstance(item, dict) and isinstance(item.get("session_context_reference"), str)
    ]
    return contexts


def _narrative_groups(
    contexts: list[dict[str, Any]], identity_links: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Group contexts only through already-established cross-interface identity.

    The grouping never invents a global session: it unions two hop-local contexts
    exactly when the accepted identity analysis publishes an ESTABLISHED
    CROSS_INTERFACE_SESSION_IDENTITY link between them in the same capture.
    """
    capture_by_context = {
        item["session_context_reference"]: str(item.get("capture_file"))
        for item in contexts
    }
    parent: dict[str, str] = {reference: reference for reference in capture_by_context}

    def find(node: str) -> str:
        while parent[node] != node:
            parent[node] = parent[parent[node]]
            node = parent[node]
        return node

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    bridge_by_context: dict[str, list[str]] = {}
    for link in identity_links:
        if not isinstance(link, dict):
            continue
        if link.get("association_status") != STATUS_ESTABLISHED:
            continue
        if link.get("relationship_type") != "CROSS_INTERFACE_SESSION_IDENTITY":
            continue
        source = link.get("source_subject_reference")
        target = link.get("target_subject_reference")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if source not in parent or target not in parent:
            continue
        if capture_by_context[source] != capture_by_context[target]:
            continue
        union(source, target)
        reference = link.get("reference")
        if isinstance(reference, str):
            bridge_by_context.setdefault(source, []).append(reference)
            bridge_by_context.setdefault(target, []).append(reference)

    members: dict[str, list[str]] = {}
    for reference in parent:
        members.setdefault(find(reference), []).append(reference)
    groups: dict[str, dict[str, Any]] = {}
    for root, group_members in members.items():
        ordered = sorted(group_members)
        capture = capture_by_context[ordered[0]]
        groups[root] = {
            "narrative_group_reference": _reference(
                "epc-release-group-", [capture] + ordered
            ),
            "narrative_group_basis": (
                "proved_cross_interface_session_identity"
                if len(ordered) > 1
                else "single_hop_local_context"
            ),
            "narrative_group_members": ordered,
            "narrative_group_capture_file": capture,
            "narrative_group_bridge_references": sorted(
                {
                    reference
                    for member in ordered
                    for reference in bridge_by_context.get(member, [])
                }
            ),
        }
    return {reference: groups[find(reference)] for reference in parent}


def build_narrative_subjects(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
) -> list[dict[str, Any]]:
    """One narrative subject per published hop-local session context."""
    contexts = _context_references(identity)
    identity_links = [
        item for item in identity.get("session_identity_links") or [] if isinstance(item, dict)
    ]
    correspondences = [
        item
        for item in identity.get("endpoint_correspondence_links") or []
        if isinstance(item, dict)
    ]
    generation_links = [
        item
        for item in identity.get("session_to_generation_links") or []
        if isinstance(item, dict)
    ]
    bindings = [
        item for item in identity.get("release_session_bindings") or [] if isinstance(item, dict)
    ]
    groups = _narrative_groups(contexts, identity_links)
    generations_by_endpoint: dict[tuple[str, str, str, int, int], list[str]] = {}
    for subject in lifecycle.get("lifecycle_subjects") or []:
        if not isinstance(subject, dict):
            continue
        reference = subject.get("generation_reference")
        if not isinstance(reference, str):
            continue
        key = (
            str(subject.get("capture_file")),
            str(subject.get("receiving_endpoint_role")),
            str(subject.get("receiving_endpoint_address")),
            _int(subject.get("receiving_endpoint_teid")) or 0,
            _int(subject.get("reviewed_interface_type")) or 0,
        )
        generations_by_endpoint.setdefault(key, []).append(reference)

    subjects: list[dict[str, Any]] = []
    for context in contexts:
        reference = context["session_context_reference"]
        capture = str(context.get("capture_file"))
        peers = [
            link
            for link in identity_links
            if link.get("relationship_type") == "CROSS_INTERFACE_SESSION_IDENTITY"
            and reference
            in (link.get("source_subject_reference"), link.get("target_subject_reference"))
        ]
        endpoints: list[dict[str, Any]] = []
        for link in generation_links:
            if link.get("source_subject_reference") != reference:
                continue
            endpoint = link.get("bearer_endpoint")
            if not isinstance(endpoint, dict):
                continue
            key = (
                capture,
                str(endpoint.get("role")),
                str(endpoint.get("address")),
                _int(endpoint.get("teid")) or 0,
                _int(endpoint.get("interface_type")) or 0,
            )
            endpoints.append(
                {
                    "bearer_endpoint_reference": link.get("target_subject_reference"),
                    "role": endpoint.get("role"),
                    "address": endpoint.get("address"),
                    "teid": endpoint.get("teid"),
                    "interface_type": endpoint.get("interface_type"),
                    "eps_bearer_identities": _bounded(
                        endpoint.get("eps_bearer_identities") or []
                    ),
                    "association_status": link.get("association_status"),
                    "association_basis": link.get("association_basis"),
                    "bridge_mediated": bool(link.get("bridge_mediated")),
                    "generation_references": sorted(
                        generations_by_endpoint.get(key, [])
                        or (endpoint.get("generation_references") or [])
                    ),
                    "source_frames": _bounded(link.get("source_frames") or []),
                }
            )
        release_references = [
            _reference(
                "epc-release-narrative-",
                [capture, str(binding.get("source_subject_reference"))],
            )
            for binding in bindings
            if binding.get("target_subject_reference") == reference
        ]
        limitations: list[str] = []
        if context.get("association_status") != STATUS_ESTABLISHED:
            limitations.append(
                "the session context is not established, so every downstream release and "
                "generation claim for it stays unproved"
            )
        if not endpoints:
            limitations.append(
                "no established session-to-generation relationship is published for this context"
            )
        temporal_limitations = [
            "the accepted model never proves the instant at which user-plane forwarding stopped"
        ]
        if not release_references:
            temporal_limitations.append(
                "no release-to-session binding addresses this context in the supplied analysis"
            )
        group = groups.get(reference) or {}
        subjects.append(
            {
                "narrative_subject_reference": _reference(
                    "epc-release-subject-", [capture, reference]
                ),
                "capture_file": capture,
                "interface_class": context.get("interface_class"),
                "session_context_reference": reference,
                "session_context_status": context.get("association_status"),
                "session_context_basis": context.get("association_basis"),
                "allocation_transaction_reference": context.get(
                    "allocation_transaction_reference"
                ),
                "allocation_outcome_status": context.get("allocation_outcome_status"),
                "member_transaction_references": _strings(
                    context.get("member_transaction_references")
                ),
                "observation_window": context.get("observation_window"),
                "source_evidence_refs": [
                    item
                    for item in context.get("evidence_refs") or []
                    if isinstance(item, dict)
                ][:MAX_EVIDENCE_REFERENCES],
                "narrative_group_reference": group.get("narrative_group_reference"),
                "narrative_group_basis": group.get("narrative_group_basis"),
                "narrative_group_members": group.get("narrative_group_members") or [],
                "narrative_group_bridge_references": group.get(
                    "narrative_group_bridge_references"
                )
                or [],
                "session_identity_links": [
                    {
                        "reference": link.get("reference"),
                        "peer_session_context_reference": (
                            link.get("target_subject_reference")
                            if link.get("source_subject_reference") == reference
                            else link.get("source_subject_reference")
                        ),
                        "association_status": link.get("association_status"),
                        "association_basis": link.get("association_basis"),
                        "source_frames": _bounded(link.get("source_frames") or []),
                        "limitations": _strings(link.get("limitations")),
                    }
                    for link in peers
                ],
                "endpoint_correspondence_references": [
                    item.get("reference")
                    for item in correspondences
                    if reference
                    in (
                        item.get("source_subject_reference"),
                        item.get("target_subject_reference"),
                    )
                ],
                "bearer_endpoints": endpoints,
                "release_narrative_references": release_references,
                "temporal_limitations": temporal_limitations,
                "source_analysis": {
                    "session_identity": "epc-session-identity",
                    "lifecycle": "epc-bearer-lifecycle",
                },
                "limitations": limitations,
            }
        )
    subjects.sort(key=lambda item: (item["capture_file"], item["session_context_reference"]))
    return subjects


# ---------------------------------------------------------------------------
# Release narratives
# ---------------------------------------------------------------------------
def _stage(
    stage: str,
    evidence_status: str,
    *,
    source_analysis: str,
    source_subject_reference: Any = None,
    transaction_reference: Any = None,
    capture_file: Any = None,
    frame_number: Any = None,
    message_type: Any = None,
    evidence_refs: Any = None,
    association_basis: Any = None,
    limitations: Any = None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "evidence_status": evidence_status,
        "source_analysis": source_analysis,
        "source_subject_reference": (
            source_subject_reference if isinstance(source_subject_reference, str) else None
        ),
        "transaction_reference": (
            transaction_reference if isinstance(transaction_reference, str) else None
        ),
        "capture_file": capture_file if isinstance(capture_file, str) else None,
        "frame_number": _int(frame_number),
        "message_type": message_type if isinstance(message_type, str) else None,
        "evidence_refs": [
            item
            for item in (evidence_refs or [])
            if isinstance(item, dict)
        ][:MAX_EVIDENCE_REFERENCES],
        "association_basis": (
            association_basis if isinstance(association_basis, str) else None
        ),
        "limitations": _strings(limitations),
    }


def _outcome_stage(outcome: Any) -> str:
    if outcome == RELEASE_ACCEPTED:
        return STAGE_RELEASE_OUTCOME_ACCEPTED
    if outcome == RELEASE_REJECTED:
        return STAGE_RELEASE_OUTCOME_REJECTED
    return STAGE_RELEASE_OUTCOME_UNRESOLVED


def _outcome_status(outcome: Any) -> str:
    if outcome == RELEASE_ACCEPTED:
        return STATUS_ACCEPTED
    if outcome == RELEASE_REJECTED:
        return STATUS_REJECTED
    return STATUS_UNRESOLVED


def _binding_index(
    identity: dict[str, Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for binding in identity.get("release_session_bindings") or []:
        if not isinstance(binding, dict):
            continue
        reference = binding.get("source_subject_reference")
        if not isinstance(reference, str):
            continue
        index[(str(binding.get("capture_file")), reference)] = binding
    return index


def _boundary_index(
    lifecycle: dict[str, Any],
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for boundary in lifecycle.get("generation_boundary_evidence") or []:
        if not isinstance(boundary, dict):
            continue
        reference = boundary.get("transaction_reference")
        if not isinstance(reference, str):
            continue
        index[(str(boundary.get("capture_file")), reference)] = boundary
    return index


def _generations_by_boundary(
    lifecycle: dict[str, Any],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Generations whose proved boundary names one release transaction."""
    result: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for subject in lifecycle.get("lifecycle_subjects") or []:
        if not isinstance(subject, dict):
            continue
        boundary = subject.get("generation_boundary")
        if not isinstance(boundary, dict):
            continue
        reference = boundary.get("transaction_reference")
        if not isinstance(reference, str):
            continue
        key = (str(subject.get("capture_file")), reference)
        result.setdefault(key, []).append(subject)
    return result


def _established_candidates(identity: dict[str, Any]) -> list[dict[str, Any]]:
    """Every established closure candidate, keeping competing entries distinct."""
    return [
        candidate
        for candidate in identity.get("generation_closure_candidates") or []
        if isinstance(candidate, dict)
        and candidate.get("association_status") == STATUS_ESTABLISHED
    ]


def _proved_generations(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    context_reference: Any,
    transaction_reference: str,
    capture: str,
    release_outcome: Any,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Generations proved closed for exactly this release and context.

    A generation is admitted only when all of the following hold: the lifecycle
    subject carries a proved boundary naming this release transaction in this
    capture; the identity analysis publishes an ESTABLISHED closure candidate for
    the same context, release and bearer endpoint; and the candidate's endpoint
    identity matches the lifecycle subject's receiving endpoint exactly.
    """
    proved: list[dict[str, Any]] = []
    competing: list[dict[str, Any]] = []
    limitations: list[str] = []
    if not isinstance(context_reference, str):
        return proved, competing, limitations
    if release_outcome != RELEASE_ACCEPTED:
        # The accepted closure basis is an accepted release response. A boundary
        # published beside a non-accepted outcome is a source inconsistency: it
        # is reported, never promoted into a proved closure.
        return proved, competing, [
            "the release outcome is not accepted, so no bearer-generation closure is promoted "
            "even where the lifecycle publishes a generation boundary"
        ]
    matching = [
        candidate
        for candidate in _established_candidates(identity)
        if candidate.get("session_context_reference") == context_reference
        and candidate.get("release_transaction_reference") == transaction_reference
    ]
    for subject in _generations_by_boundary(lifecycle).get(
        (capture, transaction_reference), []
    ):
        endpoint_key = (
            capture,
            str(subject.get("receiving_endpoint_role")),
            str(subject.get("receiving_endpoint_address")),
            _int(subject.get("receiving_endpoint_teid")) or 0,
            _int(subject.get("reviewed_interface_type")) or 0,
        )
        owned = []
        for candidate in matching:
            endpoint = candidate.get("bearer_endpoint")
            if not isinstance(endpoint, dict):
                continue
            candidate_key = (
                str(candidate.get("capture_file")),
                str(endpoint.get("role")),
                str(endpoint.get("address")),
                _int(endpoint.get("teid")) or 0,
                _int(endpoint.get("interface_type")) or 0,
            )
            if candidate_key == endpoint_key:
                owned.append(candidate)
        if len(owned) == 1 and subject.get("generation_state") == "CLOSED_BY_ACCEPTED_RELEASE":
            boundary = subject.get("generation_boundary") or {}
            proved.append(
                {
                    "generation_reference": subject.get("generation_reference"),
                    "receiving_endpoint_role": subject.get("receiving_endpoint_role"),
                    "receiving_endpoint_address": subject.get("receiving_endpoint_address"),
                    "receiving_endpoint_teid": subject.get("receiving_endpoint_teid"),
                    "reviewed_interface_type": subject.get("reviewed_interface_type"),
                    "generation_state": subject.get("generation_state"),
                    "generation_boundary_basis": boundary.get("basis"),
                    "release_request_frame": boundary.get("release_request_frame"),
                    "release_confirmation_frame": boundary.get("release_confirmation_frame"),
                    "release_effective_frame_proven": bool(
                        boundary.get("release_effective_frame_proven")
                    ),
                    "closure_candidate_reference": owned[0].get(
                        "generation_closure_candidate_reference"
                    ),
                    "closure_candidate_basis": owned[0].get("association_basis"),
                }
            )
        elif len(owned) > 1:
            competing.append(
                {
                    "generation_reference": subject.get("generation_reference"),
                    "receiving_endpoint_role": subject.get("receiving_endpoint_role"),
                    "candidate_references": sorted(
                        str(item.get("generation_closure_candidate_reference"))
                        for item in owned
                    ),
                }
            )
            limitations.append(
                "more than one established closure candidate claims this generation's endpoint, "
                "so no single bearer generation is selected"
            )
        else:
            limitations.append(
                "the lifecycle publishes a generation boundary for this release, but no "
                "established closure candidate ties it to an independently proved bearer endpoint"
            )
    proved.sort(key=lambda item: (str(item.get("receiving_endpoint_role")), str(item.get("generation_reference"))))
    return proved, competing, limitations


def build_release_narratives(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    subjects: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """One narrative per release transaction, keyed by capture and transaction."""
    subject_by_context = {
        subject["session_context_reference"]: subject for subject in subjects
    }
    bindings = _binding_index(identity)
    boundaries = _boundary_index(lifecycle)
    keys = sorted(set(bindings) | set(boundaries))
    narratives: list[dict[str, Any]] = []
    unbound: list[dict[str, Any]] = []
    for capture, transaction_reference in keys:
        binding = bindings.get((capture, transaction_reference))
        boundary = boundaries.get((capture, transaction_reference))
        context_reference = None
        if binding is not None and isinstance(binding.get("target_subject_reference"), str):
            context_reference = binding["target_subject_reference"]
        subject = subject_by_context.get(context_reference) if context_reference else None
        if context_reference and subject is None:
            unbound.append(
                {
                    "kind": "release_binding_targets_an_unpublished_session_context",
                    "capture_file": capture,
                    "transaction_reference": transaction_reference,
                    "session_context_reference": context_reference,
                    "limitations": [
                        "the release binding names a session context that the supplied identity "
                        "analysis does not publish, so no narrative subject is attached"
                    ],
                }
            )
        request_frame = None
        confirmation_frame = None
        if isinstance(binding, dict):
            frames = [item for item in binding.get("source_frames") or [] if isinstance(item, int)]
            if frames:
                request_frame = frames[0]
                confirmation_frame = frames[1] if len(frames) > 1 else None
            window = binding.get("observation_window")
            if isinstance(window, dict):
                request_frame = _int(window.get("start_frame")) or request_frame
                confirmation_frame = _int(window.get("end_frame")) or confirmation_frame
        if isinstance(boundary, dict):
            request_frame = _int(boundary.get("request_frame")) or request_frame
            confirmation_frame = _int(boundary.get("response_frame")) or confirmation_frame
        outcome = None
        outcome_basis = None
        binding_status = STATUS_INSUFFICIENT
        binding_basis = None
        binding_limitations: list[str] = []
        if isinstance(binding, dict):
            outcome = binding.get("release_outcome_status")
            outcome_basis = binding.get("release_outcome_basis")
            binding_status = binding.get("association_status")
            binding_basis = binding.get("association_basis")
            binding_limitations = _strings(binding.get("limitations"))
        elif isinstance(boundary, dict):
            outcome = boundary.get("release_outcome")
            outcome_basis = boundary.get("release_outcome_basis")
            binding_limitations.append(
                "the identity analysis publishes no release-to-session binding for this release; "
                "only the lifecycle boundary evidence is available"
            )
        proved, competing, generation_limitations = _proved_generations(
            identity, lifecycle, context_reference, transaction_reference, capture, outcome
        )
        closure_status = (
            STATUS_ESTABLISHED
            if proved and not competing
            else STATUS_AMBIGUOUS
            if competing
            else STATUS_NOT_ESTABLISHED
        )
        stages: list[dict[str, Any]] = []
        allocation_reference = subject.get("allocation_transaction_reference") if subject else None
        allocation_status = subject.get("allocation_outcome_status") if subject else None
        context_evidence = (
            (subject.get("source_evidence_refs") if subject else None) or []
        )
        request_anchor = _ref_for_message(context_evidence, "Create Session Request")
        response_anchor = _ref_for_message(context_evidence, "Create Session Response")
        stages.append(
            _stage(
                STAGE_ALLOCATION_OBSERVED,
                STATUS_OBSERVED if subject else STATUS_INSUFFICIENT,
                source_analysis="epc-session-identity",
                source_subject_reference=context_reference,
                transaction_reference=allocation_reference,
                capture_file=capture,
                frame_number=(request_anchor or {}).get("frame_number"),
                message_type="Create Session Request" if request_anchor else None,
                evidence_refs=[request_anchor] if request_anchor else [],
                association_basis=(
                    subject.get("session_context_basis") if subject else None
                ),
                limitations=(
                    []
                    if subject
                    else [
                        "no published hop-local session context backs this release, so no "
                        "allocation anchor is available"
                    ]
                ),
            )
        )
        stages.append(
            _stage(
                STAGE_ALLOCATION_ACCEPTED,
                (
                    STATUS_ACCEPTED
                    if allocation_status == STATUS_ACCEPTED
                    else STATUS_NOT_ESTABLISHED
                )
                if subject
                else STATUS_INSUFFICIENT,
                source_analysis="epc-session-identity",
                source_subject_reference=context_reference,
                transaction_reference=allocation_reference,
                capture_file=capture,
                frame_number=(response_anchor or {}).get("frame_number"),
                message_type="Create Session Response" if response_anchor else None,
                evidence_refs=[response_anchor] if response_anchor else [],
                association_basis=allocation_status,
                limitations=(
                    []
                    if allocation_status == STATUS_ACCEPTED
                    else [
                        "the owning context publishes no accepted allocation outcome, so the "
                        "allocation is not accepted in this narrative"
                    ]
                ),
            )
        )
        stages.append(
            _stage(
                STAGE_SESSION_CONTEXT_ESTABLISHED,
                (
                    STATUS_ESTABLISHED
                    if subject and subject.get("session_context_status") == STATUS_ESTABLISHED
                    else STATUS_NOT_ESTABLISHED
                )
                if subject
                else STATUS_INSUFFICIENT,
                source_analysis="epc-session-identity",
                source_subject_reference=context_reference,
                transaction_reference=allocation_reference,
                capture_file=capture,
                frame_number=(response_anchor or {}).get("frame_number"),
                message_type="Create Session Response" if response_anchor else None,
                evidence_refs=[response_anchor] if response_anchor else [],
                association_basis=(
                    subject.get("session_context_basis") if subject else None
                ),
                limitations=(
                    []
                    if subject and subject.get("session_context_status") == STATUS_ESTABLISHED
                    else ["the hop-local session context is not established"]
                ),
            )
        )
        established_endpoints = [
            item
            for item in ((subject or {}).get("bearer_endpoints") or [])
            if item.get("association_status") == STATUS_ESTABLISHED
        ]
        stages.append(
            _stage(
                STAGE_BEARER_ASSOCIATION_ESTABLISHED,
                STATUS_ESTABLISHED if established_endpoints else STATUS_NOT_ESTABLISHED,
                source_analysis="epc-session-identity",
                source_subject_reference=context_reference,
                transaction_reference=allocation_reference,
                capture_file=capture,
                frame_number=(
                    (established_endpoints[0].get("source_frames") or [None])[0]
                    if established_endpoints
                    else None
                ),
                evidence_refs=[
                    _evidence_ref("GTPv2-C", frame, None)
                    for frame in (established_endpoints[0].get("source_frames") or [])
                ]
                if established_endpoints
                else [],
                association_basis=(
                    established_endpoints[0].get("association_basis")
                    if established_endpoints
                    else "no_established_session_to_generation_relationship"
                ),
                limitations=(
                    []
                    if established_endpoints
                    else [
                        "no established session-to-generation relationship exists for this "
                        "context, so no bearer association is claimed"
                    ]
                ),
            )
        )
        stages.append(
            _stage(
                STAGE_RELEASE_REQUEST_OBSERVED,
                STATUS_OBSERVED if request_frame is not None else STATUS_INSUFFICIENT,
                source_analysis="epc-session-identity",
                source_subject_reference=transaction_reference,
                transaction_reference=transaction_reference,
                capture_file=capture,
                frame_number=request_frame,
                message_type="Delete Session Request" if request_frame is not None else None,
                evidence_refs=(
                    [_evidence_ref("GTPv2-C", request_frame, "Delete Session Request")]
                    if request_frame is not None
                    else []
                ),
                association_basis=(
                    "correlated_delete_session_request" if request_frame is not None else None
                ),
                limitations=(
                    []
                    if request_frame is not None
                    else ["no release request frame is published for this transaction"]
                ),
            )
        )
        stages.append(
            _stage(
                _outcome_stage(outcome),
                _outcome_status(outcome),
                source_analysis="epc-session-identity",
                source_subject_reference=transaction_reference,
                transaction_reference=transaction_reference,
                capture_file=capture,
                frame_number=confirmation_frame,
                message_type=(
                    "Delete Session Response" if confirmation_frame is not None else None
                ),
                evidence_refs=(
                    [_evidence_ref("GTPv2-C", confirmation_frame, "Delete Session Response")]
                    if confirmation_frame is not None
                    else []
                ),
                association_basis=outcome_basis,
                limitations=(
                    []
                    if outcome in (RELEASE_ACCEPTED, RELEASE_REJECTED)
                    else [
                        "no readable message-scope Cause backs this release, so its outcome is "
                        "unresolved"
                    ]
                ),
            )
        )
        stages.append(
            _stage(
                STAGE_BINDING_ESTABLISHED
                if binding_status == STATUS_ESTABLISHED
                else STAGE_BINDING_NOT_ESTABLISHED,
                (
                    STATUS_ESTABLISHED
                    if binding_status == STATUS_ESTABLISHED
                    else STATUS_NOT_ESTABLISHED
                ),
                source_analysis="epc-session-identity",
                source_subject_reference=transaction_reference,
                transaction_reference=transaction_reference,
                capture_file=capture,
                frame_number=request_frame,
                message_type="Delete Session Request" if request_frame is not None else None,
                evidence_refs=(
                    [_evidence_ref("GTPv2-C", request_frame, "Delete Session Request")]
                    if request_frame is not None
                    else []
                ),
                association_basis=binding_basis,
                limitations=binding_limitations,
            )
        )
        stages.append(
            _stage(
                STAGE_CLOSURE_ESTABLISHED
                if closure_status == STATUS_ESTABLISHED
                else STAGE_CLOSURE_NOT_ESTABLISHED,
                closure_status,
                source_analysis="epc-bearer-lifecycle",
                source_subject_reference=(
                    proved[0].get("generation_reference") if proved else context_reference
                ),
                transaction_reference=transaction_reference,
                capture_file=capture,
                frame_number=confirmation_frame,
                message_type=(
                    "Delete Session Response" if confirmation_frame is not None else None
                ),
                evidence_refs=[
                    _evidence_ref("GTPv2-C", frame, None)
                    for frame in (request_frame, confirmation_frame)
                    if frame is not None
                ],
                association_basis=(
                    proved[0].get("generation_boundary_basis")
                    if proved
                    else "no_independently_proved_bearer_generation_closure"
                ),
                limitations=generation_limitations,
            )
        )
        stages.append(
            _stage(
                STAGE_EFFECTIVE_INSTANT_UNPROVED,
                STATUS_NOT_ESTABLISHED,
                source_analysis="epc-bearer-lifecycle",
                source_subject_reference=transaction_reference,
                transaction_reference=transaction_reference,
                capture_file=capture,
                frame_number=confirmation_frame,
                message_type=(
                    "Delete Session Response" if confirmation_frame is not None else None
                ),
                association_basis="accepted_release_response_is_not_a_forwarding_stop_instant",
                limitations=[
                    "the accepted model proves a control-plane outcome and, at most, a reviewed "
                    "bearer-generation boundary; it never proves the instant at which "
                    "user-plane forwarding stopped"
                ],
            )
        )
        narrative_limitations = list(generation_limitations)
        if isinstance(binding, dict) and binding.get("competing_candidates"):
            narrative_limitations.append(
                "the release request addresses several hop-local contexts, so it binds to none "
                "of them"
            )
        if subject is None:
            narrative_limitations.append(
                "no narrative subject is attached: the release resolves to no published context"
            )
        narratives.append(
            {
                "release_narrative_reference": _reference(
                    "epc-release-narrative-", [capture, transaction_reference]
                ),
                "capture_file": capture,
                "narrative_subject_reference": (
                    subject.get("narrative_subject_reference") if subject else None
                ),
                "session_context_reference": context_reference,
                "interface_class": subject.get("interface_class") if subject else None,
                "narrative_group_reference": (
                    subject.get("narrative_group_reference") if subject else None
                ),
                "release_transaction_reference": transaction_reference,
                "release_request_frame": request_frame,
                "release_confirmation_frame": confirmation_frame,
                "release_outcome_status": outcome if outcome is not None else RELEASE_UNRESOLVED,
                "release_outcome_basis": outcome_basis,
                "release_session_binding_status": binding_status,
                "release_session_binding_basis": binding_basis,
                "generation_closure_status": closure_status,
                "generation_closure_basis": (
                    proved[0].get("generation_boundary_basis")
                    if proved
                    else "no_independently_proved_bearer_generation_closure"
                ),
                "release_effective_frame_proven": False,
                "stages": stages,
                "proved_generations": proved,
                "competing_generations": competing,
                "temporal_observation_references": [],
                "provenance_status": "NOT_VALIDATED",
                "limitations": narrative_limitations,
            }
        )
    narratives.sort(
        key=lambda item: (
            item["capture_file"],
            item["release_request_frame"] or 0,
            item["release_transaction_reference"],
        )
    )
    return narratives, unbound


# ---------------------------------------------------------------------------
# Source-reference validation against the supplied capture
# ---------------------------------------------------------------------------
def validate_source_references(
    narratives: list[dict[str, Any]],
    gtpv2_events: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Check that published frame anchors still exist in the supplied capture.

    The narrative never repairs a source document. When a published anchor does
    not correspond to an observed message of the supplied capture, the
    inconsistency is published and the narrative's provenance is downgraded.
    """
    unbound: list[dict[str, Any]] = []
    if gtpv2_events is None:
        for narrative in narratives:
            narrative["provenance_status"] = "NOT_VALIDATED"
        return narratives, unbound
    observed: dict[tuple[str, int], set[str]] = {}
    for event in gtpv2_events:
        if not isinstance(event, dict):
            continue
        frame = _int(event.get("frame_number"))
        capture = event.get("capture_file")
        message = event.get("message_type")
        if frame is None or not isinstance(capture, str):
            continue
        observed.setdefault((capture, frame), set()).add(str(message))
    for narrative in narratives:
        capture = narrative["capture_file"]
        checks: list[str] = []
        consistent = True
        for frame, expected in (
            (narrative.get("release_request_frame"), "Delete Session Request"),
            (narrative.get("release_confirmation_frame"), "Delete Session Response"),
        ):
            if frame is None:
                continue
            messages = observed.get((capture, frame))
            if messages is None:
                consistent = False
                checks.append(
                    f"frame {frame} is published as {expected} but no message at that frame is "
                    "present in the supplied capture"
                )
            elif expected not in messages:
                consistent = False
                checks.append(
                    f"frame {frame} is published as {expected} but the supplied capture carries "
                    f"{', '.join(sorted(messages))}"
                )
        if consistent:
            narrative["provenance_status"] = "VALIDATED"
        else:
            narrative["provenance_status"] = "INCONSISTENT"
            narrative["limitations"] = list(narrative["limitations"]) + [
                "a published frame anchor does not correspond to the supplied capture; the "
                "source claim stays visible but is not promoted here"
            ]
            unbound.append(
                {
                    "kind": "source_reference_not_observed_in_supplied_capture",
                    "capture_file": capture,
                    "transaction_reference": narrative["release_transaction_reference"],
                    "checks": checks[:MAX_LIST_ITEMS],
                    "limitations": [
                        "the narrative refuses to promote an anchor it cannot re-observe in the "
                        "supplied capture"
                    ],
                }
            )
    return narratives, unbound


# ---------------------------------------------------------------------------
# Temporal evidence
# ---------------------------------------------------------------------------
def _gtpu_index(
    gtpu_events: list[dict[str, Any]] | None,
) -> dict[tuple[str, str, str, int], list[dict[str, Any]]]:
    """Frame-ordered G-PDU events keyed by the accepted directed-stream tuple.

    The key is exactly the one the accepted S1-U and lifecycle capabilities use:
    capture, outer source, outer destination and header TEID. End Marker, Error
    Indication and Echo messages keep their own message type and are never counted
    as G-PDUs.
    """
    grouped: dict[tuple[str, str, str, int], list[dict[str, Any]]] = {}
    for event in gtpu_events or []:
        if not isinstance(event, dict):
            continue
        header = event.get("header")
        outer = event.get("outer")
        frame = _int(event.get("frame_number"))
        if not isinstance(header, dict) or not isinstance(outer, dict) or frame is None:
            continue
        if header.get("message_type") != "G-PDU":
            continue
        source = outer.get("source_address")
        destination = outer.get("destination_address")
        teid = _int(header.get("teid"))
        if not isinstance(source, str) or not isinstance(destination, str) or teid is None:
            continue
        grouped.setdefault(
            (str(event.get("capture_file")), source, destination, teid), []
        ).append(
            {
                "frame_number": frame,
                "payload_octets": _int(header.get("message_length")) or 0,
            }
        )
    for key in grouped:
        grouped[key].sort(key=lambda item: item["frame_number"])
    return grouped


def _partition_totals(events: list[dict[str, Any]]) -> dict[str, Any]:
    frames = [item["frame_number"] for item in events]
    return {
        "g_pdu_count": len(events),
        "payload_octets": sum(item["payload_octets"] for item in events),
        "first_frame": min(frames) if frames else None,
        "last_frame": max(frames) if frames else None,
    }


def build_temporal_observations(
    narratives: list[dict[str, Any]],
    s1u: dict[str, Any] | None,
    gtpu_events: list[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any], list[str]]:
    """Frame-aware temporal evidence per release, without inventing placement."""
    if s1u is None:
        return [], {
            "frame_level_evidence_supplied": False,
            "observed_g_pdu_event_count": 0,
            "assigned_to_release_window_count": 0,
            "unassigned_g_pdu_event_count": 0,
            "duplicate_assignment_count": 0,
            "conserved": True,
        }, []
    streams = [item for item in s1u.get("stream_observations") or [] if isinstance(item, dict)]
    frame_index = _gtpu_index(gtpu_events)
    observations: list[dict[str, Any]] = []
    limitations: list[str] = []
    assigned_frames: dict[tuple[str, int], str] = {}
    duplicates = 0
    total_events = sum(len(items) for items in frame_index.values())
    for narrative in narratives:
        generations = narrative.get("proved_generations") or []
        endpoints = {
            (
                str(item.get("receiving_endpoint_role")),
                str(item.get("receiving_endpoint_address")),
                _int(item.get("receiving_endpoint_teid")) or 0,
            ): item
            for item in generations
        }
        if not endpoints:
            continue
        request_frame = _int(narrative.get("release_request_frame"))
        confirmation_frame = _int(narrative.get("release_confirmation_frame"))
        for stream in streams:
            role = stream.get("matched_endpoint_role")
            key = (
                str(role),
                str(stream.get("outer_destination")),
                _int(stream.get("teid")) or 0,
            )
            generation = endpoints.get(key)
            if generation is None:
                continue
            stream_key = (
                str(stream.get("capture_file")),
                str(stream.get("outer_source")),
                str(stream.get("outer_destination")),
                _int(stream.get("teid")) or 0,
            )
            aggregate_count = _int(stream.get("observed_g_pdu_packet_count")) or 0
            aggregate_octets = _int(stream.get("observed_payload_byte_count")) or 0
            events = frame_index.get(stream_key) or []
            reference = _reference(
                "epc-release-temporal-",
                [
                    narrative["release_narrative_reference"],
                    stream.get("stream_reference"),
                ],
            )
            record: dict[str, Any] = {
                "temporal_observation_reference": reference,
                "release_narrative_reference": narrative["release_narrative_reference"],
                "capture_file": narrative["capture_file"],
                "stream_reference": stream.get("stream_reference"),
                "generation_reference": generation.get("generation_reference"),
                "receiving_endpoint_role": role,
                "direction": stream.get("direction"),
                "association_status": stream.get("association_status"),
                "observed_g_pdu_count": aggregate_count,
                "observed_payload_octets": aggregate_octets,
                "first_observed_frame": stream.get("first_frame"),
                "last_observed_frame": stream.get("last_frame"),
                "release_request_frame": request_frame,
                "release_confirmation_frame": confirmation_frame,
                "partitions": None,
                "partition_basis": PARTITION_BASIS_AGGREGATE,
                "temporal_placement_status": TEMPORAL_NOT_ESTABLISHED,
                "partition_conserved": None,
                "limitations": [],
            }
            if events and request_frame is not None and confirmation_frame is not None:
                before: list[dict[str, Any]] = []
                pending: list[dict[str, Any]] = []
                after: list[dict[str, Any]] = []
                for event in events:
                    frame = event["frame_number"]
                    if frame < request_frame:
                        before.append(event)
                    elif frame <= confirmation_frame:
                        pending.append(event)
                    else:
                        after.append(event)
                partitions = {
                    PARTITION_BEFORE: _partition_totals(before),
                    PARTITION_PENDING: _partition_totals(pending),
                    PARTITION_AFTER: _partition_totals(after),
                }
                counted = sum(item["g_pdu_count"] for item in partitions.values())
                octets = sum(item["payload_octets"] for item in partitions.values())
                record["partitions"] = partitions
                record["partition_basis"] = PARTITION_BASIS_FRAMES
                record["temporal_placement_status"] = TEMPORAL_ESTABLISHED
                record["partition_conserved"] = (
                    counted == aggregate_count and octets == aggregate_octets
                )
                if not record["partition_conserved"]:
                    record["limitations"].append(
                        "frame-level G-PDU events do not reproduce the accepted aggregate stream "
                        "count; the aggregate stays authoritative and the frame-level partition "
                        "is published as a separate observation"
                    )
                for event in events:
                    key = (str(stream.get("capture_file")), event["frame_number"])
                    owner = assigned_frames.get(key)
                    if owner is not None and owner != reference:
                        duplicates += 1
                        continue
                    assigned_frames[key] = reference
                record["limitations"].append(
                    "the pending-release interval is an observation window, not evidence that "
                    "forwarding stopped; the confirmation frame is not the traffic-stop frame"
                )
            else:
                record["limitations"].append(
                    "TEMPORAL_PLACEMENT_NOT_ESTABLISHED: only aggregate stream evidence is "
                    "available, so no packet or octet count is divided across time windows"
                )
                if request_frame is None or confirmation_frame is None:
                    record["limitations"].append(
                        "the release request or its confirmation frame is unavailable, so no "
                        "release window can be constructed"
                    )
            observations.append(record)
            narrative["temporal_observation_references"] = list(
                narrative["temporal_observation_references"]
            ) + [reference]
    observations.sort(
        key=lambda item: (
            item["capture_file"],
            item["release_request_frame"] or 0,
            str(item["receiving_endpoint_role"]),
            str(item["stream_reference"]),
        )
    )
    if duplicates:
        limitations.append(
            "a G-PDU frame was claimed by more than one release narrative; the duplicate "
            "assignment was not counted twice"
        )
    accounting = {
        "frame_level_evidence_supplied": bool(frame_index),
        "observed_g_pdu_event_count": total_events,
        "assigned_to_release_window_count": len(assigned_frames),
        "unassigned_g_pdu_event_count": max(0, total_events - len(assigned_frames)),
        "duplicate_assignment_count": duplicates,
        "conserved": duplicates == 0 and len(assigned_frames) <= total_events,
    }
    return observations, accounting, limitations


# ---------------------------------------------------------------------------
# Ambiguity and document assembly
# ---------------------------------------------------------------------------
def _ambiguous_records(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narratives: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source, items in (
        ("epc-session-identity", identity.get("ambiguous_associations")),
        ("epc-bearer-lifecycle", lifecycle.get("ambiguous_associations")),
    ):
        for item in items or []:
            if not isinstance(item, dict):
                continue
            records.append(
                {
                    "source_analysis": source,
                    "relationship_type": item.get("relationship_type"),
                    "association_basis": item.get("association_basis"),
                    "competing_candidates": _strings(item.get("competing_candidates")),
                }
            )
    for narrative in narratives:
        if narrative.get("generation_closure_status") == STATUS_AMBIGUOUS:
            records.append(
                {
                    "source_analysis": "epc-release-narrative",
                    "relationship_type": "RELEASE_TO_BEARER_GENERATION",
                    "association_basis": "several_generations_or_candidates_compete_for_one_release",
                    "competing_candidates": sorted(
                        str(item.get("generation_reference"))
                        for item in narrative.get("competing_generations") or []
                    ),
                }
            )
    records.sort(
        key=lambda item: (
            str(item.get("source_analysis")),
            str(item.get("relationship_type")),
            str(item.get("association_basis")),
        )
    )
    return records


def analyze(
    identity: dict[str, Any] | None,
    lifecycle: dict[str, Any] | None,
    s1u: dict[str, Any] | None = None,
    gtpv2_events: list[dict[str, Any]] | None = None,
    gtpu_events: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the bounded EPC release narrative document."""
    identity_document = _source_document(identity, "EPC session-identity analysis", True)
    lifecycle_document = _source_document(lifecycle, "EPC bearer-lifecycle analysis", True)
    s1u_document = _source_document(s1u, "EPC S1-U observation", False)
    assert identity_document is not None and lifecycle_document is not None

    completeness = source_completeness(identity_document, lifecycle_document, s1u_document)
    subjects = build_narrative_subjects(identity_document, lifecycle_document)
    narratives, binding_unbound = build_release_narratives(
        identity_document, lifecycle_document, subjects
    )
    narratives, reference_unbound = validate_source_references(narratives, gtpv2_events)
    observations, temporal_accounting, temporal_limitations = build_temporal_observations(
        narratives, s1u_document, gtpu_events
    )
    ambiguous = _ambiguous_records(identity_document, lifecycle_document, narratives)

    unbound: list[dict[str, Any]] = list(binding_unbound) + list(reference_unbound)
    for item in identity_document.get("unbound_evidence") or []:
        if isinstance(item, dict):
            unbound.append(
                {
                    "kind": item.get("kind"),
                    "capture_file": item.get("capture_file"),
                    "transaction_reference": item.get("transaction_reference"),
                    "limitations": _strings(item.get("limitations")),
                }
            )
    unbound.sort(
        key=lambda item: (
            str(item.get("kind")),
            str(item.get("capture_file")),
            str(item.get("transaction_reference")),
        )
    )

    limitations: list[str] = []
    if completeness.get("limitation"):
        limitations.append(str(completeness["limitation"]))
    if gtpv2_events is None:
        limitations.append(
            "no detailed GTPv2-C events were supplied, so published frame anchors were not "
            "re-validated against a capture"
        )
    if s1u_document is None:
        limitations.append(
            "no EPC S1-U observation was supplied, so no user-plane temporal evidence is reported"
        )
    elif gtpu_events is None:
        limitations.append(
            "no detailed GTP-U events were supplied, so every temporal placement stays "
            "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"
        )
    limitations.extend(temporal_limitations)
    for narrative in narratives:
        if narrative.get("provenance_status") == "INCONSISTENT":
            limitations.append(
                "at least one release narrative carries a frame anchor that the supplied "
                "capture does not reproduce"
            )
            break
    if any(
        narrative.get("release_outcome_status") == RELEASE_UNRESOLVED for narrative in narratives
    ):
        limitations.append(
            "at least one release publishes no readable message-scope Cause, so its outcome "
            "stays unresolved"
        )
    if any(
        narrative.get("generation_closure_status") != STATUS_ESTABLISHED
        for narrative in narratives
    ):
        limitations.append(
            "at least one release has no independently proved bearer-generation closure; an "
            "identity deficiency is never reported as a release failure"
        )
    limitations.append(
        "this capability reports the accepted evidence chain only; it selects no first abnormal "
        "boundary, no root cause and no network-function liability"
    )

    additional: list[str] = []
    if not temporal_accounting.get("frame_level_evidence_supplied"):
        additional.append(
            "detailed GTP-U frame events are required to place individual G-PDUs before, inside "
            "or after a release window"
        )
    if not completeness.get("exhaustive_coverage_proven"):
        additional.append(
            "complete source candidate collections are required before any exhaustive release or "
            "generation coverage is claimed"
        )
    for narrative in narratives:
        if narrative.get("release_session_binding_status") != STATUS_ESTABLISHED:
            additional.append(
                "a release request that addresses exactly one established hop-local context is "
                "required to bind a release to a session context"
            )
            break

    result = {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": provenance or {},
        "analysis_scope": {
            "capability": (
                "bounded EPC session-level release narrative and temporal evidence reporting"
            ),
            "stage_labels": list(STAGE_LABELS),
            "evidence_statuses": list(EVIDENCE_STATUSES),
            "subject_rule": (
                "the narrative subject is a published hop-local session context; an established "
                "cross-interface identity link yields a labelled narrative group and never one "
                "global PDN session"
            ),
            "release_rule": (
                "an accepted outcome, an established release-to-session binding and a proved "
                "bearer-generation closure are three separate facts and are never collapsed into "
                "one verdict"
            ),
            "generation_rule": (
                "a generation appears only when the lifecycle publishes a proved boundary naming "
                "the same release and the identity analysis publishes an established closure "
                "candidate for the same context, release and bearer endpoint"
            ),
            "temporal_rule": (
                "the pending-release interval is an observation window, the confirmation frame is "
                "not the forwarding-stop instant, an aggregate stream count is never divided "
                "across windows, and a frame is counted in at most one partition"
            ),
            "completeness_rule": (
                "no exhaustive release or generation coverage is claimed while a material source "
                "collection is truncated or its completeness metadata is invalid"
            ),
        },
        "source_completeness": completeness,
        "narrative_subjects": subjects[:MAX_SUBJECTS],
        "narrative_subject_count": len(subjects),
        "narrative_subjects_omitted": max(0, len(subjects) - MAX_SUBJECTS),
        "release_narratives": narratives[:MAX_SUBJECTS],
        "release_narrative_count": len(narratives),
        "release_narratives_omitted": max(0, len(narratives) - MAX_SUBJECTS),
        "temporal_observations": observations[:MAX_SUBJECTS],
        "temporal_observation_count": len(observations),
        "temporal_observations_omitted": max(0, len(observations) - MAX_SUBJECTS),
        "temporal_accounting": temporal_accounting,
        "ambiguous_associations": ambiguous[:MAX_SUBJECTS],
        "ambiguous_association_count": len(ambiguous),
        "unbound_evidence": unbound[:MAX_SUBJECTS],
        "unbound_evidence_count": len(unbound),
        "evidence_limitations": limitations[:MAX_LIST_ITEMS],
        "additional_evidence_needed": list(dict.fromkeys(additional))[:MAX_LIST_ITEMS],
        "not_confirmed": list(NARRATIVE_NOT_CONFIRMED),
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": (
            "a release narrative is not an abnormal failure boundary; this capability selects no "
            "first abnormal boundary and no root cause"
        ),
    }
    return result


__all__ = [
    "ANALYSIS_NAME",
    "ANALYSIS_VERSION",
    "DOMAIN_NAME",
    "DOMAIN_VERSION",
    "EVIDENCE_STATUSES",
    "EXIT_MALFORMED_INPUT",
    "EXIT_NO_SUBJECTS",
    "EXIT_OUTPUT_FAILURE",
    "InputError",
    "NarrativeInputError",
    "STAGE_LABELS",
    "analyze",
    "build_narrative_subjects",
    "build_release_narratives",
    "build_temporal_observations",
    "read_json",
    "read_jsonl",
    "safe_name",
    "source_completeness",
    "validate_source_references",
]
