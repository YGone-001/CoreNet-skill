"""Bounded EPC cross-artifact evidence-chain integrity and audit ledger.

This Domain capability audits already-published EPC analysis artifacts. It
consumes the accepted session-identity, bearer-lifecycle and release-narrative
documents plus, optionally, the accepted S1-U observation, the detailed GTPv2-C
events and the detailed GTP-U events. It never decodes a capture, never rebuilds
a transaction correlation, never re-derives session identity, never changes a
packet or octet attribution and never publishes subscriber identity.

The ledger distinguishes three dimensions that are never collapsed into one
Boolean:

* presence — does the referenced record exist in the supplied artifact?
* consistency — does that record agree with the referring record about capture,
  relationship type, endpoint, transaction, direction, identity and frame?
* proof sufficiency — are the complete candidate set and the required chain
  available to justify the published association or conclusion?

The audit examines the accepted evidence; it never generates new identity
evidence, never repairs a source document, never chooses between competing
identities and never promotes an unsupported relationship into an established
one. A source document may stay valuable while one of its relationships fails
audit, and an absent optional artifact is reported as a limitation rather than
as an inconsistency.
"""

from __future__ import annotations

import hashlib
from typing import Any

from epc_bearer_lifecycle_model import (
    MAX_LIST_ITEMS,
    MAX_SUBJECTS,
    InputError,
    _int,
    read_json,
    read_jsonl,
    safe_name,
)

DOMAIN_NAME = "epc-procedures"
DOMAIN_VERSION = "0.8.0"
ANALYSIS_NAME = "epc-evidence-audit"
ANALYSIS_VERSION = "1.0.0"

EXIT_MALFORMED_INPUT = 5
EXIT_NO_SUBJECTS = 6
EXIT_OUTPUT_FAILURE = 7

MAX_AUDIT_RECORDS = 1024
MAX_EVIDENCE_REFERENCES = 32

# ---------------------------------------------------------------------------
# Closed vocabularies
# ---------------------------------------------------------------------------
CATEGORY_SOURCE_ARTIFACT = "SOURCE_ARTIFACT"
CATEGORY_REFERENCE_INTEGRITY = "REFERENCE_INTEGRITY"
CATEGORY_CAPTURE_SCOPE = "CAPTURE_SCOPE"
CATEGORY_TRANSACTION_ANCHOR = "TRANSACTION_ANCHOR"
CATEGORY_SESSION_CONTEXT_LINK = "SESSION_CONTEXT_LINK"
CATEGORY_CROSS_INTERFACE_BRIDGE = "CROSS_INTERFACE_BRIDGE"
CATEGORY_RELEASE_SESSION_BINDING = "RELEASE_SESSION_BINDING"
CATEGORY_SESSION_GENERATION_LINK = "SESSION_GENERATION_LINK"
CATEGORY_GENERATION_CLOSURE = "GENERATION_CLOSURE"
CATEGORY_GENERATION_STREAM_ATTRIBUTION = "GENERATION_STREAM_ATTRIBUTION"
CATEGORY_RELEASE_NARRATIVE_STAGE = "RELEASE_NARRATIVE_STAGE"
CATEGORY_TEMPORAL_FRAME_PARTITION = "TEMPORAL_FRAME_PARTITION"
CATEGORY_ACCOUNTING_CONSERVATION = "ACCOUNTING_CONSERVATION"

AUDIT_CATEGORIES = (
    CATEGORY_SOURCE_ARTIFACT,
    CATEGORY_REFERENCE_INTEGRITY,
    CATEGORY_CAPTURE_SCOPE,
    CATEGORY_TRANSACTION_ANCHOR,
    CATEGORY_SESSION_CONTEXT_LINK,
    CATEGORY_CROSS_INTERFACE_BRIDGE,
    CATEGORY_RELEASE_SESSION_BINDING,
    CATEGORY_SESSION_GENERATION_LINK,
    CATEGORY_GENERATION_CLOSURE,
    CATEGORY_GENERATION_STREAM_ATTRIBUTION,
    CATEGORY_RELEASE_NARRATIVE_STAGE,
    CATEGORY_TEMPORAL_FRAME_PARTITION,
    CATEGORY_ACCOUNTING_CONSERVATION,
)

STATUS_VERIFIED = "VERIFIED_CONSISTENT"
STATUS_INCONSISTENT = "INCONSISTENT"
STATUS_AMBIGUOUS = "AMBIGUOUS"
STATUS_TRUNCATED = "SOURCE_TRUNCATED"
STATUS_METADATA_INVALID = "SOURCE_METADATA_INVALID"
STATUS_NOT_VERIFIABLE = "NOT_INDEPENDENTLY_VERIFIABLE"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

AUDIT_STATUSES = (
    STATUS_VERIFIED,
    STATUS_INCONSISTENT,
    STATUS_AMBIGUOUS,
    STATUS_TRUNCATED,
    STATUS_METADATA_INVALID,
    STATUS_NOT_VERIFIABLE,
    STATUS_NOT_APPLICABLE,
)

COMPLETE_COLLECTION = "COMPLETE"
COMPLETENESS_TRUNCATED = "SOURCE_TRUNCATED"
COMPLETENESS_METADATA_INVALID = "SOURCE_METADATA_INVALID"
COMPLETENESS_NOT_SUPPLIED = "NOT_SUPPLIED"
COMPLETENESS_NOT_APPLICABLE = "NOT_APPLICABLE"

COMPLETENESS_STATUSES = (
    COMPLETE_COLLECTION,
    COMPLETENESS_TRUNCATED,
    COMPLETENESS_METADATA_INVALID,
    COMPLETENESS_NOT_SUPPLIED,
    COMPLETENESS_NOT_APPLICABLE,
)

CONDITION_MATCHES = "COUNT_PRESENT_AND_MATCHES"
CONDITION_MISSING = "COUNT_MISSING"
CONDITION_INVALID = "COUNT_INVALID"
CONDITION_UNDERDECLARED = "COUNT_UNDERDECLARED"
CONDITION_TRUNCATED = "COUNT_TRUNCATED"
CONDITION_OMITTED_MISSING = "OMITTED_COUNT_MISSING"
CONDITION_OMITTED_NONZERO = "OMITTED_COUNT_NONZERO"
CONDITION_OMITTED_ZERO = "OMITTED_COUNT_ZERO"
CONDITION_COLLECTION_MISSING = "COLLECTION_MISSING"
CONDITION_DOCUMENT_MISSING = "DOCUMENT_NOT_SUPPLIED"

COMPLETENESS_CONDITIONS = (
    CONDITION_MATCHES,
    CONDITION_MISSING,
    CONDITION_INVALID,
    CONDITION_UNDERDECLARED,
    CONDITION_TRUNCATED,
    CONDITION_OMITTED_MISSING,
    CONDITION_OMITTED_NONZERO,
    CONDITION_OMITTED_ZERO,
    CONDITION_COLLECTION_MISSING,
    CONDITION_DOCUMENT_MISSING,
)

PROOF_SUFFICIENT = "SUFFICIENT"
PROOF_INSUFFICIENT = "INSUFFICIENT"
PROOF_NOT_APPLICABLE = "NOT_APPLICABLE"

PROOF_STATUSES = (PROOF_SUFFICIENT, PROOF_INSUFFICIENT, PROOF_NOT_APPLICABLE)

CHECK_PASS = "PASS"
CHECK_FAIL = "FAIL"
CHECK_NOT_EVALUATED = "NOT_EVALUATED"
CHECK_RESULTS = (CHECK_PASS, CHECK_FAIL, CHECK_NOT_EVALUATED)

# Closed check vocabulary. A check token names the exact question the ledger
# asked; it is never free text copied from a source document.
CHECK_RECORD_PRESENT = "referenced_record_present"
CHECK_CAPTURE_AGREES = "capture_identity_agrees"
CHECK_RELATIONSHIP_TYPE = "relationship_type_agrees"
CHECK_ENDPOINT_IDENTITY = "endpoint_identity_agrees"
CHECK_RELEASE_TRANSACTION = "release_transaction_agrees"
CHECK_CONTEXT_PRESENT = "session_context_present"
CHECK_ENDPOINT_PRESENT = "bearer_endpoint_present"
CHECK_GENERATION_PRESENT = "generation_present"
CHECK_STREAM_PRESENT = "stream_present"
CHECK_DIRECTION_ROLE = "direction_role_mapping_agrees"
CHECK_DIRECTION_STREAM = "direction_agrees_with_stream"
CHECK_CANDIDATES_COMPLETE = "candidate_collection_complete"
CHECK_UNIQUE_CANDIDATE = "unique_candidate_established"
CHECK_PARTITION_CONVERVES = "partition_counts_conserve_aggregate"
CHECK_PARTITION_WINDOW = "partition_within_release_window"
CHECK_FRAME_EXCLUSIVE = "frame_ownership_exclusive"
CHECK_FRAME_PRESENT = "frame_present_in_supplied_events"
CHECK_PRODUCER_COUNT = "producer_count_matches_records"
CHECK_OMITTED_ZERO = "producer_omitted_count_zero"
CHECK_ACCOUNTING = "accounting_conserved"
CHECK_STAGE_STATUS = "stage_status_agrees_with_summary"
CHECK_GROUP_BRIDGE = "group_membership_backed_by_established_bridge"
CHECK_SCOPE_DISTINCT = "group_preserves_hop_local_subjects"
CHECK_REFERENCE_UNIQUE = "reference_is_unique_in_its_namespace"
CHECK_FRAME_CAPTURE_LOCAL = "frame_number_is_capture_local"

CHECK_TOKENS = (
    CHECK_RECORD_PRESENT,
    CHECK_CAPTURE_AGREES,
    CHECK_RELATIONSHIP_TYPE,
    CHECK_ENDPOINT_IDENTITY,
    CHECK_RELEASE_TRANSACTION,
    CHECK_CONTEXT_PRESENT,
    CHECK_ENDPOINT_PRESENT,
    CHECK_GENERATION_PRESENT,
    CHECK_STREAM_PRESENT,
    CHECK_DIRECTION_ROLE,
    CHECK_DIRECTION_STREAM,
    CHECK_CANDIDATES_COMPLETE,
    CHECK_UNIQUE_CANDIDATE,
    CHECK_PARTITION_CONVERVES,
    CHECK_PARTITION_WINDOW,
    CHECK_FRAME_EXCLUSIVE,
    CHECK_FRAME_PRESENT,
    CHECK_PRODUCER_COUNT,
    CHECK_OMITTED_ZERO,
    CHECK_ACCOUNTING,
    CHECK_STAGE_STATUS,
    CHECK_GROUP_BRIDGE,
    CHECK_SCOPE_DISTINCT,
    CHECK_REFERENCE_UNIQUE,
    CHECK_FRAME_CAPTURE_LOCAL,
)

# Source-artifact identities.
ARTIFACT_IDENTITY = "epc-session-identity"
ARTIFACT_LIFECYCLE = "epc-bearer-lifecycle"
ARTIFACT_NARRATIVE = "epc-release-narrative"
ARTIFACT_S1U = "epc-s1u-observation"
ARTIFACT_GTPV2 = "gtpv2-c-events"
ARTIFACT_GTPU = "gtp-u-events"

REL_HOP_LOCAL = "HOP_LOCAL_SESSION_CONTEXT"
REL_ENDPOINT_CORRESPONDENCE = "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE"
REL_SESSION_IDENTITY = "CROSS_INTERFACE_SESSION_IDENTITY"
REL_RELEASE_BINDING = "RELEASE_TO_SESSION_CONTEXT"
REL_SESSION_GENERATION = "SESSION_CONTEXT_TO_BEARER_GENERATION"
REL_RELEASE_GENERATION = "RELEASE_TO_BEARER_GENERATION"

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
AMBIGUOUS = "AMBIGUOUS"
SUPPORTED = "SUPPORTED"
ACCEPTED = "ACCEPTED"
REJECTED_OBSERVED = "REJECTED_OBSERVED"
UNRESOLVED = "UNRESOLVED"

GENERATION_CLOSED = "CLOSED_BY_ACCEPTED_RELEASE"
PARTITION_BEFORE = "before_release"
PARTITION_PENDING = "pending_release"
PARTITION_AFTER = "after_confirmation"
PARTITIONS = (PARTITION_BEFORE, PARTITION_PENDING, PARTITION_AFTER)
PLACEMENT_ESTABLISHED = "ESTABLISHED"
PLACEMENT_NOT_ESTABLISHED = "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"
SCOPE_COMPLETE = "COMPLETE_STREAM"
SCOPE_SUBSET = "OBSERVED_SUBSET"
ATTRIBUTION_ESTABLISHED = "ESTABLISHED"
ATTRIBUTION_NOT_ESTABLISHED = "NOT_ESTABLISHED"

# The accepted lifecycle and S1-U producers both fix this mapping.
DIRECTION_ROLE = {"UPLINK": "sgw_s1u", "DOWNLINK": "enodeb_s1u"}

CLOSURE_CRITICAL_COLLECTIONS = (
    (ARTIFACT_IDENTITY, "release_session_bindings"),
    (ARTIFACT_IDENTITY, "session_to_generation_links"),
    (ARTIFACT_IDENTITY, "generation_closure_candidates"),
    (ARTIFACT_LIFECYCLE, "lifecycle_subjects"),
)

SCOPED_COLLECTION = (ARTIFACT_LIFECYCLE, "generation_scoped_s1u_observations")

# Collection contracts exactly as the accepted schemas publish them. No omitted
# count is invented for a collection whose producer publishes none.
COLLECTION_CONTRACTS = (
    (ARTIFACT_IDENTITY, "hop_local_contexts", "hop_local_context_count", None),
    (ARTIFACT_IDENTITY, "session_identity_links", "session_identity_count", None),
    (
        ARTIFACT_IDENTITY,
        "endpoint_correspondence_links",
        "endpoint_correspondence_count",
        None,
    ),
    (
        ARTIFACT_IDENTITY,
        "release_session_bindings",
        "release_session_binding_count",
        "release_session_bindings_omitted",
    ),
    (
        ARTIFACT_IDENTITY,
        "session_to_generation_links",
        "session_to_generation_count",
        "session_to_generation_omitted",
    ),
    (
        ARTIFACT_IDENTITY,
        "generation_closure_candidates",
        "generation_closure_candidate_count",
        "generation_closure_candidates_omitted",
    ),
    (
        ARTIFACT_LIFECYCLE,
        "lifecycle_subjects",
        "lifecycle_subject_count",
        "lifecycle_subjects_omitted",
    ),
    (
        ARTIFACT_LIFECYCLE,
        "advertisement_families",
        "advertisement_family_count",
        "advertisement_families_omitted",
    ),
    (
        ARTIFACT_LIFECYCLE,
        "generation_boundary_evidence",
        "generation_boundary_count",
        None,
    ),
    (
        ARTIFACT_LIFECYCLE,
        "generation_scoped_s1u_observations",
        "generation_scoped_observation_count",
        None,
    ),
    (
        ARTIFACT_LIFECYCLE,
        "unresolved_packet_observations",
        "unresolved_packet_observation_count",
        None,
    ),
    (
        ARTIFACT_NARRATIVE,
        "narrative_subjects",
        "narrative_subject_count",
        "narrative_subjects_omitted",
    ),
    (
        ARTIFACT_NARRATIVE,
        "release_narratives",
        "release_narrative_count",
        "release_narratives_omitted",
    ),
    (
        ARTIFACT_NARRATIVE,
        "temporal_observations",
        "temporal_observation_count",
        "temporal_observations_omitted",
    ),
    (ARTIFACT_S1U, "stream_observations", "stream_count", "streams_omitted"),
)

NOT_CONFIRMED = (
    "reference consistency is a necessary audit condition, not a replacement for the accepted protocol and domain evidence gates",
    "a verified audit record does not prove bearer identity, packet delivery, network correctness or a forwarding-stop instant",
    "an audit record never establishes a session identity, a bearer generation or a release outcome that its source did not already publish",
    "an absent optional artifact is a limitation, not an inconsistency and not a verification",
    "a truncated or metadata-invalid source collection never yields a uniqueness conclusion from its visible subset",
    "an equal TEID, EPS bearer identity, address, frame number or timestamp never joins two records across captures",
    "an endpoint correspondence is not a cross-interface session identity",
    "an accepted release outcome is audited separately from the release binding and the bearer-generation closure",
    "a duplicate frame assignment is never resolved by choosing one owner",
    "an aggregate stream count is never divided across time windows by the audit",
    "an audit finding never rewrites the source artifact and never selects a first abnormal boundary or a root cause",
    "no subscriber identity, APN name, assigned PDN address or user-plane payload is read or published",
)

UNRESOLVED_STATUSES = (
    STATUS_INCONSISTENT,
    STATUS_AMBIGUOUS,
    STATUS_TRUNCATED,
    STATUS_METADATA_INVALID,
    STATUS_NOT_VERIFIABLE,
)


class AuditInputError(InputError):
    """Raised when a supplied audit source document cannot be consumed."""


# ---------------------------------------------------------------------------
# Small deterministic helpers
# ---------------------------------------------------------------------------
def _reference(kind: str, parts: list[Any]) -> str:
    material = "|".join(str(part) for part in parts)
    return kind + hashlib.sha256(material.encode("utf-8")).hexdigest()[:10]


def _capture_label(value: Any) -> str | None:
    """A display-only capture label derived from an untrusted source value."""
    if not isinstance(value, str):
        return None
    text = value.replace("\\", "/").split("/")[-1]
    text = "".join(character for character in text if character.isprintable())
    text = text.strip()[:128]
    return text or None


def _records(document: dict[str, Any] | None, key: str) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    values = document.get(key)
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def _strings(values: Any, limit: int = MAX_LIST_ITEMS) -> list[str]:
    if not isinstance(values, list):
        return []
    return [value for value in values[:limit] if isinstance(value, str)]


def _check(token: str, passed: bool | None) -> dict[str, Any]:
    result = (
        CHECK_NOT_EVALUATED
        if passed is None
        else CHECK_PASS
        if passed
        else CHECK_FAIL
    )
    return {"check": token, "result": result}


def _failed(checks: list[dict[str, Any]]) -> bool:
    return any(item.get("result") == CHECK_FAIL for item in checks)


def _status(
    checks: list[dict[str, Any]],
    *,
    ambiguous: bool = False,
    completeness: str = COMPLETE_COLLECTION,
    not_verifiable: bool = False,
) -> str:
    """Audit status from the three independent dimensions.

    Contradiction wins over ambiguity, ambiguity over an incomplete candidate
    set, and an unavailable optional input is only reported when nothing more
    specific is visible.
    """
    if _failed(checks):
        return STATUS_INCONSISTENT
    if ambiguous:
        return STATUS_AMBIGUOUS
    if completeness == COMPLETENESS_TRUNCATED:
        return STATUS_TRUNCATED
    if completeness == COMPLETENESS_METADATA_INVALID:
        return STATUS_METADATA_INVALID
    if not_verifiable:
        return STATUS_NOT_VERIFIABLE
    return STATUS_VERIFIED


def _evidence_refs(values: Any) -> list[dict[str, Any]]:
    """Copy published evidence references through an allowlist and a hard cap."""
    projected: list[dict[str, Any]] = []
    if not isinstance(values, list):
        return projected
    for value in values:
        if not isinstance(value, dict):
            continue
        projected.append(
            {
                "protocol": value.get("protocol"),
                "frame_number": _int(value.get("frame_number")),
                "message_type": (
                    value.get("message_type")
                    if isinstance(value.get("message_type"), str)
                    else None
                ),
                "evidence_level": value.get("evidence_level"),
            }
        )
    return projected[:MAX_EVIDENCE_REFERENCES]


def _worst_status(statuses: list[str]) -> str:
    precedence = {
        COMPLETENESS_METADATA_INVALID: 3,
        COMPLETENESS_TRUNCATED: 2,
        COMPLETE_COLLECTION: 1,
        COMPLETENESS_NOT_SUPPLIED: 0,
    }
    worst = COMPLETENESS_NOT_SUPPLIED
    for status in statuses:
        if precedence.get(status, 3) > precedence.get(worst, 0):
            worst = status
    return worst


# ---------------------------------------------------------------------------
# Source completeness
# ---------------------------------------------------------------------------
def _declared_count(document: dict[str, Any], key: str) -> tuple[int | None, str]:
    if key not in document:
        return None, CONDITION_MISSING
    value = document.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None, CONDITION_INVALID
    return value, CONDITION_MATCHES


def _completeness_entry(
    document_name: str,
    document: dict[str, Any] | None,
    collection: str,
    count_key: str,
    omitted_key: str | None,
) -> dict[str, Any]:
    """Compare one published count with its own published record array."""
    entry: dict[str, Any] = {
        "document": document_name,
        "collection": collection,
        "declared_count": None,
        "published_count": 0,
        "omitted_count": None,
        "status": COMPLETENESS_NOT_SUPPLIED,
        "condition": CONDITION_DOCUMENT_MISSING,
    }
    if document is None:
        return entry
    values = document.get(collection)
    if not isinstance(values, list):
        entry["status"] = COMPLETENESS_METADATA_INVALID
        entry["condition"] = CONDITION_COLLECTION_MISSING
        return entry
    entry["published_count"] = len(values)
    declared, condition = _declared_count(document, count_key)
    entry["declared_count"] = declared
    if declared is None:
        entry["status"] = COMPLETENESS_METADATA_INVALID
        entry["condition"] = condition
        return entry
    if declared > entry["published_count"]:
        entry["status"] = COMPLETENESS_TRUNCATED
        entry["condition"] = CONDITION_TRUNCATED
        return entry
    if declared < entry["published_count"]:
        entry["status"] = COMPLETENESS_METADATA_INVALID
        entry["condition"] = CONDITION_UNDERDECLARED
        return entry
    if omitted_key is not None:
        omitted, omitted_condition = _declared_count(document, omitted_key)
        entry["omitted_count"] = omitted
        if omitted is None:
            entry["status"] = COMPLETENESS_METADATA_INVALID
            entry["condition"] = (
                CONDITION_OMITTED_MISSING
                if omitted_condition == CONDITION_MISSING
                else CONDITION_INVALID
            )
            return entry
        if omitted != 0:
            entry["status"] = COMPLETENESS_METADATA_INVALID
            entry["condition"] = CONDITION_OMITTED_NONZERO
            return entry
        entry["status"] = COMPLETE_COLLECTION
        entry["condition"] = CONDITION_OMITTED_ZERO
        return entry
    entry["status"] = COMPLETE_COLLECTION
    entry["condition"] = CONDITION_MATCHES
    return entry


def build_source_completeness(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
) -> dict[str, Any]:
    """One completeness entry per collection a supplied document publishes."""
    documents = {
        ARTIFACT_IDENTITY: identity,
        ARTIFACT_LIFECYCLE: lifecycle,
        ARTIFACT_NARRATIVE: narrative,
        ARTIFACT_S1U: s1u,
    }
    entries = [
        _completeness_entry(document_name, documents[document_name], collection, count_key, omitted_key)
        for document_name, collection, count_key, omitted_key in COLLECTION_CONTRACTS
        if documents.get(document_name) is not None
    ]
    status = _worst_status([entry["status"] for entry in entries]) if entries else COMPLETE_COLLECTION
    supplied = [name for name, document in documents.items() if document is not None]
    absent = [name for name, document in documents.items() if document is None]
    limitation: str | None = None
    if status == COMPLETENESS_TRUNCATED:
        limitation = (
            "SOURCE_TRUNCATED: at least one supplied collection publishes fewer records than "
            "its own declared count, so no uniqueness is inferred from the visible subset"
        )
    elif status == COMPLETENESS_METADATA_INVALID:
        limitation = (
            "SOURCE_METADATA_INVALID: at least one supplied collection publishes a missing, "
            "invalid, underdeclared or nonzero-omitted count"
        )
    return {
        "status": status,
        "exhaustive_coverage_proven": status == COMPLETE_COLLECTION,
        "limitation": limitation,
        "documents_supplied": supplied,
        "documents_not_supplied": absent,
        "collections": entries,
    }


def collection_status(completeness: dict[str, Any], document: str, collection: str) -> str:
    for entry in completeness.get("collections") or []:
        if not isinstance(entry, dict):
            continue
        if (entry.get("document"), entry.get("collection")) == (document, collection):
            return str(entry.get("status") or COMPLETENESS_METADATA_INVALID)
    return COMPLETENESS_METADATA_INVALID


def closure_completeness(completeness: dict[str, Any]) -> tuple[bool, list[str]]:
    """Affirmative per-collection completeness of the closure-critical set."""
    failures = [
        f"{document}:{collection}"
        for document, collection in CLOSURE_CRITICAL_COLLECTIONS
        if collection_status(completeness, document, collection) != COMPLETE_COLLECTION
    ]
    return (not failures), failures


# ---------------------------------------------------------------------------
# Capture-scoped reference indexes
# ---------------------------------------------------------------------------
def _bucket(index: dict[Any, list[dict[str, Any]]], key: Any, record: dict[str, Any]) -> None:
    index.setdefault(key, []).append(record)


def _one(index: dict[Any, list[dict[str, Any]]], key: Any) -> tuple[dict[str, Any] | None, bool]:
    """Exactly one record for a namespace key; multiplicity is ambiguity."""
    values = index.get(key) or []
    if len(values) == 1:
        return values[0], False
    if len(values) > 1:
        return None, True
    return None, False


def build_indexes(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
) -> dict[str, Any]:
    """Capture-scoped resolution indexes, one namespace per published reference."""
    contexts: dict[tuple[str, str], list[dict[str, Any]]] = {}
    bindings: dict[tuple[str, str], list[dict[str, Any]]] = {}
    identity_links: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    generation_links: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    correspondences: dict[tuple[str, str], list[dict[str, Any]]] = {}
    candidates: dict[tuple[str, str], list[dict[str, Any]]] = {}
    candidates_by_chain: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    generations: dict[tuple[str, str], list[dict[str, Any]]] = {}
    generation_captures: dict[str, list[str]] = {}
    boundaries: dict[tuple[str, str], list[dict[str, Any]]] = {}
    scoped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    scoped_unresolved: dict[str, list[dict[str, Any]]] = {}
    scoped_claimants: dict[tuple[str, str], list[str]] = {}
    subjects: dict[tuple[str, str], list[dict[str, Any]]] = {}
    releases: dict[tuple[str, str], list[dict[str, Any]]] = {}
    temporal: dict[tuple[str, str], list[dict[str, Any]]] = {}
    streams: dict[tuple[str, str], list[dict[str, Any]]] = {}

    for record in _records(identity, "hop_local_contexts"):
        reference = record.get("session_context_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(contexts, (capture, reference), record)
    for record in _records(identity, "release_session_bindings"):
        reference = record.get("source_subject_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(bindings, (capture, reference), record)
    for record in _records(identity, "session_identity_links"):
        capture = record.get("capture_file")
        source = record.get("source_subject_reference")
        target = record.get("target_subject_reference")
        if isinstance(capture, str) and isinstance(source, str) and isinstance(target, str):
            _bucket(identity_links, (capture, source, target), record)
    for record in _records(identity, "session_to_generation_links"):
        capture = record.get("capture_file")
        source = record.get("source_subject_reference")
        target = record.get("target_subject_reference")
        if isinstance(capture, str) and isinstance(source, str) and isinstance(target, str):
            _bucket(generation_links, (capture, source, target), record)
    for record in _records(identity, "endpoint_correspondence_links"):
        capture = record.get("capture_file")
        reference = record.get("reference")
        if isinstance(capture, str) and isinstance(reference, str):
            _bucket(correspondences, (capture, reference), record)
    for record in _records(identity, "generation_closure_candidates"):
        capture = record.get("capture_file")
        reference = record.get("generation_closure_candidate_reference")
        if isinstance(capture, str) and isinstance(reference, str):
            _bucket(candidates, (capture, reference), record)
        context = record.get("session_context_reference")
        transaction = record.get("release_transaction_reference")
        if isinstance(capture, str) and isinstance(context, str) and isinstance(transaction, str):
            _bucket(candidates_by_chain, (capture, context, transaction), record)

    for record in _records(lifecycle, "lifecycle_subjects"):
        capture = record.get("capture_file")
        reference = record.get("generation_reference")
        if isinstance(capture, str) and isinstance(reference, str):
            _bucket(generations, (capture, reference), record)
            captures = generation_captures.setdefault(reference, [])
            if capture not in captures:
                captures.append(capture)
    for record in _records(lifecycle, "generation_boundary_evidence"):
        capture = record.get("capture_file")
        reference = record.get("transaction_reference")
        if isinstance(capture, str) and isinstance(reference, str):
            _bucket(boundaries, (capture, reference), record)
    for record in _records(lifecycle, "generation_scoped_s1u_observations"):
        generation = record.get("generation_reference")
        stream = record.get("source_stream_reference")
        if not isinstance(stream, str):
            continue
        captures = generation_captures.get(generation) if isinstance(generation, str) else None
        if not captures or len(captures) != 1:
            _bucket(scoped_unresolved, stream, record)
            continue
        capture = captures[0]
        _bucket(scoped, (capture, str(generation), stream), record)
        claimants = scoped_claimants.setdefault((capture, stream), [])
        if str(generation) not in claimants:
            claimants.append(str(generation))

    for record in _records(narrative, "narrative_subjects"):
        reference = record.get("narrative_subject_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(subjects, (capture, reference), record)
    for record in _records(narrative, "release_narratives"):
        reference = record.get("release_narrative_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(releases, (capture, reference), record)
    for record in _records(narrative, "temporal_observations"):
        reference = record.get("temporal_observation_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(temporal, (capture, reference), record)
    for record in _records(s1u, "stream_observations"):
        reference = record.get("stream_reference")
        capture = record.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            _bucket(streams, (capture, reference), record)

    def captures(document: dict[str, Any] | None, collection: str) -> set[str]:
        return {
            str(record.get("capture_file"))
            for record in _records(document, collection)
            if isinstance(record.get("capture_file"), str)
        }

    return {
        "contexts": contexts,
        "bindings": bindings,
        "identity_links": identity_links,
        "generation_links": generation_links,
        "correspondences": correspondences,
        "candidates": candidates,
        "candidates_by_chain": candidates_by_chain,
        "generations": generations,
        "generation_captures": generation_captures,
        "boundaries": boundaries,
        "scoped": scoped,
        "scoped_unresolved": scoped_unresolved,
        "scoped_claimants": scoped_claimants,
        "subjects": subjects,
        "releases": releases,
        "temporal": temporal,
        "streams": streams,
        "captures": {
            ARTIFACT_IDENTITY: captures(identity, "hop_local_contexts"),
            ARTIFACT_LIFECYCLE: captures(lifecycle, "lifecycle_subjects"),
            ARTIFACT_NARRATIVE: captures(narrative, "release_narratives"),
            ARTIFACT_S1U: captures(s1u, "stream_observations") if s1u is not None else set(),
        },
    }


def _generation_capture(index: dict[str, Any], reference: Any) -> tuple[str | None, bool]:
    """Resolve one generation reference to exactly one capture."""
    if not isinstance(reference, str):
        return None, False
    captures = index["generation_captures"].get(reference) or []
    if len(captures) == 1:
        return captures[0], False
    return None, len(captures) > 1


def _bearer_endpoint_reference(endpoint: Any, capture: str) -> str | None:
    """Recompute the accepted deterministic bearer-endpoint reference."""
    if not isinstance(endpoint, dict):
        return None
    role = endpoint.get("role")
    address = endpoint.get("address")
    teid = _int(endpoint.get("teid"))
    interface_type = _int(endpoint.get("interface_type"))
    if not isinstance(role, str) or not isinstance(address, str):
        return None
    if teid is None or interface_type is None:
        return None
    parts = ["bearer-endpoint", capture, role, address, str(teid), str(interface_type)]
    return "epc-bearer-endpoint-" + hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:10]


# ---------------------------------------------------------------------------
# Audit record assembly
# ---------------------------------------------------------------------------
class Ledger:
    """Deterministic audit-record accumulator with stable references."""

    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self._ordinals: dict[str, int] = {}

    def add(
        self,
        category: str,
        status: str,
        *,
        source_analysis: str | None = None,
        source_artifact_reference: str | None = None,
        source_subject_reference: str | None = None,
        target_analysis: str | None = None,
        target_artifact_reference: str | None = None,
        target_subject_reference: str | None = None,
        capture_file: Any = None,
        relationship_type: str | None = None,
        source_evidence_refs: Any = None,
        checks: Any = None,
        candidate_completeness_status: str = COMPLETENESS_NOT_APPLICABLE,
        proof_sufficiency_status: str = PROOF_NOT_APPLICABLE,
        limitations: Any = None,
        additional_evidence_needed: Any = None,
    ) -> dict[str, Any]:
        material = [
            category,
            source_analysis,
            source_artifact_reference,
            source_subject_reference,
            target_analysis,
            target_artifact_reference,
            target_subject_reference,
            capture_file,
            relationship_type,
        ]
        key = "|".join("" if part is None else str(part) for part in material)
        ordinal = self._ordinals.get(key, 0)
        self._ordinals[key] = ordinal + 1
        reference = _reference(
            "epc-audit-record-", material + ([ordinal] if ordinal else [])
        )
        record = {
            "audit_record_reference": reference,
            "audit_category": category,
            "audit_status": status,
            "source_analysis": source_analysis,
            "source_artifact_reference": source_artifact_reference,
            "source_subject_reference": source_subject_reference,
            "target_analysis": target_analysis,
            "target_artifact_reference": target_artifact_reference,
            "target_subject_reference": target_subject_reference,
            "capture_file": _capture_label(capture_file),
            "relationship_type": relationship_type,
            "source_evidence_refs": _evidence_refs(source_evidence_refs),
            "consistency_checks": [
                item
                for item in (checks or [])
                if isinstance(item, dict)
                and item.get("check") in CHECK_TOKENS
                and item.get("result") in CHECK_RESULTS
            ],
            "candidate_completeness_status": candidate_completeness_status,
            "proof_sufficiency_status": proof_sufficiency_status,
            "limitations": _strings(limitations),
            "additional_evidence_needed": _strings(additional_evidence_needed),
        }
        self.records.append(record)
        return record

    def sorted_records(self) -> list[dict[str, Any]]:
        return sorted(
            self.records,
            key=lambda item: (
                item["audit_category"],
                str(item.get("capture_file")),
                str(item.get("source_artifact_reference")),
                str(item.get("source_subject_reference")),
                str(item.get("target_artifact_reference")),
                str(item.get("target_subject_reference")),
                item["audit_record_reference"],
            ),
        )


# ---------------------------------------------------------------------------
# Source-artifact audit
# ---------------------------------------------------------------------------
def audit_source_artifacts(
    ledger: Ledger,
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    gtpv2_events: list[dict[str, Any]] | None,
    gtpu_events: list[dict[str, Any]] | None,
    completeness: dict[str, Any],
) -> None:
    """Every supplied artifact is inspected once; absence is never a failure."""
    documents = (
        (ARTIFACT_IDENTITY, identity, "epc-session-identity", "hop_local_contexts"),
        (ARTIFACT_LIFECYCLE, lifecycle, "epc-bearer-lifecycle", "lifecycle_subjects"),
        (ARTIFACT_NARRATIVE, narrative, "epc-release-narrative", "release_narratives"),
        (ARTIFACT_S1U, s1u, "epc-s1u-observation", "stream_observations"),
    )
    for name, document, expected_name, collection in documents:
        if document is None:
            ledger.add(
                CATEGORY_SOURCE_ARTIFACT,
                STATUS_NOT_APPLICABLE,
                source_analysis=expected_name,
                source_artifact_reference=name,
                checks=[_check(CHECK_RECORD_PRESENT, None)],
                candidate_completeness_status=COMPLETENESS_NOT_SUPPLIED,
                proof_sufficiency_status=PROOF_NOT_APPLICABLE,
                limitations=[
                    "the optional artifact was not supplied; its absence is a coverage limitation, "
                    "never an inconsistency and never a verification"
                ],
                additional_evidence_needed=[
                    f"the {name} artifact is required to audit the relationships it publishes"
                ],
            )
            continue
        checks = [
            _check(CHECK_RECORD_PRESENT, True),
            _check(CHECK_RELATIONSHIP_TYPE, document.get("analysis_name") == expected_name),
            _check(CHECK_CAPTURE_AGREES, document.get("domain") == DOMAIN_NAME),
        ]
        status = _status(checks, completeness=collection_status(completeness, name, collection))
        ledger.add(
            CATEGORY_SOURCE_ARTIFACT,
            status,
            source_analysis=expected_name,
            source_artifact_reference=name,
            checks=checks,
            candidate_completeness_status=collection_status(completeness, name, collection),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if status == STATUS_VERIFIED
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if status == STATUS_VERIFIED
                else [
                    "the supplied document does not match the expected domain or analysis identity"
                ]
            ),
        )

    for name, expected, events in (
        (ARTIFACT_GTPV2, "GTPv2-C", gtpv2_events),
        (ARTIFACT_GTPU, "GTP-U", gtpu_events),
    ):
        if events is None:
            ledger.add(
                CATEGORY_SOURCE_ARTIFACT,
                STATUS_NOT_APPLICABLE,
                source_analysis=expected,
                source_artifact_reference=name,
                checks=[_check(CHECK_RECORD_PRESENT, None)],
                candidate_completeness_status=COMPLETENESS_NOT_SUPPLIED,
                proof_sufficiency_status=PROOF_NOT_APPLICABLE,
                limitations=[
                    "detailed events were not supplied, so frame-level anchors stay "
                    "NOT_INDEPENDENTLY_VERIFIABLE and no frame is fabricated"
                ],
                additional_evidence_needed=[
                    f"the {expected} detailed events are required to re-observe a published frame anchor"
                ],
            )
            continue
        present = bool(events) and all(isinstance(event, dict) for event in events)
        checks = [
            _check(CHECK_RECORD_PRESENT, True),
            _check(CHECK_FRAME_PRESENT, present),
        ]
        ledger.add(
            CATEGORY_SOURCE_ARTIFACT,
            STATUS_VERIFIED if present else STATUS_NOT_VERIFIABLE,
            source_analysis=expected,
            source_artifact_reference=name,
            checks=checks,
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if present else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if present
                else ["the supplied detailed event list carries no usable event"]
            ),
        )


def audit_completeness(ledger: Ledger, completeness: dict[str, Any]) -> None:
    """One ledger record per published collection, never an invented count."""
    for entry in completeness.get("collections") or []:
        if not isinstance(entry, dict):
            continue
        status = str(entry.get("status") or COMPLETENESS_METADATA_INVALID)
        audit_status = {
            COMPLETE_COLLECTION: STATUS_VERIFIED,
            COMPLETENESS_TRUNCATED: STATUS_TRUNCATED,
            COMPLETENESS_METADATA_INVALID: STATUS_METADATA_INVALID,
            COMPLETENESS_NOT_SUPPLIED: STATUS_NOT_APPLICABLE,
        }.get(status, STATUS_METADATA_INVALID)
        checks = [
            _check(
                CHECK_PRODUCER_COUNT,
                entry.get("declared_count") is not None
                and entry.get("declared_count") == entry.get("published_count"),
            ),
            _check(
                CHECK_OMITTED_ZERO,
                entry.get("omitted_count") in (None, 0),
            ),
        ]
        condition = str(entry.get("condition"))
        limitations: list[str] = []
        if audit_status == STATUS_TRUNCATED:
            limitations.append(
                "the collection publishes fewer records than its own declared count, so its "
                "visible subset cannot establish uniqueness and no candidate is completed by "
                "the audit"
            )
        elif audit_status == STATUS_METADATA_INVALID:
            limitations.append(
                f"the completeness metadata is invalid ({condition}); the published subset is "
                "reported but never treated as the complete candidate set"
            )
        ledger.add(
            CATEGORY_SOURCE_ARTIFACT,
            audit_status,
            source_analysis=str(entry.get("document")),
            source_artifact_reference=f"{entry.get('document')}:{entry.get('collection')}",
            checks=checks,
            candidate_completeness_status=status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if audit_status == STATUS_VERIFIED
                else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
            additional_evidence_needed=(
                []
                if audit_status == STATUS_VERIFIED
                else ["a complete candidate collection is required before any uniqueness is audited"]
            ),
        )


# ---------------------------------------------------------------------------
# Reference integrity
# ---------------------------------------------------------------------------
def audit_reference_integrity(
    ledger: Ledger,
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """Resolve every published cross-artifact reference inside its namespace."""
    binding_status = collection_status(
        completeness, ARTIFACT_IDENTITY, "release_session_bindings"
    )
    link_status = collection_status(
        completeness, ARTIFACT_IDENTITY, "session_to_generation_links"
    )
    candidate_status = collection_status(
        completeness, ARTIFACT_IDENTITY, "generation_closure_candidates"
    )
    generation_status = collection_status(
        completeness, ARTIFACT_LIFECYCLE, "lifecycle_subjects"
    )

    for (capture, reference), records in sorted(index["contexts"].items()):
        context = records[0]
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(records) == 1),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                context.get("relationship_type") == REL_HOP_LOCAL,
            ),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=len(records) > 1),
            source_analysis="epc-session-identity",
            source_artifact_reference="epc-session-identity:hop_local_contexts",
            source_subject_reference=reference,
            capture_file=capture,
            relationship_type=REL_HOP_LOCAL,
            source_evidence_refs=context.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_IDENTITY, "hop_local_contexts"
            ),
            proof_sufficiency_status=PROOF_SUFFICIENT,
        )

    for (capture, transaction), records in sorted(index["bindings"].items()):
        binding = records[0]
        target = binding.get("target_subject_reference")
        resolved, ambiguous = _one(index["contexts"], (capture, target)) if isinstance(target, str) else (None, False)
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(records) == 1),
            _check(CHECK_CONTEXT_PRESENT, resolved is not None),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                binding.get("relationship_type") == REL_RELEASE_BINDING,
            ),
        ]
        competing = _strings(binding.get("competing_candidates"))
        competing_resolved = all(
            _one(index["contexts"], (capture, item))[0] is not None for item in competing
        ) if competing else True
        checks.append(_check(CHECK_RECORD_PRESENT, competing_resolved))
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(
                checks,
                ambiguous=ambiguous or len(records) > 1,
                completeness=binding_status,
            ),
            source_analysis="epc-session-identity",
            source_artifact_reference="epc-session-identity:release_session_bindings",
            source_subject_reference=transaction,
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:hop_local_contexts",
            target_subject_reference=target if isinstance(target, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=binding.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=binding_status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if resolved is not None
                and binding_status == COMPLETE_COLLECTION
                else PROOF_INSUFFICIENT
            ),
        )

    identity_link_status = collection_status(
        completeness, ARTIFACT_IDENTITY, "session_identity_links"
    )
    for (capture, source, target), records in sorted(index["identity_links"].items()):
        link = records[0]
        source_resolved = _one(index["contexts"], (capture, source))[0] is not None
        target_resolved = _one(index["contexts"], (capture, target))[0] is not None
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, None if len(records) > 1 else True),
            _check(CHECK_CONTEXT_PRESENT, source_resolved),
            _check(CHECK_ENDPOINT_PRESENT, target_resolved),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                link.get("relationship_type") == REL_SESSION_IDENTITY,
            ),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=len(records) > 1, completeness=identity_link_status),
            source_analysis="epc-session-identity",
            source_artifact_reference="epc-session-identity:session_identity_links",
            source_subject_reference=source,
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:hop_local_contexts",
            target_subject_reference=target,
            capture_file=capture,
            relationship_type=REL_SESSION_IDENTITY,
            source_evidence_refs=link.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=identity_link_status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if source_resolved
                and target_resolved
                and identity_link_status == COMPLETE_COLLECTION
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if source_resolved and target_resolved
                else [
                    "a published cross-interface session identity names a context that the "
                    "supplied artifacts do not publish"
                ]
            ),
        )

    for (capture, source, target), records in sorted(index["generation_links"].items()):
        link = records[0]
        source_resolved = _one(index["contexts"], (capture, source))[0] is not None
        endpoint = link.get("bearer_endpoint")
        recomputed = _bearer_endpoint_reference(endpoint, capture)
        target_resolved = recomputed == target
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, None if len(records) > 1 else True),
            _check(CHECK_CONTEXT_PRESENT, source_resolved),
            _check(CHECK_ENDPOINT_PRESENT, target_resolved),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                link.get("relationship_type") == REL_SESSION_GENERATION,
            ),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=len(records) > 1, completeness=link_status),
            source_analysis="epc-session-identity",
            source_artifact_reference="epc-session-identity:session_to_generation_links",
            source_subject_reference=source,
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-identity-link:bearer_endpoint",
            target_subject_reference=target,
            capture_file=capture,
            relationship_type=REL_SESSION_GENERATION,
            source_evidence_refs=link.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=link_status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if source_resolved
                and target_resolved
                and link_status == COMPLETE_COLLECTION
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if target_resolved
                else [
                    "the published bearer endpoint reference does not recompute from the "
                    "endpoint it publishes, so the referenced record is not resolved"
                ]
            ),
        )

    for (capture, reference), records in sorted(index["candidates"].items()):
        candidate = records[0]
        context = candidate.get("session_context_reference")
        transaction = candidate.get("release_transaction_reference")
        target = candidate.get("bearer_endpoint_reference")
        context_resolved = (
            _one(index["contexts"], (capture, context))[0] is not None
            if isinstance(context, str)
            else False
        )
        binding_resolved = (
            _one(index["bindings"], (capture, transaction))[0] is not None
            if isinstance(transaction, str)
            else False
        )
        recomputed = _bearer_endpoint_reference(candidate.get("bearer_endpoint"), capture)
        endpoint_resolved = recomputed is not None and recomputed == target
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(records) == 1),
            _check(CHECK_CONTEXT_PRESENT, context_resolved),
            _check(CHECK_RELEASE_TRANSACTION, binding_resolved),
            _check(CHECK_ENDPOINT_IDENTITY, endpoint_resolved),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=len(records) > 1, completeness=candidate_status),
            source_analysis="epc-session-identity",
            source_artifact_reference="epc-session-identity:generation_closure_candidates",
            source_subject_reference=reference,
            target_analysis="epc-bearer-lifecycle",
            target_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
            target_subject_reference=target if isinstance(target, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            checks=checks,
            candidate_completeness_status=candidate_status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if context_resolved and binding_resolved and endpoint_resolved
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if context_resolved and binding_resolved and endpoint_resolved
                else [
                    "a closure candidate names a context, release transaction or bearer endpoint "
                    "that the supplied artifacts do not publish"
                ]
            ),
        )

    for (capture, reference), records in sorted(index["generations"].items()):
        generation = records[0]
        boundary = generation.get("generation_boundary")
        boundary_transaction = (
            boundary.get("transaction_reference") if isinstance(boundary, dict) else None
        )
        boundary_present = (
            isinstance(boundary_transaction, str)
            and _one(index["boundaries"], (capture, boundary_transaction))[0] is not None
        )
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(records) == 1),
            _check(
                CHECK_GENERATION_PRESENT,
                generation.get("generation_reference") == reference,
            ),
            _check(
                CHECK_RELEASE_TRANSACTION,
                generation.get("generation_state") != GENERATION_CLOSED or boundary_present,
            ),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(
                checks,
                ambiguous=len(records) > 1
                or len(index["generation_captures"].get(reference) or []) > 1,
                completeness=generation_status,
            ),
            source_analysis="epc-bearer-lifecycle",
            source_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
            source_subject_reference=reference,
            target_analysis="epc-bearer-lifecycle",
            target_artifact_reference="epc-bearer-lifecycle:generation_boundary_evidence",
            target_subject_reference=(
                boundary_transaction if isinstance(boundary_transaction, str) else None
            ),
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            source_evidence_refs=generation.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=generation_status,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if boundary_present or generation.get("generation_state") != GENERATION_CLOSED
                else PROOF_INSUFFICIENT
            ),
        )

    for (capture, transaction), records in sorted(index["boundaries"].items()):
        boundary = records[0]
        request = _int(boundary.get("request_frame"))
        response = _int(boundary.get("response_frame"))
        ordered = response is None or (request is not None and response >= request)
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(records) == 1),
            _check(CHECK_RELEASE_TRANSACTION, request is not None),
            _check(CHECK_FRAME_PRESENT, ordered),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=len(records) > 1),
            source_analysis="epc-bearer-lifecycle",
            source_artifact_reference="epc-bearer-lifecycle:generation_boundary_evidence",
            source_subject_reference=transaction,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=boundary.get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_LIFECYCLE, "generation_boundary_evidence"
            ),
            proof_sufficiency_status=PROOF_SUFFICIENT,
        )

    for record in _records(narrative, "narrative_subjects"):
        capture = record.get("capture_file")
        reference = record.get("session_context_reference")
        resolved, ambiguous = (
            _one(index["contexts"], (str(capture), reference))
            if isinstance(capture, str) and isinstance(reference, str)
            else (None, False)
        )
        checks = [
            _check(CHECK_CONTEXT_PRESENT, resolved is not None),
            _check(
                CHECK_CAPTURE_AGREES,
                resolved is not None and resolved.get("capture_file") == capture,
            ),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=ambiguous),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:narrative_subjects",
            source_subject_reference=record.get("narrative_subject_reference"),
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:hop_local_contexts",
            target_subject_reference=reference if isinstance(reference, str) else None,
            capture_file=capture,
            relationship_type=REL_HOP_LOCAL,
            source_evidence_refs=record.get("source_evidence_refs"),
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_IDENTITY, "hop_local_contexts"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if resolved is not None else PROOF_INSUFFICIENT
            ),
        )

    for record in _records(narrative, "release_narratives"):
        capture = record.get("capture_file")
        transaction = record.get("release_transaction_reference")
        boundary = (
            _one(index["boundaries"], (str(capture), transaction))[0]
            if isinstance(capture, str) and isinstance(transaction, str)
            else None
        )
        binding = (
            _one(index["bindings"], (str(capture), transaction))[0]
            if isinstance(capture, str) and isinstance(transaction, str)
            else None
        )
        checks = [
            _check(CHECK_RELEASE_TRANSACTION, boundary is not None or binding is not None),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-bearer-lifecycle",
            target_artifact_reference="epc-bearer-lifecycle:generation_boundary_evidence",
            target_subject_reference=transaction if isinstance(transaction, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_NARRATIVE, "release_narratives"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if boundary is not None or binding is not None
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if boundary is not None or binding is not None
                else [
                    "the narrative publishes a release transaction that neither the identity "
                    "analysis nor the lifecycle analysis publishes in the same capture"
                ]
            ),
        )
        for reference in _strings(record.get("temporal_observation_references")):
            temporal, ambiguous = _one(index["temporal"], (str(capture), reference))
            checks = [_check(CHECK_RECORD_PRESENT, temporal is not None)]
            ledger.add(
                CATEGORY_REFERENCE_INTEGRITY,
                _status(checks, ambiguous=ambiguous),
                source_analysis="epc-release-narrative",
                source_artifact_reference="epc-release-narrative:release_narratives",
                source_subject_reference=record.get("release_narrative_reference"),
                target_analysis="epc-release-narrative",
                target_artifact_reference="epc-release-narrative:temporal_observations",
                target_subject_reference=reference,
                capture_file=capture,
                relationship_type=REL_RELEASE_GENERATION,
                checks=checks,
                candidate_completeness_status=collection_status(
                    completeness, ARTIFACT_NARRATIVE, "temporal_observations"
                ),
                proof_sufficiency_status=(
                    PROOF_SUFFICIENT if temporal is not None else PROOF_INSUFFICIENT
                ),
            )
        for generation in _records(record, "proved_generations"):
            reference = generation.get("generation_reference")
            resolved, ambiguous = (
                _one(index["generations"], (str(capture), reference))
                if isinstance(capture, str) and isinstance(reference, str)
                else (None, False)
            )
            checks = [_check(CHECK_GENERATION_PRESENT, resolved is not None)]
            ledger.add(
                CATEGORY_REFERENCE_INTEGRITY,
                _status(checks, ambiguous=ambiguous),
                source_analysis="epc-release-narrative",
                source_artifact_reference="epc-release-narrative:release_narratives",
                source_subject_reference=record.get("release_narrative_reference"),
                target_analysis="epc-bearer-lifecycle",
                target_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
                target_subject_reference=reference if isinstance(reference, str) else None,
                capture_file=capture,
                relationship_type=REL_RELEASE_GENERATION,
                checks=checks,
                candidate_completeness_status=generation_status,
                proof_sufficiency_status=(
                    PROOF_SUFFICIENT if resolved is not None else PROOF_INSUFFICIENT
                ),
                limitations=(
                    []
                    if resolved is not None
                    else [
                        "the narrative publishes a proved generation that the lifecycle "
                        "analysis does not publish in the same capture"
                    ]
                ),
            )

    for record in _records(narrative, "temporal_observations"):
        capture = record.get("capture_file")
        release, release_ambiguous = (
            _one(index["releases"], (str(capture), record.get("release_narrative_reference")))
            if isinstance(capture, str)
            else (None, False)
        )
        stream_reference = record.get("stream_reference")
        stream_resolved: bool | None
        if s1u is None:
            stream_resolved = None
        else:
            stream_resolved = (
                _one(index["streams"], (str(capture), stream_reference))[0] is not None
                if isinstance(capture, str) and isinstance(stream_reference, str)
                else False
            )
        checks = [
            _check(CHECK_RECORD_PRESENT, release is not None),
            _check(CHECK_STREAM_PRESENT, stream_resolved),
        ]
        ledger.add(
            CATEGORY_REFERENCE_INTEGRITY,
            _status(checks, ambiguous=release_ambiguous),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:temporal_observations",
            source_subject_reference=record.get("temporal_observation_reference"),
            target_analysis="epc-s1u-observation",
            target_artifact_reference="epc-s1u-observation:stream_observations",
            target_subject_reference=(
                stream_reference if isinstance(stream_reference, str) else None
            ),
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            source_evidence_refs=[],
            checks=checks,
            candidate_completeness_status=(
                collection_status(completeness, ARTIFACT_S1U, "stream_observations")
                if s1u is not None
                else COMPLETENESS_NOT_SUPPLIED
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if release is not None and stream_resolved is True
                else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if stream_resolved is not False
                else ["the temporal observation names an S1-U stream the supplied document does not publish"]
            ),
        )


# ---------------------------------------------------------------------------
# Capture scope and transaction anchors
# ---------------------------------------------------------------------------
def audit_capture_scope(
    ledger: Ledger,
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    index: dict[str, Any],
    gtpv2_events: list[dict[str, Any]] | None,
    gtpu_events: list[dict[str, Any]] | None,
) -> None:
    """Capture identity is part of every reference and every value collision."""
    captures = sorted(index["captures"].get(ARTIFACT_NARRATIVE, set()))
    for capture in captures:
        present = {
            name: capture in index["captures"].get(name, set())
            for name in (ARTIFACT_IDENTITY, ARTIFACT_LIFECYCLE)
        }
        checks = [_check(CHECK_CAPTURE_AGREES, all(present.values()))]
        ledger.add(
            CATEGORY_CAPTURE_SCOPE,
            _status(checks),
            source_artifact_reference="capture-scope",
            capture_file=capture,
            checks=checks,
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=PROOF_SUFFICIENT,
            limitations=(
                []
                if all(present.values())
                else [
                    "an artifact that publishes this capture elsewhere does not publish any "
                    "record for it here"
                ]
            ),
        )

    for reference, records in sorted(index["generations"].items()):
        generation_captures = index["generation_captures"].get(reference) or []
        if len(generation_captures) <= 1:
            continue
        ledger.add(
            CATEGORY_CAPTURE_SCOPE,
            STATUS_AMBIGUOUS,
            source_analysis="epc-bearer-lifecycle",
            source_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
            source_subject_reference=reference,
            capture_file=records[0].get("capture_file"),
            checks=[_check(CHECK_FRAME_CAPTURE_LOCAL, True)],
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=PROOF_INSUFFICIENT,
            limitations=[
                "one generation reference appears in more than one capture, so it cannot be "
                "placed in exactly one capture and no stream ownership can rest on it"
            ],
        )

    values_seen: dict[tuple[str, str, int], list[tuple[str, str]]] = {}
    for (capture, reference), records in sorted(index["generations"].items()):
        for record in records:
            role = record.get("receiving_endpoint_role")
            address = record.get("receiving_endpoint_address")
            teid = _int(record.get("receiving_endpoint_teid"))
            if isinstance(role, str) and isinstance(address, str) and teid is not None:
                values_seen.setdefault((role, address, teid), []).append((capture, reference))
    for (role, address, teid), owners in sorted(values_seen.items()):
        capture_values = sorted({owner[0] for owner in owners})
        if len(capture_values) <= 1:
            continue
        ledger.add(
            CATEGORY_CAPTURE_SCOPE,
            STATUS_VERIFIED,
            source_analysis="epc-bearer-lifecycle",
            source_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
            source_subject_reference=owners[0][1],
            capture_file=owners[0][0],
            checks=[_check(CHECK_FRAME_CAPTURE_LOCAL, True)],
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=PROOF_SUFFICIENT,
            limitations=[
                "an equal receiving TEID and address appears in another capture; capture "
                "identity is part of the endpoint identity, so no cross-capture relationship "
                "is formed from the value collision"
            ],
        )

    frame_owners: dict[int, set[str]] = {}
    for events in (gtpv2_events, gtpu_events):
        for event in events or []:
            if not isinstance(event, dict):
                continue
            frame = _int(event.get("frame_number"))
            capture = event.get("capture_file")
            if frame is None or not isinstance(capture, str):
                continue
            frame_owners.setdefault(frame, set()).add(capture)
    for frame, owner_captures in sorted(frame_owners.items()):
        if len(owner_captures) <= 1:
            continue
        ledger.add(
            CATEGORY_CAPTURE_SCOPE,
            STATUS_VERIFIED,
            source_artifact_reference="detailed-events:frame-numbers",
            capture_file=sorted(owner_captures)[0],
            checks=[_check(CHECK_FRAME_CAPTURE_LOCAL, True)],
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=PROOF_SUFFICIENT,
            limitations=[
                f"frame {frame} appears in more than one capture; a frame number is "
                "capture-local and an equal frame number in another capture is never a "
                "substitute for the referenced event"
            ],
        )


def _gtpv2_messages(
    gtpv2_events: list[dict[str, Any]],
) -> dict[tuple[str, int], set[str]]:
    observed: dict[tuple[str, int], set[str]] = {}
    for event in gtpv2_events:
        if not isinstance(event, dict):
            continue
        capture = event.get("capture_file")
        frame = _int(event.get("frame_number"))
        if not isinstance(capture, str) or frame is None:
            continue
        observed.setdefault((capture, frame), set()).add(str(event.get("message_type")))
    return observed


def audit_transaction_anchors(
    ledger: Ledger,
    narrative: dict[str, Any],
    index: dict[str, Any],
    gtpv2_events: list[dict[str, Any]] | None,
    completeness: dict[str, Any],
) -> None:
    """Release transactions and their frame anchors, capture-scoped."""
    observed = _gtpv2_messages(gtpv2_events) if gtpv2_events is not None else None
    for record in _records(narrative, "release_narratives"):
        capture = record.get("capture_file")
        transaction = record.get("release_transaction_reference")
        boundary = (
            _one(index["boundaries"], (str(capture), transaction))[0]
            if isinstance(capture, str) and isinstance(transaction, str)
            else None
        )
        binding = (
            _one(index["bindings"], (str(capture), transaction))[0]
            if isinstance(capture, str) and isinstance(transaction, str)
            else None
        )
        checks = [
            _check(CHECK_RELEASE_TRANSACTION, boundary is not None or binding is not None),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                not isinstance(boundary, dict)
                or boundary.get("response_message_type") in (None, "Delete Session Response"),
            ),
        ]
        limitations: list[str] = []
        if isinstance(boundary, dict) and isinstance(binding, dict):
            boundary_request = _int(boundary.get("request_frame"))
            boundary_response = _int(boundary.get("response_frame"))
            binding_frames = [
                item for item in binding.get("source_frames") or [] if isinstance(item, int)
            ]
            binding_request = binding_frames[0] if binding_frames else None
            binding_response = binding_frames[1] if len(binding_frames) > 1 else None
            agrees = (
                (
                    boundary_request is None
                    or binding_request is None
                    or boundary_request == binding_request
                )
                and (
                    boundary_response is None
                    or binding_response is None
                    or boundary_response == binding_response
                )
            )
            checks.append(_check(CHECK_CAPTURE_AGREES, agrees))
            if not agrees:
                limitations.append(
                    "the lifecycle boundary and the identity binding publish different frames "
                    "for one release transaction"
                )
        if observed is None:
            checks.append(_check(CHECK_FRAME_PRESENT, None))
            limitations.append(
                "no detailed GTPv2-C events were supplied, so the published release frames are "
                "not re-observed and the anchor stays NOT_INDEPENDENTLY_VERIFIABLE"
            )
        else:
            consistent = True
            for frame, expected in (
                (record.get("release_request_frame"), "Delete Session Request"),
                (record.get("release_confirmation_frame"), "Delete Session Response"),
            ):
                if frame is None:
                    continue
                messages = observed.get((str(capture), int(frame)))
                if messages is None or expected not in messages:
                    consistent = False
            checks.append(_check(CHECK_FRAME_PRESENT, consistent))
            if not consistent:
                limitations.append(
                    "a published release frame anchor does not re-observe the expected message "
                    "in the supplied capture; the source claim stays visible and is not repaired"
                )
            if record.get("provenance_status") == "INCONSISTENT":
                checks.append(_check(CHECK_RELATIONSHIP_TYPE, False))
                limitations.append(
                    "the source narrative already reports inconsistent provenance for this "
                    "release, and the audit keeps that finding"
                )
        ledger.add(
            CATEGORY_TRANSACTION_ANCHOR,
            _status(checks, not_verifiable=observed is None),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:release_session_bindings",
            target_subject_reference=transaction if isinstance(transaction, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=[
                ref
                for stage in _records(record, "stages")
                for ref in stage.get("evidence_refs") or []
                if isinstance(ref, dict)
            ],
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_IDENTITY, "release_session_bindings"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if observed is not None and not _failed(checks)
                else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
            additional_evidence_needed=(
                []
                if observed is not None
                else ["detailed GTPv2-C events are required to re-observe a release frame anchor"]
            ),
        )


def audit_session_context_links(
    ledger: Ledger,
    narrative: dict[str, Any],
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """A narrative subject and a release binding must name the same context."""
    for record in _records(narrative, "release_narratives"):
        capture = record.get("capture_file")
        transaction = record.get("release_transaction_reference")
        binding = (
            _one(index["bindings"], (str(capture), transaction))[0]
            if isinstance(capture, str) and isinstance(transaction, str)
            else None
        )
        context = record.get("session_context_reference")
        context_record = (
            _one(index["contexts"], (str(capture), context))[0]
            if isinstance(capture, str) and isinstance(context, str)
            else None
        )
        checks = [
            _check(CHECK_CONTEXT_PRESENT, context_record is not None),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                (
                    binding.get("target_subject_reference") == context
                )
                if isinstance(binding, dict)
                else None,
            ),
            _check(
                CHECK_CAPTURE_AGREES,
                context_record is not None
                and context_record.get("interface_class") == record.get("interface_class"),
            ),
        ]
        ledger.add(
            CATEGORY_SESSION_CONTEXT_LINK,
            _status(
                checks,
                completeness=collection_status(
                    completeness, ARTIFACT_IDENTITY, "hop_local_contexts"
                ),
            ),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:hop_local_contexts",
            target_subject_reference=context if isinstance(context, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=[],
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_IDENTITY, "release_session_bindings"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if not _failed(checks) else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if not _failed(checks)
                else [
                    "the release narrative and the release binding do not name the same "
                    "hop-local session context, or the context interface class disagrees"
                ]
            ),
        )


def audit_cross_interface(
    ledger: Ledger,
    narrative: dict[str, Any],
    identity: dict[str, Any],
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """Endpoint correspondence is never promoted into a cross-interface identity."""
    by_reference: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for record in _records(identity, "session_identity_links"):
        capture = record.get("capture_file")
        reference = record.get("reference")
        if isinstance(capture, str) and isinstance(reference, str):
            by_reference.setdefault((capture, reference), []).append(record)
    correspondences = index["correspondences"]
    for subject in _records(narrative, "narrative_subjects"):
        capture = subject.get("capture_file")
        own = subject.get("session_context_reference")
        group_basis = subject.get("narrative_group_basis")
        members = _strings(subject.get("narrative_group_members"))
        bridge_references = _strings(subject.get("narrative_group_bridge_references"))
        members_present = bool(members) and all(
            _one(index["contexts"], (str(capture), member))[0] is not None
            for member in members
        )
        checks = [
            _check(CHECK_RECORD_PRESENT, members_present),
            _check(
                CHECK_SCOPE_DISTINCT,
                isinstance(own, str) and own in members and len(members) == len(set(members)),
            ),
        ]
        limitations: list[str] = []
        if group_basis == "proved_cross_interface_session_identity":
            bridged = True
            for member in members:
                if member == own:
                    continue
                left = _one(index["identity_links"], (str(capture), str(own), member))[0]
                right = _one(index["identity_links"], (str(capture), member, str(own)))[0]
                if not (
                    (isinstance(left, dict) and left.get("association_status") == ESTABLISHED)
                    or (
                        isinstance(right, dict)
                        and right.get("association_status") == ESTABLISHED
                    )
                ):
                    bridged = False
            published_bridges_ok = True
            for reference in bridge_references:
                resolved, ambiguous = _one(by_reference, (str(capture), reference))
                if resolved is None or ambiguous:
                    published_bridges_ok = False
                    continue
                if resolved.get("relationship_type") != REL_SESSION_IDENTITY:
                    published_bridges_ok = False
                if resolved.get("association_status") != ESTABLISHED:
                    published_bridges_ok = False
            checks.append(_check(CHECK_GROUP_BRIDGE, bridged and published_bridges_ok))
            if not bridged:
                limitations.append(
                    "the narrative group claims a proved cross-interface session identity "
                    "that no established link between its members supports"
                )
            if not published_bridges_ok:
                limitations.append(
                    "a published group bridge reference does not resolve to an established "
                    "cross-interface session identity link"
                )
        elif group_basis == "single_hop_local_context":
            checks.append(_check(CHECK_GROUP_BRIDGE, members == [own]))
            if members != [own]:
                limitations.append(
                    "a single-hop narrative subject claims more than one hop-local member"
                )
        else:
            checks.append(_check(CHECK_GROUP_BRIDGE, False))
        correspondence_used = False
        for reference in _strings(subject.get("endpoint_correspondence_references")):
            resolved, _ = _one(correspondences, (str(capture), reference))
            if resolved is None:
                checks.append(_check(CHECK_RECORD_PRESENT, False))
                continue
            if resolved.get("relationship_type") != REL_ENDPOINT_CORRESPONDENCE:
                checks.append(_check(CHECK_RELATIONSHIP_TYPE, False))
            if reference in bridge_references:
                correspondence_used = True
        if correspondence_used:
            checks.append(_check(CHECK_RELATIONSHIP_TYPE, False))
            limitations.append(
                "an endpoint correspondence reference is used as a group bridge, but an "
                "endpoint correspondence is not a session identity"
            )
        ledger.add(
            CATEGORY_CROSS_INTERFACE_BRIDGE,
            _status(
                checks,
                ambiguous=len(members) > 1
                and group_basis != "proved_cross_interface_session_identity",
            ),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:narrative_subjects",
            source_subject_reference=subject.get("narrative_subject_reference"),
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:session_identity_links",
            target_subject_reference=subject.get("narrative_group_reference"),
            capture_file=capture,
            relationship_type=REL_SESSION_IDENTITY,
            source_evidence_refs=subject.get("source_evidence_refs"),
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_IDENTITY, "session_identity_links"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if not _failed(checks) else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
            additional_evidence_needed=(
                []
                if not _failed(checks)
                else [
                    "an established cross-interface session identity link in the same capture "
                    "is required to justify a multi-member narrative group"
                ]
            ),
        )


def audit_release_bindings(
    ledger: Ledger,
    narrative: dict[str, Any],
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """Outcome, binding and closure stay three separate audited facts."""
    binding_completeness = collection_status(
        completeness, ARTIFACT_IDENTITY, "release_session_bindings"
    )
    for record in _records(narrative, "release_narratives"):
        capture = record.get("capture_file")
        transaction = record.get("release_transaction_reference")
        key = (str(capture), transaction)
        candidates = index["bindings"].get(key, []) if isinstance(transaction, str) else []
        binding = candidates[0] if len(candidates) == 1 else None
        claimed = record.get("release_session_binding_status")
        competing = _strings((binding or {}).get("competing_candidates"))
        checks = [
            _check(CHECK_REFERENCE_UNIQUE, len(candidates) == 1),
            _check(
                CHECK_RELATIONSHIP_TYPE,
                isinstance(binding, dict)
                and binding.get("relationship_type") == REL_RELEASE_BINDING,
            ),
            _check(
                CHECK_RELEASE_TRANSACTION,
                (
                    binding.get("release_outcome_status")
                    == record.get("release_outcome_status")
                )
                if isinstance(binding, dict)
                else None,
            ),
            _check(
                CHECK_RECORD_PRESENT,
                (claimed == ESTABLISHED)
                == (
                    isinstance(binding, dict)
                    and binding.get("association_status") == ESTABLISHED
                ),
            ),
            _check(CHECK_CANDIDATES_COMPLETE, not competing),
        ]
        limitations: list[str] = []
        if competing:
            limitations.append(
                "the release request addresses several hop-local contexts, so it binds to none "
                "and no single context is selected by the audit"
            )
        if not isinstance(binding, dict):
            limitations.append(
                "the identity analysis publishes no single release binding for this release "
                "transaction; the narrative binding status is audited against that absence"
            )
        if isinstance(binding, dict) and binding.get("association_status") != claimed:
            limitations.append(
                "the narrative binding status differs from the status the identity analysis "
                "publishes for the same release transaction"
            )
        status = _status(checks, ambiguous=bool(competing), completeness=binding_completeness)
        if claimed != ESTABLISHED and competing:
            status = STATUS_AMBIGUOUS
        ledger.add(
            CATEGORY_RELEASE_SESSION_BINDING,
            status,
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-session-identity",
            target_artifact_reference="epc-session-identity:release_session_bindings",
            target_subject_reference=transaction if isinstance(transaction, str) else None,
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=(binding or {}).get("evidence_refs"),
            checks=checks,
            candidate_completeness_status=binding_completeness,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if status == STATUS_VERIFIED
                else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
        )


# ---------------------------------------------------------------------------
# Session-to-generation links and generation closure
# ---------------------------------------------------------------------------
def _candidate_subject(candidate: dict[str, Any], capture: str) -> str:
    reference = candidate.get("generation_closure_candidate_reference")
    if isinstance(reference, str):
        return reference
    material = "|".join(
        [
            capture,
            str(candidate.get("session_context_reference")),
            str(candidate.get("release_transaction_reference")),
            str(candidate.get("bearer_endpoint_reference")),
        ]
    )
    return "epc-closure-candidate-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:10]


def _candidate_endpoint_key(candidate: dict[str, Any], capture: str) -> tuple[Any, ...]:
    endpoint = candidate.get("bearer_endpoint")
    if not isinstance(endpoint, dict):
        return ()
    return (
        capture,
        str(endpoint.get("role")),
        str(endpoint.get("address")),
        _int(endpoint.get("teid")) or 0,
        _int(endpoint.get("interface_type")) or 0,
    )


def _subject_endpoint_key(subject: dict[str, Any]) -> tuple[Any, ...]:
    return (
        str(subject.get("capture_file")),
        str(subject.get("receiving_endpoint_role")),
        str(subject.get("receiving_endpoint_address")),
        _int(subject.get("receiving_endpoint_teid")) or 0,
        _int(subject.get("reviewed_interface_type")) or 0,
    )


def _boundary_subjects(index: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (capture, _reference), records in index["generations"].items():
        for record in records:
            boundary = record.get("generation_boundary")
            if not isinstance(boundary, dict):
                continue
            transaction = boundary.get("transaction_reference")
            if isinstance(transaction, str):
                result.setdefault((capture, transaction), []).append(record)
    return result


def _proved_endpoint_key(generation: dict[str, Any], capture: str) -> tuple[Any, ...]:
    return (
        capture,
        str(generation.get("receiving_endpoint_role")),
        str(generation.get("receiving_endpoint_address")),
        _int(generation.get("receiving_endpoint_teid")) or 0,
        _int(generation.get("reviewed_interface_type")) or 0,
    )


def _distinct_proved_generations(record: dict[str, Any]) -> list[dict[str, Any]]:
    """One proved generation is counted once per release narrative."""
    seen: set[tuple[Any, ...]] = set()
    result: list[dict[str, Any]] = []
    for generation in record.get("proved_generations") or []:
        if not isinstance(generation, dict):
            continue
        key = (
            str(generation.get("generation_reference")),
            str(generation.get("receiving_endpoint_role")),
            str(generation.get("receiving_endpoint_address")),
            _int(generation.get("receiving_endpoint_teid")) or 0,
            _int(generation.get("reviewed_interface_type")) or 0,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(generation)
    return result


def _established_session_generation_link(
    index: dict[str, Any],
    capture: str,
    context: str,
    endpoint_reference: Any,
) -> tuple[dict[str, Any] | None, bool, bool]:
    """A generation link is proved only by an explicit established record."""
    if not isinstance(endpoint_reference, str):
        return None, False, False
    link, ambiguous = _one(
        index["generation_links"], (capture, context, endpoint_reference)
    )
    if ambiguous or not isinstance(link, dict):
        return link, ambiguous, False
    established = (
        link.get("relationship_type") == REL_SESSION_GENERATION
        and link.get("association_status") == ESTABLISHED
        and link.get("capture_file") == capture
        and link.get("source_subject_reference") == context
        and link.get("target_subject_reference") == endpoint_reference
    )
    return link, False, established


def _candidate_closes_endpoint(
    candidate: dict[str, Any],
    capture: str,
    context: str,
    transaction: str,
    endpoint_key: tuple[Any, ...],
) -> bool:
    return (
        candidate.get("capture_file") == capture
        and candidate.get("session_context_reference") == context
        and candidate.get("release_transaction_reference") == transaction
        and candidate.get("association_status") == ESTABLISHED
        and _candidate_endpoint_key(candidate, capture) == endpoint_key
    )


def _closure_endpoint_candidates(
    established: list[dict[str, Any]],
    capture: str,
    context: str,
    transaction: str,
    endpoint_key: tuple[Any, ...],
) -> list[dict[str, Any]]:
    """Candidates are unique per reviewed endpoint, never per release transaction."""
    return [
        candidate
        for candidate in established
        if _candidate_closes_endpoint(
            candidate, capture, context, transaction, endpoint_key
        )
    ]


def audit_session_generation_links(
    ledger: Ledger,
    narrative: dict[str, Any],
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """A session-to-generation claim must resolve to one accepted link."""
    link_completeness = collection_status(
        completeness, ARTIFACT_IDENTITY, "session_to_generation_links"
    )
    candidate_completeness = collection_status(
        completeness, ARTIFACT_IDENTITY, "generation_closure_candidates"
    )
    for record in _records(narrative, "release_narratives"):
        capture = str(record.get("capture_file"))
        context = record.get("session_context_reference")
        transaction = record.get("release_transaction_reference")
        if not isinstance(context, str) or not isinstance(transaction, str):
            continue
        candidates = index["candidates_by_chain"].get((capture, context, transaction), [])
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            endpoint_reference = candidate.get("bearer_endpoint_reference")
            link, ambiguous = (
                _one(index["generation_links"], (capture, context, endpoint_reference))
                if isinstance(endpoint_reference, str)
                else (None, False)
            )
            published = candidate.get("association_status") == ESTABLISHED
            checks = [
                _check(
                    CHECK_CONTEXT_PRESENT,
                    _one(index["contexts"], (capture, context))[0] is not None,
                ),
                _check(
                    CHECK_ENDPOINT_PRESENT,
                    isinstance(endpoint_reference, str)
                    and bool(_bearer_endpoint_reference(candidate.get("bearer_endpoint"), capture)),
                ),
                _check(
                    CHECK_RELATIONSHIP_TYPE,
                    None
                    if not published or ambiguous
                    else isinstance(link, dict)
                    and link.get("relationship_type") == REL_SESSION_GENERATION,
                ),
                _check(
                    CHECK_UNIQUE_CANDIDATE,
                    None
                    if not published or ambiguous
                    else isinstance(link, dict)
                    and link.get("association_status") == ESTABLISHED,
                ),
            ]
            limitations: list[str] = []
            if published and link is None and not ambiguous:
                limitations.append(
                    "the identity analysis publishes an established closure candidate whose "
                    "context-to-endpoint relationship it does not publish"
                )
            status = _status(checks, ambiguous=ambiguous, completeness=link_completeness)
            if not published and status == STATUS_VERIFIED:
                status = STATUS_NOT_APPLICABLE
            ledger.add(
                CATEGORY_SESSION_GENERATION_LINK,
                status,
                source_analysis="epc-session-identity",
                source_artifact_reference="epc-session-identity:generation_closure_candidates",
                source_subject_reference=_candidate_subject(candidate, capture),
                target_analysis="epc-session-identity",
                target_artifact_reference="epc-session-identity:session_to_generation_links",
                target_subject_reference=(
                    endpoint_reference if isinstance(endpoint_reference, str) else None
                ),
                capture_file=capture,
                relationship_type=REL_SESSION_GENERATION,
                checks=checks,
                candidate_completeness_status=(
                    _worst_status([candidate_completeness, link_completeness])
                    if published
                    else link_completeness
                ),
                proof_sufficiency_status=(
                    PROOF_SUFFICIENT if status == STATUS_VERIFIED else PROOF_INSUFFICIENT
                ),
                limitations=limitations,
            )

        for generation in _records(record, "proved_generations"):
            endpoint_key = (
                capture,
                str(generation.get("receiving_endpoint_role")),
                str(generation.get("receiving_endpoint_address")),
                _int(generation.get("receiving_endpoint_teid")) or 0,
                _int(generation.get("reviewed_interface_type")) or 0,
            )
            owners = [
                candidate
                for candidate in candidates
                if candidate.get("association_status") == ESTABLISHED
                and _candidate_endpoint_key(candidate, capture) == endpoint_key
            ]
            link_ok = False
            link_ambiguous = False
            if len(owners) == 1:
                _link, link_ambiguous, link_ok = _established_session_generation_link(
                    index,
                    capture,
                    context,
                    owners[0].get("bearer_endpoint_reference"),
                )
            checks = [
                _check(
                    CHECK_CANDIDATES_COMPLETE,
                    None if len(owners) > 1 else len(owners) == 1,
                ),
                _check(
                    CHECK_UNIQUE_CANDIDATE,
                    None
                    if len(owners) > 1 or link_ambiguous
                    else len(owners) == 1 and link_ok,
                ),
            ]
            generation_path_limitations = (
                []
                if not (_failed(checks) and not link_ambiguous)
                else [
                    "the narrative publishes a proved generation whose session-to-generation "
                    "chain the supplied identity analysis does not publish"
                ]
            )
            ledger.add(
                CATEGORY_SESSION_GENERATION_LINK,
                _status(
                    checks,
                    ambiguous=len(owners) > 1 or link_ambiguous,
                    completeness=link_completeness,
                ),
                source_analysis="epc-release-narrative",
                source_artifact_reference="epc-release-narrative:release_narratives",
                source_subject_reference=record.get("release_narrative_reference"),
                target_analysis="epc-bearer-lifecycle",
                target_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
                target_subject_reference=generation.get("generation_reference"),
                capture_file=capture,
                relationship_type=REL_SESSION_GENERATION,
                checks=checks,
                candidate_completeness_status=_worst_status(
                    [candidate_completeness, link_completeness]
                ),
                proof_sufficiency_status=(
                    PROOF_SUFFICIENT
                    if not _failed(checks) and not link_ambiguous
                    else PROOF_INSUFFICIENT
                ),
                limitations=generation_path_limitations,
            )


def audit_generation_closure(
    ledger: Ledger,
    narrative: dict[str, Any],
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """Audit each proved generation at its own endpoint; one release may close several."""
    closure_complete, closure_failures = closure_completeness(completeness)
    boundary_subjects = _boundary_subjects(index)
    completeness_status = _worst_status(
        [
            collection_status(completeness, artifact, collection)
            for artifact, collection in CLOSURE_CRITICAL_COLLECTIONS
        ]
    )
    for record in _records(narrative, "release_narratives"):
        capture = str(record.get("capture_file"))
        context = record.get("session_context_reference")
        transaction = record.get("release_transaction_reference")
        claim = record.get("generation_closure_status")
        if not isinstance(context, str) or not isinstance(transaction, str):
            continue
        candidates = index["candidates_by_chain"].get((capture, context, transaction), [])
        established = [
            candidate
            for candidate in candidates
            if candidate.get("association_status") == ESTABLISHED
        ]
        subjects = boundary_subjects.get((capture, transaction), [])
        other_release_candidates = [
            candidate
            for (key, values) in index["candidates_by_chain"].items()
            if key[0] == capture
            and key[1] == context
            and key[2] != transaction
            for candidate in values
        ]
        proved = _distinct_proved_generations(record)

        if claim == ESTABLISHED and proved:
            for generation in proved:
                generation_reference = generation.get("generation_reference")
                endpoint_key = _proved_endpoint_key(generation, capture)
                owners = _closure_endpoint_candidates(
                    established, capture, context, transaction, endpoint_key
                )
                matching = [
                    subject
                    for subject in subjects
                    if subject.get("generation_state") == GENERATION_CLOSED
                    and _subject_endpoint_key(subject) == endpoint_key
                    and subject.get("generation_reference") == generation_reference
                ]
                link_ok = False
                link_ambiguous = False
                if len(owners) == 1:
                    _link, link_ambiguous, link_ok = _established_session_generation_link(
                        index,
                        capture,
                        context,
                        owners[0].get("bearer_endpoint_reference"),
                    )
                checks = [
                    _check(
                        CHECK_CANDIDATES_COMPLETE,
                        None if not closure_complete else True,
                    ),
                    _check(
                        CHECK_UNIQUE_CANDIDATE,
                        None
                        if len(owners) > 1 or len(matching) > 1 or link_ambiguous
                        else len(owners) == 1 and len(matching) == 1 and link_ok,
                    ),
                    _check(
                        CHECK_RELEASE_TRANSACTION,
                        not (not owners and bool(other_release_candidates)),
                    ),
                ]
                limitations: list[str] = []
                if not closure_complete:
                    limitations.append(
                        "no unique bearer-generation closure is audited while a closure-critical "
                        "collection is incomplete: " + ", ".join(closure_failures)
                    )
                if len(owners) > 1:
                    limitations.append(
                        "several established closure candidates name the same bearer-generation "
                        "endpoint; the audit selects none and keeps that closure ambiguous"
                    )
                elif not owners:
                    limitations.append(
                        "the proved generation has no established closure candidate closed by "
                        "this release transaction"
                    )
                    if other_release_candidates:
                        limitations.append(
                            "a closure candidate for this context names another release "
                            "transaction, so it never justifies this release's closure"
                        )
                if len(matching) > 1:
                    limitations.append(
                        "several lifecycle subjects are closed by this release at the same "
                        "endpoint, so no single closure is audited"
                    )
                elif not matching:
                    limitations.append(
                        "no lifecycle subject closed by this release carries the proved "
                        "generation's endpoint"
                    )
                if len(owners) == 1 and not link_ok:
                    limitations.append(
                        "the session-to-generation link for this proved generation is not "
                        "explicitly established; record existence alone never proves the link"
                    )
                status = _status(
                    checks,
                    ambiguous=len(owners) > 1 or len(matching) > 1 or link_ambiguous,
                    completeness=completeness_status,
                )
                if record.get("release_outcome_status") != ACCEPTED:
                    checks.append(_check(CHECK_RELEASE_TRANSACTION, False))
                    status = STATUS_INCONSISTENT
                    limitations.append(
                        "a generation closure is claimed beside a release outcome that is not "
                        "accepted"
                    )
                ledger.add(
                    CATEGORY_GENERATION_CLOSURE,
                    status,
                    source_analysis="epc-release-narrative",
                    source_artifact_reference="epc-release-narrative:release_narratives",
                    source_subject_reference=record.get("release_narrative_reference"),
                    target_analysis="epc-bearer-lifecycle",
                    target_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
                    target_subject_reference=(
                        matching[0].get("generation_reference") if matching else None
                    ),
                    capture_file=capture,
                    relationship_type=REL_RELEASE_GENERATION,
                    source_evidence_refs=[],
                    checks=checks,
                    candidate_completeness_status=completeness_status,
                    proof_sufficiency_status=(
                        PROOF_SUFFICIENT
                        if status == STATUS_VERIFIED
                        else PROOF_INSUFFICIENT
                    ),
                    limitations=limitations,
                    additional_evidence_needed=(
                        []
                        if status == STATUS_VERIFIED
                        else [
                            "one complete closure candidate set, one established "
                            "session-to-generation link and one lifecycle subject closed by the "
                            "same release transaction are required for this generation"
                        ]
                    ),
                )
            continue

        matching: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for candidate in established:
            endpoint_key = _candidate_endpoint_key(candidate, capture)
            for subject in subjects:
                if (
                    subject.get("generation_state") == GENERATION_CLOSED
                    and _subject_endpoint_key(subject) == endpoint_key
                ):
                    matching.append((candidate, subject))
        links_established = all(
            _established_session_generation_link(
                index,
                capture,
                context,
                candidate.get("bearer_endpoint_reference"),
            )[2]
            for candidate, _subject in matching
        )
        visible_chain = (
            len(established) == 1 and len(matching) == 1 and links_established
        )
        limitations = []
        if claim == ESTABLISHED:
            checks = [
                _check(
                    CHECK_CANDIDATES_COMPLETE,
                    None if not closure_complete else True,
                ),
                _check(CHECK_UNIQUE_CANDIDATE, False),
                _check(
                    CHECK_RELEASE_TRANSACTION,
                    not (not visible_chain and bool(other_release_candidates)),
                ),
            ]
            if not closure_complete:
                limitations.append(
                    "no unique bearer-generation closure is audited while a closure-critical "
                    "collection is incomplete: " + ", ".join(closure_failures)
                )
            limitations.append(
                "the published closure promotes no proved generation, so no closure is audited"
            )
            if other_release_candidates:
                limitations.append(
                    "a closure candidate for this context names another release transaction, "
                    "so it never justifies this release's closure"
                )
            status = _status(
                checks,
                ambiguous=len(established) > 1,
                completeness=completeness_status,
            )
            proof = PROOF_INSUFFICIENT
        else:
            checks = [
                _check(
                    CHECK_CANDIDATES_COMPLETE,
                    None if not closure_complete else True,
                ),
                _check(CHECK_UNIQUE_CANDIDATE, None),
                _check(CHECK_RELEASE_TRANSACTION, None),
            ]
            if visible_chain:
                limitations.append(
                    "the accepted chain is visible but the narrative does not promote it; the "
                    "audit preserves the published refusal and promotes nothing"
                )
            if other_release_candidates:
                limitations.append(
                    "a closure candidate for this context names another release transaction; it "
                    "is published beside this release and is never used to close it"
                )
            limitations.append(
                "an accepted release outcome and an established release binding are audited "
                "separately from the bearer-generation closure"
            )
            status = _status(
                checks,
                ambiguous=len(established) > 1,
                completeness=completeness_status,
            )
            proof = PROOF_INSUFFICIENT
        if claim == ESTABLISHED and record.get("release_outcome_status") != ACCEPTED:
            checks.append(_check(CHECK_RELEASE_TRANSACTION, False))
            status = STATUS_INCONSISTENT
            limitations.append(
                "a generation closure is claimed beside a release outcome that is not accepted"
            )
        ledger.add(
            CATEGORY_GENERATION_CLOSURE,
            status,
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-bearer-lifecycle",
            target_artifact_reference="epc-bearer-lifecycle:lifecycle_subjects",
            target_subject_reference=(
                matching[0][1].get("generation_reference") if matching else None
            ),
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            source_evidence_refs=[],
            checks=checks,
            candidate_completeness_status=completeness_status,
            proof_sufficiency_status=proof,
            limitations=limitations,
            additional_evidence_needed=(
                []
                if status == STATUS_VERIFIED
                else [
                    "a complete closure candidate set and one lifecycle subject closed by the "
                    "same release transaction are required to audit a unique closure"
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Generation-scoped S1-U attribution
# ---------------------------------------------------------------------------
def scoped_direction_agrees(
    record: dict[str, Any], role: Any, stream_direction: Any
) -> bool:
    """The scoped record's direction must map to its role and the stream."""
    direction = record.get("direction")
    if not isinstance(direction, str) or not direction:
        return False
    if direction not in DIRECTION_ROLE:
        return False
    if DIRECTION_ROLE[direction] != role:
        return False
    if stream_direction is not None and stream_direction != direction:
        return False
    return True


def audit_generation_stream_attribution(
    ledger: Ledger,
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    index: dict[str, Any],
    completeness: dict[str, Any],
) -> None:
    """Audit published generation ownership; never re-derive it from endpoints."""
    scoped_completeness = collection_status(
        completeness, ARTIFACT_LIFECYCLE, "generation_scoped_s1u_observations"
    )
    for observation in _records(narrative, "temporal_observations"):
        capture = str(observation.get("capture_file"))
        generation_reference = observation.get("generation_reference")
        stream_reference = observation.get("stream_reference")
        claim = observation.get("generation_attribution_status")
        generation_capture, generation_ambiguous = _generation_capture(
            index, generation_reference
        )
        generation_record = (
            _one(index["generations"], (generation_capture, generation_reference))[0]
            if generation_capture is not None
            else None
        )
        stream = (
            _one(index["streams"], (capture, stream_reference))[0]
            if s1u is not None and isinstance(stream_reference, str)
            else None
        )
        scoped_records = (
            index["scoped"].get((capture, generation_reference, stream_reference), [])
            if isinstance(generation_reference, str) and isinstance(stream_reference, str)
            else []
        )
        claimants = (
            index["scoped_claimants"].get((capture, stream_reference), [])
            if isinstance(stream_reference, str)
            else []
        )
        unresolved = (
            index["scoped_unresolved"].get(stream_reference, [])
            if isinstance(stream_reference, str)
            else []
        )
        if generation_reference is None and claim != ATTRIBUTION_ESTABLISHED:
            ledger.add(
                CATEGORY_GENERATION_STREAM_ATTRIBUTION,
                STATUS_NOT_APPLICABLE,
                source_analysis="epc-release-narrative",
                source_artifact_reference="epc-release-narrative:temporal_observations",
                source_subject_reference=observation.get("temporal_observation_reference"),
                capture_file=capture,
                relationship_type=REL_RELEASE_GENERATION,
                checks=[_check(CHECK_GENERATION_PRESENT, None)],
                candidate_completeness_status=scoped_completeness,
                proof_sufficiency_status=PROOF_NOT_APPLICABLE,
                limitations=[
                    "the observation publishes no generation attribution, so there is no "
                    "generation-level ownership relationship to audit"
                ],
            )
            continue

        checks = [
            _check(
                CHECK_GENERATION_PRESENT,
                generation_record is not None and not generation_ambiguous,
            ),
            _check(
                CHECK_CAPTURE_AGREES,
                str((generation_record or {}).get("capture_file")) == capture,
            ),
            _check(
                CHECK_STREAM_PRESENT,
                None if s1u is None else stream is not None,
            ),
            _check(CHECK_REFERENCE_UNIQUE, None if not scoped_records else len(scoped_records) == 1),
            _check(
                CHECK_CANDIDATES_COMPLETE,
                None if scoped_completeness != COMPLETE_COLLECTION else True,
            ),
            _check(CHECK_UNIQUE_CANDIDATE, len(claimants) <= 1),
        ]
        scoped_record = scoped_records[0] if len(scoped_records) == 1 else None
        if scoped_record is not None:
            role = scoped_record.get("receiving_endpoint_role")
            stream_direction = (stream or {}).get("direction")
            checks.append(
                _check(
                    CHECK_DIRECTION_ROLE,
                    isinstance(role, str)
                    and role == (generation_record or {}).get("receiving_endpoint_role")
                    and scoped_direction_agrees(scoped_record, role, stream_direction),
                )
            )
            checks.append(
                _check(
                    CHECK_DIRECTION_STREAM,
                    None
                    if s1u is None
                    else stream_direction is not None
                    and scoped_record.get("direction") == stream_direction,
                )
            )
        limitations: list[str] = []
        if unresolved:
            limitations.append(
                "a lifecycle generation-scoped record names this stream but its generation "
                "cannot be placed in exactly one capture, so it still competes for the stream "
                "and no uniqueness is inferred from the remaining subset"
            )
        if len(scoped_records) > 1:
            limitations.append(
                "more than one lifecycle generation-scoped record names the same capture, "
                "generation and stream; the contradiction is reported and no record is selected"
            )
        if len(claimants) > 1:
            limitations.append(
                "more than one generation claims this stream reference in this capture"
            )
        if scoped_record is not None and _failed(checks):
            limitations.append(
                "the direction, receiving role or endpoint identity of the generation-scoped "
                "record does not agree with the generation and the stream it claims"
            )
        if not scoped_records:
            limitations.append(
                "the lifecycle publishes no generation-scoped S1-U observation for this "
                "generation and stream, so generation-level ownership is not published"
            )
        evidence_status = _status(
            checks,
            ambiguous=bool(unresolved) or len(scoped_records) > 1 or len(claimants) > 1,
            completeness=scoped_completeness,
        )
        if claim == ATTRIBUTION_ESTABLISHED and evidence_status != STATUS_VERIFIED:
            evidence_status = STATUS_INCONSISTENT
            limitations.append(
                "the narrative publishes generation-level ownership that the supplied "
                "lifecycle evidence does not support"
            )
        elif claim != ATTRIBUTION_ESTABLISHED and evidence_status == STATUS_VERIFIED:
            limitations.append(
                "the supplied evidence supports generation ownership but the narrative does "
                "not publish it; the audit preserves the published refusal"
            )
        if claim == ATTRIBUTION_ESTABLISHED and s1u is None:
            evidence_status = STATUS_NOT_VERIFIABLE
            limitations.append(
                "no S1-U observation was supplied, so the stream identity and direction of the "
                "published attribution are not independently re-observed"
            )
        elif (
            claim != ATTRIBUTION_ESTABLISHED
            and not scoped_records
            and not unresolved
            and scoped_completeness == COMPLETE_COLLECTION
        ):
            evidence_status = STATUS_NOT_APPLICABLE
        ledger.add(
            CATEGORY_GENERATION_STREAM_ATTRIBUTION,
            evidence_status,
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:temporal_observations",
            source_subject_reference=observation.get("temporal_observation_reference"),
            target_analysis="epc-bearer-lifecycle",
            target_artifact_reference="epc-bearer-lifecycle:generation_scoped_s1u_observations",
            target_subject_reference=(
                generation_reference if isinstance(generation_reference, str) else None
            ),
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            source_evidence_refs=(scoped_record or {}).get("packet_evidence_refs"),
            checks=checks,
            candidate_completeness_status=scoped_completeness,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if evidence_status == STATUS_VERIFIED
                else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
            additional_evidence_needed=(
                []
                if evidence_status == STATUS_VERIFIED
                else [
                    "exactly one internally consistent lifecycle generation-scoped S1-U "
                    "observation naming this generation and this stream is required"
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Narrative stages
# ---------------------------------------------------------------------------
STAGE_REQUIRED = (
    "ALLOCATION_OBSERVED",
    "ALLOCATION_ACCEPTED",
    "SESSION_CONTEXT_ESTABLISHED",
    "BEARER_ASSOCIATION_ESTABLISHED",
    "RELEASE_REQUEST_OBSERVED",
    "RELEASE_OUTCOME_ACCEPTED",
    "RELEASE_OUTCOME_REJECTED_OBSERVED",
    "RELEASE_OUTCOME_UNRESOLVED",
    "RELEASE_SESSION_BINDING_ESTABLISHED",
    "RELEASE_SESSION_BINDING_NOT_ESTABLISHED",
    "GENERATION_CLOSURE_ESTABLISHED",
    "GENERATION_CLOSURE_NOT_ESTABLISHED",
    "RELEASE_EFFECTIVE_INSTANT_UNPROVED",
)

OUTCOME_STAGE = {
    ACCEPTED: "RELEASE_OUTCOME_ACCEPTED",
    REJECTED_OBSERVED: "RELEASE_OUTCOME_REJECTED_OBSERVED",
    UNRESOLVED: "RELEASE_OUTCOME_UNRESOLVED",
}
OUTCOME_STATUS = {
    ACCEPTED: "ACCEPTED",
    REJECTED_OBSERVED: "REJECTED_OBSERVED",
    UNRESOLVED: "UNRESOLVED",
}


def audit_narrative_stages(
    ledger: Ledger,
    narrative: dict[str, Any],
) -> None:
    """Reporting stages must not contradict the published summary."""
    for record in _records(narrative, "release_narratives"):
        capture = record.get("capture_file")
        stages = _records(record, "stages")
        by_name = {
            stage.get("stage"): stage
            for stage in stages
            if stage.get("stage") in STAGE_REQUIRED
        }
        checks = [
            _check(CHECK_RECORD_PRESENT, len(by_name) == len(stages) and bool(stages)),
            _check(
                CHECK_STAGE_STATUS,
                by_name.get(OUTCOME_STAGE.get(record.get("release_outcome_status"), "")) is not None
                and by_name[OUTCOME_STAGE[record.get("release_outcome_status")]].get(
                    "evidence_status"
                )
                == OUTCOME_STATUS[record.get("release_outcome_status")],
            ),
            _check(
                CHECK_STAGE_STATUS,
                by_name.get(
                    "RELEASE_SESSION_BINDING_ESTABLISHED"
                    if record.get("release_session_binding_status") == ESTABLISHED
                    else "RELEASE_SESSION_BINDING_NOT_ESTABLISHED"
                )
                is not None,
            ),
            _check(
                CHECK_STAGE_STATUS,
                by_name.get(
                    "GENERATION_CLOSURE_ESTABLISHED"
                    if record.get("generation_closure_status") == ESTABLISHED
                    else "GENERATION_CLOSURE_NOT_ESTABLISHED"
                )
                is not None,
            ),
            _check(
                CHECK_STAGE_STATUS,
                by_name.get("RELEASE_EFFECTIVE_INSTANT_UNPROVED") is not None
                and record.get("release_effective_frame_proven") is False,
            ),
        ]
        ledger.add(
            CATEGORY_RELEASE_NARRATIVE_STAGE,
            _status(checks),
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:release_narratives",
            source_subject_reference=record.get("release_narrative_reference"),
            target_analysis="epc-release-narrative",
            target_artifact_reference="epc-release-narrative:stages",
            target_subject_reference=record.get("release_transaction_reference"),
            capture_file=capture,
            relationship_type=REL_RELEASE_BINDING,
            source_evidence_refs=[],
            checks=checks,
            candidate_completeness_status=COMPLETE_COLLECTION,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if not _failed(checks) else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if not _failed(checks)
                else [
                    "a reporting stage contradicts the published outcome, binding or closure "
                    "summary, or a required stage is missing"
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Temporal frame partitions
# ---------------------------------------------------------------------------
def _gtpu_frame_index(
    gtpu_events: list[dict[str, Any]] | None,
) -> dict[tuple[str, str, str, int], list[dict[str, int]]]:
    grouped: dict[tuple[str, str, str, int], list[dict[str, int]]] = {}
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
        capture = event.get("capture_file")
        if not isinstance(source, str) or not isinstance(destination, str) or teid is None:
            continue
        grouped.setdefault((str(capture), source, destination, teid), []).append(
            {
                "frame_number": frame,
                "payload_octets": _int(header.get("message_length")) or 0,
            }
        )
    for key in grouped:
        grouped[key].sort(key=lambda item: item["frame_number"])
    return grouped


def _stream_key(stream: dict[str, Any] | None) -> tuple[str, str, str, int] | None:
    if not isinstance(stream, dict):
        return None
    capture = stream.get("capture_file")
    source = stream.get("outer_source")
    destination = stream.get("outer_destination")
    teid = _int(stream.get("teid"))
    if not isinstance(capture, str) or not isinstance(source, str) or not isinstance(destination, str):
        return None
    if teid is None:
        return None
    return (capture, source, destination, teid)


def duplicate_frame_claims(
    observations: list[dict[str, Any]],
    index: dict[str, Any],
    frame_index: dict[tuple[str, str, str, int], list[dict[str, int]]],
) -> dict[tuple[str, int], list[str]]:
    """Frames claimed by more than one established temporal partition."""
    claims: dict[tuple[str, int], list[str]] = {}
    for observation in observations:
        if observation.get("temporal_placement_status") != PLACEMENT_ESTABLISHED:
            continue
        capture = observation.get("capture_file")
        stream, _ = (
            _one(index["streams"], (str(capture), observation.get("stream_reference")))
            if isinstance(capture, str)
            else (None, False)
        )
        key = _stream_key(stream)
        if key is None:
            continue
        for event in frame_index.get(key, []):
            claims.setdefault((str(capture), event["frame_number"]), []).append(
                str(observation.get("temporal_observation_reference"))
            )
    return {
        key: sorted(set(owners))
        for key, owners in claims.items()
        if len(set(owners)) > 1
    }


def _partition_values(partitions: Any, name: str) -> dict[str, Any]:
    if not isinstance(partitions, dict):
        return {}
    value = partitions.get(name)
    return value if isinstance(value, dict) else {}


def _observed_subset_form(observation: dict[str, Any]) -> bool:
    """A bounded partial observation is valid observed evidence, not corruption."""
    return (
        observation.get("temporal_placement_status") == PLACEMENT_NOT_ESTABLISHED
        and observation.get("partition_scope") == SCOPE_SUBSET
        and observation.get("partition_conserved") is False
    )


def _partition_span_ok(
    partitions: Any, request: int | None, confirmation: int | None
) -> bool:
    for name in PARTITIONS:
        part = _partition_values(partitions, name)
        first = _int(part.get("first_frame"))
        last = _int(part.get("last_frame"))
        if name == PARTITION_BEFORE:
            if last is not None and request is not None and last >= request:
                return False
            if first is not None and request is not None and first >= request:
                return False
        elif name == PARTITION_PENDING:
            if request is not None and first is not None and first < request:
                return False
            if confirmation is not None and last is not None and last > confirmation:
                return False
        else:
            if confirmation is not None and first is not None and first <= confirmation:
                return False
            if confirmation is not None and last is not None and last <= confirmation:
                return False
    return True


def audit_temporal_partitions(
    ledger: Ledger,
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    index: dict[str, Any],
    completeness: dict[str, Any],
    gtpu_events: list[dict[str, Any]] | None,
) -> None:
    """Frame-level placement stays conservative and never interpolates."""
    observations = _records(narrative, "temporal_observations")
    frame_index = _gtpu_frame_index(gtpu_events)
    conflicts = (
        duplicate_frame_claims(observations, index, frame_index)
        if gtpu_events is not None
        else {}
    )
    temporal_completeness = collection_status(
        completeness, ARTIFACT_NARRATIVE, "temporal_observations"
    )
    for observation in observations:
        capture = str(observation.get("capture_file"))
        reference = observation.get("temporal_observation_reference")
        placement = observation.get("temporal_placement_status")
        partitions = observation.get("partitions")
        aggregate_count = _int(observation.get("observed_g_pdu_count")) or 0
        aggregate_octets = _int(observation.get("observed_payload_octets")) or 0
        counts = {
            name: (_int(_partition_values(partitions, name).get("g_pdu_count")) or 0)
            for name in PARTITIONS
        }
        octets = {
            name: (_int(_partition_values(partitions, name).get("payload_octets")) or 0)
            for name in PARTITIONS
        }
        sum_count = sum(counts.values())
        sum_octets = sum(octets.values())
        request = _int(observation.get("release_request_frame"))
        confirmation = _int(observation.get("release_confirmation_frame"))
        checks = [
            _check(
                CHECK_CANDIDATES_COMPLETE,
                None if temporal_completeness != COMPLETE_COLLECTION else True,
            ),
        ]
        limitations: list[str] = []
        if placement == PLACEMENT_ESTABLISHED:
            checks.extend(
                [
                    _check(CHECK_PARTITION_CONVERVES, sum_count == aggregate_count),
                    _check(CHECK_PARTITION_CONVERVES, sum_octets == aggregate_octets),
                    _check(CHECK_PARTITION_WINDOW, _partition_span_ok(partitions, request, confirmation)),
                    _check(CHECK_FRAME_EXCLUSIVE, not observation.get("duplicate_frame_ownership")),
                ]
            )
            if sum_count != aggregate_count or sum_octets != aggregate_octets:
                limitations.append(
                    "the published partitions do not reproduce the aggregate G-PDU count or "
                    "payload octets, so a complete placement is not conserved"
                )
            if not _partition_span_ok(partitions, request, confirmation):
                limitations.append(
                    "a partition frame lies outside its release window boundary"
                )
            if observation.get("partition_scope") != SCOPE_COMPLETE:
                checks.append(_check(CHECK_PARTITION_CONVERVES, False))
                limitations.append(
                    "an established placement must publish the COMPLETE_STREAM scope"
                )
        else:
            scope = observation.get("partition_scope")
            conserved = observation.get("partition_conserved")
            if partitions is None:
                checks.append(
                    _check(
                        CHECK_PARTITION_CONVERVES,
                        scope != SCOPE_COMPLETE and conserved is not True,
                    )
                )
                if scope == SCOPE_COMPLETE or conserved is True:
                    limitations.append(
                        "a non-established placement publishes a complete scope or a "
                        "conserved partition claim"
                    )
            else:
                subset_form = _observed_subset_form(observation)
                checks.append(_check(CHECK_PARTITION_CONVERVES, subset_form))
                if not subset_form:
                    limitations.append(
                        "a non-established placement publishes a partition that is not the "
                        "accepted OBSERVED_SUBSET form; the observed subset is not promoted"
                    )
                else:
                    checks.append(
                        _check(
                            CHECK_PARTITION_CONVERVES,
                            sum_count <= aggregate_count
                            and sum_octets <= aggregate_octets,
                        )
                    )
                    checks.append(
                        _check(
                            CHECK_PARTITION_WINDOW,
                            _partition_span_ok(partitions, request, confirmation),
                        )
                    )
                    checks.append(
                        _check(
                            CHECK_FRAME_EXCLUSIVE,
                            not observation.get("duplicate_frame_ownership"),
                        )
                    )
                    limitations.append(
                        "the observed subset keeps only its own frame positions; the complete "
                        "stream placement is not established and stays unproved"
                    )
                    if sum_count == 0:
                        limitations.append(
                            "the observed subset counts no frame, so it proves no temporal "
                            "placement"
                        )
        if observation.get("duplicate_frame_ownership"):
            checks.append(_check(CHECK_FRAME_EXCLUSIVE, False))
            limitations.append(
                "another release narrative claims at least one of these G-PDU frames; the frame "
                "is counted in no partition and no owner is selected"
            )
        if gtpu_events is None:
            checks.append(_check(CHECK_FRAME_PRESENT, None))
            limitations.append(
                "no detailed GTP-U events were supplied, so frame-level placement is not "
                "independently re-observable and stays NOT_INDEPENDENTLY_VERIFIABLE"
            )
        else:
            stream, _ = (
                _one(index["streams"], (capture, observation.get("stream_reference")))
                if s1u is not None
                else (None, False)
            )
            key = _stream_key(stream)
            observed_frames = {event["frame_number"] for event in frame_index.get(key, [])} if key else set()
            anchors = [
                frame
                for frame in (
                    _int(observation.get("first_observed_frame")),
                    _int(observation.get("last_observed_frame")),
                )
                if frame is not None
            ]
            present = bool(anchors) and all(frame in observed_frames for frame in anchors)
            checks.append(_check(CHECK_FRAME_PRESENT, present if anchors else None))
            if anchors and not present:
                limitations.append(
                    "a published first or last observed frame is not present in the supplied "
                    "GTP-U events for this stream; no missing frame is fabricated or substituted"
                )
            if conflicts:
                checks.append(_check(CHECK_FRAME_EXCLUSIVE, False))
                limitations.append(
                    "one or more G-PDU frames are claimed by more than one temporal partition; "
                    "the conflict stays visible and no frame is assigned twice"
                )
        status = _status(checks, completeness=temporal_completeness)
        if gtpu_events is None and not _failed(checks):
            status = STATUS_NOT_VERIFIABLE
        ledger.add(
            CATEGORY_TEMPORAL_FRAME_PARTITION,
            status,
            source_analysis="epc-release-narrative",
            source_artifact_reference="epc-release-narrative:temporal_observations",
            source_subject_reference=reference,
            target_analysis="epc-s1u-observation",
            target_artifact_reference="epc-s1u-observation:stream_observations",
            target_subject_reference=observation.get("stream_reference"),
            capture_file=capture,
            relationship_type=REL_RELEASE_GENERATION,
            source_evidence_refs=[],
            checks=checks,
            candidate_completeness_status=temporal_completeness,
            proof_sufficiency_status=(
                PROOF_SUFFICIENT
                if status == STATUS_VERIFIED and placement == PLACEMENT_ESTABLISHED
                else PROOF_NOT_APPLICABLE
                if status == STATUS_VERIFIED and partitions is None
                else PROOF_INSUFFICIENT
            ),
            limitations=limitations,
            additional_evidence_needed=(
                []
                if status == STATUS_VERIFIED
                else [
                    "complete frame-level GTP-U events reproducing the accepted aggregate are "
                    "required to audit a complete temporal partition"
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Accounting conservation
# ---------------------------------------------------------------------------
def audit_accounting(
    ledger: Ledger,
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    completeness: dict[str, Any],
    gtpu_events: list[dict[str, Any]] | None,
) -> None:
    """Producer counts stay unchanged; audit-derived checks are labelled."""
    accounting = lifecycle.get("accounting") if isinstance(lifecycle.get("accounting"), dict) else {}
    aggregate_packets = _int(accounting.get("aggregate_g_pdu_count"))
    attributed_packets = _int(accounting.get("attributed_g_pdu_count"))
    unresolved_packets = _int(accounting.get("unresolved_g_pdu_count"))
    aggregate_octets = _int(accounting.get("aggregate_payload_octets"))
    attributed_octets = _int(accounting.get("attributed_payload_octets"))
    unresolved_octets = _int(accounting.get("unresolved_payload_octets"))
    packet_conserved = (
        aggregate_packets is not None
        and attributed_packets is not None
        and unresolved_packets is not None
        and aggregate_packets == attributed_packets + unresolved_packets
    )
    octet_conserved = (
        aggregate_octets is not None
        and attributed_octets is not None
        and unresolved_octets is not None
        and aggregate_octets == attributed_octets + unresolved_octets
    )
    checks = [
        _check(CHECK_ACCOUNTING, packet_conserved),
        _check(CHECK_ACCOUNTING, octet_conserved),
        _check(
            CHECK_PRODUCER_COUNT,
            accounting.get("conserved_g_pdu") is packet_conserved
            and accounting.get("conserved_payload_octets") is octet_conserved,
        ),
    ]
    ledger.add(
        CATEGORY_ACCOUNTING_CONSERVATION,
        _status(checks),
        source_analysis="epc-bearer-lifecycle",
        source_artifact_reference="epc-bearer-lifecycle:accounting",
        source_subject_reference="accounting",
        capture_file=None,
        relationship_type=None,
        checks=checks,
        candidate_completeness_status=collection_status(
            completeness, ARTIFACT_LIFECYCLE, "lifecycle_subjects"
        ),
        proof_sufficiency_status=(
            PROOF_SUFFICIENT if not _failed(checks) else PROOF_INSUFFICIENT
        ),
        limitations=(
            []
            if not _failed(checks)
            else [
                "the published producer counts do not satisfy their own conservation identity; "
                "the audit reports the mismatch and never rewrites a producer count"
            ]
        ),
    )

    if s1u is not None:
        streams = _records(s1u, "stream_observations")
        complete = collection_status(
            completeness, ARTIFACT_S1U, "stream_observations"
        ) == COMPLETE_COLLECTION
        declared_packets = _int(s1u.get("observed_g_pdu_packet_count"))
        declared_octets = _int(s1u.get("observed_payload_byte_count"))
        sum_packets: int | None = None
        sum_octets: int | None = None
        if complete and all(isinstance(stream.get("observed_g_pdu_packet_count"), int) for stream in streams):
            sum_packets = sum(int(stream.get("observed_g_pdu_packet_count")) for stream in streams)
        if complete and all(isinstance(stream.get("observed_payload_byte_count"), int) for stream in streams):
            sum_octets = sum(int(stream.get("observed_payload_byte_count")) for stream in streams)
        checks = [
            _check(
                CHECK_ACCOUNTING,
                None
                if sum_packets is None or declared_packets is None
                else sum_packets == declared_packets,
            ),
            _check(
                CHECK_ACCOUNTING,
                None
                if sum_octets is None or declared_octets is None
                else sum_octets == declared_octets,
            ),
            _check(CHECK_PRODUCER_COUNT, complete),
        ]
        ledger.add(
            CATEGORY_ACCOUNTING_CONSERVATION,
            _status(checks),
            source_analysis="epc-s1u-observation",
            source_artifact_reference="epc-s1u-observation:observed_totals",
            source_subject_reference="accounting",
            relationship_type=None,
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_S1U, "stream_observations"
            ),
            proof_sufficiency_status=(
                PROOF_SUFFICIENT if not _failed(checks) else PROOF_INSUFFICIENT
            ),
            limitations=(
                []
                if not _failed(checks)
                else [
                    "the published stream records do not reproduce the published S1-U totals"
                ]
            ),
        )

    temporal = narrative.get("temporal_accounting")
    temporal = temporal if isinstance(temporal, dict) else {}
    observed = _int(temporal.get("observed_g_pdu_event_count"))
    assigned = _int(temporal.get("assigned_to_release_window_count"))
    unassigned = _int(temporal.get("unassigned_g_pdu_event_count"))
    duplicates = _int(temporal.get("duplicate_assignment_count"))
    arithmetic = (
        observed is not None
        and assigned is not None
        and unassigned is not None
        and duplicates is not None
        and observed == assigned + unassigned + duplicates
    )
    checks = [
        _check(CHECK_ACCOUNTING, arithmetic),
        _check(CHECK_PRODUCER_COUNT, temporal.get("conserved") is arithmetic),
        _check(
            CHECK_FRAME_PRESENT,
            None
            if gtpu_events is None
            else bool(temporal.get("frame_level_evidence_supplied"))
            and bool(gtpu_events),
        ),
    ]
    ledger.add(
        CATEGORY_ACCOUNTING_CONSERVATION,
        _status(checks, not_verifiable=gtpu_events is None),
        source_analysis="epc-release-narrative",
        source_artifact_reference="epc-release-narrative:temporal_accounting",
        source_subject_reference="accounting",
        relationship_type=None,
        checks=checks,
        candidate_completeness_status=collection_status(
            completeness, ARTIFACT_NARRATIVE, "temporal_observations"
        ),
        proof_sufficiency_status=(
            PROOF_SUFFICIENT if not _failed(checks) and gtpu_events is not None else PROOF_INSUFFICIENT
        ),
        limitations=(
            []
            if not _failed(checks) and gtpu_events is not None
            else [
                "the temporal accounting is audited arithmetically; without detailed GTP-U "
                "events it is not independently re-derived from frames"
            ]
        ),
    )

    if gtpu_events is not None and s1u is not None:
        frame_totals = _gtpu_frame_index(gtpu_events)
        audit_packets = sum(len(events) for events in frame_totals.values())
        audit_octets = sum(
            event["payload_octets"] for events in frame_totals.values() for event in events
        )
        declared_packets = _int(s1u.get("observed_g_pdu_packet_count"))
        declared_octets = _int(s1u.get("observed_payload_byte_count"))
        complete = collection_status(
            completeness, ARTIFACT_S1U, "stream_observations"
        ) == COMPLETE_COLLECTION
        observed_subset = any(
            observation.get("partition_scope") == SCOPE_SUBSET
            and observation.get("partition_conserved") is False
            for observation in _records(narrative, "temporal_observations")
        )
        subset_within_aggregate = (
            observed_subset
            and audit_packets <= (declared_packets or 0)
            and audit_octets <= (declared_octets or 0)
        )
        checks = [
            _check(
                CHECK_ACCOUNTING,
                None
                if subset_within_aggregate
                else audit_packets == (declared_packets or 0),
            ),
            _check(
                CHECK_ACCOUNTING,
                None
                if subset_within_aggregate
                else audit_octets == (declared_octets or 0),
            ),
            _check(CHECK_CANDIDATES_COMPLETE, complete),
        ]
        ledger.add(
            CATEGORY_ACCOUNTING_CONSERVATION,
            _status(checks),
            source_analysis="audit-derived",
            source_artifact_reference="audit-derived:gtpu-frame-totals",
            source_subject_reference="accounting",
            relationship_type=None,
            checks=checks,
            candidate_completeness_status=collection_status(
                completeness, ARTIFACT_S1U, "stream_observations"
            ),
            proof_sufficiency_status=(
                PROOF_INSUFFICIENT
                if observed_subset or _failed(checks)
                else PROOF_SUFFICIENT
            ),
            limitations=(
                [
                    "these totals are audit-derived from the supplied frame-level events; they are "
                    "never written back into any producer count",
                    "the supplied frames reproduce only the published OBSERVED_SUBSET, so the "
                    "complete-stream packet and octet totals stay unproved",
                ]
                if observed_subset
                else [
                    "these totals are audit-derived from the supplied frame-level events; they are "
                    "never written back into any producer count"
                ]
            ),
        )


# ---------------------------------------------------------------------------
# Summaries and document assembly
# ---------------------------------------------------------------------------
def _status_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in AUDIT_STATUSES}
    for record in records:
        status = str(record.get("audit_status"))
        counts[status] = counts.get(status, 0) + 1
    return {key: counts[key] for key in sorted(counts)}


def build_audit_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts = _status_counts(records)
    category_counts = {category: 0 for category in AUDIT_CATEGORIES}
    for record in records:
        category = str(record.get("audit_category"))
        category_counts[category] = category_counts.get(category, 0) + 1
    if counts.get(STATUS_INCONSISTENT):
        overall = "AUDIT_INCONSISTENT"
    elif any(
        counts.get(status)
        for status in (
            STATUS_AMBIGUOUS,
            STATUS_TRUNCATED,
            STATUS_METADATA_INVALID,
            STATUS_NOT_VERIFIABLE,
        )
    ):
        overall = "AUDIT_LIMITED"
    elif counts.get(STATUS_VERIFIED):
        overall = "AUDIT_CONSISTENT"
    else:
        overall = "AUDIT_EMPTY"
    return {
        "overall_status": overall,
        "record_count": len(records),
        "status_counts": counts,
        "category_counts": {key: category_counts[key] for key in sorted(category_counts)},
        "verified_count": counts.get(STATUS_VERIFIED, 0),
        "inconsistent_count": counts.get(STATUS_INCONSISTENT, 0),
        "ambiguous_count": counts.get(STATUS_AMBIGUOUS, 0),
        "source_truncated_count": counts.get(STATUS_TRUNCATED, 0),
        "source_metadata_invalid_count": counts.get(STATUS_METADATA_INVALID, 0),
        "not_independently_verifiable_count": counts.get(STATUS_NOT_VERIFIABLE, 0),
        "not_applicable_count": counts.get(STATUS_NOT_APPLICABLE, 0),
    }


def build_reference_integrity_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    references = [
        record
        for record in records
        if record.get("audit_category") == CATEGORY_REFERENCE_INTEGRITY
    ]
    contradiction_tokens = {
        CHECK_CAPTURE_AGREES,
        CHECK_RELATIONSHIP_TYPE,
        CHECK_ENDPOINT_IDENTITY,
        CHECK_RELEASE_TRANSACTION,
    }
    contradictory = sum(
        1
        for record in references
        if any(
            check.get("check") in contradiction_tokens
            and check.get("result") == CHECK_FAIL
            for check in record.get("consistency_checks") or []
        )
    )
    missing = sum(
        1
        for record in references
        if any(
            check.get("check") in (CHECK_RECORD_PRESENT, CHECK_CONTEXT_PRESENT, CHECK_ENDPOINT_PRESENT, CHECK_GENERATION_PRESENT, CHECK_STREAM_PRESENT)
            and check.get("result") == CHECK_FAIL
            for check in record.get("consistency_checks") or []
        )
    )
    return {
        "references_checked": len(references),
        "references_resolved": sum(
            1 for record in references if record.get("audit_status") == STATUS_VERIFIED
        ),
        "references_missing": missing,
        "references_ambiguous": sum(
            1 for record in references if record.get("audit_status") == STATUS_AMBIGUOUS
        ),
        "references_contradictory": contradictory,
        "references_not_independently_verifiable": sum(
            1
            for record in references
            if record.get("audit_status") == STATUS_NOT_VERIFIABLE
        ),
        "capture_scoped": True,
    }


def build_capture_scope_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    scope_records = [
        record for record in records if record.get("audit_category") == CATEGORY_CAPTURE_SCOPE
    ]
    captures = sorted(
        {
            str(record.get("capture_file"))
            for record in records
            if record.get("capture_file")
        }
    )
    return {
        "captures": captures,
        "capture_count": len(captures),
        "cross_capture_rejections": sum(
            1 for record in scope_records if record.get("audit_status") == STATUS_INCONSISTENT
        ),
        "cross_capture_value_collisions": sum(
            1
            for record in scope_records
            if any(
                check.get("check") == CHECK_FRAME_CAPTURE_LOCAL
                and check.get("result") == CHECK_PASS
                for check in record.get("consistency_checks") or []
            )
        ),
        "artifacts_with_reference_mismatch": sum(
            1 for record in scope_records if record.get("audit_status") == STATUS_INCONSISTENT
        ),
    }


def build_temporal_integrity_summary(
    narrative: dict[str, Any],
    records: list[dict[str, Any]],
    gtpu_events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    observations = _records(narrative, "temporal_observations")
    temporal_records = [
        record
        for record in records
        if record.get("audit_category") == CATEGORY_TEMPORAL_FRAME_PARTITION
    ]
    return {
        "temporal_observation_count": len(observations),
        "established_placement_count": sum(
            1
            for observation in observations
            if observation.get("temporal_placement_status") == PLACEMENT_ESTABLISHED
        ),
        "not_established_placement_count": sum(
            1
            for observation in observations
            if observation.get("temporal_placement_status") != PLACEMENT_ESTABLISHED
        ),
        "incomplete_partition_count": sum(
            1
            for observation in observations
            if observation.get("partition_basis")
            in (
                "FRAME_LEVEL_EVENTS_INCOMPLETE",
                "FRAME_LEVEL_EVENTS_CONFLICTED",
                "GENERATION_ATTRIBUTION_NOT_ESTABLISHED",
            )
        ),
        "conflicted_partition_count": sum(
            1 for observation in observations if observation.get("duplicate_frame_ownership")
        ),
        "frame_level_evidence_supplied": gtpu_events is not None,
        "audit_verified_placement_count": sum(
            1 for record in temporal_records if record.get("audit_status") == STATUS_VERIFIED
        ),
        "missing_frame_evidence_count": sum(
            1
            for record in temporal_records
            if record.get("audit_status") == STATUS_NOT_VERIFIABLE
        ),
        "partition_duplicate_assignment_count": sum(
            len(record.get("limitations") or [])
            for record in temporal_records
            if any(
                check.get("check") == CHECK_FRAME_EXCLUSIVE
                and check.get("result") == CHECK_FAIL
                for check in record.get("consistency_checks") or []
            )
        ),
    }


def build_accounting_integrity_summary(
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    records: list[dict[str, Any]],
    gtpu_events: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    accounting = lifecycle.get("accounting") if isinstance(lifecycle.get("accounting"), dict) else {}
    temporal = (
        narrative.get("temporal_accounting")
        if isinstance(narrative.get("temporal_accounting"), dict)
        else {}
    )
    accounting_records = [
        record
        for record in records
        if record.get("audit_category") == CATEGORY_ACCOUNTING_CONSERVATION
    ]
    frame_index = _gtpu_frame_index(gtpu_events) if gtpu_events is not None else {}
    audit_packets = (
        sum(len(events) for events in frame_index.values()) if gtpu_events is not None else None
    )
    audit_octets = (
        sum(
            event["payload_octets"] for events in frame_index.values() for event in events
        )
        if gtpu_events is not None
        else None
    )
    return {
        "producer_lifecycle": {
            "aggregate_g_pdu_count": accounting.get("aggregate_g_pdu_count"),
            "attributed_g_pdu_count": accounting.get("attributed_g_pdu_count"),
            "unresolved_g_pdu_count": accounting.get("unresolved_g_pdu_count"),
            "aggregate_payload_octets": accounting.get("aggregate_payload_octets"),
            "attributed_payload_octets": accounting.get("attributed_payload_octets"),
            "unresolved_payload_octets": accounting.get("unresolved_payload_octets"),
            "conserved_g_pdu": accounting.get("conserved_g_pdu"),
            "conserved_payload_octets": accounting.get("conserved_payload_octets"),
        },
        "producer_s1u": (
            {
                "observed_g_pdu_packet_count": (s1u or {}).get("observed_g_pdu_packet_count"),
                "observed_payload_byte_count": (s1u or {}).get("observed_payload_byte_count"),
                "stream_count": (s1u or {}).get("stream_count"),
            }
            if s1u is not None
            else None
        ),
        "producer_temporal": {
            "frame_level_evidence_supplied": temporal.get("frame_level_evidence_supplied"),
            "observed_g_pdu_event_count": temporal.get("observed_g_pdu_event_count"),
            "assigned_to_release_window_count": temporal.get(
                "assigned_to_release_window_count"
            ),
            "unassigned_g_pdu_event_count": temporal.get("unassigned_g_pdu_event_count"),
            "duplicate_assignment_count": temporal.get("duplicate_assignment_count"),
            "conserved": temporal.get("conserved"),
        },
        "audit_derived": {
            "gtpu_event_g_pdu_count": audit_packets,
            "gtpu_event_payload_octets": audit_octets,
            "frames_available": gtpu_events is not None,
            "source_counts_unchanged": True,
            "lifecycle_packet_conserved": any(
                check.get("check") == CHECK_ACCOUNTING
                and check.get("result") == CHECK_PASS
                for record in accounting_records
                if record.get("source_artifact_reference")
                == "epc-bearer-lifecycle:accounting"
                for check in (record.get("consistency_checks") or [])[:1]
            ),
            "lifecycle_octets_conserved": all(
                check.get("result") != CHECK_FAIL
                for record in accounting_records
                if record.get("source_analysis") == "epc-bearer-lifecycle"
                for check in record.get("consistency_checks") or []
            ),
            "accounting_records_verified": sum(
                1
                for record in accounting_records
                if record.get("audit_status") == STATUS_VERIFIED
            ),
            "accounting_records_inconsistent": sum(
                1
                for record in accounting_records
                if record.get("audit_status") == STATUS_INCONSISTENT
            ),
        },
    }


def build_source_artifact_inventory(
    identity: dict[str, Any],
    lifecycle: dict[str, Any],
    narrative: dict[str, Any],
    s1u: dict[str, Any] | None,
    gtpv2_events: list[dict[str, Any]] | None,
    gtpu_events: list[dict[str, Any]] | None,
    completeness: dict[str, Any],
) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    documents = (
        (ARTIFACT_IDENTITY, identity, "hop_local_contexts", "hop_local_context_count"),
        (ARTIFACT_LIFECYCLE, lifecycle, "lifecycle_subjects", "lifecycle_subject_count"),
        (ARTIFACT_NARRATIVE, narrative, "release_narratives", "release_narrative_count"),
        (ARTIFACT_S1U, s1u, "stream_observations", "stream_count"),
    )
    for artifact, document, collection, count_key in documents:
        supplied = document is not None
        records = _records(document, collection)
        inventory.append(
            {
                "artifact": artifact,
                "analysis_name": (document or {}).get("analysis_name"),
                "supplied": supplied,
                "capture_files": sorted(
                    {
                        label
                        for label in (
                            _capture_label(record.get("capture_file")) for record in records
                        )
                        if label
                    }
                ),
                "record_count": len(records),
                "declared_count": (document or {}).get(count_key),
                "completeness_status": (
                    collection_status(completeness, artifact, collection)
                    if supplied
                    else COMPLETENESS_NOT_SUPPLIED
                ),
                "note": (
                    "supplied and audited read-only"
                    if supplied
                    else "not supplied; reported as a coverage limitation, never as an inconsistency"
                ),
            }
        )
    for artifact, events, expected in (
        (ARTIFACT_GTPV2, gtpv2_events, "GTPv2-C"),
        (ARTIFACT_GTPU, gtpu_events, "GTP-U"),
    ):
        inventory.append(
            {
                "artifact": artifact,
                "analysis_name": expected,
                "supplied": events is not None,
                "capture_files": sorted(
                    {
                        label
                        for label in (
                            _capture_label(event.get("capture_file"))
                            for event in events or []
                            if isinstance(event, dict)
                        )
                        if label
                    }
                ),
                "record_count": len(events) if events is not None else 0,
                "declared_count": len(events) if events is not None else None,
                "completeness_status": (
                    COMPLETE_COLLECTION if events is not None else COMPLETENESS_NOT_SUPPLIED
                ),
                "note": (
                    "supplied and used only to re-observe published frame anchors"
                    if events is not None
                    else "not supplied; frame-level anchors stay NOT_INDEPENDENTLY_VERIFIABLE"
                ),
            }
        )
    return inventory


def analyze(
    identity: dict[str, Any] | None,
    lifecycle: dict[str, Any] | None,
    narrative: dict[str, Any] | None,
    s1u: dict[str, Any] | None = None,
    gtpv2_events: list[dict[str, Any]] | None = None,
    gtpu_events: list[dict[str, Any]] | None = None,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the bounded read-only EPC evidence-audit ledger."""
    if not isinstance(identity, dict):
        raise AuditInputError("EPC session-identity analysis is required and must be an object")
    if not isinstance(lifecycle, dict):
        raise AuditInputError("EPC bearer-lifecycle analysis is required and must be an object")
    if not isinstance(narrative, dict):
        raise AuditInputError("EPC release-narrative analysis is required and must be an object")
    if s1u is not None and not isinstance(s1u, dict):
        raise AuditInputError("EPC S1-U observation must be an object when supplied")
    if gtpv2_events is not None and not isinstance(gtpv2_events, list):
        raise AuditInputError("GTPv2-C events must be a list when supplied")
    if gtpu_events is not None and not isinstance(gtpu_events, list):
        raise AuditInputError("GTP-U events must be a list when supplied")

    completeness = build_source_completeness(identity, lifecycle, narrative, s1u)
    index = build_indexes(identity, lifecycle, narrative, s1u)
    ledger = Ledger()
    audit_source_artifacts(
        ledger, identity, lifecycle, narrative, s1u, gtpv2_events, gtpu_events, completeness
    )
    audit_completeness(ledger, completeness)
    audit_reference_integrity(
        ledger, identity, lifecycle, narrative, s1u, index, completeness
    )
    audit_capture_scope(
        ledger, identity, lifecycle, narrative, s1u, index, gtpv2_events, gtpu_events
    )
    audit_transaction_anchors(ledger, narrative, index, gtpv2_events, completeness)
    audit_session_context_links(ledger, narrative, index, completeness)
    audit_cross_interface(ledger, narrative, identity, index, completeness)
    audit_release_bindings(ledger, narrative, index, completeness)
    audit_session_generation_links(ledger, narrative, index, completeness)
    audit_generation_closure(ledger, narrative, index, completeness)
    audit_generation_stream_attribution(ledger, narrative, s1u, index, completeness)
    audit_narrative_stages(ledger, narrative)
    audit_temporal_partitions(
        ledger, narrative, s1u, index, completeness, gtpu_events
    )
    audit_accounting(ledger, lifecycle, narrative, s1u, completeness, gtpu_events)

    records = ledger.sorted_records()
    summary = build_audit_summary(records)
    reference_summary = build_reference_integrity_summary(records)
    capture_summary = build_capture_scope_summary(records)
    temporal_summary = build_temporal_integrity_summary(
        narrative, records, gtpu_events
    )
    accounting_summary = build_accounting_integrity_summary(
        lifecycle, narrative, s1u, records, gtpu_events
    )
    inventory = build_source_artifact_inventory(
        identity, lifecycle, narrative, s1u, gtpv2_events, gtpu_events, completeness
    )

    unresolved = [
        {
            "audit_record_reference": record.get("audit_record_reference"),
            "audit_category": record.get("audit_category"),
            "audit_status": record.get("audit_status"),
            "source_artifact_reference": record.get("source_artifact_reference"),
            "capture_file": record.get("capture_file"),
            "proof_sufficiency_status": record.get("proof_sufficiency_status"),
            "limitation": (record.get("limitations") or [None])[0],
        }
        for record in records
        if record.get("audit_status") in UNRESOLVED_STATUSES
    ]
    unresolved.sort(
        key=lambda item: (
            str(item.get("audit_status")),
            str(item.get("audit_category")),
            str(item.get("audit_record_reference")),
        )
    )

    limitations: list[str] = []
    if not completeness.get("exhaustive_coverage_proven"):
        limitations.append(str(completeness.get("limitation")))
    if summary.get("inconsistent_count"):
        limitations.append(
            f"{summary['inconsistent_count']} audit record(s) report a contradiction between "
            "supplied artifacts; every source claim stays visible and none is repaired"
        )
    if summary.get("ambiguous_count"):
        limitations.append(
            f"{summary['ambiguous_count']} audit record(s) stay ambiguous because competing or "
            "unresolvable references exist; the audit never selects one"
        )
    if summary.get("source_truncated_count") or summary.get("source_metadata_invalid_count"):
        limitations.append(
            "at least one source collection is truncated or its completeness metadata is "
            "invalid, so no uniqueness is inferred from the visible subset"
        )
    if s1u is None:
        limitations.append(
            "no EPC S1-U observation was supplied, so stream, direction and user-plane "
            "accounting relationships are audited only from the narrative's own projection"
        )
    if gtpv2_events is None:
        limitations.append(
            "no detailed GTPv2-C events were supplied, so published release frame anchors stay "
            "NOT_INDEPENDENTLY_VERIFIABLE"
        )
    if gtpu_events is None:
        limitations.append(
            "no detailed GTP-U events were supplied, so frame-level temporal placement and the "
            "audit-derived packet totals stay NOT_INDEPENDENTLY_VERIFIABLE"
        )
    limitations.append(
        "this capability audits reference consistency only; it selects no first abnormal "
        "boundary, no root cause and no network-function liability"
    )

    additional: list[str] = [
        item
        for record in records
        for item in record.get("additional_evidence_needed") or []
        if isinstance(item, str)
    ]
    if not completeness.get("exhaustive_coverage_proven"):
        additional.append(
            "complete source candidate collections are required before any uniqueness or "
            "exhaustive coverage is audited"
        )
    if gtpv2_events is None:
        additional.append(
            "detailed GTPv2-C events are required to re-observe release request and confirmation frames"
        )
    if gtpu_events is None:
        additional.append(
            "detailed GTP-U events are required to audit complete frame-level temporal partitions"
        )

    bounded_records = records[:MAX_AUDIT_RECORDS]
    result = {
        "domain": DOMAIN_NAME,
        "domain_version": DOMAIN_VERSION,
        "analysis_name": ANALYSIS_NAME,
        "analysis_version": ANALYSIS_VERSION,
        "input_provenance": provenance or {},
        "analysis_scope": {
            "capability": (
                "bounded read-only EPC cross-artifact evidence-chain integrity and audit ledger"
            ),
            "audit_categories": list(AUDIT_CATEGORIES),
            "audit_statuses": list(AUDIT_STATUSES),
            "completeness_statuses": list(COMPLETENESS_STATUSES),
            "check_results": list(CHECK_RESULTS),
            "audit_dimensions": {
                "presence": "does the referenced record exist in the supplied artifact?",
                "consistency": (
                    "does that record agree with the referring record about capture, "
                    "relationship type, endpoint, transaction, direction, identity and frame?"
                ),
                "proof_sufficiency": (
                    "are the complete candidate set and the required chain available to justify "
                    "the published association or conclusion?"
                ),
            },
            "reference_namespaces": [
                "capture + hop-local session context reference",
                "capture + release transaction reference",
                "capture + bearer endpoint reference",
                "capture + bearer generation reference",
                "capture + stream reference",
                "capture + closure candidate reference",
                "capture + narrative subject and release narrative reference",
                "capture + temporal observation reference",
            ],
            "audit_rule": (
                "presence, consistency and proof sufficiency are three independent dimensions; "
                "a visible subset never establishes uniqueness, a source claim is never repaired "
                "and an absent optional artifact is never an inconsistency"
            ),
            "boundary_rule": (
                "the audit is not an abnormal failure boundary and never selects a first "
                "abnormal boundary or a root cause"
            ),
        },
        "source_artifacts": inventory,
        "source_artifact_count": len(inventory),
        "source_completeness": completeness,
        "audit_records": bounded_records,
        "audit_record_count": len(records),
        "audit_records_omitted": max(0, len(records) - MAX_AUDIT_RECORDS),
        "audit_summary": summary,
        "reference_integrity_summary": reference_summary,
        "capture_scope_summary": capture_summary,
        "temporal_integrity_summary": temporal_summary,
        "accounting_integrity_summary": accounting_summary,
        "unresolved_audit_findings": unresolved[:MAX_LIST_ITEMS],
        "unresolved_audit_finding_count": len(unresolved),
        "evidence_limitations": limitations[:MAX_LIST_ITEMS],
        "additional_evidence_needed": list(dict.fromkeys(additional))[:MAX_LIST_ITEMS],
        "not_confirmed": list(NOT_CONFIRMED),
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": (
            "an evidence-audit finding is not a network failure; this capability selects no "
            "first abnormal boundary and no root cause"
        ),
    }
    return result


__all__ = [
    "ANALYSIS_NAME",
    "ANALYSIS_VERSION",
    "AUDIT_CATEGORIES",
    "AUDIT_STATUSES",
    "AuditInputError",
    "CHECK_TOKENS",
    "COMPLETENESS_STATUSES",
    "DOMAIN_NAME",
    "DOMAIN_VERSION",
    "EXIT_MALFORMED_INPUT",
    "EXIT_NO_SUBJECTS",
    "EXIT_OUTPUT_FAILURE",
    "InputError",
    "MAX_AUDIT_RECORDS",
    "PROOF_STATUSES",
    "analyze",
    "audit_accounting",
    "audit_capture_scope",
    "audit_completeness",
    "audit_cross_interface",
    "audit_generation_closure",
    "audit_generation_stream_attribution",
    "audit_narrative_stages",
    "audit_reference_integrity",
    "audit_release_bindings",
    "audit_session_context_links",
    "audit_session_generation_links",
    "audit_source_artifacts",
    "audit_temporal_partitions",
    "audit_transaction_anchors",
    "build_indexes",
    "build_source_completeness",
    "closure_completeness",
    "collection_status",
    "duplicate_frame_claims",
    "read_json",
    "read_jsonl",
    "safe_name",
    "scoped_direction_agrees",
]