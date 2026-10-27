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
PARTITION_BASIS_INCOMPLETE = "FRAME_LEVEL_EVENTS_INCOMPLETE"
PARTITION_BASIS_CONFLICTED = "FRAME_LEVEL_EVENTS_CONFLICTED"
PARTITION_BASIS_UNATTRIBUTED = "GENERATION_ATTRIBUTION_NOT_ESTABLISHED"

PARTITION_SCOPE_COMPLETE = "COMPLETE_STREAM"
PARTITION_SCOPE_SUBSET = "OBSERVED_SUBSET"

# Generation-level user-plane ownership. A SUPPORTED S1-U stream association
# names a default-bearer subject; only the lifecycle's own generation-scoped
# observation names a bearer generation.
STREAM_ASSOCIATION_SUPPORTED = "SUPPORTED"

ATTRIBUTION_ESTABLISHED = "ESTABLISHED"
ATTRIBUTION_NOT_ESTABLISHED = "NOT_ESTABLISHED"

ATTRIBUTION_BASIS_SCOPED = (
    "accepted_stream_association_and_lifecycle_generation_scoped_s1u_observation"
)
ATTRIBUTION_BASIS_UNPROVED = "endpoint_equality_alone_is_not_generation_ownership"

ATTRIBUTION_FAILURE_CAPTURE = "capture_identity_mismatch"
ATTRIBUTION_FAILURE_SEVERAL_GENERATIONS = "several_proved_generations_share_one_endpoint"
ATTRIBUTION_FAILURE_STREAM_NOT_ACCEPTED = "stream_association_not_accepted"
ATTRIBUTION_FAILURE_STREAM_REFERENCE_MISSING = "stream_reference_missing"
ATTRIBUTION_FAILURE_NO_SCOPED = (
    "lifecycle_publishes_no_generation_scoped_s1u_observation_for_this_stream"
)
ATTRIBUTION_FAILURE_SCOPED_NOT_ACCEPTED = (
    "lifecycle_generation_scoped_attribution_not_accepted"
)
ATTRIBUTION_FAILURE_SCOPED_ROLE = (
    "lifecycle_generation_scoped_attribution_names_another_receiving_role"
)
ATTRIBUTION_FAILURE_SEVERAL_CLAIMANTS = "several_generations_claim_one_stream"
# The lifecycle generation-scoped S1-U collection is the only accepted source of
# generation-level user-plane ownership, so its own completeness and internal
# consistency are part of the attribution proof.
ATTRIBUTION_FAILURE_SCOPED_COLLECTION_TRUNCATED = (
    "lifecycle_generation_scoped_attribution_collection_truncated"
)
ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID = (
    "lifecycle_generation_scoped_attribution_collection_invalid"
)
ATTRIBUTION_FAILURE_SCOPED_CONFLICT = (
    "conflicting_lifecycle_generation_scoped_attribution"
)
ATTRIBUTION_FAILURE_SCOPED_ROLE_MISSING = (
    "lifecycle_generation_scoped_attribution_publishes_no_receiving_endpoint_role"
)
ATTRIBUTION_FAILURE_SCOPED_STREAM_ROLE = (
    "lifecycle_generation_scoped_attribution_names_another_receiving_role_than_the_stream"
)
ATTRIBUTION_FAILURE_SCOPED_GENERATION_SCOPE = "lifecycle_generation_scope_is_not_unique"
# Direction is a first-class part of the ownership claim: the accepted lifecycle
# derives the receiving role from the stream direction, so a record whose
# direction and role disagree describes no reviewed endpoint.
ATTRIBUTION_FAILURE_SCOPED_DIRECTION_MISSING = (
    "lifecycle_generation_scoped_attribution_publishes_no_direction"
)
ATTRIBUTION_FAILURE_SCOPED_DIRECTION_UNKNOWN = (
    "lifecycle_generation_scoped_attribution_publishes_an_unmapped_direction"
)
ATTRIBUTION_FAILURE_SCOPED_DIRECTION_ROLE = (
    "lifecycle_generation_scoped_attribution_direction_contradicts_its_receiving_role"
)
ATTRIBUTION_FAILURE_SCOPED_DIRECTION_STREAM = (
    "lifecycle_generation_scoped_attribution_direction_contradicts_the_stream_direction"
)
# A claim that cannot be placed in a capture still competes for the same stream.
ATTRIBUTION_FAILURE_UNRESOLVED_CLAIMANT = "unpublished_generation_claims_this_stream"
ATTRIBUTION_FAILURE_AMBIGUOUS_CLAIMANT = (
    "ambiguous_generation_scope_claims_this_stream"
)

# The accepted lifecycle and S1-U producers both fix this mapping; the narrative
# never invents a direction from TEID, address or role alone.
DIRECTION_ROLE = {"UPLINK": "sgw_s1u", "DOWNLINK": "enodeb_s1u"}

SCOPED_COLLECTION_DOCUMENT = "epc-bearer-lifecycle"
SCOPED_COLLECTION_NAME = "generation_scoped_s1u_observations"
SCOPED_COLLECTION_COUNT = "generation_scoped_observation_count"

ATTRIBUTION_FAILURE_VOCABULARY = (
    ATTRIBUTION_FAILURE_CAPTURE,
    ATTRIBUTION_FAILURE_SEVERAL_GENERATIONS,
    ATTRIBUTION_FAILURE_STREAM_NOT_ACCEPTED,
    ATTRIBUTION_FAILURE_STREAM_REFERENCE_MISSING,
    ATTRIBUTION_FAILURE_NO_SCOPED,
    ATTRIBUTION_FAILURE_SCOPED_NOT_ACCEPTED,
    ATTRIBUTION_FAILURE_SCOPED_ROLE,
    ATTRIBUTION_FAILURE_SEVERAL_CLAIMANTS,
    ATTRIBUTION_FAILURE_SCOPED_COLLECTION_TRUNCATED,
    ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID,
    ATTRIBUTION_FAILURE_SCOPED_CONFLICT,
    ATTRIBUTION_FAILURE_SCOPED_ROLE_MISSING,
    ATTRIBUTION_FAILURE_SCOPED_STREAM_ROLE,
    ATTRIBUTION_FAILURE_SCOPED_GENERATION_SCOPE,
    ATTRIBUTION_FAILURE_SCOPED_DIRECTION_MISSING,
    ATTRIBUTION_FAILURE_SCOPED_DIRECTION_UNKNOWN,
    ATTRIBUTION_FAILURE_SCOPED_DIRECTION_ROLE,
    ATTRIBUTION_FAILURE_SCOPED_DIRECTION_STREAM,
    ATTRIBUTION_FAILURE_UNRESOLVED_CLAIMANT,
    ATTRIBUTION_FAILURE_AMBIGUOUS_CLAIMANT,
)

# Collections whose completeness is a precondition for a unique closure claim.
CLOSURE_CRITICAL_COLLECTIONS = (
    ("epc-session-identity", "release_session_bindings"),
    ("epc-session-identity", "session_to_generation_links"),
    ("epc-session-identity", "generation_closure_candidates"),
    ("epc-bearer-lifecycle", "lifecycle_subjects"),
)

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
        # The generation-scoped S1-U collection is the only accepted source of
        # generation-level user-plane ownership, so its own declared count is part
        # of the completeness proof. The accepted producer publishes no omitted
        # count for this collection, so none is invented here.
        _completeness_entry(
            SCOPED_COLLECTION_DOCUMENT,
            lifecycle,
            SCOPED_COLLECTION_NAME,
            SCOPED_COLLECTION_COUNT,
            None,
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


def closure_completeness(
    completeness: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Affirmative proof that every closure-critical collection is complete.

    Unique generation closure is a uniqueness claim about a candidate set, so it
    is only assertable when the published subset provably *is* the whole set. The
    gate is evaluated per collection: an aggregate status is not enough, because
    one truncated collection is sufficient to hide a competing candidate.
    """
    entries = {
        (str(item.get("document")), str(item.get("collection"))): item
        for item in completeness.get("collections") or []
        if isinstance(item, dict)
    }
    failures: list[str] = []
    for document, collection in CLOSURE_CRITICAL_COLLECTIONS:
        entry = entries.get((document, collection))
        if entry is None or entry.get("status") != COMPLETENESS_COMPLETE:
            failures.append(f"{document}:{collection}")
    return (not failures), failures


def scoped_attribution_completeness(
    completeness: dict[str, Any],
) -> tuple[bool, str | None]:
    """Affirmative proof that the scoped-attribution collection is complete.

    A visible subset of the lifecycle generation-scoped S1-U collection is not a
    complete ownership candidate set, so a unique attribution may only rest on it
    when the declared count provably equals the published records.
    """
    for item in completeness.get("collections") or []:
        if not isinstance(item, dict):
            continue
        if (item.get("document"), item.get("collection")) != (
            SCOPED_COLLECTION_DOCUMENT,
            SCOPED_COLLECTION_NAME,
        ):
            continue
        status = item.get("status")
        if status == COMPLETENESS_COMPLETE:
            return True, None
        if status == COMPLETENESS_TRUNCATED:
            return False, ATTRIBUTION_FAILURE_SCOPED_COLLECTION_TRUNCATED
        return False, ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID
    # An unassessed collection is not a proved one.
    return False, ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID


def _scoped_attributions(
    lifecycle: dict[str, Any],
) -> tuple[
    dict[tuple[str, str, str], list[dict[str, Any]]],
    dict[tuple[str, str], list[str]],
    set[str],
    dict[str, list[dict[str, Any]]],
]:
    """Lifecycle-published generation-scoped S1-U attributions, contradiction-aware.

    The accepted lifecycle publishes ``generation_scoped_s1u_observations`` that
    name both the bearer generation and the S1-U stream that generation owns. That
    record is the only producer contract establishing generation-level user-plane
    ownership, so it is the strongest provenance available here.

    Every record is kept: a repeated ``(capture, generation, stream)`` key is a
    contradiction to be reported, never a later record silently replacing an
    earlier one. The accepted producer emits at most one record per accepted
    stream, so multiplicity is always a producer or artifact defect.

    A record whose generation cannot be placed in exactly one capture cannot
    establish ownership, but it still competes for its stream reference: discarding
    it would let the remaining subset look unique. Those records are returned in
    ``unresolved`` keyed by stream reference, so the gate can fail closed on the
    exact stream they name without invalidating unrelated streams or captures.
    """
    captures_by_generation: dict[str, set[str]] = {}
    for subject in lifecycle.get("lifecycle_subjects") or []:
        if not isinstance(subject, dict):
            continue
        reference = subject.get("generation_reference")
        capture = subject.get("capture_file")
        if isinstance(reference, str) and isinstance(capture, str):
            captures_by_generation.setdefault(reference, set()).add(capture)
    ambiguous = {
        reference
        for reference, captures in captures_by_generation.items()
        if len(captures) != 1
    }
    index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    claimants: dict[tuple[str, str], list[str]] = {}
    unresolved: dict[str, list[dict[str, Any]]] = {}
    for record in lifecycle.get("generation_scoped_s1u_observations") or []:
        if not isinstance(record, dict):
            continue
        generation = record.get("generation_reference")
        stream = record.get("source_stream_reference")
        if not isinstance(stream, str):
            # Without a stream reference the record names no reviewed stream and
            # cannot compete for one.
            continue
        captures = (
            captures_by_generation.get(generation)
            if isinstance(generation, str)
            else None
        )
        if not captures or len(captures) != 1:
            unresolved.setdefault(stream, []).append(record)
            continue
        capture = next(iter(captures))
        index.setdefault((capture, generation, stream), []).append(record)
        bucket = claimants.setdefault((capture, stream), [])
        if generation not in bucket:
            bucket.append(generation)
    return index, claimants, ambiguous, unresolved


def _generation_attribution(
    stream: dict[str, Any],
    generations: list[dict[str, Any]],
    capture: str,
    scoped: dict[tuple[str, str, str], list[dict[str, Any]]],
    claimants: dict[tuple[str, str], list[str]],
    ambiguous_generations: set[str],
    unresolved_claims: dict[str, list[dict[str, Any]]],
    scoped_completeness: tuple[bool, str | None],
) -> tuple[str, str, list[str]]:
    """Decide whether one S1-U stream may be attributed to one proved generation.

    Every condition must hold affirmatively: a complete scoped-attribution
    collection, the same capture, one proved generation owner, an accepted stream
    association, no unresolved competing claim on this stream reference, and
    exactly one internally consistent lifecycle generation-scoped observation whose
    role and direction agree with the generation, the stream and each other.
    """
    failures: list[str] = []
    scoped_complete, scoped_failure = scoped_completeness
    if not scoped_complete:
        failures.append(
            scoped_failure or ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID
        )
    if str(stream.get("capture_file")) != capture:
        failures.append(ATTRIBUTION_FAILURE_CAPTURE)
    if len(generations) != 1:
        failures.append(ATTRIBUTION_FAILURE_SEVERAL_GENERATIONS)
    if stream.get("association_status") != STREAM_ASSOCIATION_SUPPORTED:
        failures.append(ATTRIBUTION_FAILURE_STREAM_NOT_ACCEPTED)
    reference = stream.get("stream_reference")
    if not isinstance(reference, str):
        failures.append(ATTRIBUTION_FAILURE_STREAM_REFERENCE_MISSING)
    generation = generations[0] if len(generations) == 1 else None
    if isinstance(reference, str) and generation is not None:
        generation_reference = str(generation.get("generation_reference"))
        if generation_reference in ambiguous_generations:
            failures.append(ATTRIBUTION_FAILURE_SCOPED_GENERATION_SCOPE)
        records = scoped.get((capture, generation_reference, reference)) or []
        if not records:
            failures.append(ATTRIBUTION_FAILURE_NO_SCOPED)
        elif len(records) > 1:
            # Last-writer-wins, first-writer-wins and strongest-status selection
            # are all forbidden: a repeated ownership claim is a contradiction.
            failures.append(ATTRIBUTION_FAILURE_SCOPED_CONFLICT)
        else:
            record = records[0]
            if record.get("association_status") != STREAM_ASSOCIATION_SUPPORTED:
                failures.append(ATTRIBUTION_FAILURE_SCOPED_NOT_ACCEPTED)
            role = record.get("receiving_endpoint_role")
            if not isinstance(role, str) or not role:
                # A missing role must not bypass the role check.
                failures.append(ATTRIBUTION_FAILURE_SCOPED_ROLE_MISSING)
            else:
                if role != str(generation.get("receiving_endpoint_role")):
                    failures.append(ATTRIBUTION_FAILURE_SCOPED_ROLE)
                if role != str(stream.get("matched_endpoint_role")):
                    failures.append(ATTRIBUTION_FAILURE_SCOPED_STREAM_ROLE)
            # Direction is part of the ownership claim: it must be published, map
            # to a reviewed receiving role, and agree with the stream it claims to
            # own. UNKNOWN is never reinterpreted as uplink or downlink.
            direction = record.get("direction")
            if not isinstance(direction, str) or not direction:
                failures.append(ATTRIBUTION_FAILURE_SCOPED_DIRECTION_MISSING)
            elif direction not in DIRECTION_ROLE:
                failures.append(ATTRIBUTION_FAILURE_SCOPED_DIRECTION_UNKNOWN)
            else:
                if isinstance(role, str) and role and DIRECTION_ROLE[direction] != role:
                    failures.append(ATTRIBUTION_FAILURE_SCOPED_DIRECTION_ROLE)
                if str(stream.get("direction")) != direction:
                    failures.append(ATTRIBUTION_FAILURE_SCOPED_DIRECTION_STREAM)
        if len(claimants.get((capture, reference), [])) > 1:
            failures.append(ATTRIBUTION_FAILURE_SEVERAL_CLAIMANTS)
        # A record that cannot be placed in a capture still competes for this exact
        # stream reference; dropping it would make the remaining subset look unique.
        for claim in unresolved_claims.get(reference) or []:
            claimant = claim.get("generation_reference")
            if isinstance(claimant, str) and claimant in ambiguous_generations:
                token = ATTRIBUTION_FAILURE_AMBIGUOUS_CLAIMANT
            else:
                token = ATTRIBUTION_FAILURE_UNRESOLVED_CLAIMANT
            if token not in failures:
                failures.append(token)
    if failures:
        return ATTRIBUTION_NOT_ESTABLISHED, ATTRIBUTION_BASIS_UNPROVED, failures
    return ATTRIBUTION_ESTABLISHED, ATTRIBUTION_BASIS_SCOPED, []


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


def _session_generation_link_index(
    identity: dict[str, Any],
) -> dict[tuple[str, str, str], dict[str, Any]]:
    """Established session-to-generation relationships, keyed by capture and endpoints.

    The accepted identity analysis targets a *bearer endpoint* reference, not a
    lifecycle generation reference, so the chain is resolved through the
    candidate's own ``bearer_endpoint_reference``.
    """
    index: dict[tuple[str, str, str], dict[str, Any]] = {}
    for link in identity.get("session_to_generation_links") or []:
        if not isinstance(link, dict):
            continue
        source = link.get("source_subject_reference")
        target = link.get("target_subject_reference")
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        index[(str(link.get("capture_file")), source, target)] = link
    return index


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
    closure_complete: bool,
    closure_failures: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Generations proved closed for exactly this release and context.

    A generation is admitted only when the whole closure chain holds: the
    release-to-session binding is established for this capture and release; the
    lifecycle subject carries a proved boundary naming this release transaction
    in this capture; the identity analysis publishes an ESTABLISHED closure
    candidate for the same context, release and bearer endpoint; an ESTABLISHED
    session-to-generation link joins that context to the candidate's bearer
    endpoint; the candidate's endpoint identity matches the lifecycle subject's
    receiving endpoint exactly; and every closure-critical source collection is
    provably complete.
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
    if not closure_complete:
        # Unique closure is a uniqueness claim about a candidate set. While a
        # closure-critical collection is truncated or its completeness metadata is
        # invalid, the visible subset cannot establish that uniqueness.
        return proved, competing, [
            "no unique bearer-generation closure is promoted while a closure-critical source "
            "collection is incomplete: " + ", ".join(closure_failures)
        ]
    binding = _binding_index(identity).get((capture, transaction_reference))
    if binding is None or binding.get("association_status") != STATUS_ESTABLISHED:
        return proved, competing, [
            "the release-to-session binding is not established for this capture and release, so "
            "no bearer-generation closure is promoted"
        ]
    links = _session_generation_link_index(identity)
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
            endpoint_reference = owned[0].get("bearer_endpoint_reference")
            link = links.get((capture, context_reference, str(endpoint_reference)))
            if link is None or link.get("association_status") != STATUS_ESTABLISHED:
                limitations.append(
                    "the identity analysis publishes no established session-to-generation link "
                    "from this context to the candidate's bearer endpoint, so the closure chain "
                    "is incomplete and no generation is proved closed"
                )
                continue
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
    completeness: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """One narrative per release transaction, keyed by capture and transaction.

    ``completeness`` is the affirmative source-completeness proof. It gates the
    unique-closure claim: without it, an established-looking candidate from the
    visible portion of a truncated collection must not be promoted.
    """
    closure_complete, closure_failures = closure_completeness(completeness or {})
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
            identity,
            lifecycle,
            context_reference,
            transaction_reference,
            capture,
            outcome,
            closure_complete,
            closure_failures,
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
    lifecycle: dict[str, Any] | None = None,
    scoped_completeness: tuple[bool, str | None] | None = None,
) -> tuple[
    list[dict[str, Any]], dict[str, Any], list[str], list[dict[str, Any]]
]:
    """Frame-aware temporal evidence per release, without inventing placement.

    Ownership is never inferred from endpoint equality. A stream is attributed to
    a proved generation only inside its own capture, only when its own association
    is accepted, only when the lifecycle's generation-scoped S1-U collection is
    provably complete, and only when exactly one internally consistent scoped
    observation names that generation and that stream. A G-PDU frame may appear in
    at most one established partition.
    """
    if s1u is None:
        return (
            [],
            {
                "frame_level_evidence_supplied": False,
                "observed_g_pdu_event_count": 0,
                "assigned_to_release_window_count": 0,
                "unassigned_g_pdu_event_count": 0,
                "duplicate_assignment_count": 0,
                "attributed_observation_count": 0,
                "unattributed_observation_count": 0,
                "conserved": True,
            },
            [],
            [],
        )
    streams = [
        item for item in s1u.get("stream_observations") or [] if isinstance(item, dict)
    ]
    frame_index = _gtpu_index(gtpu_events)
    scoped, claimants, ambiguous_generations, unresolved_claims = _scoped_attributions(
        lifecycle or {}
    )
    scoped_gate = scoped_completeness or (
        False,
        ATTRIBUTION_FAILURE_SCOPED_COLLECTION_INVALID,
    )
    limitations: list[str] = []
    unbound: list[dict[str, Any]] = []
    seen_unbound: set[tuple[Any, ...]] = set()
    # An unplaceable claim cannot establish ownership, but it still competes for
    # the stream reference it names, so it is published as diagnostic evidence
    # instead of disappearing.
    for stream_reference in sorted(unresolved_claims):
        claims = unresolved_claims[stream_reference]
        claimants_named = sorted(
            {
                str(claim.get("generation_reference"))
                for claim in claims
                if isinstance(claim.get("generation_reference"), str)
            }
        )
        unbound.append(
            {
                "kind": "unresolved_generation_scoped_attribution_claim",
                "capture_file": None,
                "transaction_reference": None,
                "checks": [
                    f"source_stream_reference={stream_reference}",
                    "claimant_generation_references="
                    + (",".join(claimants_named) if claimants_named else "none"),
                ],
                "limitations": [
                    "a lifecycle generation-scoped record names this stream but its generation "
                    "cannot be placed in exactly one capture, so it cannot establish ownership; "
                    "it is published because it still competes for the same stream reference and "
                    "no uniqueness may be inferred from the remaining subset"
                ],
            }
        )

    # Endpoint indexes. The capture is part of every key: an endpoint value is
    # only meaningful inside the capture that observed it, so a generation in one
    # capture can never own traffic observed in another.
    endpoints_by_capture: dict[
        tuple[str, str, str, int], list[dict[str, Any]]
    ] = {}
    endpoints_any_capture: dict[tuple[str, str, int], list[str]] = {}
    addresses_by_teid: dict[tuple[str, str, int], list[str]] = {}
    for narrative in narratives:
        capture = str(narrative.get("capture_file"))
        for generation in narrative.get("proved_generations") or []:
            role = str(generation.get("receiving_endpoint_role"))
            address = str(generation.get("receiving_endpoint_address"))
            teid = _int(generation.get("receiving_endpoint_teid")) or 0
            endpoints_by_capture.setdefault(
                (capture, role, address, teid), []
            ).append(generation)
            captures = endpoints_any_capture.setdefault((role, address, teid), [])
            if capture not in captures:
                captures.append(capture)
            addresses = addresses_by_teid.setdefault((capture, role, teid), [])
            if address not in addresses:
                addresses.append(address)

    # Pass 1 — resolve the candidate attribution of every stream, per narrative.
    plans: list[dict[str, Any]] = []
    for narrative in narratives:
        capture = str(narrative.get("capture_file"))
        transaction_reference = narrative.get("release_transaction_reference")
        used_references: set[str] = set()
        for stream in streams:
            role = str(stream.get("matched_endpoint_role"))
            address = str(stream.get("outer_destination"))
            teid = _int(stream.get("teid")) or 0
            owners = [
                generation
                for generation in narrative.get("proved_generations") or []
                if str(generation.get("receiving_endpoint_role")) == role
                and str(generation.get("receiving_endpoint_address")) == address
                and (_int(generation.get("receiving_endpoint_teid")) or 0) == teid
            ]
            if str(stream.get("capture_file")) != capture:
                # Capture identity is part of the endpoint identity. Traffic
                # observed in one capture is never attributed to a generation
                # proved in another, whatever the endpoint values say and whoever
                # the lifecycle names.
                if owners:
                    key = ("cross_capture", capture, address, teid, role)
                    if key not in seen_unbound:
                        seen_unbound.add(key)
                        unbound.append(
                            {
                                "kind": (
                                    "stream_endpoint_matches_a_proved_generation_in_another_"
                                    "capture"
                                ),
                                "capture_file": capture,
                                "transaction_reference": transaction_reference,
                                "checks": [
                                    f"receiving_endpoint_role={role}",
                                    f"receiving_endpoint_address={address}",
                                    f"receiving_endpoint_teid={teid}",
                                    f"stream_capture={stream.get('capture_file')}",
                                ],
                                "limitations": [
                                    "this S1-U stream's receiving endpoint equals a proved "
                                    "generation's endpoint, but the stream was observed in "
                                    f"{stream.get('capture_file')} and the narrative belongs to "
                                    f"{capture}; capture identity is part of the endpoint "
                                    "identity, so no traffic is attributed across captures"
                                ],
                            }
                        )
                continue
            if not owners:
                near = [
                    other
                    for other in addresses_by_teid.get((capture, role, teid), [])
                    if other != address
                ]
                if near:
                    key = ("teid_only", capture, address, teid, role)
                    if key not in seen_unbound:
                        seen_unbound.add(key)
                        unbound.append(
                            {
                                "kind": (
                                    "stream_shares_a_teid_with_a_proved_generation_without_"
                                    "its_receiving_address"
                                ),
                                "capture_file": capture,
                                "transaction_reference": transaction_reference,
                                "checks": [
                                    f"receiving_endpoint_role={role}",
                                    f"receiving_endpoint_address={address}",
                                    f"receiving_endpoint_teid={teid}",
                                ],
                                "limitations": [
                                    "an equal receiving TEID is not a bearer identity; the "
                                    "stream's receiving address differs from the proved "
                                    "generation's, so no traffic is attributed"
                                ],
                            }
                        )
                continue
            attribution_status, attribution_basis, attribution_failures = (
                _generation_attribution(
                    stream,
                    owners,
                    capture,
                    scoped,
                    claimants,
                    ambiguous_generations,
                    unresolved_claims,
                    scoped_gate,
                )
            )
            reference = _reference(
                "epc-release-temporal-",
                [
                    narrative["release_narrative_reference"],
                    stream.get("stream_reference"),
                ],
            )
            ordinal = 2
            while reference in used_references:
                reference = _reference(
                    "epc-release-temporal-",
                    [
                        narrative["release_narrative_reference"],
                        stream.get("stream_reference"),
                        ordinal,
                    ],
                )
                ordinal += 1
            used_references.add(reference)
            plans.append(
                {
                    "narrative": narrative,
                    "capture": capture,
                    "reference": reference,
                    "stream": stream,
                    "generation": owners[0] if len(owners) == 1 else None,
                    "stream_key": (
                        capture,
                        str(stream.get("outer_source")),
                        str(stream.get("outer_destination")),
                        _int(stream.get("teid")) or 0,
                    ),
                    "attribution_status": attribution_status,
                    "attribution_basis": attribution_basis,
                    "attribution_failures": attribution_failures,
                }
            )

    # Pass 2 — exclusive frame ownership across candidate narratives.
    claims: dict[tuple[str, int], list[str]] = {}
    for plan in plans:
        if plan["attribution_status"] != ATTRIBUTION_ESTABLISHED:
            continue
        for event in frame_index.get(plan["stream_key"]) or []:
            claims.setdefault((plan["capture"], event["frame_number"]), []).append(
                plan["reference"]
            )
    conflicted = {key for key, owners in claims.items() if len(set(owners)) > 1}

    # Pass 3 — publish one record per candidate attribution.
    observations: list[dict[str, Any]] = []
    assigned: set[tuple[str, int]] = set()
    for plan in plans:
        narrative = plan["narrative"]
        stream = plan["stream"]
        generation = plan["generation"]
        reference = plan["reference"]
        aggregate_count = _int(stream.get("observed_g_pdu_packet_count")) or 0
        aggregate_octets = _int(stream.get("observed_payload_byte_count")) or 0
        events = frame_index.get(plan["stream_key"]) or []
        record: dict[str, Any] = {
            "temporal_observation_reference": reference,
            "release_narrative_reference": narrative["release_narrative_reference"],
            "capture_file": plan["capture"],
            "stream_reference": stream.get("stream_reference"),
            "generation_reference": (
                generation.get("generation_reference") if generation else None
            ),
            "receiving_endpoint_role": stream.get("matched_endpoint_role"),
            "direction": stream.get("direction"),
            "association_status": stream.get("association_status"),
            "generation_attribution_status": plan["attribution_status"],
            "generation_attribution_basis": plan["attribution_basis"],
            "attribution_failures": list(plan["attribution_failures"]),
            "observed_g_pdu_count": aggregate_count,
            "observed_payload_octets": aggregate_octets,
            "first_observed_frame": stream.get("first_frame"),
            "last_observed_frame": stream.get("last_frame"),
            "release_request_frame": _int(narrative.get("release_request_frame")),
            "release_confirmation_frame": _int(
                narrative.get("release_confirmation_frame")
            ),
            "partitions": None,
            "partition_scope": None,
            "partition_basis": PARTITION_BASIS_AGGREGATE,
            "temporal_placement_status": TEMPORAL_NOT_ESTABLISHED,
            "partition_conserved": None,
            "duplicate_frame_ownership": False,
            "limitations": [],
        }
        if plan["attribution_status"] != ATTRIBUTION_ESTABLISHED:
            record["partition_basis"] = PARTITION_BASIS_UNATTRIBUTED
            record["limitations"].append(
                "GENERATION_ATTRIBUTION_NOT_ESTABLISHED: the stream's endpoint matches a proved "
                "generation, but the accepted producers do not establish that the generation owns "
                "this stream, so its traffic is published as diagnostic observation only and no "
                "packet is assigned to the release window"
            )
            record["limitations"].extend(
                f"attribution gate failed: {failure}"
                for failure in plan["attribution_failures"]
            )
            observations.append(record)
            narrative["temporal_observation_references"] = list(
                narrative["temporal_observation_references"]
            ) + [reference]
            continue
        plan_keys = [(plan["capture"], event["frame_number"]) for event in events]
        if any(key in conflicted for key in plan_keys):
            # Two candidate narratives claim the same G-PDU frame. Publishing both
            # partitions would count one packet twice, so both fail closed.
            record["partition_basis"] = PARTITION_BASIS_CONFLICTED
            record["duplicate_frame_ownership"] = True
            record["limitations"].append(
                "DUPLICATE_FRAME_OWNERSHIP: another release narrative claims at least one of these "
                "G-PDU frames, so no temporal partition is established for this release"
            )
            observations.append(record)
            narrative["temporal_observation_references"] = list(
                narrative["temporal_observation_references"]
            ) + [reference]
            continue
        request_frame = record["release_request_frame"]
        confirmation_frame = record["release_confirmation_frame"]
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
            conserved = counted == aggregate_count and octets == aggregate_octets
            record["partitions"] = partitions
            record["partition_conserved"] = conserved
            if conserved:
                record["partition_basis"] = PARTITION_BASIS_FRAMES
                record["partition_scope"] = PARTITION_SCOPE_COMPLETE
                record["temporal_placement_status"] = TEMPORAL_ESTABLISHED
                assigned.update(plan_keys)
            else:
                # Individually observed frames keep a valid temporal position, but
                # the published aggregate stream is not fully partitioned, so the
                # complete placement stays unproved. Nothing is interpolated.
                record["partition_basis"] = PARTITION_BASIS_INCOMPLETE
                record["partition_scope"] = PARTITION_SCOPE_SUBSET
                record["limitations"].append(
                    "FRAME_LEVEL_EVENTS_INCOMPLETE: the observed G-PDU events do not reproduce the "
                    "accepted aggregate stream count or its payload octets, so the frame-level "
                    "subset keeps its own positions while the complete stream's temporal "
                    "placement stays unestablished; the aggregate remains authoritative and no "
                    "missing packet or octet is interpolated"
                )
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
            str(item["temporal_observation_reference"]),
        )
    )
    total_events = sum(len(items) for items in frame_index.values())
    duplicate_count = len(conflicted)
    assigned_count = len(assigned)
    unassigned_count = max(0, total_events - assigned_count - duplicate_count)
    if duplicate_count:
        limitations.append(
            "a G-PDU frame was claimed by more than one release narrative; every conflicting "
            "narrative fails closed and the frame is counted in no partition"
        )
    if any(
        plan["attribution_status"] != ATTRIBUTION_ESTABLISHED for plan in plans
    ):
        limitations.append(
            "at least one S1-U stream matches a proved generation's endpoint without an accepted "
            "generation-level attribution; its aggregate counts stay visible and no packet is "
            "assigned to a release window"
        )
    if not scoped_gate[0]:
        limitations.append(
            "no generation-level user-plane ownership is established while the lifecycle "
            "generation-scoped S1-U attribution collection is incomplete: "
            + str(scoped_gate[1])
        )
    conflicted_attributions = sum(
        1
        for plan in plans
        if ATTRIBUTION_FAILURE_SCOPED_CONFLICT in plan["attribution_failures"]
    )
    if conflicted_attributions:
        limitations.append(
            f"{conflicted_attributions} stream attribution(s) carry more than one lifecycle "
            "generation-scoped record for the same capture, generation and stream; the "
            "contradiction is reported and no record is selected by input order"
        )
    accounting = {
        "frame_level_evidence_supplied": bool(frame_index),
        "observed_g_pdu_event_count": total_events,
        "assigned_to_release_window_count": assigned_count,
        "unassigned_g_pdu_event_count": unassigned_count,
        "duplicate_assignment_count": duplicate_count,
        "attributed_observation_count": sum(
            1 for plan in plans if plan["attribution_status"] == ATTRIBUTION_ESTABLISHED
        ),
        "unattributed_observation_count": sum(
            1 for plan in plans if plan["attribution_status"] != ATTRIBUTION_ESTABLISHED
        ),
        "conserved": duplicate_count == 0
        and assigned_count + duplicate_count + unassigned_count == total_events,
    }
    return observations, accounting, limitations, unbound


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
    closure_complete, closure_failures = closure_completeness(completeness)
    scoped_complete, scoped_failure = scoped_attribution_completeness(completeness)
    subjects = build_narrative_subjects(identity_document, lifecycle_document)
    narratives, binding_unbound = build_release_narratives(
        identity_document, lifecycle_document, subjects, completeness
    )
    narratives, reference_unbound = validate_source_references(narratives, gtpv2_events)
    (
        observations,
        temporal_accounting,
        temporal_limitations,
        temporal_unbound,
    ) = build_temporal_observations(
        narratives,
        s1u_document,
        gtpu_events,
        lifecycle_document,
        (scoped_complete, scoped_failure),
    )
    ambiguous = _ambiguous_records(identity_document, lifecycle_document, narratives)

    unbound: list[dict[str, Any]] = (
        list(binding_unbound) + list(reference_unbound) + list(temporal_unbound)
    )
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
    if not closure_complete:
        limitations.append(
            "no unique bearer-generation closure is promoted while a closure-critical source "
            "collection is incomplete: " + ", ".join(closure_failures)
        )
    if not scoped_complete:
        limitations.append(
            "no generation-level user-plane ownership is established while the lifecycle "
            "generation-scoped S1-U attribution collection is incomplete: "
            + str(scoped_failure)
            + "; the release outcome, the release-session binding and any independently proved "
            "generation closure are unaffected"
        )
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
    if not closure_complete:
        additional.append(
            "complete closure-critical collections are required before a unique "
            "bearer-generation closure is promoted"
        )
    if not scoped_complete:
        additional.append(
            "a complete lifecycle generation-scoped S1-U attribution collection is required "
            "before any stream is attributed to a bearer generation"
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
            "temporal_ownership_rule": (
                "an S1-U stream is attributed to a proved generation only inside its own capture, "
                "only with an accepted stream association, and only when the lifecycle publishes a "
                "generation-scoped S1-U observation naming exactly that generation and stream; "
                "endpoint equality alone never establishes generation ownership"
            ),
            "temporal_completeness_rule": (
                "a complete temporal placement is asserted only when the observed frame-level "
                "events reproduce the accepted aggregate count and payload octets; an incomplete "
                "or conflicting frame set keeps its observed subset and fails closed"
            ),
            "scoped_attribution_rule": (
                "generation-level user-plane ownership rests on the lifecycle "
                "generation-scoped S1-U collection; that collection must prove its own declared "
                "count, and exactly one internally consistent record may name a capture, "
                "generation and stream, so no record is selected by input order"
            ),
            "directional_attribution_rule": (
                "the scoped record's direction must map to a reviewed receiving role and agree "
                "with the accepted stream direction, an unmapped direction such as UNKNOWN is "
                "never reinterpreted, and a record whose generation cannot be placed in exactly "
                "one capture still competes for the stream reference it names"
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
    "closure_completeness",
    "read_json",
    "scoped_attribution_completeness",
    "read_jsonl",
    "safe_name",
    "source_completeness",
    "validate_source_references",
]
