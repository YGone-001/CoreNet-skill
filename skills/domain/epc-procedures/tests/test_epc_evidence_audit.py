#!/usr/bin/env python3
"""Standalone tests for the read-only EPC evidence-audit ledger.

The fixtures are faithful, minimal instances of the accepted producer documents.
They carry exactly the published fields the audit consumes, so a change to a
producer contract that this capability depends on fails here instead of silently
producing a thinner ledger.
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_evidence_audit.py"

sys.path.insert(0, str(SCRIPTS))
import epc_evidence_audit_model as model  # noqa: E402
import epc_release_narrative_model as narrative_model  # noqa: E402

CAPTURE_A = "capture-a.pcap"
CAPTURE_B = "capture-b.pcap"

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
ACCEPTED = "ACCEPTED"
UNRESOLVED = "UNRESOLVED"

CONTEXT = "epc-session-context-aaaaaaaaaa"
CONTEXT_B = "epc-session-context-bbbbbbbbbb"
GENERATION = "epc-bearer-generation-cccccccccc"
STREAM = "epc-s1u-stream-0000000001"
STREAM_B = "epc-s1u-stream-0000000002"
TX = "gtpv2-delete-session-1"
TX_OTHER = "gtpv2-delete-session-2"
CANDIDATE = "epc-generation-closure-dddddddddd"
SUBJECT = "epc-release-subject-eeeeeeeeee"
GROUP = "epc-release-group-ffffffffff"
RELEASE = "epc-release-narrative-1111111111"
TEMPORAL = "epc-release-temporal-2222222222"
IDENTITY_LINK = "epc-identity-link-3333333333"
CORRESPONDENCE = "epc-identity-link-4444444444"
UP_GENERATION = "epc-bearer-generation-uuuuuuuuuu"
UP_CANDIDATE = "epc-generation-closure-uuuuuuuuuu"
THIRD_GENERATION = "epc-bearer-generation-tttttttttt"
THIRD_CANDIDATE = "epc-generation-closure-tttttttttt"
THIRD_ENDPOINT = {
    "role": "enodeb_s1u",
    "address": "10.0.0.41",
    "teid": 79,
    "interface_type": 0,
}


def endpoint_values(direction: str = "DOWNLINK") -> tuple[str, str, int, int]:
    if direction == "UPLINK":
        return ("sgw_s1u", "10.0.0.20", 88, 1)
    return ("enodeb_s1u", "10.0.0.40", 77, 0)


def endpoint_reference(
    capture: str = CAPTURE_A,
    direction: str = "DOWNLINK",
    endpoint: dict | None = None,
) -> str:
    if endpoint is None:
        role, address, teid, interface_type = endpoint_values(direction)
    else:
        role = endpoint["role"]
        address = endpoint["address"]
        teid = endpoint["teid"]
        interface_type = endpoint["interface_type"]
    material = "|".join(
        ["bearer-endpoint", capture, role, address, str(teid), str(interface_type)]
    )
    return "epc-bearer-endpoint-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:10]


def evidence(frame: int, message: str, protocol: str = "GTPv2-C") -> dict:
    return {
        "protocol": protocol,
        "frame_number": frame,
        "message_type": message,
        "evidence_level": "OBSERVED",
    }


def context(
    reference: str = CONTEXT,
    *,
    capture: str = CAPTURE_A,
    interface_class: str = "S11",
    status: str = ESTABLISHED,
    allocation: str = "tx-create-1",
) -> dict:
    return {
        "capture_file": capture,
        "session_context_reference": reference,
        "interface_class": interface_class,
        "relationship_type": "HOP_LOCAL_SESSION_CONTEXT",
        "association_status": status,
        "association_basis": "reviewed_receiver_scoped_addressing",
        "transaction_correlation_proved": True,
        "allocation_outcome_status": "ACCEPTED",
        "allocation_transaction_reference": allocation,
        "member_transactions": [],
        "member_transaction_references": [allocation],
        "control_plane_fteids": [],
        "bearer_user_plane_fteids": [],
        "observation_window": {"start_frame": 100, "end_frame": 103},
        "evidence_refs": [
            evidence(100, "Create Session Request"),
            evidence(103, "Create Session Response"),
        ],
        "limitations": [],
    }


def binding(
    *,
    capture: str = CAPTURE_A,
    transaction: str = TX,
    context_reference: str = CONTEXT,
    status: str = ESTABLISHED,
    outcome: str = ACCEPTED,
    frames: tuple[int, int] = (200, 205),
    competing: list[str] | None = None,
) -> dict:
    return {
        "capture_file": capture,
        "relationship_type": "RELEASE_TO_SESSION_CONTEXT",
        "source_subject_reference": transaction,
        "target_subject_reference": context_reference if status == ESTABLISHED else None,
        "association_status": status,
        "association_basis": "receiver_scoped_addressing",
        "reviewed_identifiers": [{"kind": "request_addressing", "header_teid": 9}],
        "source_transaction_references": [transaction],
        "source_frames": list(frames),
        "evidence_refs": [
            evidence(frames[0], "Delete Session Request"),
            evidence(frames[1], "Delete Session Response"),
        ],
        "observation_window": {"start_frame": frames[0], "end_frame": frames[1]},
        "competing_candidates": list(competing or []),
        "release_outcome_status": outcome,
        "release_outcome_basis": "accepted_cause_in_correlated_response",
        "lifecycle_control_plane_context": {
            "session_teid": 9,
            "basis": "request_header_teid",
        },
        "limitations": [],
    }


def bearer_endpoint(
    *, direction: str = "DOWNLINK", capture: str = CAPTURE_A, endpoint: dict | None = None
) -> dict:
    if endpoint is None:
        role, address, teid, interface_type = endpoint_values(direction)
    else:
        role = endpoint["role"]
        address = endpoint["address"]
        teid = endpoint["teid"]
        interface_type = endpoint["interface_type"]
    return {
        "role": role,
        "address": address,
        "teid": teid,
        "interface_type": interface_type,
        "eps_bearer_identities": [5],
        "generation_references": [GENERATION],
    }


def generation_link(
    *,
    capture: str = CAPTURE_A,
    context_reference: str = CONTEXT,
    direction: str = "DOWNLINK",
    status: str = ESTABLISHED,
    endpoint: dict | None = None,
) -> dict:
    return {
        "capture_file": capture,
        "relationship_type": "SESSION_CONTEXT_TO_BEARER_GENERATION",
        "source_subject_reference": context_reference,
        "target_subject_reference": endpoint_reference(capture, direction, endpoint),
        "association_status": status,
        "association_basis": "accepted_item_scoped_bearer_identity",
        "reviewed_identifiers": [],
        "source_transaction_references": ["tx-create-1"],
        "source_frames": [103],
        "evidence_refs": [evidence(103, "Create Session Response")],
        "observation_window": {"start_frame": 103, "end_frame": 103},
        "competing_candidates": [],
        "bearer_endpoint": bearer_endpoint(
            direction=direction, capture=capture, endpoint=endpoint
        ),
        "bridge_mediated": False,
        "limitations": [],
    }


def closure_candidate(
    *,
    capture: str = CAPTURE_A,
    reference: str = CANDIDATE,
    context_reference: str = CONTEXT,
    transaction: str = TX,
    direction: str = "DOWNLINK",
    status: str = ESTABLISHED,
    endpoint: dict | None = None,
) -> dict:
    endpoint_reference_value = endpoint_reference(capture, direction, endpoint)
    return {
        "capture_file": capture,
        "generation_closure_candidate_reference": reference,
        "session_context_reference": context_reference,
        "release_transaction_reference": transaction,
        "bearer_endpoint_reference": endpoint_reference_value,
        "bearer_endpoint": bearer_endpoint(
            direction=direction, capture=capture, endpoint=endpoint
        ),
        "association_status": status,
        "association_basis": "accepted_release_bound_to_one_established_context",
        "chain": [
            {
                "relationship_type": "RELEASE_TO_SESSION_CONTEXT",
                "subject_reference": transaction,
                "association_status": ESTABLISHED,
            },
            {
                "relationship_type": "SESSION_CONTEXT_TO_BEARER_GENERATION",
                "subject_reference": endpoint_reference_value,
                "association_status": ESTABLISHED,
            },
        ],
        "item_identities": {
            "release_bearer_identities": [5],
            "endpoint_bearer_identities": [5],
        },
        "release_request_frame": 200,
        "release_confirmation_frame": 205,
        "limitations": [],
    }


def identity_document(
    *,
    contexts: list[dict] | None = None,
    bindings: list[dict] | None = None,
    identity_links: list[dict] | None = None,
    correspondences: list[dict] | None = None,
    generation_links: list[dict] | None = None,
    candidates: list[dict] | None = None,
    overrides: dict | None = None,
) -> dict:
    contexts = [context()] if contexts is None else contexts
    bindings = [binding()] if bindings is None else bindings
    identity_links = [] if identity_links is None else identity_links
    correspondences = [] if correspondences is None else correspondences
    generation_links = [generation_link()] if generation_links is None else generation_links
    candidates = [closure_candidate()] if candidates is None else candidates
    document = {
        "domain": "epc-procedures",
        "domain_version": "0.6.0",
        "analysis_name": "epc-session-identity",
        "analysis_version": "1.0.0",
        "input_provenance": {},
        "analysis_scope": {},
        "hop_local_contexts": contexts,
        "hop_local_context_count": len(contexts),
        "established_hop_local_context_count": sum(
            1 for item in contexts if item.get("association_status") == ESTABLISHED
        ),
        "cross_interface_candidates": [],
        "cross_interface_candidate_count": 0,
        "endpoint_correspondence_links": correspondences,
        "endpoint_correspondence_count": len(correspondences),
        "session_identity_links": identity_links,
        "session_identity_count": len(identity_links),
        "release_session_bindings": bindings,
        "release_session_binding_count": len(bindings),
        "release_session_bindings_omitted": 0,
        "session_to_generation_links": generation_links,
        "session_to_generation_count": len(generation_links),
        "session_to_generation_omitted": 0,
        "generation_closure_candidates": candidates,
        "generation_closure_candidate_count": len(candidates),
        "generation_closure_candidates_omitted": 0,
        "established_closure_candidate_count": sum(
            1 for item in candidates if item.get("association_status") == ESTABLISHED
        ),
        "ambiguous_associations": [],
        "ambiguous_association_count": 0,
        "unbound_evidence": [],
        "unbound_evidence_count": 0,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "not an abnormal failure boundary",
    }
    document.update(overrides or {})
    return document


def generation(
    *,
    capture: str = CAPTURE_A,
    reference: str = GENERATION,
    direction: str = "DOWNLINK",
    state: str = "CLOSED_BY_ACCEPTED_RELEASE",
    transaction: str | None = TX,
    endpoint: dict | None = None,
) -> dict:
    if endpoint is None:
        role, address, teid, interface_type = endpoint_values(direction)
    else:
        role = endpoint["role"]
        address = endpoint["address"]
        teid = endpoint["teid"]
        interface_type = endpoint["interface_type"]
    boundary = (
        {
            "release_request_frame": 200,
            "release_confirmation_frame": 205,
            "frame_number": 205,
            "transaction_reference": transaction,
            "basis": "accepted_release_response_bound_by_reviewed_session_context",
            "release_effective_frame_proven": False,
        }
        if transaction is not None
        else None
    )
    return {
        "generation_reference": reference,
        "capture_file": capture,
        "receiving_endpoint_address": address,
        "receiving_endpoint_teid": teid,
        "receiving_endpoint_role": role,
        "reviewed_interface_type": interface_type,
        "generation_state": state,
        "generation_boundary": boundary,
        "advertisement_family_references": [],
        "observations": [],
        "observation_window": {"start_frame": 103, "end_frame": 205},
        "evidence_refs": [evidence(103, "Create Session Response")],
        "limitations": [],
    }


def boundary(
    *,
    capture: str = CAPTURE_A,
    transaction: str = TX,
    outcome: str = ACCEPTED,
) -> dict:
    role, address, teid, interface_type = endpoint_values()
    return {
        "capture_file": capture,
        "transaction_reference": transaction,
        "request_frame": 200,
        "request_message_type": "Delete Session Request",
        "response_frame": 205,
        "response_message_type": "Delete Session Response",
        "correlation_status": "MATCHED",
        "correlation_strength": "STRONG",
        "release_outcome": outcome,
        "release_outcome_basis": "accepted_cause_in_correlated_response",
        "released_endpoints": [
            {
                "address": address,
                "teid": teid,
                "interface_type": interface_type,
                "role": role,
            }
        ],
        "control_plane_context": {
            "session_teid": 9,
            "basis": "correlated_response_header_teid",
        },
        "bearer_identity_scope": [5],
        "evidence_refs": [
            evidence(200, "Delete Session Request"),
            evidence(205, "Delete Session Response"),
        ],
        "limitations": [],
    }


def scoped(
    *,
    generation_reference: str = GENERATION,
    stream_reference: str = STREAM,
    direction: str = "DOWNLINK",
    overrides: dict | None = None,
) -> dict:
    role, _address, _teid, _interface_type = endpoint_values(direction)
    record = {
        "source_stream_reference": stream_reference,
        "generation_reference": generation_reference,
        "receiving_endpoint_role": role,
        "direction": direction,
        "first_observed_frame": 100,
        "last_observed_frame": 210,
        "observed_g_pdu_count": 4,
        "observed_payload_octets": 400,
        "association_status": "SUPPORTED",
        "allocation_evidence_refs": [],
        "generation_boundary_refs": [],
        "packet_evidence_refs": [],
        "limitations": [],
    }
    record.update(overrides or {})
    return record


def lifecycle_document(
    *,
    subjects: list[dict] | None = None,
    boundaries: list[dict] | None = None,
    scoped_records: list[dict] | None = None,
    accounting: dict | None = None,
    overrides: dict | None = None,
) -> dict:
    subjects = [generation()] if subjects is None else subjects
    boundaries = [boundary()] if boundaries is None else boundaries
    scoped_records = [scoped()] if scoped_records is None else scoped_records
    accounting = (
        {
            "aggregate_g_pdu_count": 4,
            "attributed_g_pdu_count": 2,
            "unresolved_g_pdu_count": 2,
            "aggregate_payload_octets": 400,
            "attributed_payload_octets": 200,
            "unresolved_payload_octets": 200,
            "conserved_g_pdu": True,
            "conserved_payload_octets": True,
        }
        if accounting is None
        else accounting
    )
    document = {
        "domain": "epc-procedures",
        "domain_version": "0.5.0",
        "analysis_name": "epc-bearer-lifecycle",
        "analysis_version": "1.0.0",
        "input_provenance": {},
        "analysis_scope": {},
        "lifecycle_subject_count": len(subjects),
        "lifecycle_subjects": subjects,
        "lifecycle_subjects_omitted": 0,
        "advertisement_family_count": 0,
        "advertisement_families": [],
        "advertisement_families_omitted": 0,
        "generation_observations": [],
        "generation_boundary_evidence": boundaries,
        "generation_boundary_count": len(boundaries),
        "endpoint_reuse_observations": [],
        "endpoint_reuse_observation_count": 0,
        "generation_scoped_s1u_observations": scoped_records,
        "generation_scoped_observation_count": len(scoped_records),
        "unresolved_packet_observations": [],
        "unresolved_packet_observation_count": 0,
        "ambiguous_associations": [],
        "ambiguous_association_count": 0,
        "unbound_evidence": [],
        "procedure_local_deviations": [],
        "procedure_local_deviation_count": 0,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "accounting": accounting,
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "not an abnormal failure boundary",
        "release_observation_count": len(boundaries),
    }
    document.update(overrides or {})
    return document


def stage(stage_name: str, evidence_status: str, frame: int | None = None) -> dict:
    return {
        "stage": stage_name,
        "evidence_status": evidence_status,
        "source_analysis": "epc-release-narrative",
        "source_subject_reference": None,
        "transaction_reference": TX,
        "capture_file": CAPTURE_A,
        "frame_number": frame,
        "message_type": None,
        "evidence_refs": [],
        "association_basis": None,
        "limitations": [],
    }


def stages(
    *,
    outcome: str = ACCEPTED,
    binding_status: str = ESTABLISHED,
    closure_status: str = ESTABLISHED,
    effective_proven: bool = False,
) -> list[dict]:
    outcome_stage = {
        ACCEPTED: ("RELEASE_OUTCOME_ACCEPTED", "ACCEPTED"),
        "REJECTED_OBSERVED": ("RELEASE_OUTCOME_REJECTED_OBSERVED", "REJECTED_OBSERVED"),
        UNRESOLVED: ("RELEASE_OUTCOME_UNRESOLVED", "UNRESOLVED"),
    }[outcome]
    return [
        stage("ALLOCATION_OBSERVED", "OBSERVED", 100),
        stage("ALLOCATION_ACCEPTED", "ACCEPTED", 103),
        stage("SESSION_CONTEXT_ESTABLISHED", ESTABLISHED, 103),
        stage("BEARER_ASSOCIATION_ESTABLISHED", ESTABLISHED, 103),
        stage("RELEASE_REQUEST_OBSERVED", "OBSERVED", 200),
        stage(outcome_stage[0], outcome_stage[1], 205),
        stage(
            "RELEASE_SESSION_BINDING_ESTABLISHED"
            if binding_status == ESTABLISHED
            else "RELEASE_SESSION_BINDING_NOT_ESTABLISHED",
            ESTABLISHED if binding_status == ESTABLISHED else NOT_ESTABLISHED,
            200,
        ),
        stage(
            "GENERATION_CLOSURE_ESTABLISHED"
            if closure_status == ESTABLISHED
            else "GENERATION_CLOSURE_NOT_ESTABLISHED",
            ESTABLISHED if closure_status == ESTABLISHED else NOT_ESTABLISHED,
            205,
        ),
        stage(
            "RELEASE_EFFECTIVE_INSTANT_UNPROVED",
            "ESTABLISHED" if effective_proven else NOT_ESTABLISHED,
            205,
        ),
    ]


def narrative_subject(
    *,
    capture: str = CAPTURE_A,
    reference: str = SUBJECT,
    context_reference: str = CONTEXT,
    group_reference: str = GROUP,
    group_basis: str = "single_hop_local_context",
    members: list[str] | None = None,
    bridge_references: list[str] | None = None,
    correspondences: list[str] | None = None,
) -> dict:
    return {
        "narrative_subject_reference": reference,
        "capture_file": capture,
        "interface_class": "S11",
        "session_context_reference": context_reference,
        "session_context_status": ESTABLISHED,
        "session_context_basis": "reviewed_receiver_scoped_addressing",
        "allocation_transaction_reference": "tx-create-1",
        "allocation_outcome_status": "ACCEPTED",
        "member_transaction_references": ["tx-create-1"],
        "observation_window": {"start_frame": 100, "end_frame": 103},
        "source_evidence_refs": [evidence(100, "Create Session Request")],
        "narrative_group_reference": group_reference,
        "narrative_group_basis": group_basis,
        "narrative_group_members": members or [context_reference],
        "narrative_group_bridge_references": list(bridge_references or []),
        "session_identity_links": [],
        "endpoint_correspondence_references": list(correspondences or []),
        "bearer_endpoints": [],
        "release_narrative_references": [RELEASE],
        "temporal_limitations": [],
        "source_analysis": {
            "session_identity": "epc-session-identity",
            "lifecycle": "epc-bearer-lifecycle",
        },
        "limitations": [],
    }


def proved_generation(
    *,
    direction: str = "DOWNLINK",
    reference: str = GENERATION,
    endpoint: dict | None = None,
) -> dict:
    if endpoint is None:
        role, address, teid, interface_type = endpoint_values(direction)
    else:
        role = endpoint["role"]
        address = endpoint["address"]
        teid = endpoint["teid"]
        interface_type = endpoint["interface_type"]
    return {
        "generation_reference": reference,
        "receiving_endpoint_role": role,
        "receiving_endpoint_address": address,
        "receiving_endpoint_teid": teid,
        "reviewed_interface_type": interface_type,
        "generation_state": "CLOSED_BY_ACCEPTED_RELEASE",
        "generation_boundary_basis": "accepted_release_response_bound_by_reviewed_session_context",
        "release_request_frame": 200,
        "release_confirmation_frame": 205,
        "release_effective_frame_proven": False,
        "closure_candidate_reference": CANDIDATE,
        "closure_candidate_basis": "accepted_release_bound_to_one_established_context",
    }


def release(
    *,
    capture: str = CAPTURE_A,
    transaction: str = TX,
    context_reference: str = CONTEXT,
    subject_reference: str = SUBJECT,
    group_reference: str = GROUP,
    outcome: str = ACCEPTED,
    binding_status: str = ESTABLISHED,
    closure_status: str = ESTABLISHED,
    proved: list[dict] | None = None,
    temporal_references: list[str] | None = None,
    provenance: str = "VALIDATED",
) -> dict:
    return {
        "release_narrative_reference": RELEASE,
        "capture_file": capture,
        "narrative_subject_reference": subject_reference,
        "session_context_reference": context_reference,
        "interface_class": "S11",
        "narrative_group_reference": group_reference,
        "release_transaction_reference": transaction,
        "release_request_frame": 200,
        "release_confirmation_frame": 205,
        "release_outcome_status": outcome,
        "release_outcome_basis": "accepted_cause_in_correlated_response",
        "release_session_binding_status": binding_status,
        "release_session_binding_basis": "receiver_scoped_addressing",
        "generation_closure_status": closure_status,
        "generation_closure_basis": (
            "accepted_release_response_bound_by_reviewed_session_context"
            if closure_status == ESTABLISHED
            else "no_independently_proved_bearer_generation_closure"
        ),
        "release_effective_frame_proven": False,
        "stages": stages(
            outcome=outcome, binding_status=binding_status, closure_status=closure_status
        ),
        "proved_generations": (
            [proved_generation()] if proved is None and closure_status == ESTABLISHED else (proved or [])
        ),
        "competing_generations": [],
        "temporal_observation_references": (
            [TEMPORAL] if temporal_references is None else temporal_references
        ),
        "provenance_status": provenance,
        "limitations": [],
    }


def observation(
    *,
    capture: str = CAPTURE_A,
    direction: str = "DOWNLINK",
    stream_reference: str = STREAM,
    generation_reference: str | None = GENERATION,
    attribution: str = "ESTABLISHED",
    placement: str = "ESTABLISHED",
    partitions: dict | None = None,
    observed_count: int = 4,
    observed_octets: int = 400,
    duplicate_ownership: bool = False,
    overrides: dict | None = None,
) -> dict:
    role, _address, _teid, _interface_type = endpoint_values(direction)
    if partitions is None and placement == "ESTABLISHED":
        partitions = {
            "before_release": {
                "g_pdu_count": 2,
                "payload_octets": 200,
                "first_frame": 100,
                "last_frame": 150,
            },
            "pending_release": {
                "g_pdu_count": 1,
                "payload_octets": 100,
                "first_frame": 202,
                "last_frame": 202,
            },
            "after_confirmation": {
                "g_pdu_count": 1,
                "payload_octets": 100,
                "first_frame": 210,
                "last_frame": 210,
            },
        }
    record = {
        "temporal_observation_reference": TEMPORAL,
        "release_narrative_reference": RELEASE,
        "capture_file": capture,
        "stream_reference": stream_reference,
        "generation_reference": generation_reference,
        "receiving_endpoint_role": role,
        "direction": direction,
        "association_status": "SUPPORTED",
        "observed_g_pdu_count": observed_count,
        "observed_payload_octets": observed_octets,
        "first_observed_frame": 100,
        "last_observed_frame": 210,
        "release_request_frame": 200,
        "release_confirmation_frame": 205,
        "partitions": partitions if placement == "ESTABLISHED" else None,
        "partition_basis": (
            "FRAME_LEVEL_EVENTS" if placement == "ESTABLISHED" else "AGGREGATE_STREAM_ONLY"
        ),
        "temporal_placement_status": placement,
        "partition_conserved": True if placement == "ESTABLISHED" else None,
        "limitations": [],
        "generation_attribution_status": attribution,
        "generation_attribution_basis": (
            "accepted_stream_association_and_lifecycle_generation_scoped_s1u_observation"
            if attribution == "ESTABLISHED"
            else "endpoint_equality_alone_is_not_generation_ownership"
        ),
        "attribution_failures": [],
        "partition_scope": "COMPLETE_STREAM" if placement == "ESTABLISHED" else None,
        "duplicate_frame_ownership": duplicate_ownership,
    }
    record.update(overrides or {})
    return record


def narrative_document(
    *,
    subjects: list[dict] | None = None,
    releases: list[dict] | None = None,
    observations: list[dict] | None = None,
    temporal_accounting: dict | None = None,
    overrides: dict | None = None,
) -> dict:
    subjects = [narrative_subject()] if subjects is None else subjects
    releases = [release()] if releases is None else releases
    observations = [observation()] if observations is None else observations
    temporal_accounting = (
        {
            "frame_level_evidence_supplied": True,
            "observed_g_pdu_event_count": 4,
            "assigned_to_release_window_count": 4,
            "unassigned_g_pdu_event_count": 0,
            "duplicate_assignment_count": 0,
            "conserved": True,
            "attributed_observation_count": 1,
            "unattributed_observation_count": 0,
        }
        if temporal_accounting is None
        else temporal_accounting
    )
    document = {
        "domain": "epc-procedures",
        "domain_version": "0.7.0",
        "analysis_name": "epc-release-narrative",
        "analysis_version": "1.0.0",
        "input_provenance": {},
        "analysis_scope": {},
        "source_completeness": {"status": "COMPLETE"},
        "narrative_subjects": subjects,
        "narrative_subject_count": len(subjects),
        "narrative_subjects_omitted": 0,
        "release_narratives": releases,
        "release_narrative_count": len(releases),
        "release_narratives_omitted": 0,
        "temporal_observations": observations,
        "temporal_observation_count": len(observations),
        "temporal_observations_omitted": 0,
        "temporal_accounting": temporal_accounting,
        "ambiguous_associations": [],
        "ambiguous_association_count": 0,
        "unbound_evidence": [],
        "unbound_evidence_count": 0,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "not an abnormal failure boundary",
    }
    document.update(overrides or {})
    return document


def s1u_stream(
    *,
    capture: str = CAPTURE_A,
    direction: str = "DOWNLINK",
    stream_reference: str = STREAM,
    count: int = 4,
    octets: int = 400,
) -> dict:
    role, address, teid, _interface_type = endpoint_values(direction)
    source = "10.0.0.20" if direction == "DOWNLINK" else "10.0.0.40"
    return {
        "stream_reference": stream_reference,
        "capture_file": capture,
        "outer_source": source,
        "outer_destination": address,
        "teid": teid,
        "first_frame": 100,
        "last_frame": 210,
        "observed_g_pdu_packet_count": count,
        "observed_payload_byte_count": octets,
        "direction": direction,
        "association_status": "SUPPORTED",
        "matched_endpoint_role": role,
        "receiving_endpoint_match_status": "MATCHED",
        "outcomes": [],
        "deviations": [],
        "limitations": [],
    }


def s1u_document(
    *,
    streams: list[dict] | None = None,
    overrides: dict | None = None,
) -> dict:
    streams = [s1u_stream()] if streams is None else streams
    document = {
        "domain": "epc-procedures",
        "analysis_name": "epc-s1u-observation",
        "analysis_version": "1.0.0",
        "stream_count": len(streams),
        "stream_observations": streams,
        "streams_omitted": 0,
        "observed_g_pdu_packet_count": sum(
            int(item.get("observed_g_pdu_packet_count") or 0) for item in streams
        ),
        "observed_payload_byte_count": sum(
            int(item.get("observed_payload_byte_count") or 0) for item in streams
        ),
    }
    document.update(overrides or {})
    return document


def gtpu_event(
    frame: int,
    *,
    capture: str = CAPTURE_A,
    direction: str = "DOWNLINK",
    teid: int | None = None,
    octets: int = 100,
) -> dict:
    _role, address, default_teid, _interface_type = endpoint_values(direction)
    source = "10.0.0.20" if direction == "DOWNLINK" else "10.0.0.40"
    return {
        "capture_file": capture,
        "frame_number": frame,
        "header": {
            "message_type": "G-PDU",
            "teid": default_teid if teid is None else teid,
            "message_length": octets,
        },
        "outer": {"source_address": source, "destination_address": address},
    }


def gtpv2_event(frame: int, message: str, capture: str = CAPTURE_A) -> dict:
    return {"capture_file": capture, "frame_number": frame, "message_type": message}


def scenario(
    *,
    direction: str = "DOWNLINK",
    capture: str = CAPTURE_A,
    with_gtpv2: bool = True,
    with_gtpu: bool = True,
    with_s1u: bool = True,
    closure: bool = True,
) -> dict:
    documents = {
        "identity": identity_document(
            bindings=[binding(capture=capture)],
            generation_links=[generation_link(capture=capture, direction=direction)],
            candidates=(
                [closure_candidate(capture=capture, direction=direction)]
                if closure
                else []
            ),
        ),
        "lifecycle": lifecycle_document(
            subjects=[generation(capture=capture, direction=direction)],
            boundaries=[boundary(capture=capture)],
            scoped_records=[scoped(direction=direction)],
        ),
        "narrative": narrative_document(
            releases=[
                release(
                    capture=capture,
                    closure_status=ESTABLISHED if closure else NOT_ESTABLISHED,
                    proved=[proved_generation(direction=direction)] if closure else [],
                )
            ]
        ),
        "s1u": s1u_document(streams=[s1u_stream(capture=capture, direction=direction)])
        if with_s1u
        else None,
        "gtpv2": [
            gtpv2_event(100, "Create Session Request", capture),
            gtpv2_event(103, "Create Session Response", capture),
            gtpv2_event(200, "Delete Session Request", capture),
            gtpv2_event(205, "Delete Session Response", capture),
        ]
        if with_gtpv2
        else None,
        "gtpu": [
            gtpu_event(frame, capture=capture, direction=direction)
            for frame in (100, 150, 202, 210)
        ]
        if with_gtpu
        else None,
    }
    if not with_gtpu:
        documents["narrative"]["temporal_observations"] = [
            observation(
                capture=capture,
                direction=direction,
                placement="TEMPORAL_PLACEMENT_NOT_ESTABLISHED",
                partitions=None,
            )
        ]
        documents["narrative"]["temporal_accounting"] = {
            "frame_level_evidence_supplied": False,
            "observed_g_pdu_event_count": 0,
            "assigned_to_release_window_count": 0,
            "unassigned_g_pdu_event_count": 0,
            "duplicate_assignment_count": 0,
            "conserved": True,
            "attributed_observation_count": 1,
            "unattributed_observation_count": 0,
        }
    return documents


def identity_link(
    *,
    capture: str = CAPTURE_A,
    source: str = CONTEXT,
    target: str = CONTEXT_B,
    status: str = ESTABLISHED,
    reference: str = IDENTITY_LINK,
) -> dict:
    return {
        "reference": reference,
        "relationship_type": "CROSS_INTERFACE_SESSION_IDENTITY",
        "capture_file": capture,
        "source_subject_reference": source,
        "target_subject_reference": target,
        "association_status": status,
        "association_basis": "equal_relayed_control_plane_fteid",
        "source_frames": [103],
        "competing_candidates": [],
        "limitations": [],
    }


def endpoint_correspondence(
    *,
    capture: str = CAPTURE_A,
    source: str = CONTEXT,
    target: str = CONTEXT_B,
    reference: str = CORRESPONDENCE,
) -> dict:
    return {
        "reference": reference,
        "relationship_type": "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE",
        "capture_file": capture,
        "source_subject_reference": source,
        "target_subject_reference": target,
        "association_status": ESTABLISHED,
        "association_basis": "corresponding_user_plane_endpoint",
        "source_frames": [103],
        "competing_candidates": [],
        "limitations": [],
    }


def closure_documents(
    specs: list[dict],
    *,
    claim: str = ESTABLISHED,
    outcome: str = ACCEPTED,
    bindings: list[dict] | None = None,
) -> dict:
    """Minimal accepted closure chain: one proved generation per spec."""
    subjects: list[dict] = []
    links: list[dict] = []
    candidates: list[dict] = []
    proved: list[dict] = []
    for spec in specs:
        direction = spec.get("direction", "DOWNLINK")
        endpoint = spec.get("endpoint")
        generation_reference = spec.get("generation_reference", GENERATION)
        subjects.append(
            generation(
                direction=direction,
                reference=generation_reference,
                endpoint=endpoint,
            )
        )
        links.append(
            generation_link(
                direction=direction,
                endpoint=endpoint,
                status=spec.get("link_status", ESTABLISHED),
            )
        )
        candidates.append(
            closure_candidate(
                direction=direction,
                endpoint=endpoint,
                reference=spec.get("candidate_reference", CANDIDATE),
                status=spec.get("candidate_status", ESTABLISHED),
            )
        )
        proved.append(
            proved_generation(
                direction=direction,
                reference=generation_reference,
                endpoint=endpoint,
            )
        )
    identity = identity_document(
        generation_links=links,
        candidates=candidates,
        bindings=[binding()] if bindings is None else bindings,
    )
    lifecycle = lifecycle_document(
        subjects=subjects,
        boundaries=[boundary()],
        scoped_records=[],
    )
    narrative = narrative_document(
        releases=[
            release(
                proved=proved if claim == ESTABLISHED else [],
                closure_status=claim,
                outcome=outcome,
                temporal_references=[],
            )
        ],
        observations=[],
        temporal_accounting={
            "frame_level_evidence_supplied": False,
            "observed_g_pdu_event_count": 0,
            "assigned_to_release_window_count": 0,
            "unassigned_g_pdu_event_count": 0,
            "duplicate_assignment_count": 0,
            "conserved": True,
            "attributed_observation_count": 0,
            "unattributed_observation_count": 0,
        },
    )
    return {
        "identity": identity,
        "lifecycle": lifecycle,
        "narrative": narrative,
        "s1u": None,
        "gtpv2": [
            gtpv2_event(100, "Create Session Request"),
            gtpv2_event(103, "Create Session Response"),
            gtpv2_event(200, "Delete Session Request"),
            gtpv2_event(205, "Delete Session Response"),
        ],
        "gtpu": None,
    }


def observed_subset_documents() -> dict:
    """A producer-generated OBSERVED_SUBSET against the larger accepted aggregate.

    The observation and temporal accounting are emitted by the accepted release
    narrative producer, not hand-written here. For a non-conserved subset the
    producer assigns no frame to a release window: assigned = 0 and
    unassigned = the number of supplied frame events.
    """
    documents = scenario()
    stream_record = documents["s1u"]["stream_observations"][0]
    stream_record["observed_g_pdu_packet_count"] = 10
    stream_record["observed_payload_byte_count"] = 1000
    documents["s1u"]["observed_g_pdu_packet_count"] = 10
    documents["s1u"]["observed_payload_byte_count"] = 1000
    scoped_record = documents["lifecycle"]["generation_scoped_s1u_observations"][0]
    scoped_record["observed_g_pdu_count"] = 10
    scoped_record["observed_payload_octets"] = 1000
    documents["lifecycle"]["accounting"] = {
        "aggregate_g_pdu_count": 10,
        "attributed_g_pdu_count": 10,
        "unresolved_g_pdu_count": 0,
        "aggregate_payload_octets": 1000,
        "attributed_payload_octets": 1000,
        "unresolved_payload_octets": 0,
        "conserved_g_pdu": True,
        "conserved_payload_octets": True,
    }
    documents["gtpu"] = [gtpu_event(frame) for frame in (100, 202, 210)]
    release = copy.deepcopy(documents["narrative"]["release_narratives"][0])
    release["temporal_observation_references"] = []
    observations, accounting, _limitations, _unbound = (
        narrative_model.build_temporal_observations(
            [release],
            documents["s1u"],
            documents["gtpu"],
            documents["lifecycle"],
            (True, None),
        )
    )
    documents["narrative"]["release_narratives"] = [release]
    documents["narrative"]["temporal_observations"] = observations
    documents["narrative"]["temporal_observation_count"] = len(observations)
    documents["narrative"]["temporal_accounting"] = accounting
    return documents


def two_capture_documents() -> dict:
    first = scenario()
    second = scenario(capture=CAPTURE_B)
    pairs = (
        ("identity", "hop_local_contexts", "hop_local_context_count"),
        ("identity", "release_session_bindings", "release_session_binding_count"),
        ("identity", "session_to_generation_links", "session_to_generation_count"),
        (
            "identity",
            "generation_closure_candidates",
            "generation_closure_candidate_count",
        ),
        ("lifecycle", "lifecycle_subjects", "lifecycle_subject_count"),
        ("lifecycle", "generation_boundary_evidence", "generation_boundary_count"),
        (
            "lifecycle",
            "generation_scoped_s1u_observations",
            "generation_scoped_observation_count",
        ),
        ("narrative", "narrative_subjects", "narrative_subject_count"),
        ("narrative", "release_narratives", "release_narrative_count"),
        ("narrative", "temporal_observations", "temporal_observation_count"),
    )
    for document_name, key, count_key in pairs:
        first[document_name][key] += second[document_name][key]
        first[document_name][count_key] = len(first[document_name][key])
    stream_observations = first["s1u"]["stream_observations"] + second["s1u"][
        "stream_observations"
    ]
    first["s1u"]["stream_observations"] = stream_observations
    first["s1u"]["stream_count"] = len(stream_observations)
    first["s1u"]["observed_g_pdu_packet_count"] = sum(
        int(item.get("observed_g_pdu_packet_count") or 0) for item in stream_observations
    )
    first["s1u"]["observed_payload_byte_count"] = sum(
        int(item.get("observed_payload_byte_count") or 0) for item in stream_observations
    )
    first["gtpv2"] = first["gtpv2"] + second["gtpv2"]
    first["gtpu"] = first["gtpu"] + second["gtpu"]
    return first


def audit(documents: dict) -> dict:
    return model.analyze(
        documents["identity"],
        documents["lifecycle"],
        documents["narrative"],
        s1u=documents.get("s1u"),
        gtpv2_events=documents.get("gtpv2"),
        gtpu_events=documents.get("gtpu"),
        provenance={"session_identity": "identity.json"},
    )


def records(result: dict, category: str) -> list[dict]:
    return [
        record
        for record in result["audit_records"]
        if record["audit_category"] == category
    ]


def record_for(result: dict, category: str, subject: str) -> dict:
    matches = [
        record
        for record in records(result, category)
        if record.get("source_subject_reference") == subject
        or record.get("target_subject_reference") == subject
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {category} record for {subject}, found {len(matches)}"
        )
    return matches[0]


def check_result(record: dict, token: str) -> str | None:
    results = [
        str(check.get("result"))
        for check in record.get("consistency_checks") or []
        if check.get("check") == token
    ]
    if not results:
        return None
    if "FAIL" in results:
        return "FAIL"
    if "PASS" in results:
        return "PASS"
    return results[-1]


def limitations(result: dict) -> str:
    return " ".join(
        limitation
        for record in result["audit_records"]
        for limitation in record.get("limitations") or []
    )


class EvidenceAuditFixturesTest(unittest.TestCase):
    def test_f01_positive_chain_is_fully_consistent(self) -> None:
        result = audit(scenario())
        self.assertEqual(result["analysis_name"], "epc-evidence-audit")
        self.assertEqual(result["audit_summary"]["overall_status"], "AUDIT_CONSISTENT")
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)
        self.assertEqual(result["audit_summary"]["ambiguous_count"], 0)
        self.assertEqual(result["source_completeness"]["status"], "COMPLETE")
        self.assertTrue(result["source_completeness"]["exhaustive_coverage_proven"])
        self.assertEqual(result["source_artifact_count"], 6)
        self.assertEqual(result["reference_integrity_summary"]["references_missing"], 0)
        self.assertEqual(result["boundary_selection_status"], "NOT_APPLICABLE")
        self.assertIsNone(result["first_abnormal_boundary"])

    def test_f02_schema_declares_exactly_the_published_fields(self) -> None:
        schema = json.loads(
            (PACKAGE / "schemas" / "epc-evidence-audit-analysis.schema.json").read_text(
                encoding="utf-8"
            )
        )
        result = audit(scenario())
        self.assertEqual(set(schema["required"]), set(result))
        self.assertEqual(
            set(schema["$defs"]["audit_category"]["enum"]), set(model.AUDIT_CATEGORIES)
        )
        self.assertEqual(
            set(schema["$defs"]["audit_status"]["enum"]), set(model.AUDIT_STATUSES)
        )
        self.assertEqual(
            set(schema["$defs"]["check_token"]["enum"]), set(model.CHECK_TOKENS)
        )
        self.assertEqual(
            schema["properties"]["boundary_selection_status"]["const"],
            "NOT_APPLICABLE",
        )
        self.assertEqual(
            schema["properties"]["first_abnormal_boundary"], {"type": "null"}
        )

    def test_f03_rules_document_matches_the_closed_vocabularies(self) -> None:
        rules = json.loads(
            (PACKAGE / "rules" / "epc-evidence-audit-model.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(rules["audit_categories"]), set(model.AUDIT_CATEGORIES))
        self.assertEqual(set(rules["audit_statuses"]), set(model.AUDIT_STATUSES))
        self.assertEqual(
            set(rules["completeness_statuses"]), set(model.COMPLETENESS_STATUSES)
        )
        self.assertEqual(
            set(rules["proof_sufficiency_statuses"]), set(model.PROOF_STATUSES)
        )
        self.assertEqual(set(rules["check_tokens"]), set(model.CHECK_TOKENS))
        self.assertEqual(tuple(rules["not_confirmed"]), tuple(model.NOT_CONFIRMED))

    def test_f04_all_references_resolve(self) -> None:
        result = audit(scenario())
        for record in records(result, "REFERENCE_INTEGRITY"):
            self.assertEqual(record["audit_status"], "VERIFIED_CONSISTENT")
            for check in record["consistency_checks"]:
                self.assertIn(check["result"], ("PASS", "NOT_EVALUATED"))

    def test_f05_missing_referenced_transaction_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["release_narratives"][0][
            "release_transaction_reference"
        ] = "gtpv2-delete-session-unknown"
        result = audit(documents)
        self.assertGreater(result["audit_summary"]["inconsistent_count"], 0)
        anchor = next(
            record
            for record in records(result, "TRANSACTION_ANCHOR")
            if check_result(record, "release_transaction_agrees") == "FAIL"
        )
        self.assertEqual(anchor["audit_status"], "INCONSISTENT")

    def test_f06_missing_referenced_context_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["narrative_subjects"][0][
            "session_context_reference"
        ] = "epc-session-context-unknown"
        result = audit(documents)
        reference = next(
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if check_result(record, "session_context_present") == "FAIL"
        )
        self.assertEqual(reference["audit_status"], "INCONSISTENT")

    def test_f07_missing_bearer_endpoint_is_inconsistent(self) -> None:
        documents = scenario()
        documents["identity"]["generation_closure_candidates"][0][
            "bearer_endpoint_reference"
        ] = "epc-bearer-endpoint-unknown"
        result = audit(documents)
        candidate = next(
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if check_result(record, "endpoint_identity_agrees") == "FAIL"
            or check_result(record, "bearer_endpoint_present") == "FAIL"
        )
        self.assertEqual(candidate["audit_status"], "INCONSISTENT")

    def test_f08_missing_generation_reference_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["release_narratives"][0]["proved_generations"][0][
            "generation_reference"
        ] = "epc-bearer-generation-unknown"
        result = audit(documents)
        reference = next(
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if check_result(record, "generation_present") == "FAIL"
        )
        self.assertEqual(reference["audit_status"], "INCONSISTENT")
        self.assertIn("does not publish in the same capture", limitations(result))

    def test_f09_missing_stream_reference_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["temporal_observations"][0][
            "stream_reference"
        ] = "epc-s1u-stream-9999999999"
        result = audit(documents)
        reference = next(
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if check_result(record, "stream_present") == "FAIL"
        )
        self.assertEqual(reference["audit_status"], "INCONSISTENT")

    def test_f10_equal_teid_across_captures_is_not_a_relationship(self) -> None:
        documents = scenario()
        second = generation(
            capture=CAPTURE_B, reference="epc-bearer-generation-9999999999", transaction=None
        )
        second["generation_state"] = "OPEN_AT_CAPTURE_END"
        documents["lifecycle"]["lifecycle_subjects"].append(second)
        documents["lifecycle"]["lifecycle_subject_count"] = 2
        result = audit(documents)
        collision = [
            record
            for record in records(result, "CAPTURE_SCOPE")
            if check_result(record, "frame_number_is_capture_local") == "PASS"
        ]
        self.assertTrue(collision)
        self.assertIn("no cross-capture relationship", limitations(result))
        self.assertEqual(result["capture_scope_summary"]["cross_capture_value_collisions"], 1)

    def test_f11_equal_frame_number_across_captures_is_capture_local(self) -> None:
        documents = scenario()
        documents["gtpv2"] = list(documents["gtpv2"]) + [
            gtpv2_event(100, "Delete Session Request", CAPTURE_B)
        ]
        result = audit(documents)
        collision = [
            record
            for record in records(result, "CAPTURE_SCOPE")
            if check_result(record, "frame_number_is_capture_local") == "PASS"
        ]
        self.assertTrue(collision)
        self.assertIn("frame 100 appears in more than one capture", limitations(result))

    def test_f12_endpoint_correspondence_is_not_session_identity(self) -> None:
        documents = scenario()
        correspondence = {
            "reference": CORRESPONDENCE,
            "relationship_type": "CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE",
            "capture_file": CAPTURE_A,
            "source_subject_reference": CONTEXT,
            "target_subject_reference": CONTEXT_B,
            "association_status": "SUPPORTED",
            "association_basis": "equal_user_plane_fteid",
            "source_frames": [103],
            "limitations": [],
        }
        documents["identity"]["endpoint_correspondence_links"] = [correspondence]
        documents["identity"]["endpoint_correspondence_count"] = 1
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2
        documents["narrative"]["narrative_subjects"][0][
            "endpoint_correspondence_references"
        ] = [CORRESPONDENCE]
        result = audit(documents)
        bridge = record_for(result, "CROSS_INTERFACE_BRIDGE", SUBJECT)
        self.assertEqual(bridge["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(check_result(bridge, "group_membership_backed_by_established_bridge"), "PASS")

    def test_f13_competing_identity_links_fail_a_group_bridge(self) -> None:
        documents = scenario()
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2

        def ambiguous_link(reference: str) -> dict:
            return {
                "reference": reference,
                "relationship_type": "CROSS_INTERFACE_SESSION_IDENTITY",
                "capture_file": CAPTURE_A,
                "source_subject_reference": CONTEXT,
                "target_subject_reference": CONTEXT_B,
                "association_status": "AMBIGUOUS",
                "association_basis": "several_candidate_bridges",
                "source_frames": [103],
                "competing_candidates": [CONTEXT_B],
                "limitations": [],
            }

        documents["identity"]["session_identity_links"] = [
            ambiguous_link(IDENTITY_LINK),
            ambiguous_link("epc-identity-link-5555555555"),
        ]
        documents["identity"]["session_identity_count"] = 2
        subject = documents["narrative"]["narrative_subjects"][0]
        subject["narrative_group_basis"] = "proved_cross_interface_session_identity"
        subject["narrative_group_members"] = [CONTEXT, CONTEXT_B]
        subject["narrative_group_bridge_references"] = [IDENTITY_LINK]
        result = audit(documents)
        bridge = record_for(result, "CROSS_INTERFACE_BRIDGE", SUBJECT)
        self.assertEqual(bridge["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(bridge, "group_membership_backed_by_established_bridge"), "FAIL")

    def test_f14_accepted_release_without_closure_stays_separate(self) -> None:
        documents = scenario(closure=False)
        result = audit(documents)
        closure = record_for(result, "GENERATION_CLOSURE", RELEASE)
        self.assertEqual(closure["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(closure["proof_sufficiency_status"], "INSUFFICIENT")
        narrative = documents["narrative"]["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], ACCEPTED)
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertIn("audited separately", limitations(result))

    def test_f15_closure_candidate_for_another_release_never_closes_this_one(self) -> None:
        documents = scenario()
        documents["identity"]["generation_closure_candidates"][0][
            "release_transaction_reference"
        ] = TX_OTHER
        result = audit(documents)
        closure = record_for(result, "GENERATION_CLOSURE", RELEASE)
        self.assertEqual(closure["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(closure, "release_transaction_agrees"), "FAIL")
        self.assertIn("another release transaction", limitations(result))

    def test_f16_truncated_binding_collection_is_source_truncated(self) -> None:
        documents = scenario()
        documents["identity"]["release_session_binding_count"] = 2
        result = audit(documents)
        entry = next(
            item
            for item in result["source_completeness"]["collections"]
            if item["collection"] == "release_session_bindings"
        )
        self.assertEqual(entry["status"], "SOURCE_TRUNCATED")
        self.assertEqual(entry["condition"], "COUNT_TRUNCATED")
        binding_record = record_for(result, "RELEASE_SESSION_BINDING", RELEASE)
        self.assertEqual(binding_record["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(result["source_completeness"]["status"], "SOURCE_TRUNCATED")

    def test_f17_truncated_closure_candidates_return_source_truncated(self) -> None:
        documents = scenario()
        documents["identity"]["generation_closure_candidate_count"] = 2
        result = audit(documents)
        closure = record_for(result, "GENERATION_CLOSURE", RELEASE)
        self.assertEqual(closure["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(closure["proof_sufficiency_status"], "INSUFFICIENT")

    def test_f18_truncated_scoped_collection_attributes_nothing(self) -> None:
        documents = scenario()
        documents["lifecycle"]["generation_scoped_observation_count"] = 2
        documents["narrative"]["temporal_observations"][0][
            "generation_attribution_status"
        ] = NOT_ESTABLISHED
        result = audit(documents)
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "SOURCE_TRUNCATED")

    def test_f19_missing_source_count_is_metadata_invalid(self) -> None:
        documents = scenario()
        del documents["identity"]["release_session_binding_count"]
        result = audit(documents)
        entry = next(
            item
            for item in result["source_completeness"]["collections"]
            if item["collection"] == "release_session_bindings"
        )
        self.assertEqual(entry["status"], "SOURCE_METADATA_INVALID")
        self.assertEqual(entry["condition"], "COUNT_MISSING")

    def test_f20_invalid_source_count_is_metadata_invalid(self) -> None:
        documents = scenario()
        documents["lifecycle"]["lifecycle_subject_count"] = "one"
        result = audit(documents)
        entry = next(
            item
            for item in result["source_completeness"]["collections"]
            if item["collection"] == "lifecycle_subjects"
        )
        self.assertEqual(entry["status"], "SOURCE_METADATA_INVALID")
        self.assertEqual(entry["condition"], "COUNT_INVALID")


class EvidenceAuditGateTest(unittest.TestCase):
    def test_l21_underdeclared_count_is_metadata_invalid(self) -> None:
        documents = scenario()
        documents["identity"]["release_session_binding_count"] = 0
        result = audit(documents)
        entry = next(
            item
            for item in result["source_completeness"]["collections"]
            if item["collection"] == "release_session_bindings"
        )
        self.assertEqual(entry["status"], "SOURCE_METADATA_INVALID")
        self.assertEqual(entry["condition"], "COUNT_UNDERDECLARED")

    def test_l22_unresolved_claimant_competes_for_the_stream(self) -> None:
        documents = scenario()
        documents["lifecycle"]["generation_scoped_s1u_observations"].append(
            scoped(generation_reference="epc-bearer-generation-unpublished")
        )
        documents["lifecycle"]["generation_scoped_observation_count"] = 2
        result = audit(documents)
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "INCONSISTENT")
        self.assertIn("cannot be placed in exactly one capture", limitations(result))
        self.assertIn("no uniqueness is inferred", limitations(result))

    def test_l23_contradictory_scoped_direction_fails_closed(self) -> None:
        documents = scenario()
        documents["lifecycle"]["generation_scoped_s1u_observations"][0][
            "direction"
        ] = "UPLINK"
        result = audit(documents)
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "INCONSISTENT")
        self.assertEqual(
            check_result(attribution, "direction_role_mapping_agrees"), "FAIL"
        )

    def test_l24_two_scoped_records_claiming_one_stream_fail_closed(self) -> None:
        documents = scenario()
        documents["lifecycle"]["generation_scoped_s1u_observations"].append(scoped())
        documents["lifecycle"]["generation_scoped_observation_count"] = 2
        result = audit(documents)
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "INCONSISTENT")
        self.assertEqual(
            check_result(attribution, "reference_is_unique_in_its_namespace"), "FAIL"
        )

    def test_l25_correct_uplink_attribution_is_verified(self) -> None:
        result = audit(scenario(direction="UPLINK"))
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(
            check_result(attribution, "direction_role_mapping_agrees"), "PASS"
        )
        self.assertEqual(check_result(attribution, "direction_agrees_with_stream"), "PASS")
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)

    def test_l26_correct_downlink_attribution_is_verified(self) -> None:
        result = audit(scenario(direction="DOWNLINK"))
        attribution = record_for(result, "GENERATION_STREAM_ATTRIBUTION", TEMPORAL)
        self.assertEqual(attribution["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(attribution["proof_sufficiency_status"], "SUFFICIENT")

    def test_l27_duplicate_frame_ownership_is_never_resolved(self) -> None:
        documents = scenario()
        documents["narrative"]["temporal_observations"][0][
            "duplicate_frame_ownership"
        ] = True
        result = audit(documents)
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(temporal, "frame_ownership_exclusive"), "FAIL")
        self.assertIn("counted in no partition and no owner is selected", limitations(result))

    def test_l28_incomplete_partition_never_claims_complete_placement(self) -> None:
        documents = scenario()
        observation = documents["narrative"]["temporal_observations"][0]
        observation["partitions"]["pending_release"]["g_pdu_count"] = 0
        result = audit(documents)
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "INCONSISTENT")
        self.assertEqual(
            check_result(temporal, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_l29_complete_conserved_partition_is_verified(self) -> None:
        result = audit(scenario())
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(temporal["proof_sufficiency_status"], "SUFFICIENT")
        self.assertTrue(result["temporal_integrity_summary"]["frame_level_evidence_supplied"])

    def test_l30_aggregate_count_disagreement_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["temporal_observations"][0]["observed_g_pdu_count"] = 5
        result = audit(documents)
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "INCONSISTENT")

    def test_l31_payload_octet_disagreement_is_inconsistent(self) -> None:
        documents = scenario()
        documents["narrative"]["temporal_observations"][0]["partitions"][
            "after_confirmation"
        ]["payload_octets"] = 99
        result = audit(documents)
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "INCONSISTENT")

    def test_l32_missing_gtpu_events_stay_not_independently_verifiable(self) -> None:
        result = audit(scenario(with_gtpu=False))
        temporal = record_for(result, "TEMPORAL_FRAME_PARTITION", TEMPORAL)
        self.assertEqual(temporal["audit_status"], "NOT_INDEPENDENTLY_VERIFIABLE")
        self.assertEqual(check_result(temporal, "frame_present_in_supplied_events"), "NOT_EVALUATED")
        self.assertFalse(result["temporal_integrity_summary"]["frame_level_evidence_supplied"])

    def test_l33_missing_gtpv2_events_stay_not_independently_verifiable(self) -> None:
        result = audit(scenario(with_gtpv2=False))
        anchor = record_for(result, "TRANSACTION_ANCHOR", RELEASE)
        self.assertEqual(anchor["audit_status"], "NOT_INDEPENDENTLY_VERIFIABLE")
        self.assertEqual(check_result(anchor, "frame_present_in_supplied_events"), "NOT_EVALUATED")

    def test_l34_inconsistent_source_provenance_is_kept(self) -> None:
        documents = scenario()
        documents["narrative"]["release_narratives"][0]["provenance_status"] = "INCONSISTENT"
        result = audit(documents)
        anchor = record_for(result, "TRANSACTION_ANCHOR", RELEASE)
        self.assertEqual(anchor["audit_status"], "INCONSISTENT")
        self.assertIn("keeps that finding", limitations(result))

    def test_l35_multi_release_context_is_not_double_counted(self) -> None:
        documents = scenario()
        identity = documents["identity"]
        identity["release_session_bindings"].append(
            binding(transaction=TX_OTHER, frames=(300, 305))
        )
        identity["release_session_binding_count"] = 2
        documents["lifecycle"]["generation_boundary_evidence"].append(
            boundary(transaction=TX_OTHER)
        )
        documents["lifecycle"]["generation_boundary_count"] = 2
        narrative = documents["narrative"]
        narrative["release_narratives"].append(
            release(
                transaction=TX_OTHER,
                closure_status=NOT_ESTABLISHED,
                proved=[],
                temporal_references=[],
            )
        )
        narrative["release_narrative_count"] = 2
        result = audit(documents)
        self.assertEqual(
            len(records(result, "RELEASE_SESSION_BINDING")), 2
        )
        accounting = next(
            record
            for record in records(result, "ACCOUNTING_CONSERVATION")
            if record["source_analysis"] == "epc-release-narrative"
        )
        self.assertEqual(accounting["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(
            result["temporal_integrity_summary"]["established_placement_count"], 1
        )
        self.assertEqual(
            result["accounting_integrity_summary"]["producer_temporal"][
                "assigned_to_release_window_count"
            ],
            4,
        )

    def test_l36_cross_interface_groups_preserve_hop_local_subjects(self) -> None:
        documents = scenario()
        identity = documents["identity"]
        identity["hop_local_contexts"].append(context(CONTEXT_B, interface_class="S5/S8"))
        identity["hop_local_context_count"] = 2
        identity["session_identity_links"] = [
            {
                "reference": IDENTITY_LINK,
                "relationship_type": "CROSS_INTERFACE_SESSION_IDENTITY",
                "capture_file": CAPTURE_A,
                "source_subject_reference": CONTEXT,
                "target_subject_reference": CONTEXT_B,
                "association_status": ESTABLISHED,
                "association_basis": "relayed_pgw_control_plane_fteid_equal_and_unique",
                "source_frames": [103],
                "competing_candidates": [],
                "limitations": [],
            }
        ]
        identity["session_identity_count"] = 1
        narrative = documents["narrative"]
        second = narrative_subject(
            reference="epc-release-subject-9999999999",
            context_reference=CONTEXT_B,
            group_reference=GROUP,
            group_basis="proved_cross_interface_session_identity",
            members=[CONTEXT, CONTEXT_B],
            bridge_references=[IDENTITY_LINK],
        )
        second["release_narrative_references"] = []
        narrative["narrative_subjects"][0]["narrative_group_basis"] = (
            "proved_cross_interface_session_identity"
        )
        narrative["narrative_subjects"][0]["narrative_group_members"] = [
            CONTEXT,
            CONTEXT_B,
        ]
        narrative["narrative_subjects"][0]["narrative_group_bridge_references"] = [
            IDENTITY_LINK
        ]
        narrative["narrative_subjects"].append(second)
        narrative["narrative_subject_count"] = 2
        result = audit(documents)
        for subject in (SUBJECT, "epc-release-subject-9999999999"):
            bridge = record_for(result, "CROSS_INTERFACE_BRIDGE", subject)
            self.assertEqual(bridge["audit_status"], "VERIFIED_CONSISTENT")
            self.assertEqual(
                check_result(bridge, "group_preserves_hop_local_subjects"), "PASS"
            )
        contexts = {
            subject["session_context_reference"]
            for subject in narrative["narrative_subjects"]
        }
        self.assertEqual(contexts, {CONTEXT, CONTEXT_B})


class EvidenceAuditOutputTest(unittest.TestCase):
    def test_m40_repeated_audit_is_byte_identical(self) -> None:
        documents = scenario()
        first = audit(copy.deepcopy(documents))
        second = audit(copy.deepcopy(documents))
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, indent=2, sort_keys=True),
            json.dumps(second, indent=2, sort_keys=True),
        )
        from epc_evidence_audit_report import render_report

        self.assertEqual(render_report(first), render_report(second))

    def test_m41_privacy_and_producer_counts_are_preserved(self) -> None:
        documents = scenario()
        before = copy.deepcopy(documents)
        result = audit(documents)
        self.assertEqual(documents, before)
        self.assertTrue(
            result["accounting_integrity_summary"]["audit_derived"][
                "source_counts_unchanged"
            ]
        )
        self.assertEqual(
            result["accounting_integrity_summary"]["producer_lifecycle"],
            documents["lifecycle"]["accounting"],
        )
        serialized = json.dumps(result)
        for forbidden in (
            '"imsi"',
            '"msisdn"',
            '"imei"',
            '"apn"',
            '"assigned_pdn_address"',
            '"inner_ue_address"',
            '"payload_text"',
        ):
            self.assertNotIn(forbidden, serialized)
        import re

        self.assertIsNone(re.search(r"\d{14,}", serialized))

    def test_m42_standalone_cli_is_safe_and_deterministic(self) -> None:
        documents = scenario()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {}
            for name in ("identity", "lifecycle", "narrative", "s1u"):
                path = root / f"{name}.json"
                path.write_text(json.dumps(documents[name]), encoding="utf-8")
                paths[name] = path
            gtpv2_path = root / "gtpv2.jsonl"
            gtpv2_path.write_text(
                "\n".join(json.dumps(event) for event in documents["gtpv2"]) + "\n",
                encoding="utf-8",
            )
            gtpu_path = root / "gtpu.jsonl"
            gtpu_path.write_text(
                "\n".join(json.dumps(event) for event in documents["gtpu"]) + "\n",
                encoding="utf-8",
            )
            output = root / "audit.json"
            report = root / "audit.txt"
            before = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in list(paths.values()) + [gtpv2_path, gtpu_path]
            }
            command = [
                sys.executable,
                str(CLI),
                "--session-identity",
                str(paths["identity"]),
                "--lifecycle",
                str(paths["lifecycle"]),
                "--release-narrative",
                str(paths["narrative"]),
                "--s1u",
                str(paths["s1u"]),
                "--gtpv2",
                str(gtpv2_path),
                "--gtpu",
                str(gtpu_path),
                "--output",
                str(output),
                "--report",
                str(report),
            ]
            completed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue(output.is_file())
            self.assertTrue(report.is_file())
            parsed = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed["audit_summary"]["overall_status"], "AUDIT_CONSISTENT")
            self.assertEqual(parsed["source_artifact_count"], 6)
            self.assertIn("Evidence Chain Audit Ledger", report.read_text(encoding="utf-8"))
            after = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in list(paths.values()) + [gtpv2_path, gtpu_path]
            }
            self.assertEqual(before, after)
            # A second run without --force refuses the overwrite.
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(second.returncode, 7)
            # An output path aliasing an input artifact is refused.
            alias = list(command)
            alias[alias.index("--output") + 1] = str(paths["narrative"])
            aliased = subprocess.run(alias, capture_output=True, text=True)
            self.assertEqual(aliased.returncode, 7)
            self.assertIn("must not replace an input artifact", aliased.stderr)

    def test_m43_unified_domain_projection_preserves_boundary(self) -> None:
        import importlib.util

        module_path = Path(__file__).resolve().parents[4] / "scripts" / "corenet-analyze.py"
        spec = importlib.util.spec_from_file_location("corenet_analyze_audit", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        documents = scenario()
        analysis = audit(documents)
        payload = {
            "analysis": {
                "procedure_instances": [],
                "limitations": [],
                "additional_evidence_needed": [],
            },
            "session_analysis": {"control_plane_subjects": []},
            "default_bearer_analysis": {"default_bearer_instances": []},
            "s1u_analysis": {"stream_observations": []},
            "lifecycle_analysis": documents["lifecycle"],
            "lifecycle_error": None,
            "identity_analysis": documents["identity"],
            "identity_error": None,
            "release_narrative_analysis": documents["narrative"],
            "release_narrative_error": None,
            "evidence_audit_analysis": analysis,
            "evidence_audit_error": None,
            "boundary_analysis": None,
            "boundary_error": None,
        }
        result = module.execute_epc_domain(
            Path("capture.pcap"), Path("."), "case", {}, lambda *_: payload
        )
        block = result["evidence_audit"]
        self.assertIsNotNone(block)
        self.assertEqual(block["overall_status"], "AUDIT_CONSISTENT")
        self.assertTrue(block["accounting_integrity"]["producer_counts_unchanged"])
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "NOT_EVALUATED")
        summaries = {
            item["procedure"]: item for item in result["procedure_summaries"]
        }
        self.assertEqual(summaries["epc-evidence-audit"]["execution_status"], "EXECUTED")
        self.assertEqual(
            summaries["epc-evidence-audit"]["overall_audit_status"], "AUDIT_CONSISTENT"
        )
        # An audit failure degrades without discarding producer evidence.
        failed_payload = dict(payload)
        failed_payload["evidence_audit_analysis"] = None
        failed_payload["evidence_audit_error"] = {
            "code": "EVIDENCE_AUDIT_FAILED",
            "message": "audit input error",
        }
        failed = module.execute_epc_domain(
            Path("capture.pcap"), Path("."), "case", {}, lambda *_: failed_payload
        )
        self.assertIsNone(failed["evidence_audit"])
        self.assertIsNotNone(failed["release_narrative"])
        self.assertEqual(failed["failure_code"], "EVIDENCE_AUDIT_FAILED")
        self.assertTrue(
            any("not a network failure" in item for item in failed["degradation"])
        )
        self.assertTrue(
            any("no EPC protocol failure is asserted" in item for item in failed["degradation"])
        )


class EvidenceAuditMultiGenerationClosureTest(unittest.TestCase):
    def closure(self, result: dict, reference: str) -> dict:
        return record_for(result, "GENERATION_CLOSURE", reference)

    def test_n01_single_proved_generation_is_verified(self) -> None:
        result = audit(
            closure_documents([{"generation_reference": GENERATION}])
        )
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(closure["proof_sufficiency_status"], "SUFFICIENT")
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)

    def test_n02_one_release_closes_two_distinct_generations(self) -> None:
        result = audit(
            closure_documents(
                [
                    {"generation_reference": GENERATION},
                    {
                        "direction": "UPLINK",
                        "generation_reference": UP_GENERATION,
                        "candidate_reference": UP_CANDIDATE,
                    },
                ]
            )
        )
        closures = records(result, "GENERATION_CLOSURE")
        self.assertEqual(len(closures), 2)
        for reference in (GENERATION, UP_GENERATION):
            closure = self.closure(result, reference)
            self.assertEqual(closure["audit_status"], "VERIFIED_CONSISTENT")
            self.assertEqual(closure["proof_sufficiency_status"], "SUFFICIENT")
            self.assertEqual(
                check_result(closure, "unique_candidate_established"), "PASS"
            )
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)

    def test_n03_one_release_closes_three_distinct_generations(self) -> None:
        result = audit(
            closure_documents(
                [
                    {"generation_reference": GENERATION},
                    {
                        "direction": "UPLINK",
                        "generation_reference": UP_GENERATION,
                        "candidate_reference": UP_CANDIDATE,
                    },
                    {
                        "endpoint": THIRD_ENDPOINT,
                        "generation_reference": THIRD_GENERATION,
                        "candidate_reference": THIRD_CANDIDATE,
                    },
                ]
            )
        )
        closures = records(result, "GENERATION_CLOSURE")
        self.assertEqual(len(closures), 3)
        self.assertTrue(
            all(item["audit_status"] == "VERIFIED_CONSISTENT" for item in closures)
        )
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)

    def test_n04_two_competing_candidates_for_one_generation_stay_ambiguous(self) -> None:
        documents = closure_documents(
            [
                {"generation_reference": GENERATION},
                {
                    "direction": "UPLINK",
                    "generation_reference": UP_GENERATION,
                    "candidate_reference": UP_CANDIDATE,
                },
            ]
        )
        documents["identity"]["generation_closure_candidates"].append(
            closure_candidate(reference="epc-generation-closure-6666666666")
        )
        documents["identity"]["generation_closure_candidate_count"] = 3
        result = audit(documents)
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "AMBIGUOUS")
        self.assertEqual(
            check_result(closure, "unique_candidate_established"), "NOT_EVALUATED"
        )
        self.assertEqual(closure["proof_sufficiency_status"], "INSUFFICIENT")
        other = self.closure(result, UP_GENERATION)
        self.assertEqual(other["audit_status"], "VERIFIED_CONSISTENT")

    def test_n05_candidates_for_different_generations_are_both_verified(self) -> None:
        documents = closure_documents(
            [
                {"generation_reference": GENERATION},
                {
                    "direction": "UPLINK",
                    "generation_reference": UP_GENERATION,
                    "candidate_reference": UP_CANDIDATE,
                },
            ]
        )
        result = audit(documents)
        self.assertEqual(
            len(records(result, "SESSION_GENERATION_LINK")), 4
        )
        self.assertEqual(
            {
                record["target_subject_reference"]
                for record in records(result, "GENERATION_CLOSURE")
            },
            {GENERATION, UP_GENERATION},
        )

    def test_n06_candidate_for_another_release_never_closes_this_one(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidates"][0][
            "release_transaction_reference"
        ] = TX_OTHER
        result = audit(documents)
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(closure, "release_transaction_agrees"), "FAIL")
        self.assertIn("another release transaction", limitations(result))

    def test_n07_candidate_in_another_capture_never_closes_this_one(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidates"][0][
            "capture_file"
        ] = CAPTURE_B
        result = audit(documents)
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(closure, "unique_candidate_established"), "FAIL")

    def test_n08_missing_generation_link_is_inconsistent(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"] = []
        documents["identity"]["session_to_generation_count"] = 0
        result = audit(documents)
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(closure, "unique_candidate_established"), "FAIL")
        generation_link = next(
            record
            for record in records(result, "SESSION_GENERATION_LINK")
            if record["source_analysis"] == "epc-release-narrative"
        )
        self.assertEqual(generation_link["audit_status"], "INCONSISTENT")
        self.assertEqual(generation_link["proof_sufficiency_status"], "INSUFFICIENT")

    def test_n09_unestablished_generation_link_is_inconsistent(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": NOT_ESTABLISHED}]
            )
        )
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "INCONSISTENT")
        for record in records(result, "SESSION_GENERATION_LINK"):
            self.assertEqual(record["audit_status"], "INCONSISTENT")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertIn("record existence alone never proves the link", limitations(result))

    def test_n10_truncated_candidate_collection_is_source_truncated(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidate_count"] = 2
        result = audit(documents)
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(closure["proof_sufficiency_status"], "INSUFFICIENT")

    def test_n11_accepted_release_without_closure_stays_separate(self) -> None:
        result = audit(
            closure_documents([{"generation_reference": GENERATION}], claim=NOT_ESTABLISHED)
        )
        closure = self.closure(result, GENERATION)
        self.assertEqual(closure["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(closure["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertIn("audited separately", limitations(result))

    def test_n12_reordering_candidates_and_generations_changes_nothing(self) -> None:
        forward = [
            {"generation_reference": GENERATION},
            {
                "direction": "UPLINK",
                "generation_reference": UP_GENERATION,
                "candidate_reference": UP_CANDIDATE,
            },
        ]
        first = audit(closure_documents(forward))
        second = audit(closure_documents(list(reversed(forward))))
        first_map = {
            record["target_subject_reference"]: record["audit_status"]
            for record in records(first, "GENERATION_CLOSURE")
        }
        second_map = {
            record["target_subject_reference"]: record["audit_status"]
            for record in records(second, "GENERATION_CLOSURE")
        }
        self.assertEqual(first_map, second_map)


class EvidenceAuditObservedSubsetTest(unittest.TestCase):
    def temporal(self, result: dict) -> dict:
        temporal_records = records(result, "TEMPORAL_FRAME_PARTITION")
        self.assertEqual(len(temporal_records), 1)
        return temporal_records[0]

    def test_n19_producer_generated_subset_matches_published_accounting(self) -> None:
        documents = observed_subset_documents()
        observation = documents["narrative"]["temporal_observations"][0]
        accounting = documents["narrative"]["temporal_accounting"]
        release = copy.deepcopy(documents["narrative"]["release_narratives"][0])
        release["temporal_observation_references"] = []
        expected_observations, expected_accounting, _limitations, _unbound = (
            narrative_model.build_temporal_observations(
                [release],
                documents["s1u"],
                documents["gtpu"],
                documents["lifecycle"],
                (True, None),
            )
        )
        self.assertEqual(observation, expected_observations[0])
        self.assertEqual(accounting, expected_accounting)
        self.assertEqual(observation["partition_basis"], "FRAME_LEVEL_EVENTS_INCOMPLETE")
        self.assertEqual(observation["partition_scope"], "OBSERVED_SUBSET")
        self.assertEqual(
            observation["temporal_placement_status"],
            "TEMPORAL_PLACEMENT_NOT_ESTABLISHED",
        )
        self.assertFalse(observation["partition_conserved"])
        self.assertEqual(accounting["observed_g_pdu_event_count"], 3)
        self.assertEqual(accounting["assigned_to_release_window_count"], 0)
        self.assertEqual(accounting["unassigned_g_pdu_event_count"], 3)
        self.assertTrue(accounting["conserved"])

    def test_n20_valid_observed_subset_is_not_an_inconsistency(self) -> None:
        result = audit(observed_subset_documents())
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "PASS"
        )
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)
        self.assertIn("complete stream placement is not established", limitations(result))
        self.assertEqual(
            result["temporal_integrity_summary"]["incomplete_partition_count"], 1
        )

    def test_n21_missing_detailed_evidence_preserves_observed_subset(self) -> None:
        documents = observed_subset_documents()
        documents["gtpu"] = None
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "NOT_INDEPENDENTLY_VERIFIABLE")
        self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)
        self.assertIn(
            "no detailed GTP-U events were supplied", " ".join(record["limitations"])
        )
        self.assertIsNotNone(
            documents["narrative"]["temporal_observations"][0]["partitions"]
        )

    def test_n22_aggregate_only_placement_keeps_proof_not_applicable(self) -> None:
        documents = scenario()
        observation = documents["narrative"]["temporal_observations"][0]
        observation.update(
            {
                "temporal_placement_status": "TEMPORAL_PLACEMENT_NOT_ESTABLISHED",
                "partition_basis": "AGGREGATE_STREAM_ONLY",
                "partition_conserved": None,
                "partition_scope": None,
                "partitions": None,
            }
        )
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(record["proof_sufficiency_status"], "NOT_APPLICABLE")

    def test_n23_incorrect_complete_scope_claim_is_rejected(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0][
            "partition_scope"
        ] = "COMPLETE_STREAM"
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "INCONSISTENT")
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n24_incorrect_established_claim_is_rejected(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0].update(
            {
                "temporal_placement_status": "ESTABLISHED",
                "partition_scope": "COMPLETE_STREAM",
            }
        )
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "INCONSISTENT")

    def test_n25_duplicate_frame_ownership_is_never_resolved(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0][
            "duplicate_frame_ownership"
        ] = True
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(record, "frame_ownership_exclusive"), "FAIL")

    def test_n26_subset_counts_above_the_aggregate_are_rejected(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0]["observed_g_pdu_count"] = 1
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "INCONSISTENT")
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n27_cross_capture_frame_numbers_never_collide(self) -> None:
        result = audit(two_capture_documents())
        temporal_records = records(result, "TEMPORAL_FRAME_PARTITION")
        self.assertEqual(len(temporal_records), 2)
        self.assertTrue(
            all(record["audit_status"] == "VERIFIED_CONSISTENT" for record in temporal_records)
        )
        self.assertFalse(
            any(
                check_result(record, "frame_ownership_exclusive") == "FAIL"
                for record in temporal_records
            )
        )

    def test_n28_repeated_subset_audit_is_byte_identical(self) -> None:
        documents = observed_subset_documents()
        first = json.dumps(audit(documents), sort_keys=True)
        second = json.dumps(audit(documents), sort_keys=True)
        self.assertEqual(first, second)

    def assert_subset_inconsistent(self, documents: dict) -> dict:
        result = audit(documents)
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "INCONSISTENT")
        self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        return record

    def test_n50_invented_subset_packet_is_reconciled_against_events(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0]["partitions"][
            "before_release"
        ]["g_pdu_count"] += 1
        record = self.assert_subset_inconsistent(documents)
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n51_invented_subset_payload_octets_are_reconciled(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0]["partitions"][
            "pending_release"
        ]["payload_octets"] += 50
        record = self.assert_subset_inconsistent(documents)
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n52_moved_subset_packet_count_breaks_window_agreement(self) -> None:
        documents = observed_subset_documents()
        partitions = documents["narrative"]["temporal_observations"][0]["partitions"]
        partitions["before_release"]["g_pdu_count"] -= 1
        partitions["pending_release"]["g_pdu_count"] += 1
        record = self.assert_subset_inconsistent(documents)
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n53_unsupported_subset_basis_is_rejected(self) -> None:
        documents = observed_subset_documents()
        documents["narrative"]["temporal_observations"][0][
            "partition_basis"
        ] = "AGGREGATE_STREAM_ONLY"
        self.assert_subset_inconsistent(documents)

    def test_n54_removed_detailed_event_breaks_subset_reconciliation(self) -> None:
        documents = observed_subset_documents()
        documents["gtpu"] = [
            event
            for event in documents["gtpu"]
            if event["frame_number"] != 202
        ]
        record = self.assert_subset_inconsistent(documents)
        self.assertEqual(
            check_result(record, "partition_counts_conserve_aggregate"), "FAIL"
        )

    def test_n55_cross_capture_frame_number_never_satisfies_a_subset(self) -> None:
        documents = observed_subset_documents()
        documents["gtpu"][1] = dict(
            copy.deepcopy(documents["gtpu"][1]), capture_file=CAPTURE_B
        )
        self.assert_subset_inconsistent(documents)

    def test_n56_equal_teid_on_another_stream_never_satisfies_a_subset(self) -> None:
        documents = observed_subset_documents()
        event = copy.deepcopy(documents["gtpu"][1])
        event["outer"] = dict(event["outer"], source_address="10.0.0.30")
        documents["gtpu"][1] = event
        self.assert_subset_inconsistent(documents)

    def test_n57_valid_complete_placement_stays_sufficient(self) -> None:
        result = audit(scenario())
        record = self.temporal(result)
        self.assertEqual(record["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(record["proof_sufficiency_status"], "SUFFICIENT")
        self.assertEqual(result["audit_summary"]["inconsistent_count"], 0)


class EvidenceAuditProofSufficiencyTest(unittest.TestCase):
    def candidate_link(self, result: dict) -> dict:
        return next(
            record
            for record in records(result, "SESSION_GENERATION_LINK")
            if record["source_analysis"] == "epc-session-identity"
        )

    def narrative_link(self, result: dict) -> dict:
        return next(
            record
            for record in records(result, "SESSION_GENERATION_LINK")
            if record["source_analysis"] == "epc-release-narrative"
        )

    def reference_generation(self, result: dict) -> list[dict]:
        return [
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if record["relationship_type"] == "SESSION_CONTEXT_TO_BEARER_GENERATION"
        ]

    def reference_identity(self, result: dict) -> list[dict]:
        return [
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if record["relationship_type"] == "CROSS_INTERFACE_SESSION_IDENTITY"
        ]

    def test_c01_complete_candidate_and_link_collections_are_sufficient(self) -> None:
        result = audit(closure_documents([{"generation_reference": GENERATION}]))
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "VERIFIED_CONSISTENT")
            self.assertEqual(record["candidate_completeness_status"], "COMPLETE")
            self.assertEqual(record["proof_sufficiency_status"], "SUFFICIENT")
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(reference["candidate_completeness_status"], "COMPLETE")
        self.assertEqual(reference["proof_sufficiency_status"], "SUFFICIENT")
        closure = record_for(result, "GENERATION_CLOSURE", GENERATION)
        self.assertEqual(closure["proof_sufficiency_status"], "SUFFICIENT")

    def test_c02_truncated_candidates_cannot_support_candidate_to_link_proof(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidate_count"] = 2
        result = audit(documents)
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "SOURCE_TRUNCATED")
            self.assertEqual(record["candidate_completeness_status"], "SOURCE_TRUNCATED")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            record_for(result, "GENERATION_CLOSURE", GENERATION)["audit_status"],
            "SOURCE_TRUNCATED",
        )
        reference = self.reference_generation(result)
        self.assertEqual(reference[0]["candidate_completeness_status"], "COMPLETE")
        self.assertEqual(reference[0]["proof_sufficiency_status"], "SUFFICIENT")

    def test_c03_truncated_links_cannot_support_link_proof(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_count"] = 2
        result = audit(documents)
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "SOURCE_TRUNCATED")
            self.assertEqual(record["candidate_completeness_status"], "SOURCE_TRUNCATED")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            record_for(result, "GENERATION_CLOSURE", GENERATION)["audit_status"],
            "SOURCE_TRUNCATED",
        )

    def test_c04_both_collections_truncated_stay_insufficient(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidate_count"] = 2
        documents["identity"]["session_to_generation_count"] = 2
        result = audit(documents)
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "SOURCE_TRUNCATED")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")

    def test_c05_invalid_candidate_count_metadata_stays_insufficient(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["generation_closure_candidate_count"] = None
        result = audit(documents)
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "SOURCE_METADATA_INVALID")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")

    def test_c06_invalid_link_count_metadata_stays_insufficient(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_count"] = None
        result = audit(documents)
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "SOURCE_METADATA_INVALID")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")

    def test_c07_not_established_link_keeps_reference_consistency_but_not_proof(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": NOT_ESTABLISHED}]
            )
        )
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertIn("association_status=NOT_ESTABLISHED", limitations(result))
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "INCONSISTENT")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            record_for(result, "GENERATION_CLOSURE", GENERATION)["audit_status"],
            "INCONSISTENT",
        )

    def test_c08_ambiguous_link_status_keeps_reference_consistency_but_not_proof(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": "AMBIGUOUS"}]
            )
        )
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            self.candidate_link(result)["audit_status"], "INCONSISTENT"
        )
        self.assertEqual(
            self.narrative_link(result)["audit_status"], "INCONSISTENT"
        )

    def test_c09_missing_link_status_is_never_sufficient(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        del documents["identity"]["session_to_generation_links"][0]["association_status"]
        result = audit(documents)
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "INCONSISTENT")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")

    def test_c10_duplicate_links_remain_ambiguous(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"].append(generation_link())
        documents["identity"]["session_to_generation_count"] = 2
        result = audit(documents)
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "AMBIGUOUS")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        for record in (self.candidate_link(result), self.narrative_link(result)):
            self.assertEqual(record["audit_status"], "AMBIGUOUS")
            self.assertEqual(record["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            record_for(result, "GENERATION_CLOSURE", GENERATION)["audit_status"],
            "AMBIGUOUS",
        )

    def test_c11_reference_integrity_is_not_relationship_proof(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": NOT_ESTABLISHED}]
            )
        )
        reference = self.reference_generation(result)[0]
        self.assertEqual(reference["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(reference["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            reference["source_artifact_reference"],
            "epc-session-identity:session_to_generation_links",
        )

    def test_c12_identity_and_generation_namespaces_stay_separate(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2
        documents["identity"]["session_identity_links"] = [identity_link()]
        documents["identity"]["session_identity_count"] = 1
        result = audit(documents)
        identity = self.reference_identity(result)[0]
        self.assertEqual(
            identity["source_artifact_reference"],
            "epc-session-identity:session_identity_links",
        )
        self.assertEqual(identity["proof_sufficiency_status"], "SUFFICIENT")
        generation = self.reference_generation(result)[0]
        self.assertEqual(
            generation["source_artifact_reference"],
            "epc-session-identity:session_to_generation_links",
        )
        self.assertEqual(generation["proof_sufficiency_status"], "SUFFICIENT")

    def test_c13_two_generations_remain_sufficient_per_endpoint(self) -> None:
        result = audit(
            closure_documents(
                [
                    {"generation_reference": GENERATION},
                    {
                        "direction": "UPLINK",
                        "generation_reference": UP_GENERATION,
                        "candidate_reference": UP_CANDIDATE,
                    },
                ]
            )
        )
        for reference in (GENERATION, UP_GENERATION):
            closure = record_for(result, "GENERATION_CLOSURE", reference)
            self.assertEqual(closure["audit_status"], "VERIFIED_CONSISTENT")
            self.assertEqual(closure["candidate_completeness_status"], "COMPLETE")
            self.assertEqual(closure["proof_sufficiency_status"], "SUFFICIENT")

    def test_c14_status_vocabulary_and_order_are_deterministic(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        first = json.dumps(audit(documents), sort_keys=True)
        second = json.dumps(audit(documents), sort_keys=True)
        self.assertEqual(first, second)
        result = json.loads(first)
        allowed_status = {
            "VERIFIED_CONSISTENT",
            "INCONSISTENT",
            "AMBIGUOUS",
            "SOURCE_TRUNCATED",
            "SOURCE_METADATA_INVALID",
            "NOT_INDEPENDENTLY_VERIFIABLE",
            "NOT_APPLICABLE",
        }
        allowed_proof = {"SUFFICIENT", "INSUFFICIENT", "NOT_APPLICABLE"}
        for record in result["audit_records"]:
            self.assertIn(record["audit_status"], allowed_status)
            self.assertIn(record["proof_sufficiency_status"], allowed_proof)


class EvidenceAuditGenerationLinkProofTest(unittest.TestCase):
    def closure(self, result: dict) -> dict:
        return record_for(result, "GENERATION_CLOSURE", GENERATION)

    def generation_link_records(self, result: dict) -> list[dict]:
        return [
            record
            for record in records(result, "SESSION_GENERATION_LINK")
            if record["source_analysis"] == "epc-release-narrative"
        ]

    def reference_records(self, result: dict, relationship: str) -> list[dict]:
        return [
            record
            for record in records(result, "REFERENCE_INTEGRITY")
            if record["relationship_type"] == relationship
        ]

    def test_n30_established_generation_link_is_verified(self) -> None:
        result = audit(closure_documents([{"generation_reference": GENERATION}]))
        links = self.generation_link_records(result)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(links[0]["proof_sufficiency_status"], "SUFFICIENT")
        self.assertEqual(links[0]["candidate_completeness_status"], "COMPLETE")
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(len(reference), 1)
        self.assertEqual(reference[0]["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(
            reference[0]["source_artifact_reference"],
            "epc-session-identity:session_to_generation_links",
        )
        self.assertEqual(reference[0]["candidate_completeness_status"], "COMPLETE")

    def test_n31_missing_generation_link_fails_closed(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"] = []
        documents["identity"]["session_to_generation_count"] = 0
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        links = self.generation_link_records(result)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["audit_status"], "INCONSISTENT")
        self.assertEqual(links[0]["proof_sufficiency_status"], "INSUFFICIENT")
        self.assertEqual(
            self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION"), []
        )

    def test_n32_not_established_link_is_never_promoted(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": NOT_ESTABLISHED}]
            )
        )
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        for record in records(result, "SESSION_GENERATION_LINK"):
            self.assertEqual(record["audit_status"], "INCONSISTENT")
        self.assertIn("explicitly established", limitations(result))

    def test_n33_ambiguous_link_status_is_a_contradiction(self) -> None:
        result = audit(
            closure_documents(
                [{"generation_reference": GENERATION, "link_status": "AMBIGUOUS"}]
            )
        )
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "INCONSISTENT"
        )

    def test_n34_competing_links_stay_ambiguous(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"].append(generation_link())
        documents["identity"]["session_to_generation_count"] = 2
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "AMBIGUOUS")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "AMBIGUOUS"
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(reference[0]["audit_status"], "AMBIGUOUS")

    def test_n35_wrong_relationship_type_is_rejected(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"][0][
            "relationship_type"
        ] = "CROSS_INTERFACE_SESSION_IDENTITY"
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "INCONSISTENT"
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(reference[0]["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(reference[0], "relationship_type_agrees"), "FAIL")

    def test_n36_wrong_source_context_is_rejected(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"][0][
            "source_subject_reference"
        ] = CONTEXT_B
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "INCONSISTENT"
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(reference[0]["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(reference[0], "session_context_present"), "FAIL")

    def test_n37_wrong_target_endpoint_is_rejected(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"][0][
            "target_subject_reference"
        ] = endpoint_reference(CAPTURE_A, "UPLINK")
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "INCONSISTENT"
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(reference[0]["audit_status"], "INCONSISTENT")
        self.assertEqual(check_result(reference[0], "bearer_endpoint_present"), "FAIL")

    def test_n38_wrong_capture_is_rejected(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_links"][0]["capture_file"] = CAPTURE_B
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "INCONSISTENT")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"], "INCONSISTENT"
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(len(reference), 1)
        self.assertEqual(reference[0]["audit_status"], "INCONSISTENT")
        self.assertEqual(reference[0]["capture_file"], CAPTURE_B)

    def test_n39_truncated_generation_collection_follows_its_own_status(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["session_to_generation_count"] = 2
        result = audit(documents)
        self.assertEqual(self.closure(result)["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"],
            "SOURCE_TRUNCATED",
        )
        reference = self.reference_records(result, "SESSION_CONTEXT_TO_BEARER_GENERATION")
        self.assertEqual(reference[0]["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(reference[0]["proof_sufficiency_status"], "INSUFFICIENT")

    def test_n40_truncated_identity_collection_does_not_leak(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2
        documents["identity"]["session_identity_links"] = [identity_link()]
        documents["identity"]["session_identity_count"] = 2
        result = audit(documents)
        identity_records = self.reference_records(result, "CROSS_INTERFACE_SESSION_IDENTITY")
        self.assertEqual(len(identity_records), 1)
        self.assertEqual(identity_records[0]["audit_status"], "SOURCE_TRUNCATED")
        self.assertEqual(
            identity_records[0]["source_artifact_reference"],
            "epc-session-identity:session_identity_links",
        )
        generation_records = self.reference_records(
            result, "SESSION_CONTEXT_TO_BEARER_GENERATION"
        )
        self.assertEqual(generation_records[0]["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(
            generation_records[0]["candidate_completeness_status"], "COMPLETE"
        )
        self.assertEqual(
            self.generation_link_records(result)[0]["audit_status"],
            "VERIFIED_CONSISTENT",
        )

    def test_n41_positive_identity_link_keeps_its_namespace(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2
        documents["identity"]["session_identity_links"] = [identity_link()]
        documents["identity"]["session_identity_count"] = 1
        result = audit(documents)
        identity_records = self.reference_records(result, "CROSS_INTERFACE_SESSION_IDENTITY")
        self.assertEqual(len(identity_records), 1)
        self.assertEqual(identity_records[0]["audit_status"], "VERIFIED_CONSISTENT")
        self.assertEqual(identity_records[0]["proof_sufficiency_status"], "SUFFICIENT")
        self.assertEqual(
            identity_records[0]["source_artifact_reference"],
            "epc-session-identity:session_identity_links",
        )
        self.assertEqual(
            identity_records[0]["candidate_completeness_status"], "COMPLETE"
        )

    def test_n42_endpoint_correspondence_is_not_promoted_into_identity(self) -> None:
        documents = closure_documents([{"generation_reference": GENERATION}])
        documents["identity"]["hop_local_contexts"].append(
            context(CONTEXT_B, interface_class="S5/S8")
        )
        documents["identity"]["hop_local_context_count"] = 2
        documents["identity"]["endpoint_correspondence_links"] = [
            endpoint_correspondence()
        ]
        documents["identity"]["endpoint_correspondence_count"] = 1
        result = audit(documents)
        self.assertEqual(
            self.reference_records(result, "CROSS_INTERFACE_SESSION_IDENTITY"), []
        )
        self.assertFalse(
            any(
                record["source_artifact_reference"]
                == "epc-session-identity:session_identity_links"
                for record in records(result, "REFERENCE_INTEGRITY")
            )
        )
        self.assertEqual(self.closure(result)["audit_status"], "VERIFIED_CONSISTENT")


if __name__ == "__main__":
    unittest.main()