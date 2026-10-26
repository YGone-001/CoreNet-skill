#!/usr/bin/env python3
"""Standalone tests for the bounded EPC release narrative capability.

The fixtures are faithful, minimal instances of the accepted producer documents:
they carry exactly the published fields the narrative consumes, so a change to a
producer contract that this capability depends on fails here rather than silently
producing a thinner narrative.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_release_narrative.py"

sys.path.insert(0, str(SCRIPTS))
import epc_release_narrative_model as model  # noqa: E402

CAPTURE_A = "capture-a.pcap"
CAPTURE_B = "capture-b.pcap"

ESTABLISHED = "ESTABLISHED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
AMBIGUOUS = "AMBIGUOUS"
ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED_OBSERVED"
UNRESOLVED = "UNRESOLVED"

SGW = "10.0.0.20"
ENB = "10.0.0.40"
PGW = "10.0.0.30"


def evidence(frame, message, protocol="GTPv2-C"):
    return {
        "protocol": protocol,
        "frame_number": frame,
        "message_type": message,
        "evidence_level": "OBSERVED",
    }


def context(
    reference,
    *,
    capture=CAPTURE_A,
    interface_class="S11",
    status=ESTABLISHED,
    basis="proved_allocation_transaction_with_unique_hop_local_control_plane_fteids",
    allocation="tx-create-1",
    allocation_status=ACCEPTED,
    members=None,
    frames=(100, 103),
    evidence_refs=None,
):
    return {
        "relationship_type": "HOP_LOCAL_SESSION_CONTEXT",
        "session_context_reference": reference,
        "capture_file": capture,
        "interface_class": interface_class,
        "association_status": status,
        "association_basis": basis,
        "allocation_transaction_reference": allocation,
        "allocation_outcome_status": allocation_status,
        "member_transaction_references": members or [allocation],
        "member_transactions": [],
        "control_plane_fteids": [],
        "bearer_user_plane_fteids": [],
        "transaction_correlation_proved": True,
        "observation_window": {"start_frame": frames[0], "end_frame": frames[1]},
        "evidence_refs": evidence_refs
        or [
            evidence(frames[0], "Create Session Request"),
            evidence(frames[1], "Create Session Response"),
        ],
        "limitations": [],
    }


def identity_link(
    reference,
    source,
    target,
    *,
    capture=CAPTURE_A,
    status=ESTABLISHED,
    relationship_type="CROSS_INTERFACE_SESSION_IDENTITY",
    frames=(103, 102),
):
    return {
        "reference": reference,
        "relationship_type": relationship_type,
        "capture_file": capture,
        "source_subject_reference": source,
        "target_subject_reference": target,
        "association_status": status,
        "association_basis": "relayed_pgw_s5s8_control_plane_fteid_equal_and_unique_on_both_hops",
        "reviewed_identifiers": [],
        "source_transaction_references": [],
        "source_frames": list(frames),
        "evidence_refs": [evidence(frame, "Create Session Response") for frame in frames],
        "observation_window": {"start_frame": frames[0], "end_frame": frames[-1]},
        "competing_candidates": [],
        "limitations": [],
    }


def generation_link(
    reference,
    context_reference,
    *,
    capture=CAPTURE_A,
    role="sgw_s1u",
    address=SGW,
    teid=56,
    interface_type=1,
    status=ESTABLISHED,
    ebi=(5,),
    frames=(103,),
):
    return {
        "relationship_type": "SESSION_CONTEXT_TO_BEARER_GENERATION",
        "capture_file": capture,
        "source_subject_reference": context_reference,
        "target_subject_reference": reference,
        "association_status": status,
        "association_basis": (
            "endpoint_advertised_by_a_member_transaction_of_one_established_context"
        ),
        "reviewed_identifiers": [],
        "source_transaction_references": [],
        "source_frames": list(frames),
        "evidence_refs": [evidence(frame, None) for frame in frames],
        "observation_window": {"start_frame": frames[0], "end_frame": frames[-1]},
        "competing_candidates": [],
        "bearer_endpoint": {
            "role": role,
            "address": address,
            "teid": teid,
            "interface_type": interface_type,
            "eps_bearer_identities": list(ebi),
            "generation_references": [],
        },
        "limitations": [],
        "bridge_mediated": False,
    }


def binding(
    transaction,
    context_reference,
    *,
    capture=CAPTURE_A,
    status=ESTABLISHED,
    outcome=ACCEPTED,
    outcome_basis="accepted_cause_in_correlated_response",
    frames=(200, 205),
    competing=None,
    limitations=None,
):
    return {
        "relationship_type": "RELEASE_TO_SESSION_CONTEXT",
        "capture_file": capture,
        "source_subject_reference": transaction,
        "target_subject_reference": context_reference,
        "association_status": status,
        "association_basis": "request_addresses_one_hop_local_control_plane_fteid_with_its_path_peer",
        "reviewed_identifiers": [],
        "source_transaction_references": [transaction],
        "source_frames": list(frames),
        "evidence_refs": [
            evidence(frames[0], "Delete Session Request"),
            evidence(frames[1], "Delete Session Response"),
        ],
        "observation_window": {"start_frame": frames[0], "end_frame": frames[1]},
        "competing_candidates": list(competing or []),
        "release_outcome_status": outcome,
        "release_outcome_basis": outcome_basis,
        "limitations": list(limitations or []),
    }


def candidate(
    reference,
    context_reference,
    transaction,
    endpoint_reference,
    *,
    capture=CAPTURE_A,
    role="sgw_s1u",
    address=SGW,
    teid=56,
    interface_type=1,
    status=ESTABLISHED,
    ebi=(5,),
    frames=(200, 205),
):
    return {
        "generation_closure_candidate_reference": reference,
        "capture_file": capture,
        "session_context_reference": context_reference,
        "release_transaction_reference": transaction,
        "bearer_endpoint_reference": endpoint_reference,
        "bearer_endpoint": {
            "role": role,
            "address": address,
            "teid": teid,
            "interface_type": interface_type,
            "eps_bearer_identities": list(ebi),
            "generation_references": [],
        },
        "association_status": status,
        "association_basis": (
            "accepted_release_bound_to_one_established_context_with_one_established_"
            "session_to_generation_link"
        ),
        "chain": [],
        "item_identities": {"release_bearer_identities": list(ebi)},
        "release_request_frame": frames[0],
        "release_confirmation_frame": frames[1],
        "limitations": [],
    }


def identity_document(
    *,
    contexts=None,
    links=None,
    correspondences=None,
    bindings=None,
    generation_links=None,
    candidates=None,
    ambiguous=None,
    unbound=None,
    counts=None,
):
    contexts = list(contexts or [])
    links = list(links or [])
    correspondences = list(correspondences or [])
    bindings = list(bindings or [])
    generation_links = list(generation_links or [])
    candidates = list(candidates or [])
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
            1 for item in contexts if item["association_status"] == ESTABLISHED
        ),
        "cross_interface_candidates": [],
        "cross_interface_candidate_count": 0,
        "endpoint_correspondence_links": correspondences,
        "endpoint_correspondence_count": len(correspondences),
        "session_identity_links": links,
        "session_identity_count": len(links),
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
            1 for item in candidates if item["association_status"] == ESTABLISHED
        ),
        "ambiguous_associations": list(ambiguous or []),
        "ambiguous_association_count": len(ambiguous or []),
        "unbound_evidence": list(unbound or []),
        "unbound_evidence_count": len(unbound or []),
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "",
    }
    for key, value in (counts or {}).items():
        document[key] = value
    return document


def lifecycle_subject(
    reference,
    *,
    capture=CAPTURE_A,
    role="sgw_s1u",
    address=SGW,
    teid=56,
    interface_type=1,
    state="CLOSED_BY_ACCEPTED_RELEASE",
    boundary_transaction=None,
    boundary_frames=(200, 205),
    basis="accepted_release_response_bound_by_reviewed_session_context",
    observations=None,
):
    boundary = None
    if boundary_transaction is not None:
        boundary = {
            "basis": basis,
            "frame_number": boundary_frames[1],
            "release_confirmation_frame": boundary_frames[1],
            "release_request_frame": boundary_frames[0],
            "release_effective_frame_proven": False,
            "transaction_reference": boundary_transaction,
        }
    return {
        "generation_reference": reference,
        "capture_file": capture,
        "receiving_endpoint_role": role,
        "receiving_endpoint_address": address,
        "receiving_endpoint_teid": teid,
        "reviewed_interface_type": interface_type,
        "generation_state": state,
        "generation_boundary": boundary,
        "observations": observations or [],
        "advertisement_family_references": [],
        "observation_window": {"start_frame": 103, "end_frame": boundary_frames[1]},
        "evidence_refs": [],
        "limitations": [],
    }


def lifecycle_document(*, subjects=None, boundaries=None, families=None, ambiguous=None):
    subjects = list(subjects or [])
    boundaries = list(boundaries or [])
    families = list(families or [])
    return {
        "domain": "epc-procedures",
        "domain_version": "0.5.0",
        "analysis_name": "epc-bearer-lifecycle",
        "analysis_version": "1.0.0",
        "input_provenance": {},
        "analysis_scope": {},
        "lifecycle_subjects": subjects,
        "lifecycle_subject_count": len(subjects),
        "lifecycle_subjects_omitted": 0,
        "advertisement_families": families,
        "advertisement_family_count": len(families),
        "advertisement_families_omitted": 0,
        "generation_boundary_evidence": boundaries,
        "generation_boundary_count": len(boundaries),
        "release_observation_count": len(boundaries),
        "generation_observations": [],
        "generation_scoped_s1u_observations": [],
        "generation_scoped_observation_count": 0,
        "unresolved_packet_observations": [],
        "unresolved_packet_observation_count": 0,
        "endpoint_reuse_observations": [],
        "endpoint_reuse_observation_count": 0,
        "procedure_local_deviations": [],
        "procedure_local_deviation_count": 0,
        "accounting": {},
        "ambiguous_associations": list(ambiguous or []),
        "ambiguous_association_count": len(ambiguous or []),
        "unbound_evidence": [],
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "",
    }


def boundary_evidence(transaction, *, capture=CAPTURE_A, frames=(200, 205), outcome=ACCEPTED):
    return {
        "capture_file": capture,
        "transaction_reference": transaction,
        "request_frame": frames[0],
        "response_frame": frames[1],
        "request_message_type": "Delete Session Request",
        "response_message_type": "Delete Session Response",
        "release_outcome": outcome,
        "release_outcome_basis": "accepted_cause_in_correlated_response",
        "correlation_status": "MATCHED",
        "correlation_strength": "STRONG",
        "control_plane_context": {"basis": "correlated_response_header_teid", "session_teid": 1},
        "released_endpoints": [],
        "bearer_identity_scope": [],
        "evidence_refs": [
            evidence(frames[0], "Delete Session Request"),
            evidence(frames[1], "Delete Session Response"),
        ],
        "limitations": [],
    }


def stream(
    reference,
    *,
    capture=CAPTURE_A,
    role="sgw_s1u",
    direction="UPLINK",
    source=ENB,
    destination=SGW,
    teid=56,
    packets=100,
    octets=10000,
    first=10,
    last=190,
    status="SUPPORTED",
):
    return {
        "stream_reference": reference,
        "stream_key": f"gtpu-path:{capture}:{source}:2152:{destination}:2152:teid{teid}",
        "capture_file": capture,
        "outer_source": source,
        "outer_destination": destination,
        "teid": teid,
        "direction": direction,
        "matched_endpoint_role": role,
        "association_status": status,
        "observed_g_pdu_packet_count": packets,
        "observed_payload_byte_count": octets,
        "first_frame": first,
        "last_frame": last,
        "evidence_refs": [],
        "limitations": [],
    }


def s1u_document(*, streams=None, counts=None):
    streams = list(streams or [])
    document = {
        "domain": "epc-procedures",
        "domain_version": "0.4.0",
        "analysis_name": "epc-s1u-observation",
        "analysis_version": "1.0.0",
        "input_provenance": {},
        "analysis_scope": {},
        "stream_observations": streams,
        "stream_count": len(streams),
        "streams_omitted": 0,
        "supported_stream_count": sum(
            1 for item in streams if item["association_status"] == "SUPPORTED"
        ),
        "ambiguous_stream_count": 0,
        "unbound_stream_count": 0,
        "observed_g_pdu_packet_count": sum(
            item["observed_g_pdu_packet_count"] for item in streams
        ),
        "observed_payload_byte_count": sum(
            item["observed_payload_byte_count"] for item in streams
        ),
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
        "boundary_selection_status": "NOT_APPLICABLE",
        "first_abnormal_boundary": None,
        "boundary_note": "",
    }
    for key, value in (counts or {}).items():
        document[key] = value
    return document


def gtpu_event(frame, *, source=ENB, destination=SGW, teid=56, length=100, capture=CAPTURE_A):
    return {
        "capture_file": capture,
        "frame_number": frame,
        "header": {"teid": teid, "message_type": "G-PDU", "message_length": length},
        "outer": {
            "source_address": source,
            "destination_address": destination,
            "source_port": 2152,
            "destination_port": 2152,
        },
    }


def gtpv2_event(frame, message, *, capture=CAPTURE_A):
    return {
        "capture_file": capture,
        "frame_number": frame,
        "message_type": message,
    }


def simple_scenario(*, outcome=ACCEPTED, binding_status=ESTABLISHED, closure=True, **kwargs):
    """One S11 context, one release, optionally one proved generation."""
    ctx = context("ctx-1")
    bnd = binding("tx-del-1", "ctx-1", outcome=outcome, status=binding_status, **kwargs)
    documents = {
        "contexts": [ctx],
        "bindings": [bnd],
    }
    lifecycle_subjects = []
    boundaries = []
    if closure:
        documents["generation_links"] = [
            generation_link("endpoint-1", "ctx-1", role="sgw_s1u", teid=56)
        ]
        documents["candidates"] = [
            candidate("closure-1", "ctx-1", "tx-del-1", "endpoint-1", role="sgw_s1u", teid=56)
        ]
        lifecycle_subjects.append(
            lifecycle_subject(
                "generation-1", role="sgw_s1u", teid=56, boundary_transaction="tx-del-1"
            )
        )
        boundaries.append(boundary_evidence("tx-del-1"))
    return (
        identity_document(**documents),
        lifecycle_document(subjects=lifecycle_subjects, boundaries=boundaries),
    )


class NarrativeTestCase(unittest.TestCase):
    def analyze(self, identity, lifecycle, **kwargs):
        return model.analyze(identity, lifecycle, **kwargs)

    def write(self, tmp: Path, name: str, payload) -> Path:
        path = tmp / name
        if isinstance(payload, list):
            path.write_text(
                "".join(json.dumps(item, sort_keys=True) + "\n" for item in payload),
                encoding="utf-8",
            )
        else:
            path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        return path

    def run_cli(self, tmp: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(CLI), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def stage(self, narrative, label):
        return next(item for item in narrative["stages"] if item["stage"] == label)


# ---------------------------------------------------------------------------
# A — document shape and proof semantics
# ---------------------------------------------------------------------------
class DocumentContractTests(NarrativeTestCase):
    def test_a01_document_requires_the_published_fields(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        required = {
            "domain",
            "domain_version",
            "analysis_name",
            "analysis_version",
            "input_provenance",
            "analysis_scope",
            "source_completeness",
            "narrative_subjects",
            "narrative_subject_count",
            "narrative_subjects_omitted",
            "release_narratives",
            "release_narrative_count",
            "release_narratives_omitted",
            "temporal_observations",
            "temporal_observation_count",
            "temporal_observations_omitted",
            "temporal_accounting",
            "ambiguous_associations",
            "ambiguous_association_count",
            "unbound_evidence",
            "unbound_evidence_count",
            "evidence_limitations",
            "additional_evidence_needed",
            "not_confirmed",
            "boundary_selection_status",
            "first_abnormal_boundary",
            "boundary_note",
        }
        self.assertEqual(required - set(result), set())
        self.assertEqual(result["analysis_name"], "epc-release-narrative")
        self.assertEqual(result["boundary_selection_status"], "NOT_APPLICABLE")
        self.assertIsNone(result["first_abnormal_boundary"])

    def test_a02_schema_declares_the_same_required_fields(self) -> None:
        schema = json.loads(
            (PACKAGE / "schemas" / "epc-release-narrative-analysis.schema.json").read_text(
                encoding="utf-8"
            )
        )
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        self.assertEqual(set(schema["required"]), set(result))
        self.assertEqual(
            schema["properties"]["boundary_selection_status"]["const"], "NOT_APPLICABLE"
        )
        self.assertEqual(
            schema["properties"]["first_abnormal_boundary"], {"type": "null"}
        )
        self.assertEqual(
            set(schema["$defs"]["stage_label"]["enum"]), set(model.STAGE_LABELS)
        )
        self.assertEqual(
            set(schema["$defs"]["evidence_status"]["enum"]), set(model.EVIDENCE_STATUSES)
        )

    def test_a03_every_stage_uses_the_closed_vocabulary(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(len(narrative["stages"]), 9)
        for stage in narrative["stages"]:
            self.assertIn(stage["stage"], model.STAGE_LABELS)
            self.assertIn(stage["evidence_status"], model.EVIDENCE_STATUSES)
            self.assertIn(stage["source_analysis"], {"epc-session-identity", "epc-bearer-lifecycle"})
            self.assertIsInstance(stage["limitations"], list)

    def test_a04_effective_instant_is_never_proved(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertFalse(narrative["release_effective_frame_proven"])
        stage = self.stage(narrative, model.STAGE_EFFECTIVE_INSTANT_UNPROVED)
        self.assertEqual(stage["evidence_status"], NOT_ESTABLISHED)
        for generation in narrative["proved_generations"]:
            self.assertFalse(generation["release_effective_frame_proven"])

    def test_a05_malformed_input_is_rejected(self) -> None:
        with self.assertRaises(model.NarrativeInputError):
            model.analyze(None, lifecycle_document())
        with self.assertRaises(model.NarrativeInputError):
            model.analyze(identity_document(), None)
        with self.assertRaises(model.NarrativeInputError):
            model.analyze(["not", "an", "object"], lifecycle_document())


# ---------------------------------------------------------------------------
# B — release outcome, binding and closure separation
# ---------------------------------------------------------------------------
class ReleaseSeparationTests(NarrativeTestCase):
    def test_b01_accepted_release_without_generation_closure(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], ACCEPTED)
        self.assertEqual(narrative["release_session_binding_status"], ESTABLISHED)
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertEqual(narrative["proved_generations"], [])
        self.assertEqual(
            self.stage(narrative, model.STAGE_RELEASE_OUTCOME_ACCEPTED)["evidence_status"],
            ACCEPTED,
        )
        self.assertEqual(
            self.stage(narrative, model.STAGE_BINDING_ESTABLISHED)["evidence_status"],
            ESTABLISHED,
        )
        self.assertEqual(
            self.stage(narrative, model.STAGE_CLOSURE_NOT_ESTABLISHED)["evidence_status"],
            NOT_ESTABLISHED,
        )
        # An identity deficiency is never reported as a release failure.
        self.assertNotIn(
            model.STAGE_RELEASE_OUTCOME_REJECTED,
            [item["stage"] for item in narrative["stages"]],
        )

    def test_b02_rejected_release_response(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        identity["release_session_bindings"][0]["release_outcome_status"] = REJECTED
        identity["release_session_bindings"][0]["release_outcome_basis"] = (
            "rejected_cause_in_correlated_response"
        )
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], REJECTED)
        self.assertEqual(narrative["release_session_binding_status"], ESTABLISHED)
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertEqual(
            self.stage(narrative, model.STAGE_RELEASE_OUTCOME_REJECTED)["evidence_status"],
            REJECTED,
        )

    def test_b03_unresolved_release_outcome_without_message_cause(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        identity["release_session_bindings"][0]["release_outcome_status"] = UNRESOLVED
        identity["release_session_bindings"][0]["release_outcome_basis"] = None
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], UNRESOLVED)
        stage = self.stage(narrative, model.STAGE_RELEASE_OUTCOME_UNRESOLVED)
        self.assertEqual(stage["evidence_status"], UNRESOLVED)
        self.assertIsNone(stage["association_basis"])
        self.assertTrue(any("unresolved" in item for item in stage["limitations"]))

    def test_b04_binding_not_established_keeps_the_outcome(self) -> None:
        identity, lifecycle = simple_scenario(closure=False, binding_status=NOT_ESTABLISHED)
        identity["release_session_bindings"][0]["target_subject_reference"] = None
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], ACCEPTED)
        self.assertEqual(narrative["release_session_binding_status"], NOT_ESTABLISHED)
        self.assertEqual(
            self.stage(narrative, model.STAGE_BINDING_NOT_ESTABLISHED)["evidence_status"],
            NOT_ESTABLISHED,
        )

    def test_b05_release_without_session_context(self) -> None:
        identity, lifecycle = simple_scenario(closure=False, binding_status=NOT_ESTABLISHED)
        identity["release_session_bindings"][0]["target_subject_reference"] = None
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertIsNone(narrative["narrative_subject_reference"])
        self.assertIsNone(narrative["session_context_reference"])
        for label in (
            model.STAGE_ALLOCATION_OBSERVED,
            model.STAGE_ALLOCATION_ACCEPTED,
            model.STAGE_SESSION_CONTEXT_ESTABLISHED,
        ):
            self.assertEqual(self.stage(narrative, label)["evidence_status"], "INSUFFICIENT_EVIDENCE")
        self.assertTrue(any("no narrative subject" in item for item in narrative["limitations"]))

    def test_b06_release_on_a_not_established_context(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        identity["hop_local_contexts"][0]["association_status"] = NOT_ESTABLISHED
        identity["hop_local_contexts"][0]["allocation_outcome_status"] = REJECTED
        identity["established_hop_local_context_count"] = 0
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(
            self.stage(narrative, model.STAGE_SESSION_CONTEXT_ESTABLISHED)["evidence_status"],
            NOT_ESTABLISHED,
        )
        self.assertEqual(
            self.stage(narrative, model.STAGE_ALLOCATION_ACCEPTED)["evidence_status"],
            NOT_ESTABLISHED,
        )
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)


# ---------------------------------------------------------------------------
# C — generation admission
# ---------------------------------------------------------------------------
class GenerationAdmissionTests(NarrativeTestCase):
    def test_c01_proved_generation_requires_all_three_sources(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], ESTABLISHED)
        self.assertEqual(len(narrative["proved_generations"]), 1)
        generation = narrative["proved_generations"][0]
        self.assertEqual(generation["generation_reference"], "generation-1")
        self.assertEqual(generation["closure_candidate_reference"], "closure-1")
        self.assertEqual(generation["generation_state"], "CLOSED_BY_ACCEPTED_RELEASE")

    def test_c02_candidate_without_lifecycle_boundary_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        lifecycle["lifecycle_subjects"][0]["generation_boundary"] = None
        lifecycle["generation_boundary_evidence"] = []
        lifecycle["generation_boundary_count"] = 0
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertEqual(narrative["proved_generations"], [])

    def test_c03_lifecycle_boundary_without_candidate_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"] = []
        identity["generation_closure_candidate_count"] = 0
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertTrue(
            any("no established closure candidate" in item for item in narrative["limitations"])
        )

    def test_c04_candidate_for_another_context_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["session_context_reference"] = "ctx-other"
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["generation_closure_status"], NOT_ESTABLISHED
        )

    def test_c05_candidate_for_another_release_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["release_transaction_reference"] = "tx-other"
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["generation_closure_status"], NOT_ESTABLISHED
        )

    def test_c06_endpoint_mismatch_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["bearer_endpoint"]["teid"] = 999
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["generation_closure_status"], NOT_ESTABLISHED
        )

    def test_c07_role_mismatch_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["bearer_endpoint"]["role"] = "enodeb_s1u"
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["generation_closure_status"], NOT_ESTABLISHED
        )

    def test_c08_capture_mismatch_proves_nothing(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["capture_file"] = CAPTURE_B
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["generation_closure_status"], NOT_ESTABLISHED
        )

    def test_c09_two_roles_of_one_release_prove_two_generations(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["session_to_generation_links"].append(
            generation_link(
                "endpoint-2", "ctx-1", role="enodeb_s1u", address=ENB, teid=16777736,
                interface_type=0,
            )
        )
        identity["session_to_generation_count"] = 2
        identity["generation_closure_candidates"].append(
            candidate(
                "closure-2", "ctx-1", "tx-del-1", "endpoint-2", role="enodeb_s1u",
                address=ENB, teid=16777736, interface_type=0,
            )
        )
        identity["generation_closure_candidate_count"] = 2
        identity["established_closure_candidate_count"] = 2
        lifecycle["lifecycle_subjects"].append(
            lifecycle_subject(
                "generation-2", role="enodeb_s1u", address=ENB, teid=16777736,
                interface_type=0, boundary_transaction="tx-del-1",
            )
        )
        lifecycle["lifecycle_subject_count"] = 2
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], ESTABLISHED)
        self.assertEqual(len(narrative["proved_generations"]), 2)
        roles = sorted(item["receiving_endpoint_role"] for item in narrative["proved_generations"])
        self.assertEqual(roles, ["enodeb_s1u", "sgw_s1u"])

    def test_c10_competing_generations_stay_ambiguous(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"].append(
            candidate("closure-2", "ctx-1", "tx-del-1", "endpoint-1", role="sgw_s1u", teid=56)
        )
        identity["generation_closure_candidate_count"] = 2
        identity["established_closure_candidate_count"] = 2
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], AMBIGUOUS)
        self.assertEqual(len(narrative["competing_generations"]), 1)
        self.assertGreaterEqual(result["ambiguous_association_count"], 1)

    def test_c10b_rejected_outcome_never_promotes_a_published_boundary(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["release_session_bindings"][0]["release_outcome_status"] = REJECTED
        # The lifecycle boundary contradicts the rejected outcome; the narrative
        # reports the inconsistency and never promotes it into a closure.
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_outcome_status"], REJECTED)
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertEqual(narrative["proved_generations"], [])
        self.assertTrue(
            any("not accepted" in item for item in narrative["limitations"])
        )

    def test_c11_unassigned_identity_never_proves_a_generation(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["generation_closure_candidates"][0]["bearer_endpoint"]["eps_bearer_identities"] = [0]
        identity["generation_closure_candidates"][0]["association_status"] = NOT_ESTABLISHED
        identity["established_closure_candidate_count"] = 0
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["generation_closure_status"], NOT_ESTABLISHED)
        self.assertEqual(narrative["release_outcome_status"], ACCEPTED)


# ---------------------------------------------------------------------------
# D — subjects, groups and capture isolation
# ---------------------------------------------------------------------------
class SubjectScopeTests(NarrativeTestCase):
    def test_d01_one_subject_per_published_context(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context("ctx-2", interface_class="S5/S8", allocation="tx-create-2", frames=(101, 102))
        )
        identity["hop_local_context_count"] = 2
        result = self.analyze(identity, lifecycle)
        self.assertEqual(result["narrative_subject_count"], 2)
        references = {item["session_context_reference"] for item in result["narrative_subjects"]}
        self.assertEqual(references, {"ctx-1", "ctx-2"})

    def test_d02_single_hop_context_is_its_own_group(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        subject = result["narrative_subjects"][0]
        self.assertEqual(subject["narrative_group_basis"], "single_hop_local_context")
        self.assertEqual(subject["narrative_group_members"], ["ctx-1"])

    def test_d03_established_identity_link_creates_a_labelled_group(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context("ctx-2", interface_class="S5/S8", allocation="tx-create-2", frames=(101, 102))
        )
        identity["hop_local_context_count"] = 2
        identity["session_identity_links"] = [identity_link("link-1", "ctx-1", "ctx-2")]
        identity["session_identity_count"] = 1
        result = self.analyze(identity, lifecycle)
        groups = {item["narrative_group_reference"] for item in result["narrative_subjects"]}
        self.assertEqual(len(groups), 1)
        for subject in result["narrative_subjects"]:
            self.assertEqual(subject["narrative_group_basis"], "proved_cross_interface_session_identity")
            self.assertEqual(subject["narrative_group_members"], ["ctx-1", "ctx-2"])
            self.assertEqual(subject["narrative_group_bridge_references"], ["link-1"])
        # The source context references are preserved, never replaced by the group.
        self.assertEqual(
            {item["session_context_reference"] for item in result["narrative_subjects"]},
            {"ctx-1", "ctx-2"},
        )

    def test_d04_endpoint_correspondence_is_not_a_bridge(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context("ctx-2", interface_class="S5/S8", allocation="tx-create-2", frames=(101, 102))
        )
        identity["hop_local_context_count"] = 2
        identity["endpoint_correspondence_links"] = [
            identity_link(
                "corr-1",
                "ctx-1",
                "ctx-2",
                status="SUPPORTED",
                relationship_type="CROSS_INTERFACE_ENDPOINT_CORRESPONDENCE",
            )
        ]
        identity["endpoint_correspondence_count"] = 1
        result = self.analyze(identity, lifecycle)
        groups = {item["narrative_group_reference"] for item in result["narrative_subjects"]}
        self.assertEqual(len(groups), 2)
        for subject in result["narrative_subjects"]:
            self.assertEqual(subject["narrative_group_basis"], "single_hop_local_context")

    def test_d05_ambiguous_identity_link_does_not_merge(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context("ctx-2", interface_class="S5/S8", allocation="tx-create-2", frames=(101, 102))
        )
        identity["hop_local_context_count"] = 2
        identity["session_identity_links"] = [
            identity_link("link-1", "ctx-1", "ctx-2", status=AMBIGUOUS)
        ]
        identity["session_identity_count"] = 1
        result = self.analyze(identity, lifecycle)
        groups = {item["narrative_group_reference"] for item in result["narrative_subjects"]}
        self.assertEqual(len(groups), 2)

    def test_d06_equal_teid_across_captures_stays_separate(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context(
                "ctx-b",
                capture=CAPTURE_B,
                allocation="tx-create-b",
                frames=(300, 303),
                evidence_refs=[
                    evidence(300, "Create Session Request"),
                    evidence(303, "Create Session Response"),
                ],
            )
        )
        identity["hop_local_context_count"] = 2
        # A link that tries to join the two captures must not merge them.
        identity["session_identity_links"] = [
            identity_link("link-cross", "ctx-1", "ctx-b", capture=CAPTURE_A)
        ]
        identity["session_identity_count"] = 1
        result = self.analyze(identity, lifecycle)
        groups_by_capture: dict[str, set[str]] = {}
        for subject in result["narrative_subjects"]:
            groups_by_capture.setdefault(subject["capture_file"], set()).add(
                subject["narrative_group_reference"]
            )
        self.assertEqual(set(groups_by_capture), {CAPTURE_A, CAPTURE_B})
        for groups in groups_by_capture.values():
            self.assertEqual(len(groups), 1)
        self.assertNotEqual(
            groups_by_capture[CAPTURE_A], groups_by_capture[CAPTURE_B]
        )

    def test_d07_equal_ebi_across_sessions_is_not_a_bridge(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["hop_local_contexts"].append(
            context("ctx-2", allocation="tx-create-2", frames=(110, 113))
        )
        identity["hop_local_context_count"] = 2
        identity["session_to_generation_links"].append(
            generation_link("endpoint-2", "ctx-2", role="sgw_s1u", teid=56, ebi=(5,))
        )
        identity["session_to_generation_count"] = 2
        result = self.analyze(identity, lifecycle)
        groups = {item["narrative_group_reference"] for item in result["narrative_subjects"]}
        self.assertEqual(len(groups), 2)

    def test_d08_competing_session_contexts_stay_ambiguous(self) -> None:
        identity, lifecycle = simple_scenario(closure=False, binding_status=AMBIGUOUS)
        identity["release_session_bindings"][0]["target_subject_reference"] = None
        identity["release_session_bindings"][0]["competing_candidates"] = ["ctx-1", "ctx-2"]
        result = self.analyze(identity, lifecycle)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["release_session_binding_status"], AMBIGUOUS)
        self.assertIsNone(narrative["narrative_subject_reference"])
        self.assertTrue(
            any("binds to none" in item for item in narrative["limitations"])
        )


# ---------------------------------------------------------------------------
# E — source completeness and reference integrity
# ---------------------------------------------------------------------------
class SourceIntegrityTests(NarrativeTestCase):
    def test_e01_truncated_bindings_refuse_exhaustive_coverage(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["release_session_binding_count"] = 300
        result = self.analyze(identity, lifecycle)
        completeness = result["source_completeness"]
        self.assertEqual(completeness["status"], "SOURCE_CANDIDATES_TRUNCATED")
        self.assertFalse(completeness["exhaustive_coverage_proven"])
        self.assertTrue(
            any("SOURCE_CANDIDATES_TRUNCATED" in item for item in result["evidence_limitations"])
        )

    def test_e02_missing_count_refuses_exhaustive_coverage(self) -> None:
        identity, lifecycle = simple_scenario()
        identity.pop("generation_closure_candidate_count")
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["source_completeness"]["status"], "SOURCE_CANDIDATES_METADATA_INVALID"
        )
        self.assertFalse(result["source_completeness"]["exhaustive_coverage_proven"])

    def test_e03_underdeclared_count_refuses_exhaustive_coverage(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["session_to_generation_count"] = 0
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["source_completeness"]["status"], "SOURCE_CANDIDATES_METADATA_INVALID"
        )

    def test_e04_nonzero_omitted_count_refuses_exhaustive_coverage(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["release_session_bindings_omitted"] = 3
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["source_completeness"]["status"], "SOURCE_CANDIDATES_METADATA_INVALID"
        )

    def test_e05_complete_sources_prove_exhaustive_coverage(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        self.assertEqual(result["source_completeness"]["status"], "COMPLETE")
        self.assertTrue(result["source_completeness"]["exhaustive_coverage_proven"])
        self.assertIsNone(result["source_completeness"]["limitation"])

    def test_e06_source_reference_mismatch_is_published(self) -> None:
        identity, lifecycle = simple_scenario()
        events = [
            gtpv2_event(100, "Create Session Request"),
            gtpv2_event(103, "Create Session Response"),
            gtpv2_event(200, "Delete Session Request"),
            # The confirmation frame is missing from the supplied capture.
        ]
        result = self.analyze(identity, lifecycle, gtpv2_events=events)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["provenance_status"], "INCONSISTENT")
        self.assertGreaterEqual(result["unbound_evidence_count"], 1)
        kinds = {item["kind"] for item in result["unbound_evidence"]}
        self.assertIn("source_reference_not_observed_in_supplied_capture", kinds)
        # The source claim stays visible.
        self.assertEqual(narrative["release_outcome_status"], ACCEPTED)

    def test_e07_conflicting_message_type_is_published(self) -> None:
        identity, lifecycle = simple_scenario()
        events = [
            gtpv2_event(200, "Modify Bearer Request"),
            gtpv2_event(205, "Delete Session Response"),
        ]
        result = self.analyze(identity, lifecycle, gtpv2_events=events)
        narrative = result["release_narratives"][0]
        self.assertEqual(narrative["provenance_status"], "INCONSISTENT")

    def test_e08_matching_capture_validates_the_anchors(self) -> None:
        identity, lifecycle = simple_scenario()
        events = [
            gtpv2_event(100, "Create Session Request"),
            gtpv2_event(103, "Create Session Response"),
            gtpv2_event(200, "Delete Session Request"),
            gtpv2_event(205, "Delete Session Response"),
        ]
        result = self.analyze(identity, lifecycle, gtpv2_events=events)
        self.assertEqual(
            result["release_narratives"][0]["provenance_status"], "VALIDATED"
        )
        self.assertEqual(result["unbound_evidence_count"], 0)

    def test_e09_without_gtpv2_events_provenance_stays_unvalidated(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        self.assertEqual(
            result["release_narratives"][0]["provenance_status"], "NOT_VALIDATED"
        )
        self.assertTrue(
            any("not re-validated" in item for item in result["evidence_limitations"])
        )

    def test_e10_binding_to_an_unpublished_context_is_unbound(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        identity["release_session_bindings"][0]["target_subject_reference"] = "ctx-missing"
        result = self.analyze(identity, lifecycle)
        self.assertEqual(result["release_narratives"][0]["narrative_subject_reference"], None)
        kinds = {item["kind"] for item in result["unbound_evidence"]}
        self.assertIn("release_binding_targets_an_unpublished_session_context", kinds)


# ---------------------------------------------------------------------------
# F — temporal evidence
# ---------------------------------------------------------------------------
class TemporalEvidenceTests(NarrativeTestCase):
    def scenario_with_stream(self, **kwargs):
        identity, lifecycle = simple_scenario()
        return identity, lifecycle

    def test_f01_traffic_before_the_release_only(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=4, octets=400, first=10, last=190)])
        events = [gtpu_event(frame, length=100) for frame in (10, 20, 30, 190)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        self.assertEqual(observation["temporal_placement_status"], "ESTABLISHED")
        self.assertEqual(observation["partitions"]["before_release"]["g_pdu_count"], 4)
        self.assertEqual(observation["partitions"]["pending_release"]["g_pdu_count"], 0)
        self.assertEqual(observation["partitions"]["after_confirmation"]["g_pdu_count"], 0)
        self.assertTrue(observation["partition_conserved"])

    def test_f02_traffic_inside_the_pending_release_interval(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=3, octets=300, first=10, last=202)])
        events = [gtpu_event(frame, length=100) for frame in (10, 200, 202)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        self.assertEqual(observation["partitions"]["pending_release"]["g_pdu_count"], 2)
        self.assertTrue(
            any("not evidence that" in item for item in observation["limitations"])
        )
        # Pending traffic never becomes a forwarding-stop proof.
        self.assertFalse(result["release_narratives"][0]["release_effective_frame_proven"])

    def test_f03_traffic_after_the_confirmation(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=3, octets=300, first=10, last=260)])
        events = [gtpu_event(frame, length=100) for frame in (10, 210, 260)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        self.assertEqual(observation["partitions"]["after_confirmation"]["g_pdu_count"], 2)
        # After-confirmation traffic produces no delivery, loss or root-cause claim.
        joined = " ".join(result["not_confirmed"])
        self.assertIn("never proves UE receipt", joined)

    def test_f04_aggregate_stream_is_never_divided(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=100, octets=10000, first=10, last=900)])
        result = self.analyze(identity, lifecycle, s1u=s1u)
        observation = result["temporal_observations"][0]
        self.assertEqual(
            observation["temporal_placement_status"], "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"
        )
        self.assertIsNone(observation["partitions"])
        self.assertEqual(observation["partition_basis"], "AGGREGATE_STREAM_ONLY")
        self.assertIsNone(observation["partition_conserved"])
        self.assertEqual(observation["observed_g_pdu_count"], 100)
        self.assertTrue(
            any("divided across time windows" in item for item in observation["limitations"])
        )

    def test_f05_partition_exclusivity_and_conservation(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=6, octets=600, first=10, last=300)])
        events = [gtpu_event(frame, length=100) for frame in (10, 20, 200, 203, 205, 300)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        partitions = observation["partitions"]
        total = sum(partitions[name]["g_pdu_count"] for name in model.PARTITIONS)
        octets = sum(partitions[name]["payload_octets"] for name in model.PARTITIONS)
        self.assertEqual(total, 6)
        self.assertEqual(octets, 600)
        self.assertEqual(total, observation["observed_g_pdu_count"])
        self.assertTrue(observation["partition_conserved"])
        accounting = result["temporal_accounting"]
        self.assertEqual(accounting["duplicate_assignment_count"], 0)
        self.assertTrue(accounting["conserved"])

    def test_f06_frame_level_shortfall_is_published_not_repaired(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=10, octets=1000, first=10, last=190)])
        events = [gtpu_event(frame, length=100) for frame in (10, 20, 30)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        self.assertFalse(observation["partition_conserved"])
        self.assertEqual(observation["observed_g_pdu_count"], 10)
        self.assertTrue(
            any("do not reproduce" in item for item in observation["limitations"])
        )

    def test_f07_non_g_pdu_messages_are_never_counted(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", packets=2, octets=200, first=10, last=20)])
        events = [
            gtpu_event(10, length=100),
            gtpu_event(20, length=100),
            {
                "capture_file": CAPTURE_A,
                "frame_number": 30,
                "header": {"teid": 56, "message_type": "Echo Request", "message_length": 8},
                "outer": {
                    "source_address": ENB,
                    "destination_address": SGW,
                    "source_port": 2152,
                    "destination_port": 2152,
                },
            },
            {
                "capture_file": CAPTURE_A,
                "frame_number": 40,
                "header": {"teid": 56, "message_type": "End Marker", "message_length": 0},
                "outer": {
                    "source_address": ENB,
                    "destination_address": SGW,
                    "source_port": 2152,
                    "destination_port": 2152,
                },
            },
        ]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        observation = result["temporal_observations"][0]
        total = sum(
            observation["partitions"][name]["g_pdu_count"] for name in model.PARTITIONS
        )
        self.assertEqual(total, 2)
        self.assertTrue(observation["partition_conserved"])

    def test_f08_missing_gtpu_events_keep_placement_unestablished(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1")])
        result = self.analyze(identity, lifecycle, s1u=s1u)
        self.assertEqual(
            result["temporal_observations"][0]["temporal_placement_status"],
            "TEMPORAL_PLACEMENT_NOT_ESTABLISHED",
        )
        self.assertFalse(result["temporal_accounting"]["frame_level_evidence_supplied"])
        self.assertTrue(
            any("TEMPORAL_PLACEMENT_NOT_ESTABLISHED" in item for item in result["evidence_limitations"])
        )

    def test_f09_missing_confirmation_frame_prevents_a_window(self) -> None:
        identity, lifecycle = simple_scenario()
        identity["release_session_bindings"][0]["source_frames"] = [200]
        identity["release_session_bindings"][0]["observation_window"] = {
            "start_frame": 200,
            "end_frame": None,
        }
        lifecycle["lifecycle_subjects"][0]["generation_boundary"]["release_confirmation_frame"] = None
        lifecycle["generation_boundary_evidence"][0]["response_frame"] = None
        s1u = s1u_document(streams=[stream("stream-1")])
        events = [gtpu_event(frame) for frame in (10, 20)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        narrative = result["release_narratives"][0]
        self.assertIsNone(narrative["release_confirmation_frame"])
        observation = result["temporal_observations"][0]
        self.assertEqual(
            observation["temporal_placement_status"], "TEMPORAL_PLACEMENT_NOT_ESTABLISHED"
        )
        self.assertIsNone(observation["partitions"])

    def test_f10_stream_for_an_unproved_generation_is_not_attached(self) -> None:
        identity, lifecycle = simple_scenario(closure=False)
        s1u = s1u_document(streams=[stream("stream-1")])
        events = [gtpu_event(frame) for frame in (10, 20)]
        result = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        self.assertEqual(result["temporal_observation_count"], 0)
        self.assertEqual(result["temporal_accounting"]["assigned_to_release_window_count"], 0)
        self.assertEqual(result["temporal_accounting"]["unassigned_g_pdu_event_count"], 2)

    def test_f11_shared_endpoint_without_owner_is_not_attached(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1", status="NOT_ESTABLISHED")])
        result = self.analyze(identity, lifecycle, s1u=s1u)
        self.assertEqual(result["temporal_observation_count"], 1)
        self.assertEqual(
            result["temporal_observations"][0]["association_status"], "NOT_ESTABLISHED"
        )


# ---------------------------------------------------------------------------
# G — CLI contract
# ---------------------------------------------------------------------------
class CliContractTests(NarrativeTestCase):
    def test_g01_cli_writes_json_and_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            output = tmp_path / "narrative.json"
            report = tmp_path / "narrative.txt"
            completed = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(output),
                "--report",
                str(report),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["release_narrative_count"], 1)
            text = report.read_text(encoding="utf-8")
            self.assertIn("EPC Release Narrative and Temporal Evidence", text)
            self.assertIn("RELEASE_EFFECTIVE_INSTANT_UNPROVED: NOT_ESTABLISHED", text)

    def test_g02_cli_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            outputs = []
            for index in (1, 2):
                output = tmp_path / f"narrative-{index}.json"
                report = tmp_path / f"narrative-{index}.txt"
                completed = self.run_cli(
                    tmp_path,
                    "--session-identity",
                    str(identity_path),
                    "--lifecycle",
                    str(lifecycle_path),
                    "--output",
                    str(output),
                    "--report",
                    str(report),
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                outputs.append((output.read_bytes(), report.read_bytes()))
            self.assertEqual(outputs[0], outputs[1])

    def test_g03_cli_refuses_to_overwrite_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            output = tmp_path / "narrative.json"
            first = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(output),
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            second = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(output),
            )
            self.assertEqual(second.returncode, model.EXIT_OUTPUT_FAILURE)
            third = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(output),
                "--force",
            )
            self.assertEqual(third.returncode, 0, third.stderr)

    def test_g04_cli_refuses_to_replace_an_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            completed = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(identity_path),
                "--force",
            )
            self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)
            self.assertIn("must not replace an input", completed.stderr)

    def test_g05_cli_reports_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            broken = tmp_path / "broken.json"
            broken.write_text("{not json", encoding="utf-8")
            completed = self.run_cli(
                tmp_path,
                "--session-identity",
                str(broken),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(tmp_path / "out.json"),
            )
            self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)
            self.assertIn("input error", completed.stderr)

    def test_g06_cli_reports_no_release_narrative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity = identity_document()
            lifecycle = lifecycle_document()
            identity_path = self.write(tmp_path, "identity.json", identity)
            lifecycle_path = self.write(tmp_path, "lifecycle.json", lifecycle)
            output = tmp_path / "narrative.json"
            completed = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(lifecycle_path),
                "--output",
                str(output),
            )
            self.assertEqual(completed.returncode, model.EXIT_NO_SUBJECTS)
            self.assertTrue(output.is_file())

    def test_g07_cli_rejects_a_missing_required_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            identity, lifecycle = simple_scenario()
            identity_path = self.write(tmp_path, "identity.json", identity)
            completed = self.run_cli(
                tmp_path,
                "--session-identity",
                str(identity_path),
                "--lifecycle",
                str(tmp_path / "absent.json"),
                "--output",
                str(tmp_path / "out.json"),
            )
            self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)


# ---------------------------------------------------------------------------
# H — privacy and determinism
# ---------------------------------------------------------------------------
class PrivacyTests(NarrativeTestCase):
    FORBIDDEN = (
        "imsi",
        "msisdn",
        "imei",
        "subscriber_id",
        "assigned_pdn_address",
        "inner_ue_ip",
        "apn_name",
    )

    def test_h01_document_carries_no_subscriber_material(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1")])
        result = self.analyze(identity, lifecycle, s1u=s1u)
        blob = json.dumps(result).lower()
        for token in self.FORBIDDEN:
            self.assertNotIn(f'"{token}"', blob)
        self.assertIn("no subscriber identity", " ".join(result["not_confirmed"]))

    def test_h02_repeated_analysis_is_byte_identical(self) -> None:
        identity, lifecycle = simple_scenario()
        s1u = s1u_document(streams=[stream("stream-1")])
        events = [gtpu_event(frame) for frame in (10, 20)]
        first = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        second = self.analyze(identity, lifecycle, s1u=s1u, gtpu_events=events)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_h03_references_are_pseudonymous_and_stable(self) -> None:
        identity, lifecycle = simple_scenario()
        first = self.analyze(identity, lifecycle)
        second = self.analyze(identity, lifecycle)
        self.assertEqual(
            first["narrative_subjects"][0]["narrative_subject_reference"],
            second["narrative_subjects"][0]["narrative_subject_reference"],
        )
        self.assertTrue(
            first["narrative_subjects"][0]["narrative_subject_reference"].startswith(
                "epc-release-subject-"
            )
        )
        self.assertNotIn("10.0.0", first["narrative_subjects"][0]["narrative_subject_reference"])

    def test_h04_no_wall_clock_or_root_cause_fields(self) -> None:
        identity, lifecycle = simple_scenario()
        result = self.analyze(identity, lifecycle)
        self.assertNotIn("generated_at", result)
        self.assertIsNone(result["first_abnormal_boundary"])
        self.assertEqual(result["boundary_selection_status"], "NOT_APPLICABLE")
        self.assertIn("no root cause", " ".join(result["not_confirmed"]))


if __name__ == "__main__":
    unittest.main()
