#!/usr/bin/env python3
"""Non-vacuous validation of EPC Review navigation resolution semantics.

The validator builds small deterministic source documents, exercises the real
Review index builder, and re-runs each navigation gate against four semantic
mutations. A mutation must be detected; otherwise the validator fails.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REVIEW = load_module(
    ROOT / "scripts" / "epc_evidence_review.py", "epc_review_navigation_validator"
)

CAPTURE_A = "capture-a.pcap"
CAPTURE_B = "capture-b.pcap"
SUBJECT = "epc-release-subject-navigation0001"
GROUP = "epc-release-group-navigation0001"
CONTEXT = "epc-session-context-navigation0001"
IDENTITY_LINK = "epc-identity-link-navigation0001"


def reference(frame: int = 1) -> dict[str, Any]:
    return {
        "frame_number": frame,
        "message_type": "Create Session Request",
        "message_type_code": 32,
        "sequence_number": 1,
        "header_teid": 0,
        "header_teid_state": "PRESENT",
        "message_occurrence": 1,
    }


def context(capture: str = CAPTURE_A, name: str = CONTEXT) -> dict[str, Any]:
    return {
        "capture_file": capture,
        "session_context_reference": name,
        "interface_class": "S11",
        "association_status": "ESTABLISHED",
        "allocation_outcome_status": "ACCEPTED",
        "member_transaction_references": [],
        "evidence_refs": [reference()],
        "limitations": [],
    }


def subject(
    capture: str = CAPTURE_A,
    name: str = SUBJECT,
    group: str = GROUP,
    context_name: str = CONTEXT,
) -> dict[str, Any]:
    return {
        "capture_file": capture,
        "narrative_subject_reference": name,
        "narrative_group_reference": group,
        "narrative_group_basis": "single_hop_local_context",
        "narrative_group_members": [context_name],
        "narrative_group_bridge_references": [],
        "interface_class": "S11",
        "session_context_reference": context_name,
        "session_context_status": "ESTABLISHED",
        "allocation_outcome_status": "ACCEPTED",
        "member_transaction_references": [],
        "release_narrative_references": [],
        "endpoint_correspondence_references": [],
        "bearer_endpoints": [],
        "source_evidence_refs": [reference()],
        "limitations": [],
    }


def audit_record(
    name: str,
    source_reference: Any,
    target_reference: Any,
    *,
    source_analysis: Any = "epc-release-narrative",
    source_artifact: Any = "epc-release-narrative:narrative_subjects",
    target_analysis: Any = "epc-session-identity",
    target_artifact: Any = "epc-session-identity:hop_local_contexts",
    capture: str = CAPTURE_A,
) -> dict[str, Any]:
    return {
        "audit_record_reference": name,
        "capture_file": capture,
        "audit_category": "REFERENCE_INTEGRITY",
        "audit_status": "VERIFIED_CONSISTENT",
        "relationship_type": "HOP_LOCAL_SESSION_CONTEXT",
        "source_analysis": source_analysis,
        "source_artifact_reference": source_artifact,
        "source_subject_reference": source_reference,
        "target_analysis": target_analysis,
        "target_artifact_reference": target_artifact,
        "target_subject_reference": target_reference,
        "proof_sufficiency_status": "SUFFICIENT",
        "candidate_completeness_status": "COMPLETE",
        "consistency_checks": [],
        "limitations": [],
    }


def documents(
    *,
    subjects: list[dict[str, Any]] | None = None,
    audit_records: list[dict[str, Any]] | None = None,
    subjects_omitted: int = 0,
    include_context: bool = True,
) -> dict[str, Any]:
    subjects = [subject()] if subjects is None else subjects
    audit_records = audit_records or []
    identity = {
        "analysis_name": "epc-session-identity",
        "analysis_version": "1.0.0",
        "hop_local_contexts": [context()] if include_context else [],
        "release_session_bindings": [],
        "session_to_generation_links": [],
        "generation_closure_candidates": [],
        "session_identity_links": [],
        "endpoint_correspondence_links": [],
    }
    narrative = {
        "analysis_name": "epc-release-narrative",
        "analysis_version": "1.0.0",
        "narrative_subjects": subjects,
        "narrative_subjects_omitted": subjects_omitted,
        "release_narratives": [],
        "release_narratives_omitted": 0,
        "temporal_observations": [],
        "temporal_observations_omitted": 0,
        "source_completeness": {"status": "COMPLETE"},
    }
    audit = {
        "analysis_name": "epc-evidence-audit",
        "analysis_version": "1.0.0",
        "audit_records": audit_records,
        "audit_record_count": len(audit_records),
        "audit_records_omitted": 0,
        "source_completeness": {"status": "COMPLETE"},
        "audit_summary": {},
    }
    return {
        REVIEW.ARTIFACT_SESSION_IDENTITY: identity,
        REVIEW.ARTIFACT_BEARER_LIFECYCLE: {
            "analysis_name": "epc-bearer-lifecycle",
            "analysis_version": "1.0.0",
        },
        REVIEW.ARTIFACT_RELEASE_NARRATIVE: narrative,
        REVIEW.ARTIFACT_AUDIT: audit,
        REVIEW.ARTIFACT_S1U: None,
        REVIEW.ARTIFACT_DEDICATED_BEARER: None,
    }


def find_missing(index: dict[str, Any], needle: str) -> dict[str, Any] | None:
    for entry in index["missing_references"]:
        if entry.get("reference") == needle:
            return entry
    return None


def gate_relationship_only() -> str | None:
    documents_value = documents(
        audit_records=[
            audit_record(
                "epc-audit-nav-0003",
                SUBJECT,
                "epc-unregistered-target",
                target_artifact="epc-session-identity:release_session_bindings",
            )
        ]
    )
    documents_value[REVIEW.ARTIFACT_SESSION_IDENTITY]["release_session_bindings"] = [
        {
            "capture_file": CAPTURE_A,
            "source_subject_reference": CONTEXT,
            "target_subject_reference": "epc-unregistered-target",
        }
    ]
    index = REVIEW.build_index(documents_value)
    entry = find_missing(index, "epc-unregistered-target")
    if entry is None or entry["classification"] != "RELATIONSHIP_REFERENCE_ONLY":
        return "a relationship-only mention was treated as a resolved source object"
    return None


def gate_cross_capture() -> str | None:
    foreign = subject(capture=CAPTURE_B, name="epc-release-subject-crosscap01", group="epc-release-group-crosscap01", context_name="epc-session-context-crosscap01")
    documents_value = documents(
        subjects=[subject(), foreign],
        audit_records=[
            audit_record(
                "epc-audit-nav-0009",
                "epc-release-subject-crosscap01",
                CONTEXT,
            )
        ],
    )
    index = REVIEW.build_index(documents_value)
    entry = find_missing(index, "epc-release-subject-crosscap01")
    if entry is None or entry["classification"] != "CROSS_CAPTURE_ISOLATED":
        return "equal references were resolved across captures without capture qualification"
    if entry.get("candidate_captures") != [CAPTURE_B]:
        return "cross-capture isolation did not report the foreign capture"
    return None


def gate_missing_source() -> str | None:
    documents_value = documents(
        audit_records=[
            audit_record(
                "epc-audit-nav-0006",
                "epc-release-subject-absent0001",
                CONTEXT,
            )
        ]
    )
    index = REVIEW.build_index(documents_value)
    entry = find_missing(index, "epc-release-subject-absent0001")
    if entry is None:
        return "an unresolved missing source object was suppressed from the index"
    if entry["classification"] != "SOURCE_OBJECT_MISSING":
        return "an absent source object was not classified as missing"
    if index["navigation_summary"]["unresolved_reference_count"] != 1:
        return "the navigation summary hid the unresolved reference"
    return None


def gate_omission_separation() -> str | None:
    documents_value = documents(
        audit_records=[
            audit_record(
                "epc-audit-nav-0005",
                "epc-release-subject-omitted0001",
                CONTEXT,
            )
        ],
        subjects_omitted=1,
    )
    index = REVIEW.build_index(documents_value)
    entry = find_missing(index, "epc-release-subject-omitted0001")
    if entry is None or entry["classification"] != "SOURCE_OMITTED":
        return "source publication omission was not preserved"
    if not entry["source_omitted"] or entry["display_omitted"]:
        return "source omission was conflated with Review display omission"
    if entry["source_omission_status"] != "PUBLICATION_OMITTED":
        return "source omission status was not disclosed"
    return None


GATES = (
    ("relationship-only source membership", gate_relationship_only),
    ("cross-capture isolation", gate_cross_capture),
    ("missing source visibility", gate_missing_source),
    ("source/display omission separation", gate_omission_separation),
)


def main() -> int:
    errors: list[str] = []
    baseline = [(label, gate) for label, gate in GATES]
    for label, gate in baseline:
        check = gate()
        if check:
            errors.append(f"baseline gate failed: {label}: {check}")
    if errors:
        for error in errors:
            print(f"validate-epc-review-navigation: {error}", file=sys.stderr)
        return 1

    mutations: list[tuple[str, list[str]]] = []
    original_resolver = REVIEW._resolve_navigation_reference
    original_build = REVIEW.build_index

    def resolve_as(kind: str):
        def wrapper(reference_value, capture, **kwargs):
            result = original_resolver(reference_value, capture, **kwargs)
            if result["classification"] == kind:
                result = dict(result)
                result["classification"] = "RESOLVED"
                result["status"] = "RESOLVED"
            return result

        return wrapper

    REVIEW._resolve_navigation_reference = resolve_as("RELATIONSHIP_REFERENCE_ONLY")
    try:
        check = gate_relationship_only()
    finally:
        REVIEW._resolve_navigation_reference = original_resolver
    mutations.append(("A: treat any relationship mention as a resolved object", [check] if check else []))

    REVIEW._resolve_navigation_reference = resolve_as("CROSS_CAPTURE_ISOLATED")
    try:
        check = gate_cross_capture()
    finally:
        REVIEW._resolve_navigation_reference = original_resolver
    mutations.append(("B: resolve equal references across captures", [check] if check else []))

    def suppress_missing(documents_value):
        index = original_build(documents_value)
        index = dict(index)
        index["missing_references"] = []
        index["missing_reference_count"] = 0
        index["navigation_summary"] = dict(index["navigation_summary"])
        index["navigation_summary"]["unresolved_reference_count"] = 0
        return index

    REVIEW.build_index = suppress_missing
    try:
        check = gate_missing_source()
    finally:
        REVIEW.build_index = original_build
    mutations.append(("C: suppress unresolved references without evidence", [check] if check else []))

    def conflate_omission(reference_value, capture, **kwargs):
        result = original_resolver(reference_value, capture, **kwargs)
        if result["classification"] == "SOURCE_OMITTED":
            result = dict(result)
            result["source_omitted"] = False
            result["display_omitted"] = True
            result["source_omission_status"] = "NOT_OMITTED"
            result["review_display_omission_status"] = "DISPLAY_OMITTED"
        return result

    REVIEW._resolve_navigation_reference = conflate_omission
    try:
        check = gate_omission_separation()
    finally:
        REVIEW._resolve_navigation_reference = original_resolver
    mutations.append(("D: conflate source omission with display omission", [check] if check else []))

    for label, mutation_errors in mutations:
        if not mutation_errors:
            errors.append(f"mutation was not detected: {label}")

    if errors:
        for error in errors:
            print(f"validate-epc-review-navigation: {error}", file=sys.stderr)
        return 1
    print(
        "validate-epc-review-navigation: OK "
        f"({len(mutations)} navigation mutations detected)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())