#!/usr/bin/env python3
"""Sanitize automated CoreNet Skill execution outputs for benchmark storage.

Extracts only evidence boundary and selection metadata required for differential
comparison. Omits subscriber identities, temporary secrets, local filesystem paths,
and unneeded protocol fields.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


# Orchestration source Domain identities mapped explicitly to the benchmark
# Domain keys. The strings are not identical and must never be assumed to be.
# An identity outside this map is retained as explicit unsupported evidence and
# is never silently folded into a known Domain.
SOURCE_DOMAIN_IDENTITY_MAP = {
    "5gc-registration-mobility": "registration",
    "5gc-pdu-session": "pdu_session",
    "5gc-handover-mobility": "handover_mobility",
}

BENCHMARK_DOMAIN_KEYS = tuple(SOURCE_DOMAIN_IDENTITY_MAP.values())


def map_source_domain_key(value) -> str | None:
    """Map one Orchestration source Domain identity to a benchmark Domain key.

    Returns None for any identity the benchmark does not own, so unknown
    evidence is retained explicitly instead of being attributed to a known
    Domain.
    """
    if not isinstance(value, str):
        return None
    return SOURCE_DOMAIN_IDENTITY_MAP.get(value)


def consumed_domain_instance_counts(source_domain_instances) -> tuple[dict, int]:
    """Count consumed instances per benchmark Domain key from raw Orchestration records.

    Returns ``(counts, unmapped)`` where ``counts`` holds a non-negative integer
    per known benchmark Domain key and ``unmapped`` counts instances whose
    source Domain identity the benchmark does not own. Totals always agree with
    the number of source records examined.
    """
    counts = {key: 0 for key in BENCHMARK_DOMAIN_KEYS}
    unmapped = 0
    for entry in source_domain_instances or []:
        if not isinstance(entry, dict):
            unmapped += 1
            continue
        key = map_source_domain_key(entry.get("source_domain"))
        if key is None:
            unmapped += 1
            continue
        counts[key] += 1
    return counts, unmapped


class SanitizeError(ValueError):
    """A raw orchestration artifact violates the selected-boundary contract.

    The sanitizer must never fabricate a semantic identity or a frame anchor when
    the authoritative Orchestration model produced none. Contract violations fail
    loudly so the original evidence survives outside the tracked repository instead
    of being silently rewritten into a bogus selected boundary.
    """


def _require_identity(value, field_label: str, case_id: str):
    """Reject a missing required identity instead of substituting a placeholder."""
    if value is None or (isinstance(value, str) and not value.strip()):
        raise SanitizeError(f"{case_id}: selected boundary is missing required {field_label}")
    return value


def _extract_selected_boundary(primary: dict, selected_boundary, case_id: str) -> dict:
    """Extract the selected boundary from the authoritative nested contract.

    The Orchestration model publishes::

        selected_boundary = {"candidate_id": ..., "boundary_ref": <candidate>}

    and every semantic property (source domain, procedure family/stage, deviation
    type, evidence level, frame anchor) lives inside ``boundary_ref``. This helper
    reads that structure, verifies the selected candidate identity against the
    group's ``candidate_boundaries``, preserves the legitimately nullable procedure
    stage, and fails loudly instead of inventing a frame or an ``UNKNOWN`` identity.
    """
    if not isinstance(selected_boundary, dict):
        raise SanitizeError(f"{case_id}: selected_boundary is not an object")

    candidate_id = selected_boundary.get("candidate_id")
    if not isinstance(candidate_id, str) or not candidate_id.strip():
        raise SanitizeError(f"{case_id}: selected_boundary is missing candidate_id")

    boundary_ref = selected_boundary.get("boundary_ref")
    if not isinstance(boundary_ref, dict):
        raise SanitizeError(f"{case_id}: selected_boundary.boundary_ref is missing or not an object")

    ref_candidate_id = boundary_ref.get("candidate_id")
    if ref_candidate_id != candidate_id:
        raise SanitizeError(
            f"{case_id}: selected_boundary.candidate_id {candidate_id!r} does not match "
            f"boundary_ref.candidate_id {ref_candidate_id!r}"
        )

    # Candidate identity integrity: the selected candidate must be one of the
    # candidate boundaries the Orchestration runtime actually emitted.
    candidate_boundaries = primary.get("candidate_boundaries")
    if not isinstance(candidate_boundaries, list) or not any(
        isinstance(candidate, dict) and candidate.get("candidate_id") == candidate_id
        for candidate in candidate_boundaries
    ):
        raise SanitizeError(
            f"{case_id}: selected candidate {candidate_id!r} is not present in candidate_boundaries"
        )

    anchor = boundary_ref.get("boundary_anchor")
    if not isinstance(anchor, dict):
        raise SanitizeError(
            f"{case_id}: selected_boundary.boundary_ref.boundary_anchor is missing or not an object"
        )

    frame = anchor.get("frame_number")
    if isinstance(frame, bool) or not isinstance(frame, int) or frame < 1:
        raise SanitizeError(
            f"{case_id}: selected boundary has no valid frame-number anchor; "
            "refusing to fabricate a frame"
        )

    timestamp = anchor.get("timestamp")
    if timestamp is None:
        timestamp = ""
    elif not isinstance(timestamp, str):
        timestamp = str(timestamp)

    return {
        "selected_source_domain": _require_identity(
            boundary_ref.get("source_domain"), "source_domain", case_id
        ),
        "selected_procedure_family": _require_identity(
            boundary_ref.get("procedure_family"), "procedure_family", case_id
        ),
        # procedure_stage is legitimately nullable in the Domain contract.
        "selected_procedure_stage": boundary_ref.get("procedure_stage"),
        "deviation_type": _require_identity(
            boundary_ref.get("deviation_type"), "deviation_type", case_id
        ),
        "boundary_protocol": _require_identity(
            anchor.get("protocol"), "boundary_anchor.protocol", case_id
        ),
        "boundary_message": _require_identity(
            anchor.get("message_type"), "boundary_anchor.message_type", case_id
        ),
        "boundary_frame": frame,
        "boundary_timestamp": timestamp,
        "evidence_level": _require_identity(
            boundary_ref.get("evidence_level"), "evidence_level", case_id
        ),
    }


def sanitize_failure_boundary_result(raw_result: dict, case_id: str) -> dict:
    """Extract sanitized summary from failure boundary orchestration output."""
    groups = raw_result.get("diagnostic_groups") or []
    if not groups:
        return {
            "case_id": case_id,
            "selection_status": "NO_DOMAIN_INPUTS",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": ["No diagnostic groups emitted by orchestration"],
            "additional_evidence_needed": [],
            "domain_instances_count": 0,
            "candidate_boundaries_count": 0,
        }

    # Select primary diagnostic group (first group)
    primary = groups[0]
    selection_status = primary.get("selection_status", "UNKNOWN")
    selected_boundary_raw = primary.get("selected_boundary")

    # Only a SELECTED result may carry a selected boundary. The diagnostic-group
    # properties live inside selected_boundary.boundary_ref (see the authoritative
    # Orchestration model); reading them flat fabricated UNKNOWN identities and a
    # frame-1 anchor. Any non-SELECTED status (no abnormal boundary, ambiguous,
    # insufficient comparable evidence) keeps selected_boundary null; ambiguity is
    # never silently resolved into a selection, and a missing frame anchor is never
    # silently replaced with frame 1.
    sanitized_boundary = None
    if selection_status == "SELECTED":
        if not selected_boundary_raw:
            raise SanitizeError(
                f"{case_id}: selection_status is SELECTED but no selected_boundary is present"
            )
        sanitized_boundary = _extract_selected_boundary(primary, selected_boundary_raw, case_id)

    lims = []
    for item in (primary.get("evidence_limitations") or []):
        if isinstance(item, dict):
            lims.append(item.get("description") or item.get("type") or str(item))
        else:
            lims.append(str(item))

    add_evs = []
    for item in (primary.get("additional_evidence_needed") or []):
        if isinstance(item, dict):
            add_evs.append(item.get("description") or item.get("type") or str(item))
        else:
            add_evs.append(str(item))

    return {
        "case_id": case_id,
        "selection_status": selection_status,
        "selected_boundary": sanitized_boundary,
        "boundary_confidence": primary.get("boundary_confidence"),
        "evidence_limitations": lims,
        "additional_evidence_needed": add_evs,
        # Instances consumed by the primary diagnostic group. The pipeline
        # overrides this with the instances produced by executed Domain Skills
        # and reports the consumed count under orchestration_status, so one
        # counter never carries both meanings.
        "domain_instances_count": len(primary.get("source_domain_instances") or []),
        "candidate_boundaries_count": len(primary.get("candidate_boundaries") or []),
    }


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if len(argv) < 2:
        print("Usage: sanitize_result.py <raw-boundary-output.json> <case-id> [output.json]", file=sys.stderr)
        return 1
    raw_path = Path(argv[0])
    case_id = argv[1]
    raw_data = json.loads(raw_path.read_text(encoding="utf-8"))
    sanitized = sanitize_failure_boundary_result(raw_data, case_id)
    if len(argv) >= 3:
        out_path = Path(argv[2])
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(sanitized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    else:
        print(json.dumps(sanitized, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
