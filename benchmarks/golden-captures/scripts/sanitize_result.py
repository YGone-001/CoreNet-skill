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

    sanitized_boundary = None
    if selected_boundary_raw:
        anchor = selected_boundary_raw.get("boundary_anchor") or {}
        sanitized_boundary = {
            "selected_source_domain": selected_boundary_raw.get("source_domain") or "UNKNOWN",
            "selected_procedure_family": selected_boundary_raw.get("procedure_family") or "UNKNOWN",
            "selected_procedure_stage": selected_boundary_raw.get("procedure_stage"),
            "deviation_type": selected_boundary_raw.get("deviation_type") or "UNKNOWN",
            "boundary_protocol": anchor.get("protocol") or "UNKNOWN",
            "boundary_message": anchor.get("message_type") or "UNKNOWN",
            "boundary_frame": int(anchor.get("frame_number")) if anchor.get("frame_number") is not None else 1,
            "boundary_timestamp": anchor.get("timestamp") or "",
            "evidence_level": selected_boundary_raw.get("evidence_level") or "OBSERVED",
        }

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
