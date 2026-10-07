#!/usr/bin/env python3
"""Compare human/GPT independent baseline with automated CoreNet Skill summary.

Performs deterministic, standards-based differential comparison across procedure
families, stages, frame boundaries, and coverage categories. Never applies severity
ranking. Evaluates upstream Protocol evidence health and pipeline eligibility
before semantic matching. Emits differential.json.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from canonical_hash import canonical_json_sha256


def get_relevant_protocols(human_baseline: dict[str, Any]) -> set[str]:
    """Derive relevant Protocol extractor keys from structured human baseline evidence."""
    relevant: set[str] = set()

    # 1. capture_scope.protocols_present
    scope = human_baseline.get("capture_scope") or {}
    for p in scope.get("protocols_present", []):
        p_up = p.upper()
        if "NGAP" in p_up:
            relevant.add("ngap")
        elif "NAS" in p_up or "5GMM" in p_up or "5GSM" in p_up:
            relevant.add("nas-5gs")
            if "N2" in [i.upper() for i in scope.get("interfaces", [])]:
                relevant.add("ngap")
        elif "PFCP" in p_up:
            relevant.add("pfcp")
        elif "GTP" in p_up:
            relevant.add("gtpu")
        elif "SBI" in p_up or "HTTP" in p_up:
            relevant.add("sbi-http2")

    # 2. supporting_evidence
    for ev in human_baseline.get("supporting_evidence", []):
        p_up = (ev.get("protocol") or "").upper()
        if "NGAP" in p_up:
            relevant.add("ngap")
        elif "NAS" in p_up or "5GMM" in p_up or "5GSM" in p_up:
            relevant.add("nas-5gs")
            relevant.add("ngap")
        elif "PFCP" in p_up:
            relevant.add("pfcp")
        elif "GTP" in p_up:
            relevant.add("gtpu")
        elif "SBI" in p_up or "HTTP" in p_up:
            relevant.add("sbi-http2")

    # 3. first_abnormal_boundary
    first_b = human_baseline.get("first_abnormal_boundary") or {}
    p_up = (first_b.get("protocol") or "").upper()
    if "NGAP" in p_up:
        relevant.add("ngap")
    elif "NAS" in p_up or "5GMM" in p_up or "5GSM" in p_up:
        relevant.add("nas-5gs")
        relevant.add("ngap")
    elif "PFCP" in p_up:
        relevant.add("pfcp")
    elif "GTP" in p_up:
        relevant.add("gtpu")
    elif "SBI" in p_up or "HTTP" in p_up:
        relevant.add("sbi-http2")

    return relevant


def evaluate_pipeline_evidence_health(
    human_baseline: dict[str, Any],
    skill_summary: dict[str, Any],
) -> tuple[str, list[str]]:
    """Determine whether enough relevant Protocol evidence was successfully processed.

    Returns:
        (eligibility_status, defect_reasons)
        eligibility_status: "ELIGIBLE" | "DEGRADED" | "INELIGIBLE" | "BLOCKED"
    """
    defects: list[str] = []
    selection_status = skill_summary.get("selection_status", "")

    # Check if execution was blocked
    if selection_status.startswith("BLOCKED") or skill_summary.get("blocked", False):
        return "BLOCKED", ["Capture execution pipeline was blocked"]

    proto_status = skill_summary.get("protocol_status") or {}
    relevant_protocols = get_relevant_protocols(human_baseline)
    scope = human_baseline.get("capture_scope") or {}
    protocols_present = [p.upper() for p in scope.get("protocols_present", [])]

    if not relevant_protocols:
        # If no protocols declared, check all executed protocol extractors
        for proto, status in proto_status.items():
            if status not in ("SUCCESS", "NOT_OBSERVED_IN_CAPTURE"):
                defects.append(f"{proto} extractor status is {status}")
    else:
        for proto in sorted(relevant_protocols):
            st = proto_status.get(proto)
            if not st:
                defects.append(f"Relevant protocol '{proto}' missing from pipeline execution status")
            elif st.startswith("ERROR_"):
                defects.append(f"Relevant protocol '{proto}' extractor failed with {st}")
            elif st == "MISSING_MESSAGE_TYPE":
                defects.append(f"Relevant protocol '{proto}' extractor failed to extract mandatory message type fields")
            elif st == "NOT_OBSERVED_IN_CAPTURE":
                is_claimed_present = any(proto.replace("-", "").upper() in p.replace("-", "").upper() for p in protocols_present)
                if is_claimed_present:
                    defects.append(f"Protocol '{proto}' was present in capture but extractor reported NOT_OBSERVED_IN_CAPTURE")

    # Domain instance absence check:
    # When domain_instances_count == 0 and relevant protocol extraction failed,
    # the evidence chain failed.
    domain_count = skill_summary.get("domain_instances_count", 0)
    if domain_count == 0 and defects:
        defects.append("Zero Domain instances formed due to upstream Protocol extraction defects")

    if defects:
        return "INELIGIBLE", defects

    return "ELIGIBLE", []


def compare_differential(
    human_baseline: dict[str, Any],
    skill_summary: dict[str, Any],
    human_baseline_sha256: str | None = None,
    upstream_intent: str | None = None,
) -> dict[str, Any]:
    """Compute differential comparison between human baseline and skill summary."""
    case_id = human_baseline["case_id"]

    if not human_baseline_sha256:
        human_baseline_sha256 = canonical_json_sha256(human_baseline)

    human_status = human_baseline.get("analysis_status", "UNKNOWN")
    human_first_boundary = human_baseline.get("first_abnormal_boundary")

    skill_status = skill_summary.get("selection_status", "UNKNOWN")
    skill_boundary = skill_summary.get("selected_boundary")

    # Extract human boundary fields
    human_boundary_repr: dict[str, Any] | None = None
    h_proc_family: str | None = None
    h_proc_stage: str | None = None
    h_proto: str | None = None
    h_msg: str | None = None
    h_frame: int | None = None

    if human_first_boundary:
        h_proc_family = human_first_boundary.get("procedure_family")
        h_proc_stage = human_first_boundary.get("procedure_stage")
        h_proto = human_first_boundary.get("protocol")
        h_msg = human_first_boundary.get("message_type")
        h_frame = human_first_boundary.get("frame_number")

    human_boundary_repr = {
        "analysis_status": human_status,
        "procedure_family": h_proc_family,
        "procedure_stage": h_proc_stage,
        "protocol": h_proto,
        "message_type": h_msg,
        "frame_number": h_frame,
    }

    # Extract skill boundary fields
    skill_boundary_repr: dict[str, Any] | None = None
    s_domain: str | None = None
    s_proc_family: str | None = None
    s_proc_stage: str | None = None
    s_proto: str | None = None
    s_msg: str | None = None
    s_frame: int | None = None

    if skill_boundary:
        s_domain = skill_boundary.get("selected_source_domain")
        s_proc_family = skill_boundary.get("selected_procedure_family")
        s_proc_stage = skill_boundary.get("selected_procedure_stage")
        s_proto = skill_boundary.get("boundary_protocol")
        s_msg = skill_boundary.get("boundary_message")
        s_frame = skill_boundary.get("boundary_frame")

    skill_boundary_repr = {
        "selection_status": skill_status,
        "source_domain": s_domain,
        "procedure_family": s_proc_family,
        "procedure_stage": s_proc_stage,
        "boundary_protocol": s_proto,
        "boundary_message": s_msg,
        "boundary_frame": s_frame,
    }

    # Compute frame delta
    frame_delta: int | None = None
    if h_frame is not None and s_frame is not None:
        frame_delta = abs(h_frame - s_frame)

    evidence_overlap = False
    if h_frame is not None and s_frame is not None:
        evidence_overlap = (h_frame == s_frame)
    elif human_first_boundary and human_first_boundary.get("observation_window") and s_frame is not None:
        win = human_first_boundary["observation_window"]
        evidence_overlap = win["start_frame"] <= s_frame <= win["end_frame"]

    notes: list[str] = []
    capture_limitations = list(human_baseline.get("limitations") or [])

    scope_assessment = human_baseline.get("scope_assessment") or {}
    in_scope = scope_assessment.get("in_corenet_scope", True)

    comparison_status = "NEEDS_ADJUDICATION"
    layer_attribution = "UNKNOWN"
    comparison_eligibility = "ELIGIBLE"
    recommended_next_action = "NO_CHANGE"
    baseline_supported = bool(human_baseline.get("baseline_supported", True))
    adjudication_required = False

    # Check synthetic override flags for taxonomy completeness
    if skill_summary.get("unsafe_correlation"):
        comparison_status = "UNSAFE_CORRELATION"
        layer_attribution = "CORRELATION"
        comparison_eligibility = "ELIGIBLE"
        recommended_next_action = "CORRECT_CORRELATION"
        notes.append("Synthetic unsafe correlation condition triggered.")
    elif skill_summary.get("correlation_gap"):
        comparison_status = "CORRELATION_GAP"
        layer_attribution = "CORRELATION"
        comparison_eligibility = "ELIGIBLE"
        recommended_next_action = "CORRECT_CORRELATION"
        notes.append("Synthetic correlation gap condition triggered.")
    elif skill_summary.get("acceptable_difference"):
        comparison_status = "ACCEPTABLE_DIFFERENCE"
        layer_attribution = "DOMAIN"
        comparison_eligibility = "ELIGIBLE"
        recommended_next_action = "NO_CHANGE"
        notes.append("Synthetic acceptable difference condition triggered.")

    # Comparator decision order:
    # 1. baseline support validity
    elif human_status == "HUMAN_BASELINE_UNSUPPORTED" or not baseline_supported:
        comparison_status = "HUMAN_BASELINE_UNSUPPORTED"
        layer_attribution = "BASELINE"
        comparison_eligibility = "INELIGIBLE"
        adjudication_required = True
        recommended_next_action = "ADJUDICATE_BASELINE"
        notes.append("Independent baseline is marked unsupported or failed validation.")

    # 2. capture sufficiency
    elif human_status in ("INSUFFICIENT_EVIDENCE", "CAPTURE_LIMITATION"):
        comparison_status = "CAPTURE_LIMITATION"
        layer_attribution = "CAPTURE"
        comparison_eligibility = "DEGRADED"
        recommended_next_action = "NO_CHANGE"
        notes.append("Capture does not contain sufficient packet evidence to form an authoritative boundary.")

    # 3. pipeline / Protocol evidence health
    else:
        eligibility, defects = evaluate_pipeline_evidence_health(human_baseline, skill_summary)
        comparison_eligibility = eligibility

        if eligibility in ("INELIGIBLE", "BLOCKED"):
            comparison_status = "PROTOCOL_COVERAGE_GAP"
            layer_attribution = "PROTOCOL"
            adjudication_required = False
            recommended_next_action = "ADD_PROTOCOL_COVERAGE"
            notes.extend(defects)

        else:
            # Evidence pipeline was successfully processed (ELIGIBLE / DEGRADED)
            # 4. Scope handling
            if human_status == "OUTSIDE_CURRENT_CORENET_SCOPE":
                if skill_status == "NO_ABNORMAL_BOUNDARY_OBSERVED":
                    comparison_status = "OUT_OF_SCOPE"
                    layer_attribution = "OUT_OF_SCOPE"
                    recommended_next_action = "EXPAND_FUTURE_SCOPE"
                    notes.append("Capture condition falls outside implemented CoreNet interfaces (e.g. N6 external path); pipeline safely remained conservative.")
                else:
                    comparison_status = "FALSE_POSITIVE"
                    layer_attribution = "DOMAIN"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_DOMAIN_MODEL"
                    notes.append("Pipeline emitted an abnormal boundary for an out-of-scope capture condition without direct evidence.")

            elif not in_scope or h_proc_family == "ngap-management":
                comparison_status = "DOMAIN_MODEL_GAP"
                layer_attribution = "DOMAIN"
                recommended_next_action = "EXPAND_FUTURE_SCOPE"
                notes.append("Abnormal boundary occurred in node-level procedure not currently owned by implemented procedure domains.")

            # 5. Boundary semantic comparison
            elif human_status == "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED":
                if skill_status == "NO_ABNORMAL_BOUNDARY_OBSERVED":
                    comparison_status = "EXACT_MATCH"
                    layer_attribution = "NONE"
                    recommended_next_action = "NO_CHANGE"
                    notes.append("Both human baseline and automated pipeline observed no abnormal boundary in healthy/recovered capture.")
                else:
                    comparison_status = "FALSE_POSITIVE"
                    layer_attribution = "DOMAIN"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_DOMAIN_MODEL"
                    notes.append(f"Automated pipeline selected abnormal boundary at frame {s_frame} on healthy/recovered capture.")

            elif human_status == "BOUNDARY_OBSERVED":
                if skill_status == "NO_ABNORMAL_BOUNDARY_OBSERVED":
                    comparison_status = "FALSE_NEGATIVE"
                    layer_attribution = "DOMAIN"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_DOMAIN_MODEL"
                    notes.append("Human baseline identified supported abnormal boundary inside scope, but pipeline observed no boundary.")

                elif skill_status == "FIRST_ABNORMAL_BOUNDARY_SELECTED":
                    proc_match = (h_proc_family is not None and s_proc_family is not None and h_proc_family == s_proc_family)
                    stage_match = (h_proc_stage is not None and s_proc_stage is not None and h_proc_stage == s_proc_stage)

                    if proc_match and h_frame == s_frame:
                        comparison_status = "EXACT_MATCH"
                        layer_attribution = "NONE"
                        recommended_next_action = "NO_CHANGE"
                        notes.append(f"Exact match on procedure family ({s_proc_family}) and boundary frame ({s_frame}).")
                    elif proc_match and frame_delta is not None and frame_delta <= 2:
                        comparison_status = "BOUNDARY_FRAME_DIFFERENCE"
                        layer_attribution = "DOMAIN"
                        adjudication_required = False
                        recommended_next_action = "NO_CHANGE"
                        notes.append(f"Same procedure family ({s_proc_family}), adjacent transaction frames (human frame {h_frame} vs skill frame {s_frame}, delta {frame_delta}).")
                    elif proc_match and not stage_match:
                        comparison_status = "PROCEDURE_MATCH_STAGE_DIFFERENCE"
                        layer_attribution = "DOMAIN"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_DOMAIN_MODEL"
                        notes.append(f"Same procedure family ({s_proc_family}), but differing stage attribution (human {h_proc_stage} vs skill {s_proc_stage}).")
                    elif not proc_match:
                        comparison_status = "ORCHESTRATION_GAP"
                        layer_attribution = "ORCHESTRATION"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_ORCHESTRATION"
                        notes.append(f"Procedure family mismatch: human identified {h_proc_family}, pipeline selected {s_proc_family}.")

                else:
                    comparison_status = "NEEDS_ADJUDICATION"
                    layer_attribution = "UNKNOWN"
                    adjudication_required = True
                    notes.append(f"Unexpected pipeline status: {skill_status}.")

    # Evaluate upstream intent match
    upstream_intent_match = "NOT_EVALUATED"
    if upstream_intent:
        if comparison_status in ("EXACT_MATCH", "BOUNDARY_FRAME_DIFFERENCE", "OUT_OF_SCOPE", "ACCEPTABLE_DIFFERENCE"):
            upstream_intent_match = "MATCH"
        elif comparison_status in ("PROCEDURE_MATCH_STAGE_DIFFERENCE", "DOMAIN_MODEL_GAP", "PROTOCOL_COVERAGE_GAP", "CORRELATION_GAP"):
            upstream_intent_match = "PARTIAL"
        else:
            upstream_intent_match = "MISMATCH"

    return {
        "case_id": case_id,
        "human_baseline_sha256": human_baseline_sha256,
        "comparison_status": comparison_status,
        "comparison_eligibility": comparison_eligibility,
        "layer_attribution": layer_attribution,
        "human_boundary": human_boundary_repr,
        "skill_boundary": skill_boundary_repr,
        "evidence_overlap": evidence_overlap,
        "frame_delta": frame_delta,
        "capture_limitations": capture_limitations,
        "baseline_supported": baseline_supported,
        "adjudication_required": adjudication_required,
        "upstream_intent_match": upstream_intent_match,
        "notes": notes,
        "recommended_next_action": recommended_next_action,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="Path to human-baseline.json")
    parser.add_argument("--skill-summary", type=Path, required=True, help="Path to skill-result-summary.json")
    parser.add_argument("--output", type=Path, required=True, help="Path to write differential.json")
    parser.add_argument("--intent", type=str, default=None, help="Optional upstream scenario intent")
    args = parser.parse_args(argv)

    human_baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    skill_summary = json.loads(args.skill_summary.read_text(encoding="utf-8"))
    baseline_sha256 = canonical_json_sha256(human_baseline)

    differential = compare_differential(human_baseline, skill_summary, baseline_sha256, args.intent)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(differential, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Differential comparison written to {args.output}. Status: {differential['comparison_status']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
