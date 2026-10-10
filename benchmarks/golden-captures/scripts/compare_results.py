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


# Domain family names used by the independent baselines, mapped to the
# per-Domain execution evidence keys reported by the pipeline.
DOMAIN_KEY_BY_FAMILY = {
    "5gc-registration-mobility": "registration",
    "5gc-pdu-session": "pdu_session",
    "5gc-handover-mobility": "handover_mobility",
}

# Protocol extraction statuses that prove healthy extraction. A bounded Skill
# that intentionally owns no semantics for an observed procedure, or that meets a
# security-protected payload it cannot decode, is not an extractor failure; only a
# supported case that failed to expose message identity is.
HEALTHY_PROTOCOL_STATUSES = frozenset({
    "SUCCESS",
    "SUCCESS_WITH_UNSUPPORTED_SEMANTICS",
    "SUCCESS_WITH_PROTECTED_PAYLOAD",
    "NOT_OBSERVED_IN_CAPTURE",
})

# Orchestration selection statuses that assert an abnormal boundary, and those
# that explicitly decline to assert one.
BOUNDARY_SELECTED_STATUSES = frozenset({"SELECTED", "FIRST_ABNORMAL_BOUNDARY_SELECTED"})
BOUNDARY_UNRESOLVED_STATUSES = frozenset({"AMBIGUOUS_FIRST_BOUNDARY", "INSUFFICIENT_COMPARABLE_EVIDENCE"})
NO_BOUNDARY_STATUSES = frozenset({"NO_ABNORMAL_BOUNDARY_OBSERVED", "NO_DOMAIN_INPUTS"})


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
    """Evaluate the relevant Protocol extraction layer only.

    Returns:
        (eligibility_status, defect_reasons)
        eligibility_status: "ELIGIBLE" | "INELIGIBLE" | "BLOCKED"

    Higher evidence layers (Domain reconstruction, Orchestration availability,
    semantic comparison) are evaluated independently by
    ``evaluate_evidence_layers``; success here never substitutes for missing
    evidence above this layer.
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
            if status not in HEALTHY_PROTOCOL_STATUSES:
                defects.append(f"{proto} extractor status is {status}")
    else:
        for proto in sorted(relevant_protocols):
            st = proto_status.get(proto)
            if not st:
                defects.append(f"Relevant protocol '{proto}' missing from pipeline execution status")
            elif st.startswith("ERROR_"):
                defects.append(f"Relevant protocol '{proto}' extractor failed with {st}")
            elif st == "MISSING_MESSAGE_TYPE":
                defects.append(
                    f"Relevant protocol '{proto}' exposed no message identity for a semantic case it reports as supported"
                )
            elif st == "NOT_OBSERVED_IN_CAPTURE":
                is_claimed_present = any(proto.replace("-", "").upper() in p.replace("-", "").upper() for p in protocols_present)
                if is_claimed_present:
                    defects.append(f"Protocol '{proto}' was present in capture but extractor reported NOT_OBSERVED_IN_CAPTURE")

    if defects:
        return "INELIGIBLE", defects

    return "ELIGIBLE", []


def relevant_domain_keys(human_baseline: dict[str, Any]) -> set[str]:
    """Derive the Domain evidence keys the independent baseline makes relevant."""
    keys: set[str] = set()
    for observation in human_baseline.get("procedure_observations") or []:
        key = DOMAIN_KEY_BY_FAMILY.get(observation.get("procedure_family"))
        if key:
            keys.add(key)
    boundary = human_baseline.get("first_abnormal_boundary") or {}
    key = DOMAIN_KEY_BY_FAMILY.get(boundary.get("procedure_family"))
    if key:
        keys.add(key)
    return keys


def observed_procedure_families(human_baseline: dict[str, Any]) -> set[str]:
    """Every procedure family the independent baseline reports as observed."""
    families = {
        str(observation.get("procedure_family"))
        for observation in human_baseline.get("procedure_observations") or []
        if observation.get("procedure_family")
    }
    boundary = human_baseline.get("first_abnormal_boundary") or {}
    if boundary.get("procedure_family"):
        families.add(str(boundary["procedure_family"]))
    return families


def unowned_procedure_families(human_baseline: dict[str, Any]) -> list[str]:
    """Observed procedure families no implemented Domain Skill owns."""
    return sorted(family for family in observed_procedure_families(human_baseline) if family not in DOMAIN_KEY_BY_FAMILY)


def _domain_instance_count(record: dict[str, Any]) -> int:
    return (
        int(record.get("instance_count") or 0)
        + int(record.get("handover_attempt_count") or 0)
        + int(record.get("path_switch_attempt_count") or 0)
    )


def evaluate_domain_evidence(
    human_baseline: dict[str, Any],
    skill_summary: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate whether a relevant Domain procedure instance was reconstructed.

    ``state`` is one of PRESENT (a relevant instance exists), NO_RELEVANT_INSTANCE
    (a relevant Domain executed and reconstructed nothing) or FAILED (no relevant
    Domain produced an analysis). ``deviation_count`` is None when the summary
    carries no per-Domain evidence, so an absent count is never read as zero.
    """
    relevant = relevant_domain_keys(human_baseline)
    domain_status = skill_summary.get("domain_status")
    if not isinstance(domain_status, dict) or not domain_status:
        count = int(skill_summary.get("domain_instances_count") or 0)
        return {
            "state": "PRESENT" if count > 0 else "NO_RELEVANT_INSTANCE",
            "instance_count": count,
            "deviation_count": None,
            "relevant_domains": sorted(relevant),
            "reasons": [] if count > 0 else ["No per-Domain execution evidence was reported"],
            "evidence_reported": False,
        }

    keys = sorted(relevant & set(domain_status)) or sorted(domain_status)
    instances = 0
    deviations = 0
    executed = 0
    reasons: list[str] = []
    for key in keys:
        record = domain_status.get(key) or {}
        execution = record.get("execution_status")
        if execution == "EXECUTED":
            executed += 1
            instances += _domain_instance_count(record)
            deviations += int(record.get("deviation_count") or 0)
        elif execution in ("SKIPPED_NO_INPUTS", "NOT_RUN"):
            reason = record.get("first_stop_reason")
            reasons.append(f"{key} Domain did not execute ({execution}" + (f": {reason}" if reason else "") + ")")
        else:
            reason = record.get("first_stop_reason")
            reasons.append(f"{key} Domain produced no analysis ({execution}" + (f": {reason}" if reason else "") + ")")

    if instances > 0:
        state = "PRESENT"
    elif executed:
        state = "NO_RELEVANT_INSTANCE"
        reasons.append("Relevant Domain Skill executed but reconstructed no procedure instance")
    else:
        state = "FAILED"
    return {
        "state": state,
        "instance_count": instances,
        "deviation_count": deviations,
        "relevant_domains": keys,
        "reasons": reasons,
        "evidence_reported": True,
    }


def evaluate_orchestration_evidence(
    skill_summary: dict[str, Any],
    domain_evidence: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate whether Orchestration consumed the reconstructed Domain evidence."""
    status = skill_summary.get("orchestration_status")
    if not isinstance(status, dict):
        return {"state": "NOT_REPORTED", "reasons": []}
    execution = status.get("execution_status")
    if execution == "EXECUTED":
        groups = int(status.get("diagnostic_group_count") or 0)
        consumed = int(status.get("source_domain_instances_count") or 0)
        pending_deviations = int(domain_evidence.get("deviation_count") or 0)
        if domain_evidence["instance_count"] > 0 and pending_deviations > 0 and groups == 0 and consumed == 0:
            return {
                "state": "FAILED",
                "reasons": [
                    "Orchestration executed but formed no diagnostic group from Domain instances that reported deviations"
                ],
            }
        return {"state": "AVAILABLE", "reasons": []}
    if execution == "SKIPPED_NO_DOMAIN_OUTPUTS":
        return {"state": "NOT_RUN", "reasons": ["Orchestration did not run because no Domain analysis was produced"]}
    reason = status.get("first_stop_reason")
    return {
        "state": "FAILED",
        "reasons": ["Orchestration produced no diagnostic result (" + str(execution) + (f": {reason}" if reason else "") + ")"],
    }


def evaluate_evidence_layers(
    human_baseline: dict[str, Any],
    skill_summary: dict[str, Any],
) -> dict[str, Any]:
    """Evaluate the benchmark evidence layers independently, in pipeline order.

    Layer order: baseline support, capture sufficiency, relevant Protocol
    extraction, relevant Domain reconstruction, Orchestration availability,
    semantic boundary comparison. Success at one layer never substitutes for
    missing evidence at the next, and the lowest layer that accounts for a
    discrepancy owns the attribution.
    """
    protocol_eligibility, protocol_defects = evaluate_pipeline_evidence_health(human_baseline, skill_summary)
    domain_evidence = evaluate_domain_evidence(human_baseline, skill_summary)
    orchestration = evaluate_orchestration_evidence(skill_summary, domain_evidence)
    relevant_domains = relevant_domain_keys(human_baseline)

    if protocol_eligibility == "BLOCKED" or protocol_defects:
        domain_state = "NOT_EVALUATED"
        orchestration_state = "NOT_EVALUATED"
    elif not relevant_domains:
        # No implemented Domain owns the procedure families this baseline observes,
        # so Domain reconstruction is not an applicable layer for this case.
        domain_state = "NOT_APPLICABLE"
        orchestration_state = "NOT_APPLICABLE"
    else:
        domain_state = domain_evidence["state"]
        orchestration_state = orchestration["state"]

    if protocol_defects and domain_evidence["instance_count"] == 0:
        protocol_defects = protocol_defects + [
            "Zero Domain instances were reconstructed; the lowest responsible layer is Protocol extraction"
        ]

    if protocol_eligibility == "BLOCKED":
        eligibility = "BLOCKED"
    elif protocol_defects or domain_state in ("FAILED", "NO_RELEVANT_INSTANCE") or orchestration_state == "FAILED":
        eligibility = "INELIGIBLE"
    else:
        eligibility = "ELIGIBLE"

    semantic_comparison = "EVALUATED" if eligibility == "ELIGIBLE" else "NOT_EVALUATED"
    layers = {
        "baseline_support": "SUPPORTED" if human_baseline.get("baseline_supported", True) else "UNSUPPORTED",
        "capture_sufficiency": (
            "INSUFFICIENT"
            if human_baseline.get("analysis_status") in ("INSUFFICIENT_EVIDENCE", "CAPTURE_LIMITATION")
            else "SUFFICIENT"
        ),
        "protocol_extraction": "BLOCKED" if protocol_eligibility == "BLOCKED" else ("DEFECT" if protocol_defects else "HEALTHY"),
        "domain_reconstruction": domain_state,
        "orchestration_availability": orchestration_state,
        "semantic_comparison": semantic_comparison,
    }
    return {
        "eligibility": eligibility,
        "layers": layers,
        "protocol_defects": protocol_defects,
        "domain_evidence": domain_evidence,
        "orchestration_evidence": orchestration,
    }


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
    evidence_layers: dict[str, str] | None = None

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

    # 3. layered evidence evaluation: Protocol -> Domain -> Orchestration -> semantics
    else:
        evidence = evaluate_evidence_layers(human_baseline, skill_summary)
        comparison_eligibility = evidence["eligibility"]
        evidence_layers = evidence["layers"]
        domain_evidence = evidence["domain_evidence"]
        orchestration_evidence = evidence["orchestration_evidence"]
        protocol_defects = evidence["protocol_defects"]
        deviations = domain_evidence["deviation_count"]
        relevant_domains = relevant_domain_keys(human_baseline)
        unowned_families = unowned_procedure_families(human_baseline)

        if protocol_defects or comparison_eligibility == "BLOCKED":
            # Lowest responsible layer: relevant Protocol extraction.
            comparison_status = "PROTOCOL_COVERAGE_GAP"
            layer_attribution = "PROTOCOL"
            adjudication_required = False
            recommended_next_action = "ADD_PROTOCOL_COVERAGE"
            notes.extend(protocol_defects)

        # 4. Scope and Domain ownership handling. A capture whose observed
        # procedures are owned by no implemented Domain cannot be judged by
        # Domain reconstruction evidence, so ownership is settled first.
        elif human_status == "OUTSIDE_CURRENT_CORENET_SCOPE":
            if skill_status in NO_BOUNDARY_STATUSES:
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

        elif not in_scope or h_proc_family == "ngap-management" or (not relevant_domains and unowned_families):
            comparison_status = "DOMAIN_MODEL_GAP"
            layer_attribution = "DOMAIN"
            recommended_next_action = "EXPAND_FUTURE_SCOPE"
            if unowned_families:
                notes.append(
                    "Observed procedure "
                    + ("family is" if len(unowned_families) == 1 else "families are")
                    + " not owned by any implemented Domain Skill: "
                    + ", ".join(unowned_families)
                    + "."
                )
            else:
                notes.append("Abnormal boundary occurred in node-level procedure not currently owned by implemented procedure domains.")

        elif domain_evidence["state"] in ("FAILED", "NO_RELEVANT_INSTANCE"):
            # Protocol evidence succeeded, so a missing procedure reconstruction is
            # a Domain-layer gap and can never be reported as a healthy match.
            comparison_status = "DOMAIN_MODEL_GAP"
            layer_attribution = "DOMAIN"
            adjudication_required = True
            recommended_next_action = "CORRECT_DOMAIN_MODEL"
            notes.extend(domain_evidence["reasons"])
            notes.append(
                "Relevant Protocol extraction succeeded, so the absent procedure reconstruction is attributed to the Domain layer."
            )

        elif orchestration_evidence["state"] == "FAILED":
            comparison_status = "ORCHESTRATION_GAP"
            layer_attribution = "ORCHESTRATION"
            adjudication_required = True
            recommended_next_action = "CORRECT_ORCHESTRATION"
            notes.extend(orchestration_evidence["reasons"])

        else:
            # Evidence pipeline was successfully processed (ELIGIBLE / DEGRADED)
            # 5. Boundary semantic comparison
            if human_status == "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED":
                if skill_status in BOUNDARY_SELECTED_STATUSES:
                    comparison_status = "FALSE_POSITIVE"
                    layer_attribution = "DOMAIN"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_DOMAIN_MODEL"
                    notes.append(f"Automated pipeline selected abnormal boundary at frame {s_frame} on healthy/recovered capture.")
                elif skill_status in BOUNDARY_UNRESOLVED_STATUSES:
                    comparison_status = "FALSE_POSITIVE"
                    layer_attribution = "DOMAIN"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_DOMAIN_MODEL"
                    notes.append(
                        f"Automated pipeline could not resolve a single first boundary ({skill_status}) on a healthy/recovered capture "
                        f"with {skill_summary.get('candidate_boundaries_count', 0)} candidate boundary(ies)."
                    )
                elif skill_status in NO_BOUNDARY_STATUSES:
                    if deviations is None:
                        comparison_status = "EXACT_MATCH"
                        layer_attribution = "NONE"
                        recommended_next_action = "NO_CHANGE"
                        notes.append(
                            "Both human baseline and automated pipeline observed no abnormal boundary; "
                            "the summary carries no per-Domain deviation evidence."
                        )
                    elif deviations == 0:
                        comparison_status = "EXACT_MATCH"
                        layer_attribution = "NONE"
                        recommended_next_action = "NO_CHANGE"
                        notes.append(
                            f"Both human baseline and automated pipeline observed no abnormal boundary on a healthy/recovered capture; "
                            f"{domain_evidence['instance_count']} relevant Domain instance(s) were reconstructed with zero deviations."
                        )
                    else:
                        comparison_status = "NEEDS_ADJUDICATION"
                        layer_attribution = "DOMAIN"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_DOMAIN_MODEL"
                        notes.append(
                            f"Pipeline selected no abnormal boundary, but the relevant Domain instance(s) reported {deviations} "
                            "deviation(s) on a capture the independent baseline records as healthy."
                        )
                else:
                    comparison_status = "NEEDS_ADJUDICATION"
                    layer_attribution = "UNKNOWN"
                    adjudication_required = True
                    notes.append(f"Unexpected pipeline status on healthy/recovered capture: {skill_status}.")

            elif human_status == "BOUNDARY_OBSERVED":
                if skill_status in NO_BOUNDARY_STATUSES:
                    if deviations:
                        comparison_status = "ORCHESTRATION_GAP"
                        layer_attribution = "ORCHESTRATION"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_ORCHESTRATION"
                        notes.append(
                            f"Relevant Domain instance reported {deviations} deviation(s) but Orchestration selected no boundary; "
                            "human baseline identified a supported abnormal boundary inside scope."
                        )
                    else:
                        comparison_status = "FALSE_NEGATIVE"
                        layer_attribution = "DOMAIN"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_DOMAIN_MODEL"
                        notes.append(
                            "Human baseline identified supported abnormal boundary inside scope; a relevant Domain instance was "
                            "reconstructed but reported no deviation supporting that boundary."
                        )

                elif skill_status in BOUNDARY_SELECTED_STATUSES:
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

                elif skill_status in BOUNDARY_UNRESOLVED_STATUSES:
                    comparison_status = "NEEDS_ADJUDICATION"
                    layer_attribution = "ORCHESTRATION"
                    adjudication_required = True
                    recommended_next_action = "CORRECT_ORCHESTRATION"
                    notes.append(
                        f"Human baseline identified a supported boundary, but Orchestration reported {skill_status} "
                        f"across {skill_summary.get('candidate_boundaries_count', 0)} candidate boundary(ies)."
                    )

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
        "evidence_layers": evidence_layers,
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
