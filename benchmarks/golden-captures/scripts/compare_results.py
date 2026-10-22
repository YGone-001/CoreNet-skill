#!/usr/bin/env python3
"""Compare human/GPT independent baseline with automated CoreNet Skill summary.

Performs deterministic, standards-based differential comparison across procedure
families, stages, protocol and abnormal-event semantics, frame anchors and
coverage categories. An abnormal boundary is an exact match only when the
compared semantics agree as well as the evidence anchor; a frame equality or a
one- or two-frame delta never substitutes for a stage, protocol or abnormality
disagreement, and missing semantic detail is reported for adjudication instead of
being invented. Unowned procedure families are reported as Domain coverage, never
as an implemented Domain model failure. Never applies severity ranking.
Evaluates upstream Protocol evidence health and pipeline eligibility before
semantic matching. Emits differential.json.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from canonical_hash import canonical_json_sha256
from deviation_classification import summarize_classification, validate_classification_block
from sanitize_result import BENCHMARK_DOMAIN_KEYS


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

# Sanitizer placeholders that carry no identity. They must never be treated as a
# reported value, because matching a placeholder would invent semantic agreement.
ABSENT_IDENTITY_VALUES = frozenset({"", "unknown", "none", "null", "n/a"})

# Maximum frame separation still reported as a near-frame boundary difference.
NEAR_FRAME_DELTA = 2

# Bounded agreement that both sides observed no abnormal boundary, reached only
# when every relevant Domain deviation is classified as non-candidate evidence.
# This status is an agreement on the absence of a supported abnormal boundary
# within the capture and the implemented procedure scope; it never asserts
# SUCCESS, HEALTHY_NETWORK, END_TO_END_SUCCESS or SERVICE_PASSED, and it is
# never counted as EXACT_MATCH under the zero-deviation exact-match policy.
NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE = (
    "NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE"
)


def normalize_identity(value: Any) -> str | None:
    """Normalize a protocol, message or stage identity for comparison.

    Returns None when the identity is absent or is a sanitizer placeholder, so an
    unreported dimension is never silently equal to anything.
    """
    if value is None or isinstance(value, bool):
        return None
    text = str(value).strip()
    if not text or text.lower() in ABSENT_IDENTITY_VALUES:
        return None
    normalized = re.sub(r"[^A-Z0-9]", "", text.upper())
    return normalized or None


def compare_boundary_semantics(
    human_boundary: dict[str, Any] | None,
    skill_boundary: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare abnormal-boundary semantics independently of the frame anchor.

    Family is evaluated by the caller because a family disagreement is an
    Orchestration selection defect, not a boundary semantic difference. The
    remaining dimensions decide whether two boundaries describe the same
    abnormal event on the same protocol at the same procedure stage.
    """
    human_boundary = human_boundary or {}
    skill_boundary = skill_boundary or {}
    pairs = {
        "procedure_stage": (human_boundary.get("procedure_stage"), skill_boundary.get("selected_procedure_stage")),
        "protocol": (human_boundary.get("protocol"), skill_boundary.get("boundary_protocol")),
        "abnormal_event": (human_boundary.get("message_type"), skill_boundary.get("boundary_message")),
    }

    mismatched: list[str] = []
    mismatched_dimensions: list[str] = []
    unreported: list[str] = []
    matched: list[str] = []
    for dimension, (human_value, skill_value) in pairs.items():
        h_norm = normalize_identity(human_value)
        s_norm = normalize_identity(skill_value)
        if h_norm is None or s_norm is None:
            unreported.append(f"{dimension} (baseline={human_value if human_value is not None else 'absent'}, summary={skill_value if skill_value is not None else 'absent'})")
        elif h_norm == s_norm:
            matched.append(dimension)
        else:
            mismatched.append(f"{dimension} (baseline {human_value} vs Skill {skill_value})")
            mismatched_dimensions.append(dimension)

    return {
        "matched": matched,
        "mismatched": mismatched,
        "mismatched_dimensions": mismatched_dimensions,
        "unreported": unreported,
        "complete": not mismatched and not unreported,
    }



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
    (a relevant Domain executed and reconstructed nothing), NO_RELEVANT_DOMAIN (no
    report exists for a Domain the baseline makes relevant) or FAILED (a relevant
    Domain produced an unusable result). NOT_APPLICABLE records that no implemented
    Domain owns any observed procedure family. ``deviation_count`` is None when the
    summary carries no relevant per-Domain evidence, so an absent count is never
    read as zero.

    Only the relevant Domain keys are ever inspected. An unrelated Domain instance
    cannot satisfy a missing relevant Domain, because that would substitute
    evidence from a procedure the independent baseline never observed.
    """
    relevant = relevant_domain_keys(human_baseline)
    domain_status = skill_summary.get("domain_status")
    unowned = unowned_procedure_families(human_baseline)

    if not relevant and unowned:
        return {
            "state": "NOT_APPLICABLE",
            "instance_count": 0,
            "deviation_count": None,
            "relevant_domains": [],
            "reasons": [
                "No implemented Domain Skill owns the observed procedure "
                + ("family" if len(unowned) == 1 else "families")
                + ": " + ", ".join(unowned)
            ],
            "evidence_reported": False,
        }

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

    keys = sorted(relevant & set(domain_status))
    absent = sorted(relevant - set(domain_status))
    if absent:
        return {
            "state": "NO_RELEVANT_DOMAIN",
            "instance_count": 0,
            "deviation_count": None,
            "relevant_domains": sorted(relevant),
            "reasons": [
                "No execution evidence was reported for the relevant Domain(s) "
                + ", ".join(absent)
                + "; unrelated Domain instances were not substituted",
            ],
            "evidence_reported": True,
        }

    instances = 0
    deviations = 0
    executed = 0
    reasons: list[str] = []
    classification_blocks: list[Any] = []
    unclassified_domains: list[str] = []
    for key in keys:
        record = domain_status.get(key) or {}
        execution = record.get("execution_status")
        if execution == "EXECUTED":
            executed += 1
            instances += _domain_instance_count(record)
            deviations += int(record.get("deviation_count") or 0)
            if record.get("deviation_classification") is None:
                unclassified_domains.append(key)
            else:
                classification_blocks.append(record.get("deviation_classification"))
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
    # Evidence-type-aware classification of the relevant Domain deviations. A
    # summary that omits the classification contract is never assumed to report
    # zero candidate deviations: absent evidence stays explicitly unavailable.
    if unclassified_domains:
        classification: dict[str, Any] = {
            "available": False,
            "consistent": False,
            "reasons": [
                "no deviation classification was reported for relevant Domain(s) "
                + ", ".join(unclassified_domains)
            ],
        }
    elif not classification_blocks:
        classification = {
            "available": False,
            "consistent": False,
            "reasons": ["no executed relevant Domain reported deviation classification"],
        }
    else:
        classification = summarize_classification(classification_blocks)
        if classification.get("available") and classification.get("total_count") != deviations:
            classification["consistent"] = False
            classification["reasons"] = list(classification.get("reasons") or []) + [
                f"aggregated classification total {classification.get('total_count')} "
                f"does not match the reported deviation count {deviations}"
            ]

    return {
        "state": state,
        "instance_count": instances,
        "deviation_count": deviations,
        "relevant_domains": keys,
        "reasons": reasons,
        "evidence_reported": True,
        "classification": classification,
    }


def selection_consistency_problems(skill_summary: dict[str, Any]) -> list[str]:
    """Return every selection/candidate inconsistency for a no-boundary outcome.

    A bounded no-abnormal-boundary agreement must rest on a consistent record:
    the selection status must positively report the absence of an abnormal
    boundary, no selected boundary may be present, and the candidate counts
    reported at summary level and at Orchestration level must both be zero and
    must agree with each other. Contradictory candidate counts are recorded as
    discrepancies and never resolved by discarding actual candidates.
    """
    problems: list[str] = []
    status = skill_summary.get("selection_status")
    if status != "NO_ABNORMAL_BOUNDARY_OBSERVED":
        problems.append(
            f"selection_status {status!r} does not positively report an observed absence of an "
            "abnormal boundary"
        )
    if skill_summary.get("selected_boundary") is not None:
        problems.append("a selected boundary is present although selection_status reports no abnormal boundary")

    orch_status = skill_summary.get("orchestration_status")
    orch_candidates = orch_status.get("candidate_boundary_count") if isinstance(orch_status, dict) else None
    summary_candidates = skill_summary.get("candidate_boundaries_count")

    for label, value in (
        ("candidate_boundaries_count", summary_candidates),
        ("orchestration_status.candidate_boundary_count", orch_candidates),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            problems.append(f"{label} must be a non-negative integer")
        elif value < 0:
            problems.append(f"{label} must not be negative")
        elif value != 0:
            problems.append(f"{label} is {value}, so an unresolved candidate set cannot be read as agreement")

    if (
        isinstance(summary_candidates, int)
        and not isinstance(summary_candidates, bool)
        and isinstance(orch_candidates, int)
        and not isinstance(orch_candidates, bool)
        and summary_candidates != orch_candidates
    ):
        problems.append(
            f"candidate counts disagree (summary {summary_candidates} vs Orchestration {orch_candidates})"
        )
    return problems


def _nonneg_int(value: Any, label: str, problems: list[str]) -> int | None:
    """Read a bounded count field, recording every contract violation."""
    if isinstance(value, bool) or not isinstance(value, int):
        problems.append(f"{label} must be a non-negative integer")
        return None
    if value < 0:
        problems.append(f"{label} must not be negative")
        return None
    return value


def evaluate_orchestration_evidence(
    skill_summary: dict[str, Any],
    domain_evidence: dict[str, Any],
    relevant_domains: Any = frozenset(),
) -> dict[str, Any]:
    """Positively verify that Orchestration consumed the relevant Domain instances.

    States:

    - ``AVAILABLE``: consumption of every relevant Domain instance is
      positively established from structured evidence.
    - ``FAILED``: an actual failure to consume or to produce a diagnostic
      result is positively established.
    - ``UNVERIFIED``: the reported metadata is missing or internally
      inconsistent, so consumption cannot be established and no failing layer
      is proven. A legacy summary without the consumed-Domain map lands here
      and is never read as a successful consumption.
    - ``NOT_RUN``: Orchestration was skipped because no Domain analysis existed.
    - ``NOT_REPORTED``: no Orchestration execution evidence was reported at all.

    A diagnostic-group count is not consumption evidence, and an aggregate
    consumed-instance count does not identify the contributing Domain.
    """
    empty = {"consumption_verified": False, "consumed_domain_instance_counts": None}
    status = skill_summary.get("orchestration_status")
    if not isinstance(status, dict):
        return {
            "state": "NOT_REPORTED",
            "reasons": ["no Orchestration execution evidence was reported"],
            **empty,
        }
    execution = status.get("execution_status")
    if execution == "SKIPPED_NO_DOMAIN_OUTPUTS":
        return {
            "state": "NOT_RUN",
            "reasons": ["Orchestration did not run because no Domain analysis was produced"],
            **empty,
        }
    if execution != "EXECUTED":
        reason = status.get("first_stop_reason")
        return {
            "state": "FAILED",
            "reasons": [
                "Orchestration produced no diagnostic result ("
                + str(execution)
                + (f": {reason}" if reason else "")
                + ")"
            ],
            **empty,
        }

    # Execution metadata must be internally consistent before any positive
    # result can rest on it.
    problems: list[str] = []
    if status.get("output_present") is not True:
        problems.append("Orchestration reports execution_status EXECUTED but output_present is not true")
    groups = _nonneg_int(status.get("diagnostic_group_count"), "diagnostic_group_count", problems)
    aggregate = _nonneg_int(
        status.get("source_domain_instances_count"), "source_domain_instances_count", problems
    )
    _nonneg_int(status.get("candidate_boundary_count"), "candidate_boundary_count", problems)
    if problems:
        return {"state": "UNVERIFIED", "reasons": problems, **empty}

    if not groups:
        pending_deviations = int(domain_evidence.get("deviation_count") or 0)
        if int(domain_evidence.get("instance_count") or 0) > 0 and pending_deviations > 0:
            # The original established-failure condition: Domain instances that
            # reported deviations produced no diagnostic group at all.
            return {
                "state": "FAILED",
                "reasons": [
                    "Orchestration executed but formed no diagnostic group from Domain instances "
                    "that reported deviations"
                ],
                **empty,
            }
        return {
            "state": "UNVERIFIED",
            "reasons": [
                "Orchestration executed but reported no diagnostic group, so relevant Domain "
                "consumption cannot be positively verified"
            ],
            **empty,
        }

    raw_counts = status.get("consumed_domain_instance_counts")
    if raw_counts is None:
        return {
            "state": "UNVERIFIED",
            "reasons": [
                "Orchestration report carries no per-Domain consumed-instance map, so relevant "
                "Domain consumption cannot be positively verified"
            ],
            **empty,
        }
    if not isinstance(raw_counts, dict):
        return {
            "state": "UNVERIFIED",
            "reasons": ["consumed_domain_instance_counts is not an object"],
            **empty,
        }

    counts: dict[str, int] = {}
    for key, value in raw_counts.items():
        if key not in BENCHMARK_DOMAIN_KEYS:
            return {
                "state": "UNVERIFIED",
                "reasons": [f"consumed_domain_instance_counts contains unsupported Domain key {key!r}"],
                **empty,
            }
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return {
                "state": "UNVERIFIED",
                "reasons": [f"consumed_domain_instance_counts[{key!r}] must be a non-negative integer"],
                **empty,
            }
        counts[key] = value

    unmapped = _nonneg_int(
        status.get("consumed_unmapped_source_domain_instance_count", 0),
        "consumed_unmapped_source_domain_instance_count",
        problems,
    )
    if unmapped is None:
        return {"state": "UNVERIFIED", "reasons": problems, **empty}

    if sum(counts.values()) + unmapped != aggregate:
        return {
            "state": "UNVERIFIED",
            "reasons": [
                f"per-Domain consumed instance counts disagree with the reported aggregate ({aggregate})"
            ],
            "consumption_verified": False,
            "consumed_domain_instance_counts": counts,
        }

    produced: dict[str, int] = {}
    for key, record in (skill_summary.get("domain_status") or {}).items():
        if isinstance(record, dict):
            produced[key] = _domain_instance_count(record)
    for key, value in counts.items():
        if value > produced.get(key, 0):
            return {
                "state": "UNVERIFIED",
                "reasons": [
                    f"consumed {key} instance count {value} exceeds the produced instance count "
                    f"{produced.get(key, 0)}"
                ],
                "consumption_verified": False,
                "consumed_domain_instance_counts": counts,
            }

    relevant = set(relevant_domains or ())
    missing = sorted(key for key in relevant if counts.get(key, 0) <= 0)
    if missing:
        unproduced_missing = [key for key in missing if produced.get(key, 0) <= 0]
        consumed_missing = [key for key in missing if produced.get(key, 0) > 0]
        if consumed_missing:
            return {
                "state": "FAILED",
                "reasons": [
                    "Orchestration consumed no instance of relevant Domain(s) "
                    + ", ".join(consumed_missing)
                    + " that were reconstructed from capture evidence"
                ],
                "consumption_verified": False,
                "consumed_domain_instance_counts": counts,
            }
        return {
            "state": "UNVERIFIED",
            "reasons": [
                "relevant Domain consumption is not established for " + ", ".join(unproduced_missing)
            ],
            "consumption_verified": False,
            "consumed_domain_instance_counts": counts,
        }

    return {
        "state": "AVAILABLE",
        "reasons": [],
        "consumption_verified": True,
        "consumed_domain_instance_counts": counts,
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
    relevant_domains = relevant_domain_keys(human_baseline)
    orchestration = evaluate_orchestration_evidence(skill_summary, domain_evidence, relevant_domains)

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
    elif (
        protocol_defects
        or domain_state in ("FAILED", "NO_RELEVANT_INSTANCE", "NO_RELEVANT_DOMAIN")
        or orchestration_state == "FAILED"
    ):
        eligibility = "INELIGIBLE"
    else:
        eligibility = "ELIGIBLE"

    # Boundary semantics are only comparable when an implemented Domain owns the
    # observed procedure families and actually produced evidence to compare.
    semantic_comparison = "EVALUATED" if eligibility == "ELIGIBLE" and relevant_domains else "NOT_EVALUATED"
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

        elif not relevant_domains and (unowned_families or not in_scope):
            # No implemented Domain owns what the baseline observed, so this is a
            # coverage boundary of the repository, not a defect inside an
            # implemented Domain model.
            comparison_status = "DOMAIN_COVERAGE_GAP"
            layer_attribution = "DOMAIN_COVERAGE"
            recommended_next_action = "EXPAND_FUTURE_SCOPE"
            if unowned_families:
                notes.append(
                    "Observed procedure "
                    + ("family is" if len(unowned_families) == 1 else "families are")
                    + " not owned by any implemented Domain Skill: "
                    + ", ".join(unowned_families)
                    + ". This is unimplemented Domain coverage, not an implemented Domain reconstruction failure."
                )
            else:
                notes.append("Observed condition lies outside implemented procedure domains; no Domain model defect is recorded.")

        elif domain_evidence["state"] in ("FAILED", "NO_RELEVANT_INSTANCE", "NO_RELEVANT_DOMAIN"):
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
                    # Candidate deviations were emitted and no boundary was selected,
                    # so the Skill never asserted an abnormal conclusion. Declaring a
                    # confirmed false positive would turn an unresolved candidate set
                    # into proven causation without independent adjudication.
                    comparison_status = "NEEDS_ADJUDICATION"
                    layer_attribution = "MULTIPLE"
                    adjudication_required = True
                    recommended_next_action = "NO_CHANGE"
                    candidates = skill_summary.get("candidate_boundaries_count", 0)
                    notes.append(
                        f"{candidates} candidate boundar{'ies were' if candidates != 1 else 'y was'} "
                        f"emitted but no boundary was selected; Orchestration preserved the ambiguity ({skill_status})."
                    )
                    notes.append(
                        "A confirmed FALSE_POSITIVE requires independent adjudication that a candidate boundary is "
                        "unsupported by the packet evidence; candidate evidence here may be spurious, which is not yet proven."
                    )
                    if deviations:
                        notes.append(
                            f"Relevant Domain instance(s) reported {deviations} deviation(s) on a capture the independent "
                            "baseline records as healthy, so the candidate evidence needs Domain-layer review."
                        )
                elif skill_status in NO_BOUNDARY_STATUSES:
                    gate_problems = selection_consistency_problems(skill_summary)
                    if orchestration_evidence["state"] != "AVAILABLE":
                        gate_problems = list(orchestration_evidence.get("reasons") or []) + gate_problems
                    if gate_problems:
                        # Positive agreement must rest on positively verified
                        # Orchestration consumption of the relevant Domain
                        # instances. An absence of evidence never satisfies a
                        # positive acceptance condition, and a missing
                        # newly-introduced field is never read as consumption
                        # or as a proven Orchestration defect.
                        # Positive agreement must rest on positively verified
                        # Orchestration consumption of the relevant Domain
                        # instances and on internally consistent selection and
                        # candidate metadata. An absence of evidence never
                        # satisfies a positive acceptance condition, and a
                        # missing newly-introduced field is never read as
                        # consumption or as a proven Orchestration defect.
                        comparison_status = "NEEDS_ADJUDICATION"
                        layer_attribution = (
                            "ORCHESTRATION"
                            if orchestration_evidence["state"] == "FAILED"
                            else "UNKNOWN"
                        )
                        adjudication_required = True
                        recommended_next_action = (
                            "CORRECT_ORCHESTRATION"
                            if orchestration_evidence["state"] == "FAILED"
                            else "NO_CHANGE"
                        )
                        notes.extend(str(reason) for reason in gate_problems)
                        notes.append(
                            "A positive no-abnormal-boundary result requires positively verified Orchestration "
                            "consumption of the relevant Domain instances together with consistent selection and "
                            "candidate metadata; missing or inconsistent evidence is never read as consumption."
                        )
                    elif deviations is None:
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
                        # A nonzero Domain deviation count is not evidence of a
                        # confirmed abnormal boundary. The structured per-Domain
                        # classification decides whether every deviation is
                        # proven non-candidate evidence, or whether candidates or
                        # unknown types still require review.
                        classification = (domain_evidence.get("classification") or {})
                        cls_available = bool(classification.get("available"))
                        cls_consistent = bool(classification.get("consistent"))
                        candidate_count = int(classification.get("candidate_eligible_count") or 0)
                        unclassified_count = int(classification.get("unclassified_count") or 0)
                        limitation_count = int(classification.get("evidence_limitation_count") or 0)
                        supporting_count = int(classification.get("supporting_anomaly_count") or 0)

                        if not cls_available:
                            # Case E: legacy or partial summary. Missing
                            # classification metadata is never read as zero
                            # candidate deviations, so conservative compatibility
                            # behavior is preserved.
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "DOMAIN"
                            adjudication_required = True
                            recommended_next_action = "CORRECT_DOMAIN_MODEL"
                            # Case E output stays byte-identical to the legacy
                            # comparator so frozen differentials remain
                            # reproducible; the conservative NEEDS_ADJUDICATION
                            # already reports that the deviations are not proven
                            # non-candidate.
                            notes.append(
                                f"Pipeline selected no abnormal boundary, but the relevant Domain instance(s) reported {deviations} "
                                "deviation(s) on a capture the independent baseline records as healthy."
                            )
                        elif not cls_consistent:
                            # Case E: inconsistent category totals require review
                            # and are never reconciled silently.
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "DOMAIN"
                            adjudication_required = True
                            recommended_next_action = "CORRECT_DOMAIN_MODEL"
                            notes.append(
                                "The reported deviation classification is internally inconsistent with the "
                                "reported deviation count, so the deviation evidence cannot be accepted as "
                                "proven non-candidate evidence."
                            )
                            notes.extend(
                                str(reason) for reason in (classification.get("reasons") or [])
                            )
                        elif unclassified_count > 0:
                            # Case D: an unknown deviation type is never treated as
                            # benign and never folded into the non-candidate set.
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "UNKNOWN"
                            adjudication_required = True
                            recommended_next_action = "CORRECT_DOMAIN_MODEL"
                            notes.append(
                                f"{unclassified_count} unclassified deviation(s) remain in the relevant Domain "
                                f"evidence (candidate-eligible {candidate_count}, evidence limitations "
                                f"{limitation_count}, supporting anomalies {supporting_count}). An unknown "
                                "deviation type is never treated as non-candidate evidence by default, so "
                                "this case requires review."
                            )
                        elif candidate_count > 0:
                            # Case C: candidate-eligible deviations exist but
                            # Orchestration selected no boundary. Retain an
                            # evidence-preserving discrepancy instead of declaring
                            # a confirmed false positive without its required
                            # evidence.
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "DOMAIN"
                            adjudication_required = True
                            recommended_next_action = "CORRECT_DOMAIN_MODEL"
                            notes.append(
                                f"Pipeline selected no abnormal boundary, but the relevant Domain instance(s) "
                                f"reported {deviations} deviation(s), of which {candidate_count} are "
                                "candidate-eligible and were not selected as a boundary. Candidate eligibility "
                                "does not imply selection, and no confirmed FALSE_POSITIVE is reported without "
                                "its required independent evidence."
                            )
                            notes.append(
                                f"Non-candidate evidence retained: {limitation_count} evidence limitation(s) "
                                f"and {supporting_count} supporting anomal(y/ies)."
                            )
                        else:
                            # Case B: every relevant deviation is classified and
                            # proven non-candidate. This is a bounded agreement on
                            # the absence of an observed abnormal boundary, never a
                            # claim that the network or service succeeded.
                            comparison_status = (
                                NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE
                            )
                            layer_attribution = "NONE"
                            adjudication_required = False
                            recommended_next_action = "NO_CHANGE"
                            notes.append(
                                f"Both the independent baseline and the automated pipeline observed no "
                                f"abnormal boundary within the capture and the implemented procedure scope; "
                                f"all {deviations} relevant Domain deviation(s) are classified non-candidate "
                                f"evidence ({limitation_count} evidence limitation(s), {supporting_count} "
                                "supporting anomal(y/ies)) and are retained as evidence."
                            )
                            notes.append(
                                "This bounded agreement is limited to the absence of a supported abnormal "
                                "boundary; it is not an assertion of SUCCESS, HEALTHY_NETWORK, "
                                "END_TO_END_SUCCESS or SERVICE_PASSED."
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
                    h_family = normalize_identity(h_proc_family)
                    proc_match = h_family is not None and h_family == normalize_identity(s_proc_family)

                    if not proc_match:
                        comparison_status = "ORCHESTRATION_GAP"
                        layer_attribution = "ORCHESTRATION"
                        adjudication_required = True
                        recommended_next_action = "CORRECT_ORCHESTRATION"
                        notes.append(f"Procedure family mismatch: human identified {h_proc_family}, pipeline selected {s_proc_family}.")
                    else:
                        semantics = compare_boundary_semantics(human_first_boundary, skill_boundary)

                        if semantics["mismatched"]:
                            # A shared frame anchor or an adjacent frame can never
                            # repair a stage, protocol or abnormal-event disagreement.
                            if "procedure_stage" in semantics["mismatched_dimensions"]:
                                comparison_status = "PROCEDURE_MATCH_STAGE_DIFFERENCE"
                            else:
                                comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "DOMAIN"
                            adjudication_required = True
                            recommended_next_action = "CORRECT_DOMAIN_MODEL"
                            notes.append(
                                f"Same procedure family ({s_proc_family}), but the abnormal boundary semantics disagree: "
                                + "; ".join(semantics["mismatched"])
                                + ". Frame agreement is not evidence of an exact boundary match."
                            )
                        elif semantics["unreported"]:
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "UNKNOWN"
                            adjudication_required = True
                            notes.append(
                                "Boundary semantics are not fully reported on at least one side: "
                                + "; ".join(semantics["unreported"])
                                + ". Exact equivalence cannot be established without inventing detail, so no match is assumed."
                            )
                        elif h_frame is not None and s_frame is not None:
                            # Compatible abnormal-boundary semantics; adjudicate the anchor.
                            if h_frame == s_frame:
                                comparison_status = "EXACT_MATCH"
                                layer_attribution = "NONE"
                                recommended_next_action = "NO_CHANGE"
                                notes.append(
                                    f"Exact match on procedure family ({s_proc_family}), stage, protocol, abnormal event "
                                    f"and evidence anchor at frame {s_frame}; matched dimensions: "
                                    + ", ".join(["procedure_family"] + semantics["matched"])
                                    + "."
                                )
                            elif frame_delta is not None and frame_delta <= NEAR_FRAME_DELTA:
                                comparison_status = "BOUNDARY_FRAME_DIFFERENCE"
                                layer_attribution = "DOMAIN"
                                recommended_next_action = "NO_CHANGE"
                                notes.append(
                                    f"Compatible boundary semantics ({s_proc_family}, {s_proto}, {s_msg}) on adjacent "
                                    f"transaction frames (human frame {h_frame} vs skill frame {s_frame}, delta {frame_delta})."
                                )
                            else:
                                comparison_status = "NEEDS_ADJUDICATION"
                                layer_attribution = "DOMAIN"
                                adjudication_required = True
                                recommended_next_action = "CORRECT_DOMAIN_MODEL"
                                notes.append(
                                    f"Boundary semantics agree but the exact anchors are not adjacent (human frame {h_frame} "
                                    f"vs skill frame {s_frame}, delta {frame_delta}); the first abnormal boundary needs adjudication."
                                )
                        elif human_first_boundary.get("observation_window") and s_frame is not None:
                            win = human_first_boundary["observation_window"]
                            if win["start_frame"] <= s_frame <= win["end_frame"]:
                                # The baseline holds only a window, so no exact frame
                                # anchor exists to declare an exact match against.
                                comparison_status = "BOUNDARY_FRAME_DIFFERENCE"
                                layer_attribution = "DOMAIN"
                                recommended_next_action = "NO_CHANGE"
                                notes.append(
                                    f"Boundary semantics agree and the Skill frame {s_frame} falls inside the derived "
                                    f"observation window {win['start_frame']}-{win['end_frame']}; the baseline records no exact authoritative frame."
                                )
                            else:
                                comparison_status = "NEEDS_ADJUDICATION"
                                layer_attribution = "DOMAIN"
                                adjudication_required = True
                                recommended_next_action = "CORRECT_DOMAIN_MODEL"
                                notes.append(
                                    f"Boundary semantics agree but Skill frame {s_frame} lies outside the derived "
                                    f"observation window {win['start_frame']}-{win['end_frame']}."
                                )
                        else:
                            comparison_status = "NEEDS_ADJUDICATION"
                            layer_attribution = "UNKNOWN"
                            adjudication_required = True
                            notes.append("Neither the baseline nor the Skill summary provides a usable evidence anchor for the boundary.")

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

            elif human_status == "MULTIPLE_POSSIBLE_BOUNDARIES":
                comparison_status = "NEEDS_ADJUDICATION"
                layer_attribution = "MULTIPLE"
                adjudication_required = True
                notes.append(
                    "The independent baseline records several possible first boundaries and carries no candidate set the "
                    f"Skill output can be matched against (pipeline status {skill_status}); boundary selection needs adjudication."
                )

    # Evaluate upstream intent match. Upstream scenario labels are secondary
    # metadata: they are never packet evidence, and an insufficient-evidence
    # baseline can neither confirm nor refute them.
    upstream_intent_match = "NOT_EVALUATED"
    if upstream_intent:
        if comparison_status in ("EXACT_MATCH", "BOUNDARY_FRAME_DIFFERENCE", "OUT_OF_SCOPE", "ACCEPTABLE_DIFFERENCE"):
            upstream_intent_match = "MATCH"
        elif comparison_status in (
            "PROCEDURE_MATCH_STAGE_DIFFERENCE",
            "DOMAIN_MODEL_GAP",
            "DOMAIN_COVERAGE_GAP",
            "PROTOCOL_COVERAGE_GAP",
            "CORRELATION_GAP",
            NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE,
        ):
            upstream_intent_match = "PARTIAL"
            if comparison_status == NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE:
                notes.append(
                    "Upstream scenario intent remains secondary metadata and is never independent proof of "
                    "packet-level success; the bounded no-boundary agreement only reports the absence of a "
                    "supported abnormal boundary in the captured scope."
                )
        elif comparison_status == "CAPTURE_LIMITATION":
            notes.append(
                "Upstream scenario intent is retained as secondary metadata only; the captured packets are too incomplete "
                "to confirm or refute it, so the intent match is not evaluated."
            )
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
