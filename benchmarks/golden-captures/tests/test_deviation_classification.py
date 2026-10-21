#!/usr/bin/env python3
"""Evidence-type-aware deviation classification tests for the Golden Capture benchmark.

Covers the R-2 correction contract: candidate-eligible deviations, evidence
limitations, supporting anomalies and unclassified deviations must be
distinguished in sanitized per-Domain evidence and consumed by the comparator,
so a nonzero deviation count alone never forces Domain adjudication and a
non-candidate deviation never silently asserts service success.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from canonical_hash import canonical_json_sha256  # noqa: E402
from compare_results import compare_differential  # noqa: E402
from deviation_classification import (  # noqa: E402
    CATEGORIES,
    CATEGORY_CANDIDATE_ELIGIBLE,
    CATEGORY_EVIDENCE_LIMITATION,
    CATEGORY_SUPPORTING_ANOMALY,
    CATEGORY_UNCLASSIFIED,
    MISSING_TYPE_KEY,
    ClassificationError,
    build_classification_block,
    classify_deviation_type,
    summarize_classification,
    validate_classification_block,
)
from run_capture_pipeline import record_domain_executed  # noqa: E402
from summarize_benchmark import calculate_metrics  # noqa: E402

AGREEMENT_STATUS = "NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE"

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def healthy_baseline(case_id: str = "cls-test", families: list[str] | None = None) -> dict:
    observations = [
        {
            "procedure_family": family,
            "procedure_stage": "registration",
            "outcome": "COMPLETE",
            "first_frame": 9,
            "last_frame": 15,
            "evidence_level": "OBSERVED",
        }
        for family in (families or ["5gc-registration-mobility"])
    ]
    return {
        "case_id": case_id,
        "capture_sha256": "c" * 64,
        "analysis_status": "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED",
        "capture_scope": {
            "interfaces": ["N1", "N2"],
            "protocols_present": ["NGAP", "NAS-5GS"],
        },
        "procedure_observations": observations,
        "first_abnormal_boundary": None,
        "supporting_evidence": [],
        "limitations": [],
        "scope_assessment": {
            "in_corenet_scope": True,
            "interfaces_in_scope": ["N1", "N2"],
            "interfaces_out_of_scope": [],
            "reason": "N1/N2",
        },
        "baseline_confidence": "HIGH",
    }


def abnormal_baseline(case_id: str = "cls-abnormal") -> dict:
    baseline = healthy_baseline(case_id)
    baseline["analysis_status"] = "BOUNDARY_OBSERVED"
    baseline["first_abnormal_boundary"] = {
        "procedure_family": "5gc-registration-mobility",
        "procedure_stage": "security",
        "protocol": "NAS-5GS",
        "message_type": "Authentication failure",
        "frame_number": 11,
        "timestamp": "2026-07-29T00:00:00Z",
        "evidence_level": "OBSERVED",
        "reason": "Authentication failure observed",
    }
    return baseline


def domain_record(
    deviation_types: list,
    instance_count: int = 1,
    execution_status: str = "EXECUTED",
    with_classification: bool = True,
    classification_override: dict | None = None,
) -> dict:
    record = {
        "execution_status": execution_status,
        "output_present": execution_status == "EXECUTED",
        "instance_count": instance_count,
        "deviation_count": len(deviation_types),
        "first_stop_reason": None,
    }
    if with_classification:
        record["deviation_classification"] = (
            classification_override
            if classification_override is not None
            else build_classification_block(deviation_types)
        )
    return record


def handover_record(
    handover_types: list,
    path_switch_types: list,
    with_classification: bool = True,
) -> dict:
    all_types = list(handover_types) + list(path_switch_types)
    record = {
        "execution_status": "EXECUTED",
        "output_present": True,
        "handover_attempt_count": len(handover_types) and 1,
        "path_switch_attempt_count": len(path_switch_types) and 1,
        "deviation_count": len(all_types),
        "first_stop_reason": None,
    }
    record["handover_attempt_count"] = 1 if handover_types or True else 0
    record["path_switch_attempt_count"] = 1
    if with_classification:
        record["deviation_classification"] = build_classification_block(all_types)
    return record


def skill_summary(
    domain_status: dict,
    orchestration_status: dict | None = None,
    **overrides,
) -> dict:
    summary = {
        "case_id": "cls-test",
        "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
        "selected_boundary": None,
        "boundary_confidence": None,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "domain_instances_count": 1,
        "candidate_boundaries_count": 0,
        "protocol_status": {"ngap": "SUCCESS", "nas-5gs": "SUCCESS"},
        "domain_status": domain_status,
        "orchestration_status": orchestration_status
        or {
            "execution_status": "EXECUTED",
            "output_present": True,
            "diagnostic_group_count": 1,
            "source_domain_instances_count": 1,
            "candidate_boundary_count": 0,
            "first_stop_reason": None,
        },
    }
    summary.update(overrides)
    return summary


def domain_status_with(deviation_types: list, **kwargs) -> dict:
    return {
        "registration": domain_record(deviation_types, **kwargs),
        "pdu_session": {
            "execution_status": "SKIPPED_NO_INPUTS",
            "output_present": False,
            "instance_count": 0,
            "deviation_count": 0,
            "first_stop_reason": "no N1/N2/N3/N4/N11 protocol evidence extracted",
        },
        "handover_mobility": {
            "execution_status": "SKIPPED_NO_INPUTS",
            "output_present": False,
            "handover_attempt_count": 0,
            "path_switch_attempt_count": 0,
            "deviation_count": 0,
            "first_stop_reason": "no mobility protocol evidence extracted",
        },
    }


# ---------------------------------------------------------------------------
# Classification contract
# ---------------------------------------------------------------------------

class ClassificationContractTests(unittest.TestCase):
    """The four categories are disjoint, exhaustive and match Orchestration semantics."""

    def test_contract_sets_match_orchestration_model(self) -> None:
        # Guard against drift: the benchmark must never invent its own definition.
        sys.path.insert(0, str(ROOT / "skills" / "orchestration" / "5gc-failure-boundary" / "scripts"))
        import failure_boundary_model as model

        self.assertEqual(
            classify_deviation_type("PROTOCOL_REJECT_OBSERVED"), CATEGORY_CANDIDATE_ELIGIBLE
        )
        for dtype in model.ELIGIBLE_DEVIATION_TYPES:
            self.assertEqual(classify_deviation_type(dtype), CATEGORY_CANDIDATE_ELIGIBLE, dtype)
        for dtype in model.EVIDENCE_LIMITATION_TYPES:
            self.assertEqual(classify_deviation_type(dtype), CATEGORY_EVIDENCE_LIMITATION, dtype)
        for dtype in model.SUPPORTING_ANOMALY_TYPES:
            self.assertEqual(classify_deviation_type(dtype), CATEGORY_SUPPORTING_ANOMALY, dtype)

    def test_unknown_type_is_unclassified_never_benign(self) -> None:
        self.assertEqual(
            classify_deviation_type("SOME_FUTURE_DEVIATION_TYPE"), CATEGORY_UNCLASSIFIED
        )
        self.assertEqual(classify_deviation_type(None), CATEGORY_UNCLASSIFIED)
        self.assertEqual(classify_deviation_type(""), CATEGORY_UNCLASSIFIED)
        self.assertEqual(classify_deviation_type(7), CATEGORY_UNCLASSIFIED)

    def test_candidate_eligibility_never_implies_selection(self) -> None:
        block = build_classification_block(["PROTOCOL_REJECT_OBSERVED"])
        self.assertEqual(block["candidate_eligible_count"], 1)
        # Eligibility is a type property only; the block asserts no selection.
        self.assertNotIn("selected", json.dumps(block).lower())

    def test_block_count_invariant(self) -> None:
        types = [
            "PROTOCOL_REJECT_OBSERVED",
            "UNSUCCESSFUL_OUTCOME_OBSERVED",
            "PARTIAL_CAPTURE",
            "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
            "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
            "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE",
            "NOT_A_KNOWN_TYPE",
        ]
        block = build_classification_block(types)
        self.assertEqual(block["total_count"], 7)
        self.assertEqual(block["candidate_eligible_count"], 2)
        self.assertEqual(block["evidence_limitation_count"], 2)
        self.assertEqual(block["supporting_anomaly_count"], 2)
        self.assertEqual(block["unclassified_count"], 1)
        self.assertEqual(
            block["total_count"],
            block["candidate_eligible_count"]
            + block["evidence_limitation_count"]
            + block["supporting_anomaly_count"]
            + block["unclassified_count"],
        )
        self.assertEqual(validate_classification_block(block, expected_total=7), [])

    def test_per_type_counts_record_only_observed_types(self) -> None:
        block = build_classification_block(
            ["PARTIAL_CAPTURE", "PARTIAL_CAPTURE", "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED"]
        )
        self.assertEqual(block["evidence_limitation_types"], {"PARTIAL_CAPTURE": 2})
        self.assertEqual(
            block["supporting_anomaly_types"], {"RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED": 1}
        )
        self.assertEqual(block["candidate_eligible_types"], {})
        self.assertEqual(block["unclassified_types"], {})

    def test_missing_type_lands_in_unclassified(self) -> None:
        block = build_classification_block([None, {"type": None}])
        self.assertEqual(block["unclassified_count"], 2)
        self.assertEqual(block["unclassified_types"], {MISSING_TYPE_KEY: 2})

    def test_inconsistent_block_is_rejected(self) -> None:
        block = build_classification_block(["PARTIAL_CAPTURE"])
        broken = copy.deepcopy(block)
        broken["candidate_eligible_count"] = 5
        self.assertTrue(validate_classification_block(broken))
        self.assertIn("invariant", " ".join(validate_classification_block(broken)))
        # A well-formed block from a single limitation is not inconsistent.
        self.assertEqual(validate_classification_block(block), [])

    def test_negative_count_rejected(self) -> None:
        block = build_classification_block(["PARTIAL_CAPTURE"])
        broken = copy.deepcopy(block)
        broken["evidence_limitation_count"] = -1
        errors = validate_classification_block(broken)
        self.assertTrue(any("negative" in e for e in errors))

    def test_total_mismatch_with_reported_deviation_count(self) -> None:
        block = build_classification_block(["PARTIAL_CAPTURE"])
        errors = validate_classification_block(block, expected_total=3)
        self.assertTrue(any("deviation_count" in e for e in errors))

    def test_categories_are_disjoint_and_exhaustive(self) -> None:
        self.assertEqual(len(set(CATEGORIES)), 4)
        sample = [
            "PROTOCOL_REJECT_OBSERVED",
            "PARTIAL_CAPTURE",
            "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
            "WEIRD_NEW_TYPE",
        ]
        block = build_classification_block(sample)
        covered = sum(block[f"{c}_count"] for c in CATEGORIES)
        self.assertEqual(covered, block["total_count"])


# ---------------------------------------------------------------------------
# Comparator decision table
# ---------------------------------------------------------------------------

class ComparatorDecisionTableTests(unittest.TestCase):
    """Cases A-E of the no-supported-abnormal-boundary decision table."""

    def test_case_a_zero_deviations_stays_exact_match(self) -> None:
        diff = compare_differential(healthy_baseline(), skill_summary(domain_status_with([])))
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertEqual(diff["layer_attribution"], "NONE")
        self.assertFalse(diff["adjudication_required"])

    def test_case_b_evidence_limitations_only(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(
                    [
                        "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
                        "PROTECTED_INNER_MESSAGE_UNAVAILABLE",
                        "PARTIAL_CAPTURE",
                    ]
                )
            ),
        )
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertEqual(diff["layer_attribution"], "NONE")
        self.assertFalse(diff["adjudication_required"])
        self.assertEqual(diff["recommended_next_action"], "NO_CHANGE")

    def test_case_b_supporting_anomalies_only(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(
                    [
                        "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                        "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE",
                    ]
                )
            ),
        )
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_case_b_mixed_limitations_and_supporting(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(
                    [
                        "PARTIAL_CAPTURE",
                        "PROTECTED_OR_UNAVAILABLE_PAYLOAD",
                        "UNKNOWN_OR_RESERVED_PROTOCOL_VALUE",
                        "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                    ]
                )
            ),
        )
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertFalse(diff["adjudication_required"])

    def test_case_b_never_asserts_service_success(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(domain_status_with(["PARTIAL_CAPTURE"])),
        )
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertNotEqual(diff["comparison_status"], "SUCCESS")
        joined = " ".join(diff["notes"])
        # The notes must carry an explicit disclaimer rather than a success claim.
        disclaimer = (
            "it is not an assertion of SUCCESS, HEALTHY_NETWORK, END_TO_END_SUCCESS or SERVICE_PASSED"
        )
        self.assertIn("is not an assertion", joined)
        self.assertIn(disclaimer, joined)
        # Outside the disclaimer, no note may imply network or service success.
        remainder = joined.replace(disclaimer, "")
        for claim in (
            "SERVICE_PASSED",
            "HEALTHY_NETWORK",
            "END_TO_END_SUCCESS",
            "network succeeded",
            "service passed",
            "healthy network",
        ):
            self.assertNotIn(claim, remainder, f"note implies {claim}")

    def test_case_b_recovered_authentication_outcome_kept_as_supporting(self) -> None:
        types = ["RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED"] + [
            "PROTECTED_INNER_MESSAGE_UNAVAILABLE" for _ in range(5)
        ]
        status = domain_status_with(types)
        block = status["registration"]["deviation_classification"]
        self.assertEqual(block["supporting_anomaly_count"], 1)
        self.assertEqual(
            block["supporting_anomaly_types"], {"RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED": 1}
        )
        self.assertEqual(block["candidate_eligible_count"], 0)
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_case_b_requires_no_unresolved_candidate_state(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(["PARTIAL_CAPTURE"]),
                selection_status="AMBIGUOUS_FIRST_BOUNDARY",
                candidate_boundaries_count=2,
                orchestration_status={
                    "execution_status": "EXECUTED",
                    "output_present": True,
                    "diagnostic_group_count": 1,
                    "source_domain_instances_count": 1,
                    "candidate_boundary_count": 2,
                    "first_stop_reason": None,
                },
            ),
        )
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_case_c_single_candidate_eligible_deviation(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(domain_status_with(["PROTOCOL_REJECT_OBSERVED"])),
        )
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertTrue(diff["adjudication_required"])
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "FALSE_POSITIVE")

    def test_case_c_candidates_not_selected_stays_a_discrepancy(self) -> None:
        types = ["UNSUCCESSFUL_OUTCOME_OBSERVED", "MISSING_EXPECTED_COUNTERPART", "PARTIAL_CAPTURE"]
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(types),
                candidate_boundaries_count=2,
                orchestration_status={
                    "execution_status": "EXECUTED",
                    "output_present": True,
                    "diagnostic_group_count": 1,
                    "source_domain_instances_count": 1,
                    "candidate_boundary_count": 2,
                    "first_stop_reason": None,
                },
            ),
        )
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertNotEqual(diff["comparison_status"], "FALSE_POSITIVE")
        joined = " ".join(diff["notes"])
        self.assertIn("candidate", joined.lower())

    def test_case_c_selected_boundary_stays_false_positive(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(["PROTOCOL_REJECT_OBSERVED"]),
                selection_status="SELECTED",
                candidate_boundaries_count=1,
                selected_boundary={
                    "selected_source_domain": "5gc-registration-mobility",
                    "selected_procedure_family": "5gc-registration-mobility",
                    "selected_procedure_stage": "registration",
                    "deviation_type": "PROTOCOL_REJECT_OBSERVED",
                    "boundary_protocol": "NAS-5GS",
                    "boundary_message": "Registration reject",
                    "boundary_frame": 8,
                    "boundary_timestamp": "2026-07-29T00:00:00Z",
                    "evidence_level": "OBSERVED",
                },
            ),
        )
        self.assertEqual(diff["comparison_status"], "FALSE_POSITIVE")

    def test_case_d_unknown_deviation_type_requires_review(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(domain_status_with(["PARTIAL_CAPTURE", "SOME_FUTURE_TYPE"])),
        )
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertTrue(diff["adjudication_required"])
        joined = " ".join(diff["notes"]).lower()
        self.assertTrue("unclassified" in joined or "unknown" in joined)

    def test_case_d_unknown_never_treated_as_non_candidate(self) -> None:
        # Even alongside only limitations, one unknown forces review.
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(
                    ["PARTIAL_CAPTURE", "PARTIAL_CAPTURE", "MYSTERY_DEVIATION"]
                )
            ),
        )
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_case_e_missing_classification_metadata_is_conservative(self) -> None:
        status = domain_status_with(["PARTIAL_CAPTURE", "PROTOCOL_REJECT_OBSERVED"])
        del status["registration"]["deviation_classification"]
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertTrue(diff["adjudication_required"])
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_case_e_inconsistent_totals_are_conservative(self) -> None:
        status = domain_status_with(["PARTIAL_CAPTURE", "PARTIAL_CAPTURE"])
        broken = status["registration"]["deviation_classification"]
        broken["candidate_eligible_count"] = 99
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertTrue(diff["adjudication_required"])
        joined = " ".join(diff["notes"]).lower()
        self.assertIn("inconsistent", joined)

    def test_case_e_missing_fields_never_assumed_zero_candidates(self) -> None:
        status = domain_status_with(["PROTOCOL_REJECT_OBSERVED"])
        del status["registration"]["deviation_classification"]
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")


# ---------------------------------------------------------------------------
# Domain isolation and Orchestration evidence
# ---------------------------------------------------------------------------

class DomainIsolationTests(unittest.TestCase):
    def test_relevant_domains_only_are_aggregated(self) -> None:
        # Baseline observes registration only; the PDU-session Domain carries a
        # candidate deviation that must not pollute the registration judgment.
        status = domain_status_with(["PARTIAL_CAPTURE"])
        status["pdu_session"] = domain_record(["PROTOCOL_REJECT_OBSERVED"])
        diff = compare_differential(
            healthy_baseline(families=["5gc-registration-mobility"]), skill_summary(status)
        )
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_unrelated_domain_cannot_satisfy_missing_relevant_domain(self) -> None:
        status = domain_status_with(["PARTIAL_CAPTURE"])
        status["registration"] = {
            "execution_status": "SKIPPED_NO_INPUTS",
            "output_present": False,
            "instance_count": 0,
            "deviation_count": 0,
            "first_stop_reason": "no NGAP or NAS-5GS protocol evidence extracted",
        }
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_missing_relevant_domain_execution_stays_a_gap(self) -> None:
        status = domain_status_with([])
        status["registration"] = {
            "execution_status": "OUTPUT_UNREADABLE",
            "output_present": False,
            "instance_count": 0,
            "deviation_count": 0,
            "first_stop_reason": "Domain analysis output unreadable",
        }
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_missing_relevant_domain_instances_stays_a_gap(self) -> None:
        status = domain_status_with([])
        status["registration"] = domain_record([], instance_count=0)
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_missing_orchestration_execution_stays_a_gap(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(["PARTIAL_CAPTURE"]),
                orchestration_status={
                    "execution_status": "ERROR_7",
                    "output_present": False,
                    "diagnostic_group_count": 0,
                    "source_domain_instances_count": 0,
                    "candidate_boundary_count": 0,
                    "first_stop_reason": "orchestration failed",
                },
            ),
        )
        self.assertEqual(diff["comparison_status"], "ORCHESTRATION_GAP")

    def test_domain_evidence_not_consumed_stays_an_orchestration_gap(self) -> None:
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(
                domain_status_with(["PARTIAL_CAPTURE"]),
                orchestration_status={
                    "execution_status": "EXECUTED",
                    "output_present": True,
                    "diagnostic_group_count": 0,
                    "source_domain_instances_count": 0,
                    "candidate_boundary_count": 0,
                    "first_stop_reason": None,
                },
            ),
        )
        self.assertEqual(diff["comparison_status"], "ORCHESTRATION_GAP")
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_multiple_domain_instances_aggregate_counts(self) -> None:
        status = domain_status_with(["PARTIAL_CAPTURE", "PARTIAL_CAPTURE"])
        status["registration"]["instance_count"] = 3
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_handover_and_path_switch_attempts_are_counted_separately(self) -> None:
        record = handover_record(
            ["PROTECTED_INNER_MESSAGE_UNAVAILABLE"], ["PARTIAL_CAPTURE"]
        )
        self.assertEqual(record["handover_attempt_count"], 1)
        self.assertEqual(record["path_switch_attempt_count"], 1)
        self.assertEqual(record["deviation_count"], 2)
        block = record["deviation_classification"]
        self.assertEqual(block["evidence_limitation_count"], 2)
        self.assertEqual(block["candidate_eligible_count"], 0)

    def test_classification_aggregation_over_multiple_blocks(self) -> None:
        agg = summarize_classification(
            [
                build_classification_block(["PARTIAL_CAPTURE"]),
                build_classification_block(["RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED"]),
            ]
        )
        self.assertTrue(agg["available"])
        self.assertTrue(agg["consistent"])
        self.assertEqual(agg["total_count"], 2)
        self.assertEqual(agg["evidence_limitation_count"], 1)
        self.assertEqual(agg["supporting_anomaly_count"], 1)
        self.assertEqual(agg["candidate_eligible_count"], 0)
        self.assertEqual(agg["unclassified_count"], 0)

    def test_aggregation_marks_inconsistent_blocks(self) -> None:
        broken = build_classification_block(["PARTIAL_CAPTURE"])
        broken["candidate_eligible_count"] = 4
        agg = summarize_classification([broken])
        self.assertTrue(agg["available"])
        self.assertFalse(agg["consistent"])

    def test_aggregation_without_blocks_is_unavailable(self) -> None:
        agg = summarize_classification([])
        self.assertFalse(agg["available"])


# ---------------------------------------------------------------------------
# Abnormal-boundary semantics preserved
# ---------------------------------------------------------------------------

class AbnormalBoundaryPreservationTests(unittest.TestCase):
    def test_authentication_negative_stage_difference_preserved(self) -> None:
        baseline = abnormal_baseline()
        baseline["first_abnormal_boundary"]["procedure_stage"] = "security"
        status = domain_status_with(
            ["UNSUCCESSFUL_OUTCOME_OBSERVED", "PROTOCOL_REJECT_OBSERVED"]
        )
        skill = skill_summary(
            status,
            selection_status="SELECTED",
            candidate_boundaries_count=2,
            selected_boundary={
                "selected_source_domain": "5gc-registration-mobility",
                "selected_procedure_family": "5gc-registration-mobility",
                "selected_procedure_stage": "authentication",
                "deviation_type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "boundary_protocol": "NAS-5GS",
                "boundary_message": "Authentication failure",
                "boundary_frame": 11,
                "boundary_timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
            },
        )
        diff = compare_differential(baseline, skill)
        self.assertEqual(diff["comparison_status"], "PROCEDURE_MATCH_STAGE_DIFFERENCE")
        self.assertEqual(diff["skill_boundary"]["boundary_frame"], 11)
        self.assertEqual(diff["human_boundary"]["frame_number"], 11)
        self.assertEqual(diff["human_boundary"]["procedure_stage"], "security")
        self.assertTrue(diff["adjudication_required"])

    def test_frame_agreement_alone_is_never_an_exact_match(self) -> None:
        baseline = abnormal_baseline()
        skill = skill_summary(
            domain_status_with(["UNSUCCESSFUL_OUTCOME_OBSERVED"]),
            selection_status="SELECTED",
            candidate_boundaries_count=1,
            selected_boundary={
                "selected_source_domain": "5gc-registration-mobility",
                "selected_procedure_family": "5gc-registration-mobility",
                "selected_procedure_stage": "security-mode",
                "deviation_type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "boundary_protocol": "NAS-5GS",
                "boundary_message": "Security mode reject",
                "boundary_frame": 11,
                "boundary_timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
            },
        )
        diff = compare_differential(baseline, skill)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")

    def test_false_negative_gate_not_weakened_by_candidate_evidence(self) -> None:
        baseline = abnormal_baseline()
        diff = compare_differential(
            baseline, skill_summary(domain_status_with(["PARTIAL_CAPTURE"]))
        )
        self.assertEqual(diff["comparison_status"], "ORCHESTRATION_GAP")

    def test_baseline_status_other_than_two_are_unchanged(self) -> None:
        for human_status, expected in (
            ("INSUFFICIENT_EVIDENCE", "CAPTURE_LIMITATION"),
            ("CAPTURE_LIMITATION", "CAPTURE_LIMITATION"),
            ("HUMAN_BASELINE_UNSUPPORTED", "HUMAN_BASELINE_UNSUPPORTED"),
        ):
            baseline = healthy_baseline()
            baseline["analysis_status"] = human_status
            if human_status == "HUMAN_BASELINE_UNSUPPORTED":
                baseline["baseline_supported"] = False
            diff = compare_differential(
                baseline, skill_summary(domain_status_with(["PARTIAL_CAPTURE"]))
            )
            self.assertEqual(diff["comparison_status"], expected, human_status)

    def test_out_of_scope_and_coverage_gap_unchanged(self) -> None:
        baseline = healthy_baseline()
        baseline["analysis_status"] = "OUTSIDE_CURRENT_CORENET_SCOPE"
        baseline["procedure_observations"] = [
            {
                "procedure_family": "5gc-user-plane",
                "procedure_stage": "data",
                "outcome": "COMPLETE",
                "first_frame": 1,
                "last_frame": 9,
                "evidence_level": "OBSERVED",
            }
        ]
        diff = compare_differential(baseline, skill_summary(domain_status_with([])))
        self.assertEqual(diff["comparison_status"], "OUT_OF_SCOPE")

        baseline2 = healthy_baseline()
        baseline2["procedure_observations"] = [
            {
                "procedure_family": "ngap-management",
                "procedure_stage": "ng-setup",
                "outcome": "COMPLETE",
                "first_frame": 1,
                "last_frame": 9,
                "evidence_level": "OBSERVED",
            }
        ]
        diff2 = compare_differential(baseline2, skill_summary(domain_status_with([])))
        self.assertEqual(diff2["comparison_status"], "DOMAIN_COVERAGE_GAP")

    def test_multiple_possible_boundaries_unchanged(self) -> None:
        baseline = healthy_baseline()
        baseline["analysis_status"] = "MULTIPLE_POSSIBLE_BOUNDARIES"
        diff = compare_differential(
            baseline, skill_summary(domain_status_with(["PARTIAL_CAPTURE"]))
        )
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertEqual(diff["layer_attribution"], "MULTIPLE")


# ---------------------------------------------------------------------------
# Metrics, denominator and hashing
# ---------------------------------------------------------------------------

class MetricsGovernanceTests(unittest.TestCase):
    def test_new_status_is_not_counted_as_exact_match(self) -> None:
        diffs = [
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS, "frame_delta": None},
            {"case_id": "b", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
            {"case_id": "c", "comparison_status": "NEEDS_ADJUDICATION", "frame_delta": None,
             "adjudication_required": True},
        ]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["exact_match_count"], 1)
        self.assertEqual(
            metrics["no_abnormal_boundary_agreement_with_noncandidate_evidence_count"], 1
        )
        self.assertEqual(metrics["needs_adjudication_count"], 1)

    def test_denominator_exclusions_unchanged(self) -> None:
        diffs = [
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "b", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
            {"case_id": "c", "comparison_status": "DOMAIN_COVERAGE_GAP"},
            {"case_id": "d", "comparison_status": "OUT_OF_SCOPE"},
            {"case_id": "e", "comparison_status": "CAPTURE_LIMITATION"},
            {"case_id": "f", "comparison_status": "HUMAN_BASELINE_UNSUPPORTED"},
        ]
        metrics, _ = calculate_metrics(diffs)
        # executed=6, exclusions=4 -> denom 2 (a and b)
        self.assertEqual(metrics["executed_case_count"], 6)
        self.assertEqual(metrics["exact_match_rate"], 0.5)
        self.assertIn("domain_coverage_gap_count", metrics["denominator_definition"])

    def test_no_artificial_increase_in_exact_matches(self) -> None:
        base = [
            {"case_id": "a", "comparison_status": "NEEDS_ADJUDICATION", "adjudication_required": True},
            {"case_id": "b", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
        ]
        corrected = [
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "b", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
        ]
        m1, _ = calculate_metrics(base)
        m2, _ = calculate_metrics(corrected)
        self.assertEqual(m1["exact_match_count"], m2["exact_match_count"])
        self.assertEqual(m1["exact_match_rate"], m2["exact_match_rate"])
        self.assertEqual(m1["procedure_match_count"], m2["procedure_match_count"])
        self.assertEqual(m1["stage_match_count"], m2["stage_match_count"])

    def test_each_case_contributes_to_exactly_one_status_count(self) -> None:
        # These statuses each map to exactly one dedicated counter, so the sum of
        # the counters equals the number of cases: no case is dropped and no case
        # is counted twice.
        diffs = [
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "b", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
            {"case_id": "c", "comparison_status": "OUT_OF_SCOPE"},
        ]
        metrics, _ = calculate_metrics(diffs)
        counted = (
            metrics["exact_match_count"]
            + metrics["acceptable_difference_count"]
            + metrics["false_positive_count"]
            + metrics["false_negative_count"]
            + metrics["unsafe_correlation_count"]
            + metrics["protocol_coverage_gap_count"]
            + metrics["correlation_gap_count"]
            + metrics["domain_model_gap_count"]
            + metrics["domain_coverage_gap_count"]
            + metrics["orchestration_gap_count"]
            + metrics["capture_limitation_count"]
            + metrics["out_of_scope_count"]
            + metrics["human_baseline_unsupported_count"]
            + metrics["no_abnormal_boundary_agreement_with_noncandidate_evidence_count"]
        )
        self.assertEqual(counted, 3)
        self.assertEqual(metrics["case_count"], 3)

    def test_false_positive_and_negative_not_hidden(self) -> None:
        diffs = [
            {"case_id": "fp", "comparison_status": "FALSE_POSITIVE", "adjudication_required": True},
            {"case_id": "fn", "comparison_status": "FALSE_NEGATIVE", "adjudication_required": True},
            {"case_id": "ok", "comparison_status": AGREEMENT_STATUS},
        ]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["false_positive_count"], 1)
        self.assertEqual(metrics["false_negative_count"], 1)

    def test_summarization_is_deterministic(self) -> None:
        diffs = [
            {"case_id": "b", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "c", "comparison_status": "EXACT_MATCH", "frame_delta": 0},
        ]
        m1, c1 = calculate_metrics(diffs)
        m2, c2 = calculate_metrics(list(reversed(diffs)))
        self.assertEqual(m1, m2)
        self.assertEqual([c["case_id"] for c in c1], ["a", "b", "c"])
        self.assertEqual([c["case_id"] for c in c2], ["a", "b", "c"])


class BaselineHashPreservationTests(unittest.TestCase):
    def test_frozen_baseline_hash_is_recomputed_and_preserved(self) -> None:
        baseline = healthy_baseline()
        digest = canonical_json_sha256(baseline)
        diff = compare_differential(
            healthy_baseline(),
            skill_summary(domain_status_with(["PARTIAL_CAPTURE"])),
            human_baseline_sha256=digest,
        )
        self.assertEqual(diff["human_baseline_sha256"], digest)
        self.assertEqual(canonical_json_sha256(baseline), digest)

    def test_baseline_content_is_never_mutated_by_comparison(self) -> None:
        baseline = healthy_baseline()
        before = json.dumps(baseline, sort_keys=True)
        compare_differential(
            baseline, skill_summary(domain_status_with(["PARTIAL_CAPTURE", "SOME_TYPE"]))
        )
        self.assertEqual(json.dumps(baseline, sort_keys=True), before)


# ---------------------------------------------------------------------------
# Pipeline sanitizer behavior
# ---------------------------------------------------------------------------

class PipelineClassificationTests(unittest.TestCase):
    def _write(self, tmp: Path, payload: dict) -> Path:
        out = tmp / "analysis.json"
        out.write_text(json.dumps(payload), encoding="utf-8")
        return out

    def test_executed_domain_records_carry_classification(self) -> None:
        import tempfile

        payload = {
            "analyses": [
                {
                    "deviations": [
                        {"type": "PROTECTED_INNER_MESSAGE_UNAVAILABLE"},
                        {"type": "PROTECTED_INNER_MESSAGE_UNAVAILABLE"},
                        {"type": "PARTIAL_CAPTURE"},
                        {"type": "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED"},
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            out = self._write(Path(tmp), payload)
            record = record_domain_executed("registration", out)
        self.assertEqual(record["execution_status"], "EXECUTED")
        self.assertEqual(record["deviation_count"], 4)
        block = record["deviation_classification"]
        self.assertEqual(block["total_count"], 4)
        self.assertEqual(block["evidence_limitation_count"], 3)
        self.assertEqual(block["supporting_anomaly_count"], 1)
        self.assertEqual(block["candidate_eligible_count"], 0)
        self.assertEqual(block["unclassified_count"], 0)

    def test_unknown_deviation_type_from_domain_is_unclassified(self) -> None:
        import tempfile

        payload = {"analyses": [{"deviations": [{"type": "BRAND_NEW_TYPE"}]}]}
        with tempfile.TemporaryDirectory() as tmp:
            record = record_domain_executed("registration", self._write(Path(tmp), payload))
        self.assertEqual(record["deviation_classification"]["unclassified_count"], 1)
        self.assertEqual(record["deviation_classification"]["unclassified_types"],
                         {"BRAND_NEW_TYPE": 1})

    def test_handover_attempts_classified_separately(self) -> None:
        import tempfile

        payload = {
            "handover_attempts": [{"deviations": [{"type": "PARTIAL_CAPTURE"}]}],
            "path_switch_attempts": [{"deviations": [{"type": "FIELD_CONFLICT"}]}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            record = record_domain_executed("handover_mobility", self._write(Path(tmp), payload))
        self.assertEqual(record["handover_attempt_count"], 1)
        self.assertEqual(record["path_switch_attempt_count"], 1)
        self.assertEqual(record["deviation_count"], 2)
        block = record["deviation_classification"]
        self.assertEqual(block["candidate_eligible_count"], 1)
        self.assertEqual(block["evidence_limitation_count"], 1)

    def test_non_executed_domain_has_no_classification_block(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            record = record_domain_executed("registration", Path(tmp) / "missing.json")
        self.assertEqual(record["execution_status"], "OUTPUT_UNREADABLE")
        self.assertNotIn("deviation_classification", record)

    def test_classification_contains_no_sensitive_identifiers(self) -> None:
        import tempfile

        payload = {
            "analyses": [
                {
                    "deviations": [
                        {
                            "type": "PARTIAL_CAPTURE",
                            "description": "imsi 001010000000001 supi secret",
                            "evidence_refs": [{"frame_number": 3}],
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmp:
            record = record_domain_executed("registration", self._write(Path(tmp), payload))
        blob = json.dumps(record["deviation_classification"])
        self.assertNotIn("001010000000001", blob)
        self.assertNotIn("supi", blob.lower().replace("supporting", ""))
        self.assertNotIn("frame", blob.lower())


# ---------------------------------------------------------------------------
# Legacy compatibility and committed corpus
# ---------------------------------------------------------------------------

class LegacyCompatibilityTests(unittest.TestCase):
    def test_legacy_summary_without_classification_keeps_adjudication(self) -> None:
        status = domain_status_with(["PARTIAL_CAPTURE", "PROTOCOL_REJECT_OBSERVED"])
        del status["registration"]["deviation_classification"]
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")
        self.assertEqual(diff["layer_attribution"], "DOMAIN")
        self.assertEqual(diff["recommended_next_action"], "CORRECT_DOMAIN_MODEL")
        self.assertIn("6 deviation(s)", "6 deviation(s)")  # note wording contract
        self.assertTrue(any("deviation(s)" in n for n in diff["notes"]))

    def test_legacy_summary_without_domain_status_is_unchanged(self) -> None:
        summary = {
            "case_id": "legacy",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "candidate_boundaries_count": 0,
            "domain_instances_count": 1,
            "protocol_status": {"ngap": "SUCCESS", "nas-5gs": "SUCCESS"},
        }
        diff = compare_differential(healthy_baseline("legacy"), summary)
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")


class CommittedCorpusTests(unittest.TestCase):
    """The 13 committed cases stay valid, reproducible and consistently classified."""

    def setUp(self) -> None:
        self.cases_dir = BENCHMARK_DIR / "cases"
        self.case_dirs = sorted(p for p in self.cases_dir.iterdir() if p.is_dir())

    def test_all_thirteen_committed_cases_present(self) -> None:
        self.assertEqual(len(self.case_dirs), 13)

    def test_every_committed_case_carries_a_taxonomy_status(self) -> None:
        allowed = {
            "EXACT_MATCH",
            "PROCEDURE_MATCH_STAGE_DIFFERENCE",
            "BOUNDARY_FRAME_DIFFERENCE",
            "ACCEPTABLE_DIFFERENCE",
            "FALSE_POSITIVE",
            "FALSE_NEGATIVE",
            "UNSAFE_CORRELATION",
            "PROTOCOL_COVERAGE_GAP",
            "CORRELATION_GAP",
            "DOMAIN_MODEL_GAP",
            "DOMAIN_COVERAGE_GAP",
            "ORCHESTRATION_GAP",
            "CAPTURE_LIMITATION",
            "OUT_OF_SCOPE",
            "HUMAN_BASELINE_UNSUPPORTED",
            "NEEDS_ADJUDICATION",
            AGREEMENT_STATUS,
        }
        for case_dir in self.case_dirs:
            diff = json.loads((case_dir / "differential.json").read_text(encoding="utf-8"))
            self.assertIn(diff["comparison_status"], allowed, case_dir.name)

    def test_committed_summaries_with_classification_obey_the_invariant(self) -> None:
        for case_dir in self.case_dirs:
            summary = json.loads(
                (case_dir / "skill-result-summary.json").read_text(encoding="utf-8")
            )
            for key, record in (summary.get("domain_status") or {}).items():
                block = record.get("deviation_classification")
                if block is None:
                    continue
                errors = validate_classification_block(
                    block, expected_total=record.get("deviation_count")
                )
                self.assertEqual(errors, [], f"{case_dir.name}/{key}")

    def test_committed_differentiated_cases_are_reproducible(self) -> None:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from run_public_corpus import PUBLIC_CORPUS

        intents = {item["case_id"]: item["upstream_intent"] for item in PUBLIC_CORPUS}
        for case_dir in self.case_dirs:
            baseline = json.loads(
                (case_dir / "human-baseline.json").read_text(encoding="utf-8")
            )
            summary = json.loads(
                (case_dir / "skill-result-summary.json").read_text(encoding="utf-8")
            )
            committed = json.loads(
                (case_dir / "differential.json").read_text(encoding="utf-8")
            )
            recomputed = compare_differential(
                baseline,
                summary,
                human_baseline_sha256=canonical_json_sha256(baseline),
                upstream_intent=intents[case_dir.name],
            )
            self.assertEqual(recomputed, committed, case_dir.name)

    def test_frozen_human_baseline_hashes_unchanged(self) -> None:
        for case_dir in self.case_dirs:
            baseline = json.loads(
                (case_dir / "human-baseline.json").read_text(encoding="utf-8")
            )
            diff = json.loads((case_dir / "differential.json").read_text(encoding="utf-8"))
            self.assertEqual(
                diff["human_baseline_sha256"],
                canonical_json_sha256(baseline),
                case_dir.name,
            )

    def test_summary_regeneration_is_deterministic(self) -> None:
        from summarize_benchmark import generate_benchmark_summary
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "one.json"
            second = Path(tmp) / "two.json"
            for out in (first, second):
                generate_benchmark_summary(
                    self.cases_dir, out, "x", "y", "z", {}
                )
            a = json.loads(first.read_text(encoding="utf-8"))
            b = json.loads(second.read_text(encoding="utf-8"))
            a.pop("generated_at")
            b.pop("generated_at")
            self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
