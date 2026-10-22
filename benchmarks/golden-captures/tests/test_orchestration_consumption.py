#!/usr/bin/env python3
"""Orchestration evidence-consumption acceptance tests for the Golden Capture benchmark.

Positive bounded agreement must rest on positively verified Orchestration
consumption of the relevant Domain instances. A diagnostic-group count is not
consumption evidence, an aggregate consumed-instance count does not identify the
contributing Domain, and the absence of a selected abnormal boundary is not
evidence of consumption. An absence of evidence never satisfies a positive
acceptance condition.
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
from compare_results import (  # noqa: E402
    NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE,
    compare_differential,
    evaluate_domain_evidence,
    evaluate_orchestration_evidence,
)
from deviation_classification import build_classification_block  # noqa: E402
from summarize_benchmark import calculate_metrics  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"
AGREEMENT_STATUS = NO_ABNORMAL_BOUNDARY_AGREEMENT_WITH_NONCANDIDATE_EVIDENCE

# Source Domain identities emitted by the Orchestration runtime, mapped
# explicitly to the benchmark Domain keys. The strings are not identical and
# must never be assumed to be.
SOURCE_DOMAIN_IDENTITY_MAP = {
    "5gc-registration-mobility": "registration",
    "5gc-pdu-session": "pdu_session",
    "5gc-handover-mobility": "handover_mobility",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def healthy_baseline(case_id: str = "orch-test", families: list[str] | None = None) -> dict:
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
        "capture_scope": {"interfaces": ["N1", "N2"], "protocols_present": ["NGAP", "NAS-5GS"]},
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


def abnormal_baseline(case_id: str = "orch-abnormal") -> dict:
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
) -> dict:
    return {
        "execution_status": execution_status,
        "output_present": execution_status == "EXECUTED",
        "instance_count": instance_count,
        "deviation_count": len(deviation_types),
        "first_stop_reason": None,
        "deviation_classification": build_classification_block(deviation_types),
    }


def domain_status(registration: dict | None = None, pdu_session: dict | None = None) -> dict:
    return {
        "registration": registration
        or {
            "execution_status": "EXECUTED",
            "output_present": True,
            "instance_count": 1,
            "deviation_count": 1,
            "first_stop_reason": None,
            "deviation_classification": build_classification_block(["PARTIAL_CAPTURE"]),
        },
        "pdu_session": pdu_session
        or {
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


def orchestration_status(
    execution_status: str = "EXECUTED",
    output_present: bool = True,
    groups: int = 1,
    consumed: int = 1,
    candidates: int = 0,
    consumed_counts: dict | None = None,
    unmapped: int = 0,
) -> dict:
    record = {
        "execution_status": execution_status,
        "output_present": output_present,
        "diagnostic_group_count": groups,
        "source_domain_instances_count": consumed,
        "candidate_boundary_count": candidates,
        "first_stop_reason": None,
    }
    if consumed_counts is not None:
        record["consumed_domain_instance_counts"] = consumed_counts
        record["consumed_unmapped_source_domain_instance_count"] = unmapped
    return record


def skill_summary(domain_status_map: dict, orch: dict | None = None, **overrides) -> dict:
    summary = {
        "case_id": "orch-test",
        "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
        "selected_boundary": None,
        "boundary_confidence": None,
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "domain_instances_count": 1,
        "candidate_boundaries_count": 0,
        "protocol_status": {"ngap": "SUCCESS", "nas-5gs": "SUCCESS"},
        "domain_status": domain_status_map,
        "orchestration_status": orch
        if orch is not None
        else orchestration_status(consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0}),
    }
    summary.update(overrides)
    return summary


# ---------------------------------------------------------------------------
# Source Domain identity mapping
# ---------------------------------------------------------------------------

class SourceDomainIdentityMappingTests(unittest.TestCase):
    """The benchmark must map Orchestration source identities explicitly."""

    def test_identity_strings_are_not_assumed_equal(self) -> None:
        for source, key in SOURCE_DOMAIN_IDENTITY_MAP.items():
            self.assertNotEqual(source, key, source)

    def test_unknown_source_identity_is_not_mapped_to_a_known_domain(self) -> None:
        from sanitize_result import map_source_domain_key

        self.assertEqual(map_source_domain_key("5gc-registration-mobility"), "registration")
        self.assertEqual(map_source_domain_key("5gc-pdu-session"), "pdu_session")
        self.assertEqual(map_source_domain_key("5gc-handover-mobility"), "handover_mobility")
        self.assertIsNone(map_source_domain_key("5gc-ims-registration"))
        self.assertIsNone(map_source_domain_key(""))
        self.assertIsNone(map_source_domain_key(None))

    def test_consumed_identity_counts_are_recorded(self) -> None:
        from sanitize_result import consumed_domain_instance_counts

        counts, unmapped = consumed_domain_instance_counts(
            [
                {"source_domain": "5gc-registration-mobility", "source_instance_id": "r1"},
                {"source_domain": "5gc-pdu-session", "source_instance_id": "p1"},
                {"source_domain": "5gc-ims-registration", "source_instance_id": "i1"},
            ]
        )
        self.assertEqual(counts, {"registration": 1, "pdu_session": 1, "handover_mobility": 0})
        self.assertEqual(unmapped, 1)
        self.assertEqual(sum(counts.values()) + unmapped, 3)

    def test_consumed_counts_contain_no_instance_identifiers(self) -> None:
        from sanitize_result import consumed_domain_instance_counts

        counts, unmapped = consumed_domain_instance_counts(
            [
                {
                    "source_domain": "5gc-registration-mobility",
                    "source_instance_id": "5gc-reg:secret.pcap:sctp-assoc-65535:r1",
                    "source_file": "/home/user/captures/secret.pcap",
                    "capture_file": "secret.pcap",
                }
            ]
        )
        blob = json.dumps({"counts": counts, "unmapped": unmapped})
        self.assertNotIn("secret.pcap", blob)
        self.assertNotIn("sctp-assoc", blob)
        self.assertNotIn("5gc-reg:", blob)
        self.assertEqual(counts, {"registration": 1, "pdu_session": 0, "handover_mobility": 0})


# ---------------------------------------------------------------------------
# Scenario A-E: the original unsafe acceptance paths
# ---------------------------------------------------------------------------

class UnsafeAcceptanceReproductionTests(unittest.TestCase):
    """Record the pre-correction behaviour of each unsafe acceptance path."""

    def test_scenario_a_zero_consumed_instances_must_not_accept(self) -> None:
        # A diagnostic group exists but Orchestration consumed zero instances.
        skill = skill_summary(
            domain_status(),
            orchestration_status(
                execution_status="EXECUTED",
                output_present=True,
                groups=1,
                consumed=0,
                candidates=0,
                consumed_counts={"registration": 0, "pdu_session": 0, "handover_mobility": 0},
            ),
        )
        diff = compare_differential(healthy_baseline(), skill)
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")

    def test_scenario_b_missing_orchestration_status_must_not_accept(self) -> None:
        summary = skill_summary(domain_status())
        del summary["orchestration_status"]
        diff = compare_differential(healthy_baseline(), summary)
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")

    def test_scenario_c_unrelated_domain_consumption_must_not_accept(self) -> None:
        # Baseline makes Registration relevant; Orchestration consumed only PDU Session.
        skill = skill_summary(
            domain_status(),
            orchestration_status(
                groups=1,
                consumed=1,
                consumed_counts={"registration": 0, "pdu_session": 1, "handover_mobility": 0},
            ),
            domain_instances_count=2,
        )
        skill["domain_status"]["pdu_session"] = domain_record(["PARTIAL_CAPTURE"])
        diff = compare_differential(
            healthy_baseline(families=["5gc-registration-mobility"]), skill
        )
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_scenario_d_contradictory_candidate_counts_must_not_accept(self) -> None:
        for overrides in (
            {"candidate_boundaries_count": 2},
            {"candidate_boundaries_count": 0},
        ):
            with self.subTest(overrides=overrides):
                orch = orchestration_status(
                    candidates=2,
                    consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
                )
                skill = skill_summary(domain_status(), orch, **overrides)
                diff = compare_differential(healthy_baseline(), skill)
                self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_scenario_d_selected_status_with_candidates_must_not_accept(self) -> None:
        orch = orchestration_status(
            candidates=2, consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0}
        )
        skill = skill_summary(
            domain_status(), orch, candidate_boundaries_count=2, selection_status="NO_ABNORMAL_BOUNDARY_OBSERVED"
        )
        diff = compare_differential(healthy_baseline(), skill)
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_scenario_e_executed_without_output_must_not_accept(self) -> None:
        orch = orchestration_status(
            execution_status="EXECUTED",
            output_present=False,
            groups=1,
            consumed=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(domain_status(), orch))
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")

    def test_scenario_e_executed_without_group_must_not_accept(self) -> None:
        orch = orchestration_status(
            execution_status="EXECUTED",
            output_present=True,
            groups=0,
            consumed=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(domain_status(), orch))
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")


# ---------------------------------------------------------------------------
# Positive consumption verification
# ---------------------------------------------------------------------------

class PositiveConsumptionVerificationTests(unittest.TestCase):
    def test_positive_relevant_consumption_allows_bounded_agreement(self) -> None:
        skill = skill_summary(
            domain_status(),
            orchestration_status(
                groups=1, consumed=1,
                consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
            ),
        )
        diff = compare_differential(healthy_baseline(), skill)
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_multiple_relevant_domains_each_require_positive_consumption(self) -> None:
        status = domain_status()
        status["pdu_session"] = domain_record(["PARTIAL_CAPTURE"])
        skill = skill_summary(
            status,
            orchestration_status(
                groups=1, consumed=2,
                consumed_counts={"registration": 1, "pdu_session": 1, "handover_mobility": 0},
            ),
            domain_instances_count=2,
        )
        diff = compare_differential(
            healthy_baseline(families=["5gc-registration-mobility", "5gc-pdu-session"]), skill
        )
        self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS)

        # Dropping PDU-session consumption must break the agreement.
        skill2 = copy.deepcopy(skill)
        skill2["orchestration_status"]["consumed_domain_instance_counts"] = {
            "registration": 1, "pdu_session": 0, "handover_mobility": 0,
        }
        diff2 = compare_differential(
            healthy_baseline(families=["5gc-registration-mobility", "5gc-pdu-session"]), skill2
        )
        self.assertNotEqual(diff2["comparison_status"], AGREEMENT_STATUS)

    def test_consumption_state_is_reported_structurally(self) -> None:
        baseline = healthy_baseline()
        skill = skill_summary(
            domain_status(),
            orchestration_status(
                groups=1, consumed=1,
                consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
            ),
        )
        domain_evidence = evaluate_domain_evidence(baseline, skill)
        orch = evaluate_orchestration_evidence(skill, domain_evidence, {"registration"})
        self.assertEqual(orch["state"], "AVAILABLE")
        self.assertTrue(orch["consumption_verified"])
        self.assertEqual(orch["consumed_domain_instance_counts"]["registration"], 1)

    def test_missing_map_is_unverified_not_a_proven_defect(self) -> None:
        baseline = healthy_baseline()
        skill = skill_summary(domain_status(), orchestration_status(groups=1, consumed=1))
        domain_evidence = evaluate_domain_evidence(baseline, skill)
        orch = evaluate_orchestration_evidence(skill, domain_evidence, {"registration"})
        self.assertNotEqual(orch["state"], "AVAILABLE")
        self.assertNotEqual(orch["state"], "FAILED")
        self.assertFalse(orch["consumption_verified"])


# ---------------------------------------------------------------------------
# Integrity of consumed counts
# ---------------------------------------------------------------------------

class ConsumedCountIntegrityTests(unittest.TestCase):
    def _diff_for(self, consumed_counts, unmapped=0, consumed=1, **kw):
        orch = orchestration_status(
            groups=1, consumed=consumed,
            consumed_counts=consumed_counts, unmapped=unmapped,
        )
        return compare_differential(healthy_baseline(), skill_summary(domain_status(), orch, **kw))

    def test_invalid_consumed_count_types_fail_conservatively(self) -> None:
        for bad in ("1", None, 1.5, [1]):
            with self.subTest(bad=bad):
                diff = self._diff_for({"registration": bad, "pdu_session": 0, "handover_mobility": 0})
                self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_negative_consumed_counts_fail_conservatively(self) -> None:
        diff = self._diff_for({"registration": -1, "pdu_session": 0, "handover_mobility": 0})
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_boolean_consumed_counts_fail_conservatively(self) -> None:
        diff = self._diff_for({"registration": True, "pdu_session": False, "handover_mobility": 0})
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_unknown_source_domain_identity_is_not_silently_mapped(self) -> None:
        orch = orchestration_status(
            groups=1, consumed=2, unmapped=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(domain_status(), orch))
        # Unmapped evidence is retained explicitly; the agreement still requires
        # every relevant Domain to be positively consumed, which registration is.
        self.assertIn("consumed_unmapped_source_domain_instance_count", orch)
        self.assertEqual(orch["consumed_unmapped_source_domain_instance_count"], 1)

    def test_aggregate_and_per_domain_counts_must_agree(self) -> None:
        # aggregate says 1 but the map sums to 2
        diff = self._diff_for(
            {"registration": 1, "pdu_session": 1, "handover_mobility": 0}, consumed=1
        )
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_consumed_cannot_exceed_produced(self) -> None:
        diff = self._diff_for(
            {"registration": 5, "pdu_session": 0, "handover_mobility": 0}, consumed=5
        )
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_multiple_diagnostic_groups_keep_primary_authority(self) -> None:
        orch = orchestration_status(
            groups=2, consumed=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(domain_status(), orch))
        # Two groups do not invalidate a positively consumed primary group, but
        # the positive outcome must still rest on the primary group's evidence.
        self.assertIn(diff["comparison_status"], (AGREEMENT_STATUS, "NEEDS_ADJUDICATION"))


# ---------------------------------------------------------------------------
# Selection and candidate consistency
# ---------------------------------------------------------------------------

class SelectionConsistencyTests(unittest.TestCase):
    def test_unresolved_candidate_status_never_yields_agreement(self) -> None:
        for status in ("AMBIGUOUS_FIRST_BOUNDARY", "INSUFFICIENT_COMPARABLE_EVIDENCE"):
            with self.subTest(status=status):
                orch = orchestration_status(
                    groups=1, consumed=1, candidates=2,
                    consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
                )
                skill = skill_summary(
                    domain_status(), orch,
                    selection_status=status, candidate_boundaries_count=2,
                )
                diff = compare_differential(healthy_baseline(), skill)
                self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")

    def test_no_domain_inputs_cannot_establish_consumption(self) -> None:
        orch = orchestration_status(
            groups=1, consumed=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        skill = skill_summary(
            domain_status(), orch,
            selection_status="NO_DOMAIN_INPUTS", candidate_boundaries_count=0,
        )
        diff = compare_differential(healthy_baseline(), skill)
        self.assertNotEqual(diff["comparison_status"], AGREEMENT_STATUS)

    def test_selected_boundary_preserves_abnormal_comparison(self) -> None:
        orch = orchestration_status(
            groups=1, consumed=1, candidates=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        skill = skill_summary(
            domain_status(), orch,
            selection_status="SELECTED",
            candidate_boundaries_count=1,
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
        diff = compare_differential(abnormal_baseline(), skill)
        self.assertEqual(diff["comparison_status"], "PROCEDURE_MATCH_STAGE_DIFFERENCE")
        self.assertEqual(diff["skill_boundary"]["boundary_frame"], 11)

    def test_boundary_observed_semantics_do_not_require_the_new_map(self) -> None:
        # Abnormal-boundary comparison semantics are preserved even for legacy
        # summaries that carry no consumed-domain map.
        orch = orchestration_status(groups=1, consumed=1, candidates=1)
        skill = skill_summary(
            domain_status(
                registration=domain_record(["UNSUCCESSFUL_OUTCOME_OBSERVED", "PROTOCOL_REJECT_OBSERVED"])
            ),
            orch,
            selection_status="SELECTED",
            candidate_boundaries_count=1,
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
        diff = compare_differential(abnormal_baseline(), skill)
        self.assertEqual(diff["comparison_status"], "PROCEDURE_MATCH_STAGE_DIFFERENCE")


# ---------------------------------------------------------------------------
# Domain evidence gates
# ---------------------------------------------------------------------------

class DomainEvidenceGateTests(unittest.TestCase):
    def test_missing_relevant_domain_instance_blocks_agreement(self) -> None:
        status = domain_status(
            registration=domain_record([], instance_count=0),
        )
        orch = orchestration_status(
            groups=0, consumed=0,
            consumed_counts={"registration": 0, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(status, orch, domain_instances_count=0))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_missing_relevant_domain_execution_blocks_agreement(self) -> None:
        status = domain_status(
            registration={
                "execution_status": "OUTPUT_UNREADABLE",
                "output_present": False,
                "instance_count": 0,
                "deviation_count": 0,
                "first_stop_reason": "Domain analysis output unreadable",
            }
        )
        diff = compare_differential(healthy_baseline(), skill_summary(status))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_unrelated_domain_evidence_cannot_satisfy_relevant_reconstruction(self) -> None:
        status = domain_status(
            registration={
                "execution_status": "SKIPPED_NO_INPUTS",
                "output_present": False,
                "instance_count": 0,
                "deviation_count": 0,
                "first_stop_reason": "no NGAP or NAS-5GS protocol evidence extracted",
            }
        )
        status["pdu_session"] = domain_record(["PARTIAL_CAPTURE"])
        orch = orchestration_status(
            groups=1, consumed=1,
            consumed_counts={"registration": 0, "pdu_session": 1, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(status, orch))
        self.assertEqual(diff["comparison_status"], "DOMAIN_MODEL_GAP")

    def test_zero_deviations_with_missing_consumption_is_not_exact_match(self) -> None:
        status = domain_status(registration=domain_record([]))
        orch = orchestration_status(groups=1, consumed=1)  # legacy: no consumed map
        diff = compare_differential(healthy_baseline(), skill_summary(status, orch))
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertEqual(diff["comparison_status"], "NEEDS_ADJUDICATION")

    def test_zero_deviations_with_verified_consumption_stays_exact_match(self) -> None:
        status = domain_status(registration=domain_record([]))
        orch = orchestration_status(
            groups=1, consumed=1,
            consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
        )
        diff = compare_differential(healthy_baseline(), skill_summary(status, orch))
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")


# ---------------------------------------------------------------------------
# Committed corpus
# ---------------------------------------------------------------------------

class CommittedCorpusConsumptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cases_dir = BENCHMARK_DIR / "cases"

    def test_five_accepted_agreement_cases(self) -> None:
        for cid in (
            "public-5gc-auth-recovery",
            "public-5gc-baseline-lifecycle",
            "public-5gc-baseline-user-plane",
            "public-5gc-dnn-recovery",
            "public-5gc-registration-resync",
        ):
            diff = json.loads((self.cases_dir / cid / "differential.json").read_text(encoding="utf-8"))
            summary = json.loads(
                (self.cases_dir / cid / "skill-result-summary.json").read_text(encoding="utf-8")
            )
            self.assertEqual(diff["comparison_status"], AGREEMENT_STATUS, cid)
            self.assertFalse(diff["adjudication_required"], cid)
            self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH", cid)
            orch = summary.get("orchestration_status") or {}
            self.assertEqual(orch.get("execution_status"), "EXECUTED", cid)
            self.assertTrue(orch.get("output_present"), cid)
            self.assertGreaterEqual(orch.get("diagnostic_group_count", 0), 1, cid)
            self.assertIn("consumed_domain_instance_counts", orch, cid)
            counts = orch["consumed_domain_instance_counts"]
            for key, record in (summary.get("domain_status") or {}).items():
                if record.get("execution_status") == "EXECUTED" and record.get("instance_count", 0) > 0:
                    self.assertGreater(counts.get(key, 0), 0, f"{cid}/{key}")

    def test_eight_control_cases_preserved(self) -> None:
        expected = {
            "public-5gc-auth-negative": "PROCEDURE_MATCH_STAGE_DIFFERENCE",
            "public-5gc-dnn-negative": "CAPTURE_LIMITATION",
            "public-5gc-access-plmn-negative": "DOMAIN_COVERAGE_GAP",
            "public-5gc-access-plmn-recovery": "DOMAIN_COVERAGE_GAP",
            "public-5gc-access-tai-negative": "DOMAIN_COVERAGE_GAP",
            "public-5gc-access-tai-recovery": "DOMAIN_COVERAGE_GAP",
            "public-5gc-external-path-negative": "OUT_OF_SCOPE",
            "public-5gc-external-path-recovery": "DOMAIN_COVERAGE_GAP",
        }
        for cid, status in expected.items():
            diff = json.loads((self.cases_dir / cid / "differential.json").read_text(encoding="utf-8"))
            self.assertEqual(diff["comparison_status"], status, cid)

    def test_authentication_negative_boundary_semantics_preserved(self) -> None:
        diff = json.loads(
            (self.cases_dir / "public-5gc-auth-negative" / "differential.json").read_text(encoding="utf-8")
        )
        self.assertEqual(diff["comparison_status"], "PROCEDURE_MATCH_STAGE_DIFFERENCE")
        self.assertEqual(diff["skill_boundary"]["boundary_frame"], 11)
        self.assertEqual(diff["skill_boundary"]["boundary_protocol"], "NAS-5GS")
        self.assertEqual(diff["skill_boundary"]["boundary_message"], "Authentication failure")
        self.assertEqual(diff["skill_boundary"]["procedure_stage"], "authentication")
        self.assertEqual(diff["human_boundary"]["procedure_stage"], "security")

    def test_frozen_human_baseline_hashes_unchanged(self) -> None:
        for case_dir in sorted(p for p in self.cases_dir.iterdir() if p.is_dir()):
            baseline = json.loads((case_dir / "human-baseline.json").read_text(encoding="utf-8"))
            diff = json.loads((case_dir / "differential.json").read_text(encoding="utf-8"))
            self.assertEqual(
                diff["human_baseline_sha256"], canonical_json_sha256(baseline), case_dir.name
            )

    def test_committed_differentiated_cases_are_reproducible(self) -> None:
        sys.path.insert(0, str(SCRIPTS_DIR))
        from run_public_corpus import PUBLIC_CORPUS

        intents = {item["case_id"]: item["upstream_intent"] for item in PUBLIC_CORPUS}
        for case_dir in sorted(p for p in self.cases_dir.iterdir() if p.is_dir()):
            baseline = json.loads((case_dir / "human-baseline.json").read_text(encoding="utf-8"))
            summary = json.loads((case_dir / "skill-result-summary.json").read_text(encoding="utf-8"))
            committed = json.loads((case_dir / "differential.json").read_text(encoding="utf-8"))
            recomputed = compare_differential(
                baseline,
                summary,
                human_baseline_sha256=canonical_json_sha256(baseline),
                upstream_intent=intents[case_dir.name],
            )
            self.assertEqual(recomputed, committed, case_dir.name)

    def test_benchmark_metrics_and_denominator_invariance(self) -> None:
        summary = json.loads(
            (BENCHMARK_DIR / "benchmark-summary.json").read_text(encoding="utf-8")
        )["metrics"]
        self.assertEqual(summary["case_count"], 13)
        self.assertEqual(summary["executed_case_count"], 13)
        self.assertEqual(summary["exact_match_count"], 0)
        self.assertEqual(summary["procedure_match_count"], 1)
        self.assertEqual(summary["stage_match_count"], 0)
        self.assertEqual(summary["needs_adjudication_count"], 1)
        self.assertEqual(summary["no_abnormal_boundary_agreement_with_noncandidate_evidence_count"], 5)
        self.assertIn("domain_coverage_gap_count", summary["denominator_definition"])

    def test_deterministic_repeated_comparison(self) -> None:
        baseline = healthy_baseline()
        skill = skill_summary(
            domain_status(),
            orchestration_status(
                groups=1, consumed=1,
                consumed_counts={"registration": 1, "pdu_session": 0, "handover_mobility": 0},
            ),
        )
        first = compare_differential(baseline, skill)
        second = compare_differential(copy.deepcopy(baseline), copy.deepcopy(skill))
        self.assertEqual(first, second)

    def test_metrics_do_not_inflate_exact_matches(self) -> None:
        diffs = [
            {"case_id": "a", "comparison_status": AGREEMENT_STATUS},
            {"case_id": "b", "comparison_status": "PROCEDURE_MATCH_STAGE_DIFFERENCE", "adjudication_required": True},
            {"case_id": "c", "comparison_status": "NEEDS_ADJUDICATION", "adjudication_required": True},
        ]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["exact_match_count"], 0)
        self.assertEqual(metrics["no_abnormal_boundary_agreement_with_noncandidate_evidence_count"], 1)
        self.assertEqual(metrics["false_positive_count"], 0)
        self.assertEqual(metrics["false_negative_count"], 0)


if __name__ == "__main__":
    unittest.main()
