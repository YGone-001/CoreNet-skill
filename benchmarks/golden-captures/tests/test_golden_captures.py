#!/usr/bin/env python3
"""Comprehensive unit tests for the Golden Capture Benchmark framework.

Covers:
1. JSON Schema validation and forbidden field rejection.
2. Canonical cross-platform JSON semantic hash invariance (LF vs CRLF, indentation, key order, semantic mutations).
3. Evidentiary pipeline health and comparison eligibility.
4. Differential comparator taxonomy (all 15 comparison statuses).
5. Safe out-of-scope and healthy baseline evidence checks.
6. Blocked case semantics and deterministic metric aggregation.
7. Workstation privacy and binary capture safety gates.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

import sys
sys.path.insert(0, str(BENCHMARK_DIR / "scripts"))
sys.path.insert(0, str(ROOT / "scripts"))

from canonical_hash import canonical_json_bytes, canonical_json_sha256
from compare_results import compare_differential, evaluate_pipeline_evidence_health, get_relevant_protocols
from run_capture_pipeline import validate_work_dir_safety
from sanitize_result import sanitize_failure_boundary_result
from summarize_benchmark import calculate_metrics
import importlib.util

validator_path = ROOT / "scripts" / "validate-golden-captures.py"
validator_spec = importlib.util.spec_from_file_location("validate_golden_captures", validator_path)
validator_mod = importlib.util.module_from_spec(validator_spec)
assert validator_spec.loader is not None
validator_spec.loader.exec_module(validator_mod)

check_binary_captures = validator_mod.check_binary_captures
check_forbidden_fields = validator_mod.check_forbidden_fields
check_workstation_paths = validator_mod.check_workstation_paths
validate_golden_captures = validator_mod.validate_golden_captures
validate_json_schema = validator_mod.validate_json_schema


class GoldenCaptureSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        schemas_dir = BENCHMARK_DIR / "schemas"
        self.case_schema = json.loads((schemas_dir / "capture-case.schema.json").read_text(encoding="utf-8"))
        self.baseline_schema = json.loads((schemas_dir / "human-baseline.schema.json").read_text(encoding="utf-8"))
        self.skill_schema = json.loads((schemas_dir / "skill-result-summary.schema.json").read_text(encoding="utf-8"))
        self.diff_schema = json.loads((schemas_dir / "differential-result.schema.json").read_text(encoding="utf-8"))
        self.summary_schema = json.loads((schemas_dir / "benchmark-summary.schema.json").read_text(encoding="utf-8"))

    def test_valid_case_schema(self) -> None:
        valid_case = {
            "case_id": "test-case-1",
            "source_class": "synthetic-test",
            "source_repository": "test/repo",
            "source_commit": "a" * 40,
            "source_capture_path": "captures/test.pcap",
            "capture_sha256": "b" * 64,
            "capture_size_bytes": 1024,
            "capture_packet_count": 10,
        }
        errors = validate_json_schema(valid_case, self.case_schema)
        self.assertEqual(errors, [])

    def test_invalid_case_schema_missing_field(self) -> None:
        invalid_case = {
            "case_id": "test-case-1",
            "source_class": "synthetic-test",
        }
        errors = validate_json_schema(invalid_case, self.case_schema)
        self.assertTrue(len(errors) > 0)

    def test_case_schema_rejects_forbidden_fields(self) -> None:
        bad_case = {
            "case_id": "test-case-1",
            "source_class": "synthetic-test",
            "source_repository": "test/repo",
            "source_commit": "a" * 40,
            "source_capture_path": "captures/test.pcap",
            "capture_sha256": "b" * 64,
            "capture_size_bytes": 1024,
            "capture_packet_count": 10,
            "root_cause": "unsupported DNN configuration",
        }
        errors: list[str] = []
        check_forbidden_fields(bad_case, errors)
        self.assertTrue(any("Forbidden root-cause field 'root_cause'" in e for e in errors))

    def test_valid_baseline_schema(self) -> None:
        valid_baseline = {
            "case_id": "test-case-1",
            "capture_sha256": "b" * 64,
            "capture_scope": {
                "interfaces": ["N1", "N2"],
                "protocols_present": ["NGAP", "NAS-5GS"],
            },
            "analysis_status": "BOUNDARY_OBSERVED",
            "procedure_observations": [
                {
                    "procedure_family": "5gc-registration-mobility",
                    "procedure_stage": "security",
                    "outcome": "REJECT",
                    "first_frame": 1,
                    "last_frame": 10,
                    "evidence_level": "OBSERVED",
                }
            ],
            "first_abnormal_boundary": {
                "procedure_family": "5gc-registration-mobility",
                "procedure_stage": "security",
                "protocol": "NAS-5GS",
                "message_type": "Authentication reject",
                "frame_number": 5,
                "timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
                "reason": "Authentication challenge failed",
            },
            "supporting_evidence": [
                {
                    "frame_number": 5,
                    "protocol": "NAS-5GS",
                    "message_type": "Authentication reject",
                    "description": "Observed reject message",
                    "evidence_level": "OBSERVED",
                }
            ],
            "limitations": [],
            "scope_assessment": {
                "in_corenet_scope": True,
                "interfaces_in_scope": ["N1", "N2"],
                "interfaces_out_of_scope": [],
                "reason": "Signaling on standard interfaces",
            },
            "baseline_confidence": "HIGH",
        }
        errors = validate_json_schema(valid_baseline, self.baseline_schema)
        self.assertEqual(errors, [])


class CanonicalHashPortabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_doc = {
            "case_id": "public-5gc-auth-negative",
            "analysis_status": "BOUNDARY_OBSERVED",
            "capture_sha256": "70cc13c537a745625fc59d974653f5b819874a8f1a74b14db416dc97a91801c7",
            "capture_scope": {
                "interfaces": ["N1", "N2"],
                "protocols_present": ["SCTP", "NGAP", "NAS-5GS"],
            },
            "first_abnormal_boundary": {
                "frame_number": 11,
                "message_type": "Authentication failure",
                "procedure_family": "5gc-registration-mobility",
                "procedure_stage": "security",
                "protocol": "NAS-5GS",
                "reason": "MAC failure",
                "timestamp": "1785304677.839841000",
                "evidence_level": "OBSERVED",
            },
            "baseline_confidence": "HIGH",
        }

    def test_lf_and_crlf_hash_identical(self) -> None:
        lf_str = json.dumps(self.sample_doc, indent=2)
        crlf_str = lf_str.replace("\n", "\r\n")

        hash_lf = canonical_json_sha256(lf_str)
        hash_crlf = canonical_json_sha256(crlf_str)
        self.assertEqual(hash_lf, hash_crlf)
        self.assertEqual(len(hash_lf), 64)

    def test_whitespace_and_indentation_invariance(self) -> None:
        compact_str = json.dumps(self.sample_doc, separators=(",", ":"))
        four_space_str = json.dumps(self.sample_doc, indent=4)
        tab_str = json.dumps(self.sample_doc, indent="\t")

        self.assertEqual(canonical_json_sha256(compact_str), canonical_json_sha256(four_space_str))
        self.assertEqual(canonical_json_sha256(compact_str), canonical_json_sha256(tab_str))

    def test_key_reordering_invariance(self) -> None:
        reordered = {k: self.sample_doc[k] for k in reversed(list(self.sample_doc.keys()))}
        self.assertEqual(canonical_json_sha256(self.sample_doc), canonical_json_sha256(reordered))

    def test_semantic_field_mutation_changes_hash(self) -> None:
        mutated = copy.deepcopy(self.sample_doc)
        mutated["baseline_confidence"] = "MEDIUM"
        self.assertNotEqual(canonical_json_sha256(self.sample_doc), canonical_json_sha256(mutated))

    def test_frame_number_mutation_changes_hash(self) -> None:
        mutated = copy.deepcopy(self.sample_doc)
        mutated["first_abnormal_boundary"]["frame_number"] = 12
        self.assertNotEqual(canonical_json_sha256(self.sample_doc), canonical_json_sha256(mutated))

    def test_boundary_status_mutation_changes_hash(self) -> None:
        mutated = copy.deepcopy(self.sample_doc)
        mutated["analysis_status"] = "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED"
        self.assertNotEqual(canonical_json_sha256(self.sample_doc), canonical_json_sha256(mutated))


class GoldenCaptureDifferentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base_human = {
            "case_id": "diff-test",
            "capture_sha256": "c" * 64,
            "analysis_status": "BOUNDARY_OBSERVED",
            "capture_scope": {
                "interfaces": ["N1", "N2"],
                "protocols_present": ["NGAP", "NAS-5GS"],
            },
            "procedure_observations": [],
            "first_abnormal_boundary": {
                "procedure_family": "5gc-registration-mobility",
                "procedure_stage": "security",
                "protocol": "NAS-5GS",
                "message_type": "Authentication reject",
                "frame_number": 12,
                "timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
                "reason": "Auth reject",
            },
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

    def test_exact_match(self) -> None:
        skill = {
            "case_id": "diff-test",
            "selection_status": "FIRST_ABNORMAL_BOUNDARY_SELECTED",
            "selected_boundary": {
                "selected_source_domain": "5gc-registration-mobility",
                "selected_procedure_family": "5gc-registration-mobility",
                "selected_procedure_stage": "security",
                "deviation_type": "PROTOCOL_REJECT_OBSERVED",
                "boundary_protocol": "NAS-5GS",
                "boundary_message": "Authentication reject",
                "boundary_frame": 12,
                "boundary_timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
            },
            "boundary_confidence": "HIGH",
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertEqual(diff["comparison_eligibility"], "ELIGIBLE")
        self.assertEqual(diff["layer_attribution"], "NONE")
        self.assertFalse(diff["adjudication_required"])

    def test_boundary_frame_difference(self) -> None:
        skill = {
            "case_id": "diff-test",
            "selection_status": "FIRST_ABNORMAL_BOUNDARY_SELECTED",
            "selected_boundary": {
                "selected_source_domain": "5gc-registration-mobility",
                "selected_procedure_family": "5gc-registration-mobility",
                "selected_procedure_stage": "security",
                "deviation_type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "boundary_protocol": "NAS-5GS",
                "boundary_message": "Authentication failure",
                "boundary_frame": 11,
                "boundary_timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
            },
            "boundary_confidence": "HIGH",
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "BOUNDARY_FRAME_DIFFERENCE")
        self.assertEqual(diff["frame_delta"], 1)
        self.assertEqual(diff["layer_attribution"], "DOMAIN")

    def test_procedure_match_stage_difference(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["first_abnormal_boundary"]["procedure_stage"] = "authentication"
        skill = {
            "case_id": "diff-test",
            "selection_status": "FIRST_ABNORMAL_BOUNDARY_SELECTED",
            "selected_boundary": {
                "selected_source_domain": "5gc-registration-mobility",
                "selected_procedure_family": "5gc-registration-mobility",
                "selected_procedure_stage": "security_mode",
                "deviation_type": "PROTOCOL_REJECT_OBSERVED",
                "boundary_protocol": "NAS-5GS",
                "boundary_message": "Security mode reject",
                "boundary_frame": 25,
                "boundary_timestamp": "2026-07-29T00:00:00Z",
                "evidence_level": "OBSERVED",
            },
            "boundary_confidence": "HIGH",
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "PROCEDURE_MATCH_STAGE_DIFFERENCE")
        self.assertTrue(diff["adjudication_required"])

    def test_false_positive_on_healthy_baseline(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED"
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "FIRST_ABNORMAL_BOUNDARY_SELECTED",
            "selected_boundary": {
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
            "boundary_confidence": "HIGH",
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "FALSE_POSITIVE")
        self.assertTrue(diff["adjudication_required"])

    def test_false_negative_when_evidence_healthy(self) -> None:
        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "FALSE_NEGATIVE")
        self.assertEqual(diff["layer_attribution"], "DOMAIN")
        self.assertTrue(diff["adjudication_required"])

    def test_false_healthy_match_rejected_when_protocol_extraction_failed(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED"
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 0,
            "protocol_status": {
                "ngap": "ERROR_4",
                "nas-5gs": "ERROR_5",
            },
        }
        diff = compare_differential(human, skill)
        self.assertNotEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertEqual(diff["comparison_status"], "PROTOCOL_COVERAGE_GAP")
        self.assertEqual(diff["comparison_eligibility"], "INELIGIBLE")
        self.assertEqual(diff["layer_attribution"], "PROTOCOL")

    def test_healthy_match_accepted_when_pipeline_evidence_healthy(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "NO_SUPPORTED_ABNORMAL_BOUNDARY_OBSERVED"
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "ngap": "SUCCESS",
                "nas-5gs": "SUCCESS",
            },
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")
        self.assertEqual(diff["comparison_eligibility"], "ELIGIBLE")
        self.assertEqual(diff["layer_attribution"], "NONE")

    def test_out_of_scope_negative_when_in_scope_protocol_failed(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "OUTSIDE_CURRENT_CORENET_SCOPE"
        human["capture_scope"] = {
            "interfaces": ["N3", "N6"],
            "protocols_present": ["PFCP", "GTP-U", "ICMP"],
        }
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "domain_instances_count": 0,
            "protocol_status": {
                "pfcp": "ERROR_4",
                "gtpu": "ERROR_4",
            },
        }
        diff = compare_differential(human, skill)
        self.assertNotEqual(diff["comparison_status"], "OUT_OF_SCOPE")
        self.assertEqual(diff["comparison_status"], "PROTOCOL_COVERAGE_GAP")
        self.assertEqual(diff["comparison_eligibility"], "INELIGIBLE")
        self.assertEqual(diff["layer_attribution"], "PROTOCOL")

    def test_out_of_scope_positive_when_in_scope_evidence_healthy(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "OUTSIDE_CURRENT_CORENET_SCOPE"
        human["capture_scope"] = {
            "interfaces": ["N3", "N6"],
            "protocols_present": ["PFCP", "GTP-U", "ICMP"],
        }
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": ["N6 external routing unsupported"],
            "additional_evidence_needed": [],
            "domain_instances_count": 1,
            "protocol_status": {
                "pfcp": "SUCCESS",
                "gtpu": "SUCCESS",
            },
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "OUT_OF_SCOPE")
        self.assertEqual(diff["comparison_eligibility"], "ELIGIBLE")
        self.assertEqual(diff["layer_attribution"], "OUT_OF_SCOPE")

    def test_baseline_unsupported_status(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "HUMAN_BASELINE_UNSUPPORTED"
        human["baseline_supported"] = False

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "HUMAN_BASELINE_UNSUPPORTED")
        self.assertEqual(diff["layer_attribution"], "BASELINE")
        self.assertTrue(diff["adjudication_required"])

    def test_synthetic_taxonomy_states(self) -> None:
        # Unsafe correlation
        skill_unsafe = {"case_id": "diff-test", "unsafe_correlation": True}
        diff = compare_differential(self.base_human, skill_unsafe)
        self.assertEqual(diff["comparison_status"], "UNSAFE_CORRELATION")
        self.assertEqual(diff["layer_attribution"], "CORRELATION")

        # Correlation gap
        skill_corrgap = {"case_id": "diff-test", "correlation_gap": True}
        diff = compare_differential(self.base_human, skill_corrgap)
        self.assertEqual(diff["comparison_status"], "CORRELATION_GAP")
        self.assertEqual(diff["layer_attribution"], "CORRELATION")

        # Acceptable difference
        skill_accdiff = {"case_id": "diff-test", "acceptable_difference": True}
        diff = compare_differential(self.base_human, skill_accdiff)
        self.assertEqual(diff["comparison_status"], "ACCEPTABLE_DIFFERENCE")
        self.assertEqual(diff["layer_attribution"], "DOMAIN")


class GoldenCaptureMetricsTests(unittest.TestCase):
    def test_metrics_denominator_excludes_out_of_scope_and_limitations(self) -> None:
        diffs = [
            {"case_id": "c1", "comparison_status": "EXACT_MATCH", "layer_attribution": "NONE", "frame_delta": 0},
            {"case_id": "c2", "comparison_status": "EXACT_MATCH", "layer_attribution": "NONE", "frame_delta": 0},
            {"case_id": "c3", "comparison_status": "OUT_OF_SCOPE", "layer_attribution": "OUT_OF_SCOPE", "frame_delta": None},
            {"case_id": "c4", "comparison_status": "CAPTURE_LIMITATION", "layer_attribution": "CAPTURE", "frame_delta": None},
            {"case_id": "c5", "comparison_status": "FALSE_POSITIVE", "layer_attribution": "DOMAIN", "frame_delta": None, "adjudication_required": True},
        ]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["case_count"], 5)
        self.assertEqual(metrics["out_of_scope_count"], 1)
        self.assertEqual(metrics["capture_limitation_count"], 1)
        self.assertEqual(metrics["exact_match_count"], 2)
        self.assertEqual(metrics["false_positive_count"], 1)

        # In-scope evaluated = 5 - (1 + 1 + 0) = 3 cases (c1, c2, c5)
        # Exact match rate = 2 / 3 = 0.6667
        self.assertEqual(metrics["exact_match_rate"], 0.6667)
        self.assertEqual(metrics["exact_frame_match_count"], 2)

    def test_blocked_case_count_semantics(self) -> None:
        diffs = [
            {"case_id": "c1", "comparison_status": "EXACT_MATCH", "comparison_eligibility": "ELIGIBLE"},
            {"case_id": "c2", "comparison_status": "PROTOCOL_COVERAGE_GAP", "comparison_eligibility": "INELIGIBLE"},
            {"case_id": "c3", "comparison_status": "BLOCKED", "comparison_eligibility": "BLOCKED"},
        ]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["case_count"], 3)
        self.assertEqual(metrics["blocked_case_count"], 1)
        self.assertEqual(metrics["executed_case_count"], 2)
        self.assertEqual(metrics["exact_match_count"], 1)

    def test_summary_deterministic_ordering_invariant_to_input_order(self) -> None:
        diffs_forward = [
            {"case_id": "case-a", "comparison_status": "EXACT_MATCH"},
            {"case_id": "case-b", "comparison_status": "PROTOCOL_COVERAGE_GAP"},
            {"case_id": "case-c", "comparison_status": "OUT_OF_SCOPE"},
        ]
        diffs_reversed = list(reversed(diffs_forward))

        metrics1, cases1 = calculate_metrics(diffs_forward)
        metrics2, cases2 = calculate_metrics(diffs_reversed)

        self.assertEqual(metrics1, metrics2)
        self.assertEqual([c["case_id"] for c in cases1], ["case-a", "case-b", "case-c"])
        self.assertEqual([c["case_id"] for c in cases2], ["case-a", "case-b", "case-c"])

    def test_taxonomy_metrics_complete_coverage(self) -> None:
        all_statuses = [
            ("EXACT_MATCH", "exact_match_count"),
            ("BOUNDARY_FRAME_DIFFERENCE", "procedure_match_count"),
            ("PROCEDURE_MATCH_STAGE_DIFFERENCE", "procedure_match_count"),
            ("ACCEPTABLE_DIFFERENCE", "acceptable_difference_count"),
            ("FALSE_POSITIVE", "false_positive_count"),
            ("FALSE_NEGATIVE", "false_negative_count"),
            ("UNSAFE_CORRELATION", "unsafe_correlation_count"),
            ("PROTOCOL_COVERAGE_GAP", "protocol_coverage_gap_count"),
            ("CORRELATION_GAP", "correlation_gap_count"),
            ("DOMAIN_MODEL_GAP", "domain_model_gap_count"),
            ("ORCHESTRATION_GAP", "orchestration_gap_count"),
            ("CAPTURE_LIMITATION", "capture_limitation_count"),
            ("OUT_OF_SCOPE", "out_of_scope_count"),
            ("HUMAN_BASELINE_UNSUPPORTED", "human_baseline_unsupported_count"),
        ]
        diffs = [{"case_id": f"c_{idx}", "comparison_status": st} for idx, (st, _) in enumerate(all_statuses)]
        metrics, _ = calculate_metrics(diffs)
        self.assertEqual(metrics["case_count"], len(all_statuses))
        for _, metric_field in all_statuses:
            self.assertGreaterEqual(metrics[metric_field], 1)


class GoldenCaptureSafetyTests(unittest.TestCase):
    def test_refuse_workdir_inside_repo(self) -> None:
        repo_subpath = ROOT / "benchmarks" / "golden-captures" / "work"
        with self.assertRaises(ValueError) as ctx:
            validate_work_dir_safety(repo_subpath, allow_repo_workdir=False)
        self.assertIn("is located inside the CoreNet repository", str(ctx.exception))

    def test_allow_workdir_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as external_temp:
            ext_path = Path(external_temp)
            validate_work_dir_safety(ext_path, allow_repo_workdir=False)

    def test_detect_workstation_paths(self) -> None:
        sample_text = '{"log": "C:\\\\Users\\\\JohnDoe\\\\captures\\\\file.pcap"}'
        errors: list[str] = []
        check_workstation_paths(sample_text, Path("test.json"), errors)
        self.assertTrue(len(errors) > 0)

    def test_detect_binary_capture_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            pcap_file = td / "test.pcap"
            pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1")
            errors: list[str] = []
            check_binary_captures(td, errors)
            self.assertTrue(len(errors) > 0)

    def test_baseline_mutation_rejected_by_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            td = Path(temp_dir)
            cases_dir = td / "cases" / "mutated-case"
            cases_dir.mkdir(parents=True)

            baseline_data = {
                "case_id": "mutated-case",
                "capture_sha256": "a" * 64,
                "capture_scope": {"interfaces": ["N1"], "protocols_present": ["NAS-5GS"]},
                "analysis_status": "BOUNDARY_OBSERVED",
                "procedure_observations": [],
                "first_abnormal_boundary": {
                    "frame_number": 10,
                    "message_type": "Registration reject",
                    "procedure_family": "5gc-registration-mobility",
                    "procedure_stage": "registration",
                    "protocol": "NAS-5GS",
                    "reason": "Rejected",
                    "timestamp": "2026-07-29T00:00:00Z",
                    "evidence_level": "OBSERVED",
                },
                "supporting_evidence": [],
                "limitations": [],
                "scope_assessment": {"in_corenet_scope": True, "interfaces_in_scope": ["N1"], "interfaces_out_of_scope": [], "reason": "N1"},
                "baseline_confidence": "HIGH",
            }
            original_hash = canonical_json_sha256(baseline_data)

            # Mutate baseline frame number
            mutated_baseline = copy.deepcopy(baseline_data)
            mutated_baseline["first_abnormal_boundary"]["frame_number"] = 99

            (cases_dir / "human-baseline.json").write_text(json.dumps(mutated_baseline), encoding="utf-8")
            diff_data = {
                "case_id": "mutated-case",
                "human_baseline_sha256": original_hash,  # stale hash
                "comparison_status": "PROTOCOL_COVERAGE_GAP",
                "comparison_eligibility": "INELIGIBLE",
                "layer_attribution": "PROTOCOL",
                "human_boundary": None,
                "skill_boundary": None,
                "evidence_overlap": False,
                "frame_delta": None,
                "capture_limitations": [],
                "baseline_supported": True,
                "adjudication_required": False,
                "upstream_intent_match": "NOT_EVALUATED",
                "notes": [],
                "recommended_next_action": "NO_CHANGE",
            }
            (cases_dir / "differential.json").write_text(json.dumps(diff_data), encoding="utf-8")

            # Check that validator catches the hash mismatch
            computed_sha = canonical_json_sha256((cases_dir / "human-baseline.json").read_text(encoding="utf-8"))
            self.assertNotEqual(original_hash, computed_sha)


if __name__ == "__main__":
    unittest.main()
