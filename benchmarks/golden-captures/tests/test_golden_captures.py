#!/usr/bin/env python3
"""Comprehensive unit tests for the Golden Capture Benchmark framework."""

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

from compare_results import compare_differential
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
            # missing capture_sha256 and others
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


class GoldenCaptureDifferentialTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base_human = {
            "case_id": "diff-test",
            "capture_sha256": "c" * 64,
            "analysis_status": "BOUNDARY_OBSERVED",
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
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "EXACT_MATCH")
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
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "FALSE_POSITIVE")
        self.assertTrue(diff["adjudication_required"])

    def test_false_negative(self) -> None:
        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "FALSE_NEGATIVE")
        self.assertTrue(diff["adjudication_required"])

    def test_protocol_coverage_gap_lowest_layer_attribution(self) -> None:
        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": [],
            "additional_evidence_needed": [],
            "protocol_status": {
                "ngap": "ERROR_4",
                "nas-5gs": "MISSING_MESSAGE_TYPE",
            },
        }
        diff = compare_differential(self.base_human, skill)
        self.assertEqual(diff["comparison_status"], "PROTOCOL_COVERAGE_GAP")
        self.assertEqual(diff["layer_attribution"], "PROTOCOL")
        self.assertEqual(diff["recommended_next_action"], "ADD_PROTOCOL_COVERAGE")
        self.assertFalse(diff["adjudication_required"])

    def test_out_of_scope_conservative_safety(self) -> None:
        human = copy.deepcopy(self.base_human)
        human["analysis_status"] = "OUTSIDE_CURRENT_CORENET_SCOPE"
        human["first_abnormal_boundary"] = None

        skill = {
            "case_id": "diff-test",
            "selection_status": "NO_ABNORMAL_BOUNDARY_OBSERVED",
            "selected_boundary": None,
            "boundary_confidence": None,
            "evidence_limitations": ["No Domain instances formed"],
            "additional_evidence_needed": [],
        }
        diff = compare_differential(human, skill)
        self.assertEqual(diff["comparison_status"], "OUT_OF_SCOPE")
        self.assertEqual(diff["layer_attribution"], "OUT_OF_SCOPE")
        self.assertFalse(diff["adjudication_required"])


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


class GoldenCaptureSafetyTests(unittest.TestCase):
    def test_refuse_workdir_inside_repo(self) -> None:
        repo_subpath = ROOT / "benchmarks" / "golden-captures" / "work"
        with self.assertRaises(ValueError) as ctx:
            validate_work_dir_safety(repo_subpath, allow_repo_workdir=False)
        self.assertIn("is located inside the CoreNet repository", str(ctx.exception))

    def test_allow_workdir_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as external_temp:
            ext_path = Path(external_temp)
            # Should not raise
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


if __name__ == "__main__":
    unittest.main()
