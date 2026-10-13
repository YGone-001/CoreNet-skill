#!/usr/bin/env python3
"""Regression tests for the Golden Capture selected-boundary sanitizer.

Exercises the actual ``sanitize_failure_boundary_result`` function against the
authoritative nested Orchestration contract::

    diagnostic_groups[]
      selected_boundary
        candidate_id
        boundary_ref
          source_domain
          procedure_family
          procedure_stage
          deviation_type
          evidence_level
          boundary_anchor
            frame_number
            timestamp
            protocol
            message_type

The sanitizer must reproduce the selected candidate's real provenance, never
fabricate a frame-1 anchor or ``UNKNOWN`` identities, and fail loudly when a
``SELECTED`` result violates the frame-anchor or identity contract.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_DIR = ROOT / "benchmarks" / "golden-captures"

sys.path.insert(0, str(BENCHMARK_DIR / "scripts"))

from sanitize_result import SanitizeError, sanitize_failure_boundary_result

validator_path = ROOT / "scripts" / "validate-golden-captures.py"
validator_spec = importlib.util.spec_from_file_location("validate_golden_captures", validator_path)
validator_mod = importlib.util.module_from_spec(validator_spec)
assert validator_spec.loader is not None
validator_spec.loader.exec_module(validator_mod)
validate_json_schema = validator_mod.validate_json_schema

SKILL_SCHEMA_PATH = BENCHMARK_DIR / "schemas" / "skill-result-summary.schema.json"
SKILL_SCHEMA = json.loads(SKILL_SCHEMA_PATH.read_text(encoding="utf-8"))


def make_candidate(
    candidate_id: str,
    *,
    source_domain: str = "5gc-registration-mobility",
    procedure_family: str = "5gc-registration-mobility",
    procedure_stage: str | None = "security",
    deviation_type: str = "PROTOCOL_REJECT_OBSERVED",
    evidence_level: str = "OBSERVED",
    frame: int | None = 11,
    protocol: str = "NAS-5GS",
    message_type: str = "Authentication failure",
    timestamp: str = "1785304677.839841000",
) -> dict:
    """Build an authoritative boundary-ref candidate object."""
    return {
        "candidate_id": candidate_id,
        "source_domain": source_domain,
        "source_instance_id": "reg-instance-1",
        "source_attempt_id": None,
        "mobility_attempt_family": None,
        "procedure_family": procedure_family,
        "procedure_stage": procedure_stage,
        "deviation_type": deviation_type,
        "description": "Authentication challenge failed",
        "evidence_level": evidence_level,
        "boundary_anchor": {
            "capture_file": "fault.pcap",
            "frame_number": frame,
            "timestamp": timestamp,
            "protocol": protocol,
            "message_type": message_type,
        },
        "supporting_evidence": {
            "source_deviation": {},
            "source_observation_window": None,
            "source_terminal": {},
        },
        "ordering_basis": {
            "frame_number": frame,
            "observation_window": None,
            "stage_position": None,
        },
        "selectability": "SELECTABLE",
        "limitations": [],
    }


def make_group(
    selection_status: str = "SELECTED",
    selected_boundary=None,
    candidates=None,
):
    """Build one authoritative diagnostic group."""
    return {
        "diagnostic_id": "diag-0",
        "selection_status": selection_status,
        "selected_boundary": selected_boundary,
        "candidate_boundaries": candidates if candidates is not None else [],
        "boundary_confidence": "HIGH",
        "evidence_limitations": [],
        "additional_evidence_needed": [],
        "source_domain_instances": [],
    }


def make_raw(group) -> dict:
    return {"diagnostic_groups": [group]}


def selected_group(candidate, candidates) -> dict:
    return make_group(
        selection_status="SELECTED",
        selected_boundary={
            "candidate_id": candidate["candidate_id"],
            "boundary_ref": candidate,
        },
        candidates=candidates,
    )


class SanitizeSelectedBoundaryTests(unittest.TestCase):
    def test_valid_nested_boundary_ref(self) -> None:
        candidate = make_candidate("0-cand-1")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "public-5gc-auth-negative"
        )
        self.assertEqual(result["selection_status"], "SELECTED")
        self.assertIsInstance(result["selected_boundary"], dict)
        self.assertEqual(result["selected_boundary"]["boundary_frame"], 11)

    def test_exact_source_domain_extraction(self) -> None:
        candidate = make_candidate("0-cand-1", source_domain="5gc-pdu-session")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-domain"
        )
        self.assertEqual(
            result["selected_boundary"]["selected_source_domain"], "5gc-pdu-session"
        )

    def test_exact_procedure_family_extraction(self) -> None:
        candidate = make_candidate("0-cand-1", procedure_family="5gc-registration-mobility")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-family"
        )
        self.assertEqual(
            result["selected_boundary"]["selected_procedure_family"],
            "5gc-registration-mobility",
        )

    def test_nullable_procedure_stage_preserved(self) -> None:
        candidate = make_candidate("0-cand-1", procedure_stage=None)
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-stage-null"
        )
        self.assertIsNone(result["selected_boundary"]["selected_procedure_stage"])

    def test_actual_frame_number_extraction(self) -> None:
        candidate = make_candidate("0-cand-1", frame=11)
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-frame"
        )
        self.assertEqual(result["selected_boundary"]["boundary_frame"], 11)

    def test_protocol_identity_preserved(self) -> None:
        candidate = make_candidate("0-cand-1", protocol="NAS-5GS")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-protocol"
        )
        self.assertEqual(result["selected_boundary"]["boundary_protocol"], "NAS-5GS")

    def test_message_type_preserved(self) -> None:
        candidate = make_candidate("0-cand-1", message_type="Authentication failure")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-message"
        )
        self.assertEqual(result["selected_boundary"]["boundary_message"], "Authentication failure")

    def test_evidence_level_preserved(self) -> None:
        candidate = make_candidate("0-cand-1", evidence_level="OBSERVED")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-evidence"
        )
        self.assertEqual(result["selected_boundary"]["evidence_level"], "OBSERVED")

    def test_selected_candidate_identity_consistency(self) -> None:
        # Two candidates; the selected one is the second, not the first.
        first = make_candidate("0-cand-1", frame=20, message_type="Authentication reject")
        selected = make_candidate("0-cand-2", frame=11, message_type="Authentication failure")
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(selected, [first, selected])), "test-candidate-id"
        )
        self.assertEqual(result["selected_boundary"]["boundary_frame"], 11)
        self.assertEqual(result["selected_boundary"]["boundary_message"], "Authentication failure")

    def test_candidate_id_must_exist_in_candidate_boundaries(self) -> None:
        candidate = make_candidate("0-cand-unknown")
        group = selected_group(candidate, [make_candidate("0-cand-other")])
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-missing-candidate")

    def test_no_default_frame_one_fallback(self) -> None:
        # A window-only candidate has no frame anchor; the sanitizer must never
        # substitute frame 1.
        candidate = make_candidate("0-cand-1", frame=None, protocol=None, message_type=None)
        group = selected_group(candidate, [candidate])
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-no-frame-fallback")

    def test_missing_boundary_ref_fails(self) -> None:
        group = make_group(
            selection_status="SELECTED",
            selected_boundary={"candidate_id": "0-cand-1"},
            candidates=[make_candidate("0-cand-1")],
        )
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-missing-boundary-ref")

    def test_missing_boundary_anchor_fails(self) -> None:
        candidate = make_candidate("0-cand-1")
        candidate.pop("boundary_anchor")
        group = selected_group(candidate, [candidate])
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-missing-anchor")

    def test_missing_source_domain_fails(self) -> None:
        candidate = make_candidate("0-cand-1", source_domain="")
        group = selected_group(candidate, [candidate])
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-missing-domain")

    def test_missing_procedure_family_fails(self) -> None:
        candidate = make_candidate("0-cand-1", procedure_family=None)
        group = selected_group(candidate, [candidate])
        with self.assertRaises(SanitizeError):
            sanitize_failure_boundary_result(make_raw(group), "test-missing-family")

    def test_ambiguous_selection_has_no_selected_boundary(self) -> None:
        candidate = make_candidate("0-cand-1")
        group = make_group(
            selection_status="AMBIGUOUS_FIRST_BOUNDARY",
            selected_boundary=None,
            candidates=[candidate],
        )
        result = sanitize_failure_boundary_result(make_raw(group), "test-ambiguous")
        self.assertEqual(result["selection_status"], "AMBIGUOUS_FIRST_BOUNDARY")
        self.assertIsNone(result["selected_boundary"])

    def test_no_abnormal_selection_has_no_selected_boundary(self) -> None:
        group = make_group(
            selection_status="NO_ABNORMAL_BOUNDARY_OBSERVED",
            selected_boundary=None,
            candidates=[],
        )
        result = sanitize_failure_boundary_result(make_raw(group), "test-no-abnormal")
        self.assertEqual(result["selection_status"], "NO_ABNORMAL_BOUNDARY_OBSERVED")
        self.assertIsNone(result["selected_boundary"])

    def test_invalid_frame_number_rejected(self) -> None:
        for bad_frame in (0, -1, 0.5, "11", True, None):
            candidate = make_candidate("0-cand-1", frame=bad_frame)
            group = selected_group(candidate, [candidate])
            with self.assertRaises(SanitizeError):
                sanitize_failure_boundary_result(make_raw(group), "test-invalid-frame")

    def test_frame_11_authentication_failure_preserved(self) -> None:
        candidate = make_candidate(
            "0-cand-1",
            frame=11,
            message_type="Authentication failure",
            protocol="NAS-5GS",
            procedure_stage="security",
            deviation_type="PROTOCOL_REJECT_OBSERVED",
        )
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "public-5gc-auth-negative"
        )
        boundary = result["selected_boundary"]
        self.assertEqual(boundary["boundary_frame"], 11)
        self.assertEqual(boundary["boundary_message"], "Authentication failure")
        self.assertEqual(boundary["boundary_protocol"], "NAS-5GS")
        self.assertEqual(boundary["deviation_type"], "PROTOCOL_REJECT_OBSERVED")
        self.assertEqual(boundary["selected_procedure_stage"], "security")
        self.assertEqual(boundary["evidence_level"], "OBSERVED")

    def test_frame_41_recovered_intermediate_candidate_preserved(self) -> None:
        candidate = make_candidate(
            "0-cand-1",
            frame=41,
            message_type="Authentication failure",
            protocol="NAS-5GS",
            procedure_stage=None,
        )
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "public-5gc-registration-resync"
        )
        boundary = result["selected_boundary"]
        self.assertEqual(boundary["boundary_frame"], 41)
        self.assertEqual(boundary["boundary_message"], "Authentication failure")
        self.assertIsNone(boundary["selected_procedure_stage"])

    def test_sanitized_output_satisfies_schema(self) -> None:
        candidate = make_candidate("0-cand-1", procedure_stage=None)
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "public-5gc-auth-negative"
        )
        errors = validate_json_schema(result, SKILL_SCHEMA, "skill-summary")
        self.assertEqual(errors, [])

    def test_no_sensitive_identifiers_in_output(self) -> None:
        candidate = make_candidate("0-cand-1")
        candidate["source_instance_id"] = "310150123456789"
        candidate["supporting_evidence"]["source_deviation"] = {
            "imsi": "310150123456789",
            "subscriber_secret": "secret-material",
        }
        result = sanitize_failure_boundary_result(
            make_raw(selected_group(candidate, [candidate])), "test-sensitive"
        )
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("310150123456789", serialized)
        self.assertNotIn("secret-material", serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)