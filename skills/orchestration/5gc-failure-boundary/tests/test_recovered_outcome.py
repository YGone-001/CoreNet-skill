"""Synthetic regression tests for Orchestration non-candidate classification of recovered deviations.

These tests verify that RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED deviations from
the Registration Domain are classified as non-candidate supporting evidence by
the Orchestration model, while UNSUCCESSFUL_OUTCOME_OBSERVED remains
candidate-eligible.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
sys.path.insert(0, str(SCRIPTS))

import failure_boundary_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


ANALYZE = load_script("analyze_failure_boundary")


def _event_ref(frame: int, message_type: str, protocol: str = "NAS-5GS") -> dict:
    return {
        "capture_file": "reg.pcapng",
        "evidence_level": "OBSERVED",
        "field_name": None,
        "frame_number": frame,
        "kind": "EVENT",
        "message_type": message_type,
        "protocol": protocol,
        "stage_id": None,
        "timestamp": f"2024-01-02T03:04:{frame:02d}.00Z",
        "window_first_frame": None,
        "window_last_frame": None,
    }


def _registration_analysis(deviation_type: str, evidence_refs: list[dict]) -> dict:
    """Build a minimal Registration Domain analysis with one deviation."""
    return {
        "analysis_version": "0.2.5",
        "procedure_family": "5gc-registration-mobility",
        "correlation_conflicts": [],
        "unbound_records": [],
        "analyses": [
            {
                "instance_id": "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                "procedure_instance": {
                    "identifier_basis": "DERIVED",
                    "instance_id": "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                    "note": "Local analysis identifier",
                },
                "context": {
                    "association": "sctp-assoc-0",
                    "capture_file": "reg.pcapng",
                    "ngap_context": {
                        "amf_ue_ngap_id": 2,
                        "association": "sctp-assoc-0",
                        "ran_ue_ngap_id": 1,
                    },
                },
                "observation_window": {
                    "first_frame": 10,
                    "first_timestamp": "2024-01-02T03:04:10.00Z",
                    "last_frame": 18,
                    "last_timestamp": "2024-01-02T03:04:18.00Z",
                },
                "terminal": {
                    "evidence_level": "OBSERVED",
                    "frame_number": 18,
                    "message_type": "Registration complete",
                    "observation": "REGISTRATION_COMPLETE_OBSERVED",
                    "timestamp": "2024-01-02T03:04:18.00Z",
                },
                "stage_records": [
                    {
                        "confidence": "MEDIUM",
                        "evidence_basis": "OBSERVED",
                        "expected_evidence": [],
                        "limitations": [],
                        "missing_evidence": [],
                        "observation_group": "reg.pcapng",
                        "observed_evidence": ["NAS-5GS Registration request observed at frame 10"],
                        "procedure_name": "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                        "procedure_version": "0.2.5",
                        "stage": {
                            "expected_message_types": ["InitialUEMessage", "Registration request"],
                            "expected_protocols": ["NAS-5GS", "NGAP"],
                            "stage_id": "registration-initiation",
                            "stage_name": "Registration initiation",
                        },
                    },
                ],
                "deviations": [
                    {
                        "type": deviation_type,
                        "stage_id": None,
                        "description": f"Deviation {deviation_type} at frame 12",
                        "evidence_level": "OBSERVED",
                        "limitation": "Procedure evidence",
                        "evidence_refs": evidence_refs,
                    },
                ],
                "field_findings": [],
                "confidence": "MEDIUM",
                "events": [],
            },
        ],
    }


def _run_orchestration(analysis: dict) -> dict:
    """Run the Orchestration model on a single Registration analysis."""
    with tempfile.TemporaryDirectory() as d:
        input_dir = Path(d) / "input"
        input_dir.mkdir()
        (input_dir / "registration-analysis.json").write_text(
            json.dumps(analysis, indent=2), encoding="utf-8"
        )
        output_path = Path(d) / "output.json"
        rc = ANALYZE.main(["--input-dir", str(input_dir), "--output", str(output_path), "--force"])
        assert rc == 0, f"Orchestration analysis failed with rc={rc}"
        return json.loads(output_path.read_text(encoding="utf-8"))


RECOVERED_REFS = [
    _event_ref(12, "Authentication failure"),
    _event_ref(13, "Authentication request"),
    _event_ref(14, "Authentication response"),
]

UNSUCCESSFUL_REFS = [
    _event_ref(12, "Authentication failure"),
]


class OrchestrationRecoveryClassificationTests(unittest.TestCase):
    """Verify Orchestration classifies recovered deviations as non-candidate."""

    def test_16_recovered_deviation_classified_as_supporting_anomaly(self):
        """Recovered deviation is non-candidate supporting evidence, not a limitation."""
        analysis = _registration_analysis("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", RECOVERED_REFS)
        result = _run_orchestration(analysis)
        all_supporting_types = set()
        all_limitation_types = set()
        for group in result["diagnostic_groups"]:
            for sup in group.get("supporting_anomalies", []):
                if isinstance(sup, dict):
                    all_supporting_types.add(sup.get("type"))
            for lim in group.get("evidence_limitations", []):
                if isinstance(lim, dict):
                    all_limitation_types.add(lim.get("type"))
        self.assertIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", all_supporting_types)
        self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", all_limitation_types)

    def test_17_recovered_deviation_not_in_candidates(self):
        analysis = _registration_analysis("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", RECOVERED_REFS)
        result = _run_orchestration(analysis)
        for group in result["diagnostic_groups"]:
            for candidate in group.get("candidate_boundaries", []):
                self.assertNotEqual(
                    candidate.get("deviation_type"), "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                    "recovered deviation must not appear in boundary candidates",
                )

    def test_18_recovered_deviation_not_selected_as_boundary(self):
        analysis = _registration_analysis("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", RECOVERED_REFS)
        result = _run_orchestration(analysis)
        for group in result["diagnostic_groups"]:
            selected = group.get("selected_boundary")
            if selected is not None:
                ref = selected.get("boundary_ref", {})
                self.assertNotEqual(
                    ref.get("deviation_type"), "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                    "recovered deviation must not be selected as boundary",
                )

    def test_19_unsuccessful_still_candidate_eligible(self):
        """UNSUCCESSFUL_OUTCOME_OBSERVED remains candidate-eligible."""
        self.assertIn("UNSUCCESSFUL_OUTCOME_OBSERVED", MODEL.ELIGIBLE_DEVIATION_TYPES)
        self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", MODEL.ELIGIBLE_DEVIATION_TYPES)

    def test_20_recovered_type_in_supporting_anomaly_set(self):
        """The recovered type is explicitly classified in SUPPORTING_ANOMALY_TYPES."""
        self.assertIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", MODEL.SUPPORTING_ANOMALY_TYPES)
        self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", MODEL.EVIDENCE_LIMITATION_TYPES)


if __name__ == "__main__":
    unittest.main()
