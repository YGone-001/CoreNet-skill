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
    return _registration_analysis_deviations([
        {
            "type": deviation_type,
            "stage_id": None,
            "description": f"Deviation {deviation_type} at frame 12",
            "evidence_level": "OBSERVED",
            "limitation": "Procedure evidence",
            "evidence_refs": evidence_refs,
        },
    ])


def _registration_analysis_deviations(deviations: list[dict]) -> dict:
    """Build a minimal Registration Domain analysis with explicit deviations."""
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
                "deviations": deviations,
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


class OrchestrationRecoveryCoexistenceTests(unittest.TestCase):
    """Verify recovered and unsuccessful deviations coexist safely."""

    def test_21_independent_unsuccessful_outcome_not_suppressed(self):
        """An independent eligible unsuccessful outcome stays candidate-eligible
        when a recovered outcome exists in the same instance.

        The recovered intermediate outcome must never suppress an
        independently eligible unsuccessful deviation: the unsuccessful
        deviation must remain a selectable candidate while the recovered
        deviation stays supporting evidence with structured evidence
        references.
        """
        analysis = _registration_analysis_deviations([
            {
                "type": "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                "stage_id": None,
                "description": "Recovered synchronization failure at frame 12",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": RECOVERED_REFS,
            },
            {
                "type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "stage_id": None,
                "description": "Authentication failure at frame 20",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": [_event_ref(20, "Authentication failure")],
            },
        ])
        result = _run_orchestration(analysis)
        self.assertTrue(result["diagnostic_groups"])
        for group in result["diagnostic_groups"]:
            supporting_types = {
                entry.get("type") for entry in group.get("supporting_anomalies", [])
                if isinstance(entry, dict)
            }
            candidate_types = {
                candidate.get("deviation_type") for candidate in group.get("candidate_boundaries", [])
                if isinstance(candidate, dict)
            }
            self.assertIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", supporting_types)
            self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", candidate_types)
            self.assertIn("UNSUCCESSFUL_OUTCOME_OBSERVED", candidate_types)
            for entry in group.get("supporting_anomalies", []):
                if entry.get("type") == "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED":
                    refs = entry.get("_refs") or []
                    event_refs = [ref for ref in refs if ref.get("kind") == "EVENT"]
                    self.assertTrue(event_refs)
                    self.assertEqual(
                        [ref.get("frame_number") for ref in event_refs],
                        [12, 13, 14],
                    )

    def test_22_recovered_supporting_entry_preserves_structured_refs(self):
        """The recovered supporting anomaly preserves the structured evidence
        references of the source deviation.

        The entry must carry the structured event references (kind, frame
        number, protocol, message type) that downstream ordering uses;
        human-readable description is never the machine provenance
        contract.
        """
        analysis = _registration_analysis("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", RECOVERED_REFS)
        result = _run_orchestration(analysis)
        recovered_entries = []
        for group in result["diagnostic_groups"]:
            for entry in group.get("supporting_anomalies", []):
                if isinstance(entry, dict) and entry.get("type") == "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED":
                    recovered_entries.append(entry)
        self.assertTrue(recovered_entries)
        for entry in recovered_entries:
            refs = entry.get("_refs") or []
            event_refs = [ref for ref in refs
                          if isinstance(ref, dict) and ref.get("kind") == "EVENT"]
            self.assertEqual(len(event_refs), 3)
            self.assertEqual([ref.get("frame_number") for ref in event_refs], [12, 13, 14])
            self.assertEqual([ref.get("protocol") for ref in event_refs],
                             ["NAS-5GS", "NAS-5GS", "NAS-5GS"])
            self.assertEqual([ref.get("message_type") for ref in event_refs],
                             ["Authentication failure", "Authentication request", "Authentication response"])
            self.assertEqual(
                {ref.get("evidence_level") for ref in event_refs},
                {"OBSERVED"},
            )

    def test_23_recovered_never_enters_evidence_limitation_types(self):
        """The recovered type never leaks into the evidence-limitation set."""
        self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", MODEL.EVIDENCE_LIMITATION_TYPES)
        self.assertIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", MODEL.SUPPORTING_ANOMALY_TYPES)
        analysis = _registration_analysis_deviations([
            {
                "type": "RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED",
                "stage_id": None,
                "description": "Recovered synchronization failure at frame 12",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": RECOVERED_REFS,
            },
            {
                "type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "stage_id": None,
                "description": "Authentication failure at frame 20",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": [_event_ref(20, "Authentication failure")],
            },
        ])
        result = _run_orchestration(analysis)
        for group in result["diagnostic_groups"]:
            limitation_types = {
                entry.get("type") for entry in group.get("evidence_limitations", [])
                if isinstance(entry, dict)
            }
            self.assertNotIn("RECOVERED_INTERMEDIATE_OUTCOME_OBSERVED", limitation_types)

    def test_24_auth_negative_stage_attribution_consumed_by_orchestration(self):
        """Orchestration consumes the newly supported authentication stage identity
        without changing its candidate-selection algorithm or boundary anchor."""
        stage_records = [
            {
                "confidence": "MEDIUM",
                "evidence_basis": "OBSERVED",
                "expected_evidence": [],
                "limitations": [],
                "missing_evidence": [],
                "observation_group": "reg.pcapng",
                "observed_evidence": ["NAS-5GS Registration request observed at frame 1"],
                "procedure_name": "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                "procedure_version": "0.2.6",
                "stage": {
                    "expected_message_types": ["InitialUEMessage", "Registration request"],
                    "expected_protocols": ["NAS-5GS", "NGAP"],
                    "stage_id": "registration-initiation",
                    "stage_name": "Registration initiation",
                },
            },
            {
                "confidence": "MEDIUM",
                "evidence_basis": "OBSERVED",
                "expected_evidence": [],
                "limitations": [],
                "missing_evidence": [],
                "observation_group": "reg.pcapng",
                "observed_evidence": ["NAS-5GS Authentication request observed at frame 10"],
                "procedure_name": "5gc-reg:reg.pcapng:sctp-assoc-0:r1",
                "procedure_version": "0.2.6",
                "stage": {
                    "expected_message_types": ["Authentication request", "Authentication response"],
                    "expected_protocols": ["NAS-5GS"],
                    "stage_id": "authentication",
                    "stage_name": "Primary authentication and key agreement",
                },
            },
        ]
        deviations = [
            {
                "type": "UNSUCCESSFUL_OUTCOME_OBSERVED",
                "stage_id": "authentication",
                "description": "NAS-5GS Authentication failure observed at frame 11",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": [
                    {
                        "capture_file": "reg.pcapng",
                        "evidence_level": "OBSERVED",
                        "field_name": None,
                        "frame_number": 11,
                        "kind": "EVENT",
                        "message_type": "Authentication failure",
                        "protocol": "NAS-5GS",
                        "stage_id": "authentication",
                        "timestamp": "2024-01-02T03:04:11.00Z",
                        "window_first_frame": None,
                        "window_last_frame": None,
                    }
                ],
            },
            {
                "type": "PROTOCOL_REJECT_OBSERVED",
                "stage_id": "authentication",
                "description": "NAS-5GS Authentication reject observed at frame 12",
                "evidence_level": "OBSERVED",
                "limitation": "Procedure evidence",
                "evidence_refs": [
                    {
                        "capture_file": "reg.pcapng",
                        "evidence_level": "OBSERVED",
                        "field_name": None,
                        "frame_number": 12,
                        "kind": "EVENT",
                        "message_type": "Authentication reject",
                        "protocol": "NAS-5GS",
                        "stage_id": "authentication",
                        "timestamp": "2024-01-02T03:04:12.00Z",
                        "window_first_frame": None,
                        "window_last_frame": None,
                    }
                ],
            },
        ]
        doc = _registration_analysis_deviations(deviations)
        doc["analysis_version"] = "0.2.6"
        doc["analyses"][0]["stage_records"] = stage_records
        result = _run_orchestration(doc)
        group = result["diagnostic_groups"][0]
        selected = group["selected_boundary"]
        self.assertIsNotNone(selected)
        ref = selected["boundary_ref"]
        self.assertEqual(ref["boundary_anchor"]["frame_number"], 11)
        self.assertEqual(ref["boundary_anchor"]["protocol"], "NAS-5GS")
        self.assertEqual(ref["boundary_anchor"]["message_type"], "Authentication failure")
        self.assertEqual(ref["procedure_stage"], "authentication")
        self.assertEqual(ref["ordering_basis"]["stage_position"], 1)
        self.assertNotEqual(ref["procedure_stage"], "security",
                            "No equivalence between authentication and security may be assumed")


if __name__ == "__main__":
    unittest.main()
