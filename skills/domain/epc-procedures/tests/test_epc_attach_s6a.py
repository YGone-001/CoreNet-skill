#!/usr/bin/env python3
"""Standalone tests for the EPS Attach and S6a/S6d joint evidence capability."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "analyze_epc_attach_s6a.py"
SCHEMA = PACKAGE / "schemas" / "epc-attach-s6a-analysis.schema.json"
sys.path.insert(0, str(SCRIPTS))
import epc_attach_s6a_model as model  # noqa: E402


def stage(stage_id, status, frame, observed=True):
    return {
        "stage_id": stage_id,
        "stage_name": stage_id.replace("-", " ").title(),
        "conditional": False,
        "status": status,
        "messages": [],
        "first_frame": frame if observed else None,
        "last_frame": frame if observed else None,
        "evidence_refs": [],
    }


def attach_instance(reference, attempt, start, end, *, incomplete=False, deviations=0, auth_frame=None):
    stages = [
        stage("attach-initiation", "OBSERVED", start),
        stage("identity", "OBSERVED", start + 1),
        stage("authentication", "INCOMPLETE" if incomplete else "OBSERVED", start + 2),
        stage("security-mode", "NOT_OBSERVED", start + 3, observed=False),
    ]
    observations = [
        {
            "observation_type": "nas_message",
            "procedure_stage": "attach-initiation",
            "protocol": "NAS-EPS",
            "message_type": "Attach request",
            "frame_number": start,
            "evidence_level": "OBSERVED",
        },
        {
            "observation_type": "nas_message",
            "procedure_stage": "authentication",
            "protocol": "NAS-EPS",
            "message_type": "Authentication request",
            "frame_number": auth_frame if auth_frame is not None else start + 2,
            "evidence_level": "OBSERVED",
        },
    ]
    return {
        "procedure_reference": reference,
        "procedure": "eps-attach",
        "attempt_index": attempt,
        "association": {"strength": "STRONG", "basis": "S1AP UE context", "capture_file": "capture.pcapng", "sctp_association": "assoc"},
        "first_frame": start,
        "last_frame": end,
        "stages": stages,
        "observations": observations,
        "deviations": [
            {
                "deviation_type": "observed-reject",
                "procedure_stage": "authentication",
                "protocol": "NAS-EPS",
                "message_type": "Authentication reject",
                "frame_number": start + 2,
            }
            for _ in range(deviations)
        ],
        "evidence_limitations": [],
        "additional_evidence_needed": [],
    }


def attach_document(instances):
    return {
        "domain": "epc-procedures",
        "domain_version": "1.0.0",
        "model_version": "1.0.0",
        "analysis_scope": "bounded EPS Attach procedure evidence",
        "input_provenance": {
            "s1ap_events": {"file": "s1ap-events.jsonl", "event_count": 20},
            "nas_eps_events": {"file": "nas-eps-events.jsonl", "event_count": 10},
        },
        "procedure": "eps-attach",
        "stage_vocabulary": ["attach-initiation", "identity", "authentication", "security-mode"],
        "procedure_instances": instances,
        "instance_count": len(instances),
        "unbound_evidence": [],
        "ambiguous_evidence": [],
        "global_first_abnormal_boundary": None,
        "global_boundary_evaluation": "NOT_EVALUATED",
        "limitations": [],
        "additional_evidence_needed": [],
        "not_confirmed": [],
    }


def reference(frame, occurrence, direction, command, application=16777251):
    return {
        "event_reference": f"diameter-event:{frame}.{occurrence}",
        "frame_number": frame,
        "message_occurrence": occurrence,
        "direction": direction,
        "command_code": command,
        "command_name": "Authentication-Information" if command == 318 else "Update-Location",
        "application_id": application,
        "hop_by_hop_id": frame,
        "end_to_end_id": frame + 1,
        "source_endpoint": "10.0.0.1:40000",
        "destination_endpoint": "10.0.0.2:3868",
    }


def result(code=None, exp=None, vendor=None, application_result="SUCCESS_REPORTED", namespace="BASE_RFC6733"):
    return {
        "core_result_status": "SINGLE_BASE" if code is not None else ("SINGLE_EXPERIMENTAL" if exp is not None else "MISSING"),
        "namespace_status": namespace,
        "application_result": application_result,
        "base_result_code": code,
        "base_result_code_name": "DIAMETER_SUCCESS" if code in (2001, 2002) else None,
        "experimental_result_code": exp,
        "experimental_result_code_name": None,
        "experimental_vendor_id": vendor,
    }


def diameter_observation(
    name,
    procedure,
    command,
    start,
    occurrence=1,
    *,
    status="MATCHED",
    response_frame=None,
    answer_occurrence=1,
    result_value=None,
    auth="PRESENT_REDACTED",
    message_status="OBSERVED",
    transaction_prefix="diameter-tx:capture.pcapng",
):
    request = reference(start, occurrence, "REQUEST", command)
    answer = reference(response_frame, answer_occurrence, "ANSWER", command) if response_frame is not None else None
    candidates = []
    if status == "AMBIGUOUS":
        request = None
        answer = reference(start, occurrence, "ANSWER", command)
        candidates = [reference(start + 1, 1, "REQUEST", command)]
    elif status == "RESPONSE_ONLY":
        request = None
        answer = reference(start, occurrence, "ANSWER", command)
    return {
        "observation_reference": f"diameter-epc-observation:capture.pcapng:{start}.{occurrence}",
        "procedure": procedure,
        "command_code": command,
        "message_status": message_status,
        "application_result": (result_value or result(2001))["application_result"],
        "transaction_status": status,
        "transaction_reference": f"{transaction_prefix}:{command}:{start}.{occurrence}",
        "request": request,
        "answer": answer,
        "response_candidates": candidates,
        "result": result_value or result(2001),
        "authentication_information": auth,
        "latency_seconds": "0.100000" if status == "MATCHED" else None,
        "limitations": [],
    }


def diameter_document(observations, capture="capture.pcapng"):
    return {
        "analysis_name": "diameter-epc",
        "analysis_version": "1.0.0",
        "domain": "protocol",
        "input_provenance": {"capture_files": [capture]},
        "observations": observations,
        "completeness": {"observation_count": len(observations)},
    }


class JointModelTest(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self):
        self._temporary.cleanup()

    def write(self, attach=None, diameter=None, capture=None):
        attach_path = self.base / "attach.json"
        diameter_path = self.base / "diameter.json"
        attach_path.write_text(json.dumps(attach or attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)])), encoding="utf-8")
        diameter_path.write_text(json.dumps(diameter or diameter_document([diameter_observation("obs", "AIR", 318, 11, response_frame=12)])), encoding="utf-8")
        return attach_path, diameter_path

    def analyze(self, attach, diameter, *, capture=None):
        attach = attach or attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)])
        attach_path, diameter_path = self.write(attach, diameter)
        return model.analyze(attach, diameter, attach_path=attach_path, diameter_path=diameter_path, capture=capture)

    def test_one_attach_and_one_matched_air_remains_unlinked(self):
        document = self.analyze(attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)]), diameter_document([diameter_observation("obs", "AIR", 318, 11, response_frame=12)]))
        self.assertEqual(len(document["attach_inventory"]), 1)
        self.assertEqual(len(document["diameter_inventory"]), 1)
        self.assertEqual(document["identity_association"]["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(document["identity_association"]["candidate_pairs"], [])
        self.assertFalse(document["diagnostics"]["cross_protocol_attribution_established"])

    def test_two_attach_and_two_air_do_not_create_cartesian_pairs(self):
        attach = attach_document([
            attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20),
            attach_instance("epc-attach-bbbbbbbbbb", 1, 30, 40),
        ])
        diameter = diameter_document([
            diameter_observation("a", "AIR", 318, 11, response_frame=12),
            diameter_observation("b", "AIR", 318, 31, response_frame=32),
        ])
        document = self.analyze(attach, diameter)
        self.assertEqual(len(document["attach_inventory"]), 2)
        self.assertEqual(len(document["diameter_inventory"]), 2)
        self.assertEqual(document["identity_association"]["candidate_pairs"], [])
        self.assertEqual(document["identity_association"]["candidates_omitted"], 0)

    def test_multiple_diameter_transactions_preserved(self):
        diameter = diameter_document([
            diameter_observation("a", "AIR", 318, 11, response_frame=12),
            diameter_observation("u", "ULR", 316, 13, response_frame=14),
        ])
        document = self.analyze(None, diameter)
        self.assertEqual([item["procedure"] for item in document["diameter_inventory"]], ["AIR", "ULR"])

    def test_same_frame_different_occurrences_preserved(self):
        diameter = diameter_document([
            diameter_observation("a", "AIR", 318, 11, 1, response_frame=12, answer_occurrence=1),
            diameter_observation("b", "ULR", 316, 11, 2, response_frame=12, answer_occurrence=2),
        ])
        document = self.analyze(None, diameter)
        occurrences = {
            (item["request"]["frame_number"], item["request"]["message_occurrence"])
            for item in document["diameter_inventory"]
        }
        self.assertEqual(occurrences, {(11, 1), (11, 2)})

    def test_filename_equality_is_not_verified_capture_provenance(self):
        document = self.analyze(None, diameter_document([], capture="capture.pcapng"))
        self.assertEqual(document["input_provenance"]["common_capture"]["status"], "FILENAME_MATCH_ONLY")
        self.assertEqual(document["timeline_ordering"], "SOURCE_LOCAL_ONLY")

    def test_supplied_capture_context_verifies_order_but_not_identity(self):
        capture = self.base / "capture.pcapng"
        capture.write_bytes(b"synthetic")
        document = self.analyze(None, diameter_document([diameter_observation("a", "AIR", 318, 11, response_frame=12)]), capture=capture)
        self.assertEqual(document["input_provenance"]["common_capture"]["status"], "VERIFIED_COORDINATED_CAPTURE_CONTEXT")
        self.assertEqual(document["timeline_ordering"], "VERIFIED_COMMON_CAPTURE")
        self.assertEqual(document["identity_association"]["status"], "INSUFFICIENT_EVIDENCE")

    def test_contradictory_capture_filename_is_rejected(self):
        capture = self.base / "other.pcapng"
        capture.write_bytes(b"synthetic")
        attach = attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)])
        diameter = diameter_document([diameter_observation("a", "AIR", 318, 11, response_frame=12)], capture="capture.pcapng")
        with self.assertRaises(model.InputError):
            self.analyze(attach, diameter, capture=capture)

    def test_zero_diameter_observations_is_not_applicable(self):
        document = self.analyze(None, diameter_document([]))
        self.assertEqual(document["identity_association"]["status"], "NOT_APPLICABLE")
        self.assertEqual(document["diameter_inventory"], [])

    def test_open_request_response_only_and_ambiguous_are_preserved(self):
        diameter = diameter_document([
            diameter_observation("open", "AIR", 318, 11, status="OPEN_REQUEST"),
            diameter_observation("answer", "AIA", 318, 18, status="RESPONSE_ONLY"),
            diameter_observation("amb", "AIA", 318, 20, status="AMBIGUOUS"),
        ])
        document = self.analyze(None, diameter)
        statuses = [item["transaction_status"] for item in document["diameter_inventory"]]
        self.assertEqual(statuses, ["OPEN_REQUEST", "RESPONSE_ONLY", "AMBIGUOUS"])
        for item in document["diameter_inventory"]:
            if item["transaction_status"] != "MATCHED":
                self.assertIsNone(item["latency_seconds"])

    def test_experimental_failure_is_preserved(self):
        exp = result(exp=5001, vendor=10415, application_result="FAILURE_REPORTED", namespace="3GPP_TS_29_272_EXPERIMENTAL")
        document = self.analyze(None, diameter_document([diameter_observation("a", "AIA", 318, 11, response_frame=12, result_value=exp)]))
        item = document["diameter_inventory"][0]
        self.assertEqual(item["result"]["experimental_result_code"], 5001)
        self.assertEqual(item["result"]["application_result"], "FAILURE_REPORTED")

    def test_base_and_experimental_5001_remain_distinct(self):
        base = result(5001, application_result="FAILURE_REPORTED")
        exp = result(exp=5001, vendor=10415, application_result="FAILURE_REPORTED", namespace="3GPP_TS_29_272_EXPERIMENTAL")
        document = self.analyze(None, diameter_document([
            diameter_observation("base", "AIA", 318, 11, response_frame=12, result_value=base),
            diameter_observation("exp", "AIA", 318, 13, response_frame=14, result_value=exp),
        ]))
        self.assertEqual(document["diameter_inventory"][0]["result"]["base_result_code"], 5001)
        self.assertEqual(document["diameter_inventory"][1]["result"]["experimental_result_code"], 5001)
        self.assertEqual(document["diameter_inventory"][0]["result"]["experimental_result_code"], None)

    def test_truncated_authentication_information_is_not_promoted(self):
        observation = diameter_observation("a", "AIA", 318, 11, response_frame=12)
        observation["authentication_information"] = "NOT_OBSERVED_IN_PUBLISHED_SUBSET"
        document = self.analyze(None, diameter_document([observation]))
        self.assertEqual(document["diameter_inventory"][0]["authentication_information"], "NOT_OBSERVED_IN_PUBLISHED_SUBSET")

    def test_incomplete_attach_is_preserved(self):
        attach = attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20, incomplete=True)])
        document = self.analyze(attach, diameter_document([]))
        self.assertEqual(document["attach_inventory"][0]["status"], "INCOMPLETE")
        self.assertEqual(document["diagnostics"]["attach_incomplete_instance_count"], 1)

    def test_unsupported_command_is_preserved_without_application_claim(self):
        observation = diameter_observation("nor", "NOR", 321, 30, response_frame=31, message_status="UNSUPPORTED")
        observation["result"] = result(application_result="NOT_APPLICABLE")
        observation["application_result"] = "NOT_APPLICABLE"
        document = self.analyze(None, diameter_document([observation]))
        item = document["diameter_inventory"][0]
        self.assertEqual(item["message_status"], "UNSUPPORTED")
        self.assertEqual(item["result"]["application_result"], "NOT_APPLICABLE")

    def test_dangling_transaction_reference_is_rejected(self):
        observation = diameter_observation("a", "AIR", 318, 11, response_frame=12, transaction_prefix="diameter-epc-unresolved:capture")
        with self.assertRaises(model.InputError):
            self.analyze(None, diameter_document([observation]))

    def test_malformed_diameter_schema_is_rejected(self):
        observation = diameter_observation("a", "AIR", 318, 11, response_frame=12)
        del observation["result"]
        with self.assertRaises(model.InputError):
            self.analyze(None, diameter_document([observation]))

    def test_deterministic_ordering(self):
        attach = attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)])
        diameter = diameter_document([diameter_observation("a", "AIR", 318, 11, response_frame=12)])
        capture = self.base / "capture.pcapng"
        capture.write_bytes(b"synthetic")
        first = self.analyze(attach, diameter, capture=capture)
        second = self.analyze(attach, diameter, capture=capture)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        frames = [(row["frame_number"], row["message_occurrence"] or 0) for row in first["timeline"]]
        self.assertEqual(frames, sorted(frames))

    def test_sensitive_values_and_root_cause_are_absent(self):
        document = self.analyze(None, diameter_document([diameter_observation("a", "AIR", 318, 11, response_frame=12)]))
        serialized = json.dumps(document)
        for forbidden in ("001010000000001", "RAND-SYNTHETIC", "AUTN-SYNTHETIC", "XRES-SYNTHETIC", "KASME-SYNTHETIC", "root_cause\": true"):
            self.assertNotIn(forbidden, serialized)
        self.assertFalse(document["diagnostics"]["root_cause_inferred"])


class JointCliTest(unittest.TestCase):
    def setUp(self):
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self):
        self._temporary.cleanup()

    def require_jsonschema(self):
        if jsonschema is None:
            if os.environ.get("CI"):
                self.fail("jsonschema is required for the joint schema gate in CI")
            self.skipTest("jsonschema unavailable")

    def write_inputs(self, *, attach=True, diameter=True):
        attach_path = self.base / "attach.json"
        diameter_path = self.base / "diameter.json"
        if attach:
            attach_path.write_text(json.dumps(attach_document([attach_instance("epc-attach-aaaaaaaaaa", 1, 10, 20)])), encoding="utf-8")
        if diameter:
            diameter_path.write_text(json.dumps(diameter_document([diameter_observation("a", "AIR", 318, 11, response_frame=12)])), encoding="utf-8")
        return attach_path, diameter_path

    def test_cli_output_and_schema(self):
        self.require_jsonschema()
        attach, diameter = self.write_inputs()
        capture = self.base / "capture.pcapng"
        capture.write_bytes(b"synthetic")
        output = self.base / "joint.json"
        report = self.base / "joint.txt"
        completed = subprocess.run(
            [sys.executable, str(CLI), "--attach", str(attach), "--diameter-epc", str(diameter), "--capture", str(capture), "--output", str(output), "--report", str(report)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        jsonschema.validate(json.loads(output.read_text(encoding="utf-8")), json.loads(SCHEMA.read_text(encoding="utf-8")))
        self.assertIn("Attach/S6a identity association", report.read_text(encoding="utf-8"))

    def test_missing_attach_input_is_rejected(self):
        attach, diameter = self.write_inputs(attach=False)
        completed = subprocess.run(
            [sys.executable, str(CLI), "--attach", str(attach), "--diameter-epc", str(diameter), "--output", str(self.base / "out.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)

    def test_missing_diameter_input_is_rejected(self):
        attach, diameter = self.write_inputs(diameter=False)
        completed = subprocess.run(
            [sys.executable, str(CLI), "--attach", str(attach), "--diameter-epc", str(diameter), "--output", str(self.base / "out.json")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 2)

    def test_existing_output_requires_force(self):
        attach, diameter = self.write_inputs()
        output = self.base / "joint.json"
        output.write_text("existing", encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(CLI), "--attach", str(attach), "--diameter-epc", str(diameter), "--output", str(output)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 6)

    def test_zero_diameter_observations_still_writes_output(self):
        attach, _diameter = self.write_inputs()
        diameter = self.base / "empty-diameter.json"
        diameter.write_text(json.dumps(diameter_document([])), encoding="utf-8")
        output = self.base / "joint.json"
        completed = subprocess.run(
            [sys.executable, str(CLI), "--attach", str(attach), "--diameter-epc", str(diameter), "--output", str(output)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["identity_association"]["status"], "NOT_APPLICABLE")

    def test_invalid_output_object_fails_schema(self):
        self.require_jsonschema()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"analysis_name": "epc-attach-s6a"}, schema)


if __name__ == "__main__":
    unittest.main()