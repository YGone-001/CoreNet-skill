"""Package-local test suite for 5gc-handover-mobility."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
INPUTS = PACKAGE / "examples" / "inputs"
EXPECTED = PACKAGE / "examples" / "expected"

sys.path.insert(0, str(SCRIPTS))

import mobility_model as MODEL

ANALYZE_SCRIPT = SCRIPTS / "analyze_handover_mobility.py"
TIMELINE_SCRIPT = SCRIPTS / "mobility_timeline.py"

SCENARIOS = {path.name for path in INPUTS.iterdir() if path.is_dir()}
FAILURE_SCENARIOS = {"malformed-input"}


def run_analysis(name: str, directory: Path) -> dict:
    args = [sys.executable, str(ANALYZE_SCRIPT)]
    for filename, flag in (("ngap.jsonl", "--ngap"), ("pfcp.jsonl", "--pfcp"),
                           ("gtpu.jsonl", "--gtpu"), ("sbi.jsonl", "--sbi"),
                           ("pdu-session.json", "--pdu-session")):
        path = INPUTS / name / filename
        if path.is_file():
            args += [flag, str(path)]
    output = directory / f"{name}-analysis.json"
    args += ["--output", str(output), "--force"]
    completed = subprocess.run(args, capture_output=True, text=True)
    assert completed.returncode == 0, f"{name} failed: {completed.stderr}"
    return json.loads(output.read_text(encoding="utf-8"))


def expected(name: str) -> dict:
    return json.loads((EXPECTED / f"{name}-analysis.json").read_text(encoding="utf-8"))


def first_handover(document: dict) -> dict:
    return document["handover_attempts"][0]


def first_path_switch(document: dict) -> dict:
    return document["path_switch_attempts"][0]


def deviation_types(attempt: dict) -> list[str]:
    return [deviation["type"] for deviation in attempt["deviations"]]


class ContractTests(unittest.TestCase):
    def test_manifest_contract(self):
        text = (PACKAGE / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("name: 5gc-handover-mobility", text)
        self.assertIn("version: 0.1.0", text)
        self.assertIn("category: domain", text)
        self.assertIn("required: []", text)
        self.assertIn("ngap >=0.3.0", text)
        self.assertIn("5gc-pdu-session >=0.4.0", text)
        self.assertNotIn("nas-5gs", text)

    def test_all_expected_scenarios_exist(self):
        for scenario in SCENARIOS - FAILURE_SCENARIOS:
            self.assertTrue((EXPECTED / f"{scenario}-analysis.json").is_file(), scenario)

    def test_expected_outputs_match(self):
        with tempfile.TemporaryDirectory() as directory:
            for scenario in SCENARIOS - FAILURE_SCENARIOS:
                with self.subTest(scenario=scenario):
                    self.assertEqual(run_analysis(scenario, Path(directory)), expected(scenario))

    def test_schema_parses_and_copies_are_identical(self):
        for name in ("5gc-handover-mobility-analysis.schema.json", "procedure-evidence.schema.json"):
            document = json.loads((PACKAGE / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")
        generic = (PACKAGE / "schemas" / "procedure-evidence.schema.json").read_bytes()
        framework_path = (PACKAGE.parents[1] / "domain" / "procedure-evidence"
                          / "schemas" / "procedure-evidence.schema.json")
        if not framework_path.is_file():
            self.skipTest("framework schema not present in standalone copy")
        self.assertEqual(generic, framework_path.read_bytes())

    def test_no_forbidden_fields_in_schema(self):
        schema_text = (PACKAGE / "schemas" / "5gc-handover-mobility-analysis.schema.json").read_text(encoding="utf-8")
        for forbidden in ("root_cause", "culprit", "responsible_nf", "vendor_fault",
                          "implementation_failure", "radio_fault", "handover_success",
                          "path_switch_success", "mobility_success", "upf_relocation"):
            self.assertNotIn(f'"{forbidden}"', schema_text)

    def test_stage_records_projection(self):
        document = expected("full-n2-handover")
        records = MODEL.build_stage_records(document)
        self.assertTrue(records)
        for record in records:
            self.assertIn("procedure_name", record)
            self.assertEqual(record["procedure_version"], "0.1.0")
            self.assertIn(record["evidence_basis"], ("OBSERVED", "DERIVED"))
            self.assertIn(record["confidence"], ("HIGH", "MEDIUM", "LOW"))


class HandoverFormationTests(unittest.TestCase):
    def test_full_n2_handover(self):
        attempt = first_handover(expected("full-n2-handover"))
        self.assertEqual(attempt["association"]["strength"], "STRONG")
        self.assertEqual(attempt["source_context"]["ran_ue_ngap_id"], 1)
        self.assertEqual(attempt["target_context"]["ran_ue_ngap_id"], 3)
        self.assertEqual(attempt["handover_type"]["domain_scope"], "INTRA_5GS")
        stage_ids = {stage["stage_id"] for stage in attempt["stages"]}
        self.assertEqual(stage_ids, {"HANDOVER_INITIATION", "HANDOVER_PREPARATION_OUTCOME",
                                     "TARGET_RESOURCE_ALLOCATION", "HANDOVER_EXECUTION_NOTIFICATION"})
        self.assertEqual(attempt["terminal_observation"]["observation"], "HANDOVER_NOTIFY_OBSERVED")
        self.assertEqual(attempt["terminal_observation"]["evidence_level"], "OBSERVED")

    def test_handover_preparation_failure(self):
        attempt = first_handover(expected("handover-preparation-failure"))
        self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))
        self.assertEqual(attempt["terminal_observation"]["observation"],
                         "HANDOVER_PREPARATION_FAILURE_OBSERVED")

    def test_handover_resource_failure(self):
        attempt = first_handover(expected("handover-resource-failure"))
        self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))
        self.assertEqual(attempt["terminal_observation"]["observation"],
                         "HANDOVER_RESOURCE_FAILURE_OBSERVED")

    def test_truncated_required_only(self):
        attempt = first_handover(expected("handover-required-truncated"))
        self.assertIn("MISSING_EXPECTED_COUNTERPART", deviation_types(attempt))
        missing_ref = [deviation for deviation in attempt["deviations"]
                       if deviation["type"] == "MISSING_EXPECTED_COUNTERPART"][0]
        self.assertEqual(missing_ref["evidence_level"], "DERIVED")
        self.assertTrue(all(ref["kind"] == "OBSERVATION_WINDOW" for ref in missing_ref["evidence_refs"]))
        self.assertEqual(attempt["terminal_observation"]["observation"],
                         "NO_TERMINAL_MOBILITY_OBSERVATION")

    def test_cancel_branch_is_not_failure(self):
        attempt = first_handover(expected("handover-cancel-branch"))
        self.assertNotIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))
        self.assertEqual(attempt["terminal_observation"]["observation"],
                         "HANDOVER_CANCEL_ACK_OBSERVED")

    def test_cancel_stops_false_missing_counterparts(self):
        attempt = first_handover(expected("cancel-no-false-missing"))
        self.assertEqual(deviation_types(attempt), [])

    def test_inter_system_handover_type_scope(self):
        attempt = first_handover(expected("inter-system-handover-type"))
        self.assertEqual(attempt["handover_type"]["domain_scope"], "INTER_SYSTEM_OR_OTHER")
        self.assertEqual(attempt["handover_type"]["scope_status"],
                         "UNSUPPORTED_HANDOVER_TYPE_FOR_DOMAIN_PROCEDURE")
        self.assertTrue(any("inter-system" in limitation for limitation in attempt["limitations"]))

    def test_mixed_resource_outcomes_stay_item_scoped(self):
        attempt = first_handover(expected("handover-ack-mixed-resources"))
        outcomes = {finding["pdu_session_id"]: [item["outcome"] for item in finding["n2_outcomes"]]
                    for finding in attempt["pdu_session_resources"]}
        self.assertEqual(outcomes[10], ["ADMITTED_ROLE_OBSERVED"])
        self.assertEqual(outcomes[11], ["RESOURCE_FAILED_ITEM_OBSERVED"])
        self.assertIn("RESOURCE_FAILED_ITEM_OBSERVED", deviation_types(attempt))

    def test_command_mixed_lists_preserved(self):
        attempt = first_handover(expected("handover-command-mixed-lists"))
        roles = {finding["pdu_session_id"]: [role["resource_list_role"] for role in finding["n2_roles"]]
                 for finding in attempt["pdu_session_resources"]}
        self.assertEqual(roles[11], ["HANDOVER"])
        self.assertEqual(roles[12], ["TO_RELEASE"])
        self.assertEqual(attempt["terminal_observation"]["observation"], "HANDOVER_COMMAND_OBSERVED")


class SourceTargetAssociationTests(unittest.TestCase):
    def test_amf_id_reuse_lifetimes_stay_separate(self):
        document = expected("amf-id-reuse-lifetimes")
        self.assertEqual(len(document["handover_attempts"]), 2)
        strengths = {attempt["association"]["strength"] for attempt in document["handover_attempts"]}
        self.assertEqual(strengths, {"STRONG"})
        event_frames = [tuple(event["frame_number"] for event in attempt["events"])
                        for attempt in document["handover_attempts"]]
        self.assertEqual(len(set(event_frames)), 2)

    def test_two_ues_interleaved_form_two_attempts(self):
        document = expected("two-ue-interleaved")
        self.assertEqual(len(document["handover_attempts"]), 2)
        contexts = {(attempt["source_context"]["amf_ue_ngap_id"]) for attempt in document["handover_attempts"]}
        self.assertEqual(contexts, {2, 8})

    def test_ambiguous_two_targets_not_first_selected(self):
        attempt = first_handover(expected("ambiguous-two-targets"))
        self.assertEqual(attempt["association"]["strength"], "AMBIGUOUS")
        self.assertEqual(len(attempt["association"]["candidates"]), 2)
        self.assertIn("CORRELATION_AMBIGUITY", deviation_types(attempt))
        self.assertIsNone(attempt["target_context"])

    def test_same_ran_id_two_associations_no_equality_join(self):
        document = expected("same-ran-id-two-associations")
        self.assertEqual(len(document["handover_attempts"]), 2)
        for attempt in document["handover_attempts"]:
            self.assertEqual(attempt["association"]["strength"], "UNBOUND")

    def test_same_ran_id_source_target_pairs_via_amf_context(self):
        attempt = first_handover(expected("same-ran-id-source-target"))
        self.assertEqual(attempt["association"]["strength"], "STRONG")
        basis = attempt["association"]["basis"]
        self.assertIn("AMF-UE-NGAP-ID", basis)

    def test_late_capture_target_only_is_unbound_partial(self):
        attempt = first_handover(expected("late-capture-handover-request"))
        self.assertEqual(attempt["association"]["strength"], "UNBOUND")
        self.assertIsNone(attempt["source_context"])
        self.assertIn("PARTIAL_CAPTURE", deviation_types(attempt))

    def test_notify_only_late_capture(self):
        attempt = first_handover(expected("notify-only-late-capture"))
        self.assertEqual(attempt["association"]["strength"], "UNBOUND")
        self.assertEqual(attempt["terminal_observation"]["observation"], "PARTIAL_CAPTURE")
        stage_ids = {stage["stage_id"] for stage in attempt["stages"]}
        self.assertNotIn("HANDOVER_INITIATION", stage_ids)
        self.assertNotIn("HANDOVER_PREPARATION_OUTCOME", stage_ids)

    def test_multiple_captures_no_cross_capture_join(self):
        document = expected("multiple-captures")
        self.assertEqual(len(document["handover_attempts"]), 2)
        for attempt in document["handover_attempts"]:
            self.assertEqual(attempt["association"]["strength"], "UNBOUND")


class PathSwitchTests(unittest.TestCase):
    def test_independent_path_switch_ack(self):
        attempt = first_path_switch(expected("ps-independent-ack"))
        self.assertIsNone(attempt["related_handover_attempt_id"])
        self.assertEqual(attempt["relationship_strength"], "UNBOUND")
        self.assertEqual(attempt["terminal_observation"]["observation"], "PATH_SWITCH_ACK_OBSERVED")
        self.assertNotIn("MISSING_HANDOVER_REQUIRED", deviation_types(attempt))

    def test_independent_path_switch_failure(self):
        attempt = first_path_switch(expected("ps-independent-failure"))
        self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))
        self.assertEqual(attempt["terminal_observation"]["observation"],
                         "PATH_SWITCH_FAILURE_OBSERVED")
        # The reviewed basis defines no message-level Cause for PS failure.
        self.assertIsNone(attempt["events"][1]["cause"])

    def test_path_switch_mixed_resources_item_scoped(self):
        attempt = first_path_switch(expected("ps-ack-mixed-resources"))
        outcomes = {finding["pdu_session_id"]: [item["outcome"] for item in finding["n2_outcomes"]]
                    for finding in attempt["pdu_session_resources"]}
        self.assertEqual(outcomes[10], ["SWITCHED_ROLE_OBSERVED"])
        self.assertEqual(outcomes[11], ["RELEASED_ROLE_OBSERVED"])
        self.assertNotIn("FIELD_CONFLICT", deviation_types(attempt))

    def test_resource_role_conflict_preserved(self):
        attempt = first_path_switch(expected("ps-request-role-conflict"))
        self.assertIn("FIELD_CONFLICT", deviation_types(attempt))
        conflict = [deviation for deviation in attempt["deviations"]
                    if deviation["type"] == "FIELD_CONFLICT"][0]
        self.assertEqual(conflict["evidence_refs"][0]["kind"], "FIELD_FINDING")

    def test_path_switch_truncated_and_late(self):
        self.assertIn("MISSING_EXPECTED_COUNTERPART",
                      deviation_types(first_path_switch(expected("ps-request-truncated"))))
        partial = first_path_switch(expected("ps-ack-late-capture"))
        self.assertEqual(partial["terminal_observation"]["observation"], "PARTIAL_CAPTURE")
        self.assertIn("PARTIAL_CAPTURE", deviation_types(partial))

    def test_notify_without_path_switch_has_no_false_missing(self):
        document = expected("handover-notify-no-path-switch")
        self.assertEqual(len(document["path_switch_attempts"]), 0)
        self.assertEqual(deviation_types(first_handover(document)), [])

    def test_near_unrelated_handover_no_timestamp_relation(self):
        attempt = first_path_switch(expected("ps-near-unrelated-handover"))
        self.assertIsNone(attempt["related_handover_attempt_id"])
        self.assertEqual(attempt["relationship_strength"], "UNBOUND")

    def test_ambiguous_handover_relationship(self):
        attempt = first_path_switch(expected("ps-ambiguous-relationship"))
        self.assertIsNone(attempt["related_handover_attempt_id"])
        self.assertEqual(attempt["relationship_strength"], "AMBIGUOUS")
        self.assertIn("CORRELATION_AMBIGUITY", deviation_types(attempt))


class SupportingPlaneTests(unittest.TestCase):
    def test_n11_associated(self):
        attempt = first_handover(expected("n11-associated"))
        self.assertEqual(len(attempt["plane_bindings"]["n11"]), 1)
        self.assertEqual(attempt["plane_bindings"]["n11"][0]["http_status"], 200)
        self.assertEqual(attempt["pdu_session_resources"][0]["n11_evidence"][0]["operation"],
                         "UpdateSMContext")
        stage_ids = {stage["stage_id"] for stage in attempt["stages"]}
        self.assertIn("CONTROL_PLANE_UPDATE", stage_ids)

    def test_n11_redacted_stays_unbound(self):
        document = expected("n11-redacted-unbound")
        self.assertEqual(first_handover(document)["plane_bindings"]["n11"], [])
        protocols = [entry["protocol"] for entry in document["unbound_mobility_evidence"]]
        self.assertIn("SBI-HTTP2", protocols)

    def test_pfcp_associated_via_context(self):
        attempt = first_handover(expected("pfcp-associated"))
        self.assertEqual(len(attempt["plane_bindings"]["n4"]), 2)
        self.assertEqual(attempt["pdu_session_resources"][0]["n4_evidence"][0]["header_seid"], 1001)
        stage_ids = {stage["stage_id"] for stage in attempt["stages"]}
        self.assertIn("USER_PLANE_CONTROL_UPDATE", stage_ids)
        self.assertNotIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))

    def test_pfcp_negative_cause_is_bounded(self):
        attempt = first_handover(expected("pfcp-negative-cause"))
        self.assertIn("PROTOCOL_NEGATIVE_OUTCOME_OBSERVED", deviation_types(attempt))
        negative = [deviation for deviation in attempt["deviations"]
                    if deviation["type"] == "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED"
                    and deviation["stage_id"] == "USER_PLANE_CONTROL_UPDATE"][0]
        self.assertIn("Session context not found", negative["description"])

    def test_pfcp_unrelated_stays_unbound(self):
        document = expected("pfcp-unrelated-unbound")
        self.assertEqual(first_handover(document)["plane_bindings"]["n4"], [])
        protocols = [entry["protocol"] for entry in document["unbound_mobility_evidence"]]
        self.assertEqual(protocols.count("PFCP"), 2)

    def test_pfcp_gtpu_binding(self):
        attempt = first_handover(expected("pfcp-gtpu-bound"))
        self.assertEqual(len(attempt["plane_bindings"]["n3"]), 1)
        self.assertEqual(attempt["plane_bindings"]["n3"][0]["teid"], 5001)
        self.assertEqual(attempt["pdu_session_resources"][0]["n3_observations"][0]["message_type"], "G-PDU")

    def test_teid_endpoint_mismatch_never_binds(self):
        document = expected("teid-endpoint-mismatch")
        self.assertEqual(first_handover(document)["plane_bindings"]["n3"], [])
        protocols = [entry["protocol"] for entry in document["unbound_mobility_evidence"]]
        self.assertIn("GTP-U", protocols)

    def test_end_marker_optional_and_neutral(self):
        observed = first_handover(expected("end-marker-observed"))
        self.assertNotIn("MISSING_EXPECTED_COUNTERPART", deviation_types(observed))
        self.assertEqual(observed["pdu_session_resources"][0]["n3_observations"][0]["message_type"],
                         "End Marker")
        neutral = first_handover(expected("no-end-marker-neutral"))
        self.assertNotIn("MISSING_EXPECTED_COUNTERPART", deviation_types(neutral))

    def test_no_gtpu_is_neutral(self):
        attempt = first_handover(expected("no-gtpu-neutral"))
        self.assertEqual(attempt["plane_bindings"]["n3"], [])
        for finding in attempt["pdu_session_resources"]:
            self.assertEqual(finding["n3_observations"], [])

    def test_error_indication_preserved_without_verdict(self):
        attempt = first_handover(expected("error-indication-observed"))
        self.assertEqual([deviation["stage_id"] for deviation in attempt["deviations"]
                          if deviation["type"] == "PROTOCOL_NEGATIVE_OUTCOME_OBSERVED"],
                         [])  # the error indication never becomes a negative outcome
        observation = attempt["pdu_session_resources"][0]["n3_observations"][0]
        self.assertTrue(observation["error_indication_present"])

    def test_mixed_psi_partial_n4(self):
        attempt = first_handover(expected("mixed-psi-partial-n4"))
        n4_counts = {finding["pdu_session_id"]: len(finding["n4_evidence"])
                     for finding in attempt["pdu_session_resources"]}
        self.assertEqual(n4_counts[10], 1)
        self.assertEqual(n4_counts[11], 0)
        limitations = attempt["pdu_session_resources"][1]["limitations"]
        self.assertTrue(any("not to this PDU Session resource" in item for item in limitations))
        self.assertEqual(n4_counts[11], 0)

    def test_lifecycle_generation_attached(self):
        finding = first_handover(expected("lifecycle-generation-context"))["pdu_session_resources"][0]
        self.assertEqual(finding["lifecycle_generation"]["session_generation"], 2)
        self.assertIn(":g2", finding["lifecycle_generation"]["instance_id"])


class InputSafetyTests(unittest.TestCase):
    def test_out_of_order_input_normalized(self):
        attempt = first_handover(expected("out-of-order-input"))
        self.assertIn("OUT_OF_ORDER_EVIDENCE", deviation_types(attempt))
        frames = [event["frame_number"] for event in attempt["events"]]
        self.assertEqual(frames, sorted(frames))

    def test_duplicate_message_preserved(self):
        attempt = first_handover(expected("duplicate-message"))
        self.assertIn("DUPLICATE_OR_RETRANSMITTED_EVIDENCE", deviation_types(attempt))
        duplicate = [deviation for deviation in attempt["deviations"]
                     if deviation["type"] == "DUPLICATE_OR_RETRANSMITTED_EVIDENCE"][0]
        self.assertEqual(duplicate["evidence_refs"][0]["kind"], "EVENT")
        self.assertEqual(duplicate["evidence_refs"][0]["frame_number"], 10)

    def test_unsupported_ngap_procedure_preserved_unbound(self):
        document = expected("unsupported-ngap-procedure")
        attempt = first_handover(document)
        self.assertNotEqual(attempt["events"][0]["message_type"], "HandoverSuccess")
        unbound = [entry for entry in document["unbound_mobility_evidence"]
                   if entry["message_type"] == "HandoverSuccess"]
        self.assertEqual(len(unbound), 1)
        self.assertEqual(unbound[0]["support_status"], "UNSUPPORTED")

    def test_no_mobility_evidence_yields_empty_analysis(self):
        document = expected("no-mobility-evidence")
        self.assertEqual(document["handover_attempts"], [])
        self.assertEqual(document["path_switch_attempts"], [])

    def test_malformed_input_fails_loudly(self):
        args = [sys.executable, str(ANALYZE_SCRIPT),
                "--ngap", str(INPUTS / "malformed-input" / "ngap.jsonl"),
                "--output", "unused.json"]
        completed = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(completed.returncode, MODEL.EXIT_MALFORMED_INPUT)

    def test_structured_provenance_on_every_deviation(self):
        for scenario in SCENARIOS - FAILURE_SCENARIOS:
            document = expected(scenario)
            for attempt in document["handover_attempts"] + document["path_switch_attempts"]:
                for deviation in attempt["deviations"]:
                    with self.subTest(scenario=scenario, type=deviation["type"]):
                        self.assertTrue(deviation["evidence_refs"], deviation)
                        for ref in deviation["evidence_refs"]:
                            self.assertIn(ref["kind"], ("EVENT", "FIELD_FINDING", "OBSERVATION_WINDOW", "STAGE"))

    def test_timeline_renders_without_verdicts(self):
        with tempfile.TemporaryDirectory() as directory:
            analysis = Path(directory) / "a.json"
            shutil_run = subprocess.run([
                sys.executable, str(ANALYZE_SCRIPT),
                "--ngap", str(INPUTS / "full-n2-handover" / "ngap.jsonl"),
                "--output", str(analysis), "--force",
            ], capture_output=True, text=True)
            self.assertEqual(shutil_run.returncode, 0, shutil_run.stderr)
            text = subprocess.run(
                [sys.executable, str(TIMELINE_SCRIPT), str(analysis)],
                capture_output=True, text=True).stdout
            self.assertIn("[handover:", text)
            self.assertIn("HandoverNotify", text)
            self.assertIn("resources=", text)
            upper = text.upper()
            for forbidden in ("HANDOVER SUCCESS", "PATH SWITCH SUCCESS", "ROOT CAUSE"):
                self.assertNotIn(forbidden, upper)


if __name__ == "__main__":
    unittest.main()
