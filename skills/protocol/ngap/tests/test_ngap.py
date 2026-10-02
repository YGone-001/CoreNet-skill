"""Package-local test suite for the bounded NGAP Protocol Skill."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
sys.path.insert(0, str(SCRIPTS))

import ngap_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACT = load_script("extract-ngap")
CORRELATE = load_script("correlate-ngap")
TIMELINE = load_script("ngap_timeline")

EXTRACTED = PACKAGE / "examples" / "extracted"
EXPECTED = PACKAGE / "examples" / "expected"

# Fixtures exercising the bounded PDU Session resource capability.
RESOURCE_FIXTURES = (
    "pdu-session-setup",
    "pdu-session-modify",
    "pdu-session-release",
    "initial-context-resources",
    "pdu-session-qfi",
    "pdu-session-identity",
    "pdu-session-recognition",
    "pdu-session-ordering",
)


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def records(name: str) -> list[dict]:
    return list(MODEL.read_jsonl(EXTRACTED / name))


def events_for(name: str) -> list[dict]:
    return [MODEL.normalize_record(record, name) for record in records(name)]


class NgapModelTests(unittest.TestCase):
    def test_supported_procedure_mapping(self):
        identity = MODEL.resolve_procedure(14, "InitialContextSetupRequest")
        self.assertEqual(identity.procedure_name, "InitialContextSetup")
        self.assertEqual(identity.message_type, "InitialContextSetupRequest")
        self.assertEqual(identity.pdu_type, "initiatingMessage")
        self.assertEqual(identity.pdu_type_basis, "message-name")
        self.assertEqual(identity.support_status, "SUPPORTED")
        self.assertEqual(identity.result, "REQUEST")
        self.assertEqual(identity.sender_role, "amf")

    def test_supported_message_mapping_outcomes(self):
        response = MODEL.resolve_procedure(14, "InitialContextSetupResponse")
        self.assertEqual((response.pdu_type, response.result, response.sender_role), ("successfulOutcome", "SUCCESS", "ng-ran"))
        failure = MODEL.resolve_procedure(14, "InitialContextSetupFailure")
        self.assertEqual((failure.pdu_type, failure.result, failure.sender_role), ("unsuccessfulOutcome", "FAILURE", "ng-ran"))
        command = MODEL.resolve_procedure(41, "UEContextReleaseCommand")
        self.assertEqual((command.pdu_type, command.result, command.sender_role), ("initiatingMessage", "COMMAND", "amf"))
        complete = MODEL.resolve_procedure(41, "UEContextReleaseComplete")
        self.assertEqual((complete.pdu_type, complete.result, complete.sender_role), ("successfulOutcome", "COMPLETE", "ng-ran"))

    def test_unknown_procedure_falls_back_without_semantics(self):
        identity = MODEL.resolve_procedure(250, "InitialUEMessage")
        self.assertEqual(identity.support_status, "UNKNOWN")
        self.assertIsNone(identity.procedure_name)
        self.assertIsNone(identity.message_type)
        self.assertIsNone(identity.result)
        self.assertIsNone(identity.sender_role)

    def test_unsupported_procedure_preserves_identity_only(self):
        identity = MODEL.resolve_procedure(12, "HandoverPreparation")
        self.assertEqual(identity.support_status, "UNSUPPORTED")
        self.assertEqual(identity.procedure_name, "HandoverPreparation")
        self.assertIsNone(identity.message_type)
        self.assertIsNone(identity.result)

    def test_explicit_structured_pdu_type_wins(self):
        identity = MODEL.resolve_procedure(15, None, "initiatingMessage")
        self.assertEqual((identity.pdu_type, identity.pdu_type_basis), ("initiatingMessage", "structured-input"))
        self.assertEqual(identity.message_type, "InitialUEMessage")
        self.assertNotIn("pdu_type", identity.derivations)

    def test_invalid_pdu_type_is_rejected(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({"frame.number": "1", "frame.time_epoch": "0", "ngap.procedureCode": "15", "pdu_type": "maybe"}, "x.jsonl")

    def test_identifier_extraction_distinct(self):
        events = events_for("ue-context-flow.jsonl")
        initial = events[0]
        self.assertEqual(initial["ran_ue_ngap_id"], 1)
        self.assertIsNone(initial["amf_ue_ngap_id"])
        uplink = events[1]
        self.assertEqual((uplink["ran_ue_ngap_id"], uplink["amf_ue_ngap_id"]), (1, 2))

    def test_cause_category_and_value_preserved(self):
        release = events_for("ue-context-flow.jsonl")[5]
        self.assertEqual(release["cause"], {"category": "transport", "value": 1})
        failure = events_for("multi-association.jsonl")[2]
        self.assertEqual(failure["cause"], {"category": "radioNetwork", "value": 3})

    def test_nas_presence_without_decoding(self):
        event = events_for("ue-context-flow.jsonl")[0]
        self.assertTrue(event["nas_pdu_present"])
        self.assertEqual(event["nas_pdu_length"], 3)
        self.assertNotIn("nas_pdu", event)
        self.assertNotIn("nas_payload", event)
        self.assertIsNone(event["amf_ue_ngap_id"])

    def test_paging_has_no_fabricated_ue_context(self):
        paging = events_for("ue-context-flow.jsonl")[8]
        self.assertEqual((paging["ran_ue_ngap_id"], paging["amf_ue_ngap_id"]), (None, None))
        self.assertTrue(paging["paging_identity_present"])

    def test_release_initiator_evidence_boundary(self):
        request = events_for("ue-context-flow.jsonl")[5]
        self.assertEqual(request["sender_role"], "ng-ran")
        self.assertEqual(request["evidence"]["level"], "OBSERVED")
        self.assertNotIn("root_cause", json.dumps(request))
        self.assertEqual(request["result"], "REQUEST")

    def test_malformed_inputs_fail_loudly(self):
        with self.assertRaises(MODEL.InputError):
            list(records("malformed.jsonl"))
        with self.assertRaises(MODEL.InputError):
            events_for("missing-required.jsonl")

    def test_timestamp_is_utc_microsecond(self):
        self.assertEqual(MODEL.normalize_timestamp("1704164645.000001"), "2024-01-02T03:04:05.000001Z")
        self.assertEqual(MODEL.normalize_timestamp("0"), "1970-01-01T00:00:00.000000Z")

    def test_tshark_unavailable_is_clear(self):
        with mock.patch.object(MODEL.subprocess, "Popen", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                list(MODEL.tshark_records(Path("sample.pcapng")))
        with mock.patch.object(MODEL.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                MODEL.tshark_version()

    def test_tshark_command_is_argument_list(self):
        command = MODEL.build_tshark_fields_command(Path("sample.pcapng"))
        self.assertEqual(command[:4], ["tshark", "-n", "-r", "sample.pcapng"])
        self.assertNotIn("shell=True", command)
        self.assertIn("-Y", command)
        self.assertIn("ngap", command)
        for field in ("ngap.procedureCode", "ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID", "sctp.assoc_index", "sctp.data_sid", "_ws.col.Info"):
            self.assertIn(field, command)

    def test_projection_keeps_ngap_ids_out_of_generic_fields(self):
        event = events_for("ue-context-flow.jsonl")[1]
        projected = MODEL.project_trace_event(event)
        self.assertEqual(projected["protocol"], "NGAP")
        self.assertEqual(projected["interface"], "N2")
        self.assertEqual(projected["result"], {"status": "REQUEST", "cause": None, "code": None})
        blob = json.dumps(projected)
        self.assertNotIn("ngap_id", blob)
        self.assertNotIn("subscriber", blob)
        self.assertNotIn("pdu_session_id", blob)
        self.assertNotIn("dialog_id", blob)
        self.assertEqual(projected["correlation"], {"stream_id": "0"})

    def test_projection_cause_and_unknown_procedure(self):
        events = events_for("ue-context-flow.jsonl")
        release = MODEL.project_trace_event(events[5])
        self.assertEqual(release["result"]["cause"], "transport:1")
        unknown = MODEL.project_trace_event(events[9])
        self.assertNotIn("result", unknown)
        self.assertIsNone(unknown.get("procedure"))
        self.assertIsNone(unknown.get("message_type"))


class NgapCorrelationTests(unittest.TestCase):
    def test_expected_flow_correlates_one_context(self):
        summary = CORRELATE.correlate(events_for("ue-context-flow.jsonl"))
        keys = [context["context_key"] for context in summary["contexts"]]
        self.assertEqual(keys, ["ngap-context:ue-context-flow.jsonl:sctp-assoc-0:r1:a2", "ngap-context:ue-context-flow.jsonl:sctp-assoc-0:r7:a8"])
        primary = summary["contexts"][0]
        self.assertEqual(primary["binding"]["ran_ue_ngap_id"], 1)
        self.assertEqual(primary["binding"]["amf_ue_ngap_id"], 2)
        self.assertEqual(primary["frame_numbers"], [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual([event["correlation_strength"] for event in primary["events"]], ["MEDIUM"] + ["STRONG"] * 7)
        self.assertEqual(summary["contexts"][1]["frame_numbers"], [11])
        notes = summary["non_ue_associated_events"]
        self.assertEqual([note["frame_number"] for note in notes], [9, 10])
        self.assertTrue(all("not merged" in note["note"] for note in notes))

    def test_association_isolation(self):
        summary = CORRELATE.correlate(events_for("multi-association.jsonl"))
        keys = sorted(context["context_key"] for context in summary["contexts"])
        self.assertEqual(keys, [
            "ngap-context:multi-association.jsonl:sctp-assoc-0:r1:a2",
            "ngap-context:multi-association.jsonl:sctp-assoc-1:r1:a9",
        ])
        for context in summary["contexts"]:
            self.assertEqual(len({event["observed"]["ran_ue_ngap_id"] for event in context["events"]}), 1)

    def test_conflicting_binding_detected_first_retained(self):
        summary = CORRELATE.correlate(events_for("conflict-binding.jsonl"))
        self.assertEqual(len(summary["contexts"]), 1)
        context = summary["contexts"][0]
        self.assertEqual(len(context["conflicts"]), 1)
        conflict = context["conflicts"][0]
        self.assertEqual(conflict["frame_number"], 42)
        self.assertEqual(conflict["observed"], {"ran_ue_ngap_id": 1, "amf_ue_ngap_id": 9})
        self.assertEqual(conflict["existing_binding"], {"ran_ue_ngap_id": 1, "amf_ue_ngap_id": 2})
        self.assertEqual(conflict["resolution"], "first-binding-retained")
        self.assertEqual(summary["conflicts"], context["conflicts"])
        flagged = [event for event in context["events"] if event.get("binding_conflict")]
        self.assertEqual([event["frame_number"] for event in flagged], [42])

    def test_conflicting_summary_matches_expected_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "conflict-events.jsonl"
            EXTRACT.write_events(EXTRACTED / "conflict-binding.jsonl", "fields-jsonl", events_path, True)
            output = Path(directory) / "correlation.json"
            CORRELATE.write_summary(events_path, output, True)
            expected = json.loads((EXPECTED / "conflict-binding-correlation.json").read_text(encoding="utf-8"))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), expected)


class NgapCliTests(unittest.TestCase):
    def test_deterministic_jsonl_output(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.jsonl"
            second = Path(directory) / "second.jsonl"
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", first, True)
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", second, True)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_expected_detailed_events_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", output, True)
            expected = jsonl(EXPECTED / "ue-context-events.jsonl")
            self.assertEqual(jsonl(output), expected)

    def test_expected_trace_projection_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "trace.jsonl"
            events_path = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", events_path, True)
            EXTRACT.write_projection(events_path, output, True)
            expected = jsonl(EXPECTED / "ue-context-trace.jsonl")
            self.assertEqual(jsonl(output), expected)

    def test_no_events_does_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.jsonl"
            empty.write_text("", encoding="utf-8")
            output = Path(directory) / "events.jsonl"
            with self.assertRaises(MODEL.InputError):
                EXTRACT.write_events(empty, "fields-jsonl", output, True)
            self.assertFalse(output.exists())

    def test_outputs_refuse_replacement_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", output, True)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", output, False)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", EXTRACTED / "ue-context-flow.jsonl", True)

    def test_timeline_text_and_json(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "ue-context-flow.jsonl", "fields-jsonl", events_path, True)
            events = jsonl(events_path)
            text = TIMELINE.render_text(events)
            self.assertIn("UEContextReleaseCommand", text)
            self.assertIn("cause=transport:1", text)
            self.assertIn("UNKNOWN", text)
            self.assertIn("amf=-", text)  # Paging carries no UE context
            self.assertIn("UNKNOWN", text)
            document = json.loads(TIMELINE.render_json(events))
            self.assertEqual(len(document["events"]), len(events))
            self.assertEqual(document["events"][5]["cause"], {"category": "transport", "value": 1})

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            ok = subprocess.run([sys.executable, str(SCRIPTS / "extract-ngap.py"), str(EXTRACTED / "ue-context-flow.jsonl"), "--input-format", "fields-jsonl", "--output", str(directory_path / "ok.jsonl")], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            bad = subprocess.run([sys.executable, str(SCRIPTS / "extract-ngap.py"), str(EXTRACTED / "malformed.jsonl"), "--input-format", "fields-jsonl", "--output", str(directory_path / "bad.jsonl")], capture_output=True, text=True)
            self.assertEqual(bad.returncode, MODEL.EXIT_MALFORMED_INPUT)
            empty = subprocess.run([sys.executable, str(SCRIPTS / "extract-ngap.py"), str(EXTRACTED / "missing-required.jsonl"), "--input-format", "fields-jsonl", "--output", str(directory_path / "empty.jsonl")], capture_output=True, text=True)
            self.assertEqual(empty.returncode, MODEL.EXIT_MALFORMED_INPUT)
            missing = subprocess.run([sys.executable, str(SCRIPTS / "extract-ngap.py"), str(directory_path / "absent.jsonl"), "--output", str(directory_path / "x.jsonl")], capture_output=True, text=True)
            self.assertEqual(missing.returncode, MODEL.EXIT_MALFORMED_INPUT)
            nodest = subprocess.run([sys.executable, str(SCRIPTS / "extract-ngap.py"), str(EXTRACTED / "ue-context-flow.jsonl")], capture_output=True, text=True)
            self.assertEqual(nodest.returncode, MODEL.EXIT_OUTPUT_FAILURE)


class NgapSchemaTests(unittest.TestCase):
    EVENT_REQUIRED = {
        "timestamp", "frame_number", "capture_file", "pdu_type", "pdu_type_basis",
        "procedure_code", "procedure_name", "message_type", "support_status",
        "result", "sender_role", "amf_ue_ngap_id", "ran_ue_ngap_id", "cause",
        "nas_pdu_present", "nas_pdu_length", "rrc_establishment_cause",
        "user_location_information_present", "paging_identity_present",
        "evidence", "derivations",
    }
    TRACE_REQUIRED = {"timestamp", "protocol", "evidence"}

    def test_detailed_events_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "ngap-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        for event in jsonl(EXPECTED / "ue-context-events.jsonl"):
            self.assertTrue(self.EVENT_REQUIRED.issubset(event), event)
            self.assertTrue(set(event) <= allowed, event)
            self.assertEqual(event["evidence"]["level"], "OBSERVED")
            self.assertIn(event["support_status"], {"SUPPORTED", "UNSUPPORTED", "UNKNOWN"})
            self.assertIn(event["pdu_type"], {None, "initiatingMessage", "successfulOutcome", "unsuccessfulOutcome"})
            self.assertTrue(isinstance(event["derivations"], list))
            for item in event["derivations"]:
                self.assertIn(item, schema["properties"]["derivations"]["items"]["enum"])

    def test_resource_events_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "ngap-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        item_properties = set(schema["$defs"]["resourceItem"]["properties"])
        item_required = set(schema["$defs"]["resourceItem"]["required"])
        for name in RESOURCE_FIXTURES:
            for event in jsonl(EXPECTED / f"{name}-events.jsonl"):
                self.assertTrue(set(event) <= allowed, name)
                self.assertTrue(self.EVENT_REQUIRED.issubset(event), name)
                for item in event.get("pdu_session_resources", []):
                    self.assertTrue(item_required.issubset(item), item)
                    self.assertTrue(set(item) <= item_properties, item)
                    self.assertIn(item["binding_basis"], {"structured-input", "single-resource-message", "single-list-message", "unbound"})

    def test_trace_projection_conforms_structurally(self):
        for projected in jsonl(EXPECTED / "ue-context-trace.jsonl"):
            self.assertTrue(self.TRACE_REQUIRED.issubset(projected))
            self.assertEqual(projected["protocol"], "NGAP")
            self.assertEqual(projected["evidence"]["level"], "DERIVED")
            self.assertIn("packet", projected)
            blob = json.dumps(projected)
            self.assertNotIn("ngap_id", blob)

    def test_package_local_schemas_parse(self):
        for name in ("ngap-event.schema.json", "trace-event.schema.json"):
            document = json.loads((PACKAGE / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_package_local_trace_schema_matches_shared_when_available(self):
        shared = PACKAGE.parents[2] / "shared" / "schemas" / "trace-event.schema.json"
        local = PACKAGE / "schemas" / "trace-event.schema.json"
        if not shared.is_file():
            self.skipTest("shared schema not present in standalone copy")
        self.assertEqual(local.read_bytes(), shared.read_bytes())


class NgapStandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "ngap"
            shutil.copytree(PACKAGE, copied)
            scripts = copied / "scripts"
            for name in ("extract-ngap.py", "correlate-ngap.py", "ngap_timeline.py"):
                result = subprocess.run([sys.executable, str(scripts / name), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            events = copied / "events.jsonl"
            result = subprocess.run([
                sys.executable, str(scripts / "extract-ngap.py"),
                str(copied / "examples" / "extracted" / "ue-context-flow.jsonl"),
                "--input-format", "fields-jsonl", "--output", str(events),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            correlation = copied / "correlation.json"
            result = subprocess.run([
                sys.executable, str(scripts / "correlate-ngap.py"), str(events), "--output", str(correlation),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("r1:a2", correlation.read_text(encoding="utf-8"))
            timeline = subprocess.run([sys.executable, str(scripts / "ngap_timeline.py"), str(events)], capture_output=True, text=True)
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("UEContextReleaseRequest", timeline.stdout)


class NgapPduSessionResourceTests(unittest.TestCase):
    def test_version_is_expanded(self):
        manifest = (PACKAGE / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("version: 0.2.0", manifest)
        self.assertIn("protocols: [NGAP]", manifest)
        self.assertIn("interfaces: [N2]", manifest)

    def test_new_procedures_recognized(self):
        setup = MODEL.resolve_procedure(29, "PDUSessionResourceSetupRequest")
        self.assertEqual((setup.procedure_name, setup.message_type, setup.result, setup.sender_role), ("PDUSessionResourceSetup", "PDUSessionResourceSetupRequest", "REQUEST", "amf"))
        response = MODEL.resolve_procedure(29, "PDUSessionResourceSetupResponse")
        self.assertEqual((response.pdu_type, response.result, response.sender_role), ("successfulOutcome", "SUCCESS", "ng-ran"))
        modify = MODEL.resolve_procedure(26, "PDUSessionResourceModifyRequest")
        self.assertEqual((modify.message_type, modify.sender_role), ("PDUSessionResourceModifyRequest", "amf"))
        release = MODEL.resolve_procedure(28, "PDUSessionResourceReleaseCommand")
        self.assertEqual((release.result, release.sender_role), ("COMMAND", "amf"))
        released = MODEL.resolve_procedure(28, "PDUSessionResourceReleaseResponse")
        self.assertEqual(released.result, "SUCCESS")

    def test_no_setup_failure_message_is_invented(self):
        messages = {message for _name, branches in MODEL.SUPPORTED_PROCEDURES.values() for message in branches.values()}
        for invented in ("PDUSessionResourceSetupFailure", "PDUSessionResourceModifyFailure", "PDUSessionResourceReleaseFailure"):
            self.assertNotIn(invented, messages)

    def test_setup_request_multiple_resources(self):
        event = events_for("pdu-session-setup.jsonl")[1]
        self.assertEqual(event["message_type"], "PDUSessionResourceSetupRequest")
        ids = [item["pdu_session_id"] for item in event["pdu_session_resources"]]
        self.assertEqual(ids, [10, 11])
        self.assertEqual([item["resource_list_role"] for item in event["pdu_session_resources"]], ["REQUEST", "REQUEST"])
        self.assertEqual(event["pdu_session_resources"][0]["snssai"], {"sst": 1, "sd": None})

    def test_setup_response_single_success_and_failed(self):
        events = events_for("pdu-session-setup.jsonl")
        success = events[2]
        self.assertEqual(success["pdu_session_resources"][0]["resource_list_role"], "SUCCESS")
        failed = events[3]
        self.assertEqual(failed["pdu_session_resources"][0]["resource_list_role"], "FAILED")

    def test_mixed_outcome_is_preserved(self):
        event = events_for("pdu-session-setup.jsonl")[4]
        self.assertEqual(event["result"], "SUCCESS")
        self.assertEqual(event["pdu_type"], "successfulOutcome")
        outcomes = {item["pdu_session_id"]: item["resource_list_role"] for item in event["pdu_session_resources"]}
        self.assertEqual(outcomes, {10: "SUCCESS", 11: "FAILED"})
        # message-level SUCCESS must never be flattened into an all-success verdict
        self.assertIn("FAILED", [item["resource_list_role"] for item in event["pdu_session_resources"]])

    def test_item_cause_and_message_cause_are_separate(self):
        bound = events_for("pdu-session-setup.jsonl")[5]
        self.assertIsNone(bound["cause"])
        self.assertEqual(bound["pdu_session_resources"][0]["cause"], {"category": "radioNetwork", "value": 3})
        unbound = events_for("pdu-session-setup.jsonl")[6]
        self.assertEqual(unbound["pdu_session_resources"][0]["cause"], None)
        self.assertEqual(unbound["unbound_resource_metadata"]["cause_values"], [{"category": "transport", "value": 2}])

    def test_modify_procedure(self):
        events = events_for("pdu-session-modify.jsonl")
        self.assertEqual(events[0]["message_type"], "PDUSessionResourceModifyRequest")
        self.assertEqual(events[1]["pdu_session_resources"][0]["resource_operation"], "MODIFY")
        self.assertEqual(events[2]["pdu_session_resources"][0]["qfi_values"], [5, 9])
        self.assertEqual(events[3]["pdu_session_resources"][0]["resource_list_role"], "FAILED")
        mixed = {item["pdu_session_id"]: item["resource_list_role"] for item in events[4]["pdu_session_resources"]}
        self.assertEqual(mixed, {10: "SUCCESS", 11: "FAILED"})

    def test_release_procedure(self):
        events = events_for("pdu-session-release.jsonl")
        self.assertEqual(events[0]["message_type"], "PDUSessionResourceReleaseCommand")
        self.assertEqual(events[0]["pdu_session_resources"][0]["resource_list_role"], "COMMAND")
        self.assertEqual([item["pdu_session_id"] for item in events[1]["pdu_session_resources"]], [10, 11])
        self.assertEqual(events[2]["message_type"], "PDUSessionResourceReleaseResponse")
        self.assertEqual(events[2]["pdu_session_resources"][0]["resource_list_role"], "RESPONSE")
        # release command without a response stays an open boundary in the capture
        self.assertEqual(events[3]["message_type"], "PDUSessionResourceReleaseCommand")

    def test_initial_context_setup_resources(self):
        events = events_for("initial-context-resources.jsonl")
        request = events[1]
        self.assertEqual(request["message_type"], "InitialContextSetupRequest")
        self.assertEqual(request["result"], "REQUEST")
        self.assertEqual([item["pdu_session_id"] for item in request["pdu_session_resources"]], [10, 11])
        self.assertEqual(request["pdu_session_resources"][0]["resource_operation"], "INITIAL_CONTEXT_SETUP")
        response = events[3]
        self.assertEqual(response["message_type"], "InitialContextSetupResponse")
        self.assertEqual(response["result"], "SUCCESS")
        outcomes = {item["pdu_session_id"]: item["resource_list_role"] for item in response["pdu_session_resources"]}
        self.assertEqual(outcomes, {10: "SUCCESS", 11: "FAILED"})

    def test_qfi_single_and_multi(self):
        events = events_for("pdu-session-qfi.jsonl")
        single = events[0]
        self.assertEqual(single["pdu_session_resources"][0]["qfi_values"], [5])
        self.assertEqual(single["pdu_session_resources"][0]["binding_basis"], "single-resource-message")
        multi = events[1]
        self.assertEqual(multi["pdu_session_resources"][0]["qfi_values"], [5, 9])
        explicit = events[2]
        self.assertEqual([item["qfi_values"] for item in explicit["pdu_session_resources"]], [[5], [9]])

    def test_ambiguous_flattened_qfi_is_not_zipped(self):
        event = events_for("pdu-session-qfi.jsonl")[3]
        self.assertEqual([item["qfi_values"] for item in event["pdu_session_resources"]], [[], []])
        unbound = event["unbound_resource_metadata"]
        self.assertEqual(unbound["qfi_values"], [5, 9])
        self.assertTrue(any("not safely attributable" in limitation for limitation in unbound["limitations"]))

    def test_same_session_id_across_ue_contexts_stays_separate(self):
        events = events_for("pdu-session-identity.jsonl")
        self.assertEqual([(e["ran_ue_ngap_id"], e["amf_ue_ngap_id"]) for e in events], [(1, 2), (2, 3), (1, 2)])
        self.assertEqual([e["pdu_session_resources"][0]["pdu_session_id"] for e in events], [10, 10, 10])
        summary = CORRELATE.correlate(events)
        keys = sorted(context["context_key"] for context in summary["contexts"])
        self.assertEqual(len(keys), 3)
        self.assertEqual(len({context["capture_file"] + context["association"] for context in summary["contexts"]}), 2)

    def test_recognition_beyond_supported_scope(self):
        events = events_for("pdu-session-recognition.jsonl")
        self.assertEqual(events[0]["procedure_name"], "PDUSessionResourceNotify")
        self.assertEqual(events[0]["support_status"], "UNSUPPORTED")
        self.assertNotIn("pdu_session_resources", events[0])
        self.assertEqual(events[1]["procedure_name"], "PDUSessionResourceModifyIndication")
        self.assertEqual(events[1]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[2]["support_status"], "UNKNOWN")

    def test_ordering_and_duplicates_preserved(self):
        events = events_for("pdu-session-ordering.jsonl")
        self.assertEqual([event["frame_number"] for event in events], [171, 170, 172])
        duplicate = events[2]
        self.assertEqual(duplicate["message_type"], "PDUSessionResourceSetupRequest")
        self.assertEqual(duplicate["pdu_session_resources"][0]["pdu_session_id"], 10)

    def test_no_foreign_protocol_fields(self):
        for name in RESOURCE_FIXTURES:
            blob = json.dumps(events_for(f"{name}.jsonl"))
            for forbidden in ("teid", "seid", "dnn", "pti", "bearer_id", "apn"):
                self.assertNotIn(forbidden, blob, name)

    def test_no_nas_payload_or_asn1_decoder(self):
        model_text = (SCRIPTS / "ngap_model.py").read_text(encoding="utf-8").lower()
        for forbidden in ("pyasn1", "asn1tools", "asn1crypto", "import asn1"):
            self.assertNotIn(forbidden, model_text)

    def test_trace_projection_single_session_and_qfi(self):
        events = events_for("pdu-session-qfi.jsonl")
        projected = MODEL.project_trace_event(events[0])
        self.assertEqual(projected["session"], {"pdu_session_id": 10, "qfi": 5})

    def test_trace_projection_omits_multi_session_and_ambiguous_qfi(self):
        events = events_for("pdu-session-qfi.jsonl")
        multi_session = MODEL.project_trace_event(events[3])
        self.assertNotIn("session", multi_session)
        multi_qfi = MODEL.project_trace_event(events[1])
        self.assertEqual(multi_qfi["session"], {"pdu_session_id": 10})
        self.assertNotIn("qfi", multi_qfi["session"])
        two_items = MODEL.project_trace_event(events[2])
        self.assertNotIn("session", two_items)

    def test_malformed_resource_input_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({
                "frame.number": "1", "frame.time_epoch": "0", "ngap.procedureCode": "29",
                "pdu_session_resources": [{"pdu_session_id": "300"}],
            }, "x.jsonl")
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({
                "frame.number": "1", "frame.time_epoch": "0", "ngap.procedureCode": "29",
                "pdu_session_resources": "not-an-array",
            }, "x.jsonl")

    def test_expected_resource_fixtures_match(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in RESOURCE_FIXTURES:
                output = Path(directory) / f"{name}.jsonl"
                EXTRACT.write_events(EXTRACTED / f"{name}.jsonl", "fields-jsonl", output, True)
                self.assertEqual(jsonl(output), jsonl(EXPECTED / f"{name}-events.jsonl"), name)

    def test_resource_timeline_renders_outcomes(self):
        events = jsonl(EXPECTED / "pdu-session-setup-events.jsonl")
        text = TIMELINE.render_text(events)
        self.assertIn("10:SUCCESS", text)
        self.assertIn("11:FAILED", text)
        self.assertIn("unbound-resource-metadata=yes", text)
        upper = text.upper()
        for forbidden in ("PDU SESSION SUCCESS", "PDU SESSION FAILURE", "SMF FAILURE", "GNB FAILURE", "UPF FAILURE"):
            self.assertNotIn(forbidden, upper)


if __name__ == "__main__":
    unittest.main()
