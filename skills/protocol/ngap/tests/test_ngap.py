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
        for event in jsonl(EXPECTED / "ue-context-events.jsonl"):
            self.assertTrue(self.EVENT_REQUIRED.issubset(event), event)
            self.assertEqual(set(event), set(schema["properties"]))
            self.assertEqual(event["evidence"]["level"], "OBSERVED")
            self.assertIn(event["support_status"], {"SUPPORTED", "UNSUPPORTED", "UNKNOWN"})
            self.assertIn(event["pdu_type"], {None, "initiatingMessage", "successfulOutcome", "unsuccessfulOutcome"})
            self.assertTrue(isinstance(event["derivations"], list))
            for item in event["derivations"]:
                self.assertIn(item, schema["properties"]["derivations"]["items"]["enum"])

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


if __name__ == "__main__":
    unittest.main()
