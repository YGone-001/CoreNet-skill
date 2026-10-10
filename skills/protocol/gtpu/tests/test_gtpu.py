"""Package-local test suite for the bounded GTP-U (N3) Protocol Skill."""

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

import gtpu_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACT = load_script("extract-gtpu")
SUMMARIZE = load_script("summarize-gtpu")
TIMELINE = load_script("gtpu_timeline")

EXTRACTED = PACKAGE / "examples" / "extracted"
EXPECTED = PACKAGE / "examples" / "expected"

FIXTURE_NAMES = (
    "g-pdu-basic",
    "pdu-session-container",
    "teid-scope",
    "control-messages",
    "recognition",
    "inner-packets",
    "ordering",
)


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def records(name: str) -> list[dict]:
    return list(MODEL.read_jsonl(EXTRACTED / name))


def events_for(name: str) -> list[dict]:
    return [MODEL.normalize_record(record, name) for record in records(name)]


def expected_events(name: str) -> list[dict]:
    return jsonl(EXPECTED / f"{name}-events.jsonl")


class GtpuContractTests(unittest.TestCase):
    def test_manifest_contract(self):
        manifest = (PACKAGE / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("name: gtpu", manifest)
        self.assertIn("version: 0.1.1", manifest)
        self.assertIn("category: protocol", manifest)
        self.assertIn("protocols: [GTP-U]", manifest)
        self.assertIn("interfaces: [N3]", manifest)
        self.assertIn("network_functions: []", manifest)
        self.assertIn("required: []", manifest)

    def test_message_types_match_reviewed_table(self):
        self.assertEqual(MODEL.MESSAGE_TYPES[1][0], "Echo Request")
        self.assertEqual(MODEL.MESSAGE_TYPES[2][0], "Echo Response")
        self.assertEqual(MODEL.MESSAGE_TYPES[26][0], "Error Indication")
        self.assertEqual(MODEL.MESSAGE_TYPES[31][0], "Supported Extension Headers Notification")
        self.assertEqual(MODEL.MESSAGE_TYPES[253][0], "Tunnel Status")
        self.assertEqual(MODEL.MESSAGE_TYPES[254][0], "End Marker")
        self.assertEqual(MODEL.MESSAGE_TYPES[255][0], "G-PDU")

    def test_supported_scope_is_bounded(self):
        for code in (1, 2, 26, 31, 254, 255):
            self.assertEqual(MODEL.resolve_message(code).support_status, "SUPPORTED", code)
        self.assertEqual(MODEL.resolve_message(253).support_status, "UNSUPPORTED")
        for code in (0, 3, 27, 32, 252, 100):
            self.assertEqual(MODEL.resolve_message(code).support_status, "UNKNOWN", code)

    def test_extension_header_types_reviewed(self):
        self.assertEqual(MODEL.EXTENSION_HEADER_TYPES[0x85], "PDU Session Container")
        self.assertEqual(MODEL.EXTENSION_HEADER_TYPES[0x00], "No more extension headers")
        self.assertEqual(MODEL.EXTENSION_HEADER_TYPES[0x40], "UDP Port")
        self.assertEqual(MODEL.EXTENSION_HEADER_TYPES[0xC0], "PDCP PDU Number")

    def test_schemas_parse(self):
        for name in ("gtpu-event.schema.json", "gtpu-stream.schema.json", "trace-event.schema.json"):
            document = json.loads((PACKAGE / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_package_local_trace_schema_matches_shared_when_available(self):
        shared = PACKAGE.parents[2] / "shared" / "schemas" / "trace-event.schema.json"
        local = PACKAGE / "schemas" / "trace-event.schema.json"
        if not shared.is_file():
            self.skipTest("shared schema not present in standalone copy")
        self.assertEqual(local.read_bytes(), shared.read_bytes())

    def test_extension_headers_are_arrays(self):
        schema = json.loads((PACKAGE / "schemas" / "gtpu-event.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["extension_headers"]["type"], "array")
        stream = json.loads((PACKAGE / "schemas" / "gtpu-stream.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(stream["properties"]["streams"]["type"], "array")

    def test_message_map_documents_scope(self):
        text = (PACKAGE / "references" / "message-map.md").read_text(encoding="utf-8")
        for token in ("G-PDU", "Echo Request", "Echo Response", "Error Indication", "End Marker", "SUPPORTED", "UNSUPPORTED"):
            self.assertIn(token, text)


class GtpuHeaderTests(unittest.TestCase):
    def test_header_fields_preserved(self):
        header = events_for("g-pdu-basic.jsonl")[0]["header"]
        self.assertEqual(header["version"], 1)
        self.assertEqual(header["protocol_type"], 1)
        self.assertEqual(header["message_type"], "G-PDU")
        self.assertEqual(header["message_length"], 120)
        self.assertEqual(header["teid"], 305419896)
        self.assertEqual(header["sequence_number"], 100)
        self.assertTrue(header["s_flag"])
        self.assertFalse(header["e_flag"])

    def test_optional_sequence_absent_is_null(self):
        header = events_for("g-pdu-basic.jsonl")[3]["header"]
        self.assertFalse(header["s_flag"])
        self.assertIsNone(header["sequence_number"])

    def test_teid_zero_rules_are_message_specific(self):
        for code in (1, 2, 26, 31):
            self.assertTrue(MODEL.resolve_message(code).teid_expected_zero, code)
        for code in (254, 255):
            self.assertFalse(MODEL.resolve_message(code).teid_expected_zero, code)

    def test_unexpected_zero_teid_on_g_pdu_is_recorded(self):
        event = [item for item in events_for("teid-scope.jsonl") if item["frame_number"] == 34][0]
        self.assertEqual(event["header"]["teid"], 0)
        self.assertFalse(event["header"]["teid_expected_zero"])
        self.assertTrue(any("expects a tunnel TEID" in limitation for limitation in event["limitations"]))

    def test_teid_and_sequence_ranges_enforced(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({"frame.number": "1", "frame.time_epoch": "0", "gtp.message": "255", "gtp.teid": "4294967296"}, "x.jsonl")
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({"frame.number": "1", "frame.time_epoch": "0", "gtp.message": "255", "gtp.seq_number": "65536"}, "x.jsonl")


class GtpuTeidScopeTests(unittest.TestCase):
    def test_directed_path_key_scopes_by_endpoints_and_teid(self):
        events = events_for("teid-scope.jsonl")
        keys = [MODEL.directed_path_key(event) for event in events]
        self.assertEqual(len(keys), len(set(keys)), "same TEID on different endpoint contexts must not merge")

    def test_same_teid_across_endpoints_stays_separate(self):
        events = events_for("teid-scope.jsonl")
        same_teid = [event for event in events if event["header"]["teid"] == 305419896]
        self.assertEqual(len(same_teid), 3)
        keys = {MODEL.directed_path_key(event) for event in same_teid}
        self.assertEqual(len(keys), 3)

    def test_opposite_direction_is_a_separate_context(self):
        events = events_for("teid-scope.jsonl")
        forward = events[0]
        reverse = events[2]
        self.assertEqual(forward["header"]["teid"], reverse["header"]["teid"])
        self.assertNotEqual(MODEL.directed_path_key(forward), MODEL.directed_path_key(reverse))

    def test_stream_summary_keeps_five_streams(self):
        summary = SUMMARIZE.summarize(events_for("teid-scope.jsonl"))
        self.assertEqual(len(summary["streams"]), 5)
        keys = [stream["stream_key"] for stream in summary["streams"]]
        self.assertEqual(len(keys), len(set(keys)))

    def test_two_teids_between_same_endpoints_stay_separate(self):
        events = events_for("teid-scope.jsonl")
        first, second = events[0], events[3]
        self.assertEqual((first["outer"], second["outer"]), (first["outer"], first["outer"]))
        self.assertNotEqual(first["header"]["teid"], second["header"]["teid"])
        self.assertNotEqual(MODEL.directed_path_key(first), MODEL.directed_path_key(second))


class GtpuUserPlaneEvidenceTests(unittest.TestCase):
    def test_g_pdu_evidence_is_observation_only(self):
        event = events_for("g-pdu-basic.jsonl")[0]
        self.assertEqual(event["header"]["message_type"], "G-PDU")
        self.assertEqual(event["evidence"]["level"], "OBSERVED")
        blob = json.dumps(event).lower()
        for forbidden in ("delivered", "delivery", "success", "confirmed", "lost", "packet loss"):
            self.assertNotIn(forbidden, blob)

    def test_no_packet_loss_verdict_on_sequence_gap(self):
        events = events_for("g-pdu-basic.jsonl")
        sequences = [event["header"]["sequence_number"] for event in events if event["header"]["sequence_number"] is not None]
        self.assertEqual(sequences, [100, 101, 103])
        summary = SUMMARIZE.summarize(events)
        stream = summary["streams"][0]
        self.assertTrue(stream["sequence_discontinuity_candidate"])
        blob = json.dumps(summary).lower()
        for forbidden in ("packet loss", "lost packet", "loss confirmed"):
            self.assertNotIn(forbidden, blob)

    def test_duplicate_sequence_is_only_a_candidate(self):
        summary = SUMMARIZE.summarize(events_for("ordering.jsonl"))
        stream = summary["streams"][0]
        self.assertEqual(stream["duplicate_observation_candidates"], [73])
        self.assertEqual(stream["observed_g_pdu_packet_count"], 4)
        blob = json.dumps(summary).lower()
        self.assertNotIn("retransmission confirmed", blob)

    def test_byte_count_uses_one_documented_definition(self):
        summary = SUMMARIZE.summarize(events_for("g-pdu-basic.jsonl"))
        stream = summary["streams"][0]
        self.assertEqual(stream["observed_payload_byte_count"], 120 + 140 + 88 + 64)
        self.assertEqual(stream["byte_count_definition"], SUMMARIZE.BYTE_COUNT_DEFINITION)
        self.assertIn("GTP-U Length field", stream["byte_count_definition"])

    def test_one_way_observation_is_stated_as_observation(self):
        summary = SUMMARIZE.summarize(events_for("g-pdu-basic.jsonl"))
        self.assertEqual(len(summary["streams"]), 1)
        self.assertTrue(any("observed at this capture point" in limitation for limitation in summary["limitations"]))
        blob = json.dumps(summary).lower()
        for forbidden in ("downlink failed", "uplink broken", "works"):
            self.assertNotIn(forbidden, blob)

    def test_out_of_order_input_is_sorted_deterministically(self):
        events = events_for("ordering.jsonl")
        self.assertEqual([event["frame_number"] for event in events], [72, 70, 71, 73])
        summary = SUMMARIZE.summarize(events)
        stream = summary["streams"][0]
        self.assertEqual(stream["first_frame"], 70)
        self.assertEqual(stream["last_frame"], 73)
        text = TIMELINE.render_text(events)
        self.assertLess(text.index("frame=70"), text.index("frame=71"))
        self.assertLess(text.index("frame=71"), text.index("frame=72"))

    def test_g_pdu_without_container_is_supported(self):
        event = events_for("g-pdu-basic.jsonl")[0]
        self.assertIsNone(event["pdu_session_container"])
        self.assertEqual(event["support_status"], "SUPPORTED")


class GtpuContainerTests(unittest.TestCase):
    def test_qfi_from_container_preserved(self):
        container = events_for("pdu-session-container.jsonl")[0]["pdu_session_container"]
        self.assertTrue(container["present"])
        self.assertEqual(container["pdu_type"], 0)
        self.assertEqual(container["pdu_type_name"], "DL PDU SESSION INFORMATION")
        self.assertEqual(container["qfi"], 9)

    def test_rqi_and_ppi_preserved(self):
        events = events_for("pdu-session-container.jsonl")
        self.assertTrue(events[1]["pdu_session_container"]["rqi"])
        self.assertFalse(events[2]["pdu_session_container"]["rqi"])
        self.assertEqual(events[2]["pdu_session_container"]["ppi"], 3)

    def test_multiple_qfi_over_time(self):
        events = events_for("pdu-session-container.jsonl")
        summary = SUMMARIZE.summarize(events)
        reverse_stream = [stream for stream in summary["streams"] if stream["observed_g_pdu_packet_count"] == 3][0]
        self.assertEqual(reverse_stream["qfi_values"], [5, 9])

    def test_ambiguous_container_values_are_not_selected(self):
        event = events_for("pdu-session-container.jsonl")[4]
        self.assertIsNone(event["pdu_session_container"])
        unbound = event["unbound_metadata"]
        self.assertEqual([entry["qfi"] for entry in unbound["pdu_session_container_values"]], [9, 5])
        self.assertTrue(any("not safely attributable" in limitation for limitation in unbound["limitations"]))

    def test_extension_header_chain_preserved(self):
        event = events_for("pdu-session-container.jsonl")[0]
        headers = event["extension_headers"]
        self.assertEqual([header["type"] for header in headers], [0x85])
        self.assertEqual(headers[0]["name"], "PDU Session Container")
        self.assertEqual(headers[0]["binding_basis"], "structured-input")

    def test_unknown_extension_header_kept_unknown(self):
        event = events_for("recognition.jsonl")[2]
        header = event["extension_headers"][0]
        self.assertEqual(header["type"], 119)
        self.assertIsNone(header["name"])


class GtpuControlMessageTests(unittest.TestCase):
    def test_echo_request_and_response(self):
        events = events_for("control-messages.jsonl")
        self.assertEqual(events[0]["header"]["message_type"], "Echo Request")
        self.assertEqual(events[0]["result"], "REQUEST")
        self.assertEqual(events[0]["recovery"], 7)
        self.assertEqual(events[1]["header"]["message_type"], "Echo Response")
        self.assertEqual(events[1]["result"], "RESPONSE")
        self.assertEqual(events[1]["recovery"], 9)

    def test_echo_request_without_visible_response_is_not_a_claim(self):
        events = events_for("control-messages.jsonl")
        self.assertEqual(events[2]["header"]["message_type"], "Echo Request")
        blob = json.dumps(events).lower()
        for forbidden in ("unavailable", "down", "defective"):
            self.assertNotIn(forbidden, blob)

    def test_error_indication_affected_teid_distinct_from_header(self):
        event = events_for("control-messages.jsonl")[3]
        self.assertEqual(event["header"]["message_type"], "Error Indication")
        self.assertEqual(event["error_indication"]["affected_teid"], 305419896)
        self.assertEqual(event["error_indication"]["header_teid"], 0)
        self.assertNotEqual(event["error_indication"]["affected_teid"], event["error_indication"]["header_teid"])

    def test_end_marker_preserved_without_teardown_claim(self):
        event = events_for("control-messages.jsonl")[4]
        self.assertEqual(event["header"]["message_type"], "End Marker")
        self.assertEqual(event["end_marker"]["teid"], 305419897)
        blob = json.dumps(event).lower()
        for forbidden in ("teardown completed", "tunnel closed", "released"):
            self.assertNotIn(forbidden, blob)

    def test_supported_extension_headers_notification(self):
        event = events_for("control-messages.jsonl")[5]
        self.assertEqual(event["header"]["message_type"], "Supported Extension Headers Notification")
        self.assertEqual(event["advertised_extension_header_count"], 3)
        self.assertEqual([entry["type"] for entry in event["advertised_extension_headers"]], [133, 64, 192])
        self.assertEqual(event["advertised_extension_headers"][0]["name"], "PDU Session Container")

    def test_unsupported_and_unknown_messages(self):
        events = events_for("recognition.jsonl")
        self.assertEqual(events[0]["header"]["message_type"], "Tunnel Status")
        self.assertEqual(events[0]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[1]["support_status"], "UNKNOWN")
        self.assertIsNone(events[1]["header"]["message_type"])


class GtpuInnerPacketTests(unittest.TestCase):
    def test_inner_ipv4_and_ipv6_metadata(self):
        events = events_for("inner-packets.jsonl")
        self.assertEqual(events[0]["inner_packet"]["ip_version"], 4)
        self.assertEqual(events[2]["inner_packet"]["ip_version"], 6)
        self.assertEqual(events[2]["inner_packet"]["source_address"], "2001:db8::5")

    def test_inner_udp_and_tcp_metadata_without_application_interpretation(self):
        events = events_for("inner-packets.jsonl")
        udp = events[1]["inner_packet"]
        self.assertEqual(udp["protocol"], 17)
        self.assertEqual(udp["destination_port"], 5060)
        tcp = events[2]["inner_packet"]
        self.assertEqual(tcp["protocol"], 6)
        blob = json.dumps(events).lower()
        for forbidden in ("sip", "https", "tls", "http", "rtp", "quic"):
            self.assertNotIn(forbidden, blob)

    def test_opaque_inner_packet_is_flagged(self):
        inner = events_for("inner-packets.jsonl")[0]["inner_packet"]
        self.assertTrue(inner["opaque"])
        self.assertEqual(inner["protocol"], 50)
        self.assertIsNone(inner["source_port"])

    def test_application_payload_is_never_accepted(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({
                "frame.number": "1", "frame.time_epoch": "0", "gtp.message": "255", "gtp.teid": "1",
                "inner_packet": {"ip_version": 4, "payload": "deadbeef"},
            }, "x.jsonl")

    def test_no_payload_persisted_anywhere(self):
        blobs = []
        for name in FIXTURE_NAMES:
            blobs.append((EXPECTED / f"{name}-events.jsonl").read_text(encoding="utf-8"))
            events = expected_events(name)
            blobs.append(TIMELINE.render_text(events))
            blobs.append(json.dumps(SUMMARIZE.summarize(events)))
            blobs.append(json.dumps([MODEL.project_trace_event(event) for event in events]))
        combined = "\n".join(blobs).lower()
        for forbidden in ("deadbeef", "payload_bytes", "application_payload", "\"payload\""):
            self.assertNotIn(forbidden, combined)


class GtpuTraceProjectionTests(unittest.TestCase):
    def test_trace_identity(self):
        projected = MODEL.project_trace_event(events_for("g-pdu-basic.jsonl")[0])
        self.assertEqual(projected["protocol"], "GTP-U")
        self.assertEqual(projected["interface"], "N3")
        self.assertEqual(projected["procedure"], "G-PDU")

    def test_teid_and_qfi_projection(self):
        event = events_for("pdu-session-container.jsonl")[0]
        projected = MODEL.project_trace_event(event)
        self.assertEqual(projected["session"], {"teid": "305419896", "qfi": 9})

    def test_zero_placeholder_teid_is_not_projected(self):
        event = events_for("control-messages.jsonl")[0]
        self.assertNotIn("session", MODEL.project_trace_event(event))

    def test_ambiguous_qfi_omits_generic_qfi(self):
        event = events_for("pdu-session-container.jsonl")[4]
        session = MODEL.project_trace_event(event).get("session", {})
        self.assertNotIn("qfi", session)

    def test_error_indication_affected_teid_not_projected_as_session(self):
        event = events_for("control-messages.jsonl")[3]
        self.assertNotIn("session", MODEL.project_trace_event(event))

    def test_no_foreign_or_subscriber_fields(self):
        for name in FIXTURE_NAMES:
            blob = json.dumps([MODEL.project_trace_event(event) for event in expected_events(name)])
            for forbidden in ("seid", "pdu_session_id", '"dnn"', '"apn"', "bearer_id", "subscriber", "supi"):
                self.assertNotIn(forbidden, blob, name)


class GtpuCliTests(unittest.TestCase):
    def test_deterministic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.jsonl"
            second = Path(directory) / "second.jsonl"
            EXTRACT.write_events(EXTRACTED / "g-pdu-basic.jsonl", "fields-jsonl", first, True)
            EXTRACT.write_events(EXTRACTED / "g-pdu-basic.jsonl", "fields-jsonl", second, True)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_expected_fixtures_match(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in FIXTURE_NAMES:
                output = Path(directory) / f"{name}.jsonl"
                EXTRACT.write_events(EXTRACTED / f"{name}.jsonl", "fields-jsonl", output, True)
                self.assertEqual(jsonl(output), expected_events(name), name)

    def test_events_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "gtpu-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        required = set(schema["required"])
        for name in FIXTURE_NAMES:
            for event in expected_events(name):
                self.assertTrue(required <= set(event), name)
                self.assertTrue(set(event) <= allowed, name)
                self.assertEqual(event["evidence"]["level"], "OBSERVED")
                self.assertIn(event["support_status"], {"SUPPORTED", "UNSUPPORTED", "UNKNOWN"})

    def test_stream_summary_conforms_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "gtpu-stream.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["$defs"]["stream"]["properties"])
        required = set(schema["$defs"]["stream"]["required"])
        for name in FIXTURE_NAMES:
            for stream in SUMMARIZE.summarize(expected_events(name))["streams"]:
                self.assertTrue(required <= set(stream), name)
                self.assertTrue(set(stream) <= allowed, name)

    def test_timeline_text_and_json(self):
        events = expected_events("control-messages")
        text = TIMELINE.render_text(events)
        self.assertIn("Echo Request", text)
        self.assertIn("End Marker", text)
        self.assertIn("end-marker=yes", text)
        self.assertIn("affected-teid=305419896", text)
        document = json.loads(TIMELINE.render_json(events))
        self.assertEqual(len(document["events"]), len(events))
        upper = text.upper()
        for forbidden in ("TUNNEL SUCCESS", "UPF FAILURE", "GNB FAILURE", "PACKET LOSS CONFIRMED", "PDU SESSION SUCCESS"):
            self.assertNotIn(forbidden, upper)

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
            EXTRACT.write_events(EXTRACTED / "g-pdu-basic.jsonl", "fields-jsonl", output, True)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "g-pdu-basic.jsonl", "fields-jsonl", output, False)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            ok = subprocess.run([sys.executable, str(SCRIPTS / "extract-gtpu.py"), str(EXTRACTED / "g-pdu-basic.jsonl"), "--input-format", "fields-jsonl", "--output", str(target / "ok.jsonl")], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            bad = subprocess.run([sys.executable, str(SCRIPTS / "extract-gtpu.py"), str(EXTRACTED / "malformed.jsonl"), "--input-format", "fields-jsonl", "--output", str(target / "bad.jsonl")], capture_output=True, text=True)
            self.assertEqual(bad.returncode, MODEL.EXIT_MALFORMED_INPUT)
            nodest = subprocess.run([sys.executable, str(SCRIPTS / "extract-gtpu.py"), str(EXTRACTED / "g-pdu-basic.jsonl")], capture_output=True, text=True)
            self.assertEqual(nodest.returncode, MODEL.EXIT_OUTPUT_FAILURE)

    def test_malformed_input_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            events_for("malformed.jsonl")

    def test_tshark_unavailable_is_clear(self):
        with mock.patch.object(MODEL.subprocess, "Popen", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                list(MODEL.tshark_records(Path("sample.pcapng")))
        with mock.patch.object(MODEL.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(MODEL.ToolUnavailable):
                MODEL.tshark_version()

    def test_tshark_command_is_argument_list(self):
        command = MODEL.build_tshark_fields_command(Path("sample.pcapng"))
        self.assertIn(Path(command[0]).name.lower(), ("tshark", "tshark.exe"))
        self.assertEqual(command[1:4], ["-n", "-r", "sample.pcapng"])
        self.assertNotIn("shell=True", command)
        self.assertIn("-Y", command)
        self.assertIn("gtp", command)
        for field in ("gtp.message", "gtp.teid", "gtp.seq_number", "gtp.ext_hdr.pdu_ses_con.qos_flow_id"):
            self.assertIn(field, command)


class GtpuFieldResolutionTests(unittest.TestCase):
    def tearDown(self):
        MODEL.set_discovery_overrides(None, None)

    def test_pdu_session_container_candidate_fallback(self):
        MODEL.set_discovery_overrides({
            "frame.number",
            "frame.time_epoch",
            "gtp.message",
            "gtp.ext_hdr_type",
            "gtp.ext_hdr.pdu_ses_cont.rqi",
            "gtp.ext_hdr.pdu_ses_cont.ppi",
            "gtp.ext_hdr.pdu_ses_cont.ppp",
        })
        mappings, _ = MODEL.resolve_field_specs(MODEL.FIELD_SPECS, MODEL.get_available_fields(), "test-ver")
        resolved = dict(mappings)
        self.assertIn("gtp.ext_hdr.pdu_ses_cont.rqi", resolved)
        self.assertEqual(resolved["gtp.ext_hdr.pdu_ses_cont.rqi"], "gtp.ext_hdr.pdu_ses_con.rqi")

    def test_missing_required_field_raises(self):
        MODEL.set_discovery_overrides({"frame.number"})
        with self.assertRaises(MODEL.TsharkError):
            MODEL.resolve_field_specs(MODEL.FIELD_SPECS, MODEL.get_available_fields(), "test-ver")

    def test_no_raw_decoder_in_scripts(self):
        for script in SCRIPTS.glob("*.py"):
            text = script.read_text(encoding="utf-8")
            for forbidden in ("struct.unpack", "int.from_bytes", "bytes.fromhex", "memoryview("):
                self.assertNotIn(forbidden, text, script.name)


class GtpuStandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "gtpu"
            shutil.copytree(PACKAGE, copied)
            scripts = copied / "scripts"
            for name in ("extract-gtpu.py", "summarize-gtpu.py", "gtpu_timeline.py"):
                result = subprocess.run([sys.executable, str(scripts / name), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            events = copied / "events.jsonl"
            result = subprocess.run([
                sys.executable, str(scripts / "extract-gtpu.py"),
                str(copied / "examples" / "extracted" / "pdu-session-container.jsonl"),
                "--input-format", "fields-jsonl", "--output", str(events),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            summary = copied / "streams.json"
            result = subprocess.run([sys.executable, str(scripts / "summarize-gtpu.py"), str(events), "--output", str(summary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("gtpu-path:", summary.read_text(encoding="utf-8"))
            timeline = subprocess.run([sys.executable, str(scripts / "gtpu_timeline.py"), str(events)], capture_output=True, text=True)
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("G-PDU", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
