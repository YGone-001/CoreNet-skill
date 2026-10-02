"""Package-local test suite for the bounded PFCP (N4) Protocol Skill."""

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

import pfcp_model as MODEL


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


EXTRACT = load_script("extract-pfcp")
CORRELATE = load_script("correlate-pfcp")
TIMELINE = load_script("pfcp_timeline")

EXTRACTED = PACKAGE / "examples" / "extracted"
EXPECTED = PACKAGE / "examples" / "expected"

FIXTURE_NAMES = (
    "node-signaling",
    "establishment",
    "modification",
    "deletion",
    "transactions",
    "rule-binding",
    "recognition",
    "addresses",
)


def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def records(name: str) -> list[dict]:
    return list(MODEL.read_jsonl(EXTRACTED / name))


def events_for(name: str) -> list[dict]:
    return [MODEL.normalize_record(record, name) for record in records(name)]


class PfcpContractTests(unittest.TestCase):
    def test_manifest_contract(self):
        manifest = (PACKAGE / "manifest.yaml").read_text(encoding="utf-8")
        self.assertIn("name: pfcp", manifest)
        self.assertIn("version: 0.1.0", manifest)
        self.assertIn("category: protocol", manifest)
        self.assertIn("protocols: [PFCP]", manifest)
        self.assertIn("interfaces: [N4]", manifest)
        self.assertIn("network_functions: []", manifest)
        self.assertIn("required: []", manifest)

    def test_message_types_match_reviewed_table(self):
        self.assertEqual(MODEL.MESSAGE_TYPES[1][0], "PFCP Heartbeat Request")
        self.assertEqual(MODEL.MESSAGE_TYPES[50][0], "PFCP Session Establishment Request")
        self.assertEqual(MODEL.MESSAGE_TYPES[51][0], "PFCP Session Establishment Response")
        self.assertEqual(MODEL.MESSAGE_TYPES[52][0], "PFCP Session Modification Request")
        self.assertEqual(MODEL.MESSAGE_TYPES[54][0], "PFCP Session Deletion Request")
        self.assertEqual(MODEL.MESSAGE_TYPES[56][0], "PFCP Session Report Request")

    def test_supported_scope_is_bounded(self):
        for code in (1, 2, 5, 6, 50, 51, 52, 53, 54, 55):
            self.assertEqual(MODEL.resolve_message(code).support_status, "SUPPORTED", code)
        for code in (7, 9, 12, 56, 57):
            self.assertEqual(MODEL.resolve_message(code).support_status, "UNSUPPORTED", code)
        for code in (0, 40, 100, 200, 255):
            self.assertEqual(MODEL.resolve_message(code).support_status, "UNKNOWN", code)

    def test_cause_names_reviewed(self):
        self.assertEqual(MODEL.CAUSE_NAMES[1], "Request accepted (success)")
        self.assertEqual(MODEL.CAUSE_NAMES[64], "Request rejected (reason not specified)")
        self.assertEqual(MODEL.CAUSE_NAMES[65], "Session context not found")
        self.assertEqual(MODEL.CAUSE_NAMES[73], "Rule creation/modification Failure")

    def test_schemas_parse(self):
        for name in ("pfcp-event.schema.json", "pfcp-correlation.schema.json", "trace-event.schema.json"):
            document = json.loads((PACKAGE / "schemas" / name).read_text(encoding="utf-8"))
            self.assertEqual(document["$schema"], "https://json-schema.org/draft/2020-12/schema")

    def test_package_local_trace_schema_matches_shared_when_available(self):
        shared = PACKAGE.parents[2] / "shared" / "schemas" / "trace-event.schema.json"
        local = PACKAGE / "schemas" / "trace-event.schema.json"
        if not shared.is_file():
            self.skipTest("shared schema not present in standalone copy")
        self.assertEqual(local.read_bytes(), shared.read_bytes())

    def test_rule_arrays_not_singular(self):
        schema = json.loads((PACKAGE / "schemas" / "pfcp-event.schema.json").read_text(encoding="utf-8"))
        rule_operations = schema["properties"]["rule_operations"]
        for key in ("pdrs", "fars", "qers", "urrs"):
            self.assertEqual(rule_operations["properties"][key]["type"], "array", key)

    def test_message_map_documents_scope(self):
        text = (PACKAGE / "references" / "message-map.md").read_text(encoding="utf-8")
        for token in ("PFCP Session Establishment Request", "PFCP Session Modification Request", "PFCP Session Deletion Request", "SUPPORTED", "UNSUPPORTED"):
            self.assertIn(token, text)


class PfcpHeaderTests(unittest.TestCase):
    def test_establishment_request_seid_is_zero_expected(self):
        event = events_for("establishment.jsonl")[0]
        self.assertEqual(event["header"]["message_type"], "PFCP Session Establishment Request")
        self.assertEqual(event["header"]["seid"], 0)
        self.assertTrue(event["header"]["seid_expected_zero"])

    def test_non_establishment_message_does_not_expect_zero_seid(self):
        event = events_for("establishment.jsonl")[3]
        self.assertEqual(event["header"]["message_type"], "PFCP Session Establishment Response")
        self.assertFalse(event["header"]["seid_expected_zero"])

    def test_header_fields_preserved(self):
        event = events_for("node-signaling.jsonl")[0]
        header = event["header"]
        self.assertEqual(header["version"], 1)
        self.assertFalse(header["s_flag"])
        self.assertFalse(header["mp_flag"])
        self.assertEqual(header["sequence_number"], 100)
        self.assertEqual(header["message_length"], 12)

    def test_sequence_number_range_enforced(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({"frame.number": "1", "frame.time_epoch": "0", "pfcp.msg_type": "1", "pfcp.seqno": "16777216"}, "x.jsonl")

    def test_priority_range_enforced(self):
        with self.assertRaises(MODEL.InputError):
            MODEL.normalize_record({"frame.number": "1", "frame.time_epoch": "0", "pfcp.msg_type": "1", "pfcp.seqno": "1", "pfcp.mp": "16"}, "x.jsonl")


class PfcpSessionIdentityTests(unittest.TestCase):
    def test_cp_and_up_f_seid_stay_distinct(self):
        events = events_for("establishment.jsonl")
        request = events[0]
        self.assertEqual(request["session"]["cp_f_seid"], {"seid": 1001, "ipv4": "192.0.2.10", "ipv6": None})
        self.assertIsNone(request["session"]["up_f_seid"])
        response = events[3]
        self.assertIsNone(response["session"]["cp_f_seid"])
        self.assertEqual(response["session"]["up_f_seid"], {"seid": 2002, "ipv4": "192.0.2.20", "ipv6": None})

    def test_establishment_identity_transition(self):
        events = events_for("establishment.jsonl")
        request, response, follow_up = events[0], events[3], events[6]
        # TS 29.244 clause 7.2.2.4.2: the Establishment Request header SEID is 0
        # because the peer SEID is not yet available.
        self.assertEqual(request["header"]["seid"], 0)
        self.assertEqual(request["session"]["cp_f_seid"]["seid"], 1001)
        # The response header SEID is the SEID provided by the receiving entity
        # (the CP function), not the UP function's own F-SEID.
        self.assertEqual(response["header"]["seid"], 1001)
        self.assertEqual(response["session"]["up_f_seid"]["seid"], 2002)
        # Later session messages use the peer SEID: the UP function's F-SEID.
        self.assertEqual(follow_up["header"]["seid"], 2002)
        self.assertEqual(follow_up["header"]["message_type"], "PFCP Session Modification Request")

    def test_f_seid_role_not_derived_for_other_messages(self):
        event = MODEL.normalize_record({
            "frame.number": "1", "frame.time_epoch": "0", "pfcp.msg_type": "52", "pfcp.seqno": "1",
            "pfcp.f_seid.ipv4": "192.0.2.20",
        }, "x.jsonl")
        self.assertIsNone(event["session"]["cp_f_seid"])
        self.assertIsNone(event["session"]["up_f_seid"])
        self.assertTrue(any("role is not derivable" in limitation for limitation in event["unbound_ie_metadata"]["limitations"]))

    def test_generic_seid_projection_only_when_unambiguous(self):
        events = events_for("establishment.jsonl")
        self.assertEqual(MODEL.project_trace_event(events[0])["session"]["seid"], "1001")
        # The response carries both a CP-side header SEID and the UP F-SEID, so
        # the CP and UP identifiers are never collapsed into one generic value.
        self.assertNotIn("session", MODEL.project_trace_event(events[3]))


class PfcpSessionProcedureTests(unittest.TestCase):
    def test_heartbeat(self):
        events = events_for("node-signaling.jsonl")
        self.assertEqual(events[0]["header"]["message_type"], "PFCP Heartbeat Request")
        self.assertEqual(events[0]["result"], "REQUEST")
        self.assertIsNone(events[0]["direction"])
        self.assertEqual(events[1]["header"]["message_type"], "PFCP Heartbeat Response")
        self.assertEqual(events[1]["node"]["recovery_time_stamp"], "2024-01-02T03:06:41Z")

    def test_association_setup(self):
        events = events_for("node-signaling.jsonl")
        self.assertEqual(events[2]["header"]["message_type"], "PFCP Association Setup Request")
        self.assertEqual(events[2]["node"]["node_id"]["ipv4"], "192.0.2.10")
        self.assertEqual(events[2]["direction"], "control-plane-to-user-plane")
        self.assertEqual(events[3]["header"]["message_type"], "PFCP Association Setup Response")
        self.assertEqual(events[3]["node"]["node_id"]["fqdn"], "upf.example.net")
        self.assertEqual(events[3]["cause"]["code"], 1)

    def test_establishment_request_and_response(self):
        events = events_for("establishment.jsonl")
        self.assertEqual(events[0]["result"], "REQUEST")
        self.assertEqual(events[0]["direction"], "control-plane-to-user-plane")
        self.assertEqual(events[3]["result"], "RESPONSE")
        self.assertEqual(events[3]["direction"], "user-plane-to-control-plane")
        self.assertEqual(events[3]["cause"]["name"], "Request accepted (success)")

    def test_rejected_responses_preserve_cause(self):
        events = events_for("establishment.jsonl")
        self.assertEqual(events[4]["cause"], {"code": 64, "name": "Request rejected (reason not specified)"})
        self.assertEqual(events[5]["cause"], {"code": 75, "name": "No resources available"})

    def test_modification_operations(self):
        events = events_for("modification.jsonl")
        self.assertEqual(events[0]["rule_operations"]["fars"][0]["operation"], "UPDATE")
        self.assertEqual(events[1]["rule_operations"]["qers"][0]["operation"], "CREATE")
        self.assertEqual(events[2]["rule_operations"]["pdrs"][0]["operation"], "REMOVE")
        mixed = events[3]["rule_operations"]
        self.assertEqual([item["operation"] for item in mixed["pdrs"]], ["CREATE"])
        self.assertEqual([item["operation"] for item in mixed["fars"]], ["UPDATE"])
        self.assertEqual([item["operation"] for item in mixed["urrs"]], ["REMOVE"])

    def test_modification_responses(self):
        events = events_for("modification.jsonl")
        self.assertEqual(events[4]["cause"]["code"], 1)
        self.assertEqual(events[5]["cause"]["name"], "Rule creation/modification Failure")

    def test_deletion(self):
        events = events_for("deletion.jsonl")
        self.assertEqual(events[0]["header"]["message_type"], "PFCP Session Deletion Request")
        self.assertEqual(events[1]["cause"]["code"], 1)
        self.assertEqual(events[3]["cause"]["name"], "Session context not found")
        self.assertEqual(events[3]["header"]["seid"], 0)


class PfcpRuleModelTests(unittest.TestCase):
    def test_pdr_fields(self):
        pdr = events_for("establishment.jsonl")[0]["rule_operations"]["pdrs"][0]
        self.assertEqual(pdr["id"], 1)
        self.assertEqual(pdr["operation"], "CREATE")
        self.assertEqual(pdr["precedence"], 100)
        self.assertTrue(pdr["pdi_present"])
        self.assertEqual(pdr["source_interface"], "Access")
        self.assertEqual(pdr["f_teid"]["teid"], 4242)
        self.assertEqual(pdr["ue_ip"], {"ipv4": "192.0.2.55", "ipv6": None})
        self.assertEqual(pdr["network_instance"], "internet")
        self.assertEqual(pdr["qfi_values"], [9])
        self.assertEqual(pdr["far_ids"], [1])
        self.assertEqual(pdr["qer_ids"], [1])
        self.assertEqual(pdr["urr_ids"], [1])

    def test_far_fields(self):
        far = events_for("establishment.jsonl")[0]["rule_operations"]["fars"][0]
        self.assertEqual(far["apply_action"]["forward"], True)
        self.assertEqual(far["destination_interface"], "Core")
        self.assertTrue(far["outer_header_creation"]["present"])
        self.assertEqual(far["outer_header_creation"]["teid"], 777)

    def test_qer_fields(self):
        qer = events_for("establishment.jsonl")[0]["rule_operations"]["qers"][0]
        self.assertEqual(qer["gate_status"], {"ul": 0, "dl": 0})
        self.assertEqual(qer["qfi"], 9)
        self.assertEqual(qer["ul_mbr"], 1000)
        self.assertEqual(qer["dl_mbr"], 2000)

    def test_urr_fields(self):
        urr = events_for("establishment.jsonl")[0]["rule_operations"]["urrs"][0]
        self.assertEqual(urr["id"], 1)
        self.assertEqual(urr["operation"], "CREATE")
        self.assertTrue(urr["measurement_present"])

    def test_multiple_rule_groups_preserved(self):
        event = events_for("establishment.jsonl")[1]
        self.assertEqual([item["id"] for item in event["rule_operations"]["pdrs"]], [1, 2])
        self.assertEqual([item["qfi_values"] for item in event["rule_operations"]["pdrs"]], [[9], [5]])

    def test_network_instance_not_renamed_to_dnn(self):
        blob = json.dumps(events_for("establishment.jsonl"))
        self.assertIn("internet", blob)
        self.assertNotIn('"dnn"', blob)
        self.assertNotIn('"apn"', blob)

    def test_documentation_address_ranges_only(self):
        events = events_for("addresses.jsonl")
        self.assertEqual(events[0]["rule_operations"]["pdrs"][0]["ue_ip"]["ipv4"], "192.0.2.55")
        self.assertEqual(events[1]["rule_operations"]["pdrs"][0]["ue_ip"]["ipv6"], "2001:db8::5")

    def test_rule_operation_not_inferred_from_id(self):
        event = MODEL.normalize_record({
            "frame.number": "1", "frame.time_epoch": "0", "pfcp.msg_type": "52", "pfcp.seqno": "1", "pfcp.pdr_id": "5",
        }, "x.jsonl")
        self.assertIsNone(event["rule_operations"]["pdrs"][0]["operation"])


class PfcpGroupBindingTests(unittest.TestCase):
    def test_single_rule_binding_is_provable(self):
        pdr = events_for("rule-binding.jsonl")[0]["rule_operations"]["pdrs"][0]
        self.assertEqual(pdr["f_teid"]["teid"], 1111)
        self.assertEqual(pdr["qfi_values"], [9])
        self.assertEqual(pdr["binding_basis"], "single-rule-message")

    def test_multiple_teids_are_not_zipped(self):
        event = events_for("rule-binding.jsonl")[1]
        pdr = event["rule_operations"]["pdrs"][0]
        self.assertIsNone(pdr["f_teid"])
        self.assertEqual(event["unbound_ie_metadata"]["teids"], [1111, 2222])

    def test_two_pdrs_and_two_teids_stay_ambiguous(self):
        event = events_for("rule-binding.jsonl")[2]
        pdrs = event["rule_operations"]["pdrs"]
        self.assertEqual([item["id"] for item in pdrs], [1, 2])
        for item in pdrs:
            self.assertIsNone(item["f_teid"])
            self.assertEqual(item["qfi_values"], [])
            self.assertEqual(item["binding_basis"], "unbound")
        unbound = event["unbound_ie_metadata"]
        self.assertEqual(unbound["teids"], [1111, 2222])
        self.assertEqual(unbound["qfis"], [9, 5])
        # No positional zip: PDR 1 must not claim TEID 1111 / QFI 9.
        self.assertNotEqual(pdrs[0]["f_teid"], {"teid": 1111})

    def test_single_qer_qfi_binding(self):
        qer = events_for("rule-binding.jsonl")[3]["rule_operations"]["qers"][0]
        self.assertEqual(qer["qfi"], 9)
        self.assertEqual(qer["binding_basis"], "single-rule-message")

    def test_structured_multi_qer_binding(self):
        qers = events_for("rule-binding.jsonl")[4]["rule_operations"]["qers"]
        self.assertEqual([(item["id"], item["qfi"]) for item in qers], [(7, 9), (8, 5)])
        self.assertEqual({item["binding_basis"] for item in qers}, {"structured-input"})

    def test_flattened_ambiguous_qfis(self):
        event = events_for("rule-binding.jsonl")[5]
        qers = event["rule_operations"]["qers"]
        self.assertEqual([item["qfi"] for item in qers], [None, None])
        self.assertEqual(event["unbound_ie_metadata"]["qfis"], [9, 5])
        self.assertTrue(any("not safely bound" in limitation for limitation in event["unbound_ie_metadata"]["limitations"]))


class PfcpRecognitionTests(unittest.TestCase):
    def test_unsupported_and_unknown(self):
        events = events_for("recognition.jsonl")
        self.assertEqual(events[0]["header"]["message_type"], "PFCP Association Update Request")
        self.assertEqual(events[0]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[1]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[2]["support_status"], "UNKNOWN")
        self.assertIsNone(events[2]["header"]["message_type"])
        self.assertIsNone(events[2]["result"])

    def test_malformed_input_fails_loudly(self):
        with self.assertRaises(MODEL.InputError):
            events_for("malformed.jsonl")


class PfcpCorrelationTests(unittest.TestCase):
    def test_request_response_transaction(self):
        summary = CORRELATE.correlate(events_for("transactions.jsonl"))
        closed = summary["transactions"]
        self.assertEqual(len(closed), 1)
        transaction = closed[0]
        self.assertEqual(transaction["request_frames"], [40])
        self.assertEqual(transaction["response_frames"], [41])
        self.assertEqual(transaction["correlation_strength"], "STRONG")
        self.assertEqual(transaction["sequence_number"], 500)

    def test_sequence_reuse_across_endpoints_does_not_merge(self):
        summary = CORRELATE.correlate(events_for("transactions.jsonl"))
        keys = [item["transaction_key"] for item in summary["transactions"] + summary["open_transactions"]]
        self.assertEqual(len(keys), len(set(keys)))
        same_sequence = [key for key in keys if ":seq500:" in key]
        self.assertEqual(len(same_sequence), 2)

    def test_same_seid_across_endpoints_stays_separate(self):
        events = events_for("transactions.jsonl")
        deletion = [event for event in events if event["header"]["message_type"] == "PFCP Session Deletion Request"]
        self.assertEqual([event["header"]["seid"] for event in deletion], [4242, 4242])
        summary = CORRELATE.correlate(events)
        deletion_transactions = [item for item in summary["open_transactions"] if item["family"] == "SessionDeletion"]
        self.assertEqual(len(deletion_transactions), 2)

    def test_retransmission_preserved_as_candidate(self):
        summary = CORRELATE.correlate(events_for("transactions.jsonl"))
        retransmitted = [item for item in summary["open_transactions"] if item["sequence_number"] == 501]
        self.assertEqual(retransmitted[0]["request_frames"], [42, 43])
        self.assertEqual(retransmitted[0]["duplicate_request_candidates"], [43])

    def test_partial_capture_is_not_a_failure_claim(self):
        summary = CORRELATE.correlate(events_for("transactions.jsonl"))
        for item in summary["open_transactions"]:
            self.assertEqual(item["correlation_strength"], "WEAK")
            self.assertTrue(any("not evidence of a network failure" in limitation for limitation in item["limitations"]))
        blob = json.dumps(summary).lower()
        for forbidden in ("failed", "defective", "unavailable", "upf failure", "smf failure", "user plane"):
            self.assertNotIn(forbidden, blob)

    def test_out_of_order_input_still_correlates(self):
        events = events_for("transactions.jsonl")
        reversed_events = list(reversed(events))
        summary = CORRELATE.correlate(reversed_events)
        self.assertEqual(len(summary["transactions"]), 1)
        self.assertEqual(summary["transactions"][0]["request_frames"], [40])

    def test_expected_correlation_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.jsonl"
            EXTRACT.write_events(EXTRACTED / "transactions.jsonl", "fields-jsonl", events_path, True)
            output = Path(directory) / "correlation.json"
            CORRELATE.write_summary(events_path, output, True)
            expected = json.loads((EXPECTED / "transactions-correlation.json").read_text(encoding="utf-8"))
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), expected)


class PfcpTraceProjectionTests(unittest.TestCase):
    def test_trace_identity(self):
        projected = MODEL.project_trace_event(events_for("node-signaling.jsonl")[0])
        self.assertEqual(projected["protocol"], "PFCP")
        self.assertEqual(projected["interface"], "N4")
        self.assertEqual(projected["procedure"], "Heartbeat")

    def test_teid_and_qfi_single_projection(self):
        projected = MODEL.project_trace_event(events_for("rule-binding.jsonl")[0])
        self.assertEqual(projected["session"], {"teid": "1111", "qfi": 9})

    def test_multi_value_omission(self):
        projected = MODEL.project_trace_event(events_for("rule-binding.jsonl")[2])
        session = projected.get("session", {})
        self.assertNotIn("teid", session)
        self.assertNotIn("qfi", session)

    def test_no_pdu_session_id_dnn_apn_or_subscriber(self):
        for name in FIXTURE_NAMES:
            blob = json.dumps([MODEL.project_trace_event(event) for event in events_for(f"{name}.jsonl")])
            for forbidden in ("pdu_session_id", '"dnn"', '"apn"', "subscriber", "bearer_id"):
                self.assertNotIn(forbidden, blob, name)

    def test_no_gtp_u_or_pfcp_teid_verdict(self):
        text = TIMELINE.render_text(events_for("rule-binding.jsonl")).upper()
        for forbidden in ("GTP-U", "TUNNEL WORKING", "UPF FAILURE", "SMF FAILURE", "PDU SESSION SUCCESS", "N3 WORKING"):
            self.assertNotIn(forbidden, text)


class PfcpCliTests(unittest.TestCase):
    def test_deterministic_output(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.jsonl"
            second = Path(directory) / "second.jsonl"
            EXTRACT.write_events(EXTRACTED / "establishment.jsonl", "fields-jsonl", first, True)
            EXTRACT.write_events(EXTRACTED / "establishment.jsonl", "fields-jsonl", second, True)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_expected_fixtures_match(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in FIXTURE_NAMES:
                output = Path(directory) / f"{name}.jsonl"
                EXTRACT.write_events(EXTRACTED / f"{name}.jsonl", "fields-jsonl", output, True)
                self.assertEqual(jsonl(output), jsonl(EXPECTED / f"{name}-events.jsonl"), name)

    def test_events_conform_structurally(self):
        schema = json.loads((PACKAGE / "schemas" / "pfcp-event.schema.json").read_text(encoding="utf-8"))
        allowed = set(schema["properties"])
        required = set(schema["required"])
        for name in FIXTURE_NAMES:
            for event in jsonl(EXPECTED / f"{name}-events.jsonl"):
                self.assertTrue(required <= set(event), name)
                self.assertTrue(set(event) <= allowed, name)
                self.assertEqual(event["evidence"]["level"], "OBSERVED")
                self.assertIn(event["support_status"], {"SUPPORTED", "UNSUPPORTED", "UNKNOWN"})
                for derivation in event["derivations"]:
                    self.assertIn(derivation, schema["properties"]["derivations"]["items"]["enum"])

    def test_trace_projection_conforms_structurally(self):
        for name in FIXTURE_NAMES:
            for event in jsonl(EXPECTED / f"{name}-events.jsonl"):
                projected = MODEL.project_trace_event(event)
                self.assertIn("protocol", projected)
                self.assertEqual(projected["evidence"]["level"], "DERIVED")

    def test_timeline_text_and_json(self):
        events = jsonl(EXPECTED / "establishment-events.jsonl")
        text = TIMELINE.render_text(events)
        self.assertIn("PFCP Session Establishment Request", text)
        self.assertIn("Request accepted (success)(1)", text)
        self.assertIn("PDR[1:CREATE]", text)
        document = json.loads(TIMELINE.render_json(events))
        self.assertEqual(len(document["events"]), len(events))

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
            EXTRACT.write_events(EXTRACTED / "node-signaling.jsonl", "fields-jsonl", output, True)
            with self.assertRaises(OSError):
                EXTRACT.write_events(EXTRACTED / "node-signaling.jsonl", "fields-jsonl", output, False)

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            ok = subprocess.run([sys.executable, str(SCRIPTS / "extract-pfcp.py"), str(EXTRACTED / "node-signaling.jsonl"), "--input-format", "fields-jsonl", "--output", str(target / "ok.jsonl")], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            bad = subprocess.run([sys.executable, str(SCRIPTS / "extract-pfcp.py"), str(EXTRACTED / "malformed.jsonl"), "--input-format", "fields-jsonl", "--output", str(target / "bad.jsonl")], capture_output=True, text=True)
            self.assertEqual(bad.returncode, MODEL.EXIT_MALFORMED_INPUT)
            nodest = subprocess.run([sys.executable, str(SCRIPTS / "extract-pfcp.py"), str(EXTRACTED / "node-signaling.jsonl")], capture_output=True, text=True)
            self.assertEqual(nodest.returncode, MODEL.EXIT_OUTPUT_FAILURE)

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
        self.assertIn("pfcp", command)
        for field in ("pfcp.msg_type", "pfcp.seid", "pfcp.seqno", "pfcp.pdr_id", "pfcp.f_teid.teid", "pfcp.qfi_value"):
            self.assertIn(field, command)


class PfcpStandaloneTests(unittest.TestCase):
    def test_standalone_copy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "pfcp"
            shutil.copytree(PACKAGE, copied)
            scripts = copied / "scripts"
            for name in ("extract-pfcp.py", "correlate-pfcp.py", "pfcp_timeline.py"):
                result = subprocess.run([sys.executable, str(scripts / name), "--help"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
            events = copied / "events.jsonl"
            result = subprocess.run([
                sys.executable, str(scripts / "extract-pfcp.py"),
                str(copied / "examples" / "extracted" / "establishment.jsonl"),
                "--input-format", "fields-jsonl", "--output", str(events),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            correlation = copied / "correlation.json"
            result = subprocess.run([sys.executable, str(scripts / "correlate-pfcp.py"), str(events), "--output", str(correlation)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pfcp-tx:", correlation.read_text(encoding="utf-8"))
            timeline = subprocess.run([sys.executable, str(scripts / "pfcp_timeline.py"), str(events)], capture_output=True, text=True)
            self.assertEqual(timeline.returncode, 0, timeline.stderr)
            self.assertIn("PFCP Session Establishment Request", timeline.stdout)


if __name__ == "__main__":
    unittest.main()
