#!/usr/bin/env python3
"""Standalone tests for the bounded Diameter base-protocol Skill."""

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
EXAMPLES = PACKAGE / "examples"
EXPECTED = EXAMPLES / "expected"
EXTRACT = SCRIPTS / "extract-diameter-core.py"
CORRELATE = SCRIPTS / "correlate-diameter-core.py"
EVENT_SCHEMA = PACKAGE / "schemas" / "diameter-event.schema.json"
TRANSACTION_SCHEMA = PACKAGE / "schemas" / "diameter-transaction.schema.json"
TRACE_SCHEMA = PACKAGE / "schemas" / "trace-event.schema.json"

sys.path.insert(0, str(SCRIPTS))
import diameter_core_model as model  # noqa: E402


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, check=False)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_bytes(path: Path) -> bytes:
    return path.read_bytes()


class DiameterCoreCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def require_jsonschema(self) -> None:
        if jsonschema is None:
            if os.environ.get("CI"):
                self.fail("jsonschema is required for the Diameter schema gate in CI")
            self.skipTest("jsonschema unavailable")

    def extract(self, fixture: str, name: str = "events.jsonl") -> Path:
        output = self.base / name
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / fixture),
            "--output",
            str(output),
            "--force",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("wrote", completed.stdout)
        return output

    def correlate(self, events: Path, name: str = "transactions.json") -> tuple[Path, Path]:
        output = self.base / name
        timeline = self.base / (Path(name).stem + ".txt")
        completed = run(
            str(CORRELATE),
            str(events),
            "--output",
            str(output),
            "--timeline-output",
            str(timeline),
            "--force",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output, timeline

    def test_base_exchange_extraction_matches_expected(self) -> None:
        output = self.extract("pdml/base-exchange.pdml")
        self.assertEqual(read_bytes(output), read_bytes(EXPECTED / "base-events.jsonl"))

    def test_base_exchange_correlation_matches_expected(self) -> None:
        events = self.extract("pdml/base-exchange.pdml")
        transactions, timeline = self.correlate(events)
        self.assertEqual(read_bytes(transactions), read_bytes(EXPECTED / "base-transactions.json"))
        self.assertEqual(read_bytes(timeline), read_bytes(EXPECTED / "base-timeline.txt"))

    def test_negative_correlation_matches_expected(self) -> None:
        events = self.extract("dissector/negative-cases.jsonl", "negative-events.jsonl")
        self.assertEqual(read_bytes(events), read_bytes(EXPECTED / "negative-events.jsonl"))
        transactions, timeline = self.correlate(events, "negative-transactions.json")
        self.assertEqual(read_bytes(transactions), read_bytes(EXPECTED / "negative-transactions.json"))
        self.assertEqual(read_bytes(timeline), read_bytes(EXPECTED / "negative-timeline.txt"))

    def test_privacy_fixture_matches_expected_and_leaks_nothing(self) -> None:
        events = self.extract("dissector/privacy-cases.jsonl", "privacy-events.jsonl")
        self.assertEqual(read_bytes(events), read_bytes(EXPECTED / "privacy-events.jsonl"))
        text = events.read_text(encoding="utf-8")
        for secret in ("001010000000001", "a1b2c3d4e5f6", "IMSI"):
            self.assertNotIn(secret, text)

    def test_malformed_input_exits_with_input_error(self) -> None:
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / "dissector/malformed.jsonl"),
            "--output",
            str(self.base / "bad.jsonl"),
        )
        self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)
        self.assertIn("input error", completed.stderr)

    def test_missing_required_event_fields_exit_with_input_error(self) -> None:
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / "dissector/missing-required.jsonl"),
            "--output",
            str(self.base / "bad.jsonl"),
        )
        self.assertEqual(completed.returncode, model.EXIT_MALFORMED_INPUT)
        self.assertIn("header and transport", completed.stderr)

    def test_pdml_without_diameter_exits_no_events(self) -> None:
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / "pdml/no-diameter.pdml"),
            "--output",
            str(self.base / "none.jsonl"),
        )
        self.assertEqual(completed.returncode, model.EXIT_NO_EVENTS)

    def test_existing_output_requires_force(self) -> None:
        output = self.extract("pdml/base-exchange.pdml")
        completed = run(str(EXTRACT), str(EXAMPLES / "pdml/base-exchange.pdml"), "--output", str(output))
        self.assertEqual(completed.returncode, model.EXIT_OUTPUT_FAILURE)
        self.assertIn("use --force", completed.stderr)

    def test_deterministic_reruns(self) -> None:
        first = self.extract("pdml/base-exchange.pdml", "a.jsonl")
        second = self.extract("pdml/base-exchange.pdml", "b.jsonl")
        self.assertEqual(read_bytes(first), read_bytes(second))
        first_tx, first_tl = self.correlate(first, "a.json")
        second_tx, second_tl = self.correlate(second, "b.json")
        self.assertEqual(read_bytes(first_tx), read_bytes(second_tx))
        self.assertEqual(read_bytes(first_tl), read_bytes(second_tl))

    def test_trace_projection_matches_expected_and_schema(self) -> None:
        trace = self.base / "trace.jsonl"
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / "pdml/base-exchange.pdml"),
            "--trace-output",
            str(trace),
            "--force",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(read_bytes(trace), read_bytes(EXPECTED / "base-trace.jsonl"))
        self.require_jsonschema()
        schema = load_json(TRACE_SCHEMA)
        for row in load_jsonl(trace):
            jsonschema.validate(row, schema)

    def test_generated_events_and_transactions_validate_against_schemas(self) -> None:
        self.require_jsonschema()
        events = self.extract("pdml/base-exchange.pdml")
        transactions, _timeline = self.correlate(events)
        event_schema = load_json(EVENT_SCHEMA)
        transaction_schema = load_json(TRANSACTION_SCHEMA)
        for event in load_jsonl(events):
            jsonschema.validate(event, event_schema)
        jsonschema.validate(load_json(transactions), transaction_schema)

    def test_invalid_event_object_is_rejected_by_schema(self) -> None:
        self.require_jsonschema()
        schema = load_json(EVENT_SCHEMA)
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"frame_number": 1}, schema)


class DiameterCoreSemanticsTest(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        completed = run(
            str(EXTRACT),
            str(EXAMPLES / "pdml/base-exchange.pdml"),
            "--output",
            str(self.base / "events.jsonl"),
            "--trace-output",
            str(self.base / "trace.jsonl"),
            "--force",
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.events = load_jsonl(self.base / "events.jsonl")

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def event(self, frame: int, occurrence: int = 1) -> dict:
        matches = [
            event for event in self.events
            if event["frame_number"] == frame and event["message_occurrence"] == occurrence
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_header_version_flags_and_direction(self) -> None:
        request = self.event(1)
        answer = self.event(2)
        self.assertEqual(request["protocol_version"], 1)
        self.assertEqual(request["version_status"], "SUPPORTED")
        self.assertEqual(request["direction"], "REQUEST")
        self.assertTrue(request["flags"]["request"])
        self.assertEqual(answer["direction"], "ANSWER")
        self.assertFalse(answer["flags"]["request"])

    def test_valid_and_invalid_message_length_are_distinct(self) -> None:
        valid = self.event(1)
        mismatch = self.event(9)
        self.assertEqual(valid["message_length_status"], "VALID")
        self.assertEqual(mismatch["message_length_status"], "MISMATCH")
        self.assertEqual(mismatch["message_length"], 40)
        self.assertEqual(mismatch["observed_message_length"], 20)
        self.assertTrue(any("disagrees" in item for item in mismatch["limitations"]))

    def test_hop_by_hop_and_end_to_end_identifiers_stay_separate(self) -> None:
        event = self.event(1)
        self.assertEqual(event["hop_by_hop_id"], 1)
        self.assertEqual(event["end_to_end_id"], 0xA1)
        self.assertNotEqual(event["hop_by_hop_id"], event["end_to_end_id"])

    def test_multiple_messages_in_one_frame_keep_occurrence_identity(self) -> None:
        first = self.event(5, 1)
        second = self.event(5, 2)
        self.assertEqual(first["message_occurrence"], 1)
        self.assertEqual(second["message_occurrence"], 2)
        self.assertNotEqual(first["command_code"], second["command_code"])
        self.assertNotEqual(first["hop_by_hop_id"], second["hop_by_hop_id"])

    def test_transport_context_is_captured_for_tcp_and_sctp(self) -> None:
        sctp = self.event(1)
        tcp = self.event(3)
        self.assertEqual(sctp["transport"]["protocol"], "SCTP")
        self.assertEqual(sctp["transport"]["verification_tag"], "0x00000011")
        self.assertEqual(tcp["transport"]["protocol"], "TCP")
        self.assertEqual(tcp["transport"]["stream_id"], 7)
        self.assertNotEqual(
            sctp["transport"]["association_reference"],
            tcp["transport"]["association_reference"],
        )

    def test_grouped_avp_nesting_and_result_namespaces(self) -> None:
        event = self.event(8)
        grouped = [avp for avp in event["avps"] if avp["code"] == 297][0]
        self.assertEqual(grouped["grouping_status"], "DECODED")
        self.assertEqual([child["code"] for child in grouped["children"]], [298, 266])
        self.assertEqual(event["result"]["result_namespace"], "VENDOR_SPECIFIC")
        self.assertEqual(event["result"]["experimental_result_code"], 5001)
        self.assertIsNone(event["result"]["result_code"])
        self.assertIsNone(event["result"]["result_code_name"])

    def test_repeated_avps_keep_distinct_occurrences(self) -> None:
        event = self.event(7)
        repeated = [avp for avp in event["avps"] if avp["code"] == 282]
        self.assertEqual(len(repeated), 2)
        self.assertNotEqual(repeated[0]["avp_reference"], repeated[1]["avp_reference"])
        self.assertEqual([avp["occurrence_index"] for avp in repeated], [5, 6])

    def test_vendor_specific_and_unknown_avps_stay_opaque(self) -> None:
        event = self.event(7)
        unknown = [avp for avp in event["avps"] if avp["code"] == 9999][0]
        self.assertTrue(unknown["vendor_specific"])
        self.assertEqual(unknown["vendor_id"], 10415)
        self.assertIsNone(unknown["value"])
        self.assertEqual(unknown["value_kind"], "OPAQUE")
        self.assertFalse(unknown["name_reviewed"])

    def test_unknown_application_and_command_are_numeric_only(self) -> None:
        event = self.event(7)
        self.assertEqual(event["application_id"], 16777251)
        self.assertEqual(event["application_semantics"], "UNSUPPORTED")
        self.assertEqual(event["command_code"], 316)
        self.assertIsNone(event["command_name"])
        self.assertEqual(event["command_scope"], "APPLICATION_OR_UNKNOWN")

    def test_sensitive_avps_are_redacted(self) -> None:
        event = self.event(7)
        user_name = [avp for avp in event["avps"] if avp["code"] == 1][0]
        auth = [avp for avp in event["avps"] if avp["code"] == 1408][0]
        self.assertTrue(user_name["sensitive"])
        self.assertIsNone(user_name["value"])
        self.assertEqual(user_name["value_kind"], "SENSITIVE_REDACTED")
        self.assertTrue(auth["sensitive"])
        self.assertIsNone(auth["value"])
        self.assertEqual(auth["children"], [])
        self.assertGreater(auth["children_omitted"], 0)
        self.assertEqual(auth["grouping_status"], "REDACTED")

    def test_session_id_never_publishes_embedded_subscriber_value(self) -> None:
        event = self.event(7)
        session = [avp for avp in event["avps"] if avp["code"] == 263][0]
        self.assertIsNone(session["value"])
        self.assertEqual(session["value_kind"], "OPAQUE")
        self.assertTrue(any("Session-Id" in item for item in event["limitations"]))

    def test_timeline_shows_only_established_latency(self) -> None:
        transactions = model.correlate(self.events)
        for transaction in transactions["transactions"]:
            if transaction["correlation_status"] == "MATCHED":
                self.assertIsNotNone(transaction["latency_seconds"])
            else:
                self.assertIsNone(transaction["latency_seconds"])
        text = model.render_timeline(transactions)
        self.assertIn("MATCHED", text)
        self.assertIn("OPEN_REQUEST", text)
        self.assertIn("RESPONSE_ONLY", text)

    def test_no_application_or_procedure_verdict_is_published(self) -> None:
        serialized = json.dumps(self.events, sort_keys=True)
        for forbidden in (
            "procedure_family",
            "attach_success",
            "registration_success",
            "root_cause",
            "bearer_activated",
        ):
            self.assertNotIn(forbidden, serialized)


class DiameterCorrelationSemanticsTest(unittest.TestCase):
    def test_negative_fixture_distinguishes_all_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            events_path = directory / "events.jsonl"
            completed = run(
                str(EXTRACT),
                str(EXAMPLES / "dissector/negative-cases.jsonl"),
                "--output",
                str(events_path),
                "--force",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            document = model.correlate(load_jsonl(events_path))
        self.assertEqual(document["matched_count"], 1)
        self.assertEqual(document["open_request_count"], 4)
        self.assertEqual(document["response_only_count"], 1)
        self.assertEqual(document["ambiguous_count"], 1)
        self.assertEqual(document["retransmission_count"], 1)
        matched = [item for item in document["transactions"] if item["correlation_status"] == "MATCHED"][0]
        self.assertEqual(matched["request"]["frame_number"], 13)
        self.assertEqual(matched["answer"]["frame_number"], 14)
        ambiguous = [item for item in document["transactions"] if item["correlation_status"] == "AMBIGUOUS"][0]
        self.assertEqual(len(ambiguous["response_candidates"]), 2)
        self.assertIsNone(ambiguous["request"])

    def test_answer_cannot_be_assigned_to_multiple_requests(self) -> None:
        events = [
            {
                "capture_file": "one.pcapng",
                "frame_number": 1,
                "message_occurrence": 1,
                "frame_time_epoch": "1.0",
                "direction": "REQUEST",
                "command_code": 280,
                "application_id": 0,
                "hop_by_hop_id": 1,
                "end_to_end_id": 2,
                "transport": {"association_reference": "assoc", "association_identity_status": "DECODER_INDEX", "association_index": 0, "source_address": "a", "destination_address": "b", "source_port": 1, "destination_port": 2},
                "command_name": "Device-Watchdog",
                "result": {"result_code": None},
            },
            {
                "capture_file": "one.pcapng",
                "frame_number": 2,
                "message_occurrence": 1,
                "frame_time_epoch": "1.1",
                "direction": "REQUEST",
                "command_code": 280,
                "application_id": 0,
                "hop_by_hop_id": 1,
                "end_to_end_id": 2,
                "transport": {"association_reference": "assoc", "association_identity_status": "DECODER_INDEX", "association_index": 0, "source_address": "a", "destination_address": "b", "source_port": 1, "destination_port": 2},
                "command_name": "Device-Watchdog",
                "result": {"result_code": None},
            },
            {
                "capture_file": "one.pcapng",
                "frame_number": 3,
                "message_occurrence": 1,
                "frame_time_epoch": "1.2",
                "direction": "ANSWER",
                "command_code": 280,
                "application_id": 0,
                "hop_by_hop_id": 1,
                "end_to_end_id": 2,
                "transport": {"association_reference": "assoc", "association_identity_status": "DECODER_INDEX", "association_index": 0, "source_address": "b", "destination_address": "a", "source_port": 2, "destination_port": 1},
                "command_name": "Device-Watchdog",
                "result": {"result_code": 2001},
            },
        ]
        document = model.correlate(events)
        self.assertEqual(document["ambiguous_count"], 1)
        self.assertEqual(document["matched_count"], 0)
        ambiguous = [
            item
            for item in document["transactions"]
            if item["correlation_status"] == "AMBIGUOUS"
        ][0]
        self.assertIsNone(ambiguous["request"])

    def test_same_hop_id_across_connections_remains_independent(self) -> None:
        document = model.correlate(
            load_jsonl(EXAMPLES / "expected/negative-events.jsonl")
        )
        matched = [item for item in document["transactions"] if item["correlation_status"] == "MATCHED"][0]
        self.assertEqual(matched["answer"]["frame_number"], 14)
        self.assertEqual(matched["request"]["frame_number"], 13)

    def test_open_request_is_not_a_timeout_or_peer_failure(self) -> None:
        document = model.correlate(load_jsonl(EXAMPLES / "expected/negative-events.jsonl"))
        for transaction in document["transactions"]:
            if transaction["correlation_status"] == "OPEN_REQUEST":
                self.assertIn(
                    "does not prove a timeout or a peer failure",
                    " ".join(transaction["limitations"]),
                )


def make_record(
    *,
    frame: int,
    occurrence: int = 1,
    request: bool = True,
    command: int = 280,
    application: int = 0,
    hop: int,
    end_to_end: int,
    association_index: int | None = 0,
    protocol: str = "SCTP",
    stream_id: int | None = None,
    avps: list | None = None,
    capture: str = "synthetic.pcapng",
) -> dict:
    sctp = protocol == "SCTP"
    transport = {
        "protocol": protocol,
        "source_address": "10.9.0.1" if request else "10.9.0.2",
        "source_port": 40000 if request else 3868,
        "destination_address": "10.9.0.2" if request else "10.9.0.1",
        "destination_port": 3868 if request else 40000,
        "verification_tag": "0x00000001" if sctp else None,
        "stream_id": stream_id,
        "association_index": association_index if sctp else None,
    }
    return model.normalize_record(
        {
            "capture_file": capture,
            "frame_number": frame,
            "frame_time_epoch": f"{1700000000 + frame}.0",
            "message_occurrence": occurrence,
            "transport": transport,
            "header": {
                "version": 1,
                "length": 68,
                "flags": {
                    "request": request,
                    "proxyable": False,
                    "error": False,
                    "retransmitted": False,
                },
                "command_code": command,
                "application_id": application,
                "hop_by_hop_id": hop,
                "end_to_end_id": end_to_end,
            },
            "avps": avps or [],
        }
    )


class DiameterCorrelationIdentityTest(unittest.TestCase):
    def test_end_to_end_mismatch_never_attaches_request(self) -> None:
        request = make_record(frame=10, request=True, command=318, application=16777251, hop=100, end_to_end=500)
        answer = make_record(frame=11, request=False, command=318, application=16777251, hop=100, end_to_end=501)
        document = model.correlate([request, answer])
        response = [item for item in document["transactions"] if item["answer"]][0]
        self.assertEqual(response["correlation_status"], "RESPONSE_ONLY")
        self.assertIsNone(response["request"])
        self.assertIsNone(response["latency_seconds"])
        self.assertTrue(
            any("different end-to-end identifier" in item for item in response["limitations"])
        )
        open_requests = [item for item in document["transactions"] if item["correlation_status"] == "OPEN_REQUEST"]
        self.assertEqual([item["request"]["frame_number"] for item in open_requests], [10])
        self.assertEqual(document["matched_count"], 0)

    def test_one_valid_candidate_is_selected_over_contradictory_one(self) -> None:
        contradictory = make_record(frame=1, hop=100, end_to_end=500)
        valid = make_record(frame=2, hop=100, end_to_end=501)
        answer = make_record(frame=3, request=False, hop=100, end_to_end=501)
        document = model.correlate([contradictory, valid, answer])
        self.assertEqual(document["matched_count"], 1)
        matched = [item for item in document["transactions"] if item["correlation_status"] == "MATCHED"][0]
        self.assertEqual(matched["request"]["frame_number"], 2)
        self.assertEqual(document["open_request_count"], 1)
        self.assertEqual(document["ambiguous_count"], 0)

    def test_multiple_valid_candidates_remain_ambiguous(self) -> None:
        first = make_record(frame=1, hop=100, end_to_end=500)
        second = make_record(frame=2, hop=100, end_to_end=500)
        answer = make_record(frame=3, request=False, hop=100, end_to_end=500)
        document = model.correlate([first, second, answer])
        self.assertEqual(document["ambiguous_count"], 1)
        self.assertEqual(document["matched_count"], 0)
        ambiguous = [item for item in document["transactions"] if item["correlation_status"] == "AMBIGUOUS"][0]
        self.assertIsNone(ambiguous["request"])
        self.assertIsNone(ambiguous["latency_seconds"])
        self.assertEqual(len(ambiguous["response_candidates"]), 2)
        self.assertEqual(document["open_request_count"], 2)

    def test_consumed_request_is_not_reused_for_duplicate_answer(self) -> None:
        request = make_record(frame=1, hop=100, end_to_end=500)
        first_answer = make_record(frame=2, request=False, hop=100, end_to_end=500)
        duplicate_answer = make_record(frame=3, request=False, hop=100, end_to_end=500)
        document = model.correlate([request, first_answer, duplicate_answer])
        self.assertEqual(document["matched_count"], 1)
        self.assertEqual(document["response_only_count"], 1)
        reused = [item for item in document["transactions"] if item["answer"] and item["answer"]["frame_number"] == 3][0]
        self.assertIsNone(reused["request"])
        self.assertIsNone(reused["latency_seconds"])
        self.assertTrue(any("already assigned" in item for item in reused["limitations"]))

    def test_reused_hop_identifier_across_associations_stays_independent(self) -> None:
        documents = load_jsonl(EXAMPLES / "expected/association-reuse-events.jsonl")
        document = model.correlate(documents)
        self.assertEqual(document["matched_count"], 2)
        pairs = {
            (item["request"]["frame_number"], item["answer"]["frame_number"])
            for item in document["transactions"]
            if item["correlation_status"] == "MATCHED"
        }
        self.assertEqual(pairs, {(30, 33), (31, 32)})

    def test_tcp_streams_with_same_tuple_do_not_cross_pair(self) -> None:
        events = load_jsonl(EXAMPLES / "expected/tcp-stream-reuse-events.jsonl")
        document = model.correlate(events)
        self.assertEqual(document["matched_count"], 2)
        pairs = {
            (item["request"]["frame_number"], item["answer"]["frame_number"])
            for item in document["transactions"]
        }
        self.assertEqual(pairs, {(40, 43), (41, 42)})

    def test_missing_association_identity_is_fail_closed(self) -> None:
        for fixture in ("incomplete-association", "mid-capture-start"):
            events = load_jsonl(EXAMPLES / f"expected/{fixture}-events.jsonl")
            document = model.correlate(events)
            self.assertEqual(document["matched_count"], 0, fixture)
            self.assertEqual(document["open_request_count"], 1, fixture)
            self.assertEqual(document["response_only_count"], 1, fixture)
            response = [item for item in document["transactions"] if item["answer"]][0]
            self.assertIsNone(response["request"])
            self.assertIsNone(response["latency_seconds"])
            self.assertTrue(
                any("association identity" in item for item in response["limitations"])
            )

    def test_every_non_matched_transaction_has_no_selected_pair(self) -> None:
        for name in (
            "base-transactions.json",
            "negative-transactions.json",
            "association-reuse-transactions.json",
            "tcp-stream-reuse-transactions.json",
            "incomplete-association-transactions.json",
            "mid-capture-start-transactions.json",
        ):
            document = load_json(EXPECTED / name)
            for transaction in document["transactions"]:
                if transaction["correlation_status"] == "MATCHED":
                    self.assertIsNotNone(transaction["request"])
                    self.assertIsNotNone(transaction["answer"])
                    self.assertIsNotNone(transaction["latency_seconds"])
                    continue
                self.assertIsNone(transaction["latency_seconds"], name)
                if transaction["correlation_status"] == "RESPONSE_ONLY":
                    self.assertIsNone(transaction["request"], name)
                if transaction["correlation_status"] == "OPEN_REQUEST":
                    self.assertIsNone(transaction["answer"], name)
                if transaction["correlation_status"] == "AMBIGUOUS":
                    self.assertIsNone(transaction["request"], name)


class DiameterAvpBoundsTest(unittest.TestCase):
    def make_event(self, avps: list, **kwargs) -> dict:
        return make_record(frame=70, hop=700, end_to_end=800, avps=avps, **kwargs)

    def test_jsonl_avp_count_limit_and_omission_accounting(self) -> None:
        avps = [
            {"code": 264, "name": "Origin-Host", "length": 20, "value": "peer.example"}
            for _ in range(200)
        ]
        event = self.make_event(avps)
        self.assertEqual(event["avp_count"], model.MAX_AVPS)
        self.assertEqual(len(event["avps"]), model.MAX_AVPS)
        self.assertEqual(event["avps_omitted"], 200 - model.MAX_AVPS)
        self.assertTrue(any("bounded" in item for item in event["limitations"]))

    def test_jsonl_nesting_depth_limit_and_omission_accounting(self) -> None:
        node = {"code": 9999, "length": 12, "children": []}
        root = node
        for index in range(7):
            child = {"code": 9999 + index, "length": 12, "children": []}
            node["children"] = [child]
            node = child
        event = self.make_event([root])
        self.assertEqual(event["avp_count"], model.MAX_AVP_DEPTH)
        deepest = event["avps"][0]
        for _ in range(model.MAX_AVP_DEPTH - 1):
            deepest = deepest["children"][0]
        self.assertEqual(deepest["depth"], model.MAX_AVP_DEPTH)
        self.assertEqual(deepest["grouping_status"], "DEPTH_LIMITED")
        self.assertGreater(deepest["children_omitted"], 0)
        self.assertEqual(event["avp_count"] + event["avps_omitted"], 8)

    def test_jsonl_malformed_children_are_rejected(self) -> None:
        with self.assertRaises(model.InputError):
            self.make_event([{"code": 264, "children": "not-an-array"}])
        with self.assertRaises(model.InputError):
            self.make_event([{"code": 264, "children": [42]}])

    def test_jsonl_oversized_node_count_is_rejected(self) -> None:
        avps = [{"code": 9999, "length": 8} for _ in range(model.MAX_AVP_INPUT_NODES + 1)]
        with self.assertRaises(model.InputError) as raised:
            self.make_event(avps)
        self.assertIn("node count", str(raised.exception))

    def test_jsonl_excessive_input_depth_is_rejected(self) -> None:
        root = {"code": 9999, "children": []}
        node = root
        for index in range(model.MAX_AVP_INPUT_DEPTH):
            child = {"code": 9999, "children": []}
            node["children"] = [child]
            node = child
        with self.assertRaises(model.InputError) as raised:
            self.make_event([root])
        self.assertIn("depth", str(raised.exception))

    def test_sensitive_grouped_jsonl_omits_nested_authentication_vectors(self) -> None:
        event = self.make_event(
            [
                {
                    "code": 1408,
                    "vendor_specific": True,
                    "vendor_id": 10415,
                    "length": 64,
                    "children": [
                        {"code": 1413, "vendor_specific": True, "vendor_id": 10415, "length": 32, "children": [
                            {"code": 9998, "value": "RAND-SYNTHETIC-VALUE"},
                            {"code": 9997, "value": "AUTN-SYNTHETIC-VALUE"},
                        ]},
                        {"code": 9996, "value": "XRES-SYNTHETIC-VALUE"},
                    ],
                }
            ]
        )
        root = event["avps"][0]
        self.assertTrue(root["sensitive"])
        self.assertEqual(root["children"], [])
        self.assertEqual(root["grouping_status"], "REDACTED")
        self.assertGreater(root["children_omitted"], 0)
        self.assertEqual(event["avps_omitted"], 4)
        serialized = json.dumps(event)
        for secret in ("RAND-SYNTHETIC-VALUE", "AUTN-SYNTHETIC-VALUE", "XRES-SYNTHETIC-VALUE"):
            self.assertNotIn(secret, serialized)

    def test_pdml_and_jsonl_privacy_projection_parity(self) -> None:
        pdml_event = [
            event for event in load_jsonl(EXPECTED / "base-events.jsonl")
            if event["frame_number"] == 7
        ][0]
        jsonl_event = load_jsonl(EXPECTED / "privacy-events.jsonl")[0]
        for code in (1, 1408):
            left = [avp for avp in pdml_event["avps"] if avp["code"] == code][0]
            right = [avp for avp in jsonl_event["avps"] if avp["code"] == code][0]
            for field in (
                "sensitive",
                "value",
                "value_kind",
                "grouping_status",
                "children",
                "children_omitted",
            ):
                self.assertEqual(left[field], right[field], f"{code}:{field}")
        session = [avp for avp in pdml_event["avps"] if avp["code"] == 263][0]
        self.assertIsNone(session["value"])
        self.assertEqual(session["value_kind"], "OPAQUE")

    def test_privacy_is_safe_across_all_outputs(self) -> None:
        documents = load_jsonl(EXAMPLES / "expected/privacy-events.jsonl")
        transactions = model.correlate(documents)
        trace = [model.project_trace_event(event) for event in documents]
        payloads = [
            json.dumps(documents),
            json.dumps(transactions),
            json.dumps(trace),
            model.render_timeline(transactions),
        ]
        for payload in payloads:
            for secret in (
                "001010000000001",
                "a1b2c3d4e5f6",
                "IMSI",
                "RAND-SYNTHETIC-VALUE",
                "AUTN-SYNTHETIC-VALUE",
                "XRES-SYNTHETIC-VALUE",
            ):
                self.assertNotIn(secret, payload)


class DiameterNamespaceProvenanceTest(unittest.TestCase):
    def event_with(self, avps):
        return make_record(frame=80, hop=800, end_to_end=801, avps=avps)

    def test_base_result_code_requires_base_namespace(self) -> None:
        event = self.event_with([{"code": 268, "length": 12, "value": 2001}])
        self.assertEqual(event["result"]["result_status"], "SINGLE_BASE")
        self.assertEqual(event["result"]["result_code"], 2001)
        self.assertEqual(event["result"]["result_code_name"], "DIAMETER_SUCCESS")
        self.assertEqual(event["result"]["base_result_codes"][0]["avp_reference"], event["avps"][0]["avp_reference"])

    def test_vendor_specific_code_268_is_not_a_base_result(self) -> None:
        event = self.event_with(
            [{"code": 268, "vendor_specific": True, "vendor_id": 9999, "length": 12, "value": 2001}]
        )
        self.assertEqual(event["avps"][0]["namespace"], "UNKNOWN_VENDOR")
        self.assertEqual(event["result"]["result_status"], "MISSING")
        self.assertIsNone(event["result"]["result_code"])
        self.assertIsNone(event["result"]["result_code_name"])

    def test_vendor_specific_code_297_is_not_experimental_result(self) -> None:
        event = self.event_with(
            [
                {
                    "code": 297,
                    "vendor_specific": True,
                    "vendor_id": 9999,
                    "length": 32,
                    "children": [
                        {"code": 298, "vendor_specific": True, "vendor_id": 9999, "length": 12, "value": 5001},
                        {"code": 266, "vendor_specific": True, "vendor_id": 9999, "length": 12, "value": 9999},
                    ],
                }
            ]
        )
        self.assertEqual(event["avps"][0]["namespace"], "UNKNOWN_VENDOR")
        self.assertEqual(event["result"]["result_status"], "MISSING")
        self.assertEqual(event["result"]["experimental_results"], [])

    def test_nested_result_code_is_not_promoted(self) -> None:
        event = self.event_with(
            [
                {
                    "code": 279,
                    "length": 24,
                    "children": [{"code": 268, "length": 12, "value": 2001}],
                }
            ]
        )
        self.assertEqual(event["result"]["result_status"], "MISSING")
        self.assertIsNone(event["result"]["result_code"])

    def test_valid_experimental_result_preserves_group_and_children(self) -> None:
        event = self.event_with(
            [
                {
                    "code": 297,
                    "length": 32,
                    "children": [
                        {"code": 298, "length": 12, "value": 5001},
                        {"code": 266, "length": 12, "value": 10415},
                    ],
                }
            ]
        )
        self.assertEqual(event["result"]["result_status"], "SINGLE_EXPERIMENTAL")
        entry = event["result"]["experimental_results"][0]
        self.assertEqual(entry["vendor_id"], 10415)
        self.assertEqual(entry["code"], 5001)
        self.assertIsNotNone(entry["group_reference"])
        self.assertIsNotNone(entry["code_reference"])
        self.assertIsNotNone(entry["vendor_reference"])
        self.assertEqual(event["result"]["experimental_vendor_id"], 10415)

    def test_other_vendor_experimental_result_stays_unresolved(self) -> None:
        event = self.event_with(
            [
                {
                    "code": 297,
                    "length": 32,
                    "children": [
                        {"code": 298, "length": 12, "value": 5001},
                        {"code": 266, "length": 12, "value": 9999},
                    ],
                }
            ]
        )
        entry = event["result"]["experimental_results"][0]
        self.assertEqual(entry["vendor_id"], 9999)
        self.assertEqual(entry["code"], 5001)

    def test_duplicate_base_results_do_not_select_arbitrarily(self) -> None:
        event = self.event_with(
            [
                {"code": 268, "length": 12, "value": 2001},
                {"code": 268, "length": 12, "value": 5001},
            ]
        )
        self.assertEqual(event["result"]["result_status"], "DUPLICATE")
        self.assertIsNone(event["result"]["result_code"])
        self.assertEqual(len(event["result"]["base_result_codes"]), 2)

    def test_conflicting_result_namespaces_preserve_both(self) -> None:
        event = self.event_with(
            [
                {"code": 268, "length": 12, "value": 2001},
                {
                    "code": 297,
                    "length": 32,
                    "children": [
                        {"code": 298, "length": 12, "value": 5001},
                        {"code": 266, "length": 12, "value": 10415},
                    ],
                },
            ]
        )
        self.assertEqual(event["result"]["result_status"], "CONFLICTING")
        self.assertIsNone(event["result"]["result_code"])
        self.assertIsNone(event["result"]["experimental_result_code"])
        self.assertEqual(event["result"]["base_result_codes"][0]["code"], 2001)
        self.assertEqual(event["result"]["experimental_results"][0]["code"], 5001)

    def test_vendor_code_1_is_not_user_name_and_stays_redacted(self) -> None:
        event = self.event_with(
            [{"code": 1, "vendor_specific": True, "vendor_id": 9999, "length": 12, "value": "001010000000001"}]
        )
        avp = event["avps"][0]
        self.assertEqual(avp["namespace"], "UNKNOWN_VENDOR")
        self.assertIsNone(avp["name"])
        self.assertTrue(avp["sensitive"])
        self.assertIsNone(avp["value"])

    def test_base_code_1_is_user_name(self) -> None:
        event = self.event_with([{"code": 1, "length": 12, "value": "001010000000001"}])
        avp = event["avps"][0]
        self.assertEqual(avp["namespace"], "BASE")
        self.assertEqual(avp["name"], "User-Name")
        self.assertTrue(avp["sensitive"])
        self.assertIsNone(avp["value"])

    def test_vendor_code_263_is_not_session_id(self) -> None:
        event = self.event_with(
            [{"code": 263, "vendor_specific": True, "vendor_id": 9999, "length": 12, "value": "session"}]
        )
        avp = event["avps"][0]
        self.assertEqual(avp["namespace"], "UNKNOWN_VENDOR")
        self.assertIsNone(avp["name"])
        self.assertIsNone(avp["value"])


if __name__ == "__main__":
    unittest.main()