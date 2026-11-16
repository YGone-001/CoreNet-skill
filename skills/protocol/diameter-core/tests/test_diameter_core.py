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
                "transport": {"association_reference": "assoc", "source_address": "a", "destination_address": "b", "source_port": 1, "destination_port": 2},
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
                "transport": {"association_reference": "assoc", "source_address": "a", "destination_address": "b", "source_port": 1, "destination_port": 2},
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
                "transport": {"association_reference": "assoc", "source_address": "b", "destination_address": "a", "source_port": 2, "destination_port": 1},
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


if __name__ == "__main__":
    unittest.main()