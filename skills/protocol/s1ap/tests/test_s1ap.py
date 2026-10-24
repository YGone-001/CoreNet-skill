#!/usr/bin/env python3
"""Standalone tests for the bounded S1AP Protocol Skill."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
EXTRACT = SCRIPTS / "extract-s1ap.py"
TIMELINE = SCRIPTS / "s1ap_timeline.py"
EXAMPLES = PACKAGE / "examples"

sys.path.insert(0, str(SCRIPTS))
import s1ap_model as model  # noqa: E402


def run(script: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(script), *args], capture_output=True, text=True, check=False
    )


def read_events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


class ExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def extract(self, fixture: str, name: str = "events.jsonl", extra: tuple[str, ...] = ()) -> Path:
        output = self.base / name
        completed = run(
            EXTRACT, str(EXAMPLES / "extracted" / fixture), "--output", str(output), *extra
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return output

    # S1 / S2 ---------------------------------------------------------------
    def test_s1_setup_identities(self) -> None:
        events = read_events(self.extract("s1-setup.jsonl"))
        self.assertEqual(
            [(event["pdu_type"], event["message_type"]) for event in events],
            [
                ("initiatingMessage", "S1SetupRequest"),
                ("successfulOutcome", "S1SetupResponse"),
                ("unsuccessfulOutcome", "S1SetupFailure"),
            ],
        )
        self.assertEqual([event["result"] for event in events], ["REQUEST", "SUCCESS", "FAILURE"])
        self.assertEqual([event["sender_role"] for event in events], ["enodeb", "mme", "mme"])

    def test_s1_setup_failure_retains_cause(self) -> None:
        events = read_events(self.extract("s1-setup.jsonl"))
        self.assertEqual(events[2]["cause"], {"category": "radioNetwork", "value": 1})
        self.assertEqual(events[2]["support_status"], "SUPPORTED")

    # S3 / S4 ---------------------------------------------------------------
    def test_initial_ue_message_preserves_frame_and_identifier(self) -> None:
        events = read_events(self.extract("ue-context-flow.jsonl"))
        first = events[0]
        self.assertEqual(first["frame_number"], 33)
        self.assertEqual(first["message_type"], "InitialUEMessage")
        self.assertEqual(first["enb_ue_s1ap_id"], 24)
        self.assertIsNone(first["mme_ue_s1ap_id"])
        self.assertTrue(first["nas_pdu_present"])
        self.assertEqual(first["nas_pdu_length"], 67)

    def test_nas_transport_directions_stay_distinct(self) -> None:
        events = read_events(self.extract("nas-transport.jsonl"))
        self.assertEqual(
            [event["message_type"] for event in events],
            ["DownlinkNASTransport", "UplinkNASTransport"],
        )
        self.assertEqual([event["sender_role"] for event in events], ["mme", "enodeb"])

    # S5 / S6 ---------------------------------------------------------------
    def test_initial_context_setup_evidence(self) -> None:
        events = read_events(self.extract("initial-context-setup.jsonl"))
        request, response, failure = events
        self.assertEqual(request["message_type"], "InitialContextSetupRequest")
        self.assertEqual(
            [(item["erab_id"], item["list_role"]) for item in request["erab_items"]],
            [(5, "REQUEST"), (6, "REQUEST")],
        )
        self.assertTrue(request["eutran_cgi_present"])
        self.assertEqual(response["message_type"], "InitialContextSetupResponse")
        self.assertEqual(response["result"], "SUCCESS")
        self.assertIn("extraction_limitations", response)
        self.assertEqual(failure["message_type"], "InitialContextSetupFailure")
        self.assertEqual(failure["result"], "FAILURE")
        self.assertEqual(failure["cause"], {"category": "radioNetwork", "value": 0})

    def test_initial_context_setup_success_is_not_an_attach_verdict(self) -> None:
        events = read_events(self.extract("initial-context-setup.jsonl"))
        response = events[1]
        self.assertEqual(response["result"], "SUCCESS")
        serialised = json.dumps(response).lower()
        for forbidden in ("attach", "healthy", "root cause", "verdict", "culprit"):
            self.assertNotIn(forbidden, serialised)

    # S7 -------------------------------------------------------------------
    def test_ue_release_sequence_preserved(self) -> None:
        events = read_events(self.extract("ue-release.jsonl"))
        self.assertEqual(
            [event["message_type"] for event in events],
            ["DownlinkNASTransport", "UEContextReleaseCommand", "UEContextReleaseComplete"],
        )
        command = events[1]
        self.assertEqual(command["result"], "COMMAND")
        self.assertEqual(command["cause"], {"category": "nas", "value": 0})

    # S8 / S9 --------------------------------------------------------------
    def test_multiple_ues_stay_separate(self) -> None:
        output = self.base / "multi.jsonl"
        correlation = self.base / "multi-correlation.json"
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "multi-ue.jsonl"),
            "--output", str(output),
            "--correlation-output", str(correlation),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads(correlation.read_text(encoding="utf-8"))
        strong = [item for item in summary["contexts"] if item["strength"] == "STRONG"]
        self.assertGreaterEqual(len(strong), 2)
        pairs = {(item["enb_ue_s1ap_id"], item["mme_ue_s1ap_id"]) for item in strong}
        self.assertEqual(len(pairs), len(strong))

    def test_conflicting_identifiers_remain_ambiguous(self) -> None:
        correlation = self.base / "conflict.json"
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "conflicting-ids.jsonl"),
            "--output", str(self.base / "conflict-events.jsonl"),
            "--correlation-output", str(correlation),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads(correlation.read_text(encoding="utf-8"))
        ambiguous = [item for item in summary["contexts"] if item["strength"] == "AMBIGUOUS"]
        self.assertEqual(len(ambiguous), 2)
        for item in ambiguous:
            self.assertTrue(item["ambiguity_reasons"])

    def test_partial_identifiers_are_supported_not_strong(self) -> None:
        correlation = self.base / "partial.json"
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "partial-ids.jsonl"),
            "--output", str(self.base / "partial-events.jsonl"),
            "--correlation-output", str(correlation),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        summary = json.loads(correlation.read_text(encoding="utf-8"))
        self.assertEqual([item["strength"] for item in summary["contexts"]], ["SUPPORTED"])

    # S10 ------------------------------------------------------------------
    def test_unsupported_and_unknown_messages_are_explicit(self) -> None:
        events = read_events(self.extract("unsupported.jsonl"))
        self.assertEqual(events[0]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[0]["procedure_name"], "id-Paging")
        self.assertIsNone(events[0]["message_type"])
        self.assertEqual(events[1]["support_status"], "UNKNOWN")
        self.assertIsNone(events[1]["procedure_name"])

    # Shared behaviour ------------------------------------------------------
    def test_expected_events_match_committed_golden_files(self) -> None:
        cases = {
            "s1-setup.jsonl": "s1-setup-events.jsonl",
            "initial-context-setup.jsonl": "initial-context-setup-events.jsonl",
            "conflicting-ids.jsonl": "conflicting-ids-events.jsonl",
            "partial-ids.jsonl": "partial-ids-events.jsonl",
            "unsupported.jsonl": "unsupported-events.jsonl",
            "multi-ue.jsonl": "multi-ue-events.jsonl",
            "ue-context-flow.jsonl": "ue-context-flow-events.jsonl",
            "nas-transport.jsonl": "nas-transport-events.jsonl",
            "ue-release.jsonl": "ue-release-events.jsonl",
        }
        for fixture, expected in cases.items():
            with self.subTest(fixture=fixture):
                produced = read_events(self.extract(fixture, name=f"{fixture}.out"))
                golden = read_events(EXAMPLES / "expected" / expected)
                self.assertEqual(produced, golden)

    def test_trace_projection_is_deterministic(self) -> None:
        first = self.base / "trace-a.jsonl"
        second = self.base / "trace-b.jsonl"
        for target in (first, second):
            completed = run(
                EXTRACT,
                str(EXAMPLES / "extracted" / "ue-context-flow.jsonl"),
                "--output", str(self.base / "events.jsonl"),
                "--trace-output", str(target),
                "--force",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        projected = read_events(first)
        self.assertEqual(projected[0]["protocol"], "S1AP")
        self.assertEqual(projected[0]["interface"], "S1-MME")
        self.assertNotIn("enb_ue_s1ap_id", projected[0])

    def test_output_is_deterministic(self) -> None:
        first = self.base / "det-a.jsonl"
        second = self.base / "det-b.jsonl"
        run(EXTRACT, str(EXAMPLES / "extracted" / "ue-context-flow.jsonl"), "--output", str(first))
        run(EXTRACT, str(EXAMPLES / "extracted" / "ue-context-flow.jsonl"), "--output", str(second))
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_no_nas_payload_is_published(self) -> None:
        events = read_events(self.extract("ue-context-flow.jsonl"))
        for event in events:
            serialised = json.dumps(event)
            self.assertNotIn("NAS_PDU", serialised)
            for value in event.values():
                if isinstance(value, str):
                    self.assertFalse(
                        value.startswith("00") and len(value) > 20,
                        "raw payload hex must not appear in an event",
                    )

    def test_malformed_input_fails_visibly(self) -> None:
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "malformed.jsonl"),
            "--output", str(self.base / "malformed.jsonl"),
        )
        self.assertEqual(completed.returncode, 5)
        self.assertIn("input error", completed.stderr)
        self.assertFalse((self.base / "malformed.jsonl").exists())

    def test_missing_required_field_fails_visibly(self) -> None:
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "missing-required.jsonl"),
            "--output", str(self.base / "missing.jsonl"),
        )
        self.assertEqual(completed.returncode, 5)
        self.assertIn("s1ap.procedureCode", completed.stderr)

    def test_existing_output_is_not_overwritten_without_force(self) -> None:
        output = self.base / "events.jsonl"
        output.write_text("keep-me\n", encoding="utf-8")
        completed = run(EXTRACT, str(EXAMPLES / "extracted" / "s1-setup.jsonl"), "--output", str(output))
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep-me\n")
        forced = run(
            EXTRACT, str(EXAMPLES / "extracted" / "s1-setup.jsonl"), "--output", str(output), "--force"
        )
        self.assertEqual(forced.returncode, 0)
        self.assertNotEqual(output.read_text(encoding="utf-8"), "keep-me\n")

    def test_no_destination_requested(self) -> None:
        completed = run(EXTRACT, str(EXAMPLES / "extracted" / "s1-setup.jsonl"))
        self.assertEqual(completed.returncode, 7)


class TimelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.events = self.base / "events.jsonl"
        run(EXTRACT, str(EXAMPLES / "extracted" / "ue-release.jsonl"), "--output", str(self.events))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_text_timeline_renders_frame_and_cause(self) -> None:
        completed = run(TIMELINE, str(self.events), "--format", "text")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("frame=47", completed.stdout)
        self.assertIn("UEContextReleaseCommand", completed.stdout)
        self.assertIn("cause=nas:0", completed.stdout)

    def test_json_timeline_contract(self) -> None:
        completed = run(TIMELINE, str(self.events), "--format", "json")
        payload = json.loads(completed.stdout)
        self.assertEqual(len(payload["events"]), 3)
        self.assertEqual(payload["events"][0]["message_type"], "DownlinkNASTransport")

    def test_timeline_rejects_malformed_events(self) -> None:
        broken = self.base / "broken.jsonl"
        broken.write_text('{"frame_number": 1}\n', encoding="utf-8")
        completed = run(TIMELINE, str(broken))
        self.assertEqual(completed.returncode, 5)


class ModelTests(unittest.TestCase):
    def test_procedure_identity_requires_a_known_pdu_branch(self) -> None:
        identity = model.resolve_procedure(9, None, None, "unavailable")
        self.assertEqual(identity["support_status"], "UNKNOWN")
        self.assertIsNone(identity["message_type"])

    def test_known_procedure_without_message_identity(self) -> None:
        identity = model.resolve_procedure(10, None, "initiatingMessage", "presence_field")
        self.assertEqual(identity["support_status"], "UNSUPPORTED")
        self.assertEqual(identity["procedure_name"], "id-Paging")

    def test_context_key_is_scoped_and_explicit(self) -> None:
        key = model.context_key("capture.pcap", "sctp-assoc-1", 5, None)
        self.assertEqual(key, "s1ap-context:capture.pcap:sctp-assoc-1:e5:m?")

    def test_erab_identifier_is_not_a_ue_identity(self) -> None:
        event = model.normalize_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1741719000.000001000",
                "s1ap.procedureCode": "9",
                "s1ap.initiatingMessage_element": "1",
                "s1ap.E_RABToBeSetupListCtxtSUReq": "1",
                "s1ap.e_RAB_ID": "5",
            },
            "capture.pcap",
        )
        self.assertIsNone(event["enb_ue_s1ap_id"])
        self.assertIsNone(event["mme_ue_s1ap_id"])
        self.assertEqual(event["erab_items"][0]["erab_id"], 5)


if __name__ == "__main__":
    unittest.main()
