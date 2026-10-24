#!/usr/bin/env python3
"""Standalone tests for the bounded NAS-EPS Protocol Skill."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
EXTRACT = SCRIPTS / "extract-nas-eps.py"
TIMELINE = SCRIPTS / "nas_eps_timeline.py"
EXAMPLES = PACKAGE / "examples"

sys.path.insert(0, str(SCRIPTS))
import nas_eps_model as model  # noqa: E402


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

    # N1 / N2 / N6 ---------------------------------------------------------
    def test_attach_flow_identities(self) -> None:
        events = read_events(self.extract("attach-flow.jsonl"))
        self.assertEqual([event["message_type"] for event in events], ["Attach request", "Attach reject"])
        self.assertEqual(events[0]["procedure"], "eps-attach")
        self.assertEqual(events[0]["result"], "REQUEST")
        self.assertEqual(events[1]["result"], "REJECT")

    def test_attach_accept_and_complete(self) -> None:
        events = read_events(self.extract("attach-accept-complete.jsonl"))
        self.assertEqual(
            [event["message_type"] for event in events], ["Attach accept", "Attach complete"]
        )
        self.assertEqual([event["result"] for event in events], ["ACCEPT", "COMPLETE"])
        self.assertTrue(all(event["ciphered_payload_present"] for event in events))

    def test_authentication_request_and_response(self) -> None:
        events = read_events(self.extract("authentication.jsonl"))
        self.assertEqual(
            [event["message_type"] for event in events],
            ["Authentication request", "Authentication response"],
        )
        self.assertEqual([event["procedure"] for event in events], ["authentication", "authentication"])
        self.assertEqual([event["direction"] for event in events], ["downlink", "uplink"])

    # N3 / N5 / N7 ---------------------------------------------------------
    def test_authentication_failure_preserves_cause(self) -> None:
        events = read_events(self.extract("auth-failure.jsonl"))
        self.assertEqual(events[0]["message_type"], "Authentication failure")
        self.assertEqual(events[0]["emm_cause"], {"value": 20, "name": "MAC failure"})
        self.assertEqual(events[1]["message_type"], "Authentication reject")
        self.assertEqual(events[1]["emm_cause"], {"value": 3, "name": "Illegal UE"})

    def test_security_mode_reject_preserves_cause(self) -> None:
        events = read_events(self.extract("security-reject.jsonl"))
        self.assertEqual(events[0]["message_type"], "Security mode reject")
        self.assertEqual(events[0]["emm_cause"]["value"], 24)
        self.assertEqual(events[0]["procedure"], "security-mode-control")

    def test_attach_reject_preserves_cause(self) -> None:
        events = read_events(self.extract("attach-flow.jsonl"))
        self.assertEqual(events[1]["emm_cause"], {"value": 19, "name": "ESM failure"})

    # N4 / K ---------------------------------------------------------------
    def test_security_mode_control_is_separate_from_authentication(self) -> None:
        security = read_events(self.extract("security-mode.jsonl", name="security.jsonl"))
        authentication = read_events(self.extract("authentication.jsonl", name="auth.jsonl"))
        self.assertEqual(
            [event["procedure"] for event in security], ["security-mode-control", "security-mode-control"]
        )
        self.assertEqual(
            [event["procedure"] for event in authentication], ["authentication", "authentication"]
        )
        self.assertNotEqual(
            {event["procedure"] for event in security}, {event["procedure"] for event in authentication}
        )

    # N8 -------------------------------------------------------------------
    def test_protected_inner_message_is_not_fabricated(self) -> None:
        events = read_events(self.extract("protected-inner.jsonl"))
        self.assertEqual(events[0]["message_type"], "Security mode complete")
        self.assertEqual(events[0]["support_status"], "SUPPORTED")
        for event in events[1:]:
            self.assertIsNone(event["message_type"])
            self.assertEqual(event["support_status"], "PROTECTED_INNER_MESSAGE_UNAVAILABLE")
            self.assertTrue(event["protected_inner_message_unavailable"])
            self.assertTrue(event["ciphered_payload_present"])

    # N9 -------------------------------------------------------------------
    def test_esm_container_presence_without_decoding(self) -> None:
        events = read_events(self.extract("esm-container.jsonl"))
        event = events[0]
        self.assertTrue(event["esm_container_present"])
        self.assertEqual(event["esm_container_length"], 5)
        self.assertNotIn("esm_message_type", event)
        self.assertNotIn("apn", json.dumps(event).lower())

    # N10 ------------------------------------------------------------------
    def test_no_subscriber_or_authentication_material_is_published(self) -> None:
        forbidden_keys = {
            "imsi", "imei", "imeisv", "guti", "tmsi", "msisdn", "supi", "suci",
            "rand", "autn", "res", "xres", "kasme", "key", "identity_value",
            "esm_msg_cont", "ciphered_msg", "msg_auth_code", "nas_pdu",
        }
        for fixture in ("attach-flow.jsonl", "authentication.jsonl", "identity.jsonl", "protected-inner.jsonl"):
            events = read_events(self.extract(fixture, name=f"{fixture}.out"))
            for event in events:
                self.assertFalse(forbidden_keys & set(event), event)
                for value in event.values():
                    if isinstance(value, str):
                        self.assertNotRegex(value, r"\d{14,}")
                self.assertNotRegex(json.dumps(event), r"\b[0-9a-fA-F]{32,}\b")

    def test_identity_type_reports_only_the_numeric_value(self) -> None:
        events = read_events(self.extract("identity.jsonl"))
        self.assertEqual(events[0]["identity_type_value"], 1)
        self.assertIsNone(events[1]["identity_type_value"])
        self.assertNotIn("identity_value", json.dumps(events[0]))

    # Shared ---------------------------------------------------------------
    def test_expected_events_match_committed_golden_files(self) -> None:
        cases = {
            "attach-flow.jsonl": "attach-flow-events.jsonl",
            "attach-accept-complete.jsonl": "attach-accept-complete-events.jsonl",
            "authentication.jsonl": "authentication-events.jsonl",
            "identity.jsonl": "identity-events.jsonl",
            "auth-failure.jsonl": "auth-failure-events.jsonl",
            "security-mode.jsonl": "security-mode-events.jsonl",
            "security-reject.jsonl": "security-reject-events.jsonl",
            "protected-inner.jsonl": "protected-inner-events.jsonl",
            "esm-container.jsonl": "esm-container-events.jsonl",
            "unsupported.jsonl": "unsupported-events.jsonl",
        }
        for fixture, expected in cases.items():
            with self.subTest(fixture=fixture):
                produced = read_events(self.extract(fixture, name=f"{fixture}.out"))
                golden = read_events(EXAMPLES / "expected" / expected)
                self.assertEqual(produced, golden)

    def test_unsupported_and_unknown_messages_are_explicit(self) -> None:
        events = read_events(self.extract("unsupported.jsonl"))
        self.assertEqual(events[0]["support_status"], "UNSUPPORTED")
        self.assertEqual(events[0]["message_type"], "Tracking area update request")
        self.assertEqual(events[1]["support_status"], "UNKNOWN")
        self.assertIsNone(events[1]["message_type"])

    def test_deterministic_output(self) -> None:
        first = self.base / "a.jsonl"
        second = self.base / "b.jsonl"
        run(EXTRACT, str(EXAMPLES / "extracted" / "attach-flow.jsonl"), "--output", str(first))
        run(EXTRACT, str(EXAMPLES / "extracted" / "attach-flow.jsonl"), "--output", str(second))
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_trace_projection_contract(self) -> None:
        trace = self.base / "trace.jsonl"
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "attach-flow.jsonl"),
            "--output", str(self.base / "events.jsonl"),
            "--trace-output", str(trace),
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        projected = read_events(trace)
        self.assertEqual(projected[0]["protocol"], "NAS-EPS")
        self.assertEqual(projected[0]["interface"], "N1")
        self.assertEqual(projected[1]["result"]["code"], 19)

    def test_malformed_input_fails_visibly(self) -> None:
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "malformed.jsonl"),
            "--output", str(self.base / "malformed.jsonl"),
        )
        self.assertEqual(completed.returncode, 5)
        self.assertFalse((self.base / "malformed.jsonl").exists())

    def test_missing_required_field_fails_visibly(self) -> None:
        completed = run(
            EXTRACT,
            str(EXAMPLES / "extracted" / "missing-required.jsonl"),
            "--output", str(self.base / "missing.jsonl"),
        )
        self.assertEqual(completed.returncode, 5)
        self.assertIn("frame.time_epoch", completed.stderr)

    def test_existing_output_is_not_overwritten_without_force(self) -> None:
        output = self.base / "events.jsonl"
        output.write_text("keep-me\n", encoding="utf-8")
        completed = run(EXTRACT, str(EXAMPLES / "extracted" / "attach-flow.jsonl"), "--output", str(output))
        self.assertEqual(completed.returncode, 7)
        self.assertEqual(output.read_text(encoding="utf-8"), "keep-me\n")


class TimelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)
        self.events = self.base / "events.jsonl"
        run(EXTRACT, str(EXAMPLES / "extracted" / "auth-failure.jsonl"), "--output", str(self.events))

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_text_timeline_renders_cause_and_protection(self) -> None:
        completed = run(TIMELINE, str(self.events), "--format", "text")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("Authentication failure", completed.stdout)
        self.assertIn("cause=emm:20:MAC failure", completed.stdout)
        self.assertIn("protection=PLAIN", completed.stdout)

    def test_json_timeline_contract(self) -> None:
        completed = run(TIMELINE, str(self.events), "--format", "json")
        payload = json.loads(completed.stdout)
        self.assertEqual(len(payload["events"]), 2)
        self.assertEqual(payload["events"][0]["procedure"], "authentication")

    def test_timeline_rejects_malformed_events(self) -> None:
        broken = self.base / "broken.jsonl"
        broken.write_text("[]\n", encoding="utf-8")
        completed = run(TIMELINE, str(broken))
        self.assertEqual(completed.returncode, 5)


class ModelTests(unittest.TestCase):
    def test_protected_without_identity_is_unavailable_not_missing(self) -> None:
        name, status, procedure = model.resolve_message(None, "INTEGRITY_AND_CIPHERED")
        self.assertIsNone(name)
        self.assertEqual(status, "PROTECTED_INNER_MESSAGE_UNAVAILABLE")
        self.assertIsNone(procedure)

    def test_plain_without_identity_is_unknown(self) -> None:
        _, status, _ = model.resolve_message(None, "PLAIN")
        self.assertEqual(status, "UNKNOWN")

    def test_known_message_outside_scope_is_unsupported(self) -> None:
        name, status, procedure = model.resolve_message(72, "PLAIN")
        self.assertEqual(name, "Tracking area update request")
        self.assertEqual(status, "UNSUPPORTED")
        self.assertIsNone(procedure)

    def test_hexadecimal_message_type_is_accepted(self) -> None:
        event = model.normalize_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1741719000.000001000",
                "nas-eps.nas_msg_emm_type": "0x41",
                "nas-eps.security_header_type": "0",
            },
            "capture.pcap",
        )
        self.assertEqual(event["message_type"], "Attach request")
        self.assertEqual(event["protection"], "PLAIN")

    def test_comma_joined_security_header_uses_first_value(self) -> None:
        event = model.normalize_record(
            {
                "frame.number": "1",
                "frame.time_epoch": "1741719000.000001000",
                "nas-eps.nas_msg_emm_type": "0x5e",
                "nas-eps.security_header_type": "4,0,1,0",
            },
            "capture.pcap",
        )
        self.assertEqual(event["security_header_type"], 4)
        self.assertEqual(event["protection"], "INTEGRITY_AND_CIPHERED_NEW_CONTEXT")


if __name__ == "__main__":
    unittest.main()
