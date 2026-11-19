#!/usr/bin/env python3
"""Deterministic tests for the bounded SIP Protocol Skill."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

try:
    import jsonschema
except ImportError:
    jsonschema = None

PACKAGE = Path(__file__).resolve().parents[1]
SCRIPTS = PACKAGE / "scripts"
CLI = SCRIPTS / "extract-sip.py"
SCHEMA = PACKAGE / "schemas" / "sip-events.schema.json"
TRACE_SCHEMA = PACKAGE / "schemas" / "trace-event.schema.json"
EXAMPLES = PACKAGE / "examples"
EXPECTED = EXAMPLES / "expected"

sys.path.insert(0, str(SCRIPTS))
import sip_model as model  # noqa: E402

TSHARK = shutil.which("tshark")
TEXT2PCAP = shutil.which("text2pcap")

PRIVATE_TOKENS = (
    "PRIVATE-USER-001",
    "PRIVATE-CALL-ID-001",
    "PRIVATE-BRANCH-001",
    "PRIVATE-FROM-TAG-001",
    "PRIVATE-TO-TAG-001",
    "PRIVATE-REASON-001",
    "secretuser",
    "callidsecret12345",
    "fromtagsecret",
    "totagsecret",
    "noncesecret",
    "digestresponse",
    "secretbody",
)

FORBIDDEN_SEMANTIC_TOKENS = (
    "registration_success",
    "registration_failure",
    "call_success",
    "call_failure",
    "transaction_status",
    "dialog_id",
    "transaction_matched",
    "ims_registered",
    "root_cause",
    "sdp_body",
    "rtp_stream",
)


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def event_by_frame(rows: list[dict], frame: int, occurrence: int = 1) -> dict:
    for row in rows:
        if row["frame_number"] == frame and row["message_occurrence"] == occurrence:
            return row
    raise AssertionError(f"no event for frame {frame}.{occurrence}")


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def hexdump(data: bytes) -> str:
    return "\n".join(
        f"{index:06x} " + " ".join(f"{byte:02x}" for byte in data[index:index + 16])
        for index in range(0, len(data), 16)
    )


def sip_message(method: str = "REGISTER", status: int | None = None) -> bytes:
    if status is None:
        start = f"{method} sip:ims.example SIP/2.0\r\n"
        cseq = f"CSeq: 1 {method}\r\n"
        extra = ""
    else:
        reason = {200: "OK", 401: "Unauthorized", 407: "Proxy Authentication Required"}.get(status, "Response")
        start = f"SIP/2.0 {status} {reason}\r\n"
        cseq = "CSeq: 1 REGISTER\r\n"
        extra = "WWW-Authenticate: Digest realm=\"ims.example\", nonce=\"PRIVATE-NONCE\"\r\n" if status == 401 else ""
    return (
        start
        + "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-PRIVATE-BRANCH\r\n"
        + "Max-Forwards: 70\r\n"
        + "From: <sip:PRIVATE-USER-001@ims.example>;tag=PRIVATE-FROM-TAG\r\n"
        + "To: <sip:PRIVATE-USER-001@ims.example>;tag=PRIVATE-TO-TAG\r\n"
        + "Call-ID: PRIVATE-CALL-ID@192.0.2.10\r\n"
        + cseq
        + extra
        + "Content-Length: 0\r\n\r\n"
    ).encode()


def build_capture(
    directory: Path,
    packets: list[bytes],
    *,
    mode: str = "udp",
    ipv6: bool = False,
    ports: tuple[int, int] = (5060, 5060),
    name: str = "synthetic.pcapng",
) -> Path:
    source = directory / f"{name}.txt"
    destination = directory / name
    source.write_text("\n\n".join(hexdump(packet) for packet in packets) + "\n", encoding="utf-8")
    command = [TEXT2PCAP, "-q"]
    if ipv6:
        command.extend(["-6", "2001:db8::1,2001:db8::2"])
    command.extend(["-u" if mode == "udp" else "-T", f"{ports[0]},{ports[1]}", str(source), str(destination)])
    completed = run(command)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "text2pcap failed")
    return destination


class SchemaContractTests(unittest.TestCase):
    def require_jsonschema(self) -> None:
        if jsonschema is None:
            if os.environ.get("CI"):
                self.fail("jsonschema is required for the SIP schema gate in CI")
            self.skipTest("jsonschema unavailable")

    def test_event_schema_is_strict(self) -> None:
        self.require_jsonschema()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertFalse(schema["additionalProperties"])
        self.assertIn("event_schema_version", schema["required"])
        self.assertFalse(schema["$defs"]["headers"]["additionalProperties"])
        self.assertFalse(schema["$defs"]["transport"]["additionalProperties"])
        self.assertIn("encrypted", schema["$defs"]["transport"]["required"])

    def test_expected_events_validate(self) -> None:
        self.require_jsonschema()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        for path in sorted(EXPECTED.glob("*-events.jsonl")):
            for row in load_jsonl(path):
                jsonschema.validate(row, schema)

    def test_expected_trace_projection_validates(self) -> None:
        self.require_jsonschema()
        schema = json.loads(TRACE_SCHEMA.read_text(encoding="utf-8"))
        for row in load_jsonl(EXPECTED / "base-udp-trace.jsonl"):
            jsonschema.validate(row, schema)

    def test_invalid_event_is_rejected(self) -> None:
        self.require_jsonschema()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate({"event_schema_version": "1.0.0", "protocol": "SIP"}, schema)

    def test_trace_schema_matches_shared_contract(self) -> None:
        shared = Path(__file__).resolve().parents[4] / "shared" / "schemas" / "trace-event.schema.json"
        self.assertEqual(json.loads(TRACE_SCHEMA.read_text(encoding="utf-8")), json.loads(shared.read_text(encoding="utf-8")))

    def test_no_transaction_or_ims_semantics_are_published(self) -> None:
        text = "\n".join(path.read_text(encoding="utf-8") for path in EXPECTED.glob("*.jsonl"))
        for token in FORBIDDEN_SEMANTIC_TOKENS:
            self.assertNotIn(token, text)


class SipMessageParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.rows = load_jsonl(EXPECTED / "message-cases-events.jsonl")

    def test_register_request(self) -> None:
        row = event_by_frame(self.rows, 1)
        self.assertEqual(row["message_type"], "REQUEST")
        self.assertEqual(row["method"], "REGISTER")
        self.assertEqual(row["method_scope"], "CORE")
        self.assertEqual(row["headers"]["cseq"]["sequence"], 1)
        self.assertTrue(row["headers"]["call_id"]["present"])
        self.assertTrue(row["headers"]["via"]["branch_present"])
        self.assertEqual(row["message_completeness"], "COMPLETE")

    def test_401_unauthorized_response(self) -> None:
        row = event_by_frame(self.rows, 2)
        self.assertEqual(row["message_type"], "RESPONSE")
        self.assertEqual(row["status_code"], 401)
        self.assertEqual(row["reason_phrase"], "Unauthorized")
        self.assertEqual(row["headers"]["www_authenticate"]["count"], 1)

    def test_407_proxy_authentication_required_response(self) -> None:
        row = event_by_frame(self.rows, 3)
        self.assertEqual(row["status_code"], 407)
        self.assertEqual(row["reason_phrase"], "Proxy Authentication Required")
        self.assertEqual(row["headers"]["proxy_authenticate"]["count"], 1)

    def test_200_ok_response(self) -> None:
        row = event_by_frame(self.rows, 4)
        self.assertEqual(row["status_code"], 200)
        self.assertEqual(row["reason_phrase"], "OK")

    def test_invite_request(self) -> None:
        row = event_by_frame(self.rows, 5)
        self.assertEqual(row["method"], "INVITE")
        self.assertEqual(row["headers"]["content_type"], "application/sdp")

    def test_100_trying(self) -> None:
        row = event_by_frame(self.rows, 6)
        self.assertEqual((row["status_code"], row["reason_phrase"]), (100, "Trying"))

    def test_180_ringing(self) -> None:
        row = event_by_frame(self.rows, 7)
        self.assertEqual((row["status_code"], row["reason_phrase"]), (180, "Ringing"))

    def test_183_session_progress(self) -> None:
        row = event_by_frame(self.rows, 8)
        self.assertEqual((row["status_code"], row["reason_phrase"]), (183, "Session Progress"))

    def test_ack_request(self) -> None:
        row = event_by_frame(self.rows, 9)
        self.assertEqual((row["method"], row["headers"]["cseq"]["method"]), ("ACK", "ACK"))

    def test_bye_request(self) -> None:
        self.assertEqual(event_by_frame(self.rows, 10)["method"], "BYE")

    def test_cancel_request(self) -> None:
        self.assertEqual(event_by_frame(self.rows, 11)["method"], "CANCEL")

    def test_options_request(self) -> None:
        self.assertEqual(event_by_frame(self.rows, 12)["method"], "OPTIONS")

    def test_unknown_extension_method(self) -> None:
        row = event_by_frame(self.rows, 13)
        self.assertEqual(row["method"], "X-CUSTOM")
        self.assertEqual(row["method_scope"], "EXTENSION")
        self.assertEqual(row["message_completeness"], "COMPLETE")
        self.assertTrue(any("extension method" in item for item in row["limitations"]))

    def test_response_without_request_in_capture(self) -> None:
        row = event_by_frame(self.rows, 14)
        self.assertEqual(row["message_type"], "RESPONSE")
        self.assertEqual(row["status_code"], 404)
        self.assertEqual(row["reason_phrase"], "Not Found")

    def test_request_without_response_in_capture(self) -> None:
        row = event_by_frame(self.rows, 15)
        self.assertEqual(row["message_type"], "REQUEST")
        self.assertEqual(row["method"], "MESSAGE")
        self.assertEqual(row["message_completeness"], "COMPLETE")

    def test_repeated_registration_is_preserved(self) -> None:
        rows = [row for row in self.rows if row["method"] == "REGISTER" and row["message_type"] == "REQUEST"]
        self.assertEqual([row["frame_number"] for row in rows], [1, 16])
        self.assertNotEqual(rows[0]["source_reference"], rows[1]["source_reference"])


class SipContactExpirationMetadataTests(unittest.TestCase):
    def _record(self, headers: dict) -> dict:
        base = {
            "capture_file": "contact.pcapng",
            "frame_number": 1,
            "frame_time_epoch": "1700000000.000000001",
            "frame_time_relative": "1.000000000",
            "message_occurrence": 1,
            "transport": {
                "protocol": "UDP",
                "source_address": "192.0.2.10",
                "source_port": 5060,
                "destination_address": "192.0.2.20",
                "destination_port": 5060,
                "stream_id": None,
            },
            "headers": {
                "method": "REGISTER",
                "cseq_sequence": 1,
                "cseq_method": "REGISTER",
                "call_id": "CALL",
                "via": [
                    {
                        "branch": "z9hG4bK-A",
                        "sent_by": "192.0.2.10:5060",
                        "transport": "UDP",
                    }
                ],
                "from": {"uri": "sip:alice@example.com", "count": 1, "tag": "FTAG"},
                "to": {"uri": "sip:registrar.example.com", "count": 1, "tag": None},
                "request_uri": "sip:registrar.example.com",
                "contact_count": 0,
                **headers,
            },
        }
        return model.normalize_record_message(base)

    def test_mixed_contact_expiration_is_aggregate_and_private(self) -> None:
        record = self._record(
            {
                "contact_count": 2,
                "contact_expiration_values": [0, 3600],
            }
        )
        entries = record["event"]["headers"]["contact_entries"]
        self.assertEqual(entries["total"], 2)
        self.assertEqual(entries["non_wildcard"], 2)
        self.assertEqual(entries["explicit_expires"], 2)
        self.assertEqual(entries["zero_expires"], 1)
        self.assertEqual(entries["positive_expires"], 1)
        self.assertEqual(entries["boundary_status"], "EXACT_ENTRY_VALUES")
        self.assertTrue(entries["expiration_complete"])
        self.assertEqual(record["match"]["contact_zero_expires_count"], 1)
        self.assertEqual(record["match"]["contact_positive_expires_count"], 1)

    def test_multiple_headers_without_entry_values_preserve_boundary_limit(self) -> None:
        record = self._record(
            {
                "contact_count": 3,
                "contact_non_wildcard": True,
            }
        )
        entries = record["event"]["headers"]["contact_entries"]
        self.assertEqual(entries["total"], 3)
        self.assertEqual(entries["without_explicit_expires"], 3)
        self.assertEqual(entries["boundary_status"], "HEADER_OCCURRENCE_ONLY")
        self.assertFalse(entries["expiration_complete"])

    def test_contact_uri_is_never_published(self) -> None:
        record = self._record(
            {
                "contact_count": 1,
                "contact_expiration_values": [0],
            }
        )
        text = json.dumps(record["event"])
        self.assertNotIn("sip:", text)
        self.assertNotIn("contact_uri", text)

    def test_raw_mixed_wildcard_and_contact_is_mixed(self) -> None:
        summary = model._contact_expiration(
            "Contact: *, <sip:alice@device.example>\nExpires: 0\n"
        )
        self.assertEqual(summary["contact_wildcard_count"], 1)
        self.assertEqual(summary["contact_non_wildcard_count"], 1)
        self.assertEqual(summary["contact_wildcard_boundary"], "MIXED")

    def test_raw_duplicate_wildcards_are_duplicate(self) -> None:
        for raw in (
            "Contact: *\nContact: *\nExpires: 0\n",
            "Contact: *, *\nExpires: 0\n",
        ):
            with self.subTest(raw=raw):
                summary = model._contact_expiration(raw)
                self.assertEqual(summary["contact_wildcard_count"], 2)
                self.assertEqual(summary["contact_wildcard_boundary"], "DUPLICATE")

    def test_raw_bracketed_uri_comma_is_one_boundary(self) -> None:
        summary = model._contact_expiration(
            "Contact: <sip:alice,smith@device.example>;expires=0\n"
        )
        self.assertEqual(summary["contact_non_wildcard_count"], 1)
        self.assertEqual(summary["contact_zero_expires_count"], 1)
        self.assertEqual(summary["contact_boundary_status"], "HEADER_OCCURRENCE_ONLY")
        self.assertEqual(summary["contact_wildcard_boundary"], "NONE")

    def test_raw_unbracketed_uri_comma_is_unresolved(self) -> None:
        summary = model._contact_expiration(
            "Contact: sip:alice,smith@device.example;expires=0\n"
        )
        self.assertEqual(summary["contact_boundary_status"], "UNRESOLVED")
        self.assertEqual(summary["contact_wildcard_boundary"], "UNRESOLVED")

    def test_raw_truncated_contact_is_unresolved(self) -> None:
        summary = model._contact_expiration(
            "Contact: <sip:alice@device.example;expires=0\n"
        )
        self.assertEqual(summary["contact_boundary_status"], "UNRESOLVED")
        self.assertEqual(summary["contact_wildcard_boundary"], "UNRESOLVED")

    def test_raw_malformed_wildcard_is_malformed(self) -> None:
        summary = model._contact_expiration(
            "Contact: *;expires=abc\nExpires: 0\n"
        )
        self.assertEqual(summary["contact_wildcard_count"], 1)
        self.assertEqual(summary["contact_malformed_wildcard_count"], 1)
        self.assertEqual(summary["contact_wildcard_boundary"], "MALFORMED")

    def test_uri_starting_with_star_is_not_a_wildcard(self) -> None:
        summary = model._contact_expiration(
            "Contact: *user@device.example;expires=0\n"
        )
        self.assertEqual(summary["contact_wildcard_count"], 0)
        self.assertEqual(summary["contact_non_wildcard_count"], 1)
        self.assertEqual(summary["contact_zero_expires_count"], 1)
        self.assertEqual(summary["contact_wildcard_boundary"], "NONE")

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_contact_entries_validate_against_event_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        record = self._record(
            {
                "contact_count": 2,
                "contact_expiration_values": [0, 3600],
            }
        )
        jsonschema.validate(record["event"], schema)

    @unittest.skipIf(jsonschema is None, "jsonschema is not installed")
    def test_new_contact_boundary_fields_remain_optional(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        record = self._record(
            {
                "contact_count": 1,
                "contact_expiration_values": [0],
            }
        )
        entries = record["event"]["headers"]["contact_entries"]
        del entries["wildcard_boundary"]
        del entries["malformed_wildcard"]
        jsonschema.validate(record["event"], schema)


class SipTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base = load_jsonl(EXPECTED / "base-udp-events.jsonl")
        cls.transport = load_jsonl(EXPECTED / "transport-cases-events.jsonl")
        cls.tcp = load_jsonl(EXPECTED / "tcp-reassembled-events.jsonl")
        cls.multi = load_jsonl(EXPECTED / "multi-message-events.jsonl")

    def test_udp_transport(self) -> None:
        row = event_by_frame(self.base, 1)
        self.assertEqual(row["transport"]["protocol"], "UDP")
        self.assertEqual(row["transport"]["reassembly"], "NOT_APPLICABLE")
        self.assertFalse(row["transport"]["encrypted"])

    def test_ipv4_addresses(self) -> None:
        row = event_by_frame(self.base, 1)
        self.assertEqual(row["transport"]["source_address"], "192.0.2.10")
        self.assertEqual(row["transport"]["destination_address"], "192.0.2.20")

    def test_tcp_reassembly(self) -> None:
        row = event_by_frame(self.tcp, 2)
        self.assertEqual(row["transport"]["protocol"], "TCP")
        self.assertEqual(row["transport"]["stream_id"], 0)
        self.assertEqual(row["transport"]["reassembly"], "REASSEMBLED")
        self.assertEqual(row["transport"]["segment_count"], 2)
        self.assertEqual(row["transport"]["reassembled_length"], 240)

    def test_ipv6_addresses(self) -> None:
        row = event_by_frame(self.transport, 3)
        self.assertEqual(row["transport"]["source_address"], "2001:db8::1")
        self.assertEqual(row["transport"]["destination_address"], "2001:db8::2")

    def test_tcp_single_segment_status(self) -> None:
        row = event_by_frame(self.transport, 4)
        self.assertEqual(row["transport"]["protocol"], "TCP")
        self.assertEqual(row["transport"]["reassembly"], "SINGLE_SEGMENT")

    def test_multiple_messages_in_one_capture(self) -> None:
        self.assertEqual(len(load_jsonl(EXPECTED / "message-cases-events.jsonl")), 16)

    def test_multiple_messages_in_one_frame(self) -> None:
        first = event_by_frame(self.multi, 1, 1)
        second = event_by_frame(self.multi, 1, 2)
        self.assertEqual(first["method"], "OPTIONS")
        self.assertEqual(second["status_code"], 200)
        self.assertNotEqual(first["source_reference"], second["source_reference"])

    def test_non_standard_port_record(self) -> None:
        row = event_by_frame(self.transport, 6)
        self.assertEqual((row["transport"]["source_port"], row["transport"]["destination_port"]), (5070, 5070))

    def test_no_sip_messages_is_not_a_decoder_failure(self) -> None:
        completed = run(
            [sys.executable, str(CLI), str(EXAMPLES / "pdml" / "no-sip.pdml"), "--output", str(Path(tempfile.mkdtemp()) / "out.jsonl")]
        )
        self.assertEqual(completed.returncode, 3)


class SipDefensiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_invalid_capture_is_rejected(self) -> None:
        bad = self.base / "invalid.pcapng"
        bad.write_bytes(b"not a capture")
        completed = run([sys.executable, str(CLI), str(bad), "--output", str(self.base / "out.jsonl")])
        self.assertEqual(completed.returncode, 2)
        self.assertFalse((self.base / "out.jsonl").exists())

    def test_missing_input_is_rejected(self) -> None:
        completed = run([sys.executable, str(CLI), str(self.base / "missing.jsonl"), "--output", str(self.base / "out.jsonl")])
        self.assertEqual(completed.returncode, 2)

    def test_malformed_jsonl_is_rejected_without_echoing_values(self) -> None:
        bad = self.base / "bad.jsonl"
        bad.write_text('{"frame_number": 1, "headers": {"call_id": "PRIVATE-CALL-ID-001"', encoding="utf-8")
        completed = run([sys.executable, str(CLI), str(bad), "--output", str(self.base / "out.jsonl")])
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("PRIVATE-CALL-ID-001", completed.stderr)

    def test_missing_source_frame_is_rejected(self) -> None:
        bad = self.base / "bad.jsonl"
        bad.write_text(json.dumps({"transport": {"protocol": "UDP"}, "headers": {"method": "OPTIONS"}}), encoding="utf-8")
        completed = run([sys.executable, str(CLI), str(bad), "--output", str(self.base / "out.jsonl")])
        self.assertEqual(completed.returncode, 2)

    def test_unsupported_record_field_is_rejected(self) -> None:
        bad = self.base / "bad.jsonl"
        bad.write_text(
            json.dumps(
                {
                    "frame_number": 1,
                    "transport": {"protocol": "UDP"},
                    "headers": {"method": "OPTIONS", "unsupported_header": "value"},
                }
            ),
            encoding="utf-8",
        )
        completed = run([sys.executable, str(CLI), str(bad), "--output", str(self.base / "out.jsonl")])
        self.assertEqual(completed.returncode, 2)

    def test_missing_output_directory(self) -> None:
        completed = run(
            [sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml"), "--output", str(self.base / "missing" / "out.jsonl")]
        )
        self.assertEqual(completed.returncode, 6)

    def test_existing_output_without_force(self) -> None:
        output = self.base / "out.jsonl"
        output.write_text("existing", encoding="utf-8")
        completed = run([sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml"), "--output", str(output)])
        self.assertEqual(completed.returncode, 6)
        self.assertEqual(output.read_text(encoding="utf-8"), "existing")

    def test_source_overwrite_is_protected(self) -> None:
        completed = run(
            [sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml"), "--output", str(EXAMPLES / "pdml" / "base-udp.pdml")]
        )
        self.assertEqual(completed.returncode, 6)

    def test_no_destination_is_an_output_failure(self) -> None:
        completed = run([sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml")])
        self.assertEqual(completed.returncode, 6)

    def test_malformed_start_line_is_classified(self) -> None:
        row = load_jsonl(EXPECTED / "malformed-events.jsonl")[0]
        self.assertEqual(row["message_completeness"], "MALFORMED")
        self.assertIn("MISSING_START_LINE", row["integrity_findings"])

    def test_truncated_message_is_classified(self) -> None:
        row = load_jsonl(EXPECTED / "truncated-events.jsonl")[0]
        self.assertEqual(row["message_completeness"], "TRUNCATED")
        self.assertIn("CAPTURE_TRUNCATED", row["integrity_findings"])

    def test_invalid_cseq_is_classified(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 2)
        self.assertEqual(row["message_completeness"], "MALFORMED")
        self.assertIn("INVALID_CSEQ", row["integrity_findings"])
        self.assertIsNone(row["headers"]["cseq"]["sequence"])

    def test_missing_cseq_is_incomplete(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 3)
        self.assertEqual(row["message_completeness"], "INCOMPLETE")
        self.assertEqual(row["extraction_status"], "PARTIAL")

    def test_invalid_status_code_is_malformed(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 5)
        self.assertEqual(row["message_completeness"], "MALFORMED")
        self.assertIsNone(row["status_code"])
        self.assertFalse(row["status_code_valid"])

    def test_invalid_content_length_is_classified(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 6)
        self.assertIn("INVALID_CONTENT_LENGTH", row["integrity_findings"])

    def test_missing_call_id_is_incomplete(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 7)
        self.assertEqual(row["message_completeness"], "INCOMPLETE")
        self.assertIn("MISSING_CALL_ID", row["integrity_findings"])

    def test_missing_optional_header_is_not_malformed(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 11)
        self.assertEqual(row["message_completeness"], "COMPLETE")
        self.assertEqual(row["headers"]["contact"]["count"], 0)
        self.assertEqual(row["headers"]["route"]["count"], 0)

    def test_unrecognized_header_is_preserved_as_finding(self) -> None:
        row = event_by_frame(load_jsonl(EXPECTED / "negative-cases-events.jsonl"), 9)
        self.assertEqual(row["message_completeness"], "COMPLETE")
        self.assertIn("UNRECOGNIZED_HEADER", row["integrity_findings"])

    def test_deterministic_output(self) -> None:
        first = self.base / "first.jsonl"
        second = self.base / "second.jsonl"
        for destination in (first, second):
            completed = run([sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml"), "--output", str(destination)])
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_truncated_capture_file_is_handled(self) -> None:
        if not (TSHARK and TEXT2PCAP):
            self.skipTest("TShark and text2pcap are required")
        full = build_capture(self.base, [sip_message("OPTIONS")])
        truncated = self.base / "truncated.pcapng"
        truncated.write_bytes(full.read_bytes()[:12])
        output = self.base / "truncated.jsonl"
        completed = run([sys.executable, str(CLI), str(truncated), "--output", str(output)])
        self.assertIn(completed.returncode, {2, 3, 5})
        self.assertNotIn("Traceback", completed.stderr)

    def test_missing_output_after_nominal_success_fails(self) -> None:
        spec = importlib.util.spec_from_file_location("extract_sip_under_test", CLI)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        original = module.write_jsonl
        module.write_jsonl = lambda destination, rows: None
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = module.main(
                    [
                        str(EXAMPLES / "pdml" / "base-udp.pdml"),
                        "--output",
                        str(self.base / "missing.jsonl"),
                    ]
                )
        finally:
            module.write_jsonl = original
        self.assertEqual(code, 6)

    def test_missing_tshark_is_tool_unavailable(self) -> None:
        spec = importlib.util.spec_from_file_location("extract_sip_under_test", CLI)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        capture = self.base / "valid.pcapng"
        capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
        original_which = model.shutil.which
        original_run = model.subprocess.run
        model.shutil.which = lambda name: None
        model.subprocess.run = lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("tshark"))
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = module.main([str(capture), "--output", str(self.base / "out.jsonl")])
        finally:
            model.shutil.which = original_which
            model.subprocess.run = original_run
        self.assertEqual(code, 4)

    def test_tshark_execution_failure_is_decoder_failure(self) -> None:
        spec = importlib.util.spec_from_file_location("extract_sip_under_test", CLI)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        capture = self.base / "valid.pcapng"
        capture.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 60)
        original_run = model.subprocess.run
        model.subprocess.run = lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="decoder failure")
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = module.main([str(capture), "--output", str(self.base / "out.jsonl")])
        finally:
            model.subprocess.run = original_run
        self.assertEqual(code, 5)


class SipPrivacyTests(unittest.TestCase):
    def test_no_identity_or_uri_in_base_events(self) -> None:
        text = (EXPECTED / "base-udp-events.jsonl").read_text(encoding="utf-8")
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, text)
        self.assertNotIn("<sip:", text)
        self.assertNotIn("tel:+", text)

    def test_no_identity_or_uri_in_privacy_events(self) -> None:
        text = (EXPECTED / "privacy-cases-events.jsonl").read_text(encoding="utf-8")
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, text)

    def test_no_authentication_header_value(self) -> None:
        text = (EXPECTED / "base-udp-events.jsonl").read_text(encoding="utf-8")
        for token in ("Digest", "nonce", "response=", "username=", "realm=", "Authorization:", "WWW-Authenticate:"):
            self.assertNotIn(token, text)

    def test_no_message_body_or_sdp(self) -> None:
        text = (EXPECTED / "base-udp-events.jsonl").read_text(encoding="utf-8")
        for token in ("v=0", "a=secretbody", "application/sdp\r\n"):
            self.assertNotIn(token, text)
        self.assertIn("body_length", text)

    def test_cli_output_and_error_do_not_echo_secrets(self) -> None:
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "dissector" / "privacy-cases.jsonl"),
                "--output",
                str(Path(tempfile.mkdtemp()) / "privacy.jsonl"),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        combined = completed.stdout + completed.stderr
        for token in PRIVATE_TOKENS:
            self.assertNotIn(token, combined)

    def test_trace_projection_publishes_no_dialog_or_transaction_identity(self) -> None:
        text = (EXPECTED / "base-udp-trace.jsonl").read_text(encoding="utf-8")
        for token in ("call_id", "Call-ID", "PRIVATE", "fromtag", "totag", "branch", "transaction", "dialog"):
            self.assertNotIn(token, text)


@unittest.skipUnless(TSHARK and TEXT2PCAP, "TShark and text2pcap are required for live decoder tests")
class SipActualTsharkTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def extract(self, capture: Path) -> tuple[subprocess.CompletedProcess, list[dict]]:
        output = self.base / "events.jsonl"
        completed = run([sys.executable, str(CLI), str(capture), "--output", str(output)])
        rows = load_jsonl(output) if output.is_file() else []
        return completed, rows

    def test_udp_request_and_response(self) -> None:
        capture = build_capture(self.base, [sip_message("REGISTER"), sip_message(status=401)])
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["method"], "REGISTER")
        self.assertEqual(rows[1]["status_code"], 401)
        self.assertEqual(rows[1]["reason_phrase"], "Unauthorized")

    def test_tcp_segmentation_and_reassembly(self) -> None:
        payload = sip_message("REGISTER")
        cut = len(payload) // 2
        capture = build_capture(self.base, [payload[:cut], payload[cut:]], mode="tcp")
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["transport"]["protocol"], "TCP")
        self.assertEqual(row["transport"]["reassembly"], "REASSEMBLED")
        self.assertEqual(row["transport"]["segment_count"], 2)
        self.assertIsNotNone(row["transport"]["reassembled_length"])
        self.assertEqual(row["frame_number"], 2)

    def test_ipv6_udp(self) -> None:
        capture = build_capture(self.base, [sip_message("OPTIONS")], ipv6=True)
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(rows[0]["transport"]["source_address"], "2001:db8::1")

    def test_non_standard_port_with_dissector_evidence(self) -> None:
        capture = build_capture(self.base, [sip_message("OPTIONS")], ports=(5070, 5070))
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(rows[0]["transport"]["source_port"], 5070)

    def test_tls_without_decryption_is_unavailable(self) -> None:
        tls_record = bytes.fromhex(
            "160301002f0100002b030300000000000000000000000000000000000000000000000000000000000000000000000002002f0100"
        )
        capture = build_capture(self.base, [tls_record], mode="tcp", ports=(5061, 5061))
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(rows, [])

    def test_port_5060_alone_does_not_create_sip_evidence(self) -> None:
        capture = build_capture(self.base, [b"not a sip message"], ports=(5060, 5060))
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(rows, [])

    def test_capture_without_sip(self) -> None:
        capture = build_capture(self.base, [b"not sip"], ports=(9999, 9999))
        completed, rows = self.extract(capture)
        self.assertEqual(completed.returncode, 3)
        self.assertEqual(rows, [])


class SipCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.base = Path(self._temporary.name)

    def tearDown(self) -> None:
        self._temporary.cleanup()

    def test_help(self) -> None:
        completed = run([sys.executable, str(CLI), "--help"])
        self.assertEqual(completed.returncode, 0)
        self.assertIn("--output", completed.stdout)

    def test_explicit_pdml_format(self) -> None:
        output = self.base / "out.jsonl"
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "base-udp.pdml"),
                "--input-format",
                "pdml",
                "--output",
                str(output),
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(load_jsonl(output)), 2)

    def test_force_replaces_output(self) -> None:
        output = self.base / "out.jsonl"
        output.write_text("old", encoding="utf-8")
        completed = run(
            [
                sys.executable,
                str(CLI),
                str(EXAMPLES / "pdml" / "base-udp.pdml"),
                "--output",
                str(output),
                "--force",
            ]
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotEqual(output.read_text(encoding="utf-8"), "old")

    def test_trace_output_requires_destination(self) -> None:
        completed = run([sys.executable, str(CLI), str(EXAMPLES / "pdml" / "base-udp.pdml")])
        self.assertEqual(completed.returncode, 6)


class UnifiedAnalyzerBoundaryTests(unittest.TestCase):
    """A SIP Protocol Skill must not declare IMS Domain support prematurely."""

    @classmethod
    def setUpClass(cls) -> None:
        path = PACKAGE.parents[2] / "scripts" / "corenet-analyze.py"
        spec = importlib.util.spec_from_file_location("corenet_analyze_sip_boundary", path)
        cls.module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.module)

    def test_ims_domain_remains_unsupported(self) -> None:
        capability = self.module.DOMAIN_CAPABILITIES["ims"]
        self.assertEqual(capability["implementation_status"], "UNSUPPORTED")
        self.assertIsNone(capability["entry_point"])
        self.assertEqual(capability["analysis_capabilities"], [])

    def test_sip_is_a_protocol_identity_not_a_domain_verdict(self) -> None:
        self.assertEqual(self.module.PROTOCOL_TOKENS["sip"], "SIP")
        self.assertIn("SIP", self.module.IMS_SIGNALING)

    def test_no_ims_domain_adapter_is_registered(self) -> None:
        adapters = self.module.build_domain_adapters(lambda *args: None, lambda *args: None)
        self.assertEqual(set(adapters), {"5gc", "epc"})


if __name__ == "__main__":
    unittest.main()
