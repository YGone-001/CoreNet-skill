#!/usr/bin/env python3
"""Deterministic tests for the bounded SDP Protocol Skill."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:
    jsonschema = None

SKILL = Path(__file__).resolve().parents[1]
SCRIPTS = SKILL / "scripts"
CLI = SCRIPTS / "parse-sdp.py"
SCHEMA = SKILL / "schemas" / "sdp-events.schema.json"
INPUTS = SKILL / "examples" / "inputs"
EXPECTED = SKILL / "examples" / "expected"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import sdp_fixture_builder as builder  # noqa: E402
import sdp_model  # noqa: E402


def analyze(records) -> dict:
    document = sdp_model.build_analysis(records)
    sdp_model.validate_analysis(document)
    return document


def message(document: dict, index: int = 0) -> dict:
    return document["messages"][index]


def run_cli(input_path: Path, output: Path, report: Path | None = None) -> subprocess.CompletedProcess:
    command = [
        sys.executable,
        str(CLI),
        "--input",
        str(input_path),
        "--output",
        str(output),
        "--force",
    ]
    if report is not None:
        command.extend(["--report", str(report)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


class SdpParsingTests(unittest.TestCase):
    def records(self):
        return builder.build_records()

    def test_01_valid_single_media(self) -> None:
        document = analyze(self.records()[:1])
        item = message(document)
        self.assertEqual(item["evidence_status"], "OBSERVED")
        self.assertEqual(item["media_section_count"], 1)
        self.assertEqual(item["media_sections"][0]["media_type"], "audio")
        self.assertEqual(item["media_sections"][0]["port"], 49170)

    def test_02_multiple_media_sections(self) -> None:
        item = message(analyze([self.records()[1]]))
        self.assertEqual(item["media_section_count"], 2)
        self.assertEqual([section["media_type"] for section in item["media_sections"]], ["audio", "video"])

    def test_03_audio_and_video_descriptions(self) -> None:
        item = message(analyze([self.records()[2]]))
        self.assertEqual(item["media_sections"][0]["media_type"], "audio")
        self.assertEqual(item["media_sections"][1]["media_type"], "video")

    def test_04_ipv4_and_ipv6_connection(self) -> None:
        item = message(analyze([self.records()[3]]))
        self.assertEqual(item["session"]["connection"]["address_family"], "IPv4")
        self.assertEqual(item["media_sections"][1]["connection"]["address_family"], "IPv6")
        self.assertEqual(item["media_sections"][1]["connection"]["address_class"], "PRIVATE")

    def test_05_static_and_dynamic_payload_types(self) -> None:
        item = message(analyze([self.records()[4]]))
        formats = item["media_sections"][0]["formats"]
        self.assertEqual([entry["classification"] for entry in formats], ["STATIC", "STATIC", "DYNAMIC"])
        self.assertEqual(formats[2]["payload_type"], 96)

    def test_06_rtp_mapping(self) -> None:
        item = message(analyze([self.records()[5]]))
        mapping = item["media_sections"][0]["rtpmap"][0]
        self.assertEqual(mapping, {"payload_type": 96, "encoding_name": "opus", "clock_rate": 48000, "channels": 2})

    def test_07_fmtp_recognition(self) -> None:
        item = message(analyze([self.records()[6]]))
        fmtp = item["media_sections"][0]["fmtp"][0]
        self.assertEqual(fmtp["payload_type"], 96)
        safe = {entry["name"]: entry["safe_value"] for entry in fmtp["parameters"]}
        self.assertEqual(safe["max-fs"], "10")
        self.assertIsNone(safe["useinbandfec"])

    def test_08_media_direction_attributes(self) -> None:
        item = message(analyze([self.records()[7]]))
        self.assertEqual(item["media_sections"][0]["direction"], "sendonly")
        self.assertEqual(item["media_sections"][1]["direction"], "recvonly")

    def test_09_session_and_media_scopes_are_separate(self) -> None:
        item = message(analyze([self.records()[8]]))
        self.assertEqual(item["session"]["direction"], "sendrecv")
        self.assertEqual(item["session"]["mid"], "session-mid")
        self.assertEqual(item["media_sections"][0]["direction"], "inactive")
        self.assertEqual(item["media_sections"][0]["mid"], "media-mid")

    def test_10_rtcp_and_rtcp_mux(self) -> None:
        item = message(analyze([self.records()[9]]))
        media = item["media_sections"][0]
        self.assertEqual(media["rtcp"]["port"], 49171)
        self.assertEqual(media["rtcp"]["address_family"], "IPv4")
        self.assertTrue(media["rtcp_mux"])

    def test_11_bundle_group_references(self) -> None:
        item = message(analyze([self.records()[10]]))
        group = item["session"]["groups"][0]
        self.assertEqual(group["semantics"], "BUNDLE")
        self.assertEqual(group["reference_status"], "RESOLVED")
        self.assertEqual(group["mids"], ["0", "1"])

    def test_12_missing_mandatory_fields_fail_closed(self) -> None:
        item = message(analyze([self.records()[11]]))
        self.assertEqual(item["evidence_status"], "INCOMPLETE")
        for reason in ("MISSING_ORIGIN", "MISSING_SESSION_NAME", "MISSING_TIME_DESCRIPTION"):
            self.assertIn(reason, item["invalid_reasons"])

    def test_13_invalid_media_port(self) -> None:
        item = message(analyze([self.records()[12]]))
        self.assertEqual(item["evidence_status"], "INVALID")
        self.assertEqual(item["media_section_count"], 0)
        self.assertIn("MEDIA_FIELD_MALFORMED", item["invalid_reasons"])

    def test_14_invalid_payload_declaration(self) -> None:
        item = message(analyze([self.records()[13]]))
        self.assertEqual(item["media_sections"][0]["evidence_status"], "INVALID")
        self.assertIn("RTP_PAYLOAD_TYPE_INVALID", item["media_sections"][0]["invalid_reasons"])

    def test_15_duplicate_and_contradictory_attributes(self) -> None:
        item = message(analyze([self.records()[14]]))
        self.assertEqual(item["evidence_status"], "AMBIGUOUS")
        self.assertEqual(item["media_sections"][0]["direction"], "AMBIGUOUS")
        self.assertIn("DUPLICATE_RTPMAP", item["media_sections"][0]["invalid_reasons"])

    def test_16_malformed_line(self) -> None:
        item = message(analyze([self.records()[15]]))
        self.assertEqual(item["evidence_status"], "INVALID")
        self.assertIn("MALFORMED_LINE", item["invalid_reasons"])
        self.assertEqual(item["session"]["malformed_lines"][0]["line_number"], 6)

    def test_17_mixed_line_endings(self) -> None:
        item = message(analyze([self.records()[16]]))
        self.assertEqual(item["line_ending_style"], "MIXED")
        self.assertEqual(item["evidence_status"], "OBSERVED")

    def test_18_unknown_attributes_are_preserved(self) -> None:
        item = message(analyze([self.records()[17]]))
        self.assertEqual(item["evidence_status"], "OBSERVED")
        names = [entry["name"] for entry in item["session"]["unknown_attributes"]]
        self.assertIn("x-session-extension", names)
        names = [entry["name"] for entry in item["media_sections"][0]["unknown_attributes"]]
        self.assertIn("x-media-extension", names)
        text = json.dumps(item)
        self.assertNotIn("not-published", text)

    def test_19_truncated_input_is_incomplete(self) -> None:
        item = message(analyze([self.records()[18]]))
        self.assertEqual(item["evidence_status"], "INCOMPLETE")
        self.assertIn("TRUNCATED_INPUT", item["invalid_reasons"])

    def test_20_oversized_input_is_invalid(self) -> None:
        item = message(analyze([self.records()[19]]))
        self.assertEqual(item["evidence_status"], "INVALID")
        self.assertIn("OVERSIZED_INPUT", item["invalid_reasons"])
        self.assertEqual(item["media_section_count"], 0)

    def test_21_sensitive_fields_are_redacted(self) -> None:
        item = message(analyze([self.records()[20]]))
        sensitive = item["session"]["sensitive_attributes"]
        self.assertEqual(len(sensitive), 5)
        self.assertTrue(all(entry["redacted"] for entry in sensitive))
        text = json.dumps(item)
        for token in (
            "private-user",
            "private-ufrag-value",
            "private-password-value",
            "private-key-material",
            "AA:BB:CC:DD",
            "203.0.113.10",
            "49170 typ host",
        ):
            self.assertNotIn(token, text)
        self.assertIn("sha-256", text)
        self.assertIn("AES_CM_128_HMAC_SHA1_80", text)

    def test_22_deterministic_replay(self) -> None:
        first = analyze(self.records())
        second = analyze(self.records())
        self.assertEqual(first, second)
        self.assertEqual(
            json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True)
        )

    def test_23_capture_provenance_mismatch_is_rejected(self) -> None:
        records = builder.build_records()
        records[1]["capture_file"] = "other-capture.pcapng"
        records[1]["source_reference"] = "sip-body:other-capture.pcapng:2.1"
        with self.assertRaises(sdp_model.InputError):
            sdp_model.load_messages(self._write(records))

    def test_24_bundle_reference_integrity(self) -> None:
        item = message(analyze([self.records()[21]]))
        self.assertEqual(item["evidence_status"], "AMBIGUOUS")
        self.assertEqual(item["session"]["groups"][0]["reference_status"], "UNRESOLVED")
        self.assertIn("BUNDLE_REFERENCE_UNRESOLVED", item["invalid_reasons"])

    def test_unknown_line_type_is_unsupported(self) -> None:
        record = dict(self.records()[0])
        record["source_reference"] = "sip-body:synthetic-sdp.pcapng:99.1"
        record["sdp_body"] = record["sdp_body"].replace("t=0 0\r\n", "t=0 0\r\nq=unknown\r\n")
        item = message(analyze([record]))
        self.assertEqual(item["evidence_status"], "UNSUPPORTED")
        self.assertEqual(item["session"]["unknown_lines"][0]["field_type"], "q")

    def _write(self, records) -> Path:
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text(
            "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
            encoding="utf-8",
        )
        return path


class SdpCliAndSchemaTests(unittest.TestCase):
    def test_schema_validation(self) -> None:
        document = analyze(builder.build_records())
        if jsonschema is not None:
            jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        sdp_model.validate_analysis(document)

    def test_cli_expected_output_and_report(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = run_cli(INPUTS / "sdp-cases.jsonl", output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        expected = json.loads((EXPECTED / "sdp-analysis.json").read_text(encoding="utf-8"))
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), expected)
        self.assertEqual(
            report.read_text(encoding="utf-8"),
            (EXPECTED / "sdp-report.txt").read_text(encoding="utf-8"),
        )

    def test_cli_output_collision_is_rejected(self) -> None:
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "input.jsonl"
        builder.write_input(input_path)
        completed = run_cli(input_path, input_path)
        self.assertNotEqual(completed.returncode, 0)

    def test_cli_rejects_empty_input(self) -> None:
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "empty.jsonl"
        input_path.write_text("", encoding="utf-8")
        completed = run_cli(input_path, directory / "out.json")
        self.assertEqual(completed.returncode, 3)

    def test_cli_rejects_invalid_sha(self) -> None:
        records = builder.build_records()
        records[0]["capture_sha256"] = "not-a-sha"
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "input.jsonl"
        input_path.write_text(json.dumps(records[0]) + "\n", encoding="utf-8")
        completed = run_cli(input_path, directory / "out.json")
        self.assertEqual(completed.returncode, 2)

    def test_cli_does_not_publish_private_values(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = run_cli(INPUTS / "sdp-cases.jsonl", output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        text = output.read_text(encoding="utf-8") + report.read_text(encoding="utf-8") + completed.stdout + completed.stderr
        for token in (
            "private-user",
            "private-ufrag-value",
            "private-password-value",
            "private-key-material",
            "AA:BB:CC:DD",
            "203.0.113.10",
        ):
            self.assertNotIn(token, text)
        self.assertNotIn("v=0", text)
        self.assertNotIn("sdp_body", text)

    def test_cli_reference_integrity(self) -> None:
        duplicate = builder.build_records()[:1] * 2
        duplicate[1]["source_reference"] = duplicate[0]["source_reference"]
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "input.jsonl"
        input_path.write_text(
            "\n".join(json.dumps(record) for record in duplicate) + "\n", encoding="utf-8"
        )
        completed = run_cli(input_path, directory / "out.json")
        self.assertEqual(completed.returncode, 2)


if __name__ == "__main__":
    unittest.main()