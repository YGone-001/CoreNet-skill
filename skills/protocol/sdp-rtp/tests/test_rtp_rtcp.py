#!/usr/bin/env python3
"""Deterministic tests for bounded RTP/RTCP packet evidence."""

from __future__ import annotations

import hashlib
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
CLI = SCRIPTS / "extract-rtp-rtcp.py"
SCHEMA = SKILL / "schemas" / "rtp-rtcp-events.schema.json"
MANIFEST = SKILL / "manifest.yaml"
SDP_SCHEMA = SKILL / "schemas" / "sdp-events.schema.json"
SDP_INPUT = SKILL / "examples" / "inputs" / "sdp-cases.jsonl"
SDP_EXPECTED = SKILL / "examples" / "expected" / "sdp-analysis.json"
INPUTS = SKILL / "examples" / "inputs" / "rtp-rtcp-cases.jsonl"
EXPECTED = SKILL / "examples" / "expected"
TEST_DIR = Path(__file__).resolve().parent
for path in (SCRIPTS, TEST_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import rtp_rtcp_fixture_builder as builder  # noqa: E402
import rtp_rtcp_model  # noqa: E402
import sdp_model  # noqa: E402


def analyze(records) -> dict:
    directory = Path(tempfile.mkdtemp())
    path = directory / "input.jsonl"
    path.write_text(
        "\n".join(json.dumps(record, sort_keys=True) for record in records) + "\n",
        encoding="utf-8",
    )
    events, provenance = rtp_rtcp_model.extract_structured(path)
    document = rtp_rtcp_model.build_analysis(events, provenance)
    rtp_rtcp_model.validate_analysis(document)
    return document


def events(document: dict, protocol: str | None = None) -> list[dict]:
    return [
        event
        for event in document["events"]
        if protocol is None or event["protocol"] == protocol
    ]


def run_cli(input_path: Path, output: Path, report: Path | None = None, *extra: str):
    command = [
        sys.executable,
        str(CLI),
        "--input",
        str(input_path),
        "--input-format",
        "jsonl",
        "--output",
        str(output),
        "--force",
        *extra,
    ]
    if report is not None:
        command.extend(["--report", str(report)])
    return subprocess.run(command, capture_output=True, text=True, check=False)


class RtpEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = analyze(builder.build_records())
        self.rtp = events(self.document, "RTP")

    def test_01_rtp_version_2(self) -> None:
        self.assertTrue(self.rtp)
        self.assertEqual(self.rtp[0]["version"], 2)
        self.assertEqual(self.rtp[0]["evidence_status"], "OBSERVED")

    def test_02_valid_fixed_header(self) -> None:
        item = self.rtp[1]
        self.assertEqual(item["payload_type"], 96)
        self.assertEqual(item["sequence_number"], 1)
        self.assertEqual(item["timestamp"], 160)
        self.assertEqual(item["ssrc"], 0x01020304)
        self.assertEqual(item["packet_length"], 20)

    def test_03_marker_bit(self) -> None:
        self.assertTrue(self.rtp[0]["marker"])

    def test_04_static_and_dynamic_payload_types(self) -> None:
        self.assertEqual(self.rtp[0]["payload_type"], 0)
        self.assertEqual(self.rtp[1]["payload_type"], 96)

    def test_05_sequence_number_boundaries(self) -> None:
        self.assertEqual(self.rtp[2]["sequence_number"], 0)
        self.assertEqual(self.rtp[3]["sequence_number"], 65535)

    def test_06_timestamp_boundaries(self) -> None:
        self.assertEqual(self.rtp[2]["timestamp"], 0)
        self.assertEqual(self.rtp[3]["timestamp"], 4294967295)

    def test_07_ssrc_preservation(self) -> None:
        self.assertEqual(self.rtp[4]["ssrc"], 4294967295)
        self.assertEqual(self.rtp[0]["ssrc_reference"], "rtp-ssrc:synthetic-rtp.pcapng:01020304")

    def test_08_multiple_csrc_entries(self) -> None:
        self.assertEqual(self.rtp[5]["csrc_count"], 3)
        self.assertEqual(self.rtp[5]["csrc"], [1, 2, 3])

    def test_09_header_extension_presence(self) -> None:
        self.assertTrue(self.rtp[6]["extension"])

    def test_10_extension_profile_and_length(self) -> None:
        self.assertEqual(self.rtp[6]["extension_profile"], 0xBEDE)
        self.assertEqual(self.rtp[6]["extension_length"], 4)

    def test_11_padding(self) -> None:
        self.assertTrue(self.rtp[7]["padding"])
        self.assertEqual(self.rtp[7]["padding_count"], 4)

    def test_12_missing_fields(self) -> None:
        item = self.rtp[8]
        self.assertEqual(item["evidence_status"], "INCOMPLETE")
        self.assertIn("RTP_SEQUENCE_MISSING", item["invalid_reasons"])

    def test_13_invalid_field_ranges(self) -> None:
        item = self.rtp[9]
        self.assertEqual(item["evidence_status"], "INVALID")
        for reason in ("RTP_PAYLOAD_TYPE_INVALID", "RTP_SEQUENCE_INVALID", "RTP_PACKET_LENGTH_INVALID"):
            self.assertIn(reason, item["invalid_reasons"])

    def test_14_truncated_packet(self) -> None:
        self.assertEqual(self.rtp[10]["evidence_status"], "INCOMPLETE")
        self.assertIn("TRUNCATED_RTP_PACKET", self.rtp[10]["invalid_reasons"])

    def test_15_unsupported_rtp_version(self) -> None:
        self.assertEqual(self.rtp[11]["evidence_status"], "UNSUPPORTED")
        self.assertIn("UNSUPPORTED_RTP_VERSION", self.rtp[11]["invalid_reasons"])

    def test_16_payload_privacy(self) -> None:
        text = json.dumps(self.document)
        self.assertNotIn("SECRET-PAYLOAD-BYTES", text)
        self.assertNotIn("payload", self.rtp[12])
        self.assertIn("RTP payload field ignored and not published", self.rtp[12]["limitations"])

    def test_17_deterministic_replay(self) -> None:
        first = analyze(builder.build_records())
        second = analyze(builder.build_records())
        self.assertEqual(first, second)


class RtcpEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.document = analyze(builder.build_records())
        self.rtcp = events(self.document, "RTCP")

    def test_18_sender_report(self) -> None:
        sr = self.rtcp[0]
        self.assertEqual(sr["packet_type_name"], "SR")
        self.assertEqual(sr["sender_report"]["packet_count"], 10)
        self.assertEqual(sr["sender_report"]["octet_count"], 1000)

    def test_19_receiver_report(self) -> None:
        rr = self.rtcp[1]
        self.assertEqual(rr["packet_type_name"], "RR")
        self.assertEqual(rr["report_blocks"][0]["fraction_lost"], 10)

    def test_20_multiple_report_blocks(self) -> None:
        rr = self.rtcp[2]
        self.assertEqual(len(rr["report_blocks"]), 2)
        self.assertEqual([block["reported_ssrc"] for block in rr["report_blocks"]], [0x11111111, 0x22222222])

    def test_21_positive_cumulative_loss(self) -> None:
        self.assertEqual(self.rtcp[2]["report_blocks"][0]["cumulative_packets_lost"], 5)

    def test_22_negative_cumulative_loss(self) -> None:
        self.assertEqual(self.rtcp[2]["report_blocks"][1]["cumulative_packets_lost"], -7)

    def test_23_fraction_lost(self) -> None:
        self.assertEqual(self.rtcp[1]["report_blocks"][0]["fraction_lost"], 10)
        self.assertEqual(self.rtcp[1]["report_blocks"][0]["reported_value_class"], "RECEIVER_REPORTED")

    def test_24_receiver_reported_jitter(self) -> None:
        self.assertEqual(self.rtcp[3]["report_blocks"][0]["interarrival_jitter"], 3200)
        self.assertIn("LOCAL_JITTER", self.rtcp[3]["not_confirmed"])

    def test_25_ntp_and_rtp_timestamps(self) -> None:
        sender = self.rtcp[0]["sender_report"]
        self.assertEqual(sender["ntp_msw"], 0)
        self.assertEqual(sender["ntp_lsw"], 0)
        self.assertTrue(sender["ntp_present"])
        self.assertEqual(sender["rtp_timestamp"], 160)

    def test_26_sdes_cname_redaction(self) -> None:
        sdes = self.rtcp[4]
        self.assertEqual(sdes["packet_type_name"], "SDES")
        cname = sdes["sdes_chunks"][0]["items"][0]
        self.assertEqual(cname["item_name"], "CNAME")
        self.assertTrue(cname["value_redacted"])
        self.assertNotIn("secret-sdes-text", json.dumps(self.document))

    def test_27_other_sdes_items(self) -> None:
        items = self.rtcp[4]["sdes_chunks"][0]["items"]
        self.assertEqual([item["item_name"] for item in items], ["CNAME", "NAME", "EMAIL", "PHONE", "LOC", "TOOL", "NOTE", "PRIV"])

    def test_28_bye_sources(self) -> None:
        bye = self.rtcp[5]
        self.assertEqual(bye["packet_type_name"], "BYE")
        self.assertEqual(bye["bye_sources"], [0x01020304, 0x01020305])
        self.assertEqual(bye["bye_source_count"], 2)

    def test_29_bye_reason_redaction(self) -> None:
        bye = self.rtcp[5]
        self.assertTrue(bye["bye_reason_present"])
        self.assertEqual(bye["bye_reason_length"], 12)
        self.assertNotIn("secret-bye-reason", json.dumps(self.document))

    def test_30_compound_rtcp_ordering(self) -> None:
        compound = [event for event in self.rtcp if event["event_reference"].startswith("rtcp-component:synthetic-rtp.pcapng:20.1.")]
        self.assertEqual([event["component_index"] for event in compound], [0, 1, 2, 3])
        self.assertEqual([event["packet_type_name"] for event in compound], ["SR", "RR", "SDES", "BYE"])

    def test_31_multiple_components_independent_identities(self) -> None:
        compound = [event for event in self.rtcp if event["event_reference"].startswith("rtcp-component:synthetic-rtp.pcapng:21.1.")]
        self.assertEqual([event["sender_ssrc"] for event in compound], [0xAAAAAAAA, 0xBBBBBBBB])

    def test_32_unsupported_app_packet(self) -> None:
        item = next(event for event in self.rtcp if event["packet_type"] == 204)
        self.assertEqual(item["packet_type_name"], "APP")
        self.assertEqual(item["evidence_status"], "UNSUPPORTED")
        self.assertNotIn("SECRET-APP-DATA", json.dumps(self.document))

    def test_33_unsupported_rtpfb_and_psfb(self) -> None:
        items = [event for event in self.rtcp if event["packet_type"] in (205, 206)]
        self.assertEqual([event["packet_type_name"] for event in items], ["RTPFB", "PSFB"])
        self.assertTrue(all(event["evidence_status"] == "UNSUPPORTED" for event in items))

    def test_34_unsupported_xr_packet(self) -> None:
        item = next(event for event in self.rtcp if event["packet_type"] == 207)
        self.assertEqual(item["packet_type_name"], "XR")
        self.assertEqual(item["evidence_status"], "UNSUPPORTED")

    def test_35_unknown_packet_type(self) -> None:
        item = next(event for event in self.rtcp if event["packet_type"] == 250)
        self.assertEqual(item["packet_type_name"], "UNKNOWN")
        self.assertEqual(item["evidence_status"], "UNSUPPORTED")

    def test_36_malformed_packet_length(self) -> None:
        item = next(event for event in self.rtcp if "RTCP_LENGTH_INVALID" in event["invalid_reasons"])
        self.assertEqual(item["evidence_status"], "INVALID")
        self.assertIn("RTCP_LENGTH_INVALID", item["invalid_reasons"])

    def test_37_invalid_report_block_binding(self) -> None:
        item = next(event for event in self.rtcp if "REPORT_COUNT_MISMATCH" in event["invalid_reasons"])
        self.assertEqual(item["evidence_status"], "AMBIGUOUS")
        self.assertIn("REPORT_COUNT_MISMATCH", item["invalid_reasons"])
        self.assertEqual(item["report_blocks"], [])

    def test_38_truncated_compound_packet(self) -> None:
        item = next(event for event in self.rtcp if "TRUNCATED_RTCP_COMPONENT" in event["invalid_reasons"])
        self.assertEqual(item["evidence_status"], "INCOMPLETE")
        self.assertIn("TRUNCATED_RTCP_COMPONENT", item["invalid_reasons"])


class RtpRtcpWorkflowTests(unittest.TestCase):
    def test_39_mixed_capture_rejected(self) -> None:
        records = builder.build_records()
        records[1]["capture_file"] = "other.pcapng"
        records[1]["source_reference"] = "rtp-packet:other.pcapng:2.1"
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        with self.assertRaises(rtp_rtcp_model.InputError):
            rtp_rtcp_model.extract_structured(path)

    def test_40_duplicate_reference_rejected(self) -> None:
        records = builder.build_records()[:2]
        records[1]["source_reference"] = records[0]["source_reference"]
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        with self.assertRaises(rtp_rtcp_model.InputError):
            rtp_rtcp_model.load_structured_messages(path)

    def test_41_provenance_mismatch_rejected(self) -> None:
        records = builder.build_records()[:2]
        records[1]["capture_sha256"] = "2" * 64
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
        with self.assertRaises(rtp_rtcp_model.InputError):
            rtp_rtcp_model.load_structured_messages(path)

    def test_42_tshark_unavailable(self) -> None:
        capture = Path(tempfile.mkdtemp()) / "empty.pcap"
        capture.write_bytes(b"")
        with self.assertRaises(rtp_rtcp_model.ToolError) as context:
            rtp_rtcp_model.extract_capture(
                capture,
                prober=lambda _tshark: (_ for _ in ()).throw(
                    rtp_rtcp_model.ToolError("TSHARK_UNAVAILABLE", "TShark is not installed")
                ),
                runner=lambda *_args: {"packets": []},
            )
        self.assertEqual(context.exception.code, "TSHARK_UNAVAILABLE")

    def test_43_unsupported_dissector_field(self) -> None:
        capture = Path(tempfile.mkdtemp()) / "capture.pcap"
        capture.write_bytes(b"")
        with self.assertRaises(rtp_rtcp_model.ToolError) as context:
            rtp_rtcp_model.extract_capture(
                capture,
                prober=lambda _tshark: (_ for _ in ()).throw(
                    rtp_rtcp_model.ToolError("UNSUPPORTED_TSHARK_FIELD", "missing rtp.seq")
                ),
                runner=lambda *_args: {"packets": []},
            )
        self.assertEqual(context.exception.code, "UNSUPPORTED_TSHARK_FIELD")

    def test_44_explicit_decode_as(self) -> None:
        capture = Path(tempfile.mkdtemp()) / "capture.pcap"
        capture.write_bytes(b"capture")
        calls = []

        def runner(_capture, decode_as, _tshark):
            calls.append(list(decode_as))
            return {"packets": []}

        rtp_rtcp_model.extract_capture(
            capture,
            ["udp.port==5004,rtp"],
            prober=lambda _tshark: None,
            runner=runner,
        )
        self.assertEqual(calls, [["udp.port==5004,rtp"]])

    def test_45_no_port_based_inference(self) -> None:
        capture = Path(tempfile.mkdtemp()) / "capture.pcap"
        capture.write_bytes(b"capture")
        calls = []

        def runner(_capture, decode_as, _tshark):
            calls.append(list(decode_as))
            return {"packets": []}

        rtp_rtcp_model.extract_capture(
            capture,
            [],
            prober=lambda _tshark: None,
            runner=runner,
        )
        self.assertEqual(calls, [[]])

    def test_46_no_payload_leakage(self) -> None:
        document = analyze(builder.build_records())
        text = json.dumps(document)
        self.assertNotIn("SECRET-PAYLOAD-BYTES", text)
        self.assertNotIn("SECRET-EXTENSION-DATA", text)
        self.assertNotIn("udp.payload", text)

    def test_47_no_rtcp_identity_leakage(self) -> None:
        document = analyze(builder.build_records())
        text = json.dumps(document)
        self.assertNotIn("secret-sdes-text", text)
        self.assertNotIn("secret-bye-reason", text)
        self.assertNotIn("SECRET-APP-DATA", text)

    def test_48_no_raw_extension_data_leakage(self) -> None:
        document = analyze(builder.build_records())
        text = json.dumps(document)
        self.assertNotIn("extension_data", text)
        self.assertNotIn("SECRET-EXTENSION-DATA", text)

    def test_49_output_collision_rejected(self) -> None:
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "input.jsonl"
        builder.write_input(input_path)
        completed = run_cli(input_path, input_path)
        self.assertNotEqual(completed.returncode, 0)

    def test_50_deterministic_json_and_report(self) -> None:
        directory = Path(tempfile.mkdtemp())
        first_output = directory / "first.json"
        first_report = directory / "first.txt"
        second_output = directory / "second.json"
        second_report = directory / "second.txt"
        first = run_cli(INPUTS, first_output, first_report)
        second = run_cli(INPUTS, second_output, second_report)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first_output.read_bytes(), second_output.read_bytes())
        self.assertEqual(first_report.read_bytes(), second_report.read_bytes())
        self.assertEqual(
            json.loads(first_output.read_text(encoding="utf-8")),
            json.loads(EXPECTED.joinpath("rtp-rtcp-analysis.json").read_text(encoding="utf-8")),
        )

    def test_51_existing_sdp_fixtures_unchanged(self) -> None:
        records = sdp_model.load_messages(SDP_INPUT)
        document = sdp_model.build_analysis(records, input_name=SDP_INPUT.name)
        self.assertEqual(
            document,
            json.loads(SDP_EXPECTED.read_text(encoding="utf-8")),
        )
        schema = json.loads(SDP_SCHEMA.read_text(encoding="utf-8"))
        if jsonschema is not None:
            jsonschema.validate(document, schema)


class RtpRtcpIntegrityTests(unittest.TestCase):
    def _rtp_document(self, **overrides) -> dict:
        return analyze([builder.rtp(1, **overrides)])

    def _rtcp_document(self, component: dict) -> dict:
        return analyze([builder.rtcp(1, [component])])

    def test_52_explicit_false_padding(self) -> None:
        event = events(self._rtp_document(padding=False), "RTP")[0]
        self.assertIs(event["padding"], False)
        self.assertEqual(event["evidence_status"], "OBSERVED")

    def test_53_missing_padding_flag(self) -> None:
        record = builder.rtp(1)
        del record["fields"]["padding"]
        event = events(analyze([record]), "RTP")[0]
        self.assertIsNone(event["padding"])
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("RTP_PADDING_FLAG_MISSING", event["invalid_reasons"])

    def test_54_invalid_padding_flag(self) -> None:
        event = events(self._rtp_document(padding="yes"), "RTP")[0]
        self.assertIsNone(event["padding"])
        self.assertEqual(event["evidence_status"], "INVALID")
        self.assertIn("RTP_PADDING_FLAG_INVALID", event["invalid_reasons"])

    def test_55_explicit_false_extension(self) -> None:
        event = events(self._rtp_document(extension=False), "RTP")[0]
        self.assertIs(event["extension"], False)
        self.assertEqual(event["evidence_status"], "OBSERVED")

    def test_56_missing_extension_flag(self) -> None:
        record = builder.rtp(1)
        del record["fields"]["extension"]
        event = events(analyze([record]), "RTP")[0]
        self.assertIsNone(event["extension"])
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("RTP_EXTENSION_FLAG_MISSING", event["invalid_reasons"])

    def test_57_invalid_extension_flag(self) -> None:
        event = events(self._rtp_document(extension=2), "RTP")[0]
        self.assertIsNone(event["extension"])
        self.assertEqual(event["evidence_status"], "INVALID")
        self.assertIn("RTP_EXTENSION_FLAG_INVALID", event["invalid_reasons"])

    def test_58_explicit_false_marker(self) -> None:
        event = events(self._rtp_document(marker=False), "RTP")[0]
        self.assertIs(event["marker"], False)
        self.assertEqual(event["evidence_status"], "OBSERVED")

    def test_59_missing_marker(self) -> None:
        record = builder.rtp(1)
        del record["fields"]["marker"]
        event = events(analyze([record]), "RTP")[0]
        self.assertIsNone(event["marker"])
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("RTP_MARKER_FLAG_MISSING", event["invalid_reasons"])

    def test_60_invalid_marker(self) -> None:
        event = events(self._rtp_document(marker="set"), "RTP")[0]
        self.assertIsNone(event["marker"])
        self.assertEqual(event["evidence_status"], "INVALID")
        self.assertIn("RTP_MARKER_FLAG_INVALID", event["invalid_reasons"])

    def test_61_missing_padding_count(self) -> None:
        record = builder.rtp(1, padding=True, padding_count=None)
        record["fields"].pop("padding_count")
        event = events(analyze([record]), "RTP")[0]
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("PADDING_COUNT_MISSING", event["invalid_reasons"])

    def test_62_missing_extension_profile(self) -> None:
        record = builder.rtp(1, extension=True, extension_profile=None, extension_length=4)
        record["fields"].pop("extension_profile")
        event = events(analyze([record]), "RTP")[0]
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("EXTENSION_PROFILE_MISSING", event["invalid_reasons"])

    def test_63_missing_extension_length(self) -> None:
        record = builder.rtp(1, extension=True, extension_profile=0xBEDE, extension_length=None)
        record["fields"].pop("extension_length")
        event = events(analyze([record]), "RTP")[0]
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("EXTENSION_LENGTH_MISSING", event["invalid_reasons"])

    def test_64_rtp_version_boundaries(self) -> None:
        for version, status in ((0, "UNSUPPORTED"), (1, "UNSUPPORTED"), (2, "OBSERVED"), (3, "UNSUPPORTED"), (4, "INVALID"), (255, "INVALID")):
            with self.subTest(version=version):
                event = events(self._rtp_document(version=version), "RTP")[0]
                self.assertEqual(event["evidence_status"], status)
                if version in (4, 255):
                    self.assertIn("RTP_VERSION_INVALID", event["invalid_reasons"])
                    self.assertIsNone(event["version"])
                else:
                    self.assertEqual(event["version"], version)

    def test_65_rtcp_version_boundaries(self) -> None:
        for version, status in ((0, "UNSUPPORTED"), (1, "UNSUPPORTED"), (2, "OBSERVED"), (3, "UNSUPPORTED"), (4, "INVALID"), (255, "INVALID")):
            with self.subTest(version=version):
                component = builder.sender_report()
                component["version"] = version
                event = events(self._rtcp_document(component), "RTCP")[0]
                self.assertEqual(event["evidence_status"], status)
                if version in (4, 255):
                    self.assertIn("RTCP_VERSION_INVALID", event["invalid_reasons"])
                    self.assertIsNone(event["version"])
                else:
                    self.assertEqual(event["version"], version)

    def test_66_sdes_declared_count_matches_chunks(self) -> None:
        event = events(self._rtcp_document(builder.sdes([builder.item(1)])), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "OBSERVED")
        self.assertEqual(event["declared_source_count"], 1)
        self.assertEqual(event["observed_source_count"], 1)
        self.assertEqual(event["source_count_status"], "OBSERVED")

    def test_67_sdes_missing_chunk_hierarchy(self) -> None:
        component = builder.sdes([builder.item(1)])
        component.pop("sdes_chunks")
        event = events(self._rtcp_document(component), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("SDES_CHUNKS_UNAVAILABLE", event["invalid_reasons"])

    def test_68_sdes_count_mismatch(self) -> None:
        component = builder.sdes([builder.item(1)])
        component["source_count"] = 2
        event = events(self._rtcp_document(component), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "AMBIGUOUS")
        self.assertIn("SDES_SOURCE_COUNT_MISMATCH", event["invalid_reasons"])

    def test_69_bye_declared_count_matches_sources(self) -> None:
        event = events(self._rtcp_document(builder.bye([1, 2])), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "OBSERVED")
        self.assertEqual(event["declared_source_count"], 2)
        self.assertEqual(event["observed_source_count"], 2)
        self.assertEqual(event["source_count_status"], "OBSERVED")

    def test_70_bye_missing_source_hierarchy(self) -> None:
        component = builder.bye([1, 2])
        component.pop("bye_sources")
        event = events(self._rtcp_document(component), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("BYE_SOURCES_UNAVAILABLE", event["invalid_reasons"])

    def test_71_bye_count_mismatch(self) -> None:
        component = builder.bye([1, 2])
        component["source_count"] = 3
        event = events(self._rtcp_document(component), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "AMBIGUOUS")
        self.assertIn("BYE_SOURCE_COUNT_MISMATCH", event["invalid_reasons"])

    def test_72_invalid_bye_source_identifier(self) -> None:
        component = builder.bye([-1])
        event = events(self._rtcp_document(component), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "INVALID")
        self.assertIn("BYE_SOURCE_INVALID", event["invalid_reasons"])

    def test_73_zero_source_bye_is_valid_but_useless(self) -> None:
        event = events(self._rtcp_document(builder.bye([], reason_present=False, reason_length=0)), "RTCP")[0]
        self.assertEqual(event["evidence_status"], "OBSERVED")
        self.assertEqual(event["declared_source_count"], 0)
        self.assertEqual(event["observed_source_count"], 0)
        self.assertIn("zero-source BYE", " ".join(event["limitations"]))

    def test_74_structured_capture_basename_allowed(self) -> None:
        record = builder.rtp(1)
        record["capture_file"] = "capture-01.pcapng"
        record["source_reference"] = "rtp-packet:capture-01.pcapng:1.1"
        event = events(analyze([record]), "RTP")[0]
        self.assertEqual(event["capture_file"], "capture-01.pcapng")

    def test_75_absolute_workstation_path_rejected(self) -> None:
        record = builder.rtp(1)
        record["capture_file"] = "/root/private/capture.pcapng"
        record["source_reference"] = "rtp-packet:/root/private/capture.pcapng:1.1"
        directory = Path(tempfile.mkdtemp())
        path = directory / "input.jsonl"
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        with self.assertRaises(rtp_rtcp_model.InputError) as context:
            rtp_rtcp_model.extract_structured(path)
        self.assertNotIn("/root/private", str(context.exception))

    def test_76_no_path_leakage_into_json_or_report(self) -> None:
        record = builder.rtp(1)
        record["capture_file"] = "C:\\Users\\private\\capture.pcapng"
        record["source_reference"] = "rtp-packet:C:\\Users\\private\\capture.pcapng:1.1"
        directory = Path(tempfile.mkdtemp())
        input_path = directory / "input.jsonl"
        input_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        output = directory / "output.json"
        report = directory / "report.txt"
        completed = run_cli(input_path, output, report)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(output.exists())
        self.assertFalse(report.exists())
        self.assertNotIn("Users", completed.stderr)

    def test_77_manifest_include_exclude_consistency(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        self.assertIn("RFC 3550 RTP version 2 packet evidence extraction", manifest)
        self.assertNotIn("RTP packet extraction", manifest)

    def test_78_manifest_input_output_contract_files_exist(self) -> None:
        manifest = MANIFEST.read_text(encoding="utf-8")
        for relative in (
            "schemas/sdp-events.schema.json",
            "schemas/rtp-rtcp-events.schema.json",
            "scripts/parse-sdp.py",
            "scripts/extract-rtp-rtcp.py",
        ):
            self.assertIn(relative, manifest)
            self.assertTrue((SKILL / relative).is_file())

    def test_79_existing_sdp_output_byte_identity(self) -> None:
        records = sdp_model.load_messages(SDP_INPUT)
        document = sdp_model.build_analysis(records, input_name=SDP_INPUT.name)
        serialized = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self.assertEqual(serialized.encode("utf-8"), SDP_EXPECTED.read_bytes())

    def test_80_rtp_rtcp_fixture_stability(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        completed = run_cli(INPUTS, output)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            output.read_bytes(),
            EXPECTED.joinpath("rtp-rtcp-analysis.json").read_bytes(),
        )

    def test_81_deterministic_replay_after_corrections(self) -> None:
        first = analyze(builder.build_records())
        second = analyze(builder.build_records())
        self.assertEqual(first, second)


class RtpRtcpCaptureFlagTests(unittest.TestCase):
    def _capture(self):
        directory = Path(tempfile.mkdtemp())
        capture = directory / "capture.pcap"
        capture.write_bytes(b"capture")
        return capture

    def _extract(self, rtp_fields: dict) -> dict:
        capture = self._capture()
        def runner(_capture, _decode_as, _tshark):
            return {
                "packets": [
                    {
                        "_source": {
                            "layers": {
                                "frame": {
                                    "frame.number": "1",
                                    "frame.time_epoch": "1700000600.000000001",
                                    "frame.len": "60",
                                },
                                "udp": {"udp.stream": "0", "udp.stream.pnum": "1"},
                                "rtp": rtp_fields,
                            }
                        }
                    }
                ]
            }
        events, provenance = rtp_rtcp_model.extract_capture(
            capture, [], prober=lambda _tshark: None, runner=runner
        )
        return events[0]

    def test_82_tshark_explicit_zero_flags_remain_false(self) -> None:
        event = self._extract(
            {
                "rtp.version": "2",
                "rtp.padding": "0",
                "rtp.ext": "0",
                "rtp.cc": "0",
                "rtp.marker": "0",
                "rtp.p_type": "96",
                "rtp.seq": "1",
                "rtp.timestamp": "160",
                "rtp.ssrc": "0x01020304",
            }
        )
        self.assertIs(event["padding"], False)
        self.assertIs(event["extension"], False)
        self.assertIs(event["marker"], False)
        self.assertEqual(event["evidence_status"], "OBSERVED")

    def test_83_tshark_absent_flag_is_incomplete_not_false(self) -> None:
        event = self._extract(
            {
                "rtp.version": "2",
                "rtp.ext": "0",
                "rtp.cc": "0",
                "rtp.marker": "0",
                "rtp.p_type": "96",
                "rtp.seq": "1",
                "rtp.timestamp": "160",
                "rtp.ssrc": "0x01020304",
            }
        )
        self.assertIsNone(event["padding"])
        self.assertEqual(event["evidence_status"], "INCOMPLETE")
        self.assertIn("RTP_PADDING_FLAG_MISSING", event["invalid_reasons"])


class RtpRtcpSchemaTests(unittest.TestCase):
    def test_schema_validation(self) -> None:
        document = analyze(builder.build_records())
        if jsonschema is not None:
            jsonschema.validate(document, json.loads(SCHEMA.read_text(encoding="utf-8")))
        rtp_rtcp_model.validate_analysis(document)

    def test_cli_expected_report(self) -> None:
        directory = Path(tempfile.mkdtemp())
        output = directory / "analysis.json"
        report = directory / "report.txt"
        completed = run_cli(INPUTS, output, report)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            report.read_text(encoding="utf-8"),
            EXPECTED.joinpath("rtp-rtcp-report.txt").read_text(encoding="utf-8"),
        )


class CompoundRtcpCaptureTests(unittest.TestCase):
    def test_pdml_compound_rtcp_components_are_preserved(self) -> None:
        pdml = """<pdml><packet>
<proto name="frame"><field name="frame.number" show="859"/><field name="frame.time_epoch" show="1700000000.000000"/></proto>
<proto name="udp"><field name="udp.stream" show="17"/><field name="udp.stream.pnum" show="5"/></proto>
<proto name="rtcp">
<field name="rtcp.version" show="2"/><field name="rtcp.rc" show="1"/><field name="rtcp.pt" show="200"/><field name="rtcp.length" show="12"/><field name="rtcp.senderssrc" show="0x00080588"/>
<field name="rtcp.timestamp.ntp.msw" show="1"/><field name="rtcp.timestamp.ntp.lsw" show="2"/><field name="rtcp.timestamp.ntp" show="present"/><field name="rtcp.timestamp.rtp" show="3"/><field name="rtcp.sender.packetcount" show="10"/><field name="rtcp.sender.octetcount" show="1000"/>
<field name="" show="Source 1"><field name="rtcp.ssrc.identifier" show="0xf0ea65d9"/><field name="" show="SSRC contents"><field name="rtcp.ssrc.fraction" show="1"/><field name="rtcp.ssrc.cum_nr" show="2"/></field><field name="rtcp.ssrc.ext_high" show="44"/><field name="rtcp.ssrc.jitter" show="160"/><field name="rtcp.ssrc.lsr" show="0"/><field name="rtcp.ssrc.dlsr" show="0"/></field>
</proto>
<proto name="rtcp">
<field name="rtcp.version" show="2"/><field name="rtcp.sc" show="1"/><field name="rtcp.pt" show="202"/><field name="rtcp.length" show="2"/>
<field name="" show="Chunk 1"><field name="rtcp.ssrc.identifier" show="0x00080588"/><field name="" show="SDES items"><field name="rtcp.sdes.type" show="1"/><field name="rtcp.sdes.length" show="0"/><field name="rtcp.sdes.type" show="0"/></field></field>
</proto>
</packet></pdml>"""
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "compound.pcapng"
            capture.write_bytes(b"not-a-real-capture")
            records = rtp_rtcp_model._capture_records(
                capture,
                [],
                "tshark",
                runner=lambda *args, **kwargs: {"packets": []},
                pdml_runner=lambda *args, **kwargs: pdml,
            )
            events = []
            for record in records:
                events.extend(rtp_rtcp_model._parse_record(record))
        self.assertEqual([event["packet_type"] for event in events], [200, 202])
        sr = events[0]
        self.assertEqual(sr["packet_type_name"], "SR")
        self.assertEqual(sr["evidence_status"], "OBSERVED")
        self.assertEqual(len(sr["report_blocks"]), 1)
        self.assertEqual(sr["report_blocks"][0]["fraction_lost"], 1)
        self.assertEqual(sr["report_blocks"][0]["interarrival_jitter"], 160)
        self.assertEqual(sr["udp_stream"], 17)
        sdes = events[1]
        self.assertEqual(sdes["declared_source_count"], 1)
        self.assertEqual(sdes["observed_source_count"], 1)


if __name__ == "__main__":
    unittest.main()